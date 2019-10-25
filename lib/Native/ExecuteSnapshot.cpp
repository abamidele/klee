/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <signal.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <iomanip>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "Native/Memory/Snapshot.h"
#include "Native/Workspace/Workspace.h"

// allows the target binary of ptrace to be traced
DEFINE_uint64(main, 0, "Address of where to inject a breakpoint.");
DEFINE_uint64(pid, 0, "pid of the targeted process");
DEFINE_bool(dynamic, false, "Bool set if the snapshotted binary is dynamic");
DECLARE_string(arch);
DECLARE_string(os);

DEFINE_bool(verbose, true, "Enable verbose logging?");

namespace {

enum : int {
  kMaxNumAttempts = 10
};

enum : size_t {
  kPageBuffSize = 4096ULL,
  kPageMask = ~(kPageBuffSize - 1ULL)
};

static int gTraceeArgc = 0;

static char **gTraceeArgv = nullptr;


static void EnableTracing(void) {
  for (auto i = 0ULL; i < kMaxNumAttempts; ++i) {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr)) {
      raise(SIGSTOP);
      return;
    }
  }
  LOG(FATAL) << "Failed to enable tracing for ptrace tracee";
}

static bool IsErrorSignal(int sig) {
  switch (sig) {
  case SIGHUP:
  case SIGQUIT:
  case SIGABRT:
  case SIGBUS:
  case SIGFPE:
  case SIGKILL:
  case SIGSEGV:
  case SIGPIPE:
  case SIGTERM:
    return true;
  default:
    return false;
  }
}

static void TraceSubprocess(pid_t pid) {
  while (true) {
    auto status = 0;
    const auto res = waitpid(pid, &status, 0);
    const auto err = -1 == res ? errno : 0;
    if (res == pid) {
      if (WIFSTOPPED(status)) {
        if (SIGSTOP == WSTOPSIG(status)) {
          break;
        } else if (IsErrorSignal(WSTOPSIG(status))) {
          LOG(FATAL)
              << "Unable to acquire control of tracee; it exited with signal "
              << WSTOPSIG(status);
        } else {
          LOG(INFO) << "Still trying to acquire control of tracee; "
              << "it stopped with signal " << WSTOPSIG(status);
        }
      } else if (WIFEXITED(status)) {
        LOG(FATAL)
            << "Unable to acquire control of tracee; it exited with status "
            << WEXITSTATUS(status);

      } else if (WIFSIGNALED(status)) {
        LOG(FATAL)
            << "Unable to acquire control of tracee; it terminated with signal "
            << WTERMSIG(status);
      } else {
        LOG(INFO) << "Unrecognized status " << status
            << " while trying to acquire control of tracee.";
      }

    } else if (EINTR != err) {
      auto err = strerror(errno);
      kill(pid, SIGKILL);
      LOG(FATAL) << "Problem waiting to acquire control of tracee: " << err;
    }
  }

  errno = 0;
  ptrace(PTRACE_SETOPTIONS, pid, 0,
      PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL);

  CHECK(ESRCH != errno)<< "Unable to trace subprocess " << pid;
}

static void CloseFdsOnExec(void) {
  auto dp = opendir("/proc/self/fd");
   CHECK(nullptr != dp)
       << "Unable to open /proc/self/fd directory of tracee: "
       << strerror(errno);

   while (true) {
     errno = 0;
     auto dirent = readdir(dp);
     if (!dirent) {
       CHECK(!errno)
           << "Unable to list /proc/self/fd directory of tracee: "
           << strerror(errno);
       break;
     }

     int fd = 0;
     if (1 != sscanf(dirent->d_name, "%d", &fd)) {
       continue;
     }

     switch (fd) {
       case STDIN_FILENO:
       case STDOUT_FILENO:
       case STDERR_FILENO:
         break;
       default:
         LOG(INFO)
             << "Setting fd " << std::dec << fd << " to close on exec.";

         CHECK(!fcntl(fd, F_SETFD, FD_CLOEXEC))
             << "Unable to change fd " << fd << " in tracee to close on exec: "
             << strerror(errno);
         break;
     }
   }

   closedir(dp);
}

bool ExtractTraceeArgs(int *argc, char **argv) {
  const auto old_argc = *argc;
  auto new_argc = 0;

  for (auto i = 0; i < old_argc; ++i) {
    auto arg = argv[i];
    if (!strcmp("--", arg)) {
      break;
    } else {
      ++new_argc;
    }
  }

  if (old_argc == new_argc) {
    return false;
  }

  *argc = new_argc;
  argv[new_argc] = nullptr;
  gTraceeArgv = &(argv[new_argc + 1]);
  gTraceeArgc = old_argc - new_argc - 1;

  return true;
}

static bool ReadPageInfoLine(const std::string &line,
                             klee::native::snapshot::AddressSpace *memory) {
  auto cline = line.c_str();
  uint64_t begin = 0;
  uint64_t end = 0;
  uint64_t offset = 0;
  unsigned dev_major = 0;
  unsigned dev_minor = 0;
  uint64_t inode = 0;
  struct stat;
  char r = '-';
  char w = '-';
  char x = '-';
  char p = '-';
  char path_mem[PATH_MAX + 1] = {};

  auto num_vars_read = sscanf(
      cline, "%" SCNx64 "-%" SCNx64 " %c%c%c%c %" SCNx64 " %x:%x %"
      SCNd64 "%s", &begin, &end, &r, &w, &x, &p, &offset, &dev_major,
      &dev_minor, &inode, &(path_mem[0]));

  if (!(10 == num_vars_read || 11 == num_vars_read)) {
    return false;
  }

  // Make sure that `path` points to the first non-space character in
  // `path_mem`.
  path_mem[PATH_MAX] = '\0';
  auto path = &(path_mem[0]);
  for (auto i = 0; i < PATH_MAX && path_mem[i] && ' ' == path_mem[i]; ++i) {
    path++;
  }

  auto info = memory->add_page_ranges();

  LOG(INFO)
      << "Page info: " << line;

  info->set_base(static_cast<int64_t>(begin));
  info->set_limit(static_cast<int64_t>(end));
  info->set_can_read('r' == r);
  info->set_can_write('w' == w);
  info->set_can_exec('x' == x);
  info->set_name(PageRangeName(line));

  if (strstr(path, "[stack]")) {
    info->set_kind(klee::native::snapshot::kLinuxStackPageRange);

//    auto curr_stack_size = end - begin;
//    auto new_stack_size = std::max(curr_stack_size, GetMaxStackSize());
//
//    info->set_base(static_cast<int64_t>(end - new_stack_size & kPageMask));
//
//    LOG(INFO)
//        << "New stack base is " << std::hex << info->base() << std::dec;

  } else if (strstr(path, "[vvar]")) {
    info->set_kind(klee::native::snapshot::kLinuxVVarPageRange);

  } else if (strstr(path, "[vdso]")) {
    info->set_kind(klee::native::snapshot::kLinuxVDSOPageRange);

  } else if (strstr(path, "[vsyscall]")) {
    info->set_kind(klee::native::snapshot::kLinuxVSysCallPageRange);

  } else if (strstr(path, "[heap]")) {
    info->set_kind(klee::native::snapshot::kLinuxHeapPageRange);

  } else if (path[0]) {
    info->set_kind(klee::native::snapshot::kFileBackedPageRange);
    info->set_file_path(path);
    info->set_file_offset(static_cast<int64_t>(offset));

  } else {
    info->set_kind(klee::native::snapshot::kAnonymousPageRange);
  }

  return true;
}

static void ReadTraceePageMaps(pid_t pid, klee::native::snapshot::AddressSpace *memory) {
  std::stringstream ss;
  ss << "/proc/" << pid << "/maps";

  std::ifstream maps_file(ss.str());
  std::string line;
  while (std::getline(maps_file, line)) {
    LOG_IF(ERROR, !ReadPageInfoLine(line, memory))
        << "Unexpected format for page line: " << line;
  }
}

static void RunJittedTracesUntilBreakpoint(pid_t pid) {
  /* Only runs until main in the runtime lib jitted library does not work yet */
  LOG(INFO)
      << "Setting breakpoint at " << std::hex << FLAGS_main;

  if (FLAGS_dynamic){
    LOG(INFO) << "calculating binary base for breakpoint offset";
    klee::native::snapshot::AddressSpace init_memory;
    ReadTraceePageMaps(pid, &init_memory);
    for (const auto &info : init_memory.page_ranges()) {
      if ((info.kind() == klee::native::snapshot::kFileBackedPageRange)
              && (info.can_exec())) {
          printf("the base of the binary is %lx\n", info.base());
          printf("the limit of the binary is %lx\n", info.limit());
          FLAGS_main += info.base();
          printf("the new breakpoint is at %lx\n", FLAGS_main);
          break;
      }
    }
  }

  errno = 0;
  auto old_text_word = ptrace(PTRACE_PEEKTEXT, pid, FLAGS_main, 0);
  auto has_err = 0 != errno;

  // Add in an `int3`.
  auto new_text_word = (old_text_word & (~0xFFL)) | 0xCCL;
  ptrace(PTRACE_POKETEXT, pid, FLAGS_main, new_text_word);

  if (has_err || 0 != errno) {
    kill(pid, SIGKILL);
    LOG(FATAL)
        << "Unable to write breakpoint at "
        << std::setw(16) << std::hex << std::setfill('0') << FLAGS_main
        << " into " << gTraceeArgv[0];
  }

  while (true) {  // Run until the breakpoint is hit.
    if (0 > ptrace(PTRACE_CONT, pid, 0, 0)) {
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Breakpoint won't be hit; unable to continue executing "
          << gTraceeArgv[0];
    }

    auto status = 0;
    const auto res = waitpid(pid, &status, 0);
    const auto err = -1 == res ? errno : 0;
    if (res == pid) {
      if (WIFSTOPPED(status)) {
        if (SIGTRAP == WSTOPSIG(status)) {
          break;
        } else if (IsErrorSignal(WSTOPSIG(status))) {
          LOG(FATAL)
              << "Tracee exited with signal " << WSTOPSIG(status)
              << " before the breakpoint was hit.";
        } else {
          LOG(INFO)
              << "Tracee " << gTraceeArgv[0] << " received signal "
              << WSTOPSIG(status) << " before the breakpoint was hit.";
        }
      } else if (WIFEXITED(status)) {
        LOG(FATAL)
            << "Tracee " << gTraceeArgv[0]
            << " exited before breakpoint was hit";
      } else if (WIFSIGNALED(status)) {
        LOG(FATAL)
            << "Tracee " << gTraceeArgv[0]
            << " exited before breakpoint was hit";
      } else {
        LOG(INFO)
            << "Unrecognized status " << status << " received before "
            << "hitting breakpoint in " << gTraceeArgv[0];
      }

    } else if (EINTR != err) {
      auto err = strerror(errno);
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Problem waiting for the breakpoint in " << gTraceeArgv[0]
          << " to be hit: " << err;
    }
  }
}

} // namespace

int main(int argc, char **argv, char **envp) {

  const auto got_tracee_args = ExtractTraceeArgs(&argc, argv);

  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --main ADDR \\" << std::endl
     << "    --workspace WORKSPACE_DIR \\" << std::endl
     << "    -- PROGRAM ..." << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);

  CHECK(got_tracee_args)
      << "Unable to extract arguments to tracee. Make sure to provide "
      << "the program and command-line arguments to that program after "
      << "a '--'.";
  pid_t child_pid;
  if (const auto& pid = fork()) {
    CHECK(-1 != pid)
        << "Could not fork process.";
    TraceSubprocess(pid);
    LOG(INFO) << "Acquired control of tracee with pid " << pid;
    //RunOrchestrator(pid);
    RunJittedTracesUntilBreakpoint(pid);
    kill(pid, SIGSTOP);
    child_pid = pid;
  } else {
    EnableTracing();
    CloseFdsOnExec();
    const auto &orchestrator = klee::native::Workspace::OrchestratorLibPath();
    CHECK(!setenv("LD_BIND_NOW", "1", true))
      << "Unable to set LD_BIND_NOW=1 for tracee: " << strerror(errno);

    CHECK(!setenv("LD_PRELOAD", orchestrator.c_str(), true))
      << "Unable to set LD_PRELOAD for tracee: " << strerror(errno);

    CHECK(!execvpe(gTraceeArgv[0], gTraceeArgv, __environ))
      << "Unable to exec traces: " << strerror(errno);
  }

  /* continue with klee emulation, here I need to ensure
   * that the correct malloc information, fds, and runtime module
   * are extracted from the "raw mapped ranges" and properly
   * loaded into the klee-native executor
   * should flesh out my vmill like runtime definitions before
   * I get to this part
   */

  /* auto snapshot = klee::native::LoadSnapshotFromFile
   * (This is the function that needs to be updated to extract info
   * from the raw mapped memory ranges
   */
  kill(child_pid, SIGKILL);
  return EXIT_SUCCESS;
}
