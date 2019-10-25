/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#if defined(__APPLE__)
# error "Taking snapshots on macOS is not yet supported."
#endif

#include <algorithm>
#include <cinttypes>
#include <climits>
#include <csignal>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#include <sys/mman.h>
#if defined(__linux__)
# include <sys/personality.h>
#endif
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"

#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "Native/Memory/Snapshot.h"
#include "Native/Workspace/Workspace.h"

#include <iostream>

namespace klee {
namespace native {

// Copy the register state from the tracee with PID `pid` into the file
// with FD `fd`.
extern void CopyX86TraceeState(pid_t pid, pid_t tid, int64_t memory_id,
                               snapshot::Program *snapshot);

extern void CopyAArch64TraceeState(pid_t pid, pid_t tid, int64_t memory_id,
                                   snapshot::Program *snapshot);
}  // namespace native
}  // namespace klee

namespace {

enum : int {
  kMaxNumAttempts = 10
};

enum : size_t {
  kPageBuffSize = 4096ULL,
  kPageMask = ~(kPageBuffSize - 1ULL)
};

static char gPageBuff[kPageBuffSize];

static klee::native::snapshot::Program gSnapshot;

// Returns `true` if a signal looks like an error signal. Used when checking
// `WIFSTOPPED`.
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

// Set a breakpoint on an address within the tracee.
static void ReadTraceePageMaps(pid_t pid, klee::native::snapshot::AddressSpace *memory);

// Gets the list of all thread IDs for this process.
static std::vector<pid_t> GetTIDs(pid_t pid) {
  std::vector<pid_t> tids;

  std::stringstream ss;
  ss << "/proc/" << pid << "/task/";

  auto dir = opendir(ss.str().c_str());
  CHECK(dir != nullptr)
      << "Could not list the " << ss.str() << " directory to find the thread "
      << "IDs";

  while (auto ent = readdir(dir)) {
    pid_t tid = -1;
    char dummy;
    if (sscanf(ent->d_name, "%d%c", &tid, &dummy) == 1 &&
        0 <= tid) {
      tids.push_back(tid);
    }
  }
  closedir(dir);
  return tids;
}

// Converts a line from `/proc/<pid>/maps` into a name that will be used as
// the file name for a file containing the actual data contained within the
// range.
static std::string PageRangeName(const std::string &line) {
  std::stringstream ss;
  auto seen_sym = false;
  for (auto c : line) {
    if (isalnum(c)) {
      ss << c;
      seen_sym = false;
    } else if ('\r' == c || '\n' == c) {
      break;
    } else if (!seen_sym) {
      if (c == '-') {
        ss << "-";
      } else if (c == '.') {
        ss << '.';
      } else if (c == '_'){
        ss << '_';
      } else {
        ss << ' ';
      }
      seen_sym = true;
    }
  }
  return ss.str();
}

// Parse a line from `/proc/<pid>/maps` and fill in a `PageInfo` structure.
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

// Read out the ranges of mapped pages.
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

// Copy some data from the tracee into the snapshot file, using ptrace to do
// the copying.
static bool CopyTraceeMemoryWithPtrace(pid_t pid, uint64_t addr,
                                       uint64_t size, void *dest) {
  for (auto i = 0UL; i < size; ) {
    errno = 0;
    auto copied_data = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
    if (errno) {
      return false;
    }

    auto dest_data = reinterpret_cast<decltype(copied_data) *>(dest);
    dest_data[i / sizeof(copied_data)] = copied_data;

    i += sizeof(copied_data);
    addr += sizeof(copied_data);
  }

  return true;
}

static const uint8_t kUD2Sled[] = {
  0x0f, 0x0b, 0x0f, 0x0b, 0x0f, 0x0b, 0x0f, 0x0b
};

// Patch in a bunch of NOPs over the indirect jump following a sled of UD2s.
static void PerformInterceptPatching(void) {
  for (size_t i=0; i < kPageBuffSize; i += 16) {
    if (!memcmp(&(gPageBuff[i]), kUD2Sled, sizeof(kUD2Sled))) {
      memset(&(gPageBuff[i + sizeof(kUD2Sled)]), 0x90, 6);
    }
  }
}

// Copy memory from the tracee into the snapshot file.
static void CopyTraceeMemory(
    pid_t pid, const klee::native::snapshot::AddressSpace *memory) {

  // Open up the file that maps in the processes's memory; succeeded is not
  // a strict requirement given the ptrace-based fallback.
  std::stringstream ss;
  ss << "/proc/" << pid << "/mem";
  std::string source_path = ss.str();
  auto mem_fd = open(source_path.c_str(), O_RDONLY);

  LOG_IF(ERROR, -1 == mem_fd)
      << "Can't open " << source_path << " for reading";

  for (const auto &info : memory->page_ranges()) {

    std::stringstream dest_path_ss;
    dest_path_ss << klee::native::Workspace::MemoryDir()
                 << remill::PathSeparator()
                 << info.name();

    // Make sure the file that will contain the memory has the right size.
    std::string dest_path = dest_path_ss.str();
    auto dest_fd = open(dest_path.c_str(), O_RDWR | O_TRUNC | O_CREAT, 0666);
    CHECK(-1 != dest_fd)
        << "Can't open " << dest_path << " for writing.";

    CHECK_LE(static_cast<uint64_t>(info.base()),
             static_cast<uint64_t>(info.limit()));
    auto size_to_copy = static_cast<uint64_t>(info.limit() - info.base());
    ftruncate(dest_fd, size_to_copy);

    uint64_t i = 0;

    // The mapping is originally file-backed. Start by copying in the original
    // backing data.
    if (info.kind() == klee::native::snapshot::kFileBackedPageRange) {
      int mapped_file_fd = open(info.file_path().c_str(), O_RDONLY);
      if (-1 != mapped_file_fd) {
        lseek(mapped_file_fd, info.file_offset(), SEEK_SET);

        LOG(INFO)
            << "Copying " << std::dec << size_to_copy << " bytes from "
            << info.file_path() << " at offset " << std::hex
            << info.file_offset() << " into " << dest_path << std::dec;



        for (i = 0; i < size_to_copy; i += kPageBuffSize) {
          memset(gPageBuff, 0, kPageBuffSize);
          if (kPageBuffSize == read(mapped_file_fd, gPageBuff, kPageBuffSize)) {
            if (info.file_path().find("intercept") != std::string::npos) {
              PerformInterceptPatching();
            }
/*            for (size_t k=0; k <kPageBuffSize; ++k){
             printf("0x%x ", gPageBuff[k]);
            }
            puts("-------------------------------------------");*/
            lseek(dest_fd, i, SEEK_SET);
            write(dest_fd, gPageBuff, kPageBuffSize);
          }
        }


      } else {
        LOG(ERROR)
            << "Unable to open " << info.file_path() << " for reading";
      }
      close(mapped_file_fd);
    }

    LOG(INFO)
        << "Copying " << std::dec << size_to_copy
        << " bytes from the tracee's memory (" << source_path << ") from "
        << std::hex << info.base() << " to " << std::hex << info.limit()
        << " into " << dest_path << std::dec;

    // Start by trying to copy from the `/proc/<pid>/mem` file.
    for (uint64_t i = 0; i < size_to_copy; i += kPageBuffSize) {
      auto page_addr = static_cast<uint64_t>(info.base()) + i;
      lseek(mem_fd, static_cast<int64_t>(page_addr), SEEK_SET);
      memset(gPageBuff, 0, kPageBuffSize);

      if (kPageBuffSize == read(mem_fd, gPageBuff, kPageBuffSize) ||
          CopyTraceeMemoryWithPtrace(pid, page_addr,
                                     kPageBuffSize, gPageBuff)) {
        if (info.file_path().find("intercept") != std::string::npos) {
          PerformInterceptPatching();
        }
        lseek(dest_fd, i, SEEK_SET);
        write(dest_fd, gPageBuff, kPageBuffSize);
      } else {
        LOG(WARNING)
            << "Can't copy memory at offset " << std::hex << page_addr
            << std::dec;
      }
    }
    close(dest_fd);
  }
  close(mem_fd);
}

static void SaveSnapshotFile(void) {
  const auto &path = klee::native::Workspace::SnapshotPath();
  std::ofstream snaphot_out(path);
  CHECK(snaphot_out)
      << "Unable to open " << path << " for writing";

  CHECK(gSnapshot.SerializePartialToOstream(&snaphot_out))
      << "Unable to serialize snapshot description to " << path;
}

// Create a snapshot file of the tracee.
static void SnapshotPid(pid_t pid) {
  const auto &path = klee::native::Workspace::SnapshotPath();
  int64_t memory_id = 1;

  auto memory = gSnapshot.add_address_spaces();
  memory->set_id(memory_id);

  ReadTraceePageMaps(pid, memory);
  CopyTraceeMemory(pid, memory);

  const auto arch_name = remill::GetTargetArch()->arch_name;
  for (auto tid : GetTIDs(pid)) {
    switch (arch_name) {
      case remill::kArchX86:
      case remill::kArchX86_AVX:
      case remill::kArchX86_AVX512:
        LOG(INFO)
            << "Writing X86 register state for thread " << std::dec
            << tid << " into " << path;
        klee::native::CopyX86TraceeState(pid, tid, memory_id, &gSnapshot);
        break;
      case remill::kArchAMD64:
      case remill::kArchAMD64_AVX:
      case remill::kArchAMD64_AVX512:
        LOG(INFO)
            << "Writing AMD64 register state for thread " << std::dec
            << tid << " into " << path;
        klee::native::CopyX86TraceeState(pid, tid, memory_id, &gSnapshot);
        break;

      case remill::kArchAArch64LittleEndian:
        LOG(INFO)
            << "Writing AArch64 register state for thread " << std::dec
            << tid << " into " << path;
        klee::native::CopyAArch64TraceeState(pid, tid, memory_id, &gSnapshot);
        break;

      default:
        LOG(FATAL)
            << "Cannot copy tracee register state for unsupported architecture ";
    }
  }
  SaveSnapshotFile();
}


static void GenerateTraceListWithBinja() {
  struct stat binja_script;
  std::stringstream ss;
  LOG(INFO) << "generating binja traces ";
  const auto& memory_dir = klee::native::Workspace::MemoryDir();
  const auto& binja_script_path = klee::native::Workspace::BinjaScriptPath();
  ss << "python " << binja_script_path << " " << memory_dir;
  system(ss.str().c_str());
  if (!remill::FileExists(klee::native::Workspace::TraceListPath())) {
    LOG(ERROR) << "Failed to create the trace_list file do you have the binja python package?";
  } else {
    LOG(INFO) << "Successfully created trace_list file";
  }
}

}  // namespace



void __attribute__((constructor)) Orchestrate() {
  // snapshot
  // lift traces ahead of time
  // jit traces
  // dlopen jitted trace lib
  // call _start function in that traces lib
  // ptrace will operate until breakpoint
  // new mapped range class will have to come into affect to grab info like
  // mallocs, program states, and fds
}
