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

#ifndef VMILL_RUNTIME_LINUX_RUN_CPP_
#define VMILL_RUNTIME_LINUX_RUN_CPP_

namespace {

static linux_task *gTaskList = nullptr;
static linux_task *gLastTask = nullptr;

}  // namespace

static pid_t gNextTid = kProcessId;

// Initialize the emulated Linux operating system.
extern "C" void __kleemill_init(void) {
  gNextTid = kProcessId;
  gTaskList = nullptr;
  gLastTask = nullptr;
}

// Tear down the emulated Linux operating system.
extern "C" void __kleemill_fini(void) {
  linux_task *next_task = nullptr;
  for (auto task = gTaskList; task; task = next_task) {
    next_task = task->next;
    task->next = nullptr;
    task->next_circular = nullptr;

    delete task;
  }

  gTaskList = nullptr;
  gLastTask = nullptr;
}

// adds new OS task
extern "C" linux_task *__kleemill_create_task(State &state) {
  auto native_task = reinterpret_cast<Task &>(state);
  auto task = new linux_task;
  bzero(task, sizeof(linux_task));

  task->state = native_task.state;
  task->time_stamp_counter = native_task.time_stamp_counter;
  task->status = kTaskStatusRunnable;
  task->continuation = native_task.continuation;
  task->location = native_task.location;
  task->last_pc = native_task.last_pc;

  task->tid = gNextTid++;

  if (gTaskList) {
    gLastTask->next_circular = task;
    task->next_circular = gTaskList;

  } else {
    gLastTask = task;
    task->next_circular = task;
  }

  task->next = gTaskList;
  gTaskList = task;

  return task;
}

// Call into kleemill to execute the actual task.
extern "C" void __kleemill_run(linux_task *task, Memory *memory){
  gCurrent = task;
  task->continuation(reinterpret_cast<State &>(*task), task->last_pc, memory);
  gCurrent = nullptr;
}

// Called by the executor when all initial tasks are loaded.
extern "C" void __kleemill_resume(Memory * memory) {
  for (auto progressed = true; progressed; ) {
    progressed = false;
    for (auto task = gTaskList; task; task = task->next) {
      switch (task->status) {
        case kTaskStatusRunnable:
        case kTaskStatusResumable:
          progressed = true;
          if (!task->blocked_count) {
            __kleemill_run(task, memory);
          } else {
            task->blocked_count--;
          }
          break;

        default:
          printf("Task status %p = %" PRIx64 "\n",
                 reinterpret_cast<void *>(&(task->status)), task->status);
          break;
      }
    }
  }
}

#endif  // VMILL_RUNTIME_LINUX_RUN_CPP_
