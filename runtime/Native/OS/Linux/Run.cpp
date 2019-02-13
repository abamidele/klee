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

#ifndef KLEEMILL_RUNTIME_LINUX_RUN_CPP_
#define KLEEMILL_RUNTIME_LINUX_RUN_CPP_

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
extern "C" linux_task *__kleemill_create_task(State *state,
                                              Memory *memory) {
  auto task = new linux_task;
  memcpy(&(task->state), state, sizeof(State));
  task->time_stamp_counter = 0;
  task->status = kTaskStatusRunnable;
  task->location = kTaskStoppedAtSnapshotEntryPoint;
  task->tid = gNextTid++;
  task->memory = memory;
  task->last_pc = CurrentPC(task->state);
  task->continuation = __kleemill_get_lifted_function(memory, task->last_pc);

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
extern "C" void __kleemill_run(linux_task *task){
  gCurrent = task;
  task->continuation(reinterpret_cast<State &>(*task),
                     task->last_pc, task->memory);
  gCurrent = nullptr;
}

// Called by the executor when all initial tasks are loaded.
extern "C" void __kleemill_schedule(void) {
  for (auto progressed = true; progressed; ) {
    progressed = false;
    for (auto task = gTaskList; task; task = task->next) {
      switch (task->status) {
        case kTaskStatusRunnable:
        case kTaskStatusResumable:
          progressed = true;
          if (!task->blocked_count) {
            __kleemill_run(task);
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

#endif  // KLEEMILL_RUNTIME_LINUX_RUN_CPP_
