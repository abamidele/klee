/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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


inline static addr_t CurrentPC(X86State &state) {
  return state.gpr.rip.aword;
}

extern "C" {

Memory *__remill_sync_hyper_call(
    X86State &state, Memory *mem, SyncHyperCall::Name call) {

  auto &task = reinterpret_cast<Task &>(state);
  task.time_stamp_counter += 500;

  switch (call) {
    case SyncHyperCall::kInvalid:
      task.location = kTaskStoppedAtError;
      task.last_pc = CurrentPC(state);
      break;

    case SyncHyperCall::kX86CPUID:
      state.gpr.rax.aword = 0;
      state.gpr.rbx.aword = 0;
      state.gpr.rcx.aword = 0;
      state.gpr.rdx.aword = 0;
      break;

    case SyncHyperCall::kX86ReadTSC:
      state.gpr.rax.aword = static_cast<uint32_t>(task.time_stamp_counter);
      state.gpr.rdx.aword = static_cast<uint32_t>(task.time_stamp_counter >> 32);
      break;

    case SyncHyperCall::kX86ReadTSCP:
      state.gpr.rax.aword = static_cast<uint32_t>(task.time_stamp_counter);
      state.gpr.rdx.aword = static_cast<uint32_t>(task.time_stamp_counter >> 32);
      state.gpr.rcx.aword = 0;  // Processor 0.
      break;

    case SyncHyperCall::kX86EmulateInstruction:
    case SyncHyperCall::kAMD64EmulateInstruction:
      task.location = kTaskStoppedAtUnsupportedInstruction;
      task.last_pc = CurrentPC(state);
      break;

    default:
      abort();
  }

  return mem;
}

}  // extern C
