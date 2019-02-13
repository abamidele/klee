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

#include "runtime/Native/OS/Linux/SystemCall.cpp"

// 64-bit `svc` system call ABI.
class AArch64SupervisorCall : public SystemCallABI<AArch64SupervisorCall> {
 public:
  ~AArch64SupervisorCall(void) = default;

  addr_t GetPC(const State *state) const  {
    return state->gpr.pc.aword;
  }

  void SetPC(State *state, addr_t new_pc) const  {
    state->gpr.pc.aword = new_pc;
  }

  void SetSP(State *state, addr_t new_sp) const {
    state->gpr.sp.aword = new_sp;
  }

  addr_t GetReturnAddress(Memory *, State *, addr_t ret_addr) const {
    return ret_addr;
  }

  addr_t GetSystemCallNum(Memory *, State *state) const {
    return state->gpr.x8.qword;
  }

  Memory *DoSetReturn(Memory *memory, State *state,
                    addr_t ret_val) const {
    state->gpr.x0.qword = ret_val;
    return memory;
  }

  bool CanReadArgs(Memory *, State *, int num_args) const {
    return num_args <= 6;
  }

  addr_t GetArg(Memory *&memory, State *state, int i) const {
    switch (i) {
      case 0:
        return state->gpr.x0.qword;
      case 1:
        return state->gpr.x1.qword;
      case 2:
        return state->gpr.x2.qword;
      case 3:
        return state->gpr.x3.qword;
      case 4:
        return state->gpr.x4.qword;
      case 5:
        return state->gpr.x5.qword;
      default:
        return 0;
    }
  }
};

inline static addr_t CurrentPC(AArch64State &state) {
  return state.gpr.pc.aword;
}

extern "C" {

Memory *__remill_sync_hyper_call(AArch64State &, Memory *memory, SyncHyperCall::Name) {
  abort();
  return memory;
}

Memory *__remill_async_hyper_call(
    State &state, addr_t ret_addr, Memory *memory) {
  abort();
  return memory;
}

}  // extern C
