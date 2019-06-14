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

#include "Continuation.h"
#include "SpecialFunctionHandler.h"

#include "klee/Solver.h"


namespace klee {
MemoryAccessContinuation::MemoryAccessContinuation(ExecutionState *state_,
                                                   ref<Expr> addr_,
                                                   uint64_t min_val_,
                                                   uint64_t max_val_,
                                                   uint64_t next_val_,
                                                   uint64_t memory_index_,
                                                   ref<Expr> memory_,
                                                   MemoryContinuationKind kind_)
    : StateContinuation(state_),
      addr(addr_),
      min_addr(min_val_),
      max_addr(max_val_),
      next_addr(next_val_),
      memory_index(memory_index_),
      memory(memory_),
      kind(kind_) {
}

ExecutionState *MemoryAccessContinuation::YieldNextState(Executor &exe) {
  const auto curr_state = state.release();
  auto curr_addr = next_addr;
  const auto curr_mem = exe.Memory(*curr_state, memory_index);
  auto found = false;
  auto has_error = false;

  MemoryReadResult val;
  ref<Expr> constr;
  uint64_t next_addr = curr_addr;
  while (min_addr <= next_addr && next_addr <= max_addr) {
    curr_addr = next_addr;
    val = {};
    auto can_read = false;

    switch (kind) {
      case MemoryContinuationKind::kContinueRead8:
      case MemoryContinuationKind::kContinueWrite8:
        can_read = curr_mem->TryRead(curr_addr, &(val.as_byte));
        break;
      case MemoryContinuationKind::kContinueRead16:
      case MemoryContinuationKind::kContinueWrite16:
        can_read = curr_mem->TryRead(curr_addr, &(val.as_word));
        break;
      case MemoryContinuationKind::kContinueRead32:
      case MemoryContinuationKind::kContinueWrite32:
        can_read = curr_mem->TryRead(curr_addr, &(val.as_dword));
        break;
      case MemoryContinuationKind::kContinueRead64:
      case MemoryContinuationKind::kContinueWrite64:
        can_read = curr_mem->TryRead(curr_addr, &(val.as_qword));
        break;
    }

    constr = EqExpr::create(addr, ConstantExpr::create(curr_addr, 64));
    bool res = false;
    (void) exe.solver->mayBeTrue(*curr_state, constr, res);
    // TODO(sai) terminate state on false

    // Not readable.
    if (!can_read) {
      min_addr = curr_addr;

      // Not readable, but satisfiable; this is a memory access violation.
      if (res) {
        found = true;
        has_error = true;
        break;

      // Not readable, not satisfiable, so round up to the next page boundary
      // and keep looking.
      } else {
        next_addr = (curr_addr + 4096ULL) & ~4095ULL;
        continue;
      }

    // Readable but not satisfiable.
    } else if (!res) {
      min_addr = curr_addr;
      next_addr = curr_addr + 1;
      continue;

    // Readable and satisfiable.
    } else {
      found = true;
      break;
    }
  }

  // There are no more addresses to find.
  if (!found) {
    exe.terminateState(*curr_state);
    return curr_state;
  }

  // Fork/branch the current state, without changing the depth or weight.
  state.reset(new ExecutionState(*curr_state));
  state->coveredNew = false;
  state->coveredLines.clear();
  next_addr = curr_addr + 1;

  // If we found an error, report it immediately by terminating the state.
  // This happens *after* forking the current state, so that the executor
  // can go visit the next valid values for the addresss.
  if (has_error) {
    std::stringstream ss;
    ss << "Failed 1-byte read from address 0x" << std::hex << curr_addr;
    exe.terminateStateOnError(*curr_state, ss.str(), Executor::ReportError);
    return curr_state;
  }

  // Add the constraint to our current state that the address must equal
  // `curr_addr`.
  exe.addConstraint(*curr_state, constr);

  switch (kind) {
    case MemoryContinuationKind::kContinueRead8:
      exe.bindLocal(
          curr_state->prevPC, *curr_state,
          exe.specialFunctionHandler->runtime_read_memory(
              curr_mem, curr_addr, 1, val));
      break;
    case MemoryContinuationKind::kContinueRead16:
      exe.bindLocal(
          curr_state->prevPC, *curr_state,
          exe.specialFunctionHandler->runtime_read_memory(
              curr_mem, curr_addr, 2, val));
      break;
    case MemoryContinuationKind::kContinueRead32:
      exe.bindLocal(
          curr_state->prevPC, *curr_state,
          exe.specialFunctionHandler->runtime_read_memory(
              curr_mem, curr_addr, 4, val));
      break;
    case MemoryContinuationKind::kContinueRead64:
      exe.bindLocal(
          curr_state->prevPC, *curr_state,
          exe.specialFunctionHandler->runtime_read_memory(
              curr_mem, curr_addr, 8, val));
      break;

    case MemoryContinuationKind::kContinueWrite8:
      exe.bindLocal(
          curr_state->prevPC, *curr_state,
          exe.specialFunctionHandler->runtime_write_8(*curr_state, curr_addr,
                                                      val_to_write,
                                                      curr_mem, memory));
      break;
    case MemoryContinuationKind::kContinueWrite16:
      exe.bindLocal(
          curr_state->prevPC, *curr_state,
          exe.specialFunctionHandler->runtime_write_16(*curr_state, curr_addr,
                                                       val_to_write,
                                                       curr_mem, memory));
      break;
    case MemoryContinuationKind::kContinueWrite32:
      exe.bindLocal(
          curr_state->prevPC, *curr_state,
          exe.specialFunctionHandler->runtime_write_32(*curr_state, curr_addr,
                                                       val_to_write,
                                                       curr_mem, memory));
      break;
    case MemoryContinuationKind::kContinueWrite64:
      exe.bindLocal(
          curr_state->prevPC, *curr_state,
          exe.specialFunctionHandler->runtime_write_64(*curr_state, curr_addr,
                                                       val_to_write,
                                                       curr_mem, memory));
      break;
  }

  return curr_state;
}

ExecutionState *NullContinuation::YieldNextState(Executor &exe) {
  return state.release();
}

static ExecutionState *PopBack(std::vector<ExecutionState *> &states) {
  auto ret = states.back();
  states.pop_back();
  return ret;
}

BranchContinuation::BranchContinuation(ExecutionState *disabled_state_,
                                       std::vector<ExecutionState *> &states_)
    : StateContinuation(nullptr),
      disabled_state(disabled_state_),
      states(states_) {}

ExecutionState *BranchContinuation::YieldNextState(Executor &exe) {
  while (!states.empty()) {
    auto state = states.back();
    if (!state || state == disabled_state) {
      continue;
    }
    states.pop_back();
    return state;
  }
  return nullptr;
}

}  //namespace klee
