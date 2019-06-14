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


namespace klee {
  MemoryAccessContinuation::MemoryAccessContinuation(ExecutionState *state, ref<Expr> addr,
							   uint64_t min_val, uint64_t max_val,
							   uint64_t next_val, uint64_t memory_index_,
							   ref<Expr> memory_, MemoryContinuationKind kind_)
	 : state(state),
	  addr(addr),
	  min_addr(min_val),
	  max_addr(max_val),
	  next_addr(next_val),
	  memory_index(memory_index_),
	  memory(memory_),
	  kind(kind_) {}

  ExecutionState *MemoryAccessContinuation::TryContinue(Executor &exe) {
	return exe.updateMemContinuation(*this);
  }

  BranchContinuation::BranchContinuation(ExecutionState *state):
    state(state) {}

  ExecutionState *BranchContinuation::TryContinue(Executor &exe){
    return state;
  }

}  //namespace klee
