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

#include <cstdint>
#include <memory>

#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"

#pragma once

namespace llvm {
class LLVMContext;
class Function;
class Module;
}  // namespace llvm
namespace klee {
namespace native {

class AddressSpace;
class TraceManager;

//The goal here is to get the Lift function working
class TraceLifter {
 public:
  TraceLifter(llvm::Module &lifted_traces_, TraceManager &trace_manager_);

  llvm::Function *GetLiftedFunction(vmill::AddressSpace *memory, uint64_t addr);

  const remill::IntrinsicTable &GetIntrinsics(void);

 private:
  TraceLifter(void) = delete;

  llvm::Function *Lift(vmill::AddressSpace *memory, uint64_t addr);

  llvm::LLVMContext &context;
  llvm::Module &traces_module;
  const std::unique_ptr<llvm::Module> semantics_module;
  const remill::IntrinsicTable intrinsics;
  TraceManager &trace_manager;
  remill::InstructionLifter inst_lifter;
  remill::TraceLifter trace_lifter_impl;
};

}  // namespace native
}  // namespace klee
