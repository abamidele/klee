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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <limits>
#include <set>
#include <string>
#include <utility>

#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"

#include "remill/BC/ABI.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/BC/Optimizer.h"

#include "remill/OS/OS.h"

#include "TraceManager.h"
#include "TraceLifter.h"
#include "vmill/Program/AddressSpace.h"

namespace klee {

TraceLifter::TraceLifter(llvm::Module &lifted_traces_,
                         TraceManager &trace_manager_)
    : context(lifted_traces_.getContext()),
      traces_module(lifted_traces_),
      semantics_module(remill::LoadTargetSemantics(&context)),
      intrinsics(semantics_module),
      trace_manager(trace_manager_),
      inst_lifter(remill::GetTargetArch(), intrinsics),
      trace_lifter_impl(inst_lifter, trace_manager) {}


const remill::IntrinsicTable &TraceLifter::GetIntrinsics(void){
  return intrinsics;
}

llvm::Function *TraceLifter::GetLiftedFunction(
    vmill::AddressSpace *memory, uint64_t addr) {
  auto func = trace_manager.GetLiftedTraceDefinition(addr);
  if (func) {
    CHECK(!func->isDeclaration());
    return func;
  }

  // TODO(sai): Eventually remove this in favor of "importing" all lifted
  //            traces already in `lifted_traces`.
  const auto trace_name = trace_manager.TraceName(addr);
  func = traces_module.getFunction(trace_name);
  if (func) {
    CHECK(!func->isDeclaration());
    trace_manager.SetLiftedTraceDefinition(addr, func);
    return func;
  }

  return Lift(memory, addr);
}

llvm::Function *TraceLifter::Lift(vmill::AddressSpace *memory, uint64_t addr) {
  
  std::unordered_map<uint64_t, llvm::Function *> new_lifted_traces;

  trace_manager.memory = memory;
  trace_lifter_impl.Lift(
      addr,
      [&new_lifted_traces] (uint64_t trace_addr, llvm::Function *func) {
        func->setLinkage(llvm::GlobalValue::ExternalLinkage);
        new_lifted_traces[trace_addr] = func;
      });
  trace_manager.memory = nullptr;

  //  assumes remill::TraceLifter has all protected fields and no private fields
  remill::OptimizationGuide guide = {};
  guide.slp_vectorize = false;
  guide.loop_vectorize = false;
  guide.verify_input = false;
  guide.eliminate_dead_stores = false;  // Avoids buggy DSE for now.

  LOG(INFO)
      << "Optimizing lifted traces";

  remill::OptimizeModule(semantics_module, new_lifted_traces, guide);

  for (auto lifted_entry : new_lifted_traces) {
    remill::MoveFunctionIntoModule(lifted_entry.second, &traces_module);
  }
  return new_lifted_traces[addr];
}

}  //namespace klee
