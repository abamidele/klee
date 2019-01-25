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

#pragma once

#include "remill/BC/Lifter.h"

namespace vmill {
  class AddressSpace;
}

namespace klee {

class TraceLifter;
class Executor;

class TraceManager : public ::remill::TraceManager {
 public:
  explicit TraceManager(llvm::Module &lifted_code_);

  void ForEachDevirtualizedTarget(
      const remill::Instruction &inst,
      std::function<void(uint64_t, remill::DevirtualizedTargetKind)> func)
          override;

  bool TryReadExecutableByte(uint64_t addr, uint8_t *byte) override;

  llvm::Function *GetLiftedTraceDeclaration(uint64_t addr) override;

  llvm::Function *GetLiftedTraceDefinition(uint64_t addr) override;


 protected:
  void SetLiftedTraceDefinition(
      uint64_t addr, llvm::Function *lifted_func) override;

 private:
  friend class TraceLifter;

  llvm::Module &lifted_code;
  vmill::AddressSpace *memory;
  std::unordered_map<uint64_t, llvm::Function *> traces;
};

}  // namespace klee
