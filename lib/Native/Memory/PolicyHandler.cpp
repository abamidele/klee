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

#include <glog/logging.h>
#include <Native/Memory/AddressSpace.h>
#include <Native/Memory/AllocList.h>
#include <Native/Memory/PolicyHandler.h>
#include <Core/Memory.h>
#include <Core/AddressSpace.h>
#include <Core/Executor.h>
#include <klee/ExecutionState.h>
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include <llvm/Support/raw_ostream.h>

namespace klee {
namespace native {

ReportErrorPolicyHandler::ReportErrorPolicyHandler()
    : PolicyHandler(),
      exe(nullptr),
      st(nullptr) {
}

void ReportErrorPolicyHandler::Init(klee::Executor *exe_) {
  exe = exe_;
}

void ReportErrorPolicyHandler::setState(klee::ExecutionState *state) {
  st = state;
}

klee::ExecutionState *ReportErrorPolicyHandler::getState() {
  return st;
}

klee::Executor *ReportErrorPolicyHandler::getExecutor() {
  return exe;
}

bool ReportErrorPolicyHandler::HandleHeapWriteOverflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  *res = false;
  if (address.offset >= address.size) {
    LOG(ERROR) << "Heap address overflow on memory write address " << std::hex
      << address.flat << std::dec;
    return true;
  }
  return false;
}

bool ReportErrorPolicyHandler::HandleHeapWriteUnderflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  *res = false;
  if (address.must_be_0x1 != 0x1) {
    LOG(ERROR) << "Heap address underflow on memory write address " << std::hex
        << address.flat << std::dec;
    return true;
  }
  return false;
}

bool ReportErrorPolicyHandler::HandleHeapReadOverflow(AddressSpace *mem,
    const Address& address, uint8_t *byte_out, bool *res, AllocList *alloc_list) {
  *res = true;
  if (address.offset >= address.size) {
    LOG(ERROR) << "Heap address overflow on memory read address " << std::hex
      << address.flat << std::dec;
    *byte_out = 0;
    return true;
  }
  return false;
}

bool ReportErrorPolicyHandler::HandleHeapReadUnderflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  *res = false;
  if (address.must_be_0x1 != 0x1) {
    LOG(ERROR) << "Heap address underflow on memory read address " << std::hex
      << address.flat << std::dec;
    return true;
  }
  return false;
}

bool ReportErrorPolicyHandler::HandleInvalidOutOfBoundsHeapRead(
    AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) {
  *res = false;
  if(address.alloc_index >= alloc_list->allocations.size()) {
    LOG(ERROR) << "Invalid memory read address " << std::hex << address.flat
      << std::dec << "; out-of-bounds allocation index";
    return true;
  }
  return false;
}

bool ReportErrorPolicyHandler::HandleInvalidOutOfBoundsHeapWrite(
    AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) {
  *res = false;
  if(address.alloc_index >= alloc_list->allocations.size()) {
    LOG(ERROR) << "Invalid memory write address " << std::hex << address.flat
      << std::dec << "; out-of-bounds allocation index";
    return true;
  }
  return false;
}

bool ReportErrorPolicyHandler::HandleReadUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  *res = true;
  auto base = alloc_list->zeros.at(address.alloc_index);
  if(base == kFreeValue) {
    LOG(ERROR) << "Use-after-free on memory read addresss " << std::hex
      << address.flat << std::dec;
    return true;
  }
  return false;
}

bool ReportErrorPolicyHandler::HandleWriteUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  *res = false;
  auto base = alloc_list->zeros.at(address.alloc_index);
  if(base == kFreeValue) {
    LOG(ERROR) << "Use-after-free on memory write addresss " << std::hex
      << address.flat << std::dec;
    return true;
  }
  return false;
}

bool ReportErrorPolicyHandler::HandlePseudoUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  *res = false;
  if (!alloc_list->allocations[address.alloc_index]) {
  LOG(ERROR) << "Error in memory implementation; pseudo-use-after-free on "
      << std::hex << address.flat << std::dec << " (size=" << address.size
      << ", entry=" << address.alloc_index << ")";
  return true;
  }
  return false;
}

bool ReportErrorPolicyHandler::HandleDoubleFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  *res = true;
  auto base = alloc_list->zeros[address.alloc_index];
  if(base == kFreeValue) {
    LOG(ERROR) << "Double free on " << std::hex << address.flat << std::dec
      << " (size=" << address.size << ", entry=" << address.alloc_index << ")";
    return true;  // To let it continue.
  }
  return false;
}

void ReportErrorPolicyHandler::HandleFreeOffset(AddressSpace *mem,
    Address& address, bool *res) {
  *res = true;
  if (address.offset != 0) {
    LOG(ERROR) << "Freeing internal pointer " << std::hex << address.flat
      << std::dec;
    address.offset = 0;
  // TODO(sai): Eventually do something more interesting here.
  }
}

bool ReportErrorPolicyHandler::HandleFreeUnallocatedMem(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  *res = false;
  if (address.alloc_index >= alloc_list->zeros.size()){
    LOG(ERROR) << "Free of unallocated memory (size=" << address.size
        << ", entry=" << address.alloc_index << ")";
    return true;
  }
  return false;
}

bool ReportErrorPolicyHandler::HandleTryExecuteHeapMem(AddressSpace *mem,
    const Address& address, bool *res) {
  *res = false;
  if (address.must_be_0xa == 0xa && address.must_be_0x1 == 0x1) {
    LOG(ERROR) << "Trying to execute heap-allocated memory at " << std::hex
        << address.flat << std::dec;
    return true;
  }
  return false;
}

bool ReportErrorPolicyHandler::HandleBadRealloc(AddressSpace *mem,
    const Address& address, size_t alloc_size, uint64_t err_type, AllocList *alloc_list ) {
  switch (err_type) {
  case (kReallocInternalPtr): {
    // TODO(sai): Report?
    if (address.offset != 0) {
      LOG(ERROR) << "Realloc of internal pointer with size " << address.size
          << ", index " << address.alloc_index << ", and offset " << std::hex
          << address.offset << std::dec;
      return true;
    }
    return false;
  }
  case (kReallocTooBig): {
    if (address.size != alloc_size) {
       LOG(ERROR)
           << "Realloc of size " << address.size << " to " << alloc_size
           << " has to be handled by native.";
       return true;
     }
    return false;
  }
  case (kReallocInvalidPtr): {
    if (address.flat && address.alloc_index >= alloc_list->allocations.size()) {
      LOG(ERROR)
          << "Bad old realloc address";
      return true;
     }
    return false;
  }
  case (kReallocFreedPtr): {
    if (address.flat && (alloc_list->zeros[address.alloc_index] == kFreeValue) ) {
      LOG(ERROR)
          << "Cannot realloc on a freed memory region";
      return true;
    }
    return false;
    }
  }
  return err_type;
}

ProxyPolicyHandler::ProxyPolicyHandler() :
  proxy(new ReportErrorPolicyHandler()){
}

void ProxyPolicyHandler::Init(klee::Executor *exe_) {
  proxy->Init(exe_);
}

void ProxyPolicyHandler::setState(klee::ExecutionState *state) {
  proxy->setState(state);
}

klee::Executor *ProxyPolicyHandler::getExecutor() {
  return proxy->getExecutor();
}

klee::ExecutionState *ProxyPolicyHandler::getState() {
  return proxy->getState();
}

bool ProxyPolicyHandler::HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleInvalidOutOfBoundsHeapRead(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleInvalidOutOfBoundsHeapWrite(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleHeapWriteOverflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  KInstruction *ins = getState()->prevPC;
  return proxy->HandleHeapWriteOverflow(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleHeapWriteUnderflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleHeapWriteUnderflow(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleHeapReadOverflow(AddressSpace *mem,
    const Address& address, uint8_t *byte_out, bool *res, AllocList *alloc_list) {
  return proxy->HandleHeapReadOverflow(mem, address, byte_out, res, alloc_list);
}

bool ProxyPolicyHandler::HandleHeapReadUnderflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleHeapReadUnderflow(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleReadUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleReadUseAfterFree(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleWriteUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleWriteUseAfterFree(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandlePseudoUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandlePseudoUseAfterFree(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleDoubleFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleDoubleFree(mem, address, res, alloc_list);
}

void ProxyPolicyHandler::HandleFreeOffset(AddressSpace *mem,
    Address& address, bool *res) {
  return proxy->HandleFreeOffset(mem, address, res);
}

bool ProxyPolicyHandler::HandleFreeUnallocatedMem(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleFreeUnallocatedMem(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleTryExecuteHeapMem(AddressSpace *mem,
    const Address& address, bool *res) {
  return proxy->HandleTryExecuteHeapMem(mem, address, res);
}

bool ProxyPolicyHandler::HandleBadRealloc(AddressSpace *mem,
    const Address& address, size_t alloc_size, uint64_t err_type, AllocList *alloc_list) {
  return proxy->HandleBadRealloc(mem, address, alloc_size, err_type, alloc_list);
}

bool SymbolicBufferPolicy::HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return false;
}
bool SymbolicBufferPolicy::HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  *res = false;
  return false;
}

bool SymbolicBufferPolicy::HandleHeapWriteOverflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  static uint64_t buff_index;
  if (proxy->HandleHeapWriteOverflow(mem, address, res, alloc_list)){
    LOG(INFO) << "HIT SYMBOLIC HEAP OVERFLOW";
    auto *exe = getExecutor();
    *res = true;
    auto state = getState();
    for (auto &sym_pairs: state->symbolics) {
      if (sym_pairs.first->address == exe->sym_buff_addr){
        auto mo = sym_pairs.first;
        auto os = state->addressSpace.findObject(mo);
        auto byte = ReadExpr::create(UpdateList(sym_pairs.second, 0),
            ConstantExpr::alloc(buff_index, sym_pairs.second->getDomain()));
        byte->dump();
        mem->symbolic_memory[address.flat] = byte;
        //exit(0);
      }
    }

    buff_index = (buff_index + 1) % exe->policy_array_size;
    //  TODO(sai, handle the wrap around)
    return true;
  }
  *res = true;
  return false;
}

bool SymbolicBufferPolicy::HandleHeapWriteUnderflow(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) {
  return false;
}

bool SymbolicBufferPolicy::HandleHeapReadOverflow(AddressSpace *mem, const Address& address,
    uint8_t *byte_out, bool *res, AllocList *alloc_list) {
  return false;
}

bool SymbolicBufferPolicy::HandleHeapReadUnderflow(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) {
  return false;
}

}  //  namespace native
}  //  namespace klee

