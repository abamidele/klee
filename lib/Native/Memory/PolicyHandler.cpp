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

namespace klee {
namespace native {

  bool PolicyHandler::HandleHeapWriteOverflow(AddressSpace *mem, const Address& address){
    LOG(ERROR)
        << "Heap address overflow on memory write address "
        << std::hex << address.flat << std::dec;
    return false;
  }

  bool PolicyHandler::HandleHeapWriteUnderflow(AddressSpace *mem, const Address& address){
    LOG(ERROR)
        << "Heap address underflow on memory write address "
        << std::hex << address.flat << std::dec;
    return false;
  }

  bool PolicyHandler::HandleHeapReadOverflow(AddressSpace *mem, const Address& address){
    LOG(ERROR)
        << "Heap address overflow on memory read address "
        << std::hex << address.flat << std::dec;
    return true;
  }

  bool PolicyHandler::HandleHeapReadUnderflow(AddressSpace *mem, const Address& address){
    LOG(ERROR)
        << "Heap address underflow on memory read address "
        << std::hex << address.flat << std::dec;
    return false;
  }

  bool PolicyHandler::HandleUseAfterFree(AddressSpace *mem, const Address& address){
    LOG(ERROR)
        << "Use-after-free on memory read addresss "
        << std::hex << address.flat << std::dec;
    return false;
  }

  bool PolicyHandler::HandleDoubleFree(AddressSpace *mem, const Address& address){
    LOG(ERROR)
        << "Use-after-free on memory write addresss "
        << std::hex << address.flat << std::dec;
    return false;
  }

  void PolicyHandler::HandleFreeOffset(AddressSpace *mem, const Address& address){
    LOG(ERROR)
        << "Freeing internal pointer " << std::hex << address.flat << std::dec;
    // TODO(sai): Eventually do something more interesting here.
  }

  bool PolicyHandler::HandleFreeUnallocatedMem(AddressSpace *mem, const Address& address){
    LOG(ERROR)
        << "Free of unallocated memory (size=" << address.size << ", entry="
        << address.alloc_index << ")";
    return false;
  }

  bool HandleTryExecuteHeapMem(AddressSpace *mem, const Address& address){
    LOG(ERROR)
        << "Trying to execute heap-allocated memory at "
        << std::hex << address.flat << std::dec;
    return false;
  }

  const uint64_t HandleBadInternalRealloc(AddressSpace *mem, const Address& address){
    LOG(ERROR)
        << "Realloc of internal pointer with size " << address.size
        << ", index " << address.alloc_index << ", and offset "
        << std::hex << address.offset << std::dec;

    return kReallocInternalPtr;
  }

  const uint64_t HandleBadRealloc(AddressSpace *mem,
      const Address& address, size_t alloc_size, uint64_t err_type) {
    switch (err_type) {
      case (kReallocInternalPtr): {
        // TODO(sai): Report?
        LOG(ERROR)
            << "Realloc of internal pointer with size " << address.size
            << ", index " << address.alloc_index << ", and offset "
            << std::hex << address.offset << std::dec;

        return kReallocInternalPtr;
      }
      case (kReallocInvalidPtr): {
        LOG(ERROR)
            << "Bad old realloc address";
        return kReallocInvalidPtr;
      }
      case (kReallocFreedPtr): {
        LOG(ERROR)
            << "Cannot realloc on a freed memory region";
        return kReallocFreedPtr;
      }
    }
  }

}//  namespace native
}//  namespace klee

