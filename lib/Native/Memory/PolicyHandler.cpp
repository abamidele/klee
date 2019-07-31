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

  bool ReportErrorPolicyHandler::HandleHeapWriteOverflow(AddressSpace *mem, const Address& address) {
    LOG(ERROR)
        << "Heap address overflow on memory write address "
        << std::hex << address.flat << std::dec;
    return false;
  }

  bool ReportErrorPolicyHandler::HandleHeapWriteUnderflow(AddressSpace *mem, const Address& address) {
    LOG(ERROR)
        << "Heap address underflow on memory write address "
        << std::hex << address.flat << std::dec;
    return false;
  }

  bool ReportErrorPolicyHandler::HandleHeapReadOverflow(AddressSpace *mem, const Address& address,  uint8_t *byte_out) {
    LOG(ERROR)
        << "Heap address overflow on memory read address "
        << std::hex << address.flat << std::dec;
    *byte_out = 0;
    return true;
  }

  bool ReportErrorPolicyHandler::HandleHeapReadUnderflow(AddressSpace *mem, const Address& address) {
    LOG(ERROR)
        << "Heap address underflow on memory read address "
        << std::hex << address.flat << std::dec;
    return false;
  }

  bool ReportErrorPolicyHandler::HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem, const Address& address) {
    LOG(ERROR)
        << "Invalid memory read address " << std::hex << address.flat << std::dec
        << "; out-of-bounds allocation index";
    return false;
  }

  bool ReportErrorPolicyHandler::HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem, const Address& address) {
    LOG(ERROR)
        << "Invalid memory write address " << std::hex << address.flat << std::dec
        << "; out-of-bounds allocation index";
    return false;
  }

  bool ReportErrorPolicyHandler::HandleReadUseAfterFree(AddressSpace *mem, const Address& address) {
    LOG(ERROR)
        << "Use-after-free on memory read addresss "
        << std::hex << address.flat << std::dec;
    return false;
  }

  bool ReportErrorPolicyHandler::HandleWriteUseAfterFree(AddressSpace *mem, const Address& address) {
    LOG(ERROR)
        << "Use-after-free on memory write addresss "
        << std::hex << address.flat << std::dec;
    return false;
  }

  bool ReportErrorPolicyHandler::HandlePseudoUseAfterFree(AddressSpace *mem,
      const Address& address) {
    LOG(ERROR)
        << "Error in memory implementation; pseudo-use-after-free on "
        << std::hex << address.flat << std::dec
        << " (size=" << address.size << ", entry=" << address.alloc_index
        << ")";
    return false;
  }

  bool ReportErrorPolicyHandler::HandleDoubleFree(AddressSpace *mem, const Address& address) {
    LOG(ERROR)
        << "Double free on " << std::hex << address.flat << std::dec
        << " (size=" << address.size << ", entry=" << address.alloc_index << ")";
    return true;  // To let it continue.
  }

  void ReportErrorPolicyHandler::HandleFreeOffset(AddressSpace *mem, const Address& address) {
    LOG(ERROR)
        << "Freeing internal pointer " << std::hex << address.flat << std::dec;
    // TODO(sai): Eventually do something more interesting here.
  }

  bool ReportErrorPolicyHandler::HandleFreeUnallocatedMem(AddressSpace *mem, const Address& address) {
    LOG(ERROR)
        << "Free of unallocated memory (size=" << address.size << ", entry="
        << address.alloc_index << ")";
    return false;
  }

  bool ReportErrorPolicyHandler::HandleTryExecuteHeapMem(AddressSpace *mem, const Address& address) {
    LOG(ERROR)
        << "Trying to execute heap-allocated memory at "
        << std::hex << address.flat << std::dec;
    return false;
  }


  uint64_t ReportErrorPolicyHandler::HandleBadRealloc(AddressSpace *mem,
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
    return err_type;
  }

    ProxyPolicyHandler::ProxyPolicyHandler():
        proxy(new ReportErrorPolicyHandler()) {}

    bool ProxyPolicyHandler::HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
        const Address& address) {
      return proxy->HandleInvalidOutOfBoundsHeapRead(mem, address);
    }

    bool ProxyPolicyHandler::HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
        const Address& address) {
      return proxy->HandleInvalidOutOfBoundsHeapWrite(mem, address);
    }

    bool ProxyPolicyHandler::HandleHeapWriteOverflow(AddressSpace *mem, const Address& address) {
      return proxy->HandleHeapWriteOverflow(mem, address);
    }

    bool ProxyPolicyHandler::HandleHeapWriteUnderflow(AddressSpace *mem, const Address& address) {
      return proxy->HandleHeapWriteUnderflow(mem, address);
    }

    bool ProxyPolicyHandler::HandleHeapReadOverflow(AddressSpace *mem, const Address& address,
        uint8_t *byte_out) {
      return proxy->HandleHeapReadOverflow(mem, address, byte_out);
    }

    bool ProxyPolicyHandler::HandleHeapReadUnderflow(AddressSpace *mem, const Address& address) {
      return proxy->HandleHeapReadUnderflow(mem, address);
    }

    bool ProxyPolicyHandler::HandleReadUseAfterFree(AddressSpace *mem, const Address& address) {
      return proxy->HandleReadUseAfterFree(mem, address);
    }

    bool ProxyPolicyHandler::HandleWriteUseAfterFree(AddressSpace *mem, const Address& address) {
      return proxy->HandleWriteUseAfterFree(mem, address);
    }

    bool ProxyPolicyHandler::HandlePseudoUseAfterFree(AddressSpace *mem, const Address& address) {
      return proxy->HandlePseudoUseAfterFree(mem, address);
    }

    bool ProxyPolicyHandler::HandleDoubleFree(AddressSpace *mem, const Address& address) {
      return proxy->HandleDoubleFree(mem, address);
    }

    void ProxyPolicyHandler::HandleFreeOffset(AddressSpace *mem, const Address& address) {
      return proxy->HandleFreeOffset(mem, address);
    }

    bool ProxyPolicyHandler::HandleFreeUnallocatedMem(AddressSpace *mem, const Address& address) {
      return proxy->HandleFreeUnallocatedMem(mem, address);
    }

    bool ProxyPolicyHandler::HandleTryExecuteHeapMem(AddressSpace *mem, const Address& address) {
      return proxy->HandleTryExecuteHeapMem(mem, address);
    }

    uint64_t ProxyPolicyHandler::HandleBadRealloc(AddressSpace *mem, const Address& address,
        size_t alloc_size, uint64_t err_type) {
      return proxy->HandleBadRealloc(mem, address, alloc_size, err_type);
    }

}//  namespace native
}//  namespace klee

