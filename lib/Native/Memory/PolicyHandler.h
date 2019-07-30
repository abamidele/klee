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

namespace klee {
namespace native {
  class AddressSpace;
  class AllocList;
  union Address;

class PolicyHandler {
  public:
    virtual bool HandleHeapWriteOverflow(AddressSpace *mem, const Address& address);
    virtual bool HandleHeapWriteUnderflow(AddressSpace *mem, const Address& address);
    virtual bool HandleHeapReadOverflow(AddressSpace *mem, const Address& address);
    virtual bool HandleHeapReadUnderflow(AddressSpace *mem, const Address& address);
    virtual bool HandleUseAfterFree(AddressSpace *mem, const Address& address);
    virtual bool HandleDoubleFree(AddressSpace *mem, const Address& address);
    virtual void HandleFreeOffset(AddressSpace *mem, const Address& address);
    virtual bool HandleFreeUnallocatedMem(AddressSpace *mem, const Address& address);
    virtual bool HandleTryExecuteHeapMem(AddressSpace *mem, const Address& address);
    virtual uint64_t HandleBadRealloc(AddressSpace *mem,
        const Address& address, size_t alloc_size, uint64_t err_type);
} ;

}//  namespace native
}//  namespace klee

