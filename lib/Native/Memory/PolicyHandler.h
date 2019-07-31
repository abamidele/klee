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
#pragma once

namespace klee {
namespace native {
class AddressSpace;
class AllocList;
union Address;

class PolicyHandler {
public:
  PolicyHandler() = default;
  virtual ~PolicyHandler() = default;
  virtual bool HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
      const Address& address) = 0;
  virtual bool HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
      const Address& address) = 0;
  virtual bool HandleHeapWriteOverflow(AddressSpace *mem,
      const Address& address) = 0;
  virtual bool HandleHeapWriteUnderflow(AddressSpace *mem,
      const Address& address) = 0;
  virtual bool HandleHeapReadOverflow(AddressSpace *mem, const Address& address,
      uint8_t *byte_out) = 0;
  virtual bool HandleHeapReadUnderflow(AddressSpace *mem,
      const Address& address) = 0;
  virtual bool HandleReadUseAfterFree(AddressSpace *mem,
      const Address& address) = 0;
  virtual bool HandleWriteUseAfterFree(AddressSpace *mem,
      const Address& address) = 0;
  virtual bool HandlePseudoUseAfterFree(AddressSpace *mem,
      const Address& address) = 0;
  virtual bool HandleDoubleFree(AddressSpace *mem, const Address& address) = 0;
  virtual void HandleFreeOffset(AddressSpace *mem, const Address& address) = 0;
  virtual bool HandleFreeUnallocatedMem(AddressSpace *mem,
      const Address& address) = 0;
  virtual bool HandleTryExecuteHeapMem(AddressSpace *mem,
      const Address& address) = 0;
  virtual uint64_t HandleBadRealloc(AddressSpace *mem, const Address& address,
      size_t alloc_size, uint64_t err_type) = 0;

};

class ReportErrorPolicyHandler: public PolicyHandler {
public:
  ReportErrorPolicyHandler() = default;
  bool HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
      const Address& address) override;
  bool HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
      const Address& address) override;
  bool HandleHeapWriteOverflow(AddressSpace *mem, const Address& address) override;
  bool HandleHeapWriteUnderflow(AddressSpace *mem, const Address& address) override;
  bool HandleHeapReadOverflow(AddressSpace *mem, const Address& address,
      uint8_t *byte_out) override;
  bool HandleHeapReadUnderflow(AddressSpace *mem, const Address& address) override;
  bool HandleReadUseAfterFree(AddressSpace *mem, const Address& address) override;
  bool HandleWriteUseAfterFree(AddressSpace *mem, const Address& address) override;
  bool HandlePseudoUseAfterFree(AddressSpace *mem, const Address& address) override;
  bool HandleDoubleFree(AddressSpace *mem, const Address& address) override;
  void HandleFreeOffset(AddressSpace *mem, const Address& address) override;
  bool HandleFreeUnallocatedMem(AddressSpace *mem, const Address& address) override;
  bool HandleTryExecuteHeapMem(AddressSpace *mem, const Address& address) override;
  uint64_t HandleBadRealloc(AddressSpace *mem, const Address& address,
      size_t alloc_size, uint64_t err_type) override;

};

class ProxyPolicyHandler: public PolicyHandler {
public:
  ProxyPolicyHandler();
  bool HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
      const Address& address) override;
  bool HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
      const Address& address) override;
  bool HandleHeapWriteOverflow(AddressSpace *mem, const Address& address) override;
  bool HandleHeapWriteUnderflow(AddressSpace *mem, const Address& address) override;
  bool HandleHeapReadOverflow(AddressSpace *mem, const Address& address,
      uint8_t *byte_out) override;
  bool HandleHeapReadUnderflow(AddressSpace *mem, const Address& address) override;
  bool HandleReadUseAfterFree(AddressSpace *mem, const Address& address) override;
  bool HandleWriteUseAfterFree(AddressSpace *mem, const Address& address) override;
  bool HandlePseudoUseAfterFree(AddressSpace *mem, const Address& address) override;
  bool HandleDoubleFree(AddressSpace *mem, const Address& address) override;
  void HandleFreeOffset(AddressSpace *mem, const Address& address) override;
  bool HandleFreeUnallocatedMem(AddressSpace *mem, const Address& address) override;
  bool HandleTryExecuteHeapMem(AddressSpace *mem, const Address& address) override;
  uint64_t HandleBadRealloc(AddressSpace *mem, const Address& address,
      size_t alloc_size, uint64_t err_type) override;

  std::unique_ptr<PolicyHandler> proxy;
};

class SymbolicBufferPolicy: public ProxyPolicyHandler {
  SymbolicBufferPolicy() = default;
  bool HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
      const Address& address) override;
  bool HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
      const Address& address) override;
  bool HandleHeapWriteOverflow(AddressSpace *mem, const Address& address) override;
  bool HandleHeapWriteUnderflow(AddressSpace *mem, const Address& address) override;
  bool HandleHeapReadOverflow(AddressSpace *mem, const Address& address,
      uint8_t *byte_out) override;
  bool HandleHeapReadUnderflow(AddressSpace *mem, const Address& address) override;
};


} //  namespace native
} //  namespace klee

