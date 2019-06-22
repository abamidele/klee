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

#include <cstdint>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "Native/Memory/MappedRange.h"
#include "Native/Memory/AllocList.h"
#include "Core/AddressSpace.h"
#include "klee/Expr.h"

struct Memory {};

namespace klee {
namespace native {

using CodeVersion = uint64_t;
using PC = uint64_t;
static const uint8_t kSymbolicByte = 0xff;

// Basic memory implementation.
class AddressSpace : public Memory {
 public:
  AddressSpace(void);

  // Creates a copy/clone of another address space.
  explicit AddressSpace(const AddressSpace &);

  // Kill this address space. This prevents future allocations, and removes
  // all existing ranges.
  void Kill(void);

  // Returns `true` if this address space is "dead".
  bool IsDead(void) const;

  // Returns `true` if the byte at address `addr` is readable,
  // writable, or executable, respectively.
  bool CanRead(uint64_t addr) const;
  bool CanWrite(uint64_t addr) const;
  bool CanExecute(uint64_t addr) const;

  // Get the code version associated with some program counter.
  CodeVersion ComputeCodeVersion(PC pc);

  __attribute__((hot))
  bool TryRead(uint64_t addr, void *val, size_t size);

  __attribute__((hot))
  bool TryWrite(uint64_t addr, const void *val, size_t size);

  // Read/write a byte to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, uint8_t *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, uint8_t val);

  // Read/write a word to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, uint16_t *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, uint16_t val);

  // Read/write a dword to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, uint32_t *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, uint32_t val);

  // Read/write a qword to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, uint64_t *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, uint64_t val);

  // Read/write a float to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, float *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, float val);

  // Read/write a double to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, double *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, double val);

  // Return the virtual address of the memory backing `addr`.
  __attribute__((hot)) void *ToReadWriteVirtualAddress(uint64_t addr);

  // Return the virtual address of the memory backing `addr`.
  __attribute__((hot)) const void *ToReadOnlyVirtualAddress(uint64_t addr);

  // Read a byte as an executable byte. This is used for instruction decoding.
  // Returns `false` if the read failed. This function operates on the state
  // of a page, and may result in broad-reaching cache invalidations.
  __attribute__((hot)) bool TryReadExecutable(uint64_t addr, uint8_t *val);

  // Change the permissions of some range of memory. This can split memory
  // maps.
  void SetPermissions(uint64_t base, size_t size, bool can_read,
                      bool can_write, bool can_exec);

  // Adds a new memory mapping with default read/write permissions.
  void AddMap(uint64_t base, size_t size, const char *name=nullptr,
              uint64_t offset=0);

  // Removes a memory mapping.
  void RemoveMap(uint64_t base, size_t size);

  // Log out the current state of the memory maps.
  void LogMaps(std::ostream &stream) const;

  // Returns `true` if `find` is a mapped address (with any permission).
  bool IsMapped(uint64_t find) const;

  // Find a hole big enough to hold `size` bytes in the address space,
  // such that the hole falls within the bounds `[min, max)`.
  bool FindHole(uint64_t min, uint64_t max, uint64_t size,
                uint64_t *hole) const;

  // Mark some PC in this address space as being a known trace head. This is
  // used for helping the decoder to not repeat past work.
  void MarkAsTraceHead(PC pc);

  // Check to see if a given program counter is a trace head.
  bool IsMarkedTraceHead(PC pc) const;
  
  bool TryFree(uint64_t addr);
  uint64_t TryMalloc(size_t alloc_size);
  uint64_t TryRealloc(uint64_t addr, size_t alloc_size);


 private:
  AddressSpace(AddressSpace &&) = delete;
  AddressSpace &operator=(const AddressSpace &) = delete;
  AddressSpace &operator=(const AddressSpace &&) = delete;

  // Recreate the `range_base_to_index` and `range_limit_to_index` indices.
  void CreatePageToRangeMap(void);

  // Permission checking on page-aligned `addr` values.
  bool CanReadAligned(uint64_t addr) const;
  bool CanWriteAligned(uint64_t addr) const;
  bool CanExecuteAligned(uint64_t addr) const;

  // Find the memory map containing `addr`. If none is found then a "null"
  // map pointer is returned, whose operations will all fail.
  __attribute__((hot)) MappedRange &FindRange(uint64_t addr);
  __attribute__((hot)) MappedRange &FindWNXRange(uint64_t addr);

  // Find the range associated with a page-aligned value of `addr`.
  __attribute__((hot)) MappedRange &FindRangeAligned(uint64_t addr);
  __attribute__((hot)) MappedRange &FindWNXRangeAligned(uint64_t addr);

  // Sorted list of mapped memory page ranges.
  std::vector<MemoryMapPtr> maps;

  // A cache mapping pages accessed to the range.
  using PageCache = std::unordered_map<uint64_t, MemoryMapPtr>;
  PageCache page_to_map;
  PageCache wnx_page_to_map;

  // Minimum allocated address.
  uint64_t min_addr;

  // Mask on addresses (e.g. to make them 32- or 64-bit).
  const uint64_t addr_mask;

  // Invalid memory map covering the whole address space.
  const MemoryMapPtr invalid;

  enum : uint64_t {
    kRangeCacheSize = 256ULL,
    kRangeCacheMask = kRangeCacheSize - 1ULL
  };

  MappedRange *last_map_cache[kRangeCacheSize + 1];
  MappedRange *wnx_last_map_cache[kRangeCacheSize + 1];

  // Sets of pages that are readable, writable, and executable.
  std::unordered_set<uint64_t> page_is_readable;
  std::unordered_set<uint64_t> page_is_writable;
  std::unordered_set<uint64_t> page_is_executable;

  // Set of lifted trace heads observed for this code version.
  std::unordered_set<uint64_t> trace_heads;

  /* an instance of klee's address space to handle symbolic writes and reads
   __remill_read_memory_N and __remill_write_memory_N */
 public:

  // TODO(sai) add symbolic memory addr2symbol set and move this to mapped range 
  // would potentially be better if both symbolic mem and addr2symbol set where
  // in own overarching object
  
  std::unordered_map<uint64_t, ref<klee::Expr>> symbolic_memory;
  std::unordered_map<uint64_t, AllocList> alloc_lists;

  // Is the address space dead? This means that all operations on it
  // will be muted.
  bool is_dead;
};

}  // namespace native
}  // namespace klee
