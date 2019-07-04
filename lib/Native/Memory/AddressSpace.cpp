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

#include "Native/Memory/AddressSpace.h"

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <iomanip>
#include <limits>
#include <new>
#include <unordered_map>

#include "remill/Arch/Arch.h"
#include "remill/OS/OS.h"

#include "Native/Util/Compiler.h"
#include "Native/Util/Hash.h"
#include "klee/Expr.h"

DECLARE_bool(verbose);

DEFINE_bool(version_code, false,
    "Use code versioning to track self-modifying code.");

// static FILE *OpenReadAddrs(void) {
//   return fopen("/tmp/read_addrs", "w");
// }

// static FILE * read_addrs = nullptr;

namespace klee {
namespace native {
namespace {
enum : uint64_t {
  kPageSize = 4096ULL, kPageShift = (kPageSize - 1ULL), kPageMask = ~kPageShift
};

static constexpr inline uint64_t AlignDownToPage(uint64_t addr) {
  return addr & kPageMask;
}

static constexpr inline uint64_t RoundUpToPage(uint64_t size) {
  return (size + kPageShift) & kPageMask;
}

static uint64_t GetAddressMask(void) {
  const auto arch = remill::GetTargetArch();
  if (arch->address_size == 32) {
    return 0xFFFFFFFFULL;
  } else {
    return ~0ULL;
  }
}

}  // namespace

AddressSpace::AddressSpace(void) :
    page_to_map(256), wnx_page_to_map(256), min_addr(
        std::numeric_limits<uint64_t>::max()), addr_mask(GetAddressMask()), invalid(
        MappedRange::CreateInvalid(0, addr_mask)), symbolic_memory(), is_dead(
        false) {
  maps.push_back(invalid);
  CreatePageToRangeMap();
}

AddressSpace::AddressSpace(const AddressSpace &parent) :
    maps(parent.maps.size()),
    page_to_map(parent.page_to_map.size()),
    wnx_page_to_map(parent.wnx_page_to_map.size()),
    min_addr(parent.min_addr),
    addr_mask(parent.addr_mask),
    invalid(parent.invalid),
    page_is_readable(parent.page_is_readable),
    page_is_writable(parent.page_is_writable),
    page_is_executable(parent.page_is_executable),
    trace_heads(parent.trace_heads),
    symbolic_memory(parent.symbolic_memory),
    is_dead(parent.is_dead) {

  // Only copy the lists with non-full free lists.
  for (const auto &size_list : parent.alloc_lists) {
    if (size_list.second.num_free == size_list.second.free_list.size()) {
      continue;
    } else {
      alloc_lists.emplace(size_list.first, size_list.second);
    }
  }

  // TODO(sai) add a thing in here that properly copies over the AllocList map
  unsigned i = 0;
  for (const auto &range : parent.maps) {
    if (range->IsValid()) {
      maps[i++] = range->Clone();
    } else {
      maps[i++] = range;
    }
  }

  CreatePageToRangeMap();
}

void AddressSpace::MarkAsTraceHead(PC pc) {
  trace_heads.insert(static_cast<uint64_t>(pc));
}

bool AddressSpace::IsMarkedTraceHead(PC pc) const {
  return 0 != trace_heads.count(static_cast<uint64_t>(pc));
}

static constexpr uint64_t kBadAddr = ~0ULL;
static constexpr uint64_t kReallocInternalPtr = ~0ULL - 1ULL;
static constexpr uint64_t kReallocTooBig = ~0ULL - 2ULL;
static constexpr uint64_t kReallocInvalidPtr = ~0ULL - 3ULL;
static constexpr uint64_t kReallocFreedPtr = ~0ULL - 4ULL;

bool AddressSpace::TryFree(uint64_t addr) {
  Address address = {};
  address.flat = addr;

  if (address.must_be_0x1 != 0x1 ||
      address.must_be_0xa != 0xa) {
    return 0;
  }

  // Realloc of a contained address.
  if (address.offset != 0) {
    // TODO(sais): Report?
    return 0;
  }

  auto &alloc_list = alloc_lists[address.size];
  bool can_free = alloc_list.TryFree(address);
  if (can_free) {
    for (size_t i = 0; i < address.size; ++i) {
      auto sym_byte_pair = symbolic_memory.find(addr + i);
      if (sym_byte_pair != symbolic_memory.end()) {
        symbolic_memory.erase(addr + i);
      }
    }
    return can_free;
  }
  LOG(ERROR) << "Invalid free at address " << addr << " :-(";
  return false;
}

uint64_t AddressSpace::TryMalloc(size_t alloc_size) {
  if (alloc_size == 0) {
    return 0;
  }

  Address address = {};
  address.size = alloc_size;
  LOG(INFO) << "alloc_size: " << alloc_size;
  LOG(INFO) << "address size: " << address.size;

  // The size was truncated, need tro fall back to the real malloc.
  if (address.size != alloc_size) {
    return ~0ULL;
  }

  address.must_be_0x1 = 0x1;
  address.must_be_0xa = 0xa;

  return alloc_lists[alloc_size].Allocate(address);
}

uint64_t AddressSpace::TryRealloc(uint64_t addr, size_t alloc_size) {
  Address address = {};
  address.flat = addr;

  if (address.must_be_0x1 != 0x1 ||
      address.must_be_0xa != 0xa) {
    return kBadAddr;
  }

  // Realloc of a contained address.
  if (address.offset != 0) {
    // TODO(sai): Report?
    LOG(ERROR)
        << "Realloc of internal pointer with size " << address.size
        << ", index " << address.alloc_index << ", and offset "
        << std::hex << address.offset << std::dec;
    return kReallocInternalPtr;
  }

  Address new_address = {};
  new_address.size = alloc_size;
  if (new_address.size != alloc_size) {
    LOG(ERROR)
        << "Realloc of size " << address.size << " to " << alloc_size
        << " has to be handled by native.";
    return kReallocTooBig;
  }

  if (address.size == alloc_size) {
    return addr;
  }

  auto &old_alloc_list = alloc_lists[address.size];
  auto &new_alloc_list = alloc_lists[alloc_size];

  const auto old_size = address.size;
  const auto old_alloc_index = address.alloc_index;

  if (old_alloc_index >= old_alloc_list.allocations.size()) {
    LOG(ERROR) << "Bad old realloc address";
    return kReallocInvalidPtr;
  }

  if (old_alloc_list.free_list[old_alloc_index]) {
    LOG(ERROR) << "Cannot realloc on a freed memory region";
    return kReallocFreedPtr;
  }

  const auto new_addr = new_alloc_list.Allocate(new_address);
  new_address.flat = new_addr;

  // Migrate the old data.
  auto &old_bytes = old_alloc_list.allocations[old_alloc_index];
  auto &new_bytes = new_alloc_list.allocations[new_address.alloc_index];
  const auto it_end = symbolic_memory.end();
  for (size_t i = 0; i < old_size; ++i) {
    uint8_t byte = old_bytes[i];
    if (byte == kSymbolicByte) {
      auto it = symbolic_memory.find(addr + i);
      if (it != it_end) {
        symbolic_memory[new_addr + i] = it->second;
        symbolic_memory.erase(it->first);
      }
    }
    new_bytes[i] = byte;
  }

  CHECK(TryFree(addr));
  return new_address.flat;
}

// Clear out the contents of this address space.
void AddressSpace::AddressSpace::Kill(void) {
  if (is_dead) {
    return;
  }
  maps.clear();
  page_to_map.clear();
  symbolic_memory.clear();
  page_is_readable.clear();
  page_is_writable.clear();
  page_is_executable.clear();
  trace_heads.clear();
  is_dead = true;
  memset(last_map_cache, 0, sizeof(last_map_cache));
  memset(wnx_last_map_cache, 0, sizeof(wnx_last_map_cache));
}

// Returns `true` if this address space is "dead".
bool AddressSpace::IsDead(void) const {
  return is_dead;
}

bool AddressSpace::CanRead(uint64_t addr) const {
  Address address = { };
  address.flat = addr;
  if (address.must_be_0xa == 0xa &&
      address.must_be_0x1 == 0x1) {
    return true;
  }
  return page_is_readable.count(AlignDownToPage(addr & addr_mask));
}

bool AddressSpace::CanWrite(uint64_t addr) const {
  Address address = { };
  address.flat = addr;
  if (address.must_be_0xa == 0xa &&
      address.must_be_0x1 == 0x1) {
    return true;
  }
  return page_is_writable.count(AlignDownToPage(addr & addr_mask));
}

bool AddressSpace::CanExecute(uint64_t addr) const {
  return page_is_executable.count(AlignDownToPage(addr & addr_mask));
}

bool AddressSpace::CanReadAligned(uint64_t addr) const {
  Address address = { };
  address.flat = addr;
  if (address.must_be_0xa == 0xa &&
      address.must_be_0x1 == 0x1) {
    return true;
  }
  return page_is_readable.count(addr);
}

bool AddressSpace::CanWriteAligned(uint64_t addr) const {
  Address address = { };
  address.flat = addr;
  if (address.must_be_0xa == 0xa &&
      address.must_be_0x1 == 0x1) {
    return true;
  }
  return page_is_writable.count(addr);
}

bool AddressSpace::CanExecuteAligned(uint64_t addr) const {
  return page_is_executable.count(addr);
}

bool AddressSpace::TryRead(uint64_t addr_, void *val_out, size_t size) {
  //LOG(INFO) << "HIT TRY READ CASE !!!";
  auto addr = addr_ & addr_mask;
  auto out_stream = reinterpret_cast<uint8_t *>(val_out);
  Address address = { };
  address.flat = addr;
  if (address.must_be_0xa == 0xa) {
    //LOG(INFO) << "HIT THE HEAP READ CASE !!!!!";
    auto alloc_list_pair = alloc_lists.find(address.size);
    if (alloc_list_pair == alloc_lists.end()) {
      LOG(ERROR) << "Invalid Memory Access In Malloced Memory Region On Read";
      return false;
    }
    for (size_t offset = 0; offset < size; ++offset) {
      if (alloc_list_pair->second.TryRead(addr + offset, out_stream++)) {
      } else {
        return false;
      }
    }
    return true;

  } else {
    for (auto page_addr = AlignDownToPage(addr), end_addr = addr + size;
        page_addr < end_addr; page_addr += kPageSize) {

      auto &range = FindRangeAligned(page_addr);
      auto page_end_addr = page_addr + kPageSize;
      auto next_end_addr = std::min(end_addr, page_end_addr);
      while (addr < next_end_addr) {
        if (!range.Read(addr++, out_stream++)) {
          return false;
        }
      }
    }
    return true;
  }
}

bool AddressSpace::TryWrite(uint64_t addr_, const void *val, size_t size) {
  auto addr = addr_ & addr_mask;
  auto in_stream = reinterpret_cast<const uint8_t *>(val);
  Address address = { };
  address.flat = addr;

  if (address.must_be_0xa == 0xa && address.must_be_0x1 == 0x1) {

    auto alloc_list_pair = alloc_lists.find(address.size);
    if (alloc_list_pair == alloc_lists.end()) {
      LOG(ERROR) << "SIZE IS " << address.size;
      for (auto& pairs: alloc_lists){
        LOG(ERROR) << "size : " << pairs.first;
      }
      LOG(ERROR) << "Invalid Memory Access In Malloced Memory Region On Write";
      return false;
    }
    for (size_t offset = 0; offset < size; ++offset) {
      if (alloc_list_pair->second.TryWrite(addr + offset, *in_stream++)) {
      } else {
        return false;
      }
    }
    return true;
  } else {
    for (auto page_addr = AlignDownToPage(addr), end_addr = addr + size;
         page_addr < end_addr; page_addr += kPageSize) {

      if (!CanWriteAligned(page_addr)) {
        return false;
      }

      auto &range = FindRangeAligned(page_addr);
      if (FLAGS_version_code && CanExecuteAligned(page_addr)) {

        // TODO(pag): remove cache entries associated with this range
        // TODO(pag): Split the range?

        range.InvalidateCodeVersion();
        trace_heads.clear();
      }

      auto page_end_addr = page_addr + kPageSize;
      auto next_end_addr = std::min(end_addr, page_end_addr);

      while (addr < next_end_addr) {
        if (!range.Write(addr++, *in_stream++)) {
          return false;
        }
      }
    }
    return true;
  }
}

// Read/write a byte to memory.
bool AddressSpace::TryRead(uint64_t addr_, uint8_t *val_out) {
  const auto addr = addr_ & addr_mask;
  auto out_stream = reinterpret_cast<uint8_t *>(val_out);
  Address address = { };
  address.flat = addr;
  if (address.must_be_0xa == 0xa && address.must_be_0x1 == 0x1) {
    //LOG(INFO) << "HIT THE HEAP READ CASE !!!!!";
    auto alloc_list_pair = alloc_lists.find(address.size);
    if (alloc_list_pair == alloc_lists.end()) {
      LOG(ERROR) << "Invalid Memory Access In Malloced Memory Region On Read";
      return false;
    }

    if (alloc_list_pair->second.TryRead(addr, out_stream++)) {
      //LOG(INFO) << "try read was successful";
      return true;
    } else {
      //LOG(INFO) << "try read failed";
      return false;
    }
  }
  return FindRange(addr).Read(addr, val_out);
}

#define MAKE_TRY_READ(type) \
		bool AddressSpace::TryRead(uint64_t addr_, type *val_out) { \
	const auto addr = addr_ & addr_mask; \
	Address address = {}; \
	address.flat = addr; \
	if (address.must_be_0xa == 0xa && address.must_be_0x1 == 0x1) { \
		return TryRead(addr, val_out, sizeof(type)); \
		\
	} else { \
		auto &range = FindRange(addr); \
		auto ptr = reinterpret_cast<const type *>( \
				range.ToReadOnlyVirtualAddress(addr)); \
				if (unlikely(ptr == nullptr)) { \
					return false; \
				} \
				const auto end_addr = addr + sizeof(type) - 1; \
				if (likely(range.BaseAddress() <= addr && \
						end_addr < range.LimitAddress())) { \
					if (likely(AlignDownToPage(addr) == AlignDownToPage(end_addr))) { \
						*val_out = *ptr; \
						return true; \
					} \
				} \
				return TryRead(addr, val_out, sizeof(type)); \
	} \
} \

MAKE_TRY_READ(uint16_t)
MAKE_TRY_READ(uint32_t)
MAKE_TRY_READ(uint64_t)
MAKE_TRY_READ(float)
MAKE_TRY_READ(double)

#undef MAKE_TRY_READ

bool AddressSpace::TryWrite(uint64_t addr_, uint8_t val) {
  const auto addr = addr_ & addr_mask;
  if (likely(FindWNXRange(addr).Write(addr, val))) {
    return true;
  } else {
    return TryWrite(addr, &val, sizeof(val));
  }
}

#define MAKE_TRY_WRITE(type) \
		bool AddressSpace::TryWrite(uint64_t addr_, type val) { \
	const auto addr = addr_ & addr_mask; \
	auto &range = FindWNXRange(addr); \
	auto ptr = reinterpret_cast<type *>( \
			range.ToReadWriteVirtualAddress(addr)); \
			if (likely(ptr != nullptr)) { \
				const auto end_addr = addr + sizeof(type) - 1; \
				if (likely(range.BaseAddress() <= addr && \
						end_addr < range.LimitAddress())) { \
					if (likely(AlignDownToPage(addr) == AlignDownToPage(end_addr))) { \
						*ptr = val; \
						return true; \
					} \
				} \
			} \
			const auto out_stream = reinterpret_cast<const uint8_t *>(&val); \
			return TryWrite(addr, out_stream, sizeof(type)); \
}

MAKE_TRY_WRITE(uint16_t)
MAKE_TRY_WRITE(uint32_t)
MAKE_TRY_WRITE(uint64_t)
MAKE_TRY_WRITE(float)
MAKE_TRY_WRITE(double)
#undef MAKE_TRY_WRITE

// Return the virtual address of the memory backing `addr`.
void *AddressSpace::ToReadWriteVirtualAddress(uint64_t addr_) {
  const auto addr = addr_ & addr_mask;
  return FindRange(addr).ToReadWriteVirtualAddress(addr);
}

// Return the virtual address of the memory backing `addr`.
const void *AddressSpace::ToReadOnlyVirtualAddress(uint64_t addr_) {
  const auto addr = addr_ & addr_mask;
  return FindRange(addr).ToReadOnlyVirtualAddress(addr);
}

// Read a byte as an executable byte. This is used for instruction decoding.
bool AddressSpace::TryReadExecutable(PC pc, uint8_t *val) {
  // if (!read_addrs) {
  //   read_addrs = OpenReadAddrs();
  // }
  auto addr = static_cast<uint64_t>(pc) & addr_mask;
  auto page_addr = AlignDownToPage(addr);
  auto &range = FindRangeAligned(page_addr);
  return range.Read(addr, val) && CanExecuteAligned(page_addr);
}

namespace {

// Return a vector of memory maps, where none of the maps overlap with the
// range of memory `[base, limit)`.
static std::vector<MemoryMapPtr> RemoveRange(
    const std::vector<MemoryMapPtr> &ranges, uint64_t base, uint64_t limit) {

  std::vector<MemoryMapPtr> new_ranges;
  new_ranges.reserve(ranges.size() + 1);

  DLOG_IF(INFO, FLAGS_verbose)<< "  RemoveRange: [" << std::hex << base << ", "
  << std::hex << limit << ") from list of "
  << ranges.size() << " ranges";

  for (auto &map : ranges) {
    auto map_base_address = map->BaseAddress();
    auto map_limit_address = map->LimitAddress();

    // No overlap between `map` and the range to remove.
    if (map_limit_address <= base || map_base_address >= limit) {
      DLOG_IF(INFO, FLAGS_verbose)<< "    Keeping with no overlap ["
      << std::hex << map_base_address << ", "
      << std::hex << map_limit_address << ")";
      new_ranges.push_back(map);

      // `map` is fully contained in the range to remove.
    } else if (map_base_address >= base && map_limit_address <= limit) {
      DLOG_IF(INFO, FLAGS_verbose)
      << "    Removing with full containment ["
      << std::hex << map_base_address << ", "
      << std::hex << map_limit_address << ")";
      continue;

      // The range to remove is fully contained in `map`.
    } else if (map_base_address < base && map_limit_address > limit) {
      DLOG_IF(INFO, FLAGS_verbose)
      << "    Splitting with overlap ["
      << std::hex << map_base_address << ", "
      << std::hex << map_limit_address << ") into "
      << "[" << std::hex << map_base_address << ", "
      << std::hex << base << ") and ["
      << std::hex << limit << ", " << std::hex << map_limit_address << ")";

      new_ranges.push_back(map->Copy(map_base_address, base));
      new_ranges.push_back(map->Copy(limit, map_limit_address));

      // The range to remove is a prefix of `map`.
    } else if (map_base_address == base) {
      DLOG_IF(INFO, FLAGS_verbose)
      << "    Keeping prefix [" << std::hex << limit << ", "
      << std::hex << map_limit_address << ")";
      new_ranges.push_back(map->Copy(limit, map_limit_address));

      // The range to remove is a suffix of `map`.
    } else {
      DLOG_IF(INFO, FLAGS_verbose)
      << "    Keeping suffix ["
      << std::hex << map_base_address << ", "
      << std::hex << base << ")";
      new_ranges.push_back(map->Copy(map_base_address, base));
    }
  }

  return new_ranges;
}

}  // namespace

void AddressSpace::SetPermissions(uint64_t base_, size_t size, bool can_read,
    bool can_write, bool can_exec) {
  const auto base = AlignDownToPage(base_);
  const auto limit = base + RoundUpToPage(size);

  for (auto addr = base; addr < limit; addr += kPageSize) {
    if (can_read) {
      page_is_readable.insert(addr);
    } else {
      page_is_readable.erase(addr);
    }

    if (can_write) {
      page_is_writable.insert(addr);
    } else {
      page_is_writable.erase(addr);
    }

    if (can_exec) {
      page_is_executable.insert(addr);
    } else {
      page_is_executable.erase(addr);
    }
  }
  CreatePageToRangeMap();
}

void AddressSpace::AddMap(uint64_t base_, size_t size, const char *name,
    uint64_t offset) {
  auto base = AlignDownToPage(base_);
  auto limit = std::min(base + RoundUpToPage(size), addr_mask);

  if (unlikely(is_dead)) {
    LOG(ERROR) << "Trying to map range [" << std::hex << base << ", " << limit
        << ") in destroyed address space." << std::dec;
    return;
  }

  CHECK((base & addr_mask) == base)<< "Base address " << std::hex << base << " cannot fit into mask "
  << addr_mask << std::dec << "; are you trying to map a 64-bit address "
  << "into a 32-bit address space?";

  LOG(INFO) << "Mapping range [" << std::hex << base << ", " << limit << ")"
      << std::dec;

  auto new_map = MappedRange::Create(base, limit, name, offset);

  CHECK(!maps.empty());

  auto old_ranges = RemoveRange(maps, base, limit);
  if (old_ranges.size() < maps.size()) {
    LOG(INFO) << "New map [" << std::hex << base << ", " << limit << ")"
        << " overlapped with " << std::dec << (maps.size() - old_ranges.size())
        << " existing maps";
  }
  maps.swap(old_ranges);
  maps.push_back(new_map);
  SetPermissions(base, limit - base, true, true, false);
}

void AddressSpace::RemoveMap(uint64_t base_, size_t size) {
  auto base = AlignDownToPage(base_);
  auto limit = std::min(base + RoundUpToPage(size), addr_mask);

  if (unlikely(is_dead)) {
    LOG(ERROR) << "Trying to map range [" << std::hex << base << ", " << limit
        << ") in destroyed address space." << std::dec;
    return;
  }

  CHECK((base & addr_mask) == base)<< "Base address " << std::hex << base << " cannot fit into mask "
  << addr_mask << std::dec << "; are you trying to remove a 64-bit address "
  << "from a 32-bit address space?";

  LOG(INFO) << "Unmapping range [" << std::hex << base << ", " << limit << ")"
      << std::dec;

  auto new_map = MappedRange::CreateInvalid(base, limit);
  CHECK(!maps.empty());
  auto old_ranges = RemoveRange(maps, base, limit);
  if (old_ranges.size() < maps.size()) {
    LOG(INFO) << "New invalid map [" << std::hex << base << ", " << limit << ")"
        << " overlapped with " << std::dec << (maps.size() - old_ranges.size())
        << " existing maps";
  }
  maps.swap(old_ranges);
  maps.push_back(new_map);
  SetPermissions(base, limit - base, false, false, false);
}

// Returns `true` if `find` is a mapped address (with any permission).
bool AddressSpace::IsMapped(uint64_t find) const {
  Address address = { };
  address.flat = find;
  if (address.must_be_0xa == 0xa) {
    return true;
  }
  if (is_dead) {
    return false;
  }

  auto it = page_to_map.find(AlignDownToPage(find));
  if (it == page_to_map.end()) {
    return false;
  }

  auto &range = it->second;
  return range->IsValid();
}

// Find a hole big enough to hold `size` bytes in the address space,
// such that the hole falls within the bounds `[min, max)`.
bool AddressSpace::FindHole(uint64_t min, uint64_t max, uint64_t size,
    uint64_t *hole) const {
  *hole = 0;
  if (!size) {
    return false;
  }

  min = AlignDownToPage(min);
  max = AlignDownToPage(max);
  if (min >= max) {
    return false;
  }

  size = RoundUpToPage(size);
  if (size > (max - min)) {
    return false;
  }

  // Note: There are tombstone ranges bracketing the other ranges.

  auto it = maps.rbegin();
  auto it_end = maps.rend();

  while (it != it_end) {
    const auto &range_high = *it++;
    uint64_t high_base = 0;
    uint64_t low_limit = 0;

    // Might be able to find a hole in this invalid map.
    if (!range_high->IsValid()) {
      high_base = range_high->LimitAddress();
      low_limit = range_high->BaseAddress();

    } else if (it == it_end) {
      break;

    } else {
      high_base = range_high->BaseAddress();

      const auto &range_low = *it;
      low_limit = range_low->LimitAddress();
    }

    if (high_base < min) {
      break;
    }

    CHECK(low_limit <= high_base);

    // No overlap in our range.
    if (low_limit >= max) {
      continue;
    }

    const auto alloc_max = std::min(max, high_base);
    const auto alloc_min = std::max(min, low_limit);
    const auto avail_size = alloc_max - alloc_min;
    if (avail_size < size) {
      continue;
    }

    *hole = alloc_max - size;
    CHECK(*hole >= alloc_min);
    return true;
  }

  return false;
}

void AddressSpace::CreatePageToRangeMap(void) {
  page_to_map.clear();
  wnx_page_to_map.clear();
  memset(last_map_cache, 0, sizeof(last_map_cache));
  memset(wnx_last_map_cache, 0, sizeof(wnx_last_map_cache));

  auto old_read_size = page_to_map.size();
  auto old_write_size = wnx_page_to_map.size();

  page_to_map.reserve(old_read_size);
  wnx_page_to_map.reserve(old_write_size);

  std::sort(maps.begin(), maps.end(),
      [=] (const MemoryMapPtr &left, const MemoryMapPtr &right) {
        return left->BaseAddress() < right->BaseAddress();
      });

  min_addr = std::numeric_limits<uint64_t>::max();

  for (const auto &map : maps) {
    if (!map->IsValid()) {
      continue;
    }

    const auto base_address = map->BaseAddress();
    const auto limit_address = map->LimitAddress();

    min_addr = std::min(min_addr, base_address);
    for (auto addr = base_address; addr < limit_address; addr += kPageSize) {

      auto can_read = CanReadAligned(addr);
      auto can_write = CanWriteAligned(addr);
      auto can_exec = CanExecuteAligned(addr);

      if (can_read || can_write || can_exec) {
        page_to_map[addr] = map;
      }

      if (can_write && !can_exec) {
        wnx_page_to_map[addr] = map;
      }
    }
  }
}

// Get the code version associated with some program counter.
CodeVersion AddressSpace::ComputeCodeVersion(PC pc) {
  if (FLAGS_version_code) {
    auto masked_pc = static_cast<uint64_t>(pc) & addr_mask;
    return FindRange(masked_pc).ComputeCodeVersion();
  } else {
    return static_cast<CodeVersion>(0);
  }
}

MappedRange &AddressSpace::FindRange(uint64_t addr) {
  return FindRangeAligned(AlignDownToPage(addr));
}

enum : uint64_t {
  kRangeCachePageShift = 26ULL,
};

MappedRange &AddressSpace::FindRangeAligned(uint64_t page_addr) {
  auto last_range = last_map_cache[kRangeCacheSize];
  if (likely(last_range && last_range->Contains(page_addr))) {
    return *last_range;
  }

  const auto cache_index = (page_addr >> 12) & kRangeCacheMask;

  last_range = last_map_cache[cache_index];
  if (likely(last_range && last_range->Contains(page_addr))) {
    last_map_cache[kRangeCacheSize] = last_range;
    return *last_range;
  }

  auto it = page_to_map.find(page_addr);
  if (likely(it != page_to_map.end())) {
    last_range = it->second.get();
    last_map_cache[kRangeCacheSize] = last_range;
    last_map_cache[cache_index] = last_range;
    return *last_range;
  } else {
    return *invalid;
  }
}

MappedRange &AddressSpace::FindWNXRange(uint64_t addr) {
  return FindWNXRangeAligned(AlignDownToPage(addr));
}

MappedRange &AddressSpace::FindWNXRangeAligned(uint64_t page_addr) {
  auto last_range = wnx_last_map_cache[kRangeCacheSize];
  if (likely(last_range && last_range->Contains(page_addr))) {
    return *last_range;
  }

  const auto cache_index = (page_addr >> 12) & kRangeCacheMask;

  last_range = wnx_last_map_cache[cache_index];
  if (likely(last_range && last_range->Contains(page_addr))) {
    wnx_last_map_cache[kRangeCacheSize] = last_range;
    return *last_range;
  }

  auto it = wnx_page_to_map.find(page_addr);
  if (likely(it != wnx_page_to_map.end())) {
    last_range = it->second.get();
    wnx_last_map_cache[kRangeCacheSize] = last_range;
    wnx_last_map_cache[cache_index] = last_range;
    return *last_range;
  } else {
    return *invalid;
  }
}

// Log out the current state of the memory maps.
void AddressSpace::LogMaps(std::ostream &os) const {
  auto arch = remill::GetTargetArch();

  os << "Memory maps:" << std::endl;
  for (const auto &range : maps) {
    if (!range->IsValid()) {
      continue;
    }
    std::stringstream ss;
    auto flags = ss.flags();
    ss << "  [" << std::hex << std::setw((int32_t) (arch->address_size / 4))
        << std::setfill('0') << range->BaseAddress() << ", " << std::hex
        << std::setw((int32_t) (arch->address_size) / 4) << std::setfill('0')
        << range->LimitAddress() << ")";
    ss.setf(flags);

    auto virt = range->ToReadOnlyVirtualAddress(range->BaseAddress());
    if (virt) {
      ss << " at " << virt;
    }

    auto name = range->Name();
    auto offset = range->Offset();
    if (name && name[0]) {
      ss << " from " << name;
      if (offset) {
        ss << " (offset " << std::hex << offset << ")";
      }
    }

    ss << " implemented by " << range->Provider();

    os << ss.str() << std::endl;
  }
}
}  // namespace native
}  // namespace klee
