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
#include "Native/Memory/AllocList.h"

namespace klee {
namespace native {

uint64_t AllocList::Allocate(Address addr) {

  // Try to re-use a random one.
  size_t free_slot;
  bool found_free = false;

  if (auto max_j = free_list.size()) {
    uint64_t i = static_cast<size_t>(rand()) % max_j;
    for (size_t j = 0; j < max_j; ++j) {
      free_slot = (i + j) % max_j;
      if (free_list[free_slot]) {
        found_free = true;
        break;
      }
    }
  }

  auto mem = new uint8_t[addr.size];

  if (!found_free) {
    addr.alloc_index = allocations.size();
    allocations.emplace_back(mem);
    free_list.push_back(false);

  } else {
    num_free--;
    addr.alloc_index = free_slot;
    allocations[free_slot].reset(mem);
    free_list[free_slot] = false;
  }

  return addr.flat;
}

bool AllocList::TryFree(Address address) {
  auto alloc_index = address.alloc_index;
  if (alloc_index >= free_list.size()) {
    LOG(ERROR)
        << "Free of unallocated memory (size=" << address.size << ", entry="
        << alloc_index << ")";
    return false;
  }

  auto is_free = free_list[alloc_index];

  if (is_free) {
    LOG(ERROR)
        << "Double free on " << std::hex << address.flat << std::dec
        << " (size=" << address.size << ", entry=" << alloc_index << ")";
    return true;  // To let it continue.
  }

  num_free++;
  free_list[alloc_index] = true;
  return true;
}

#define MEMORY_ACCESS_CHECKS(addr, type) \
    Address address = {}; \
    address.flat = addr;\
    const auto alloc_index = address.alloc_index;\
    if (alloc_index >= allocations.size()){\
      LOG(ERROR) << "Invalid Memory Access Error At " << addr;\
      return false; \
    } else if (free_list.at(alloc_index)) {\
      LOG(ERROR) << "UAF Detected Tried To " << type << " Corrupted Data At " << addr;\
      return false;\
    }


bool AllocList::TryRead(uint64_t addr, uint8_t *byte_out) {
  MEMORY_ACCESS_CHECKS(addr, "Read");
  //LOG(INFO) << "TRY READ CASE WAS HIT IN THE ALLOCATOR!!!!";
  //LOG(INFO) << (int)allocations[alloc_index][address.offset];
  *byte_out = allocations[alloc_index][address.offset];
  return true;
}

bool AllocList::TryWrite(uint64_t addr, uint8_t byte) {
  // still need to do a ref count check for copy on write
  MEMORY_ACCESS_CHECKS(addr, "Write");
  auto &alloc_buffer = allocations[alloc_index];
  //LOG(INFO) << "ref count for buffer was " << alloc_buffer.use_count();
  if (alloc_buffer.use_count() > 1) {
    auto old_array = alloc_buffer.get();
    auto new_array = new uint8_t[address.size];
    memcpy(new_array, old_array, address.size);
    alloc_buffer.reset(new_array);
  }

  alloc_buffer[address.offset] = byte;
  //LOG(INFO) << "written byte was " << (int)allocations[alloc_index][address.offset];
  return true;
}

#undef MEMORY_ACCESS_CHECKS

}  // namespace native
}  // namespace klee
