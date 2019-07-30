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
#include "Native/Memory/PolicyHandler.h"

namespace klee {
namespace native {

static const unsigned kMinNumFree = 32;

uint64_t AllocList::Allocate(Address addr) {

  // Try to re-use a random one.
  size_t free_slot = 0;
  bool found_free = false;

  if (num_free >= kMinNumFree) {
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
  }

  auto mem = std::make_shared<std::vector<uint8_t>>();
  mem->resize(addr.size);

  if (!found_free) {
    addr.alloc_index = allocations.size();
    allocations.emplace_back(std::move(mem));
    free_list.push_back(false);

  } else {
    num_free--;
    addr.alloc_index = free_slot;
    allocations[free_slot] = std::move(mem);
    free_list[free_slot] = false;
  }

  return addr.flat;
}

bool AllocList::TryFree(Address address, AddressSpace *mem,  PolicyHandler &policy_handler) {
  auto alloc_index = address.alloc_index;
  if (alloc_index >= free_list.size()) {
    return policy_handler.HandleFreeUnallocatedMem(mem, address);
  }

  auto is_free = free_list[alloc_index];

  if (is_free) {
    LOG(ERROR)
        << "Double free on " << std::hex << address.flat << std::dec
        << " (size=" << address.size << ", entry=" << alloc_index << ")";
    return true;  // To let it continue.
  }

  auto &alloc = allocations[alloc_index];
  if (!alloc) {
    LOG(ERROR)
        << "Error in memory implementation; pseudo-double free on "
        << std::hex << address.flat << std::dec
        << " (size=" << address.size << ", entry=" << alloc_index << ")";
  }

  alloc.reset();  // Free the std::vector.
  num_free++;
  free_list[alloc_index] = true;
  return true;
}

bool AllocList::TryRead(uint64_t addr, uint8_t *byte_out, AddressSpace *mem, PolicyHandler &policy_handler) {
  Address address = {};
  address.flat = addr;

  if (address.alloc_index >= allocations.size()) {
    LOG(ERROR)
        << "Invalid memory read address " << std::hex << addr << std::dec
        << "; out-of-bounds allocation index";
    return false;
  }

  if (free_list.at(address.alloc_index)) {
    LOG(ERROR)
        << "Use-after-free on memory read addresss "
        << std::hex << addr << std::dec;
    return false;
  }

  if (address.must_be_0x1 != 0x1) {
    LOG(ERROR)
        << "Heap address underflow on memory read address "
        << std::hex << addr << std::dec;
    return false;
  }

  if (address.offset >= address.size) {
    LOG(ERROR)
        << "Heap address overflow on memory read address "
        << std::hex << addr << std::dec;
    *byte_out = 0;
    return true;
  }

  *byte_out = allocations[address.alloc_index]->at(address.offset);
  return true;
}

bool AllocList::TryWrite(uint64_t addr, uint8_t byte, AddressSpace *mem, PolicyHandler &policy_handler) {
  Address address = {};
  address.flat = addr;

  if (address.alloc_index >= allocations.size()) {
    LOG(ERROR)
        << "Invalid memory write address " << std::hex << addr << std::dec
        << "; out-of-bounds allocation index";
    return false;
  }

  if (free_list.at(address.alloc_index)) {
    LOG(ERROR)
        << "Use-after-free on memory write addresss "
        << std::hex << addr << std::dec;
    return false;
  }

  if (address.must_be_0x1 != 0x1) {
    LOG(ERROR)
        << "Heap address underflow on memory write address "
        << std::hex << addr << std::dec;
    return false;
  }

  if (address.offset >= address.size) {
    LOG(ERROR)
        << "Heap address overflow on memory write address "
        << std::hex << addr << std::dec;
    return false;
  }

  auto &alloc_buffer = allocations[address.alloc_index];
  if (!alloc_buffer) {
    LOG(ERROR)
        << "Error in memory implementation; pseudo-use-after-free on "
        << std::hex << address.flat << std::dec
        << " (size=" << address.size << ", entry=" << address.alloc_index
        << ")";
    return false;
  }

  if (alloc_buffer.use_count() > 1) {
    auto old_array = alloc_buffer.get();
    auto new_array = std::make_shared<std::vector<uint8_t>>();
    new_array->resize(address.size);
    memcpy(new_array->data(), old_array->data(), address.size);
    alloc_buffer = std::move(new_array);
  }

  allocations[address.alloc_index]->at(address.offset) = byte;
  return true;
}

}  // namespace native
}  // namespace klee
