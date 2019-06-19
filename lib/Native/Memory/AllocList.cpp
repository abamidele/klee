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

  AllocList::AllocList(uint64_t size_):
      size(size_) {}
  
  uint64_t AllocList::Allocate(size_t alloc_size) {
    if (alloc_size == 0 ){
      LOG(FATAL) << "tried to malloc something of size 0";
    } else if (alloc_size != size) {
      LOG(FATAL) << "incorrect alloc " << 
 		alloc_size << " in " << size << " bucket!";
    }

    Address address = {};
    address.must_be_0f = 0x0f;
    address.size = alloc_size;

    
    size_t free_slot; 
	for(free_slot=0; free_slot < free_list.size(); ++free_slot) {
      if (free_list[free_slot]) {
        break;
      }
    }
    LOG(INFO) << "free_slot is " << free_slot;
	if (free_slot == free_list.size()){
      LOG(INFO) << "a new allocation is being pushed back on the AllocList";
	  address.alloc_index = allocations.size();
      allocations.emplace_back(new uint8_t[alloc_size]);
      free_list.push_back(false);
      LOG(INFO) << "allocation count is " << free_list.size();
    } else {
      LOG(INFO) << "A free slot at " << free_slot << " was found";
	  address.alloc_index = free_slot;
      allocations[free_slot].reset((new uint8_t[alloc_size]));
      free_list[free_slot] = false;
    }

    address.must_be_fe = special_malloc_byte;
    LOG(INFO) << "the address returned was " << address.flat;
    
    return address.flat;
  }

  bool AllocList::TryFree(uint64_t addr) {
    Address address = {};
    address.flat = addr;
    LOG(INFO) << "free is at " << address.flat;
	auto alloc_index = address.alloc_index; 
    LOG(INFO) << "alloc_index was: " << alloc_index;
    LOG(INFO) << "free list size is " << free_list.size();
    if (free_list.at(alloc_index)){
      LOG(ERROR) << "detected a double free on address " << addr;
      return false;
    }
    LOG(INFO) << "the address freed: " << addr;
    free_list[alloc_index] = true;
    return true;
  }

#define MEMORY_ACCESS_CHECKS(addr, type) \
	Address address = {}; \
    address.flat = addr;\
    auto alloc_index = address.alloc_index;\
    if (alloc_index >= allocations.size() || address.offset >= size){\
      LOG(ERROR) << "Invalid Memory Access Error At " << addr;\
 	  return false; \
    } else if (free_list.at(alloc_index)) {\
      LOG(ERROR) << "UAF Detected Tried To " << type << " Corrupted Data At " << addr;\
	  return false;\
	} else if (address.must_be_0f != under_flow_check) {\
      LOG(ERROR) << "Failed Underlow/Overflow Check On " << type << " At " << addr;\
	  return false;\
 	}\


  bool AllocList::TryRead(uint64_t addr, uint8_t *byte_out) {
    MEMORY_ACCESS_CHECKS(addr, "Read");
	byte_out = &allocations[alloc_index][address.offset];
	return true;
  }

  bool AllocList::TryWrite(uint64_t addr, uint8_t byte) {
    // still need to do a ref count check for copy on write
    MEMORY_ACCESS_CHECKS(addr, "Write");
 	allocations[alloc_index][address.offset] = byte;
	return true;
  }

#undef MEMORY_ACCESS_CHECKS

}  // namespace native
}  // namespace klee
