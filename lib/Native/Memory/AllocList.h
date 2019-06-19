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

#include <memory>
#include <list>
#include <vector>

namespace klee {
namespace native {
 
  union Address {
	uint64_t flat;
	struct {
	  uint64_t offset:12;
	  uint64_t must_be_0f:8;  // Helps to detect overflows/underflows.
	  uint64_t size:12;  // Size of allocated object, used to find the `AllocList`.
	  uint64_t alloc_index:24;  // Index of this object in the `AllocList`.
	  uint64_t must_be_fe:8;  // Helps to distinguish our address from mmap addresses.
	} __attribute__((packed));
  };

  static uint8_t under_flow_check = 0x0f;
  static uint8_t special_malloc_byte = 0xfe;


 
  class AllocList {
    public:
     explicit AllocList(size_t size_);
     //  TODO(sai) add a copy constructor for executor forks
     ~AllocList(void) = default;
     uint64_t Allocate(size_t alloc_size);
     bool TryFree(uint64_t addr);
     bool TryRead(uint64_t addr, uint8_t *byte_out);
     bool TryWrite(uint64_t addr, uint8_t byte);

     size_t size;

     std::vector<bool> free_list;
     std::vector<std::shared_ptr<uint8_t[]>> allocations;
  };

}  // namespace native
}  // namespace klee
