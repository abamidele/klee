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
#include "runtime/Native/Intrinsics.h"
namespace {


extern "C" {
  long strtol_intercept(addr_t nptr, addr_t endptr, int base, Memory *memory);
  addr_t malloc_intercept( Memory *memory, uint64_t size);
  bool free_intercept( Memory *memory, addr_t ptr);
  addr_t calloc_intercept( Memory *memory, uint64_t size);
  addr_t realloc_intercept( Memory *memory, addr_t ptr,  uint64_t size);
  size_t malloc_size( Memory *memory, addr_t ptr);
  addr_t independent_calloc_intercept(Memory *memory, size_t n_elements,size_t size);
  addr_t independent_comalloc_intercept(Memory *memory, size_t n_elements, size_t size);
}

template <typename ABI>
static Memory *Intercept_strtol(Memory *memory, State *state,
                       const ABI &intercept) {
  addr_t nptr = 0;
  addr_t endptr;
  int base;
  
  if (!intercept.TryGetArgs(memory, state, &nptr, &endptr, &base)) {
    STRACE_ERROR(read, "Couldn't get args");
    return intercept.SetReturn(memory, state, -EFAULT);
  }

  long number = strtol_intercept(nptr, endptr, base, memory);

  exit(0);
}


#define DO_INTERCEPT_MALLOC() \
  size_t alloc_size; \
  if (!intercept.TryGetArgs(memory, state, &alloc_size)) { \
    STRACE_ERROR(read, "Couldn't get args"); \
    return intercept.SetReturn(0, state, 0); \
  } \
  addr_t ptr; \
  if (alloc_size > (1U << 15U)) { \
    printf("HIT THE BIIG MALLOC CASE WITH SIZE %lx\n", alloc_size); \
    switch_to_normal_malloc = true ; \
    return intercept.SetReturn(memory, state, 0x13337); \
  } else { \
    ptr = malloc_intercept(memory, alloc_size);\
    return intercept.SetReturn(memory, state, ptr); \
  } \

#define DO_INTERCEPT_FREE() \
    addr_t address; \
    if (!intercept.TryGetArgs(memory, state, &address)) { \
      STRACE_ERROR(read, "Couldn't get args"); \
    } else { \
      if (!free_intercept(memory, address)) { \
        printf("HIT THE NATURAL FREE CASE AT ADDRESS 0x%lx\n", address); \
        switch_to_normal_malloc = true ; \
      } \
    } \
    return memory; \


template <typename ABI>
static Memory *Intercept_malloc(Memory *memory, State *state,
                       const ABI &intercept) {
  DO_INTERCEPT_MALLOC()
}

template <typename ABI>
static Memory *Intercept_free(Memory *memory, State *state,
                       const ABI &intercept) {
  DO_INTERCEPT_FREE()
}

template <typename ABI>
static Memory *Intercept_calloc(Memory *memory, State *state,
                       const ABI &intercept) {
  size_t alloc_size;
  if (!intercept.TryGetArgs(memory, state, &alloc_size)) {
    STRACE_ERROR(read, "Couldn't get args");
    return intercept.SetReturn(0, state, 0);
  }
  addr_t ptr = calloc_intercept(memory, alloc_size);
  return intercept.SetReturn(memory, state, ptr);
}

template <typename ABI>
static Memory *Intercept_realloc(Memory *memory, State *state,
                       const ABI &intercept) {
  addr_t ptr;
  size_t alloc_size;
  if (!intercept.TryGetArgs(memory, state, &ptr, &alloc_size)) {
    STRACE_ERROR(read, "Couldn't get args");
    return intercept.SetReturn(0, state, 0);
  }
  ptr = realloc_intercept(memory, ptr, alloc_size);
  return intercept.SetReturn(memory, state, ptr);
}



template <typename ABI>
static Memory *Intercept__ZdaPv(Memory *memory, State *state,
                       const ABI &intercept) {
  DO_INTERCEPT_FREE()
}

template <typename ABI>
static Memory *Intercept__ZdlPv(Memory *memory, State *state,
                       const ABI &intercept) {
  DO_INTERCEPT_FREE()
}

template <typename ABI>
static Memory *Intercept__Znaj(Memory *memory, State *state,
                       const ABI &intercept) {
  DO_INTERCEPT_MALLOC()
}

template <typename ABI>
static Memory *Intercept__Znwj(Memory *memory, State *state,
                       const ABI &intercept) {
  DO_INTERCEPT_MALLOC()
}

template <typename ABI>
static Memory *Intercept__Znam(Memory *memory, State *state,
                       const ABI &intercept) {
  DO_INTERCEPT_MALLOC()
}

template <typename ABI>
static Memory *Intercept__Znwm(Memory *memory, State *state,
                       const ABI &intercept) {
  DO_INTERCEPT_MALLOC()
}

template <typename ABI>
static Memory *Intercept_valloc(Memory *memory, State *state,
                       const ABI &intercept) {
  DO_INTERCEPT_MALLOC()
}

template <typename ABI>
static Memory *Intercept_memalign(Memory *memory, State *state,
                       const ABI &intercept) {
  size_t alignment;
  size_t size;
  if (!intercept.TryGetArgs(memory, state, &alignment, &size)) {
    STRACE_ERROR(read, "Couldn't get args");
    return intercept.SetReturn(0, state, 0);
  }
  addr_t ptr = malloc_intercept(memory, size);
  return intercept.SetReturn(memory, state, ptr);
}


template <typename ABI>
static Memory *Intercept_independent_calloc(Memory *memory, State *state,
                       const ABI &intercept) {
  size_t n_elements;
  size_t size;
  addr_t chunks;
  if (!intercept.TryGetArgs(memory, state, &n_elements, &size, &chunks)) {
    STRACE_ERROR(read, "Couldn't get args");
    return intercept.SetReturn(0, state, 0);
    }

  chunks = independent_calloc_intercept(memory, n_elements, size);
  return intercept.SetReturn(memory, state, chunks);
}

template <typename ABI>
static Memory *Intercept_independent_comalloc(Memory *memory, State *state,
                       const ABI &intercept) {
  size_t n_elements;
  addr_t sizes;
  addr_t chunks;
  if (!intercept.TryGetArgs(memory, state, &n_elements, &sizes, &chunks)) {
    STRACE_ERROR(read, "Couldn't get args");
    return intercept.SetReturn(0, state, 0);
  }

  chunks = independent_comalloc_intercept(memory, n_elements, sizes);
  return intercept.SetReturn(memory, state, chunks);
}

template <typename ABI>
static Memory *Intercept_pvalloc(Memory *memory, State *state,
                       const ABI &intercept) {
  DO_INTERCEPT_MALLOC()
}

template <typename ABI>
static Memory *Intercept_malloc_trim(Memory *memory, State *state,
                       const ABI &intercept) {
  return intercept.SetReturn(memory, state, 0);
}

template <typename ABI>
static Memory *Intercept_malloc_usable_size(Memory *memory, State *state,
                       const ABI &intercept) {
  addr_t ptr;
  if (!intercept.TryGetArgs(memory, state, &ptr)) {
    STRACE_ERROR(read, "Couldn't get args");
    return intercept.SetReturn(0, state, 0);
  }
  addr_t size = malloc_size(memory, ptr);
  return intercept.SetReturn(memory, state, size);
}


}  // namespace
