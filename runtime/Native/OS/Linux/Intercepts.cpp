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

namespace {


extern "C" {
  long strtol_intercept(addr_t nptr, addr_t endptr, int base, Memory *memory);
  addr_t malloc_intercept( Memory *memory, uint64_t size);
  void free_intercept( Memory *memory, addr_t ptr);
  addr_t calloc_intercept( Memory *memory, uint64_t size);
  addr_t realloc_intercept( Memory *memory, addr_t ptr,  uint64_t size);
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
  addr_t ptr = malloc_intercept(memory, alloc_size); \
  return intercept.SetReturn(memory, state, ptr); \

#define DO_INTERCEPT_FREE() \
    addr_t address; \
    if (!intercept.TryGetArgs(memory, state, &address)) { \
      STRACE_ERROR(read, "Couldn't get args"); \
    } else { \
      free_intercept(memory, address); \
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

/*
add("_ZdaPv", handleDeleteArray, false),
// operator delete(void*)
add("_ZdlPv", handleDelete, false),

// operator new[](unsigned int)
add("_Znaj", handleNewArray, true),
// operator new(unsigned int)
add("_Znwj", handleNew, true),

// FIXME-64: This is wrong for 64-bit long...

// operator new[](unsigned long)
add("_Znam", handleNewArray, true),
// operator new(unsigned long)
add("_Znwm", handleNew, true),
*/


}  // namespace
