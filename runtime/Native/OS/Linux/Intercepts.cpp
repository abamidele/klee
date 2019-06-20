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
}

template <typename ABI>
static Memory *InterceptStrtol(Memory *memory, State *state,
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

template <typename ABI>
static Memory *InterceptMalloc(Memory *memory, State *state,
                       const ABI &intercept) {
}

template <typename ABI>
static Memory *InterceptFree(Memory *memory, State *state,
                       const ABI &intercept) {
}

}  // namespace
