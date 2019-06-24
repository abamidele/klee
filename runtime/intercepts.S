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

#include "remill/Arch/Assembly.S"

TEXT_SECTION

#define INTERCEPT(name, id) \
  .globl SYMBOL(name) ; \
   SYMBOL(name): \
   int $ ##id ; \
   ret ;

#define INTERCEPT_ALIAS(name, id) \
  INTERCEPT(name, id)\
  INTERCEPT(dl##name, id)\
  INTERCEPT(__libc_##name, id)\
  INTERCEPT(__GI___libc_##name, id)

#define IGNORE(name) \
  .globl SYMBOL(name) ; \
  SYMBOL(name): \
  xor %eax, %eax ; \
  ret ;

#define IGNORE_ALIAS(name) \
  IGNORE(name)\
  IGNORE(dl##name)\
  IGNORE(__libc_##name)\
  IGNORE(__GI___libc_##name)

#include "intercepts.inc"

IGNORE_ALIAS(mallinfo)
IGNORE_ALIAS(mallopt)
IGNORE_ALIAS(malloc_stats)
