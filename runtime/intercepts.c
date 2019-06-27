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
#include <dlfcn.h>

#define STR_HELPER(id) #id
#define STR(id) STR_HELPER(id)
#define RTLD_NEXT -1

/*
void *libc;

__attribute__((constructor)) void init(void){
  libc = dlopen("libc.so", RTLD_NEXT);
}
*/


#define INTERCEPT(name, id) \
  __attribute__((naked)) void name() { \
    asm ( \
      "push %%rcx; " \
      "push %%rdx; " \
      "push %%rsi; " \
      "push %%rdi; " \
      "push %%r8; " \
      "push %%r9; " \
      "push %%r10; " \
      "push %%r11; " \
      : \
      ); \
    register void *f asm("rax") = dlsym(RTLD_NEXT, STR(name)); \
    asm ( \
      "pop %%r11;"  \
      "pop %%r10;"  \
      "pop %%r9;"  \
      "pop %%r8;"  \
      "pop %%rdi;"  \
      "pop %%rsi;"  \
      "pop %%rdx;"  \
      "pop %%rcx;"  \
      "add $8, %%rsp;" \
      "jmp %0;"  \
      "ret ;"  \
      "int $" STR(id) ";" \
      "ret;"  \
      : \
      : "r"(f) \
   );\
  }

#define INTERCEPT_ALIAS(name, id) \
  INTERCEPT(name, id)\
  INTERCEPT(dl##name, id)\
  INTERCEPT(__libc_##name, id)\
  INTERCEPT(__GI___libc_##name, id)

#define IGNORE(name) \
  __attribute__((naked)) inline int name() { \
    asm ( \
          "xor %eax, %eax;" \
          "ret;" \
          : \
      ); \
    } \

#define IGNORE_ALIAS(name) \
  IGNORE(name)\
  IGNORE(dl##name)\
  IGNORE(__libc_##name)\
  IGNORE(__GI___libc_##name)

#include "intercepts.inc"

IGNORE_ALIAS(mallinfo)
IGNORE_ALIAS(mallopt)
IGNORE_ALIAS(malloc_stats)
