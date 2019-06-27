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

#define STR_HELPER(id) #id
#define STR(id) STR_HELPER(id)
#define RTLD_NEXT 0xffffffffffffffff


#define INTERCEPT(name, id) \
.intel_syntax noprefix \
 DATA_SECTION ; \
 .Laddr_ ## name : \
 .quad .Lfind_ ## name ; \
 CONST_SECTION ; \
 .Lname_ ## name: \
 .asciz #name ; \
 TEXT_SECTION ; \
 .globl SYMBOL(name) ; \
SYMBOL(name): \
 .intel_syntax noprefix \
 jmp qword ptr [.Laddr_ ## name ] ; \
 int $ ##id ; \
 ret ; \
.Lfind_ ## name : \
   push    rax ; \
   push    rsi ; \
   push    rcx ; \
   push    rdx ; \
   push    rbx ; \
   push    rbp ; \
   push    r8 ; \
   push    r9  ; \
   push    r10  ; \
   push    r11  ; \
   push    r12 ; \
   push    r13 ; \
   push    r14 ; \
   push    r15 ; \
   xor edi, edi; \
   not rdi; \
   lea rsi, [rip + .Lname_ ## name] ; \
  call dlsym; \
  mov [.Laddr_ ## name], rax ; \
   pop     r15 ; \
   pop     r14 ; \
   pop     r13 ; \
   pop     r12 ; \
   pop     r11 ; \
   pop     r10 ; \
   pop     r9 ; \
   pop     r8 ; \
   pop     rbp ; \
   pop     rbx ; \
   pop     rdx ; \
   pop     rcx ; \
   pop     rdi ; \
   pop     rax ; \
   jmp SYMBOL(name) ;  \TEXT_SECTION

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

.intel_syntax noprefix
#include "intercepts.inc"

IGNORE_ALIAS(mallinfo)
IGNORE_ALIAS(mallopt)
IGNORE_ALIAS(malloc_stats)
