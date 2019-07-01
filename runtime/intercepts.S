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

.intel_syntax noprefix

TEXT_SECTION

.extern SYMBOL(dlsym)
.extern SYMBOL(intercepted_malloc)
.extern SYMBOL(intercepted_calloc)
.extern SYMBOL(intercepted_free)
.extern SYMBOL(og_malloc)
.extern SYMBOL(og_calloc)
.extern SYMBOL(og_free)

DATA_SECTION
.Ldlsym_addr:
   .quad SYMBOL(dlsym)

.Lintercepted_malloc_addr:
   .quad SYMBOL(intercepted_malloc)

.Lintercepted_calloc_addr:
   .quad SYMBOL(intercepted_calloc)

.Lintercepted_free_addr:
   .quad SYMBOL(intercepted_free)

.Log_malloc_addr:
   .quad SYMBOL(intercepted_malloc)

.Log_calloc_addr:
   .quad SYMBOL(intercepted_calloc)

.Log_free_addr:
   .quad SYMBOL(intercepted_free)


#define C_INTERCEPT(name, id) \
   TEXT_SECTION ; \
   .globl SYMBOL(name) ; \
   SYMBOL(name): \
       nop dword ptr [eax + 00] ; \
       jmp       qword ptr [rip + .Lintercepted_ ## name ##_addr ] ; \
       int     id ; \
       ret ; \
       jmp       qword ptr [rip + .Log_ ## name ##_addr ] ; \

#define ASM_INTERCEPT(name, id) \
   DATA_SECTION ; \
   .Laddr_ ## name : \
       .quad .Lfind_ ## name ; \
   .Lname_ ## name: \
       .asciz #name ; \
   TEXT_SECTION ; \
   .globl SYMBOL(name) ; \
   SYMBOL(name): \
       nop     dword ptr [eax + 00] ; \
       jmp     qword ptr [rip + .Laddr_ ## name ] ; \
       int     id ; \
       ret ; \
   .Lfind_ ## name : \
       push    rax ; \
       push    rdi ; \
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
       xor     edi, edi; \
       not     rdi; \
       lea     rsi, [rip + .Lname_ ## name] ; \
       call    qword ptr [rip + .Ldlsym_addr] ; \
       mov     qword ptr [rip + .Laddr_ ## name], rax ; \
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
       pop     rsi ; \
       pop     rdi ; \
       pop     rax ; \
       jmp     SYMBOL(name) ;

#define ALIAS(name, other_name) \
   TEXT_SECTION ; \
   .globl SYMBOL(name) ; \
   SYMBOL(name): \
       jmp SYMBOL(other_name) ;

#define IGNORE(name) \
   TEXT_SECTION ; \
   .globl SYMBOL(name) ; \
   SYMBOL(name): \
       xor eax, eax ; \
       ret ;

ALIAS(__libc_malloc, malloc)
ALIAS(__GI___libc_malloc, malloc)
ALIAS(dlmalloc, malloc)

ALIAS(__libc_calloc, calloc)
ALIAS(__GI___libc_calloc, calloc)
ALIAS(dlcalloc, calloc)

ALIAS(__libc_free, free)
ALIAS(__GI___libc_free, free)
ALIAS(dlfree, free)

IGNORE(mallinfo)
ALIAS(__libc_mallinfo, mallinfo)
ALIAS(__GI___libc_mallinfo, mallinfo)

IGNORE(mallopt)
ALIAS(__libc_mallopt, mallopt)
ALIAS(__GI___libc_mallopt, mallopt)

IGNORE(malloc_stats)
ALIAS(__libc_malloc_stats, malloc_stats)
ALIAS(__GI___libc_malloc_stats, malloc_stats)

#include "intercepts.inc"
