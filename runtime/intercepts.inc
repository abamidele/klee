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

ASM_INTERCEPT( strtol, 0xa1 )
ASM_INTERCEPT( realloc, 0xa4 )

C_INTERCEPT(malloc, 0x81)
C_INTERCEPT(calloc, 0x82)
C_INTERCEPT(free, 0x83)

/*
INTERCEPT(_ZdaPv, 0xa6)
INTERCEPT(_ZdlPv, 0xa7)
INTERCEPT(_Znaj, 0xa8)
INTERCEPT(_Znwj, 0xa9)
INTERCEPT(_Znam, 0xaa)
INTERCEPT(_Znwm, 0xab)

INTERCEPT_ALIAS(memalign, 0xac)
INTERCEPT_ALIAS(valloc, 0xad)
INTERCEPT_ALIAS(independent_calloc, 0xb0)
INTERCEPT_ALIAS(independent_comalloc, 0xb1)
INTERCEPT_ALIAS(pvalloc, 0xb2)
INTERCEPT_ALIAS(malloc_trim, 0xb3)
INTERCEPT_ALIAS(malloc_usable_size, 0xb4)
*/
