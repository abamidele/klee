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

INTERCEPT(strtol, 0xa1)
INTERCEPT(malloc, 0xa2)
INTERCEPT(free, 0xa3)
INTERCEPT(realloc, 0xa4)
INTERCEPT(calloc, 0xa5)
INTERCEPT(_ZdaPv, 0xa6)
INTERCEPT(_ZdlPv, 0xa7)
INTERCEPT(_Znaj, 0xa8)
INTERCEPT(_Znwj, 0xa9)
INTERCEPT(_Znam, 0xaa)
INTERCEPT(_Znwm, 0xab)
