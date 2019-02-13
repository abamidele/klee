/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#define ADDRESS_SIZE_BITS 32
#define HAS_FEATURE_AVX 1
#define HAS_FEATE_AVX512 0
#define KLEEMILL_RUNTIME_X86 32
#define KLEEMILL_RUNTIME

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cfenv>
#include <cfloat>
#include <cinttypes>
#include <climits>
#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-alignof-expression"

#include "FreeStanding/FreeStanding.cpp"

#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Intrinsics.cpp"
#include "remill/Arch/X86/Runtime/State.h"

#include "klee-libc/klee-libc.h"
#include "Intrinsic/Intrinsics.cpp"
#include "Native/Intrinsics.h"

#include "Native/Memory.cpp"
#include "Native/SystemCalls/Linux/Run.h"
#include "Native/Task.h"
#include "Native/SystemCalls/Linux/Run.cpp"
#include "Native/X86.cpp"
#include "Native/SystemCalls/Linux/SystemCallABI.h"
#include "Native/SystemCalls/Linux/X86.cpp"

#pragma clang diagnostic pop
