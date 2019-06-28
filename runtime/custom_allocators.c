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

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>

#define BUMP_REGION_SIZE 4098
#define RTLD_NEXT -1

static char bump_region[BUMP_REGION_SIZE];
static char *bump = &(bump_region[0]);
static const char * const bump_end = &(bump_region[BUMP_REGION_SIZE]);

static void *reentrant_malloc(unsigned long long size) {
  char *ret = bump;
  bump += size;
  if (bump <= bump_end) {
    return ret;
  } else {
    bump = &(bump_region[0]);
    return reentrant_malloc(size);
  }
}

static void *reentrant_calloc(unsigned long long a, unsigned long long b) {
  void *ret = reentrant_malloc(a * b);
  bzero(ret, a * b);
  return ret;
}

static int is_reentrant = 0;
static void *(*real_malloc)(unsigned long long) = NULL;
static void *(*real_calloc)(unsigned long long, unsigned long long) = NULL;
static void (*real_free)(void *) = NULL;

void *intercepted_malloc(unsigned long long a) {
  if (is_reentrant) {
    return reentrant_malloc(a);
  } else if (!real_malloc) {
    is_reentrant++;
    printf("re-entrant++: %d\n", is_reentrant);
    real_malloc = (void *(*)(unsigned long long)) dlsym(RTLD_NEXT, "malloc");
    is_reentrant--;

    printf("re-entrant++: %d\n", is_reentrant);
  }
  return real_malloc(a);
}

void *intercepted_calloc(unsigned long long a, unsigned long long b) {
  if (is_reentrant) {
    return reentrant_calloc(a, b);
  } else if (!real_calloc) {
    is_reentrant++;
    //printf("re-entrant++: %d\n", is_reentrant);
    real_calloc = (void *(*)(unsigned long long, unsigned long long)) dlsym(
        RTLD_NEXT, "calloc");
    is_reentrant--;
    //printf("re-entrant++: %d\n", is_reentrant);
  }
  return real_calloc(a, b);
}

void intercepted_free(void *ptr) {
  if (ptr >= &(bump_region[0]) && ptr < bump_end) {
    return;
  } else if (is_reentrant) {
    return;
  } else if (!real_free) {
    is_reentrant++;
    printf("re-entrant++: %d\n", is_reentrant);
    real_free = (void (*)(void *)) dlsym(RTLD_NEXT, "free");
    is_reentrant--;
    printf("re-entrant++: %d\n", is_reentrant);
  }
  real_free(ptr);
}
