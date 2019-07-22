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
static const char * const bump_start = &(bump_region[0]);
static const char * const bump_end = &(bump_region[BUMP_REGION_SIZE]);
static char *bump = &(bump_region[0]);

static void *reentrant_malloc(unsigned long long size) {
  if (!size) {
    return NULL;
  }

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
  if (ret) {
    bzero(ret, a * b);
  }
  return ret;
}

static void *reentrant_realloc(void *old, unsigned long long size) {
  void *ret = reentrant_malloc(size);
  if (old) {
    memcpy(ret, old, size);
  }
  return ret;
}

static void reentrant_free(void *ptr) {
}

void *(*real_malloc)(unsigned long long) = NULL;
void *(*real_calloc)(unsigned long long, unsigned long long) = NULL;
void *(*real_realloc)(void *, unsigned long long) = NULL;
void (*real_free)(void *) = NULL;

void *(*real_memset)(void *, int, size_t) = NULL;
void *(*real_memmove)(void *, void *, size_t) = NULL;
void *(*real_memcpy)(void *, void *, size_t) = NULL;
char *(*real_strcpy)(char *, const char *) = NULL;
int (*real_strcmp)(const char *, const char *) = NULL;
int (*real_strncmp)(const char *, const char *, size_t) = NULL;


int intercepted_strcmp(volatile const char *a, volatile const char *b) {
  write(2, "HIT STRCMP!\n", 12);
  while (*a && *a == *b) {
    ++a, ++b;
  }
  return *a - *b;
}

/****EXPERIMENTAL*****/
char *setlocale(int category, const char *locale){
  return "en_US.UTF-8";
}

int intercepted_strncmp(volatile const char *s1,
    volatile const char *s2, size_t n) {
  write(2, "HIT STRNCMP!\n", 13);
  if (n == 0) {
    return (0);
  }
  do {
    if (*s1 != *s2++) {
      return (*(unsigned char *)s1 -
        *(unsigned char *)(s2 - 1));
    }
    if (*s1++ == 0) {
      break;
    }
  } while (--n != 0);
  return (0);
}

/*
int strcmp(volatile const char *a, volatile const char *b) {
  //write(0, "HIT STRCMP!\n", 12);
  return intercepted_strcmp(a,b);
}
*/

__attribute__((initializer))
void init(void) {
  real_malloc = reentrant_malloc;
  real_calloc = reentrant_calloc;
  real_free = reentrant_free;
  real_realloc = reentrant_realloc;
  bump = bump_start;
  void *(*og_malloc)(unsigned long long) = (void *(*)(unsigned long long)) dlsym(RTLD_NEXT, "malloc");
  bump = bump_start;
  void *(*og_calloc)(unsigned long long, unsigned long long) = (void *(*)(unsigned long long, unsigned long long)) dlsym(RTLD_NEXT, "calloc");
  bump = bump_start;
  void *(*og_realloc)(void *, unsigned long long) = (void *(*)(void *, unsigned long long)) dlsym(RTLD_NEXT, "realloc");
  bump = bump_start;
  void (*og_free)(void *) = (void (*)(void *)) dlsym(RTLD_NEXT, "free");
  bump = bump_start;
  real_memset = (void * (*)(void *, int, size_t)) dlsym(RTLD_NEXT, "memset");
  bump = bump_start;
  real_memmove = (void * (*)(void *, void *, size_t)) dlsym(RTLD_NEXT, "memmove");
  bump = bump_start;
  real_memcpy = (void * (*)(void *, void *, size_t)) dlsym(RTLD_NEXT, "memcpy");
  bump = bump_start;
  real_strcpy = (char * (*)(char *, const char *)) dlsym(RTLD_NEXT, "strcpy");
  bump = bump_start;

  real_malloc = og_malloc;
  real_calloc = og_calloc;
  real_realloc = og_realloc;
  real_free = og_free;

  real_strcmp = intercepted_strcmp;
  real_strncmp = intercepted_strncmp;
}

void *intercepted_malloc(unsigned long long a) {
  if (!real_malloc) {
    real_malloc = reentrant_malloc;
    real_malloc = (void *(*)(unsigned long long)) dlsym(RTLD_NEXT, "malloc");
  }
  return real_malloc(a);
}

void *intercepted_calloc(unsigned long long a, unsigned long long b) {
  if (!real_calloc) {
    real_calloc = reentrant_calloc;
    real_calloc = (void *(*)(unsigned long long, unsigned long long)) dlsym(
        RTLD_NEXT, "calloc");
  }
  return real_calloc(a, b);
}

void *intercepted_realloc(void *old, unsigned long long a) {
  if (!real_realloc) {
    real_realloc = reentrant_realloc;
    real_realloc = (void *(*)(unsigned long long)) dlsym(RTLD_NEXT, "realloc");
  }
  return real_realloc(old, a);
}

void intercepted_free(void *ptr) {
  if (!real_free) {
    real_free = reentrant_free;
    real_free = (void (*)(void *)) dlsym(RTLD_NEXT, "free");
  }
  real_free(ptr);
}
