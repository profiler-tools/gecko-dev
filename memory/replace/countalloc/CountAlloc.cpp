/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "replace_malloc.h"

static const malloc_table_t* sFuncs = nullptr;

#ifdef ANDROID
/* See mozglue/android/APKOpen.cpp */
extern "C" MOZ_EXPORT __attribute__((weak))
void* __dso_handle;
#endif

void (*__hook_alloc)(void *, int32_t);
void (*__hook_free)(void *);

extern "C" void CARegister(void (*_alloc)(void *, int32_t), void (*_free)(void *)) MOZ_EXPORT;
extern "C" void CARegister(void (*_alloc)(void *, int32_t), void (*_free)(void *))
{
  __hook_alloc = _alloc;
  __hook_free = _free;
}

extern "C" void CAUnregister() MOZ_EXPORT;
extern "C" void CAUnregister()
{
  __hook_alloc = nullptr;
  __hook_free = nullptr;
}

static void AllocHook(void *p, size_t size)
{
    if (__hook_alloc)
        __hook_alloc(p, size);
}

static void FreeHook(void *p)
{
    if (__hook_free)
        __hook_free(p);
}

void
replace_init(const malloc_table_t* aTable)
{
  sFuncs = aTable;
}

void*
replace_malloc(size_t aSize)
{
  void* ptr = sFuncs->malloc(aSize);
  if (ptr) {
    AllocHook(ptr, aSize);
  }
  return ptr;
}

int
replace_posix_memalign(void** aPtr, size_t aAlignment, size_t aSize)
{
  int ret = sFuncs->posix_memalign(aPtr, aAlignment, aSize);
  if (ret == 0) {
    AllocHook(*aPtr, aSize);
  }
  return ret;
}

void*
replace_aligned_alloc(size_t aAlignment, size_t aSize)
{
  void* ptr = sFuncs->aligned_alloc(aAlignment, aSize);
  if (ptr) {
    AllocHook(ptr, aSize);
  }
  return ptr;
}

void*
replace_calloc(size_t aNum, size_t aSize)
{
  void* ptr = sFuncs->calloc(aNum, aSize);
  if (ptr) {
    AllocHook(ptr, aNum * aSize);
  }
  return ptr;
}

void*
replace_realloc(void* aPtr, size_t aSize)
{
  void* new_ptr = sFuncs->realloc(aPtr, aSize);
  if (new_ptr || !aSize) {
    FreeHook(aPtr);
    if (!aSize) {
      AllocHook(new_ptr, aSize);
    }
  }
  return new_ptr;
}

void
replace_free(void* aPtr)
{
  if (aPtr) {
    FreeHook(aPtr);
  }
  sFuncs->free(aPtr);
}

void*
replace_memalign(size_t aAlignment, size_t aSize)
{
  void* ptr = sFuncs->memalign(aAlignment, aSize);
  if (ptr) {
    AllocHook(ptr, aSize);
  }
  return ptr;
}

void*
replace_valloc(size_t aSize)
{
  void* ptr = sFuncs->valloc(aSize);
  if (ptr) {
    AllocHook(ptr, aSize);
  }
  return ptr;
}
