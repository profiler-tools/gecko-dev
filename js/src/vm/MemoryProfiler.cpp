/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 * vim: set ts=8 sts=4 et sw=4 tw=99:
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "vm/Runtime.h"
#include "js/MemoryProfiler.h"

mozilla::Atomic<int> MemProfiler::mGlobalSwitch;
NativeProfiler *MemProfiler::mNativeProfiler;

GCHeapProfiler *MemProfiler::GetGCHeapProfiler(void *addr)
{
    JSRuntime *runtime = reinterpret_cast<gc::Cell *>(addr)->runtimeFromAnyThread();
    return runtime->mMemProfiler.mGCHeapProfiler;
}

GCHeapProfiler *MemProfiler::GetGCHeapProfiler(JSRuntime *runtime)
{
    return runtime->mMemProfiler.mGCHeapProfiler;
}

MemProfiler *MemProfiler::GetMemProfiler(JSRuntime *runtime)
{
    return &runtime->mMemProfiler;
}
