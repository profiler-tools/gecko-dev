/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 * vim: set ts=8 sts=4 et sw=4 tw=99:
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef js_MemoryProfiler_h
#define js_MemoryProfiler_h

#include "mozilla/Atomics.h"

struct JSRuntime;

class NativeProfiler {
  public:
    virtual ~NativeProfiler() {};
    virtual void sampleNative(void *addr, int32_t size) = 0;
    virtual void removeNative(void *addr) = 0;
    virtual void reset() = 0;
};

class GCHeapProfiler {
  public:
    virtual ~GCHeapProfiler() {};
    virtual void sampleTenured(void *addr, int32_t size) = 0;
    virtual void sampleNursery(void *addr, int32_t size) = 0;
    virtual void markTenuredStart() = 0;
    virtual void markTenured(void *addr) = 0;
    virtual void sweepTenured() = 0;
    virtual void sweepNursery() = 0;
    virtual void moveNurseryToTenured(void *addrOld, void *addrNew) = 0;
    virtual void reset() = 0;
};

class MemProfiler {
    static mozilla::Atomic<int> mGlobalSwitch;
    static NativeProfiler *mNativeProfiler;

    static GCHeapProfiler *GetGCHeapProfiler(void *addr);
    static GCHeapProfiler *GetGCHeapProfiler(JSRuntime *runtime);

    static NativeProfiler *GetNativeProfiler() {
        return mNativeProfiler;
    }

    GCHeapProfiler *mGCHeapProfiler;

  public:
    void start(GCHeapProfiler *aGCHeapProfiler) {
        mGCHeapProfiler = aGCHeapProfiler;
        mGlobalSwitch++;
    }

    void stop() {
        mGlobalSwitch--;
        mGCHeapProfiler = nullptr;
    }

    GCHeapProfiler *getGCHeapProfiler() const {
        return mGCHeapProfiler;
    }

    static MemProfiler *GetMemProfiler(JSRuntime *runtime);

    static void SetNativeProfiler(NativeProfiler *aProfiler) {
        mNativeProfiler = aProfiler;
    }

    static void SampleNative(void *addr, int32_t size) {
        if (mGlobalSwitch == 0)
            return;

        NativeProfiler *profiler = GetNativeProfiler();
        if (profiler)
            profiler->sampleNative(addr, size);
    }

    static void SampleTenured(void *addr, int32_t size) {
        if (mGlobalSwitch == 0)
            return;

        GCHeapProfiler *profiler = GetGCHeapProfiler(addr);
        if (profiler)
            profiler->sampleTenured(addr, size);
    }

    static void SampleNursery(void *addr, int32_t size) {
        if (mGlobalSwitch == 0)
            return;

        GCHeapProfiler *profiler = GetGCHeapProfiler(addr);
        if (profiler)
            profiler->sampleNursery(addr, size);
    }

    static void RemoveNative(void *addr) {
        if (mGlobalSwitch == 0)
            return;

        NativeProfiler *profiler = GetNativeProfiler();
        if (profiler)
            profiler->removeNative(addr);
    }

    static void MarkTenuredStart(JSRuntime *runtime) {
        if (mGlobalSwitch == 0)
            return;

        GCHeapProfiler *profiler = GetGCHeapProfiler(runtime);
        if (profiler)
            profiler->markTenuredStart();
    }

    static void MarkTenured(void *addr) {
        if (mGlobalSwitch == 0)
            return;

        GCHeapProfiler *profiler = GetGCHeapProfiler(addr);
        if (profiler)
            profiler->markTenured(addr);
    }

    static void SweepTenured(JSRuntime *runtime) {
        if (mGlobalSwitch == 0)
            return;

        GCHeapProfiler *profiler = GetGCHeapProfiler(runtime);
        if (profiler)
            profiler->sweepTenured();
    }

    static void SweepNursery(JSRuntime *runtime) {
        if (mGlobalSwitch == 0)
            return;

        GCHeapProfiler *profiler = GetGCHeapProfiler(runtime);
        if (profiler)
            profiler->sweepNursery();
    }

    static void MoveNurseryToTenured(void *addrOld, void *addrNew) {
        if (mGlobalSwitch == 0)
            return;

        GCHeapProfiler *profiler = GetGCHeapProfiler(addrOld);
        if (profiler)
            profiler->moveNurseryToTenured(addrOld, addrNew);
    }
};

#endif
