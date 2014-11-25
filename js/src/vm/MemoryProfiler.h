#ifndef vm_MemoryProfiler_h
#define vm_MemoryProfiler_h

#include "jslock.h"

struct AllocTable;
class MProfiler {
    friend JSObject* MPGetFrameNameTable(JSRuntime *runtime, JSContext *cx);
    friend JSObject* MPGetStacktraceTable(JSRuntime *runtime, JSContext *cx);
    friend JSObject* MPGetAllocatedEntries(JSRuntime *runtime, JSContext *cx);

    PRLock *lock_;
    pid_t lockOwner_;
    AllocTable *allocTable_;
    bool active_;
    bool marking_;

  public:
    MProfiler();
    ~MProfiler();

    bool isActive() {
        return active_;
    }

    PRLock* getLock() {
        return lock_;
    }

    void start();
    void stop();
    void clear();
    void record(void *addr, int32_t size, int heapKind);
    void remove(void *addr);
    void remove_unchecked(void *addr);
    void relocate(void *old_addr, void *new_addr);
    void mark(void *addr);
    void markStart();
    void sweep();
    void collect();

    void dump2buf(char *buf, size_t size);
};

#endif
