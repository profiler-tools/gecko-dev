/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "MemoryProfiler.h"
#include "nsIDOMClassInfo.h"
#include "nsIGlobalObject.h"
#include "js/TypeDecls.h"
#include "xpcprivate.h"
#include "mozilla/Atomics.h"

#include "js/MemoryProfiler.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

extern std::vector<const char *> SPSGetStacktrace();

// For stlport.
namespace std {
    namespace tr1 {
    }
    using namespace tr1;
}

#if defined(__GLIBC__)
// glibc doesn't implement gettid(2).
#include <sys/syscall.h>
static pid_t _gettid()
{
  return (pid_t) syscall(SYS_gettid);
}
#else
static pid_t _gettid()
{
  return gettid();
}
#endif

class AutoMPLock
{
  public:
    explicit AutoMPLock(PRLock *lock, pid_t *owner)
    {
        MOZ_ASSERT(lock, "Parameter should not be null!");
        PR_Lock(lock);
        *owner = _gettid();
        lock_ = lock;
        owner_ = owner;
    }

    ~AutoMPLock() {
        if (owner_)
            *owner_ = 0;
        if (lock_)
            PR_Unlock(lock_);
    }

    void unlock() {
        if (owner_)
            *owner_ = 0;
        if (lock_)
            PR_Unlock(lock_);
        owner_ = nullptr;
        lock_ = nullptr;
    }

  private:
    PRLock *lock_;
    pid_t *owner_;
};

struct TrieNode {
  uint32_t parentIdx;
  uint32_t nameIdx;
  bool operator==(const TrieNode t) const {
    return parentIdx == t.parentIdx && nameIdx == t.nameIdx;
  }
};

struct TrieHasher {
  size_t operator()(const TrieNode &v) const noexcept {
    uint64_t k = static_cast<uint64_t>(v.parentIdx) << 32 | v.nameIdx;
    return std::hash<uint64_t>()(k);
  }
};

template<typename C, typename ...ARGS>
class Unique {
  std::unordered_map<C, uint32_t, ARGS...> m;

public:
  uint32_t insert(const C &e) {
    auto i = m.insert(std::make_pair(e, m.size()));
    return i.first->second;
  }

  std::vector<C> serialize() const {
    std::vector<C> v(m.size());
    for (auto i: m)
      v[i.second] = i.first;
    return v;
  }

  uint32_t size() const {
    return m.size();
  }

  void clear() {
    m.clear();
  }
};

class CompactTraceTable {
private:
  Unique<std::string> names;
  Unique<TrieNode, TrieHasher> traces;
public:
  CompactTraceTable() {
    names.insert("(unknown)");
    traces.insert(TrieNode{0, 0});
  }

  std::vector<std::string> getNames() const {
    return names.serialize();
  }

  std::vector<TrieNode> getTraces() const {
    return traces.serialize();
  }

  // Returns an ID to a stacktrace.
  uint32_t insert(const std::vector<const char *> &aRawStacktrace) {
    uint32_t parent = 0;
    for (auto i: aRawStacktrace)
      parent = traces.insert(TrieNode{parent, names.insert(i)});
    return parent;
  }

  void reset() {
    names.clear();
    traces.clear();
  }
};

struct AllocEvent {
  // Microseconds.
  int64_t mTimestamp;
  // index to a stacktrace singleton.
  uint32_t mTraceIdx;
  // Allocation size
  int32_t mSize;

  AllocEvent(uint32_t aTraceIdx, int32_t aSize, int64_t aTimestamp) {
    mTraceIdx = aTraceIdx;
    mSize = aSize;
    mTimestamp = aTimestamp;
  }
};

struct AllocEntry {
  int mEventIdx : 31;
  int marked : 1;

  AllocEntry(int aEventIdx) {
    mEventIdx = aEventIdx;
    marked = 0;
  }
};

class GCHeapProfilerImpl : public GCHeapProfiler {
private:
  PRLock *lock_;
  pid_t lockOwner_;
  int32_t cumulated;
  int32_t mSampleSize;
  bool marking_;

  // Record allocations in a address -> AllocEntry map.
  std::unordered_map<void *, AllocEntry> nurseryEntries;
  std::unordered_map<void *, AllocEntry> tenuredEntriesFG;
  std::unordered_map<void *, AllocEntry> tenuredEntriesBG;

  // Events to report
  std::vector<AllocEvent> allocEvents;

  // Save the traces efficiently.
  CompactTraceTable mTraceTable;

public:
  GCHeapProfilerImpl() {
    lock_ = PR_NewLock();
    lockOwner_ = 0;
    marking_ = false;
    cumulated = 0;
    // TODO: customizable
    mSampleSize = 65536;
  }

  virtual ~GCHeapProfilerImpl() {
    PR_Lock(lock_);
    PR_Unlock(lock_);
    PR_DestroyLock(lock_);
  }

  std::vector<std::string> getNames() {
    return mTraceTable.getNames();
  }

  std::vector<TrieNode> getTraces() {
    return mTraceTable.getTraces();
  }

  const std::vector<AllocEvent>& getEvents() {
    return allocEvents;
  }

  virtual void reset() {
    mTraceTable.reset();
    allocEvents.clear();
    nurseryEntries.clear();
    tenuredEntriesFG.clear();
    tenuredEntriesBG.clear();
  }

  virtual void sampleTenured(void *addr, int32_t size) {
    AutoMPLock lock(lock_, &lockOwner_);
    cumulated += size;
    if (cumulated >= mSampleSize) {
      int32_t count = cumulated / mSampleSize;
      cumulated %= mSampleSize;
      std::vector<const char *> trace = SPSGetStacktrace();
      AllocEvent ai(mTraceTable.insert(trace), count * mSampleSize, PR_Now());
      tenuredEntriesFG.insert(std::make_pair(addr, AllocEntry(allocEvents.size())));
      allocEvents.push_back(ai);
    }
  }

  virtual void sampleNursery(void *addr, int32_t size) {
    AutoMPLock lock(lock_, &lockOwner_);
    cumulated += size;
    if (cumulated >= mSampleSize) {
      int32_t count = cumulated / mSampleSize;
      cumulated %= mSampleSize;
      std::vector<const char *> trace = SPSGetStacktrace();
      AllocEvent ai(mTraceTable.insert(trace), count * mSampleSize, PR_Now());
      nurseryEntries.insert(std::make_pair(addr, AllocEntry(allocEvents.size())));
      allocEvents.push_back(ai);
    }
  }

  virtual void markTenuredStart() {
    AutoMPLock lock(lock_, &lockOwner_);
    MOZ_ASSERT(!marking_);
    marking_ = true;
    std::swap(tenuredEntriesFG, tenuredEntriesBG);
  }

  virtual void markTenured(void *addr) {
    MOZ_ASSERT(marking_);
    auto res = tenuredEntriesBG.find(addr);
    if (res != tenuredEntriesBG.end())
      res->second.marked = -1;
  }

  virtual void sweepTenured() {
    AutoMPLock lock(lock_, &lockOwner_);
    MOZ_ASSERT(marking_);
    marking_ = false;
    for (auto i: tenuredEntriesBG) {
      if (i.second.marked != 0) {
        i.second.marked = 0;
        tenuredEntriesFG.insert(i);
      } else {
        AllocEvent &oldEvent = allocEvents[i.second.mEventIdx];
        AllocEvent newEvent(oldEvent.mTraceIdx, -oldEvent.mSize, PR_Now());
        allocEvents.push_back(newEvent);
      }
    }
    tenuredEntriesBG.clear();
  }

  virtual void sweepNursery() {
    AutoMPLock lock(lock_, &lockOwner_);
    for (auto i: nurseryEntries) {
      AllocEvent &oldEvent = allocEvents[i.second.mEventIdx];
      AllocEvent newEvent(oldEvent.mTraceIdx, -oldEvent.mSize, PR_Now());
      allocEvents.push_back(newEvent);
    }
    nurseryEntries.clear();
  }

  virtual void moveNurseryToTenured(void *addrOld, void *addrNew) {
    AutoMPLock lock(lock_, &lockOwner_);
    auto iterOld = nurseryEntries.find(addrOld);
    if (iterOld == nurseryEntries.end())
      return;

    auto res = tenuredEntriesFG.insert(std::make_pair(addrNew, AllocEntry(iterOld->second.mEventIdx)));
    auto iterNew = res.first;

    if (!res.second) {
      allocEvents[iterNew->second.mEventIdx].mSize = 0;
      iterNew->second.mEventIdx = iterOld->second.mEventIdx;
    }
    nurseryEntries.erase(iterOld);
  }
};

class NativeProfilerImpl : public NativeProfiler {
private:
  PRLock *lock_;
  pid_t lockOwner_;
  int32_t cumulated;
  int32_t mSampleSize;

  // Record allocations in a address -> AllocEntry map.
  std::unordered_map<void *, AllocEntry> nativeEntries;

  // Events to report
  std::vector<AllocEvent> allocEvents;

  // Save the traces efficiently.
  CompactTraceTable mTraceTable;

public:
  NativeProfilerImpl() {
    lock_ = PR_NewLock();
    lockOwner_ = 0;
    cumulated = 0;
    // TODO: customizable
    mSampleSize = 65536;
  }

  virtual ~NativeProfilerImpl() {
    PR_Lock(lock_);
    PR_Unlock(lock_);
    PR_DestroyLock(lock_);
  }

  std::vector<std::string> getNames() {
    return mTraceTable.getNames();
  }

  std::vector<TrieNode> getTraces() {
    return mTraceTable.getTraces();
  }

  const std::vector<AllocEvent>& getEvents() {
    return allocEvents;
  }

  virtual void reset() {
    mTraceTable.reset();
    allocEvents.clear();
    nativeEntries.clear();
  }

  virtual void sampleNative(void *addr, int32_t size) {
    if (lockOwner_ == _gettid())
        return;
    AutoMPLock lock(lock_, &lockOwner_);
    cumulated += size;
    if (cumulated >= mSampleSize) {
      int32_t count = cumulated / mSampleSize;
      cumulated %= mSampleSize;
      std::vector<const char *> trace = SPSGetStacktrace();
      AllocEvent ai(mTraceTable.insert(trace), count * mSampleSize, PR_Now());
      nativeEntries.insert(std::make_pair(addr, AllocEntry(allocEvents.size())));
      allocEvents.push_back(ai);
    }
  }

  virtual void removeNative(void *addr) {
    if (lockOwner_ == _gettid())
        return;
    AutoMPLock lock(lock_, &lockOwner_);

    auto res = nativeEntries.find(addr);
    if (res == nativeEntries.end())
      return;

    AllocEvent &oldEvent = allocEvents[res->second.mEventIdx];
    AllocEvent newEvent(oldEvent.mTraceIdx, -oldEvent.mSize, PR_Now());
    allocEvents.push_back(newEvent);
    nativeEntries.erase(res);
  }
};

static void _SampleNative(void *addr, int32_t size) {
    MemProfiler::SampleNative(addr, size);
}

static void _RemoveNative(void *addr) {
    MemProfiler::RemoveNative(addr);
}

#ifdef XP_DARWIN
extern "C" void CARegister(void (*_alloc)(void *, int32_t), void (*_free)(void *)) __attribute__((weak_import));
static void _initNativeHook()
{
    static bool registered = false;
    if (!registered && CARegister)
        CARegister(_SampleNative, _RemoveNative);
}
#elif defined(XP_WIN)
#include <windows.h>
extern "C" {
    static void (*_CARegister)(void (*_alloc)(void *, int32_t), void (*_free)(void *));
}
static void _initNativeHook()
{
    if (_CARegister)
        return;

    char replace_malloc_lib[1024];
    if (GetEnvironmentVariableA("MOZ_REPLACE_MALLOC_LIB", (LPSTR)&replace_malloc_lib,
                sizeof(replace_malloc_lib)) > 0) {
        HMODULE handle = LoadLibraryA(replace_malloc_lib);
        if (handle) {
            _CARegister = GetProcAddress(handle, "CARegister");
            if (_CARegister)
                _CARegister(_SampleNative, _RemoveNative);
        }
    }
}
#elif defined(__GNUC__) || defined(MOZ_WIDGET_ANDROID) || defined(MOZ_WIDGET_GONK)
#include <dlfcn.h>
extern "C" {
    static void (*_CARegister)(void (*_alloc)(void *, int32_t), void (*_free)(void *));
}
static void _initNativeHook()
{
    if (!_CARegister)
      _CARegister = (void (*)(void (*_alloc)(void *, int32_t), void (*_free)(void *)))dlsym(RTLD_DEFAULT, "CARegister");
    if (_CARegister)
        _CARegister(_SampleNative, _RemoveNative);
}
static void _finiNativeHook()
{
    if (!_CARegister)
      _CARegister = (void (*)(void (*_alloc)(void *, int32_t), void (*_free)(void *)))dlsym(RTLD_DEFAULT, "CARegister");
    if (_CARegister)
        _CARegister(nullptr, nullptr);
}
#else
#   error No implementation for SampleAlloc.
#endif

NS_IMPL_ISUPPORTS(MemoryProfiler, nsIMemoryProfiler)

MemoryProfiler::MemoryProfiler()
{
  /* member initializers and constructor code */
}

MemoryProfiler::~MemoryProfiler()
{
  /* destructor code */
}

struct JSRuntime;

static PRLock *gLock;
static int gRefCnt;
static NativeProfilerImpl* gNativeProfiler;
static std::unordered_map<JSRuntime *, GCHeapProfilerImpl *> gRuntimeToGCHeapProfiler;

static void _initOnce()
{
  static bool initialized;
  static mozilla::Atomic<int> init_cnt;

  if (!initialized) {
    if (init_cnt++ == 0) {
      gLock = PR_NewLock();
      initialized = true;
    } else {
      while (!initialized);
    }
  }
}

NS_IMETHODIMP
MemoryProfiler::StartProfiler()
{
  _initOnce();
  JSRuntime* runtime = XPCJSRuntime::Get()->Runtime();
  PR_Lock(gLock);
  if (gRefCnt++ == 0) {
    js::EnableRuntimeProfilingStack(runtime, true);
    if (!gNativeProfiler) {
      gNativeProfiler = new NativeProfilerImpl();
    }
    MemProfiler::SetNativeProfiler(gNativeProfiler);
    _initNativeHook();
  }
  GCHeapProfilerImpl *gp = new GCHeapProfilerImpl();
  gRuntimeToGCHeapProfiler.insert(std::make_pair(runtime, gp));
  MemProfiler::GetMemProfiler(runtime)->start(gp);
  PR_Unlock(gLock);
  return NS_OK;
}

NS_IMETHODIMP
MemoryProfiler::StopProfiler()
{
  JSRuntime* runtime = XPCJSRuntime::Get()->Runtime();
  PR_Lock(gLock);
  MemProfiler::GetMemProfiler(runtime)->stop();
  if (--gRefCnt == 0) {
    _finiNativeHook();
    MemProfiler::SetNativeProfiler(nullptr);
    js::EnableRuntimeProfilingStack(runtime, false);
  }
  PR_Unlock(gLock);
  return NS_OK;
}

NS_IMETHODIMP
MemoryProfiler::ResetProfiler()
{
  JSRuntime* runtime = XPCJSRuntime::Get()->Runtime();
  PR_Lock(gLock);
  delete gRuntimeToGCHeapProfiler[runtime];
  gRuntimeToGCHeapProfiler.erase(runtime);
  if (gRefCnt == 0) {
    delete gNativeProfiler;
    gNativeProfiler = nullptr;
  }
  PR_Unlock(gLock);
  return NS_OK;
}

static std::tuple<std::vector<std::string>, std::vector<TrieNode>, std::vector<AllocEvent>>
merge(std::vector<std::string> names0, std::vector<TrieNode> traces0, std::vector<AllocEvent> events0,
      std::vector<std::string> names1, std::vector<TrieNode> traces1, std::vector<AllocEvent> events1)
{
  Unique<string> names;
  Unique<TrieNode, TrieHasher> traces;
  std::vector<AllocEvent> events;

  std::vector<size_t> names1Tonames0;
  std::vector<size_t> traces1Totraces0(1, 0);

  // Merge names.
  for (auto &i: names0)
    names.insert(i);
  for (auto &i: names1)
    names1Tonames0.push_back(names.insert(i));

  // Merge traces. Note that traces1[i].parentIdx < i for all i > 0.
  for (auto &i: traces0)
    traces.insert(i);
  for (size_t i = 1; i < traces1.size(); i++) {
    TrieNode node = traces1[i];
    node.parentIdx = traces1Totraces0[node.parentIdx];
    node.nameIdx = names1Tonames0[node.nameIdx];
    traces1Totraces0.push_back(traces.insert(node));
  }

  // Update events1
  for (auto &i: events1)
    i.mTraceIdx = traces1Totraces0[i.mTraceIdx];

  // Merge the events according to timestamps.
  auto p0 = events0.begin();
  auto p1 = events1.begin();

  while (p0 != events0.end() && p1 != events1.end()) {
    if (p0->mTimestamp < p1->mTimestamp) {
      events.push_back(*p0);
      p0++;
    } else {
      events.push_back(*p1);
      p1++;
    }
  }

  while (p0 != events0.end())
    events.push_back(*p0++);

  while (p1 != events1.end())
    events.push_back(*p1++);

  return std::make_tuple(names.serialize(), traces.serialize(), move(events));
}

NS_IMETHODIMP
MemoryProfiler::GetResults(JSContext *cx, JS::MutableHandle<JS::Value> aResult)
{
  JSRuntime *runtime = XPCJSRuntime::Get()->Runtime();
  GCHeapProfilerImpl *gp = gRuntimeToGCHeapProfiler[runtime];
  if (!gp)
    return NS_OK;

  auto results = merge(gp->getNames(), gp->getTraces(), gp->getEvents(),
      gNativeProfiler->getNames(), gNativeProfiler->getTraces(), gNativeProfiler->getEvents());
  std::vector<std::string> names = move(std::get<0>(results));
  std::vector<TrieNode> traces = move(std::get<1>(results));
  std::vector<AllocEvent> events = move(std::get<2>(results));

  JS::RootedObject jsnames(cx, JS_NewArrayObject(cx, names.size()));
  JS::RootedObject jstraces(cx, JS_NewArrayObject(cx, traces.size()));
  JS::RootedObject jsevents(cx, JS_NewArrayObject(cx, events.size()));

  for (size_t i = 0; i < names.size(); i++) {
    JS::RootedString name(cx, JS_NewStringCopyZ(cx, names[i].c_str()));
    JS_SetElement(cx, jsnames, i, name);
  }

  for (size_t i = 0; i < traces.size(); i++) {
    JS::RootedObject tn(cx, JS_NewObject(cx, nullptr, JS::NullPtr(), JS::NullPtr()));
    JS::RootedValue nameIdx(cx, JS_NumberValue(traces[i].nameIdx));
    JS::RootedValue parentIdx(cx, JS_NumberValue(traces[i].parentIdx));
    JS_SetProperty(cx, tn, "nameIdx", nameIdx);
    JS_SetProperty(cx, tn, "parentIdx", parentIdx);
    JS_SetElement(cx, jstraces, i, tn);
  }

  int i = 0;
  for (auto ent: events) {
    if (ent.mSize == 0)
      continue;
    JS::RootedObject tn(cx, JS_NewObject(cx, nullptr, JS::NullPtr(), JS::NullPtr()));
    JS::RootedValue size(cx, JS_NumberValue(ent.mSize));
    JS::RootedValue traceIdx(cx, JS_NumberValue(ent.mTraceIdx));
    JS::RootedValue timestamp(cx, JS_NumberValue(ent.mTimestamp));
    JS_SetProperty(cx, tn, "size", size);
    JS_SetProperty(cx, tn, "traceIdx", traceIdx);
    JS_SetProperty(cx, tn, "timestamp", timestamp);
    JS_SetElement(cx, jsevents, i++, tn);
  }
  JS_SetArrayLength(cx, jsevents, i);

  JS::RootedObject result(cx, JS_NewObject(cx, nullptr, JS::NullPtr(), JS::NullPtr()));
  JS::RootedValue objnames(cx, ObjectOrNullValue(jsnames));
  JS_SetProperty(cx, result, "names", objnames);
  JS::RootedValue objtraces(cx, ObjectOrNullValue(jstraces));
  JS_SetProperty(cx, result, "traces", objtraces);
  JS::RootedValue objevents(cx, ObjectOrNullValue(jsevents));
  JS_SetProperty(cx, result, "events", objevents);
  aResult.setObject(*result);
  return NS_OK;
}
