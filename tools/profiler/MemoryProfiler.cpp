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

extern void MPStart(JSRuntime *);
extern void MPStop(JSRuntime *);
extern void MPReset(JSRuntime *);
extern void MPIsActive(JSRuntime *);
extern char *MPGetResult(JSRuntime *);
extern JSObject* MPGetFrameNameTable(JSRuntime *runtime, JSContext *cx);
extern JSObject* MPGetStacktraceTable(JSRuntime *runtime, JSContext *cx);
extern JSObject* MPGetAllocatedEntries(JSRuntime *runtime, JSContext *cx);

NS_IMPL_ISUPPORTS(MemoryProfiler, nsIMemoryProfiler)

MemoryProfiler::MemoryProfiler()
{
  /* member initializers and constructor code */
}

MemoryProfiler::~MemoryProfiler()
{
  /* destructor code */
}

NS_IMETHODIMP
MemoryProfiler::StartProfiler()
{
  XPCJSRuntime* rt = XPCJSRuntime::Get();
  MPStart(rt->Runtime());
  return NS_OK;
}

NS_IMETHODIMP
MemoryProfiler::StopProfiler()
{
  XPCJSRuntime* rt = XPCJSRuntime::Get();
  MPStop(rt->Runtime());
  return NS_OK;
}

NS_IMETHODIMP
MemoryProfiler::ResetProfiler()
{
  XPCJSRuntime* rt = XPCJSRuntime::Get();
  MPReset(rt->Runtime());
  return NS_OK;
}


NS_IMETHODIMP
MemoryProfiler::GetFrameNameTable(JSContext *cx, JS::MutableHandle<JS::Value> aResult)
{
  JSRuntime *runtime = XPCJSRuntime::Get()->Runtime();
  aResult.setObject(*MPGetFrameNameTable(runtime, cx));
  return NS_OK;
}

NS_IMETHODIMP
MemoryProfiler::GetStacktraceTable(JSContext *cx, JS::MutableHandle<JS::Value> aResult)
{
  JSRuntime *runtime = XPCJSRuntime::Get()->Runtime();
  aResult.setObject(*MPGetStacktraceTable(runtime, cx));
  return NS_OK;
}

NS_IMETHODIMP
MemoryProfiler::GetAllocatedEntries(JSContext *cx, JS::MutableHandle<JS::Value> aResult)
{
  JSRuntime *runtime = XPCJSRuntime::Get()->Runtime();
  aResult.setObject(*MPGetAllocatedEntries(runtime, cx));
  return NS_OK;
}

