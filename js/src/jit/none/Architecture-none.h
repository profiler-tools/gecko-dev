/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 * vim: set ts=8 sts=4 et sw=4 tw=99:
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef jit_none_Architecture_none_h
#define jit_none_Architecture_none_h

// JitSpewer.h is included through MacroAssembler implementations for other
// platforms, so include it here to avoid inadvertent build bustage.
#include "jit/JitSpewer.h"

namespace js {
namespace jit {

static const bool SupportsSimd = false;
static const uint32_t SimdStackAlignment = 4; // Make it 4 to avoid a bunch of div-by-zero warnings
static const uint32_t AsmJSStackAlignment = 4;

class Registers
{
  public:
    typedef uint8_t Code;
    typedef uint8_t SetType;

    static uint32_t SetSize(SetType) { MOZ_CRASH(); }
    static uint32_t FirstBit(SetType) { MOZ_CRASH(); }
    static uint32_t LastBit(SetType) { MOZ_CRASH(); }
    static const char *GetName(Code) { MOZ_CRASH(); }
    static Code FromName(const char *) { MOZ_CRASH(); }

    static const Code StackPointer = 0;
    static const Code Invalid = 0;
    static const uint32_t Total = 1;
    static const uint32_t TotalPhys = 0;
    static const uint32_t Allocatable = 0;
    static const uint32_t AllMask = 0;
    static const uint32_t ArgRegMask = 0;
    static const uint32_t VolatileMask = 0;
    static const uint32_t NonVolatileMask = 0;
    static const uint32_t NonAllocatableMask = 0;
    static const uint32_t AllocatableMask = 0;
    static const uint32_t TempMask = 0;
    static const uint32_t JSCallMask = 0;
    static const uint32_t CallMask = 0;
};

typedef uint8_t PackedRegisterMask;

class FloatRegisters
{
  public:
    typedef uint8_t Code;
    typedef uint32_t SetType;

    static const char *GetName(Code) { MOZ_CRASH(); }
    static Code FromName(const char *) { MOZ_CRASH(); }

    static const Code Invalid = 0;
    static const uint32_t Total = 0;
    static const uint32_t TotalPhys = 0;
    static const uint32_t Allocatable = 0;
    static const uint32_t AllMask = 0;
    static const uint32_t AllDoubleMask = 0;
    static const uint32_t VolatileMask = 0;
    static const uint32_t NonVolatileMask = 0;
    static const uint32_t NonAllocatableMask = 0;
    static const uint32_t AllocatableMask = 0;
};

template <typename T>
class TypedRegisterSet;

struct FloatRegister
{
    typedef FloatRegisters Codes;
    typedef Codes::Code Code;
    typedef Codes::SetType SetType;

    Code _;

    static uint32_t FirstBit(SetType) { MOZ_CRASH(); }
    static uint32_t LastBit(SetType) { MOZ_CRASH(); }
    static FloatRegister FromCode(uint32_t) { MOZ_CRASH(); }
    Code code() const { MOZ_CRASH(); }
    const char *name() const { MOZ_CRASH(); }
    bool volatile_() const { MOZ_CRASH(); }
    bool operator != (FloatRegister) const { MOZ_CRASH(); }
    bool operator == (FloatRegister) const { MOZ_CRASH(); }
    bool aliases(FloatRegister) const { MOZ_CRASH(); }
    uint32_t numAliased() const { MOZ_CRASH(); }
    void aliased(uint32_t, FloatRegister *) { MOZ_CRASH(); }
    bool equiv(FloatRegister) const { MOZ_CRASH(); }
    uint32_t size() const { MOZ_CRASH(); }
    uint32_t numAlignedAliased() const { MOZ_CRASH(); }
    void alignedAliased(uint32_t, FloatRegister *) { MOZ_CRASH(); }
    template <typename T> static T ReduceSetForPush(T) { MOZ_CRASH(); }
    uint32_t getRegisterDumpOffsetInBytes() { MOZ_CRASH(); }

    // This is used in static initializers, so produce a bogus value instead of crashing.
    static uint32_t GetPushSizeInBytes(const TypedRegisterSet<FloatRegister> &) { return 0; }
};

inline bool hasUnaliasedDouble() { MOZ_CRASH(); }
inline bool hasMultiAlias() { MOZ_CRASH(); }

static const uint32_t ShadowStackSpace = 0;

#ifdef JS_NUNBOX32
static const int32_t NUNBOX32_TYPE_OFFSET = 4;
static const int32_t NUNBOX32_PAYLOAD_OFFSET = 0;
#endif

} // namespace jit
} // namespace js

#endif /* jit_none_Architecture_none_h */
