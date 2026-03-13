// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
//
// Platform abstraction macros for compiler-specific attributes.
// This is a lightweight header safe to include from anywhere without
// pulling in heavy dependencies.

#pragma once

/**
 * Marks an extern declaration for import from the host executable when
 * compiling JIT DLL code on MSVC. MSVC requires explicit __declspec(dllimport)
 * for symbols defined in a different binary (the host executable); on other
 * platforms or in non-JIT builds, extern linkage alone suffices.
 *
 * Usage: extern HILTI_JIT_IMPORT Type name;
 */
#if defined(_MSC_VER) && defined(HILTI_JIT_DLL)
#define HILTI_JIT_IMPORT __declspec(dllimport)
#else
#define HILTI_JIT_IMPORT
#endif

/**
 * For class-static data members that are normally ``inline static`` but need
 * to be imported from the host executable in JIT DLL builds on MSVC. When
 * building a JIT DLL, MSVC places ``inline static`` data in the DLL's .rdata
 * (read-only) section, which breaks because these counters must be mutable
 * and shared with the host. Importing them from the host executable solves
 * both problems.
 *
 * Usage: HILTI_JIT_IMPORT_OR_INLINE static uint64_t counter;
 */
#if defined(_MSC_VER) && defined(HILTI_JIT_DLL)
#define HILTI_JIT_IMPORT_OR_INLINE __declspec(dllimport)
#else
#define HILTI_JIT_IMPORT_OR_INLINE inline
#endif

/** Marks a function as never returning. */
#if defined(_MSC_VER)
#define HILTI_NORETURN __declspec(noreturn)
#else
#define HILTI_NORETURN __attribute__((noreturn))
#endif

/** Prevents the compiler from inlining a function. */
#if defined(_MSC_VER)
#define HILTI_NOINLINE __declspec(noinline)
#else
#define HILTI_NOINLINE __attribute__((noinline))
#endif
