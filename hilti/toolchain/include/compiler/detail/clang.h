// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>

#include <hilti/base/result.h>
#include <hilti/compiler/jit.h>

#ifndef HILTI_HAVE_JIT
#error clang.h cannot be included if JIT support is not compiled in
#endif

namespace hilti::detail {

/** JIT implementation using clang/LLVM as the backend. */
class ClangJIT {
public:
    /**
     * Constructor
     *
     * @param context global context to pull settings from
     */
    ClangJIT(std::shared_ptr<Context> context);
    ~ClangJIT();

    ClangJIT(const ClangJIT&) = delete;
    ClangJIT(ClangJIT&&) noexcept = delete;
    ClangJIT& operator=(const ClangJIT&) = delete;
    ClangJIT& operator=(ClangJIT&&) noexcept = delete;

    /**
     * Compiles one C++ module into LLVM bitcode. This kicks off Clang
     * compilation and then stores the resulting LLVM module internally. for
     * later linking.
     *
     * This must be called after ``init()`` and before ``jit()``.
     *
     * @param code in-memory representation of the C++ code to compile
     * @return true if compilation succeeded; the LLVM module will then have
     * been recorded internally for later linking
     */
    bool compile(const CxxCode& code);

    /**
     * Compiles one C++ module into LLVM bitcode. This kicks off Clang
     * compilation and then stores the resulting LLVM module internally. for
     * later linking.
     *
     * This must be called after ``init()`` and before ``jit()``.
     *
     * @param p path to read C++ code from
     * @return true if compilation succeeded; the LLVM module will then have
     * been recorded internally for later linking
     */
    bool compile(const std::filesystem::path& p);

    /*
     * Links all LLVM< bitcode modules compiled far into one LLVM module
     * using LLVM's linker class. Then, just in times that joined module and
     * adds its symbols to the JIT. Like its cousin, `init()`, this method
     * failing is likely reason to stop execution.
     *
     * This must be called after ``init()`` and after all desired code has
     * been added.
     *
     * @return success if linking and JITing was successful, an appropiate
     * error otherwise.
     */
    Result<Nothing> jit();

    /**
     * Retrieves the compiled object code. This must be called only after
     * ``jit()`` has succeeded and will return the shared library for the
     * final fully-linked module.
     */
    std::shared_ptr<const Library> retrieveLibrary() const;

    /**
     * Activates saving any emitted code to disk for debugging purposes.
     * It will land in files ``dbg.*``.
     */
    void setDumpCode();

    /** Returns a string describing the version of Clang compiler in use. */
    static std::string compilerVersion();

private:
    struct Implementation;
    std::unique_ptr<Implementation> _impl; // PIMPL
};

} // namespace hilti::detail
