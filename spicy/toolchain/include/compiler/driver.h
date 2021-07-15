// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/compiler/driver.h>

namespace spicy {

/**
 * Compiler options for the Spicy code generator.
 */
struct Options {
    bool track_offsets = false; /**< true to have the generated code record fields' offsets */
};

/**
 * Compiler driver.
 *
 * The driver is a high-level building block for writing command-line tools
 * compiling Spicy source files (and more). `spicyc` is just a tiny
 * wrapper around this class. This class derives from `hilti::Driver``, which
 * does all the heavy lifting. Classes can in turn further derive from the driver
 * to expand its functionality.
 */
class Driver : public hilti::Driver {
public:
    /**
     * @param name descriptive name for the tool using the driver, which will
     * be used in usage and error messages.
     */
    explicit Driver(std::string name) : hilti::Driver(name) {}

    /**
     * @param name descriptive name for the tool using the driver, which will
     * be used in usage and error messages.
     * @param argv0 the current exectuable, which will change the path's that
     * the global options instance returns if it's inside Spicy build
     * directory.
     */
    Driver(std::string name, const hilti::rt::filesystem::path& argv0) : hilti::Driver(name, argv0) {}

    virtual ~Driver() {}

    Driver() = delete;
    Driver(const Driver&) = delete;
    Driver(Driver&&) noexcept = delete;
    Driver& operator=(const Driver&) = delete;
    Driver& operator=(Driver&&) noexcept = delete;

    /** Returns the Spicy compiler options currently in effect. */
    spicy::Options spicyCompilerOptions() const;

    /**
     * Sets Spicy's compiler options.
     *
     * @param options the options
     */
    void setSpicyCompilerOptions(const spicy::Options& options);

protected:
    std::string hookAddCommandLineOptions() override;
    bool hookProcessCommandLineOption(char opt, const char* optarg) override;
    std::string hookAugmentUsage() override;

private:
    spicy::Options _compiler_options;
};

} // namespace spicy
