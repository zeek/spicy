// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <compiler/driver.h>

#include <memory>
#include <string>
#include <vector>

#include <zeek-spicy/plugin.h>

namespace plugin::Zeek_Spicy {

/** Customized Spicy-to-Zeek Driver class that the JIT plugin employs. */
class Driver : public spicy::zeek::Driver {
public:
    using spicy::zeek::Driver::Driver;

protected:
    /** Overidden from driver class. */
    void hookAddInput(const std::filesystem::path& path) override;

    /** Overidden from driver class. */
    void hookAddInput(const hilti::Module& m, const std::filesystem::path& path) override;

    /** Overidden from driver class. */
    void hookNewEnumType(const spicy::zeek::EnumInfo& e) override;

private:
    friend class PluginJIT;
    void _initialize();

    bool _initialized = false;
    std::vector<std::filesystem::path> _import_paths;
};

/** JIT version of the Zeek plugin. */
class PluginJIT : public Plugin {
public:
    PluginJIT();
    virtual ~PluginJIT();

private:
    // Overriding method from Zeek's plugin API.
    void addLibraryPaths(const std::string& dirs) override;

    // Overriding method from Zeek's plugin API.
    void InitPreScript() override;

    // Overriding method from Zeek's plugin API.
    void InitPostScript() override;

    // Overriding method from Zeek's plugin API.
    int HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved) override;

    std::unique_ptr<Driver> _driver;
};

} // namespace plugin::Zeek_Spicy

#ifdef ZEEK_HAVE_JIT
extern plugin::Zeek_Spicy::PluginJIT SpicyPlugin;
#endif
