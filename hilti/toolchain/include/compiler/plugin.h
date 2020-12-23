// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/3rdparty/ArticleEnumClass-v2/EnumClass.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/node.h>
#include <hilti/ast/type.h>
#include <hilti/base/logger.h>
#include <hilti/base/result.h>
#include <hilti/base/util.h>
#include <hilti/compiler/coercion.h>
#include <hilti/compiler/context.h>

namespace hilti {

class Unit;
class Context;

namespace printer {
class Stream;
} // namespace printer

/**
 * Compiler plugin that can hook into the compilation process that's driven
 * by `Unit`.
 *
 * A plugin gets access to the AST at all major stages. In particular it can
 * add support implement support for new language using HILTI as its code
 * generation backend by providing a parse method building its AST, along
 * with a transformation method converting any non-standard nodes HILTI
 * equivalents.
 *
 * A plugin implements a set of hook methods that get called by the
 * compilation process at the appropriate times. All hooks should be
 * stateless, apart from changing the AST where appropriate.
 *
 * @note HILTI compilation itself is also implemented through a default
 * plugin that's always available. `Unit` cycles through all available
 * plugins during the compilation process, including that default plugin.
 */
struct Plugin {
    /** Helper template to define the type of hook methods. */
    template<typename Result, typename... Args>
    using Hook = std::optional<std::function<Result(Args...)>>;

    /** Name of the plugin. */
    std::string component;

    /** Extension for source files that the plugin handles. Must include the leading `.`. */
    hilti::rt::filesystem::path extension;

    /**
     * Additional C++ include files that the plugin needs to have added to
     * generated C++ code.
     */
    std::vector<hilti::rt::filesystem::path> cxx_includes;

    /**
     * Callbacks for plugins will be executed in numerical order, with lower
     * order numbers executing first.
     */
    int order = 0;

    /**
     * Hook called to retrieve paths to search when importing modules that
     * this plugin handles.
     *
     * @param arg1 compiler context that's in use
     * @return directories to search
     */
    Hook<std::vector<hilti::rt::filesystem::path>, std::shared_ptr<hilti::Context>> library_paths;

    /**
     * Hook called to parse input file that this plugin handles.
     *
     * @param arg1 compiler context that's in use
     * #param arg2 input stream to parse
     * @param arg3 file associated with the input stream
     * @return directories to search
     */
    Hook<Result<Node>, std::istream&, hilti::rt::filesystem::path> parse;

    /**
     * Hook called to perform coercion of a `Ctor` into another of a given target type.
     *
     * If the plugin knows how to handle the coercion, the hook returns a new
     * `Ctor` that's now of the target type.
     *
     * @param arg1 compiler context that's in use
     * @param arg2 ctor that needs coercion
     * @param arg3 target type for ctor
     * @param arg4 coercion style to use
     * @return new ctor if plugin performed coercion
     */
    Hook<std::optional<Ctor>, Ctor, const Type&, bitmask<CoercionStyle>> coerce_ctor;

    /**
     * Hook called to approved coercion of an expression into a different
     * type.
     *
     * If the plugin knows it can handle the coercion, it returns the
     * resulting coerced `Type`. If so, it must then also provide an
     * `apply_coercions` hook that will later be called to perform the actual
     * coercion during code generation.
     *
     * @param arg1 compiler context that's in use
     * @param arg2 type that needs coercion
     * @param arg3 target type for coercion
     * @param arg4 coercion style to use
     * @return new type if plugin can handle this coercion
     */
    Hook<std::optional<Type>, Type, const Type&, bitmask<CoercionStyle>> coerce_type;

    /**
     * Hook called to build the scopes in a module's AST.
     *
     * @param arg1 compiler context that's in use
     * @param arg2 root node of AST; the hook may modify the AST
     * @param arg3 current unit being compiled
     * @return true if the hook modified the AST in a substantial way
     */
    Hook<void, std::shared_ptr<hilti::Context>, const std::vector<std::pair<ID, NodeRef>>&, Unit*> build_scopes;

    /**
     * Hook called to resolved IDs in a module's AST.
     *
     * @param arg1 compiler context that's in use
     * @param arg2 root node of AST; the hook may modify the AST
     * @param arg3 current unit being compiled
     * @return true if the hook modified the AST in a substantial way
     */
    Hook<bool, std::shared_ptr<hilti::Context>, Node*, Unit*> resolve_ids;

    /**
     * Hook called to resolved operators in a module's AST.
     *
     * @param arg1 compiler context that's in use
     * @param arg2 root node of AST; the hook may modify the AST
     * @param arg3 current unit being compiled
     * @return true if the hook modified the AST in a substantial way
     */
    Hook<bool, std::shared_ptr<hilti::Context>, Node*, Unit*> resolve_operators;

    /**
     * Hook called perform coercions. This must carry out all the coercions
     * that `coerce_type` has indicated as valid.
     *
     * @param arg1 compiler context that's in use
     * @param arg2 root node of AST; the hook may modify the AST
     * @param arg3 current unit being compiled
     * @return true if the hook modified the AST in a substantial way
     */
    Hook<bool, std::shared_ptr<hilti::Context>, Node*, Unit*> apply_coercions;

    /**
     * Hook called to validate correctness of an AST, pre-transformation. Any
     * errors must be reported by setting the nodes' error information.
     *
     * @param arg1 compiler context that's in use
     * @param arg2 root node of AST; the hook may not modify the AST
     * @param arg3 current unit being compiled
     * @param arg4 pointer to boolean that the hook must set to true to
     * indicate that errors were encountered.
     */
    Hook<void, std::shared_ptr<hilti::Context>, Node*, Unit*, bool*> pre_validate;

    /**
     * Hook called to validate correctness of an AST, post-transformation.
     * Any errors must be reported by setting the nodes' error information.
     *
     * @param arg1 compiler context that's in use
     * @param arg2 root node of AST; the hook may not modify the AST
     * @param arg3 current unit being compiled
     */
    Hook<void, std::shared_ptr<hilti::Context>, Node*, Unit*> post_validate;

    /**
     * Hook called to validate correctness of AST nodes that a module
     * preserved before transformation. The hook runs just before the
     * ``post_validate`` hook. Any errors must be reported by setting the
     * nodes' error information.
     *
     * @param arg1 compiler context that's in use
     * @param arg2 preserved nodes to validate
     * @param arg3 current unit being compiled
     */
    Hook<void, std::shared_ptr<hilti::Context>, std::vector<Node>*, Unit*> preserved_validate;

    /**
     * Hook called to replace any custom AST nodes with standard HILTI
     * nodes. Note that this may be called multiple times while ASTs are built.
     *
     * @param arg1 compiler context that's in use
     * @param arg2 root node of AST; the hook may modify the AST
     * @param arg3 boolean that's true if this hook runs for the first time on this AST.
     * @param arg4 current unit being compiled
     * @return true if the hook modified the AST in a substantial way
     */
    Hook<bool, std::shared_ptr<hilti::Context>, Node*, bool, Unit*> transform;

    /**
     * Hook called to print an AST back as source code. The hook gets to
     * choose if it wants to print the node itself, or fall back to the default printer.
     *
     * @param arg1 root of AST to print
     * @param arg2 stream to print to
     * @return true if the hook printed the AST, false to fall back to default
     */
    Hook<bool, const Node&, hilti::printer::Stream&> print_ast;
};

class PluginRegistry;

namespace plugin {
/** Returns the global plugin registry. It's a singleton instance. */
PluginRegistry& registry();
} // namespace plugin

/**
 * Maintains the set of all available plugins. `registry()` returns the
 * global singleton registry instance.
 */
class PluginRegistry {
public:
    PluginRegistry();

    /**
     * Returns a vector of all currently registered plugins, sorted by their
     * order numbers.
     */
    const std::vector<Plugin>& plugins() const { return _plugins; }

    /**
     * Returns the plugin handling a module with a given file extension, if
     * available.
     *
     * @param ext extension, including the leading `.`
     * @return plugin if any has been register for the extension
     */
    Result<Plugin> pluginForExtension(hilti::rt::filesystem::path ext) const;

    /**
     * Checks if at least one plugin implements a given hook.
     *
     * \tparam PluginMember the hook
     * \return true if there's an implementation for the hook
     */
    template<typename PluginMember>
    bool hasHookFor(PluginMember hook) {
        for ( const auto& p : plugin::registry().plugins() ) {
            if ( p.*hook )
                return true;
        }

        return false;
    }

    /**
     * Checks if there a plugin registered for a specific file extension.
     *
     * @param ext extension, including the leading `.`
     * \return true if there's a plugin for this extension
     */
    bool supportsExtension(hilti::rt::filesystem::path ext) const {
        return pluginForExtension(std::move(ext)).hasValue();
    }

    /** Returns a vector of all extensions that registered set of plugins handles. */
    auto supportedExtensions() const {
        return util::transform(_plugins, [](auto& p) { return p.extension; });
    }

    /**
     * Registers a plugin with the registry.
     *
     * @note This method should normally not be called directly, use
     * `plugin::Register()` instead.
     *
     * @param p plugin to register
     */
    void register_(const Plugin& p);

private:
    std::vector<Plugin> _plugins;
};

namespace plugin {
/**
 * Helper class to register a plugin at startup. To add a plugin, create a
 * global `Register` instance to register it.
 */
class Register {
public:
    /**
     * Registers a plugin with the global `registry()`.
     *
     * @param p plugin to register
     */
    Register(const Plugin& p) { registry().register_(p); }
};

} // namespace plugin

} // namespace hilti
