// Copyright (c) 2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <memory_resource>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <hilti/rt/types/integer.h>

#include <hilti/ast/declarations/module-uid.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>
#include <hilti/base/logger.h>
#include <hilti/base/uniquer.h>

namespace hilti {

class ASTContext;
class Context;
class Driver;
struct Plugin;

namespace type {
struct Wildcard;
}

/**
 * Parses a HILTI source file into an AST.
 *
 * @param builder builder to use for constructing the AST
 * @param in stream to read from
 * @param filename path associated with the input
 *
 * @returns the parsed AST, or a corresponding error if parsing failed.
 */
Result<declaration::Module*> parseSource(Builder* builder, std::istream& in, const std::string& filename);

namespace ast {

namespace detail {

/**
 * Helper class to define a strongly-typed index type used with maps inside the
 * AST context.
 */
template<char Prefix>
class ContextIndex {
public:
    /**
     * Constructor.
     *
     * @param index value to store with the index, which should be larger than
     * zero for valid indices; zero is the default and reserved for `None`.
     */
    explicit ContextIndex(uint64_t index = 0) : _value(index) {}

    /** Returns the index' value. */
    auto value() const { return _value; }

    /**
     * Returns a string representation of the value, including a prefix
     * indicating the index' type.
     */
    auto str() const { return _value > 0 ? std::string(1, Prefix) + std::to_string(_value) : std::string("-"); }

    /** Returns true if the index is not `None` (i.e., zero). */
    explicit operator bool() const { return *this != None; }

    bool operator==(const ContextIndex& other) const { return _value == other._value; }
    bool operator!=(const ContextIndex& other) const { return _value != other._value; }

    ContextIndex(const ContextIndex& other) = default;
    ContextIndex(ContextIndex&& other) noexcept = default;
    ContextIndex& operator=(const ContextIndex& other) = default;
    ContextIndex& operator=(ContextIndex&& other) noexcept = default;

    inline static const ContextIndex None{0}; /**< index with reserved value zero representing an unset index */

private:
    uint64_t _value;
};

template<char Prefix>
inline std::string to_string(const hilti::ast::detail::ContextIndex<Prefix>& index) {
    return index.str();
}

template<char Prefix>
inline std::ostream& operator<<(std::ostream& out, const hilti::ast::detail::ContextIndex<Prefix>& index) {
    return out << index.str();
}
} // namespace detail

/** Strongly typed index for declarations. */
using DeclarationIndex = detail::ContextIndex<'D'>;

/** Strongly typed index for types. */
using TypeIndex = detail::ContextIndex<'T'>;

} // namespace ast

/**
 * Environment for AST-wide state. The context maintains the AST root node and
 * owns all nodes added to it or, recursively, any of if children. Each node
 * can be part of just one AST context. Over time, the context also builds up
 * further state about the AST.
 */
class ASTContext : public std::enable_shared_from_this<ASTContext> {
public:
    /**
     * Constructor.
     *
     * @param context compiler context to use for logging and error reporting
     */
    ASTContext(Context* context);

    /** Destructor. */
    ~ASTContext();

    /** Returns the AST's root node. This always exists. */
    auto root() const { return _root; }

    /**
     * Parses a source file and adds it to the AST as a new module. If a module
     * for this file is already part of the AST, returns the existing module
     * without any further AST changes.
#    *
     *
     * @param builder builder to use for constructing the parsed AST
     * @param path path to source file to parse
     * @param process_extension if given, file extension indicating which
     * plugin to use later for processing the resulting AST for the module; if
     * not given, the same plugin will be used as for parsing (which is
     * determined by the path's extension)
     * @return UID of the parsed module (which is now a part of the AST), or an
     * error if parsing failed
     */
    Result<declaration::module::UID> parseSource(Builder* builder, const hilti::rt::filesystem::path& path,
                                                 std::optional<hilti::rt::filesystem::path> process_extension = {});

    /**
     * Imports a module from an external source file and adds it to the AST as
     * a new module. This implements HILTI's `import` statement. If a module
     * for the requested `import` is already part of the AST, returns the
     * existing module without any further AST changes.
     *
     * @param builder builder to use for constructing the parsed AST
     * @param id name of the module to import (as in: ``import <id>``)
     * @param scope search scope for the import (as in: ``import ... from <scope>``)
     * @param parse_extension file extension indicating which plugin to use for
     * parsing the module's source code
     * @param process_extension if given, file extension indicating which
     * plugin to use later for processing the resulting AST; if not given, the
     * same plugin will be used as for parsing
     * @param search_dirs list of directories to search for the module's source
     * (in addition to any globally configured search directories)
     * @return UID of the parsed module (which is now a part of the AST), or an
     * error if parsing failed
     */
    Result<declaration::module::UID> importModule(Builder* builder, const ID& id, const ID& scope,
                                                  const hilti::rt::filesystem::path& parse_extension,
                                                  const std::optional<hilti::rt::filesystem::path>& process_extension,
                                                  std::vector<hilti::rt::filesystem::path> search_dirs);

    /** Adds a new, empty module to the AST. */
    declaration::Module* newModule(Builder* builder, const ID& id,
                                   const hilti::rt::filesystem::path& process_extension);

    /**
     * Retrieves a module node from the AST given its UID. Returns null if no
     * such module exists.
     *
     * @param uid UID of module to return
     */
    declaration::Module* module(const declaration::module::UID& uid) const {
        if ( auto m = _modules_by_uid.find(uid); m != _modules_by_uid.end() )
            return m->second;
        else
            return nullptr;
    }

    /**
     * Processes the whole AST with all of the compiler's visitor passes. This
     * is the top-level entry point for all resolving/validating/optimizing. If
     * successful, the will be fully resolved and validated; and ready for code
     * generation.
     *
     * @param builder current compiler builder, which AST processing may access
     * @param driver current compiler driver, which AST processing may access
     */
    Result<Nothing> processAST(Builder* builder, Driver* driver);

    /**
     * During AST processing, returns the current compiler driver. If called
     * outside of `processAST() executing, it will return null.
     */
    Driver* driver() const { return _driver; }

    /**
     * Returns direct & indirect dependencies that a module imports. This
     * information will be available only once the AST has been processed
     * successfully through `processAST()`.
     *
     * @param uid UID of module to return dependencies for; the module must be
     * known, otherwise an internal error is reported
     * @param recursive if true, return the transitive closure of all
     * dependent units, vs just direct dependencies of the specified unit
     * @return set of dependencies
     */
    std::vector<declaration::module::UID> dependencies(const declaration::module::UID& uid,
                                                       bool recursive = false) const;

    /**
     * Updates an existing UID with new information.
     *
     * The given, old UID must correspond to a module parsed or imported into
     * the context. This method then changes the module associated with that
     * old UID to be associated with the new UID instead, and updates any
     * context state accordingly, so that the module can now be found through
     * the new UID.
     *
     * @param old_uid existing UID; it's an internal error if this doesn't exist
     * @param new_uid new UID to replace `old_uid`
     */
    void updateModuleUID(const declaration::module::UID& old_uid, const declaration::module::UID& new_uid);

    /**
     * Registers a declaration with the context, assigning it a unique index
     * through which it can later be retrieved. That index is automatically
     * stored with the declaration as its `declarationindex().
     *
     * If the declaration is a type declaration, the method also sets the
     * declared type's `declarationIndex()` accordingly, linked the type with
     * its declaration.
     *
     * If the same declaration had already been registered earlier, nothing is
     * changed; the method then simply returns the prior index.
     *
     * @param decl declaration to register
     * @returns the index now associated with the declaration; it's value is
     * guaranteed to not be `None` (and hence be larger than zero).
     */
    ast::DeclarationIndex register_(Declaration* decl);

    /**
     * Returns the declaration associated with an index.
     *
     * @param index index to lookup, which must have been registered before to
     * not trigger an internal error; unless its `None`, in which case it
     * returns `null`.
     */
    Declaration* lookup(ast::DeclarationIndex index); // must exists, otherwise internal error -> result is not null

    /**
     * Replaces a previously registered declaration with a new one. This means
     * that any lookup for the existing declaration's index will now return the
     * new declaration instead. The new declaration's `declarationIndex()` will
     * automatically be set to index; the old declaration's
     * `declarationIndex()` will not be changed.
     *
     * If the new declaration is a type declaration, the method also sets the
     * declared type's `declarationIndex()` accordingly, linking the type with
     * its declaration. The old declaraed type is not changed.
     *
     * @param old old declaration; if it has not been registered yet at all,
     * the method returns without doing anything
     * @param new new declaration to take the place of the old one
     */
    void replace(Declaration* old, Declaration* new_);

    /**
     * Registers a type with the context, assigning it a unique index through
     * which it can later be retrieved. That index is automatically stored with
     * the type as its `typeIndex().
     *
     * If the same type had already been registered earlier, nothing is
     * changed; the method then simply returns the prior index.
     *
     * @param decl declaration to register
     * @returns the index now associated with the type; it's value is
     * guaranteed to not be `None` (and hence be larger than zero).
     */
    ast::TypeIndex register_(UnqualifiedType* type);

    /**
     * Returns the type associated with an index.
     *
     * @param index index to lookup, which must have been registered before to
     * not trigger an internal error; unless its `None`, in which case it
     * returns `null`.
     */
    UnqualifiedType* lookup(ast::TypeIndex index);

    /**
     * Replaces a previously registered type with a new one. This means
     * that any lookup for the existing type's index will now return the
     * new type instead. The new type's `typeIndex()` will
     * automatically be set to index; the old type's
     * `typeIndex()` will not be changed.
     *
     * @param old old type; if it has not been registered yet at all,
     * the method returns without doing any tying
     * @param new new type to take the place of the old one
     */
    void replace(UnqualifiedType* old, UnqualifiedType* new_);

    /**
     * Given an ID that's supposed to become a declaration's canonical ID,
     * ensure that ID is globally unique within the context, returning an appropriately modified version if necessary.
     */
    ID uniqueCanononicalID(const ID& id) { return _canon_id_uniquer.get(id, false); }

    /**
     * Dumps the current total AST of all modules to a debug stream.
     *
     * @param stream debug stream to write to
     * @param prefix prefix line to start output with
     */
    void dump(const hilti::logging::DebugStream& stream, const std::string& prefix);

    /**
     * Factory function creating a new node of type T. This allocates the new
     * through the context-wide memory resource.
     *
     * @param args arguments to pass to the constructor of T
     */
    template<typename T, typename... Args>
    T* make(Args&&... args) {
        return new (allocateNode<T>()) T(std::forward<Args>(args)...);
    }

    /**
     * Factory function creating a new node of type T. This allocates the new
     * through the context-wide memory resource.
     *
     * We need this variant because `std::initializer_list` cannot be passed
     * through the generic `std::forward`.
     *
     * @param ctx first argument to pass to the constructor of T; must be `this`
     * @param children second argument to pass to the constructor of T
     * @param args remaining arguments to pass to the constructor of T
     */
    template<typename T, typename... Args>
    T* make(ASTContext* ctx, std::initializer_list<Node*> children, Args&&... args) {
        assert(ctx == this);
        return new (allocateNode<T>()) T(ctx, children, std::forward<Args>(args)...);
    }

    /**
     * Factory function creating a new node of type T. This allocates the new
     * through the context-wide memory resource.
     *
     * We need this variant because `std::initializer_list` cannot be passed
     * through the generic `std::forward`.
     *
     * @param ctx first argument to pass to the constructor of T; must be `this`
     * @param wildcard second argument to pass to the constructor of T; must be `this`
     * @param children third second argument to pass to the constructor of T
     * @param args remaining arguments to pass to the constructor of T
     */
    template<typename T, typename... Args>
    T* make(ASTContext* ctx, type::Wildcard&& wildcard, std::initializer_list<Node*> children, Args&&... args) {
        assert(ctx == this);
        return new (allocateNode<T>())
            T(ctx, std::forward<type::Wildcard>(wildcard), children, std::forward<Args>(args)...);
    }

private:
    template<typename T>
    T* allocateNode() {
        auto* t = reinterpret_cast<T*>(_memory_resource.allocate(sizeof(T), alignof(T)));
        _nodes.emplace_back(t);
        return t;
    }

    // The following methods implement the corresponding phases of AST processing.

    Result<declaration::module::UID> _parseSource(Builder* builder, const hilti::rt::filesystem::path& path,
                                                  const ID& scope,
                                                  std::optional<hilti::rt::filesystem::path> process_extension = {});
    Result<Nothing> _init(Builder* builder, const Plugin& plugin);
    Result<Nothing> _buildScopes(Builder* builder, const Plugin& plugin);
    Result<Nothing> _clearState(Builder* builder, const Plugin& plugin);
    Result<Nothing> _resolve(Builder* builder, const Plugin& plugin);
    Result<Nothing> _resolveUnresolvedNodes(bool* modified, Builder* builder, const Plugin& plugin);
    Result<Nothing> _resolveRoot(bool* modified, Builder* builder, const Plugin& plugin);
    Result<Nothing> _validate(Builder* builder, const Plugin& plugin, bool pre_resolver);
    Result<Nothing> _transform(Builder* builder, const Plugin& plugin);
    Result<Nothing> _collectErrors();
    Result<Nothing> _optimize(Builder* builder);

    // Adds a module to the AST. The module must not be part of any AST yet
    // (including the current one).
    declaration::module::UID _addModuleToAST(declaration::Module* module);

    // Performs internal consistency checks on the AST. Meant to execute only
    // in debug builds as it may affect performance.
    void _checkAST(bool finished) const;

    // Dumps the AST to disk during AST processing, for debugging..
    void _saveIterationAST(const Plugin& plugin, const std::string& prefix, int round = 0);

    // Dumps the AST to disk during AST processing, for debugging..
    void _saveIterationAST(const Plugin& plugin, const std::string& prefix, const std::string& tag);

    // Dumps the AST to a debugging stream.
    void _dumpAST(const hilti::logging::DebugStream& stream, const Plugin& plugin, const std::string& prefix,
                  int round);

    // Dumps the AST to a debugging stream.
    void _dumpAST(std::ostream& stream, const Plugin& plugin, const std::string& prefix, int round);

    // Dumps the accumulated state tables of the context to a debugging stream.
    void _dumpState(const logging::DebugStream& stream);

    // Dump statistics about the AST to a debugging stream.
    void _dumpStats(const logging::DebugStream& stream, const Plugin& plugin);

    // Dumps the accumulated state tables of the context to a debugging stream.
    void _dumpDeclarations(const logging::DebugStream& stream, const Plugin& plugin);

    Context* _context = nullptr;                          // compiler context
    std::pmr::monotonic_buffer_resource _memory_resource; // memory resource for all AST nodes
    std::vector<Node*> _nodes; // all nodes allocated through the context so that we can run destructors at the end

    ASTRoot* _root = nullptr;            // root node of the AST
    bool _resolved = false;              // true if `processAST()` has finished successfully
    Driver* _driver = nullptr;           // pointer to compiler drive during `processAST()`, null outside of that
    util::Uniquer<ID> _canon_id_uniquer; // Produces unique canonified IDs

    uint64_t _total_rounds = 0; // total number of rounds of AST processing

    std::unordered_map<declaration::module::UID, declaration::Module*>
        _modules_by_uid;                                                    // all known modules indexed by UID
    std::unordered_map<std::string, declaration::Module*> _modules_by_path; // all known modules indexed by path
    std::map<std::pair<ID, ID>, declaration::Module*>
        _modules_by_id_and_scope; // all known modules indexed by their ID and search scope

    std::vector<Declaration*>
        _declarations_by_index; // all registered declarations; vector position corresponds to their index
    std::vector<UnqualifiedType*> _types_by_index; // all registered types; vector position corresponds to their index
};

/**
 * Root node for the AST inside an AST context. This will always exist exactly
 * once.
 */
class ASTRoot : public Node {
public:
    static auto create(ASTContext* ctx) { return ctx->make<ASTRoot>(ctx); }

protected:
    ASTRoot(ASTContext* ctx) : Node(ctx, NodeTags, {}, Meta(Location("<root>"))) {}

    std::string _dump() const final;

    HILTI_NODE_0(ASTRoot, final);
};

} // namespace hilti
