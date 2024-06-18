// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <hilti/rt/util.h>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/module-uid.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>
#include <hilti/ast/statements/block.h>

namespace hilti {

namespace detail::cxx {
class Unit;
}

namespace declaration {

/** AST node for a module declaration. */
class Module : public Declaration {
public:
    const auto& uid() const { return _uid; }
    const auto& id() const { return _uid.unique; }
    const auto& scopeID() const { return _uid.id; }
    const auto& scopePath() const { return _scope_path; }
    auto statements() const { return child<statement::Block>(0); }
    auto declarations() const { return childrenOfType<Declaration>(); }
    const auto& dependencies() const { return _dependencies; }

    bool isEmpty() const {
        // We always have a block as children.
        return children().size() <= 1 && statements()->statements().empty();
    }

    /** Retrieves the module's `%skip-implementation` flag. */
    bool skipImplementation() const { return _skip_implementation; }

    /** Sets the module's `%skip-implementation` flag. */
    void setSkipImplementation(bool skip_implementation) { _skip_implementation = skip_implementation; }

    auto cxxUnit() const { return _cxx_unit; }
    void setCxxUnit(std::shared_ptr<::hilti::detail::cxx::Unit> unit) { _cxx_unit = std::move(unit); }

    /**
     * Removes any content from the module. The result is an empty module just
     * as if it had just been created. (The ID remains in place.)
     */
    void clear();

    /**
     * Returns a module's property declaration of a given name. If there's no
     * property declaration of that name, return an error. If there's more than
     * one of that name, it's undefined which one is returned.
     *
     * @param id name of the property to return
     */
    Property* moduleProperty(const ID& id) const;

    /**
     * Returns all of module's property declarations of a given name. If
     * there's no property declaration of that ID, return an empty container.
     *
     * @param id name of the property to return; leave unset for returning all
     */
    hilti::node::Set<declaration::Property> moduleProperties(const ID& id) const;

    /**
     * Adds a declaration to the module. It will be appended to the current
     * list of declarations.
     */
    void add(ASTContext* ctx, Declaration* d) { addChild(ctx, d); }

    /**
     * Adds a top-level statement to the module. It will be appended to the
     * end of the current list of statements and execute at module initialize
     * time.
     */
    void add(ASTContext* ctx, Statement* s) { child<statement::Block>(0)->add(ctx, s); }

    void addDependency(declaration::module::UID uid) { _dependencies.insert(std::move(uid)); }
    void setScopePath(const ID& scope) { _scope_path = scope; }
    void setUID(declaration::module::UID uid) { _uid = std::move(uid); }

    std::string_view displayName() const final { return "module"; }

    node::Properties properties() const override {
        auto p = node::Properties{{"id", _uid.id},
                                  {"path", _uid.path.native()},
                                  {"ext", _uid.process_extension.native()},
                                  {"scope", _scope_path},
                                  {"dependencies", util::join(_dependencies, ", ")},
                                  {"skip-implementation", _skip_implementation}};
        return hilti::Declaration::properties() + p;
    }

    std::string_view branchTag() const final { return _uid.process_extension.native(); }

    static auto create(ASTContext* ctx, const declaration::module::UID& uid, const ID& scope, const Declarations& decls,
                       Statements stmts, Meta meta = {}) {
        Nodes nodes = {statement::Block::create(ctx, std::move(stmts), meta)};
        for ( auto d : decls )
            nodes.push_back(d);

        return ctx->make<Module>(ctx, std::move(nodes), uid, scope, std::move(meta));
    }

    static auto create(ASTContext* ctx, const declaration::module::UID& uid, const ID& scope = {}, Meta meta = {}) {
        return create(ctx, uid, scope, {}, {}, std::move(meta));
    }

    static auto create(ASTContext* ctx, const declaration::module::UID& uid, const ID& scope, const Declarations& decls,
                       Meta meta = {}) {
        return create(ctx, uid, scope, decls, {}, std::move(meta));
    }

protected:
    Module(ASTContext* ctx, Nodes children, declaration::module::UID uid, ID scope, Meta meta = {})
        : Declaration(ctx, NodeTags, std::move(children), uid.id, declaration::Linkage::Public, std::move(meta)),
          _uid(std::move(uid)),
          _scope_path(std::move(scope)) {}

    std::string _dump() const override;

    HILTI_NODE_1(declaration::Module, Declaration, final);

private:
    declaration::module::UID _uid;
    ID _scope_path;
    std::set<declaration::module::UID> _dependencies;
    bool _skip_implementation = true;
    std::shared_ptr<::hilti::detail::cxx::Unit> _cxx_unit;
};

} // namespace declaration
} // namespace hilti
