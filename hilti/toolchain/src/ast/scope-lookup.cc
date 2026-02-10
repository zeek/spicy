// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ctors/enum.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/base/logger.h>

using namespace hilti;

std::pair<bool, Result<std::pair<Declaration*, ID>>> hilti::scope::detail::lookupID(const ID& id, const Node* n,
                                                                                    const Node* orig_node) {
    assert(n);

    if ( ! n->scope() ) {
        auto err = result::Error(util::fmt("unknown ID '%s'", id));
        return std::make_pair(false, std::move(err));
    }

    auto resolved = n->scope()->lookupAll(id);

    if ( resolved.empty() ) {
        auto err = result::Error(util::fmt("unknown ID '%s'", id));
        return std::make_pair(false, std::move(err));
    }

    if ( resolved.size() == 1 ) {
        auto& r = resolved.front();
        auto& d = r.node;

        if ( ! d ) {
            // Explicit stop-lookup-here marker.
            auto err = result::Error(util::fmt("unknown ID '%s'", id));
            return std::make_pair(true, std::move(err));
        }

        if ( d->isA<declaration::Module>() || d->isA<declaration::ImportedModule>() ) {
            auto err = result::Error(util::fmt("cannot use module '%s' as an ID", id));
            return std::make_pair(true, std::move(err));
        }

        if ( r.external && ! d->isPublic() ) {
            bool ok = false;

            // We allow access to types (and type-derived constants) to
            // make it less cumbersome to define external hooks.

            if ( d->isA<declaration::Type>() )
                ok = true;

            if ( auto* c = d->tryAs<declaration::Constant>() ) {
                if ( auto* ctor = c->value()->tryAs<expression::Ctor>(); ctor && ctor->ctor()->isA<ctor::Enum>() )
                    ok = true;
            }

            if ( ! ok ) {
                auto err = result::Error(util::fmt("'%s' has not been declared public", id));
                return std::make_pair(true, std::move(err));
            }
        }

        if ( d->isA<declaration::LocalVariable>() ) {
            // If we're inside a block defining the local variable, we need to
            // check that the statement using the ID comes after its declaration.
            if ( auto* decl_stmt = d->parent()->tryAs<statement::Declaration>() ) {
                auto* decl_block =
                    decl_stmt->parent()
                        ->as<statement::Block>(); // declaration statements are always top-level inside a block
                assert(decl_block->scope() && decl_block->scope()->has(id)); // parent's scope must have the ID

                for ( auto* stmt : decl_block->statements() ) {
                    if ( stmt == decl_stmt )
                        break; // found declaration before the node using it

                    if ( stmt->hasChild(orig_node, true) ) {
                        // oops, node using declaration comes before declaration itself
                        auto err = result::Error(util::fmt("local variable '%s' not yet declared", id));
                        return std::make_pair(false, std::move(err));
                    }
                }
            }
        }

        auto x = std::make_pair(resolved.front().node, ID(resolved.front().qualified));
        return std::make_pair(true, std::move(x));
    }

    auto err = result::Error(util::fmt("ID '%s' is ambiguous", id));
    return std::make_pair(true, std::move(err));
}
