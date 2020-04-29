// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <string>
#include <utility>

#include <hilti/ast/ctors/enum.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/global.h>

using namespace hilti;

void hilti::render(std::ostream& out, const Node& node, bool include_scopes) {
    detail::renderNode(node, out, include_scopes);
}

void hilti::render(logging::DebugStream stream, const Node& node, bool include_scopes) {
    detail::renderNode(node, std::move(stream), include_scopes);
}

#ifdef HILTI_HAVE_SANITIZER
// Prevent some errors from showing up, include some (presumably) false positives in LLVM
// because it wasn't built with sanitizer support.
//
// TODO(robin): Doesn't work on Linux to have this in shared library. The weak symbol in static ASAN runtime
// wins during linking.
extern "C" {
const char* __asan_default_options() { return "detect_container_overflow=0:detect_odr_violation=0"; }
}
#endif

namespace hilti::logging::debug {
inline const DebugStream Resolver("resolver");
} // namespace hilti::logging::debug

std::pair<bool, Result<std::pair<NodeRef, ID>>> hilti::detail::lookupID(const ID& id, const Node& n) {
    auto resolved = n.scope()->lookupAll(id);

    if ( resolved.empty() ) {
        auto err = result::Error(util::fmt("unknown ID '%s'", id));
        return std::make_pair(false, std::move(err));
    }

    if ( resolved.size() == 1 ) {
        auto& r = resolved.front();

        if ( ! r.node ) {
            auto err = result::Error(util::fmt("internal error: scope's entry for ID '%s' is no longer valid", id));
            return std::make_pair(false, std::move(err));
        }

        if ( auto d = r.node->template tryAs<Declaration>() ) {
            if ( auto c = d->tryAs<declaration::Module>() ) {
                auto err = result::Error(util::fmt("cannot use module '%s' as an ID", id));
                return std::make_pair(true, std::move(err));
            }

            if ( r.external && d->linkage() != declaration::Linkage::Public ) {
                bool ok = false;

                // We allow access to types (and type-derived constants) to
                // make it less cumbersome to define external hooks.

                if ( d->isA<declaration::Type>() )
                    ok = true;

                if ( auto c = d->tryAs<declaration::Constant>() ) {
                    if ( auto ctor = c->value().tryAs<expression::Ctor>(); ctor && ctor->ctor().isA<ctor::Enum>() )
                        ok = true;
                }

                if ( ! ok ) {
                    auto err = result::Error(util::fmt("'%s' has not been declared public", id));
                    return std::make_pair(true, std::move(err));
                }
            }

            HILTI_DEBUG(logging::debug::Resolver, util::fmt("resolved ID %s (%s) to %s", id, id.meta().location(),
                                                            resolved.front().node->render()));

            auto x = std::make_pair(resolved.front().node, ID(resolved.front().qualified));
            return std::make_pair(true, std::move(x));
        }

        logger().internalError(util::fmt("ID '%s' resolved to something else than a declaration (%s)", id,
                                         resolved.front().node->typename_()),
                               resolved.front().node->meta().location());
    }

    auto err = result::Error(util::fmt("ID '%s' is ambiguous", id));
    return std::make_pair(true, std::move(err));
}
