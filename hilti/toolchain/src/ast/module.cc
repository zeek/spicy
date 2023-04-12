// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/module.h>
#include <hilti/compiler/detail/visitors.h>

using namespace hilti;

void Module::clear() {
    auto v = visitor::PostOrder<>();

    // We fully walk the AST here in order to break any reference cycles it may
    // contain. Start at child 1 to leave ID in place.
    for ( size_t i = 1; i < children().size(); i++ ) {
        for ( auto j : v.walk(&children()[i]) )
            j.node = node::none;
    }

    children()[1] = statement::Block({}, meta());
    clearDocumentation();
}

hilti::optional_ref<const declaration::Property> Module::moduleProperty(const ID& id) const {
    for ( const auto& d : declarations() ) {
        if ( ! d.isA<declaration::Property>() )
            return {};

        auto& x = d.as<declaration::Property>();
        if ( x.id() == id )
            return {x};
    }

    return {};
}

node::Set<declaration::Property> Module::moduleProperties(const std::optional<ID>& id) const {
    node::Set<declaration::Property> props;

    for ( const auto& d : declarations() ) {
        if ( auto p = d.tryAs<declaration::Property>(); p && (! id || p->id() == id) )
            props.insert(*p);
    }

    return props;
}

void Module::destroyPreservedNodes() {
    for ( auto& n : _preserved )
        n.destroyChildren();

    _preserved.clear();
}
