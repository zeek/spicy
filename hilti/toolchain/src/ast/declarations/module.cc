// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/visitor.h>
#include <hilti/compiler/detail/cxx/unit.h>

using namespace hilti;

std::string declaration::Module::_dump() const { return ""; }

declaration::Property* declaration::Module::moduleProperty(const ID& id) const {
    for ( const auto& d : declarations() ) {
        if ( ! d->isA<declaration::Property>() )
            return {};

        const auto& x = d->as<declaration::Property>();
        if ( x->id() == id )
            return x;
    }

    return nullptr;
}

node::Set<declaration::Property> declaration::Module::moduleProperties(const ID& id) const {
    node::Set<declaration::Property> props;

    for ( const auto& d : declarations() ) {
        if ( auto p = d->tryAs<declaration::Property>(); p && (! id || p->id() == id) )
            props.push_back(p);
    }

    return props;
}
