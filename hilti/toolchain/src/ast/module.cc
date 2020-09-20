// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/module.h>
#include <hilti/compiler/detail/visitors.h>

using namespace hilti;

NodeRef Module::preserve(Node n) {
    detail::clearErrors(&n);
    _preserved.push_back(std::move(n));
    return NodeRef(_preserved.back());
}

Result<declaration::Property> Module::moduleProperty(const ID& id) const {
    for ( const auto& d : declarations() ) {
        if ( auto p = d.tryAs<declaration::Property>(); p && p->id() == id )
            return *p;
    }

    return result::Error("no property of specified id");
}

std::vector<declaration::Property> Module::moduleProperties(const ID& id) const {
    std::vector<declaration::Property> props;

    for ( const auto& d : declarations() ) {
        if ( auto p = d.tryAs<declaration::Property>(); p && p->id() == id )
            props.push_back(*p);
    }

    return props;
}
