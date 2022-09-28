// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/node-ref.h>
#include <hilti/ast/node.h>

using namespace hilti;

uint64_t node_ref::detail::Control::_rid_counter = 0;

NodeRef::NodeRef(const Node& n) : _control(n._control()), _originalType(n.typename_()) {
    if ( n.data() ) {
    }
}

const Node* NodeRef::_node() const {
    if ( ! _control )
        throw node_ref::Invalid(util::fmt("access to uninitialized node reference %s", _originalType));

    if ( ! _control->_node )
        throw node_ref::Invalid(util::fmt("dangling node reference %s", _originalType));

    return _control->_node;
}
