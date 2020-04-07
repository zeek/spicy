// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/node.h>
#include <hilti/ast/node_ref.h>

using namespace hilti;

uint64_t node_ref::detail::Control::_rid_counter = 0;

NodeRef::NodeRef(Node& n) : _control(n._control()) {}

Node* NodeRef::_node() const {
    if ( ! _control )
        throw node_ref::Invalid("accesd to uninitalized node reference");

    if ( ! _control->_node )
        throw node_ref::Invalid("dangling node reference");

    return _control->_node;
}
