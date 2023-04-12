// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/node-ref.h>
#include <hilti/ast/node.h>

using namespace hilti;

uint64_t node_ref::detail::Control::_rid_counter = 0;

NodeRef::NodeRef(const Node& n) : _control(n._control()) {}

const Node* NodeRef::_node() const {
    if ( ! _control )
        throw node_ref::Invalid("access to uninitialized node reference");

    if ( ! _control->_node )
        throw node_ref::Invalid("dangling node reference");

    return _control->_node;
}
