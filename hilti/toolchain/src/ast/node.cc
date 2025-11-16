// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <iomanip>
#include <ranges>
#include <sstream>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/enum.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/node.h>
#include <hilti/ast/type.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/ast-dumper.h>
#include <hilti/compiler/printer.h>

using namespace hilti;
using namespace hilti::detail;

uint64_t hilti::Node::_instances = 0;

std::string node::to_string(const Tags& ti) {
    return util::join(ti | std::views::transform([](auto i) { return std::to_string(i); }), ",");
}

Node::~Node() {
    clearChildren();
    _ref_count = -1; // for debugging, mark as destroyed
}

std::string Node::dump() const {
    std::stringstream s;
    s << '\n';
    ast_dumper::dump(s, const_cast<Node*>(this));
    return s.str();
}

std::string Node::renderSelf(bool include_location) const {
    auto f = [](const node::Properties::value_type& x) {
        return util::fmt("%s=%s", x.first, std::quoted(node::to_string(x.second)));
    };

    auto name = [](const Node* n) {
        auto name = n->typename_();

        // Prettify the name a bit.
        if ( util::startsWith(name, "detail::") )
            name = util::join(util::slice(util::split(name, "::"), 2), "::");

        return name;
    };

    auto identity = [&name](const Node* n) {
        return util::fmt("@%s:%p", util::tolower(name(n).substr(0, 1)), n->identity());
    };

    std::vector<std::string> props;

    for ( const auto& x : properties() )
        props.push_back(f(x));

    std::string sprops;

    if ( ! props.empty() )
        sprops = util::fmt(" <%s>", util::join(props, " "));

    const auto& location =
        (include_location && meta().location()) ? util::fmt(" (%s)", meta().location().dump(true)) : "";
    const auto* no_inherit_scope = (inheritScope() ? "" : " (no-inherit-scope)");
    const auto& parent = (_parent ? util::fmt(" [parent %s]", identity(_parent)) : " [no parent]");

    auto s = util::fmt("%s%s%s%s%s", name(this), sprops, parent, no_inherit_scope, location);

    if ( auto derived_render = _dump(); ! derived_render.empty() )
        s += std::string(" ") + derived_render;

    s += util::fmt(" [%s]", identity(this));

    // Format errors last on the line since they are not properly delimited.
    if ( hasErrors() )
        for ( auto&& e : errors() ) {
            const auto* prio = "";
            if ( e.priority == node::ErrorPriority::Low )
                prio = " (low prio)";
            else if ( e.priority == node::ErrorPriority::High )
                prio = " (high prio)";

            s += util::fmt("  [ERROR] %s%s", e.message, prio);
        }

    return s;
}

void Node::print(std::ostream& out, bool compact, bool user_visible) const {
    printer::print(out, const_cast<Node*>(this), compact, user_visible);
}

std::string Node::print() const {
    std::stringstream out;
    printer::print(out, const_cast<Node*>(this), true, true);
    return out.str();
}

std::string Node::printRaw() const {
    std::stringstream out;
    printer::print(out, const_cast<Node*>(this), true, false);
    return out.str();
}

void Node::replaceChild(ASTContext* ctx, Node* old, Node* new_) {
    for ( auto i = 0U; i < _children.size(); i++ ) {
        if ( _children[i] == old ) {
            setChild(ctx, i, new_);
            return;
        }
    }

    logger().internalError("child not found");
}

void Node::removeFromParent() {
    if ( ! _parent )
        return;

    assert(_parent->hasChild(this));
    _parent->removeChild(this);
}

void Node::replaceChildren(ASTContext* ctx, const Nodes& children) {
    clearChildren();

    for ( auto&& c : children )
        addChild(ctx, c);
}

void Node::clearChildren() {
    for ( auto& c : _children ) {
        if ( c ) {
            c->_parent = nullptr;
            c->release();
        }
    }

    _children.clear();
}

Node* Node::_newChild(ASTContext* ctx, Node* child) {
    if ( child->_parent )
        return node::deepcopy(ctx, child);
    else
        return child;
}

void Node::_checkCastBackend() const {
    if ( dynamic_cast<const QualifiedType*>(this) )
        logger().internalError("as/tryAs/isA used on a QualifiedType; probably meant to use its type() instead");
}

Node* node::detail::deepcopy(ASTContext* ctx, Node* n, bool force) {
    if ( ! n )
        return nullptr;

    if ( ! force && ! n->_parent )
        return n;

    auto* clone = n->_clone(ctx);

    for ( const auto& c : n->children() )
        clone->addChild(ctx, c); // this will copy the children recursively (because they have a parent already)

    return clone;
}

// Helper looking up an ID inside a node's direct scope, applying visibility rules.
static std::pair<bool, Result<std::pair<Declaration*, ID>>> lookupIDBackend(const ID& id, const Node* n) {
    assert(n->scope());
    auto resolved = n->scope()->lookupAll(id);

    if ( resolved.empty() ) {
        auto err = result::Error(util::fmt("unknown ID '%s'", id));
        return std::make_pair(false, std::move(err));
    }

    if ( resolved.size() > 1 ) {
        auto err = result::Error(util::fmt("ID '%s' is ambiguous", id));
        return std::make_pair(true, std::move(err));
    }

    const auto& r = resolved.front();
    assert(r.node);
    const auto& d = r.node;

    if ( d->isA<declaration::Module>() || d->isA<declaration::ImportedModule>() ) {
        auto err = result::Error(util::fmt("cannot refer to module '%s' through an ID in this context", id));
        return std::make_pair(true, std::move(err));
    }

    if ( r.external && d->linkage() != declaration::Linkage::Public ) {
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

    auto x = std::make_pair(resolved.front().node, ID(resolved.front().qualified));
    return std::make_pair(true, std::move(x));
}

Result<std::pair<Declaration*, ID>> Node::lookupID(const ID& id, const std::string_view& what) const {
    for ( const auto* n = this; n; n = n->parent() ) {
        if ( ! n->scope() )
            continue;

        auto [stop, resolved] = lookupIDBackend(id, n);
        if ( resolved )
            // Found it.
            return resolved;

        if ( stop )
            // Pass back error.
            return std::move(resolved);

        if ( ! n->inheritScope() ) {
            // Advance to module scope directly.
            while ( n->parent() && (! n->parent()->isA<declaration::Module>()) )
                n = n->parent();
        }
    }

    return result::Error(util::fmt("unknown ID '%s'", id));
}
