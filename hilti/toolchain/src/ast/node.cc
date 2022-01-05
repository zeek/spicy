// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <iomanip>
#include <sstream>

#include <hilti/ast/expressions/id.h>
#include <hilti/ast/node.h>
#include <hilti/ast/types/unresolved-id.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/visitors.h>

using namespace hilti;

const Node node::none = None::create();

std::string Node::render(bool include_location) const {
    auto f = [&](const node::Properties::value_type& x) {
        return util::fmt("%s=%s", x.first, std::quoted(node::detail::to_string(x.second)));
    };

    std::vector<std::string> props;

    for ( const auto& x : properties() )
        props.push_back(f(x));

    std::string sprops;

    if ( ! props.empty() )
        sprops = util::fmt(" <%s>", util::join(props, " "));

    // Prettify the name a bit.
    auto name = typename_();
    name = util::replace(name, "hilti::", "");

    if ( util::startsWith(name, "detail::") )
        name = util::join(util::slice(util::split(name, "::"), 2), "::");

    auto location = (include_location && meta().location()) ? util::fmt(" (%s)", meta().location().render(true)) : "";
    auto id = rid() ? util::fmt(" %s", renderedRid()) : "";
    auto prune = (this->pruneWalk() ? " (prune)" : "");

    std::string type;

    if ( auto x = this->tryAs<expression::ResolvedID>() )
        type = util::fmt(" (type: %s [@t:%p])", x->type(), x->type().identity());

    auto s = util::fmt("%s%s%s%s%s%s", name, id, sprops, type, prune, location);

    if ( auto t = this->tryAs<Type>() ) {
        std::vector<std::string> flags;

        if ( type::isConstant(*t) )
            flags.emplace_back("const");
        else
            flags.emplace_back("non-const");

        s += util::fmt(" (%s)", util::join(flags, ", "));

        if ( t->hasFlag(type::Flag::NoInheritScope) )
            s += util::fmt(" (top-level scope)");

        if ( auto tid = t->typeID() )
            s += util::fmt(" (type-id: %s)", *tid);

        if ( auto cppid = t->cxxID() )
            s += util::fmt(" (cxx-id: %s)", *cppid);

        if ( t->isWildcard() )
            s += " (wildcard)";

        s += (type::isResolved(t) ? " (resolved)" : " (not resolved)");
    }

    else if ( auto e = this->tryAs<Expression>() ) {
        s += (e->isConstant() ? " (const)" : " (non-const)");
        s += (type::isResolved(e->type()) ? " (resolved)" : " (not resolved)");
    }

    else if ( auto d = this->tryAs<Declaration>() ) {
        s += util::fmt(" [canon-id: %s]", d->canonicalID() ? d->canonicalID().str() : "not set");

        if ( auto t = this->tryAs<declaration::Type>() )
            s += (type::isResolved(t->type()) ? " (resolved)" : " (not resolved)");
    }

    s += util::fmt(" [@%s:%p]", util::tolower(name.substr(0, 1)), identity());

    // Format errors last on the line since they are not properly delimited.
    if ( hasErrors() )
        for ( auto&& e : errors() ) {
            auto prio = "";
            if ( e.priority == node::ErrorPriority::Low )
                prio = " (low prio)";
            else if ( e.priority == node::ErrorPriority::High )
                prio = " (high prio)";

            s += util::fmt("  [ERROR] %s%s", e.message, prio);
        }

    return s;
}

void Node::print(std::ostream& out, bool compact) const { detail::printAST(*this, out, compact); }

std::string Node::print() const {
    std::stringstream out;
    detail::printAST(*this, out, true);
    return out.str();
}

node::Properties operator+(const node::Properties& p1, const node::Properties& p2) {
    node::Properties p;

    for ( auto& i : p1 )
        p.insert(i);

    for ( auto& i : p2 )
        p.insert(i);

    return p;
}

void node::detail::flattenedChildren(const hilti::Node& n, node::Set<const hilti::Node>* dst) {
    const auto& children = n.children();
    for ( auto i = 0u; i < children.size(); i++ ) {
        dst->insert(children[i]);
        flattenedChildren(children[i], dst);
    }
}

static void _destroyChildrenRecursively(Node* n) {
    for ( auto& c : n->children() ) {
        if ( ! c.pruneWalk() )
            _destroyChildrenRecursively(&c);
    }

    n->children().clear();
}

void Node::destroyChildren() {
    _destroyChildrenRecursively(this);
    children().clear();
}
