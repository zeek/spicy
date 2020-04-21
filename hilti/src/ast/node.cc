// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <iomanip>

#include <hilti/ast/expressions/id.h>
#include <hilti/ast/node.h>
#include <hilti/ast/types/id.h>
#include <hilti/compiler/detail/visitors.h>

using namespace hilti;

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
    auto orig = originalNode() ? util::fmt(" (original %s)", originalNode()->renderedRid()) : "";

    std::string error_string;
    if ( hasErrors() )
        error_string =
            util::join(util::transform(errors(),
                                       [](const auto& e) {
                                           return util::fmt("  [ERROR] %s%s", e.message,
                                                            (e.priority == node::ErrorPriority::Low ? " (low prio)" :
                                                                                                      ""));
                                       }),
                       "");

    std::string type;

    if ( auto x = this->tryAs<expression::ResolvedID>() )
        type = util::fmt(" (type: %s)", x->type());

    else if ( auto x = this->tryAs<type::ResolvedID>() )
        type = util::fmt(" (type: %s)", x->type());

    auto s = util::fmt("%s%s%s%s%s%s%s", name, id, orig, sprops, type, location, error_string);

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
    }

    return s;
}

void Node::print(std::ostream& out, bool compact) const { detail::printAST(*this, out, compact); }

node::Properties operator+(const node::Properties& p1, const node::Properties& p2) {
    node::Properties p;

    for ( auto& i : p1 )
        p.insert(i);

    for ( auto& i : p2 )
        p.insert(i);

    return p;
}
