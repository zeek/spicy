// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/base/logger.h>
#include <hilti/compiler/printer.h>

#include <spicy/ast/all.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/hook.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace {

struct Visitor : hilti::visitor::PreOrder<void, Visitor> {
    explicit Visitor(hilti::printer::Stream& out) : out(out) {} // NOLINT

    auto const_(const Type& t) { return (out.isCompact() && hilti::type::isConstant(t)) ? "const " : ""; }

    void operator()(const type::Sink& /* n */) { out << "sink"; }

    void operator()(const type::Unit& n) {
        if ( n.isWildcard() )
            out << "unit<*>";
        else {
            out << "unit { XXX } ";
        }
    }

    void operator()(const type::unit::item::Field& n) { out << n.id(); }

    hilti::printer::Stream& out;
};

} // anonymous namespace

bool spicy::detail::ast::print(const hilti::Node& root, hilti::printer::Stream& out) {
    hilti::util::timing::Collector _("spicy/printer");

    return Visitor(out).dispatch(root);
}
