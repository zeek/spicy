// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <csignal>

#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/forward.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/printer.h>

using namespace spicy;

namespace {

struct VisitorPrinter : visitor::PreOrder {
    VisitorPrinter(hilti::printer::Stream& out) : out(out) {}

    hilti::printer::Stream& out;

    bool result = false;

    void operator()(type::Sink* n) final {
        out << "sink";
        result = true;
    }

    void operator()(type::Unit* n) final {
        if ( ! out.isExpandSubsequentType() ) {
            if ( auto id = n->typeID() ) {
                out << id;
                result = true;
                return;
            }
        }

        out.setExpandSubsequentType(false);
        if ( n->isWildcard() )
            out << "unit<*>";
        else {
            out << "unit { XXX } ";
        }

        result = true;
    }

    void operator()(type::unit::item::Field* n) final {
        out << n->id();
        result = true;
    }
};

} // anonymous namespace

bool spicy::detail::printer::print(hilti::printer::Stream& stream, const NodePtr& root) {
    hilti::util::timing::Collector _("spicy/printer");

    return visitor::dispatch(VisitorPrinter(stream), root, [](const auto& v) { return v.result; });
}
