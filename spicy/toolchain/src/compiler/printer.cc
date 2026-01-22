// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <csignal>

#include <hilti/ast/declarations/module.h>
#include <hilti/ast/types/reference.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/forward.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/printer.h>

using namespace spicy;

bool spicy::detail::printer::printID(hilti::printer::Stream& out, const ID& id) {
    // In user-visible output, replace any `hilti` prefix with `spicy`. This is
    // a bit of a hammer: it's assuming that any HILTI types showing up there
    // have a corresponding Spicy type. The alternative would be to explicitly
    // identify valid mappings somehow (e.g., through a shared `&cxxname`).
    // However, that's neither easy nor is it clear that that's worth it. For
    // one, we currently do indeed maintain only such 1:1 mappings (i.e., we
    // don't rename IDs existing at both layers other than the namespace). And
    // second, when displaying Spicy code to users, there should really never
    // be any HILTI identifier showing up anyways; so if we still end up with
    // any, printing them with a `spicy` prefix is probably still a better
    // solution than just printing them as-is.
    if ( out.state().user_visible && id.namespace_() && id.sub(0) == ID("hilti") ) {
        out << ID("spicy", id.sub(1, -1));
        return true;
    }

    return false;
}

namespace {

struct VisitorPrinter : visitor::PreOrder {
    VisitorPrinter(hilti::printer::Stream& out) : out(out) {}

    hilti::printer::Stream& out;

    bool result = false;

    void operator()(type::Sink* n) final {
        out << "sink";
        result = true;
    }

    void operator()(hilti::type::StrongReference* n) final {
        if ( auto* m = n->parent<hilti::declaration::Module>(); m && m->uid().process_extension != ".spicy" )
            return;

        if ( n->isWildcard() )
            out << "T&";
        else
            out << n->dereferencedType() << "&";

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

bool spicy::detail::printer::print(hilti::printer::Stream& stream, Node* root) {
    hilti::util::timing::Collector _("spicy/printer");

    if ( ! root ) {
        stream << "<null>";
        return true;
    }

    return visitor::dispatch(VisitorPrinter(stream), root, [](const auto& v) { return v.result; });
}
