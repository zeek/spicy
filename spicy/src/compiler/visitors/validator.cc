// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ctors/string.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/statements/switch.h>
#include <hilti/base/logger.h>
#include <spicy/ast/all.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/hook.h>
#include <spicy/compiler/detail/visitors.h>
#include <spicy/rt/mime.h>

using namespace spicy;
using util::fmt;

namespace {

struct PreTransformVisitor : public hilti::visitor::PreOrder<void, PreTransformVisitor> {
    void operator()(const statement::Print& /* n */) {
        // TODO(robin): .
    }

    void operator()(const statement::Stop& n, const_position_t p) {
        // Must be inside &foreach hook.
        if ( auto x = p.findParent<Hook>(); ! (x && x->get().isForEach()) )
            hilti::logger().error("'stop' can only be used inside a 'foreach' hook", n);
    }

    void operator()(const type::Unit& n) {
        for ( const auto& i : n.items<spicy::type::unit::item::Property>() ) {
            // TODO(robin): should maybe validate Property individually instead of within Unit validation?
            if ( i.id().str() == "%random-access" ) {
                if ( i.expression() )
                    hilti::logger().error("%random-access does not accept an argument", i);
            }

            else if ( i.id().str() == "%filter" ) {
                if ( i.expression() )
                    hilti::logger().error("%filter does not accept an argument", i);
            }

            else if ( i.id().str() == "%byte-order" ) {
                if ( ! i.expression() )
                    hilti::logger().error("%byte-order requires an expression", i);

                // expression type is checked by code generater
            }

            else if ( i.id().str() == "%description" ) {
                if ( ! i.expression() ) {
                    hilti::logger().error("%description requires an argument", i);
                    return;
                }

                if ( ! i.expression()->type().isA<type::String>() )
                    hilti::logger().error("%description requires a string argument", i);
            }

            else if ( i.id().str() == "%mime-type" ) {
                if ( ! i.expression() ) {
                    hilti::logger().error("%mime-type requires an argument", i);
                    return;
                }

                if ( ! i.expression()->type().isA<type::String>() )
                    hilti::logger().error("%mime-type requires a string argument", i);

                if ( auto x = i.expression()->tryAs<hilti::expression::Ctor>() ) {
                    auto mt = x->ctor().as<hilti::ctor::String>().value();

                    if ( ! spicy::rt::MIMEType::parse(mt) )
                        hilti::logger().error("%mime-type argument must follow \"main/sub\" form", i);
                }
            }

            else if ( i.id().str() == "%port" ) {
                if ( ! i.expression() ) {
                    hilti::logger().error("%ports requires an argument", i);
                    return;
                }

                if ( ! i.expression()->type().tryAs<type::Port>() )
                    hilti::logger().error("%port requires a port as its argument", i);
            }

            else
                hilti::logger().error(fmt("unknown property '%s'", i.id().str()), i);
        }
    }

    void operator()(const Attribute& a, const_position_t p) {
        auto getAttrField = [](const_position_t p) -> std::optional<spicy::type::unit::item::Field> {
            try {
                // Expected parent is AttributeSet whose expected parent is Field.
                auto n = p.parent(2);
                return n.tryAs<spicy::type::unit::item::Field>();
            } catch ( std::out_of_range& ) {
            }

            return {};
        };

        if ( a.tag() == "&size" && ! a.hasValue() )
            hilti::logger().error("&size must provide an expression", a);

        else if ( a.tag() == "&default" && ! a.hasValue() )
            hilti::logger().error("%default requires an argument", a);

        else if ( a.tag() == "&eod" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! f->parseType().isA<type::Bytes>() || f->ctor() )
                    hilti::logger().error("&eod is only valid for bytes fields", a);
            }
            else
                hilti::logger().error("&eod is only valid for bytes fields", a);
        }

        else if ( a.tag() == "&until" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! (f->parseType().isA<type::Bytes>() || f->parseType().isA<type::Vector>()) )
                    hilti::logger().error("&until is only valid for fields of type bytes or vector", a);
                else if ( ! a.hasValue() )
                    hilti::logger().error("&until must provide an expression", a);
            }
            else
                hilti::logger().error("&until is only valid for fields of type bytes or vector", a);
        }

        else if ( a.tag() == "&while" || a.tag() == "&until_including" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! f->parseType().isA<type::Vector>() )
                    hilti::logger().error(fmt("%s is only valid for fields of type bytes or vector", a.tag()), a);
                else if ( ! a.hasValue() )
                    hilti::logger().error(fmt("%s must provide an expression", a.tag()), a);
            }
            else
                hilti::logger().error(fmt("%s is only valid for fields of type bytes or vector", a.tag()), a);
        }

        else if ( a.tag() == "&chunked" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! f->parseType().isA<type::Bytes>() || f->ctor() )
                    hilti::logger().error("&chunked is only valid for bytes fields", a);
                else if ( a.hasValue() )
                    hilti::logger().error("&chunked cannot have an expression", a);
                else if ( ! (AttributeSet::has(f->attributes(), "&eod") ||
                             AttributeSet::has(f->attributes(), "&size")) )
                    hilti::logger().error("&chunked must be used with &eod or &size", a);
            }
            else
                hilti::logger().error("&chunked is only valid for bytes fields", a);
        }

        else if ( a.tag() == "&convert" ) {
            if ( ! a.hasValue() )
                hilti::logger().error("&convert must provide an expression", a);
        }

        else if ( a.tag() == "&transient" )
            hilti::logger()
                .error("&transient is no longer available, use an anonymous field instead to achieve the same effect",
                       a);

        else if ( a.tag() == "&parse-from" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! a.hasValue() )
                    hilti::logger().error("&parse-from must provide an expression", a);
                else if ( auto e = a.valueAs<Expression>();
                          e && e->type() != type::unknown && e->type() != type::Bytes() )
                    hilti::logger()
                        .error("&parse-from must have an expression of type either bytes or iterator<stream>", a);
            }
        }

        else if ( a.tag() == "&parse-at" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! a.hasValue() )
                    hilti::logger().error("&parse-at must provide an expression", a);
                else if ( auto e = a.valueAs<Expression>();
                          e && e->type() != type::unknown && e->type() != type::stream::Iterator() )
                    hilti::logger().error("&parse-at must have an expression of type iterator<stream>", a);
            }
        }
    }

    void operator()(const spicy::type::unit::item::Field& f) {
        auto repeat = f.repeatCount();
        auto size_attr = AttributeSet::find(f.attributes(), "&size");
        auto count_attr = AttributeSet::find(f.attributes(), "&count");
        auto parse_from_attr = AttributeSet::find(f.attributes(), "&parse-from");
        auto parse_at_attr = AttributeSet::find(f.attributes(), "&parse-at");

        if ( count_attr && (repeat && ! repeat->type().isA<type::Null>()) )
            hilti::logger().error("cannot have both `[..]` and &count", f);

        if ( parse_from_attr && parse_at_attr )
            hilti::logger().error("cannot have both &parse-from and &parse-at", f);

        if ( f.parseType().isA<type::Bytes>() && ! f.ctor() ) {
            auto eod_attr = AttributeSet::find(f.attributes(), "&eod");
            auto until_attr = AttributeSet::find(f.attributes(), "&until");

            if ( eod_attr ) {
                if ( until_attr )
                    hilti::logger().error("&eod incompatible with &until", f);
            }

            else if ( ! until_attr && ! size_attr && ! parse_from_attr && ! parse_at_attr )
                hilti::logger().error("bytes field requires one of &size, &eod, or &until", f);
        }

        if ( f.parseType().isA<type::Address>() ) {
            auto v4 = AttributeSet::find(f.attributes(), "&ipv4");
            auto v6 = AttributeSet::find(f.attributes(), "&ipv6");

            if ( ! (v4 || v6) )
                hilti::logger().error("address field must come with either &ipv4 or &ipv6 attribute", f);

            if ( v4 && v6 )
                hilti::logger().error("address field cannot have both &ipv4 and &ipv6 attributes", f);
        }

        if ( f.parseType().isA<type::Real>() ) {
            auto type = AttributeSet::find(f.attributes(), "&type");

            if ( type ) {
                if ( auto t = type->valueAs<Expression>()->type().tryAs<type::Enum>();
                     ! (t && t->cxxID() && *t->cxxID() == ID("hilti::rt::real::Type")) )
                    hilti::logger().error("&type attribute must be a spicy::RealType", f);
            }
            else
                hilti::logger().error("field of type real must with a &type attribute", f);
        }

        if ( f.sinks().size() && ! f.parseType().isA<type::Bytes>() )
            hilti::logger().error("only a bytes field can have sinks attached", f);
    }

    void operator()(const spicy::type::unit::item::Switch& s) {
        if ( s.cases().empty() ) {
            hilti::logger().error("switch without cases", s);
            return;
        }

        int defaults = 0;
        std::vector<Expression> seen_exprs;
        std::vector<spicy::type::unit::item::Field> seen_fields;

        for ( const auto& c : s.cases() ) {
            if ( c.items().empty() )
                hilti::logger().error("switch case without any item", c);

            if ( c.isDefault() )
                ++defaults;

            if ( s.expression() && ! c.isDefault() && c.expressions().empty() ) {
                hilti::logger().error("case without expression", c);
                break;
            }

            if ( ! s.expression() && c.expressions().size() ) {
                hilti::logger().error("case does not expect expression", c);
                break;
            }

            for ( const auto& e : c.expressions() ) {
                for ( const auto& x : seen_exprs ) {
                    if ( e == x ) {
                        hilti::logger().error("duplicate case", e);
                        break;
                    }
                }

                seen_exprs.emplace_back(e);
            }

            for ( const auto& i : c.items() ) {
                if ( auto f = i.tryAs<spicy::type::unit::item::Field>() ) {
                    for ( const auto& x : seen_fields ) {
                        if ( f->id() == x.id() && (f->itemType() != x.itemType()) ) {
                            hilti::logger().error(fmt("field '%s' defined multiple times with different types",
                                                      f->id()),
                                                  i);
                            break;
                        }
                    }

                    seen_fields.emplace_back(*f);
                }
            }
        }

        if ( defaults > 1 )
            hilti::logger().error("more than one default case", s);
    }

    void operator()(const spicy::type::unit::item::Variable& v) {
        if ( v.itemType().isA<type::Sink>() )
            hilti::logger().error(
                "cannot use type 'sink' for unit variables; use either a 'sink' item or a reference to a sink "
                "('sink&')",
                v);
    }
};

struct PostTransformVisitor : public hilti::visitor::PreOrder<void, PostTransformVisitor> {};

struct PreservedVisitor : public hilti::visitor::PreOrder<void, PreservedVisitor> {
    auto methodArgument(const hilti::expression::ResolvedOperatorBase& o, int i) {
        auto ctor = o.op2().as<hilti::expression::Ctor>().ctor();

        if ( auto x = ctor.tryAs<hilti::ctor::Coerced>() )
            ctor = x->coercedCtor();

        return ctor.as<hilti::ctor::Tuple>().value()[i];
    }

    void operator()(const operator_::sink::Connect& n) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->supportsSinks() )
            hilti::logger().error("unit type does not support sinks", n);
    }

    void operator()(const operator_::sink::ConnectMIMETypeBytes& n) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>() ) {
            if ( ! x->supportsSinks() )
                hilti::logger().error("unit type does not support sinks", n);

            if ( x->parameters().size() )
                hilti::logger().error("unit types with parameters cannot be connected through MIME type", n);
        }
    }

    void operator()(const operator_::sink::ConnectMIMETypeString& n) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>() ) {
            if ( ! x->supportsSinks() )
                hilti::logger().error("unit type does not support sinks", n);

            if ( x->parameters().size() )
                hilti::logger().error("unit types with parameters cannot be connected through MIME type", n);
        }
    }

    void operator()(const operator_::unit::ConnectFilter& n) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->supportsFilters() )
            hilti::logger().error("unit type does not support filters", n);

        if ( auto y = methodArgument(n, 0)
                          .type()
                          .as<type::StrongReference>()
                          .dereferencedType()
                          .originalNode()
                          ->as<type::Unit>();
             ! y.isFilter() )
            hilti::logger().error("unit type cannot be a filter, %filter missing", n);
    }

    void operator()(const operator_::unit::Forward& n) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->isFilter() )
            hilti::logger().error("unit type cannot be a filter, %filter missing", n);
    }

    void operator()(const operator_::unit::ForwardEod& n) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->isFilter() )
            hilti::logger().error("unit type cannot be a filter, %filter missing", n);
    }

    void operator()(const operator_::unit::Input& n) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->usesRandomAccess() )
            hilti::logger().error("use of 'input()' requires unit type to have property `%random-access`", n);
    }

    void operator()(const operator_::unit::Offset& n) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->usesRandomAccess() )
            hilti::logger().error("use of 'offset()' requires unit type to have property `%random-access`", n);
    }

    void operator()(const operator_::unit::SetInput& n) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->usesRandomAccess() )
            hilti::logger().error("use of 'set_input()' requires unit type to have property `%random-access`", n);
    }
};

} // anonymous namespace

void spicy::detail::preTransformValidateAST(const Node& root, hilti::Unit* /* unit */) {
    util::timing::Collector _("spicy/compiler/validator");

    auto v = PreTransformVisitor();
    for ( auto i : v.walk(root) )
        v.dispatch(i);
}

void spicy::detail::postTransformValidateAST(const Node& root, hilti::Unit* /* unit */) {
    util::timing::Collector _("spicy/compiler/validator");

    auto v = PostTransformVisitor();
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    hilti::reportErrorsInAST(root);
}

void spicy::detail::preservedValidateAST(const std::vector<Node>& nodes, hilti::Unit* /* unit */) {
    util::timing::Collector _("spicy/compiler/validator");

    auto v = PreservedVisitor();
    for ( const auto& root : nodes ) {
        for ( auto i : v.walk(root) )
            v.dispatch(i);
    }
}
