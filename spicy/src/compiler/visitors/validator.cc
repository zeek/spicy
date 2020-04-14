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
    int errors = 0;

    void error(std::string msg, position_t& p) { p.node.setError(msg); ++errors; }

    void operator()(const statement::Print& /* n */, position_t p) {
        // TODO(robin): .
    }

    void operator()(const statement::Stop& n, position_t p) {
        // Must be inside &foreach hook.
        if ( auto x = p.findParent<Hook>(); ! (x && x->get().isForEach()) )
            error("'stop' can only be used inside a 'foreach' hook", p);
    }

    void operator()(const type::Unit& n, position_t p) {
        for ( const auto& i : n.items<spicy::type::unit::item::Property>() ) {
            // TODO(robin): should maybe validate Property individually instead of within Unit validation?
            if ( i.id().str() == "%random-access" ) {
                if ( i.expression() )
                    error("%random-access does not accept an argument", p);
            }

            else if ( i.id().str() == "%filter" ) {
                if ( i.expression() )
                    error("%filter does not accept an argument", p);
            }

            else if ( i.id().str() == "%byte-order" ) {
                if ( ! i.expression() )
                    error("%byte-order requires an expression", p);

                // expression type is checked by code generater
            }

            else if ( i.id().str() == "%description" ) {
                if ( ! i.expression() ) {
                    error("%description requires an argument", p);
                    return;
                }

                if ( ! i.expression()->type().isA<type::String>() )
                    error("%description requires a string argument", p);
            }

            else if ( i.id().str() == "%mime-type" ) {
                if ( ! i.expression() ) {
                    error("%mime-type requires an argument", p);
                    return;
                }

                if ( ! i.expression()->type().isA<type::String>() )
                    error("%mime-type requires a string argument", p);

                if ( auto x = i.expression()->tryAs<hilti::expression::Ctor>() ) {
                    auto mt = x->ctor().as<hilti::ctor::String>().value();

                    if ( ! spicy::rt::MIMEType::parse(mt) )
                        error("%mime-type argument must follow \"main/sub\" form", p);
                }
            }

            else if ( i.id().str() == "%port" ) {
                if ( ! i.expression() ) {
                    error("%ports requires an argument", p);
                    return;
                }

                if ( ! i.expression()->type().tryAs<type::Port>() )
                    error("%port requires a port as its argument", p);
            }

            else
                error(fmt("unknown property '%s'", i.id().str()), p);
        }
    }

    void operator()(const Attribute& a, position_t p) {
        auto getAttrField = [](position_t p) -> std::optional<spicy::type::unit::item::Field> {
            try {
                // Expected parent is AttributeSet whose expected parent is Field.
                auto n = p.parent(2);
                return n.tryAs<spicy::type::unit::item::Field>();
            } catch ( std::out_of_range& ) {
            }

            return {};
        };

        if ( a.tag() == "&size" && ! a.hasValue() )
            error("&size must provide an expression", p);

        else if ( a.tag() == "&byte-order" && ! a.hasValue() )
            error("&byte-order requires an expression", p);

        else if ( a.tag() == "&default" && ! a.hasValue() )
            error("%default requires an argument", p);

        else if ( a.tag() == "&eod" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! f->parseType().isA<type::Bytes>() || f->ctor() )
                    error("&eod is only valid for bytes fields", p);
            }
        }

        else if ( a.tag() == "&until" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! (f->parseType().isA<type::Bytes>() || f->parseType().isA<type::Vector>()) )
                    error("&until is only valid for fields of type bytes or vector", p);
                else if ( ! a.hasValue() )
                    error("&until must provide an expression", p);
            }
        }

        else if ( a.tag() == "&while" || a.tag() == "&until_including" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! f->parseType().isA<type::Vector>() )
                    error(fmt("%s is only valid for fields of type bytes or vector", a.tag()), p);
                else if ( ! a.hasValue() )
                    error(fmt("%s must provide an expression", a.tag()), p);
            }
        }

        else if ( a.tag() == "&chunked" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! f->parseType().isA<type::Bytes>() || f->ctor() )
                    error("&chunked is only valid for bytes fields", p);
                else if ( a.hasValue() )
                    error("&chunked cannot have an expression", p);
                else if ( ! (AttributeSet::has(f->attributes(), "&eod") ||
                             AttributeSet::has(f->attributes(), "&size")) )
                    error("&chunked must be used with &eod or &size", p);
            }
        }

        else if ( a.tag() == "&convert" ) {
            if ( ! a.hasValue() )
                error("&convert must provide an expression", p);
        }

        else if ( a.tag() == "&transient" )
            error("&transient is no longer available, use an anonymous field instead to achieve the same effect", p);

        else if ( a.tag() == "&parse-from" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! a.hasValue() )
                    error("&parse-from must provide an expression", p);
                else if ( auto e = a.valueAs<Expression>();
                          e && e->type() != type::unknown && e->type() != type::Bytes() )
                    error("&parse-from must have an expression of type either bytes or iterator<stream>", p);
            }
        }

        else if ( a.tag() == "&parse-at" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! a.hasValue() )
                    error("&parse-at must provide an expression", p);
                else if ( auto e = a.valueAs<Expression>();
                          e && e->type() != type::unknown && e->type() != type::stream::Iterator() )
                    error("&parse-at must have an expression of type iterator<stream>", p);
            }
        }
    }

    void operator()(const spicy::type::unit::item::Field& f, position_t p) {
        auto repeat = f.repeatCount();
        auto size_attr = AttributeSet::find(f.attributes(), "&size");
        auto count_attr = AttributeSet::find(f.attributes(), "&count");
        auto parse_from_attr = AttributeSet::find(f.attributes(), "&parse-from");
        auto parse_at_attr = AttributeSet::find(f.attributes(), "&parse-at");

        if ( count_attr && (repeat && ! repeat->type().isA<type::Null>()) )
            error("cannot have both `[..]` and &count", p);

        if ( parse_from_attr && parse_at_attr )
            error("cannot have both &parse-from and &parse-at", p);

        if ( f.parseType().isA<type::Bytes>() && ! f.ctor() ) {
            auto eod_attr = AttributeSet::find(f.attributes(), "&eod");
            auto until_attr = AttributeSet::find(f.attributes(), "&until");

            if ( eod_attr ) {
                if ( until_attr )
                    error("&eod incompatible with &until", p);
            }

            else if ( ! until_attr && ! size_attr && ! parse_from_attr && ! parse_at_attr )
                error("bytes field requires one of &size, &eod, or &until", p);
        }

        if ( f.parseType().isA<type::Address>() ) {
            auto v4 = AttributeSet::find(f.attributes(), "&ipv4");
            auto v6 = AttributeSet::find(f.attributes(), "&ipv6");

            if ( ! (v4 || v6) )
                error("address field must come with either &ipv4 or &ipv6 attribute", p);

            if ( v4 && v6 )
                error("address field cannot have both &ipv4 and &ipv6 attributes", p);
        }

        if ( f.parseType().isA<type::Real>() ) {
            auto type = AttributeSet::find(f.attributes(), "&type");

            if ( type ) {
                if ( auto t = type->valueAs<Expression>()->type().tryAs<type::Enum>();
                     ! (t && t->cxxID() && *t->cxxID() == ID("hilti::rt::real::Type")) )
                    error("&type attribute must be a spicy::RealType", p);
            }
            else
                error("field of type real must with a &type attribute", p);
        }

        if ( f.sinks().size() && ! f.parseType().isA<type::Bytes>() )
            error("only a bytes field can have sinks attached", p);
    }

    void operator()(const spicy::type::unit::item::Switch& s, position_t p) {
        if ( s.cases().empty() ) {
            error("switch without cases", p);
            return;
        }

        int defaults = 0;
        std::vector<Expression> seen_exprs;
        std::vector<spicy::type::unit::item::Field> seen_fields;

        for ( const auto& c : s.cases() ) {
            if ( c.items().empty() )
                error("switch case without any item", p);

            if ( c.isDefault() )
                ++defaults;

            if ( s.expression() && ! c.isDefault() && c.expressions().empty() ) {
                error("case without expression", p);
                break;
            }

            if ( ! s.expression() && c.expressions().size() ) {
                error("case does not expect expression", p);
                break;
            }

            for ( const auto& e : c.expressions() ) {
                for ( const auto& x : seen_exprs ) {
                    if ( e == x ) {
                        error("duplicate case", p);
                        break;
                    }
                }

                seen_exprs.emplace_back(e);
            }

            for ( const auto& i : c.items() ) {
                if ( auto f = i.tryAs<spicy::type::unit::item::Field>() ) {
                    for ( const auto& x : seen_fields ) {
                        if ( f->id() == x.id() && (f->itemType() != x.itemType()) ) {
                            error(fmt("field '%s' defined multiple times with different types", f->id()), p);
                            break;
                        }
                    }

                    seen_fields.emplace_back(*f);
                }
            }
        }

        if ( defaults > 1 )
            error("more than one default case", p);
    }

    void operator()(const spicy::type::unit::item::Variable& v, position_t p) {
        if ( v.itemType().isA<type::Sink>() )
            error(
                "cannot use type 'sink' for unit variables; use either a 'sink' item or a reference to a sink "
                "('sink&')",
                p);
    }
};

struct PostTransformVisitor : public hilti::visitor::PreOrder<void, PostTransformVisitor> {
    void error(std::string msg, position_t& p) { p.node.setError(msg); }
};

struct PreservedVisitor : public hilti::visitor::PreOrder<void, PreservedVisitor> {
    void error(std::string msg, position_t& p) { p.node.setError(msg); }

    auto methodArgument(const hilti::expression::ResolvedOperatorBase& o, int i) {
        auto ctor = o.op2().as<hilti::expression::Ctor>().ctor();

        if ( auto x = ctor.tryAs<hilti::ctor::Coerced>() )
            ctor = x->coercedCtor();

        return ctor.as<hilti::ctor::Tuple>().value()[i];
    }

    void operator()(const operator_::sink::Connect& n, position_t p) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->supportsSinks() )
            error("unit type does not support sinks", p);
    }

    void operator()(const operator_::sink::ConnectMIMETypeBytes& n, position_t p) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>() ) {
            if ( ! x->supportsSinks() )
                error("unit type does not support sinks", p);

            if ( x->parameters().size() )
                error("unit types with parameters cannot be connected through MIME type", p);
        }
    }

    void operator()(const operator_::sink::ConnectMIMETypeString& n, position_t p) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>() ) {
            if ( ! x->supportsSinks() )
                error("unit type does not support sinks", p);

            if ( x->parameters().size() )
                error("unit types with parameters cannot be connected through MIME type", p);
        }
    }

    void operator()(const operator_::unit::ConnectFilter& n, position_t p) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->supportsFilters() )
            error("unit type does not support filters", p);

        if ( auto y = methodArgument(n, 0)
                          .type()
                          .as<type::StrongReference>()
                          .dereferencedType()
                          .originalNode()
                          ->as<type::Unit>();
             ! y.isFilter() )
            error("unit type cannot be a filter, %filter missing", p);
    }

    void operator()(const operator_::unit::Forward& n, position_t p) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->isFilter() )
            error("unit type cannot be a filter, %filter missing", p);
    }

    void operator()(const operator_::unit::ForwardEod& n, position_t p) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->isFilter() )
            error("unit type cannot be a filter, %filter missing", p);
    }

    void operator()(const operator_::unit::Input& n, position_t p) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->usesRandomAccess() )
            error("use of 'input()' requires unit type to have property `%random-access`", p);
    }

    void operator()(const operator_::unit::Offset& n, position_t p) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->usesRandomAccess() )
            error("use of 'offset()' requires unit type to have property `%random-access`", p);
    }

    void operator()(const operator_::unit::SetInput& n, position_t p) {
        if ( auto x = n.op0().type().originalNode()->tryAs<type::Unit>(); x && ! x->usesRandomAccess() )
            error("use of 'set_input()' requires unit type to have property `%random-access`", p);
    }
};

} // anonymous namespace

void spicy::detail::preTransformValidateAST(Node* root, hilti::Unit* /* unit */, bool* found_errors) {
    util::timing::Collector _("spicy/compiler/validator");

    auto v = PreTransformVisitor();
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    *found_errors = (v.errors > 0);
}

void spicy::detail::postTransformValidateAST(Node* root, hilti::Unit* /* unit */) {
    util::timing::Collector _("spicy/compiler/validator");

    auto v = PostTransformVisitor();
    for ( auto i : v.walk(root) )
        v.dispatch(i);
}

void spicy::detail::preservedValidateAST(std::vector<Node>* nodes, hilti::Unit* /* unit */) {
    util::timing::Collector _("spicy/compiler/validator");

    auto v = PreservedVisitor();
    for ( auto& root : *nodes ) {
        for ( auto i : v.walk(&root) )
            v.dispatch(i);
    }
}
