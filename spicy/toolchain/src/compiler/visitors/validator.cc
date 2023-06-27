// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <utility>

#include <spicy/rt/mime.h>

#include <hilti/ast/ctors/string.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/expressions/type.h>
#include <hilti/ast/operators/reference.h>
#include <hilti/ast/statements/switch.h>
#include <hilti/ast/types/stream.h>
#include <hilti/base/logger.h>
#include <hilti/base/result.h>
#include <hilti/base/util.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/all.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/hook.h>
#include <spicy/ast/types.h>
#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;
using hilti::util::fmt;

namespace {

bool isEnumType(const Type& t, const char* expected_id) { return t.typeID() && *t.typeID() == ID(expected_id); }

// Helper to validate that a type is parseable.
hilti::Result<hilti::Nothing> isParseableType(const Type& pt, const type::unit::item::Field& f) {
    if ( pt.isA<type::Bitfield>() )
        return hilti::Nothing();

    if ( pt.isA<type::Bytes>() ) {
        if ( f.ctor() )
            return hilti::Nothing();

        auto eod_attr = AttributeSet::find(f.attributes(), "&eod");
        auto until_attr = AttributeSet::find(f.attributes(), "&until");
        auto until_including_attr = AttributeSet::find(f.attributes(), "&until-including");
        auto parse_at_attr = AttributeSet::find(f.attributes(), "&parse-at");
        auto parse_from_attr = AttributeSet::find(f.attributes(), "&parse-from");
        auto size_attr = AttributeSet::find(f.attributes(), "&size");
        auto max_size_attr = AttributeSet::find(f.attributes(), "&max-size");

        std::vector<std::string> start_attrs_present;
        for ( const auto& i : {parse_from_attr, parse_at_attr} ) {
            if ( i )
                start_attrs_present.emplace_back(i->tag());
        }

        std::vector<std::string> end_attrs_present;
        for ( const auto& i : {eod_attr, until_attr, until_including_attr} ) {
            if ( i )
                end_attrs_present.emplace_back(i->tag());
        }

        std::vector<std::string> size_attrs_present;
        for ( const auto& i : {size_attr, max_size_attr} ) {
            if ( i )
                size_attrs_present.emplace_back(i->tag());
        }

        for ( const auto* attrs_present : {&start_attrs_present, &size_attrs_present} ) {
            if ( attrs_present->size() > 1 )
                return hilti::result::Error(
                    fmt("attributes cannot be combined: %s", hilti::util::join(*attrs_present, ", ")));
        }

        if ( until_attr && until_including_attr )
            return hilti::result::Error(fmt("attributes cannot be combined: &until, &until-including"));

        if ( ! size_attr && start_attrs_present.empty() && end_attrs_present.empty() )
            return hilti::result::Error(
                "bytes field requires one of &eod, &parse_at, &parse_from, &size, &until, &until-including");

        return hilti::Nothing();
    }

    if ( pt.isA<type::Address>() ) {
        auto v4 = AttributeSet::find(f.attributes(), "&ipv4");
        auto v6 = AttributeSet::find(f.attributes(), "&ipv6");

        if ( ! (v4 || v6) )
            return hilti::result::Error("address field must come with either &ipv4 or &ipv6 attribute");

        if ( v4 && v6 )
            return hilti::result::Error("address field cannot have both &ipv4 and &ipv6 attributes");

        return hilti::Nothing();
    }

    if ( pt.isA<type::Real>() ) {
        auto type = AttributeSet::find(f.attributes(), "&type");

        if ( type ) {
            if ( const auto& t = type->valueAsExpression()->get().type(); ! isEnumType(t, "spicy::RealType") )
                return hilti::result::Error("&type attribute must be a spicy::RealType");
        }
        else
            return hilti::result::Error("field of type real must be used with a &type attribute");

        return hilti::Nothing();
    }

    if ( pt.isA<type::SignedInteger>() || pt.isA<type::UnsignedInteger>() )
        return hilti::Nothing();

    if ( pt.isA<type::Unit>() )
        return hilti::Nothing();

    if ( const auto& x = pt.tryAs<type::ValueReference>() ) {
        const auto& dt = x->dereferencedType();

        if ( auto rc = isParseableType(dt, f); ! rc )
            return rc;

        return hilti::Nothing();
    }

    if ( pt.isA<type::Void>() ) {
        if ( f.attributes() ) {
            for ( const auto& a : f.attributes()->attributes() ) {
                if ( a.tag() != "&requires" )
                    return hilti::result::Error("no parsing attributes supported for void field");
            }
        }

        return hilti::Nothing();
    }

    // A vector can be parsed either through a sub-item, or through a type.

    if ( auto item = f.item() ) {
        if ( auto item_field = item->tryAs<spicy::type::unit::item::Field>() ) {
            // Nothing to check here right now.
        }

        return hilti::Nothing();
    }

    else if ( const auto& x = pt.tryAs<type::Vector>() ) {
        if ( auto rc = isParseableType(x->elementType(), f); ! rc )
            return rc;

        return hilti::Nothing();
    }

    return hilti::result::Error(fmt("not a parseable type (%s)", pt));
}

struct VisitorBase {
    int errors = 0;

    // Record error at location of current node.
    void error(std::string msg, position_t& p,
               hilti::node::ErrorPriority priority = hilti::node::ErrorPriority::Normal) {
        p.node.addError(std::move(msg), p.node.location(), priority);
        ++errors;
    }

    // Record error with current node, but report with another node's location.
    void error(std::string msg, position_t& p, const Node& n,
               hilti::node::ErrorPriority priority = hilti::node::ErrorPriority::Normal) {
        p.node.addError(std::move(msg), n.location(), priority);
        ++errors;
    }

    // Record error with current node, but report with a custom location.
    void error(std::string msg, position_t& p, Location l,
               hilti::node::ErrorPriority priority = hilti::node::ErrorPriority::Normal) {
        p.node.addError(std::move(msg), std::move(l), priority);
        ++errors;
    }

    /** Returns a method call's i-th argument. */
    const Expression& methodArgument(const hilti::expression::ResolvedOperatorBase& o, size_t i) {
        auto ops = o.op2();

        // If the argument list was the result of a coercion unpack its result.
        if ( auto coerced = ops.tryAs<hilti::expression::Coerced>() )
            ops = coerced->expression();

        if ( auto ctor_ = ops.tryAs<hilti::expression::Ctor>() ) {
            auto ctor = ctor_->ctor();

            // If the argument was the result of a coercion unpack its result.
            if ( auto x = ctor.tryAs<hilti::ctor::Coerced>() )
                ctor = x->coercedCtor();

            if ( auto args = ctor.tryAs<hilti::ctor::Tuple>(); args && i < args->value().size() )
                return args->value()[i];
        }

        hilti::util::cannot_be_reached();
    }
};

struct VisitorPre : public hilti::visitor::PreOrder<void, VisitorPre>, public VisitorBase {};

struct VisitorPost : public hilti::visitor::PreOrder<void, VisitorPost>, public VisitorBase {
    template<typename GlobalOrLocalVariable>
    void checkVariable(const GlobalOrLocalVariable& n, position_t p) {
        // A variable initialized from a struct initializer always needs an explicit type.
        const bool isTyped = n.type().typeID().has_value();
        if ( isTyped )
            return;

        if ( auto init = n.init() ) {
            if ( auto ctor = init->template tryAs<hilti::expression::Ctor>() ) {
                if ( ctor->ctor().template tryAs<hilti::ctor::Struct>() ) {
                    error("declaration needs a concrete struct type", p);
                }
            }
        }
    }

    void operator()(const hilti::declaration::GlobalVariable& n, position_t p) { checkVariable(n, p); }

    void operator()(const hilti::declaration::LocalVariable& n, position_t p) { checkVariable(n, p); }

    void operator()(const hilti::declaration::Constant& n, position_t p) {
        if ( auto parent = p.parent(); ! parent.isA<hilti::Module>() && ! parent.isA<hilti::type::Enum>() )
            error("constant cannot be declared at local scope", p);
    }

    void operator()(const hilti::expression::ResolvedID& id, position_t p) {
        if ( id.id() == ID("__dd") ) {
            if ( auto hook = p.findParent<spicy::Hook>(); hook && hook->get().isForEach() )
                // $$ in "foreach" ok is ok.
                return;

            if ( auto attr = p.findParent<spicy::Attribute>() ) {
                auto tag = attr->get().tag();
                if ( tag == "&until" || tag == "&until-including" || tag == "&while" )
                    // $$ inside these attributes is ok
                    return;
            }

            if ( auto field = p.findParent<spicy::type::unit::item::Field>() ) {
                if ( field->get().isContainer() && field->get().isTransient() )
                    error("cannot use $$ with container inside transient field", p);
            }
        }
    }

    void operator()(const hilti::Module& m, position_t p) {
        if ( auto version = m.moduleProperty("%spicy-version") ) {
            if ( ! version->expression() ) {
                error("%spicy-version requires an argument", p);
                return;
            }

            bool ok = false;
            if ( auto c = version->expression()->tryAs<hilti::expression::Ctor>() ) {
                if ( auto s = c->ctor().tryAs<hilti::ctor::String>() ) {
                    // Parse string as either "x.y" or "x.y.z".

                    if ( auto v = hilti::util::split(s->value(), "."); v.size() >= 2 && v.size() <= 3 ) {
                        auto parse_number = [&ok](const std::string& s) {
                            return hilti::util::chars_to_uint64(s.c_str(), 10, [&ok]() { ok = false; });
                        };

                        ok = true;
                        auto major = parse_number(v[0]);
                        auto minor = parse_number(v[1]);
                        uint64_t patch = 0;

                        if ( v.size() == 3 )
                            patch = parse_number(v[2]);

                        // This must match the computation in the toplevel `CMakeLists.txt` file.
                        auto version = major * 10000 + minor * 100 + patch;
                        if ( hilti::configuration().version_number < version )
                            error(fmt("module %s requires at least Spicy version %s (have %s)", m.id(), s->value(),
                                      hilti::configuration().version_string),
                                  p);
                    }
                }
            }

            if ( ! ok )
                error(fmt("%%spicy-version requires argument of the form x.y[.z] (have: %s)", *version->expression()),
                      p);
        }
    }

    void operator()(const statement::Print& /* n */, position_t p) {
        // TODO(robin): .
    }

    void operator()(const statement::Stop& n, position_t p) {
        // Must be inside &foreach hook.
        if ( auto x = p.findParent<Hook>(); ! (x && x->get().isForEach()) )
            error("'stop' can only be used inside a 'foreach' hook", p);
    }

    void operator()(const hilti::declaration::Property& i, position_t p) {
        if ( i.id().str() == "%spicy-version" )
            ; // Nothing; handled in validator for `hilti::Module`.

        else if ( i.id().str() == "%byte-order" ) {
            if ( auto e = i.expression(); ! e ) {
                error("%byte-order requires an argument", p);
                return;
            }
        }

        else if ( i.id().str() == "%cxx-include" ) {
            if ( auto e = i.expression(); ! e ) {
                error("%byte-order requires an argument", p);
                return;
            }
        }

        else if ( const auto& prop = i.id().str(); prop == "%skip" || prop == "%skip-post" || prop == "%skip-pre" ) {
            if ( const auto& e = i.expression(); ! e ) {
                error(fmt("%s requires an argument", prop), p);
                return;
            }

            else if ( auto t = e->type(); ! t.isA<type::RegExp>() && ! t.isA<type::Null>() ) {
                error(fmt("%s requires a regexp as its argument", prop), p);
                return;
            }
        }

        else if ( const auto& prop = i.id().str(); prop == "%synchronize-at" || prop == "%synchronize-after" ) {
            if ( auto e = i.expression(); ! e ) {
                error(fmt("%s requires an argument", prop), p);
                return;
            }
        }

        else
            error(fmt("unknown property '%s'", i.id().str()), p);
    }

    void operator()(const spicy::type::unit::item::Property& i, position_t p) {
        if ( i.id().str() == "%random-access" ) {
            if ( i.expression() )
                error("%random-access does not accept an argument", p);

            hilti::logger().deprecated("%random-access is no longer needed and deprecated", i.meta().location());
        }

        else if ( i.id().str() == "%filter" ) {
            if ( i.expression() )
                error("%filter does not accept an argument", p);
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

            if ( ! i.expression()->type().isA<type::String>() ) {
                error("%mime-type requires a string argument", p);
                return;
            }

            if ( auto x = i.expression()->tryAs<hilti::expression::Ctor>() ) {
                const auto& mt = x->ctor().as<hilti::ctor::String>().value();

                if ( ! spicy::rt::MIMEType::parse(mt) )
                    error("%mime-type argument must follow \"main/sub\" form", p);
            }
        }

        else if ( i.id().str() == "%port" ) {
            if ( ! i.expression() ) {
                error("%port requires an argument", p);
                return;
            }

            if ( ! i.expression()->type().tryAs<type::Port>() )
                error("%port requires a port as its argument", p);
        }

        else if ( i.id().str() == "%context" ) {
            if ( auto e = i.expression(); ! e )
                error("%context requires an argument", p);
            else if ( ! e->isA<hilti::expression::Type_>() )
                error("%context requires a type", p);

            auto decl = p.findParent<hilti::declaration::Type>();
            if ( decl && decl->get().linkage() != hilti::declaration::Linkage::Public )
                error("only public units can have %context", p);
        }

        else if ( const auto& prop = i.id().str(); prop == "%skip" || prop == "%skip-post" || prop == "%skip-pre" ) {
            if ( const auto& e = i.expression(); ! e ) {
                error(fmt("%s requires an argument", prop), p);
                return;
            }

            else if ( auto t = e->type(); ! t.isA<type::RegExp>() && ! t.isA<type::Null>() ) {
                error(fmt("%s requires a regexp as its argument", prop), p);
                return;
            }
        }

        else if ( i.id().str() == "%byte-order" ) {
            if ( const auto& e = i.expression(); ! e ) {
                error(fmt("%s requires an argument", prop), p);
                return;
            }

            if ( ! isEnumType(i.expression()->type(), "spicy::ByteOrder") )
                error(fmt("%%byte-order expression must be of spicy::ByteOrder, but is of type %s",
                          i.expression()->type()),
                      p);
        }

        else if ( const auto& prop = i.id().str(); prop == "%synchronize-at" || prop == "%synchronize-after" ) {
            if ( ! i.expression() ) {
                error(fmt("%s requires an argument", prop), p);
                return;
            }
        }

        else
            error(fmt("unknown property '%s'", i.id().str()), p);
    }

    void operator()(const spicy::Hook& h, position_t p) {
        if ( auto field = p.findParent<spicy::type::unit::item::Field>() ) {
            if ( h.isForEach() && ! field->get().isContainer() )
                error("foreach can only be used with containers", p);
        }
    }

    void operator()(const spicy::type::unit::item::UnitHook& i, position_t p) {
        auto decl = p.findParent<hilti::declaration::Type>();
        if ( ! decl || ! decl->get().type().isA<type::Unit>() )
            return;

        auto unit = p.findParent<type::Unit>(); // note that this can be a different unit than in the decl, when nested
        if ( ! unit )
            return;

        _checkHook(*unit, i.hook(), decl->get().linkage() == hilti::declaration::Linkage::Public, false, p);
    }

    void operator()(const Attribute& a, position_t p) {
        auto getAttrField = [](position_t p) -> std::optional<spicy::type::unit::item::Field> {
            try {
                // Expected parent is AttributeSet whose expected parent is Field.
                const auto& n = p.parent(2);
                return n.tryAs<spicy::type::unit::item::Field>();
            } catch ( std::out_of_range& ) {
            }

            return {};
        };

        if ( a.tag() == "&size" && ! a.hasValue() )
            error("&size must provide an expression", p);

        else if ( a.tag() == "&max-size" && ! a.hasValue() )
            error("&max-size must provide an expression", p);

        else if ( a.tag() == "&byte-order" && ! a.hasValue() )
            error("&byte-order requires an expression", p);

        else if ( a.tag() == "&default" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! a.hasValue() )
                    error("&default requires an argument", p);
                else {
                    if ( auto x = a.valueAsExpression(); ! x ) {
                        error(x.error(), p);
                    }

                    // expression type is checked HILTI-side.
                }
            }
        }

        else if ( a.tag() == "&eod" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! (f->parseType().isA<type::Bytes>() || f->parseType().isA<type::Vector>()) || f->ctor() )
                    error("&eod is only valid for bytes and vector fields", p);
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

        else if ( a.tag() == "&while" || a.tag() == "&until-including" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! (f->parseType().isA<type::Bytes>() || f->parseType().isA<type::Vector>()) )
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
                             AttributeSet::has(f->attributes(), "&size") ||
                             AttributeSet::has(f->attributes(), "&until") ||
                             AttributeSet::has(f->attributes(), "&until-including")) )
                    error("&chunked must be used with &eod, &until, &until-including or &size", p);
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
                else if ( auto e = a.valueAsExpression();
                          e && e->get().type() != type::stream::Iterator() && e->get().type() != type::Bytes() )
                    error("&parse-from must have an expression of type either bytes or iterator<stream>", p);
            }
        }

        else if ( a.tag() == "&parse-at" ) {
            if ( auto f = getAttrField(p) ) {
                if ( ! a.hasValue() )
                    error("&parse-at must provide an expression", p);
                else if ( auto e = a.valueAsExpression(); e && e->get().type() != type::stream::Iterator() &&
                                                          e->get().type() != type::stream::Iterator() )
                    error("&parse-at must have an expression of type iterator<stream>", p);
            }
        }

        else if ( a.tag() == "&requires" ) {
            if ( ! a.hasValue() )
                error("&requires must provide an expression", p);
            else if ( auto e = a.valueAsExpression(); e && e->get().type() != type::Bool() )
                error(fmt("&requires expression must be of type bool, but is of type %d ", e->get().type()), p);
        }
    }

    void operator()(const spicy::type::Unit& u, position_t p) {
        if ( auto attrs = u.attributes() ) {
            if ( AttributeSet::find(attrs, "&size") && AttributeSet::find(attrs, "&max-size") )
                error(("attributes cannot be combined: &size, &max-size"), p);

            for ( const auto& a : attrs->attributes() ) {
                if ( a.tag() == "&size" ) {
                    if ( ! a.hasValue() )
                        error("&size must provide an expression", p);
                }

                else if ( a.tag() == "&max-size" ) {
                    if ( ! a.hasValue() )
                        error("&max-size must provide an expression", p);
                }

                else if ( a.tag() == "&requires" ) {
                    auto e = a.valueAsExpression();
                    if ( ! e )
                        error(e.error(), p);
                    else {
                        if ( e->get().type() != type::Bool() )
                            error(fmt("&requires expression must be of type bool, but is of type %s ", e->get().type()),
                                  p);
                    }
                }
                else if ( a.tag() == "&byte-order" ) {
                    auto e = a.valueAsExpression();
                    if ( ! e )
                        error(e.error(), p);
                    else {
                        if ( ! isEnumType(e->get().type(), "spicy::ByteOrder") )
                            error(fmt("&byte-order expression must be of spicy::ByteOrder, but is of type %s ",
                                      e->get().type()),
                                  p);
                    }
                }
                else if ( a.tag() == "&convert" ) {
                    if ( ! a.hasValue() )
                        error("&convert must provide an expression", p);
                }
                else
                    error(fmt("attribute %s not supported for unit types", a.tag()), p);
            }
        }

        if ( auto contexts = u.propertyItems("%context"); contexts.size() > 1 )
            error("unit cannot have more than one %context", p);

        if ( const auto& typeId = u.id() ) {
            const auto& type_name = typeId->local();
            for ( const auto& item : u.items() )
                if ( auto field = item.tryAs<spicy::type::unit::item::Field>(); field && field->id() == type_name )
                    error(fmt("field name '%s' cannot have name identical to owning unit '%s'", field->id(), *typeId),
                          p);
        }

        if ( u.propertyItem("%synchronize-at") && u.propertyItem("%synchronize-after") )
            error("unit cannot specify both %synchronize-at and %synchronize-after", p);
    }

    void operator()(const hilti::operator_::value_reference::Equal& o, position_t p) {
        if ( auto ref = o.op0().type().tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType().isA<type::Unit>() )
            error("units cannot be compared with ==", p);
    }

    void operator()(const hilti::operator_::value_reference::Unequal& o, position_t p) {
        if ( auto ref = o.op0().type().tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType().isA<type::Unit>() )
            error("units cannot be compared with !=", p);
    }

    void operator()(const hilti::operator_::strong_reference::Equal& o, position_t p) {
        if ( auto ref = o.op0().type().tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType().isA<type::Unit>() )
            error("units cannot be compared with ==", p);
    }

    void operator()(const hilti::operator_::strong_reference::Unequal& o, position_t p) {
        if ( auto ref = o.op0().type().tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType().isA<type::Unit>() )
            error("units cannot be compared with !=", p);
    }

    void operator()(const spicy::type::unit::item::Field& f, position_t p) {
        auto count_attr = AttributeSet::find(f.attributes(), "&count");
        auto repeat = f.repeatCount();
        auto is_sub_item = p.parent().isA<spicy::type::unit::item::Field>();

        if ( f.isSkip() ) {
            if ( ! f.sinks().empty() )
                error("skip field cannot have sinks attached", p);
        }

        if ( count_attr && (repeat && ! repeat->type().isA<type::Null>()) )
            error("cannot have both `[..]` and &count", p);

        if ( f.sinks().size() && ! f.parseType().isA<type::Bytes>() )
            error("only a bytes field can have sinks attached", p);

        if ( const auto& c = f.ctor() ) {
            // Check that constants are of a supported type.
            if ( ! type::supportsLiterals(c->type()) )
                error(fmt("not a parseable constant (%s)", *c), p);
        }

        else {
            if ( f.originalType().isA<type::RegExp>() ) {
                error("need regexp constant for parsing a field", p);
                return;
            }

            if ( f.originalType().isA<type::Vector>() && is_sub_item ) {
                error("use [] syntax to parse vectors", p);
                return;
            }

            if ( ! f.item() ) {
                if ( auto rc = isParseableType(f.parseType(), f); ! rc ) {
                    error(rc.error(), p);
                    return;
                }
            }
        }
    }

    void operator()(const spicy::type::unit::item::UnresolvedField& u, position_t p) {
        if ( auto id = u.unresolvedID() )
            error(fmt("unknown ID '%s'", *id), p);
        else
            // I don't think this can actually happen ...
            error("unit field left unresolved", p);
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

                    if ( auto x = AttributeSet::find(f->attributes(), "&synchronize") )
                        error(fmt("unit switch branches cannot be &synchronize"), p);

                    seen_fields.emplace_back(*f);
                }
            }
        }

        if ( defaults > 1 )
            error("more than one default case", p);

        if ( const auto& attrs = s.attributes() ) {
            for ( const auto& attr : attrs->attributes() ) {
                const auto& tag = attr.tag();

                if ( tag != "&size" && tag != "&parse-at" && tag != "&parse-from" )
                    error(fmt("attribute '%s' is not supported here", tag), p);
            }
        }
    }

    void operator()(const spicy::type::unit::item::Variable& v, position_t p) {
        if ( auto attrs = v.attributes() ) {
            for ( const auto& attr : attrs->attributes() ) {
                const auto& tag = attr.tag();
                if ( tag != "&optional" )
                    error(fmt("attribute '%s' not supported for unit variables", tag), p);
            }
        }

        if ( v.itemType().isA<type::Sink>() )
            error(
                "cannot use type 'sink' for unit variables; use either a 'sink' item or a reference to a sink "
                "('sink&')",
                p);
    }

    void operator()(const spicy::declaration::UnitHook& u, position_t p) {
        if ( const auto& ut = u.hook().unitType() )
            _checkHook(*ut, u.hook(), ut->isPublic(), true, p);
        else
            error("unknown unit type", p);
    }

    void _checkHook(const type::Unit& unit, const Hook& hook, bool is_public, bool is_external, position_t& p) {
        // Note: We can't use any of the unit.isX() methods here that depend
        // on unit.isPublic() being set correctly, as they might not have
        // happened yet.

        auto params = hook.ftype().parameters();
        const auto& location = hook.meta().location();

        if ( ! hook.ftype().result().type().isA<type::Void>() && hook.id().local().str() != "0x25_print" )
            error("hook cannot have a return value", p, location);

        if ( hook.id().namespace_() && ! is_external )
            error("hook ID cannot be scoped", p, location);

        auto id = hook.id().local().str();
        bool needs_sink_support = false;

        if ( id.find('.') != std::string::npos )
            error("cannot use paths in hooks; trigger on the top-level field instead", p, location);

        else if ( hilti::util::startsWith(id, "0x25_") ) {
            auto id_readable = hilti::util::replace(hook.id().local().str(), "0x25_", "%");

            if ( id == "0x25_init" || id == "0x25_done" || id == "0x25_print" || id == "0x25_finally" ||
                 id == "0x25_rejected" || id == "0x25_confirmed" || id == "0x25_synced" ) {
                if ( params.size() != 0 )
                    error(fmt("hook '%s' does not take any parameters", id_readable), p, location);
            }

            else if ( id == "0x25_error" ) {
                if ( params.size() != 1 || params[0].type() != type::String() )
                    error("signature for hook must be: %error or %error(err: string)", p, location);
            }

            else if ( id == "0x25_gap" ) {
                needs_sink_support = true;
                if ( params.size() != 2 || params[0].type() != type::UnsignedInteger(64) ||
                     params[1].type() != type::UnsignedInteger(64) )
                    error("signature for hook must be: %gap(seq: uint64, len: uint64)", p, location);
            }

            else if ( id == "0x25_overlap" ) {
                needs_sink_support = true;
                if ( params.size() != 3 || params[0].type() != type::UnsignedInteger(64) ||
                     params[1].type() != type::Bytes() || params[2].type() != type::Bytes() )
                    error("signature for hook must be: %overlap(seq: uint64, old: bytes, new_: bytes)", p, location);
            }

            else if ( id == "0x25_skipped" ) {
                needs_sink_support = true;
                if ( params.size() != 1 || params[0].type() != type::UnsignedInteger(64) )
                    error("signature for hook must be: %skipped(seq: uint64)", p, location);
            }

            else if ( id == "0x25_undelivered" ) {
                needs_sink_support = true;
                if ( params.size() != 2 || params[0].type() != type::UnsignedInteger(64) ||
                     params[1].type() != type::Bytes() )
                    error("signature for hook must be: %undelivered(seq: uint64, data: bytes)", p, location);
            }

            else
                error(fmt("unknown hook '%s'", id_readable), p, location);

            if ( needs_sink_support && ! is_public ) // don't use supportsSink() here, see above
                error(fmt("cannot use hook '%s', unit type does not support sinks because it is not public",
                          id_readable),
                      p, location);
        }
        else {
            if ( auto i = unit.itemByName(ID(id)); ! i )
                error(fmt("no field '%s' in unit type", id), p, location);
        }
    }

    void operator()(const operator_::sink::ConnectMIMETypeBytes& n, position_t p) {
        if ( auto x = n.op0().type().tryAs<type::Unit>() ) {
            if ( x->parameters().size() )
                error("unit types with parameters cannot be connected through MIME type", p);
        }
    }

    void operator()(const operator_::sink::ConnectMIMETypeString& n, position_t p) {
        if ( auto x = n.op0().type().tryAs<type::Unit>() ) {
            if ( x->parameters().size() )
                error("unit types with parameters cannot be connected through MIME type", p);
        }
    }

    void operator()(const operator_::unit::ConnectFilter& n, position_t p) {
        if ( const auto& y =
                 methodArgument(n, 0).type().as<type::StrongReference>().dereferencedType().as<type::Unit>();
             ! y.isFilter() )
            error("unit type cannot be a filter, %filter missing", p);
    }

    void operator()(const operator_::unit::ContextConst& n, position_t p) {
        if ( auto x = n.op0().type().tryAs<type::Unit>(); x && ! x->contextType() )
            error("context() used with a unit which did not declare %context", p);
    }

    void operator()(const operator_::unit::ContextNonConst& n, position_t p) {
        if ( auto x = n.op0().type().tryAs<type::Unit>(); x && ! x->contextType() )
            error("context() used with a unit which did not declare %context", p);
    }

    void operator()(const operator_::unit::Forward& n, position_t p) {
        if ( auto x = n.op0().type().tryAs<type::Unit>(); x && ! x->isFilter() )
            error("unit type cannot be a filter, %filter missing", p);
    }

    void operator()(const operator_::unit::ForwardEod& n, position_t p) {
        if ( auto x = n.op0().type().tryAs<type::Unit>(); x && ! x->isFilter() )
            error("unit type cannot be a filter, %filter missing", p);
    }

    void operator()(const spicy::type::Bitfield& b, position_t p) {
        const auto width = b.width();

        for ( const auto& bit : b.bits() ) {
            const auto lower = bit.lower();
            const auto upper = bit.upper();

            if ( lower > upper )
                error("lower limit needs to be lower than upper limit", p);

            if ( upper >= width )
                error("upper limit is beyond the width of the bitfield", p);
        }
    }
};

} // anonymous namespace

void spicy::detail::ast::validate_pre(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root,
                                      hilti::Unit* unit) {
    {
        auto v = VisitorPre();
        hilti::util::timing::Collector _("spicy/compiler/validator");

        for ( auto i : v.walk(root) )
            v.dispatch(i);
    }

    (*hilti::plugin::registry().hiltiPlugin().ast_validate_pre)(ctx, root, unit);
}

void spicy::detail::ast::validate_post(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root,
                                       hilti::Unit* unit) {
    {
        auto v = VisitorPost();
        hilti::util::timing::Collector _("spicy/compiler/validator");

        for ( auto i : v.walk(root) )
            v.dispatch(i);
    }

    (*hilti::plugin::registry().hiltiPlugin().ast_validate_post)(ctx, root, unit);
}
