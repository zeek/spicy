// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/rt/mime.h>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/node.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/validator.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/forward.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/validator.h>

#include "ast/node.h"
#include "ast/type.h"

using namespace spicy;
using hilti::util::fmt;

namespace {

bool isEnumType(QualifiedType* t, const char* expected_id) {
    return t->type()->typeID() && t->type()->typeID() == ID(expected_id);
}

// Helper to validate that a type supports parsing from literals.
bool supportsLiterals(QualifiedType* t) {
    return t->type()->isA<hilti::type::Bytes>() || t->type()->isA<hilti::type::RegExp>() ||
           t->type()->isA<hilti::type::SignedInteger>() || t->type()->isA<hilti::type::UnsignedInteger>() ||
           t->type()->isA<hilti::type::Bitfield>();
}

// Helper to validate that a type is parseable.
hilti::Result<hilti::Nothing> isParseableType(QualifiedType* pt, const type::unit::item::Field* f) {
    if ( pt->type()->isA<hilti::type::Bitfield>() )
        return hilti::Nothing();

    if ( pt->type()->isA<hilti::type::Bytes>() ) {
        if ( f->ctor() )
            return hilti::Nothing();

        auto eod_attr = f->attributes()->find("&eod");
        auto until_attr = f->attributes()->find("&until");
        auto until_including_attr = f->attributes()->find("&until-including");
        auto parse_at_attr = f->attributes()->find("&parse-at");
        auto parse_from_attr = f->attributes()->find("&parse-from");
        auto size_attr = f->attributes()->find("&size");
        auto max_size_attr = f->attributes()->find("&max-size");

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

    if ( pt->type()->isA<hilti::type::Address>() ) {
        auto v4 = f->attributes()->find("&ipv4");
        auto v6 = f->attributes()->find("&ipv6");

        if ( ! (v4 || v6) )
            return hilti::result::Error("address field must come with either &ipv4 or &ipv6 attribute");

        if ( v4 && v6 )
            return hilti::result::Error("address field cannot have both &ipv4 and &ipv6 attributes");

        return hilti::Nothing();
    }

    if ( pt->type()->isA<hilti::type::Real>() ) {
        auto type = f->attributes()->find("&type");

        if ( type ) {
            if ( const auto& t = (*type->valueAsExpression())->type(); ! isEnumType(t, "spicy::RealType") )
                return hilti::result::Error("&type attribute must be a spicy::RealType");
        }
        else
            return hilti::result::Error("field of type real must be used with a &type attribute");

        return hilti::Nothing();
    }

    if ( pt->type()->isA<hilti::type::SignedInteger>() || pt->type()->isA<hilti::type::UnsignedInteger>() )
        return hilti::Nothing();

    if ( pt->type()->isA<type::Unit>() )
        return hilti::Nothing();

    if ( const auto& x = pt->type()->tryAs<hilti::type::ValueReference>() ) {
        const auto& dt = x->dereferencedType();

        if ( auto rc = isParseableType(dt, f); ! rc )
            return rc;

        return hilti::Nothing();
    }

    if ( pt->type()->isA<hilti::type::Void>() ) {
        if ( f->attributes() ) {
            for ( const auto& a : f->attributes()->attributes() ) {
                if ( a->tag() != "&requires" )
                    return hilti::result::Error("no parsing attributes supported for void field");
            }
        }

        return hilti::Nothing();
    }

    // A vector can be parsed either through a sub-item, or through a type.

    if ( auto item = f->item() ) {
        if ( item->isA<spicy::type::unit::item::Field>() ) {
            // Nothing to check here right now.
        }

        return hilti::Nothing();
    }

    else if ( const auto& x = pt->type()->tryAs<hilti::type::Vector>() ) {
        if ( auto rc = isParseableType(x->elementType(), f); ! rc )
            return rc;

        return hilti::Nothing();
    }

    return hilti::result::Error(fmt("not a parseable type (%s)", *pt));
}

Expression* methodArgument(const hilti::expression::ResolvedOperator& o, size_t i) {
    auto ops = o.op2();

    // If the argument list was the result of a coercion unpack its result.
    if ( auto coerced = ops->tryAs<hilti::expression::Coerced>() )
        ops = coerced->expression();

    if ( auto ctor_ = ops->tryAs<hilti::expression::Ctor>() ) {
        auto ctor = ctor_->ctor();

        // If the argument was the result of a coercion unpack its result.
        if ( auto x = ctor->tryAs<hilti::ctor::Coerced>() )
            ctor = x->coercedCtor();

        if ( auto args = ctor->tryAs<hilti::ctor::Tuple>(); args && i < args->value().size() )
            return args->value()[i];
    }

    hilti::util::cannotBeReached();
}

struct VisitorPre : visitor::PreOrder, hilti::validator::VisitorMixIn {
    using hilti::validator::VisitorMixIn::VisitorMixIn;
};

struct VisitorPost : visitor::PreOrder, hilti::validator::VisitorMixIn {
    using hilti::validator::VisitorMixIn::VisitorMixIn;

    template<typename GlobalOrLocalVariable>
    void checkVariable(const GlobalOrLocalVariable& n) {
        // A variable initialized from a struct initializer always needs an explicit type.
        const bool isTyped = ! n->type()->type()->typeID().empty();
        if ( isTyped )
            return;

        if ( auto init = n->init() ) {
            if ( auto expr = init->template tryAs<hilti::expression::Ctor>() ) {
                auto ctor = expr->ctor();

                if ( auto coerced = ctor->template tryAs<hilti::ctor::Coerced>() ) {
                    ctor = coerced->coercedCtor();
                }

                if ( ctor->template tryAs<hilti::ctor::Struct>() )
                    error("declaration needs a concrete struct type", n, node::ErrorPriority::High);
            }
        }
    }

    void operator()(hilti::declaration::GlobalVariable* n) final { checkVariable(n); }

    void operator()(hilti::declaration::LocalVariable* n) final { checkVariable(n); }

    void operator()(hilti::declaration::Constant* n) final {
        if ( auto parent = n->parent();
             ! parent->isA<hilti::declaration::Module>() && ! parent->isA<hilti::type::Enum>() )
            error("constant cannot be declared at local scope", n);
    }

    void operator()(hilti::expression::Name* n) final {
        if ( n->id() == ID("__dd") ) {
            if ( auto hook = n->parent<spicy::declaration::Hook>(); hook && hook->isForEach() )
                // $$ in "foreach" ok is ok.
                return;

            if ( auto attr = n->parent<hilti::Attribute>() ) {
                auto tag = attr->tag();
                if ( tag == "&until" || tag == "&until-including" || tag == "&while" )
                    // $$ inside these attributes is ok
                    return;
            }

            if ( auto field = n->parent<spicy::type::unit::item::Field>() ) {
                if ( field->isContainer() && field->isTransient() )
                    error("cannot use $$ with container inside transient field", n);
            }
        }
    }

    void operator()(hilti::declaration::Module* n) final {
        if ( auto version = n->moduleProperty("%spicy-version") ) {
            if ( ! version->expression() ) {
                error("%spicy-version requires an argument", n);
                return;
            }

            bool ok = false;
            if ( auto c = version->expression()->tryAs<hilti::expression::Ctor>() ) {
                if ( auto s = c->ctor()->tryAs<hilti::ctor::String>() ) {
                    // Parse string as either "x.y" or "x.y.z".

                    if ( auto v = hilti::util::split(s->value(), "."); v.size() >= 2 && v.size() <= 3 ) {
                        auto parse_number = [&ok](const std::string& s) {
                            return hilti::util::charsToUInt64(s.c_str(), 10, [&ok]() { ok = false; });
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
                            error(fmt("module %s requires at least Spicy version %s (have %s)", n->id(), s->value(),
                                      hilti::configuration().version_string),
                                  n);
                    }
                }
            }

            if ( ! ok )
                error(fmt("%%spicy-version requires argument of the form x.y[.z] (have: %s)", *version->expression()),
                      n);
        }
    }

    void operator()(statement::Print* n) final {
        // TODO(robin): .
    }

    void operator()(statement::Stop* n) final {
        // Must be inside &foreach hook.
        if ( auto x = n->parent<declaration::Hook>(); ! (x && x->isForEach()) )
            error("'stop' can only be used inside a 'foreach' hook", n);
    }

    void operator()(hilti::declaration::Property* n) final {
        if ( n->id().str() == "%spicy-version" )
            ; // Nothing; handled in validator for `hilti::Module`.

        else if ( n->id().str() == "%skip-implementation" )
            ; // Nothing; just passed on to HILTI

        else if ( n->id().str() == "%byte-order" ) {
            if ( auto e = n->expression(); ! e ) {
                error("%byte-order requires an argument", n);
                return;
            }
        }

        else if ( n->id().str() == "%cxx-include" ) {
            if ( auto e = n->expression(); ! e ) {
                error("%byte-order requires an argument", n);
                return;
            }
        }

        else if ( const auto& prop = n->id().str(); prop == "%skip" || prop == "%skip-post" || prop == "%skip-pre" ) {
            if ( const auto& e = n->expression(); ! e ) {
                error(fmt("%s requires an argument", prop), n);
                return;
            }

            else if ( auto t = e->type();
                      ! t->type()->isA<hilti::type::RegExp>() && ! t->type()->isA<hilti::type::Null>() ) {
                error(fmt("%s requires a regexp as its argument", prop), n);
                return;
            }
        }

        else if ( const auto& prop = n->id().str(); prop == "%synchronize-at" || prop == "%synchronize-after" ) {
            if ( auto e = n->expression(); ! e ) {
                error(fmt("%s requires an argument", prop), n);
                return;
            }
        }

        else
            error(fmt("unknown property '%s'", n->id().str()), n);
    }

    void operator()(hilti::declaration::Type* n) final {
        if ( n->linkage() == hilti::declaration::Linkage::Public && n->type()->alias() ) {
            if ( n->type()->alias()->resolvedDeclaration()->linkage() != hilti::declaration::Linkage::Public )
                error("public unit alias cannot refer to a non-public type", n);
        }
    }

    void operator()(spicy::type::unit::item::Property* n) final {
        if ( n->id().str() == "%random-access" ) {
            if ( n->expression() )
                error("%random-access does not accept an argument", n);

            hilti::logger().deprecated("%random-access is no longer needed and deprecated", n->meta().location());
        }

        else if ( n->id().str() == "%filter" ) {
            if ( n->expression() )
                error("%filter does not accept an argument", n);
        }

        else if ( n->id().str() == "%description" ) {
            if ( ! n->expression() ) {
                error("%description requires an argument", n);
                return;
            }

            if ( ! n->expression()->type()->type()->isA<hilti::type::String>() )
                error("%description requires a string argument", n);
        }

        else if ( n->id().str() == "%mime-type" ) {
            if ( ! n->expression() ) {
                error("%mime-type requires an argument", n);
                return;
            }

            if ( ! n->expression()->type()->type()->isA<hilti::type::String>() ) {
                error("%mime-type requires a string argument", n);
                return;
            }

            if ( auto x = n->expression()->tryAs<hilti::expression::Ctor>() ) {
                const auto& mt = x->ctor()->as<hilti::ctor::String>()->value();

                if ( ! spicy::rt::MIMEType::parse(mt) )
                    error("%mime-type argument must follow \"main/sub\" form", n);
            }
        }

        else if ( n->id().str() == "%port" ) {
            if ( ! n->expression() ) {
                error("%port requires an argument", n);
                return;
            }

            if ( ! n->expression()->type()->type()->tryAs<hilti::type::Port>() )
                error("%port requires a port as its argument", n);
        }

        else if ( n->id().str() == "%context" ) {
            if ( auto e = n->expression(); ! e )
                error("%context requires an argument", n);
            else if ( ! e->type()->type()->isA<hilti::type::Type_>() )
                error("%context requires a type", n);

            auto decl = n->parent<hilti::declaration::Type>();
            if ( decl && decl->linkage() != hilti::declaration::Linkage::Public )
                error("only public units can have %context", n);
        }

        else if ( const auto& prop = n->id().str(); prop == "%skip" || prop == "%skip-post" || prop == "%skip-pre" ) {
            if ( const auto& e = n->expression(); ! e ) {
                error(fmt("%s requires an argument", prop), n);
                return;
            }

            else if ( auto t = e->type();
                      ! t->type()->isA<hilti::type::RegExp>() && ! t->type()->isA<hilti::type::Null>() ) {
                error(fmt("%s requires a regexp as its argument", prop), n);
                return;
            }
        }

        else if ( n->id().str() == "%byte-order" ) {
            if ( const auto& e = n->expression(); ! e ) {
                error(fmt("%s requires an argument", prop), n);
                return;
            }

            if ( ! isEnumType(n->expression()->type(), "spicy::ByteOrder") )
                error(fmt("%%byte-order expression must be of spicy::ByteOrder, but is of type %s",
                          *n->expression()->type()),
                      n);
        }

        else if ( const auto& prop = n->id().str(); prop == "%synchronize-at" || prop == "%synchronize-after" ) {
            if ( ! n->expression() ) {
                error(fmt("%s requires an argument", prop), n);
                return;
            }
        }

        else
            error(fmt("unknown property '%s'", n->id().str()), n);
    }

    void operator()(spicy::declaration::Hook* n) final {
        if ( auto field = n->parent<spicy::type::unit::item::Field>() ) {
            if ( n->isForEach() && ! field->isContainer() )
                error("'foreach' can only be used with containers", n);
        }
    }

    void operator()(spicy::type::unit::item::UnitHook* n) final {
        auto decl = n->parent<hilti::declaration::Type>();
        if ( ! decl || ! decl->type()->type()->isA<type::Unit>() )
            return;

        auto unit = n->parent<type::Unit>(); // note that this can be a different unit than in the decl, when nested
        if ( ! unit )
            return;

        checkHook(unit, n->hook(), decl->linkage() == hilti::declaration::Linkage::Public, false, n);
    }

    void operator()(hilti::Attribute* n) final {
        auto builder = Builder(VisitorMixIn::builder());

        auto get_attr_field = [](hilti::Attribute* a) -> spicy::type::unit::item::Field* {
            try {
                // Expected parent is AttributeSet* whose expected parent is Field.
                const auto& n = a->parent(2);
                return n->tryAs<spicy::type::unit::item::Field>();
            } catch ( std::out_of_range& ) {
            }

            return nullptr;
        };

        if ( n->tag() == "&size" && ! n->hasValue() )
            error("&size must provide an expression", n);

        else if ( n->tag() == "&max-size" && ! n->hasValue() )
            error("&max-size must provide an expression", n);

        else if ( n->tag() == "&byte-order" && ! n->hasValue() )
            error("&byte-order requires an expression", n);

        else if ( n->tag() == "&default" ) {
            if ( get_attr_field(n) ) {
                if ( ! n->hasValue() )
                    error("&default requires an argument", n);
                else {
                    if ( auto x = n->valueAsExpression(); ! x ) {
                        error(x.error(), n);
                    }

                    // expression type is checked HILTI-side.
                }
            }
        }

        else if ( n->tag() == "&eod" ) {
            if ( auto f = get_attr_field(n) ) {
                if ( ! (f->parseType()->type()->isA<hilti::type::Bytes>() ||
                        f->parseType()->type()->isA<hilti::type::Vector>()) ||
                     f->ctor() )
                    error("&eod is only valid for bytes and vector fields", n);
            }
        }

        else if ( n->tag() == "&until" ) {
            if ( auto f = get_attr_field(n) ) {
                if ( ! (f->parseType()->type()->isA<hilti::type::Bytes>() ||
                        f->parseType()->type()->isA<hilti::type::Vector>()) )
                    error("&until is only valid for fields of type bytes or vector", n);
                else if ( ! n->hasValue() )
                    error("&until must provide an expression", n);
            }
        }

        else if ( n->tag() == "&while" || n->tag() == "&until-including" ) {
            if ( auto f = get_attr_field(n) ) {
                if ( ! (f->parseType()->type()->isA<hilti::type::Bytes>() ||
                        f->parseType()->type()->isA<hilti::type::Vector>()) )
                    error(fmt("%s is only valid for fields of type bytes or vector", n->tag()), n);
                else if ( ! n->hasValue() )
                    error(fmt("%s must provide an expression", n->tag()), n);
            }
        }

        else if ( n->tag() == "&chunked" ) {
            if ( auto f = get_attr_field(n) ) {
                if ( ! f->parseType()->type()->isA<hilti::type::Bytes>() || f->ctor() )
                    error("&chunked is only valid for bytes fields", n);
                else if ( n->hasValue() )
                    error("&chunked cannot have an expression", n);
                else if ( ! (f->attributes()->has("&eod") || f->attributes()->has("&size") ||
                             f->attributes()->has("&until") || f->attributes()->has("&until-including")) )
                    error("&chunked must be used with &eod, &until, &until-including or &size", n);
            }
        }

        else if ( n->tag() == "&convert" ) {
            if ( ! n->hasValue() )
                error("&convert must provide an expression", n);
        }

        else if ( n->tag() == "&transient" )
            error("&transient is no longer available, use an anonymous field instead to achieve the same effect", n);

        else if ( n->tag() == "&parse-from" ) {
            if ( get_attr_field(n) ) {
                if ( ! n->hasValue() )
                    error("&parse-from must provide an expression", n);
                else if ( auto e = n->valueAsExpression();
                          e && ! hilti::type::same((*e)->type()->type(), builder.typeStreamIterator()) &&
                          ! hilti::type::same((*e)->type()->type(), builder.typeBytes()) )
                    error("&parse-from must have an expression of type either bytes or iterator<stream>", n);
            }
        }

        else if ( n->tag() == "&parse-at" ) {
            if ( get_attr_field(n) ) {
                if ( ! n->hasValue() )
                    error("&parse-at must provide an expression", n);
                else if ( auto e = n->valueAsExpression();
                          e && ! hilti::type::same((*e)->type()->type(), builder.typeStreamIterator()) )
                    error("&parse-at must have an expression of type iterator<stream>", n);
            }
        }

        else if ( n->tag() == "&requires" ) {
            if ( ! n->hasValue() )
                error("&requires must provide an expression", n);
            else if ( auto e = n->valueAsExpression();
                      e && ! hilti::type::same((*e)->type()->type(), builder.typeBool()) )
                error(fmt("&requires expression must be of type bool, but is of type %d ", *(*e)->type()), n);
        }
    }

    void checkBits(const spicy::type::Unit& u, const hilti::node::Set<type::unit::Item>& items,
                   std::set<ID>* seen_bits) {
        for ( const auto& item : items ) {
            if ( auto f = item->tryAs<spicy::type::unit::item::Field>() ) {
                if ( ! f->isAnonymous() )
                    continue;

                auto t = f->itemType()->type()->tryAs<hilti::type::Bitfield>();
                if ( ! t )
                    continue;

                for ( const auto& b : t->bits() ) {
                    if ( u.itemByName(b->id()) )
                        error(fmt("bitfield item '%s' shadows unit field", b->id()), item);

                    if ( seen_bits->find(b->id()) != seen_bits->end() )
                        error(fmt("bitfield item name '%s' appears in multiple anonymous bitfields", b->id()), item);

                    seen_bits->insert(b->id());
                }
            }

            else if ( auto f = item->tryAs<spicy::type::unit::item::Switch>() ) {
                for ( const auto& c : f->cases() )
                    checkBits(u, c->items(), seen_bits);
            }
        }
    }

    void operator()(spicy::type::Unit* n) final {
        if ( auto attrs = n->attributes() ) {
            if ( attrs->has("&size") && attrs->has("&max-size") )
                error(("attributes cannot be combined: &size, &max-size"), n);

            for ( const auto& a : attrs->attributes() ) {
                if ( a->tag() == "&size" || a->tag() == "&max-size" ) {
                    if ( ! a->hasValue() )
                        error(fmt("%s must provide an expression", a->tag()), n);
                    else {
                        auto v = visitor::PreOrder();
                        for ( auto i : visitor::range(v, a->value(), {}) )
                            if ( const auto& name = i->tryAs<hilti::expression::Name>();
                                 name && name->id().str() == "self" ) {
                                error(fmt("%s expression cannot use 'self' since it is only available after "
                                          "parsing of "
                                          "unit has started",
                                          a->tag()),
                                      n);
                                break;
                            }
                    }
                }

                else if ( a->tag() == "&requires" ) {
                    auto e = a->valueAsExpression();
                    if ( ! e )
                        error(e.error(), n);
                    else {
                        if ( ! hilti::type::same((*e)->type()->type(), builder()->typeBool()) )
                            error(fmt("&requires expression must be of type bool, but is of type %s ", *(*e)->type()),
                                  n);
                    }
                }
                else if ( a->tag() == "&byte-order" ) {
                    auto e = a->valueAsExpression();
                    if ( ! e )
                        error(e.error(), n);
                    else {
                        if ( ! isEnumType((*e)->type(), "spicy::ByteOrder") )
                            error(fmt("&byte-order expression must be of spicy::ByteOrder, but is of type %s ",
                                      *(*e)->type()),
                                  n);
                    }
                }
                else if ( a->tag() == "&convert" ) {
                    if ( ! a->hasValue() )
                        error("&convert must provide an expression", n);
                }
                else
                    error(fmt("attribute %s not supported for unit types", a->tag()), n);
            }
        }

        if ( auto contexts = n->propertyItems("%context"); contexts.size() > 1 )
            error("unit cannot have more than one %context", n);

        if ( const auto& type_id = n->typeID() ) {
            const auto& type_name = type_id.local();
            for ( const auto& item : n->items() )
                if ( auto field = item->tryAs<spicy::type::unit::item::Field>(); field && field->id() == type_name )
                    error(fmt("field name '%s' cannot have name identical to owning unit '%s'", field->id(), type_id),
                          n);
        }

        if ( n->propertyItem("%synchronize-at") && n->propertyItem("%synchronize-after") )
            error("unit cannot specify both %synchronize-at and %synchronize-after", n);

        for ( auto* p : n->parameters() ) {
            if ( p->kind() == hilti::parameter::Kind::InOut ) {
                auto t = p->type()->type();
                if ( ! (t->isReferenceType() || t->isA<type::Unit>()) )
                    error("type of inout parameter must be a reference or a unit", p);
            }
        }

        // Ensure that the items of anonymous bitfields do not lead to ambiguities.
        std::set<ID> seen_bits;
        checkBits(*n, n->items(), &seen_bits);
    }

    void operator()(hilti::operator_::value_reference::Equal* n) final {
        if ( auto ref = n->op0()->type()->type()->tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType()->type()->isA<type::Unit>() )
            error("units cannot be compared with ==", n);
    }

    void operator()(hilti::operator_::value_reference::Unequal* n) final {
        if ( auto ref = n->op0()->type()->type()->tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType()->type()->isA<type::Unit>() )
            error("units cannot be compared with !=", n);
    }

    void operator()(hilti::operator_::strong_reference::Equal* n) final {
        if ( auto ref = n->op0()->type()->type()->tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType()->type()->isA<type::Unit>() )
            error("units cannot be compared with ==", n);
    }

    void operator()(hilti::operator_::strong_reference::Unequal* n) final {
        if ( auto ref = n->op0()->type()->type()->tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType()->type()->isA<type::Unit>() )
            error("units cannot be compared with !=", n);
    }

    void operator()(spicy::type::unit::item::Field* n) final {
        const auto count_attr = n->attributes()->find("&count");
        const auto repeat = n->repeatCount();

        if ( n->isSkip() ) {
            if ( ! n->sinks().empty() )
                error("skip field cannot have sinks attached", n);
        }

        if ( count_attr && (repeat && ! repeat->type()->type()->isA<hilti::type::Null>()) )
            error("cannot have both `[..]` and &count", n);

        if ( n->attributes()->has("&convert") && n->attributes()->has("&chunked") )
            hilti::logger().deprecated(
                "usage of &convert on &chunked field is ill-defined and deprecated; support will be "
                "removed in future versions",
                n);

        if ( n->sinks().size() && ! n->parseType()->type()->isA<hilti::type::Bytes>() )
            error("only a bytes field can have sinks attached", n);

        if ( const auto& c = n->ctor() ) {
            // Check that constants are of a supported type.
            if ( ! supportsLiterals(c->type()) )
                error(fmt("not a parseable constant (%s)", *c), n);
        }

        else {
            if ( n->originalType()->type()->isA<hilti::type::RegExp>() ) {
                error("need regexp constant for parsing a field", n);
                return;
            }

            if ( ! n->item() ) {
                if ( auto rc = isParseableType(n->parseType(), n); ! rc ) {
                    error(rc.error(), n);
                    return;
                }
            }
        }

        // Check for attributes which can be used at most once.
        if ( n->attributes() ) {
            std::unordered_map<std::string, size_t> attrs;
            for ( const auto& a : n->attributes()->attributes() )
                attrs[a->tag()] += 1;

            for ( const auto& [a, count] : attrs ) {
                if ( count <= 1 )
                    continue;

                if ( a == "&convert" || a == "&size" || a == "&max-size" || a == "&parse-at" || a == "&parse-from" ||
                     a == "&type" || a == "&until" || a == "&until-including" || a == "&while" )
                    error(fmt("'%s' can be used at most once", a), n);
            }
        }

        if ( auto t = n->itemType()->type()->tryAs<hilti::type::Bitfield>() ) {
            for ( const auto& b : t->bits() ) {
                if ( b->attributes()->has("&bit-order") )
                    hilti::logger().deprecated(fmt("&bit-order on bitfield item '%s' has no effect and is deprecated",
                                                   b->id()),
                                               b->meta().location());
            }
        }
    }

    void operator()(spicy::type::unit::item::UnresolvedField* n) final {
        if ( auto id = n->unresolvedID() )
            error(fmt("unknown ID '%s'", id), n, node::ErrorPriority::High);
        else
            // I don't think this can actually happen ...
            error("unit field left unresolved", n);
    }

    void operator()(spicy::type::unit::item::Switch* n) final {
        if ( n->cases().empty() ) {
            error("switch without cases", n);
            return;
        }

        int defaults = 0;
        std::vector<std::string> seen_exprs;
        std::vector<spicy::type::unit::item::Field*> seen_fields;

        for ( const auto& c : n->cases() ) {
            if ( c->items().empty() )
                error("switch case without any item", n);

            if ( c->isDefault() )
                ++defaults;

            if ( n->expression() && ! c->isDefault() && c->expressions().empty() ) {
                error("case without expression", n);
                break;
            }

            if ( ! n->expression() && c->expressions().size() ) {
                error("case does not expect expression", n);
                break;
            }

            for ( const auto& e : c->expressions() ) {
                for ( const auto& x : seen_exprs ) {
                    if ( e->print() == x ) {
                        error("duplicate case", n);
                        break;
                    }
                }

                seen_exprs.emplace_back(e->print());
            }

            for ( const auto& i : c->items() ) {
                if ( auto f = i->tryAs<spicy::type::unit::item::Field>() ) {
                    for ( const auto& x : seen_fields ) {
                        if ( f->id() == x->id() &&
                             (! hilti::type::sameExceptForConstness(f->itemType(), x->itemType())) ) {
                            error(fmt("field '%s' defined multiple times with different types", f->id()), n);
                            break;
                        }
                    }

                    if ( f->attributes()->find("&synchronize") )
                        error(fmt("unit switch branches cannot be &synchronize"), n);

                    seen_fields.emplace_back(f);
                }
            }
        }

        if ( defaults > 1 )
            error("more than one default case", n);

        if ( const auto& attrs = n->attributes() ) {
            for ( const auto& attr : attrs->attributes() ) {
                const auto& tag = attr->tag();

                if ( tag != "&size" && tag != "&parse-at" && tag != "&parse-from" )
                    error(fmt("attribute '%s' is not supported here", tag), n);
            }
        }
    }

    void operator()(spicy::type::unit::item::Variable* n) final {
        if ( auto attrs = n->attributes() ) {
            for ( const auto& attr : attrs->attributes() ) {
                const auto& tag = attr->tag();
                if ( tag != "&optional" )
                    error(fmt("attribute '%s' not supported for unit variables", tag), n);
            }
        }

        if ( n->itemType()->type()->isA<type::Sink>() )
            error(
                "cannot use type 'sink' for unit variables; use either a 'sink' item or a reference to a sink "
                "('sink&')",
                n);
    }

    void operator()(spicy::declaration::UnitHook* n) final {
        if ( auto t = builder()->context()->lookup(n->hook()->unitTypeIndex()) ) {
            auto ut = t->as<type::Unit>();
            checkHook(ut, n->hook(), ut->isPublic(), true, n);
        }
        else
            error("unknown unit type", n);
    }

    void checkHook(const type::Unit* unit, const declaration::Hook* hook, bool is_public, bool is_external, Node* n) {
        // Note: We can't use any of the unit.isX() methods here that depend
        // on unit.isPublic() being set correctly, as they might not have
        // happened yet.

        auto params = hook->ftype()->parameters();
        const auto& location = hook->meta().location();

        if ( ! hook->ftype()->result()->type()->isA<hilti::type::Void>() && hook->id().local().str() != "0x25_print" )
            error("hook cannot have a return value", n, location);

        if ( hook->id().namespace_() && ! is_external )
            error("hook ID cannot be scoped", n, location);

        auto id = hook->id().local().str();
        bool needs_sink_support = false;

        if ( id.find('.') != std::string::npos )
            error("cannot use paths in hooks; trigger on the top-level field instead", n, location);

        else if ( hilti::util::startsWith(id, "0x25_") ) {
            auto id_readable = hilti::util::replace(hook->id().local().str(), "0x25_", "%");

            if ( id == "0x25_init" || id == "0x25_done" || id == "0x25_print" || id == "0x25_finally" ||
                 id == "0x25_rejected" || id == "0x25_confirmed" || id == "0x25_synced" ) {
                if ( params.size() != 0 )
                    error(fmt("hook '%s' does not take any parameters", id_readable), n, location);
            }

            else if ( id == "0x25_error" ) {
                if ( params.size() != 1 || ! hilti::type::same(params[0]->type()->type(), builder()->typeString()) )
                    error("signature for hook must be: %error or %error(err: string)", n, location);
            }

            else if ( id == "0x25_gap" ) {
                needs_sink_support = true;
                if ( params.size() != 2 ||
                     ! hilti::type::same(params[0]->type()->type(), builder()->typeUnsignedInteger(64)) ||
                     ! hilti::type::same(params[1]->type()->type(), builder()->typeUnsignedInteger(64)) )
                    error("signature for hook must be: %gap(seq: uint64, len: uint64)", n, location);
            }

            else if ( id == "0x25_overlap" ) {
                needs_sink_support = true;
                if ( params.size() != 3 ||
                     ! hilti::type::same(params[0]->type()->type(), builder()->typeUnsignedInteger(64)) ||
                     ! hilti::type::same(params[1]->type()->type(), builder()->typeBytes()) ||
                     ! hilti::type::same(params[2]->type()->type(), builder()->typeBytes()) )
                    error("signature for hook must be: %overlap(seq: uint64, old: bytes, new_: bytes)", n, location);
            }

            else if ( id == "0x25_skipped" ) {
                needs_sink_support = true;
                if ( params.size() != 1 ||
                     ! hilti::type::same(params[0]->type()->type(), builder()->typeUnsignedInteger(64)) )
                    error("signature for hook must be: %skipped(seq: uint64)", n, location);
            }

            else if ( id == "0x25_undelivered" ) {
                needs_sink_support = true;
                if ( params.size() != 2 ||
                     ! hilti::type::same(params[0]->type()->type(), builder()->typeUnsignedInteger(64)) ||
                     ! hilti::type::same(params[1]->type()->type(), builder()->typeBytes()) )
                    error("signature for hook must be: %undelivered(seq: uint64, data: bytes)", n, location);
            }

            else
                error(fmt("unknown hook '%s'", id_readable), n, location);

            if ( needs_sink_support && ! is_public ) // don't use supportsSink() here, see above
                error(fmt("cannot use hook '%s', unit type does not support sinks because it is not public",
                          id_readable),
                      n, location);
        }
        else {
            if ( auto i = unit->itemByName(ID(id)); ! i )
                error(fmt("no field '%s' in unit type", id), n, location);
        }
    }

    void operator()(operator_::sink::ConnectMIMETypeBytes* n) final {
        if ( auto x = n->op0()->type()->type()->tryAs<type::Unit>() ) {
            if ( x->parameters().size() )
                error("unit types with parameters cannot be connected through MIME type", n);
        }
    }

    void operator()(operator_::sink::ConnectMIMETypeString* n) final {
        if ( auto x = n->op0()->type()->type()->tryAs<type::Unit>() ) {
            if ( x->parameters().size() )
                error("unit types with parameters cannot be connected through MIME type", n);
        }
    }

    void operator()(operator_::unit::ConnectFilter* n) final {
        if ( const auto& y = methodArgument(*n, 0)
                                 ->type()
                                 ->type()
                                 ->as<hilti::type::StrongReference>()
                                 ->dereferencedType()
                                 ->type()
                                 ->as<type::Unit>();
             ! y->isFilter() )
            error("unit type cannot be a filter, %filter missing", n);
    }

    void operator()(operator_::unit::ContextConst* n) final {
        if ( auto x = n->op0()->type()->type()->tryAs<type::Unit>(); x && ! x->contextType() )
            error("context() used with a unit which did not declare %context", n);
    }

    void operator()(operator_::unit::ContextNonConst* n) final {
        if ( auto x = n->op0()->type()->type()->tryAs<type::Unit>(); x && ! x->contextType() )
            error("context() used with a unit which did not declare %context", n);
    }

    void operator()(operator_::unit::Forward* n) final {
        if ( auto x = n->op0()->type()->type()->tryAs<type::Unit>(); x && ! x->isFilter() )
            error("unit type cannot be a filter, %filter missing", n);
    }

    void operator()(operator_::unit::ForwardEod* n) final {
        if ( auto x = n->op0()->type()->type()->tryAs<type::Unit>(); x && ! x->isFilter() )
            error("unit type cannot be a filter, %filter missing", n);
    }
};

} // anonymous namespace

void detail::validator::validatePre(Builder* builder, hilti::ASTRoot* root) {
    hilti::util::timing::Collector _("spicy/compiler/ast/validator");
    visitor::visit(VisitorPre(builder), root, ".spicy");
    (*hilti::plugin::registry().hiltiPlugin().ast_validate_pre)(builder, root);
}

void detail::validator::validatePost(Builder* builder, hilti::ASTRoot* root) {
    hilti::util::timing::Collector _("spicy/compiler/ast/validator");
    visitor::visit(VisitorPost(builder), root, ".spicy");
    (*hilti::plugin::registry().hiltiPlugin().ast_validate_post)(builder, root);
}
