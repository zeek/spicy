// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <unordered_set>

#include <spicy/rt/mime.h>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/attribute.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/node.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/regexp.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/validator.h>

#include <spicy/ast/attribute.h>
#include <spicy/ast/builder/builder.h>
#include <spicy/ast/forward.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/validator.h>

using namespace spicy;
using hilti::util::fmt;

namespace {
/**
 * A mapping of node tags to any attributes that node allows. When a new
 * attribute is added, this map must be updated to accept that attribute on any
 * nodes it applies to.
 *
 * This also includes many types that cannot themselves contain attributes. Those
 * types ensure that they can be within a field with the provided attributes.
 */
std::unordered_map<node::Tag, std::unordered_set<hilti::attribute::Kind>> allowed_attributes{
    {hilti::node::tag::declaration::Hook,
     {attribute::kind::Foreach, attribute::kind::Error, attribute::kind::Debug, attribute::kind::Priority}},
    {hilti::node::tag::declaration::Parameter, {attribute::kind::CxxAnyAsPtr}},
    {hilti::node::tag::declaration::Type, {attribute::kind::Cxxname, attribute::kind::BitOrder}},
    {hilti::node::tag::Function, {attribute::kind::Cxxname, attribute::kind::Priority, attribute::kind::Debug}},
    {hilti::node::tag::type::Enum, {attribute::kind::Cxxname}},
    {hilti::node::tag::type::Unit,
     {attribute::kind::ByteOrder, attribute::kind::Convert, attribute::kind::Size, attribute::kind::MaxSize,
      attribute::kind::Requires}},
    {hilti::node::tag::type::unit::item::Variable, {hilti::attribute::kind::AlwaysEmit, attribute::kind::Optional}},
    {hilti::node::tag::type::unit::item::Field,
     {hilti::attribute::kind::AlwaysEmit,
      attribute::kind::Count,
      attribute::kind::Convert,
      attribute::kind::Chunked,
      attribute::kind::Synchronize,
      attribute::kind::Size,
      attribute::kind::ParseAt,
      attribute::kind::MaxSize,
      attribute::kind::ParseFrom,
      attribute::kind::Type,
      attribute::kind::Until,
      attribute::kind::UntilIncluding,
      attribute::kind::While,
      attribute::kind::IPv4,
      attribute::kind::IPv6,
      attribute::kind::Eod,
      attribute::kind::ByteOrder,
      attribute::kind::BitOrder,
      attribute::kind::Requires,
      attribute::kind::Try,
      attribute::kind::Nosub,
      attribute::kind::Default}},
    {hilti::node::tag::type::unit::item::Block,
     {attribute::kind::Size, attribute::kind::ParseAt, attribute::kind::ParseFrom}},
    {hilti::node::tag::type::unit::item::Switch,
     {attribute::kind::Size, attribute::kind::ParseAt, attribute::kind::ParseFrom}},
    {hilti::node::tag::type::unit::item::Property, {attribute::kind::Originator, attribute::kind::Responder}},

    // The following apply only to types within a field
    {hilti::node::tag::type::Address, {attribute::kind::IPv4, attribute::kind::IPv6, attribute::kind::ByteOrder}},
    {hilti::node::tag::type::Bitfield, {attribute::kind::ByteOrder, attribute::kind::BitOrder}},
    {hilti::node::tag::type::Bytes,
     {attribute::kind::Eod, attribute::kind::Until, attribute::kind::UntilIncluding, attribute::kind::Chunked,
      attribute::kind::Nosub}},
    {hilti::node::tag::type::Real, {attribute::kind::Type, attribute::kind::ByteOrder}},
    {hilti::node::tag::type::RegExp, {attribute::kind::Nosub}},
    {hilti::node::tag::type::SignedInteger, {attribute::kind::ByteOrder, attribute::kind::BitOrder}},
    {hilti::node::tag::type::Unit, {attribute::kind::ParseAt}},
    {hilti::node::tag::type::UnsignedInteger, {attribute::kind::ByteOrder, attribute::kind::BitOrder}},
    {hilti::node::tag::type::Vector,
     {attribute::kind::UntilIncluding, attribute::kind::While, attribute::kind::Until, attribute::kind::Count,
      attribute::kind::Eod}},
};

std::unordered_set<hilti::attribute::Kind> allowed_attributes_for_any_field =
    {hilti::attribute::kind::AlwaysEmit, attribute::kind::Synchronize, attribute::kind::Convert,
     attribute::kind::Requires,          attribute::kind::Default,     attribute::kind::Size,
     attribute::kind::MaxSize,           attribute::kind::Try,         attribute::kind::ParseAt,
     attribute::kind::ParseFrom};

bool isEnumType(QualifiedType* t, const char* expected_id) {
    return t->type()->typeID() && t->type()->typeID() == ID(expected_id);
}

// Helper to validate that a type supports parsing from literals.
bool supportsLiterals(QualifiedType* t) {
    return t->type()->isA<hilti::type::Bytes>() || t->type()->isA<hilti::type::RegExp>() ||
           t->type()->isA<hilti::type::SignedInteger>() || t->type()->isA<hilti::type::UnsignedInteger>() ||
           t->type()->isA<hilti::type::Bitfield>();
}

// Helper to make sure a field's attributes are consistent. This is type-independent.
hilti::Result<hilti::Nothing> checkFieldAttributes(type::unit::item::Field* f) {
    // Can't combine ipv4 and ipv6
    auto* v4 = f->attributes()->find(attribute::kind::IPv4);
    auto* v6 = f->attributes()->find(attribute::kind::IPv6);

    if ( v4 && v6 )
        return hilti::result::Error("field cannot have both &ipv4 and &ipv6 attributes");

    // Termination conditions cannot be combined in certain ways
    auto* eod_attr = f->attributes()->find(attribute::kind::Eod);
    auto* until_attr = f->attributes()->find(attribute::kind::Until);
    auto* until_including_attr = f->attributes()->find(attribute::kind::UntilIncluding);
    auto* parse_at_attr = f->attributes()->find(attribute::kind::ParseAt);
    auto* parse_from_attr = f->attributes()->find(attribute::kind::ParseFrom);
    auto* size_attr = f->attributes()->find(attribute::kind::Size);
    auto* max_size_attr = f->attributes()->find(attribute::kind::MaxSize);

    std::vector<hilti::attribute::Kind> start_attrs_present;
    for ( const auto& i : {parse_from_attr, parse_at_attr} ) {
        if ( i )
            start_attrs_present.emplace_back(i->kind());
    }

    std::vector<hilti::attribute::Kind> end_attrs_present;
    for ( const auto& i : {eod_attr, until_attr, until_including_attr} ) {
        if ( i )
            end_attrs_present.emplace_back(i->kind());
    }

    std::vector<hilti::attribute::Kind> size_attrs_present;
    for ( const auto& i : {size_attr, max_size_attr} ) {
        if ( i )
            size_attrs_present.emplace_back(i->kind());
    }

    for ( const auto* attrs_present : {&start_attrs_present, &size_attrs_present} ) {
        if ( attrs_present->size() > 1 ) {
            // Transform attribute kinds into strings for the diagnostic
            std::vector<std::string> attr_strings(attrs_present->size());
            std::ranges::transform(*attrs_present, attr_strings.begin(),
                                   [](const hilti::attribute::Kind& kind) { return to_string(kind); });
            return hilti::result::Error(
                fmt("attributes cannot be combined: %s", hilti::util::join(attr_strings, ", ")));
        }
    }

    if ( until_attr && until_including_attr )
        return hilti::result::Error(fmt("attributes cannot be combined: &until, &until-including"));

    return hilti::Nothing();
}

// Helper to validate that a type is parseable.
hilti::Result<hilti::Nothing> isParseableType(QualifiedType* pt, type::unit::item::Field* f) {
    if ( pt->type()->isA<hilti::type::Bitfield>() )
        return hilti::Nothing();

    if ( pt->type()->isA<hilti::type::Bytes>() ) {
        if ( f->ctor() )
            return hilti::Nothing();

        const auto required_one_of = {attribute::kind::Eod,  attribute::kind::ParseAt, attribute::kind::ParseFrom,
                                      attribute::kind::Size, attribute::kind::Until,   attribute::kind::UntilIncluding};

        // Make sure we have one of the required attributes
        for ( const auto& attr : required_one_of ) {
            if ( f->attributes()->find(attr) )
                return hilti::Nothing();
        }

        std::vector<std::string> attr_strings(required_one_of.size());
        std::ranges::transform(required_one_of, attr_strings.begin(),
                               [](const hilti::attribute::Kind& kind) { return to_string(kind); });
        return hilti::result::Error(fmt("bytes field requires one of %s", hilti::util::join(attr_strings, ", ")));
    }

    if ( pt->type()->isA<hilti::type::Address>() ) {
        auto* v4 = f->attributes()->find(attribute::kind::IPv4);
        auto* v6 = f->attributes()->find(attribute::kind::IPv6);

        if ( ! (v4 || v6) )
            return hilti::result::Error("address field must come with either &ipv4 or &ipv6 attribute");

        return hilti::Nothing();
    }

    if ( pt->type()->isA<hilti::type::Real>() ) {
        auto* type = f->attributes()->find(attribute::kind::Type);

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

    if ( pt->type()->isA<hilti::type::Void>() )
        // Already validated that Void only has allowed attributes
        return hilti::Nothing();

    // A vector can contain a sub-item
    if ( f->item() ) {
        return hilti::Nothing();
    }
    // But a vector cannot contain a type; this is enforced at parse time
    else if ( pt->type()->isA<hilti::type::Vector>() ) {
        hilti::logger().internalError("vectors must only have sub-item, not an inner type");
    }

    return hilti::result::Error(fmt("not a parseable type (%s)", *pt));
}

Expression* methodArgument(const hilti::expression::ResolvedOperator& o, size_t i) {
    auto* ops = o.op2();

    // If the argument list was the result of a coercion unpack its result.
    if ( auto* coerced = ops->tryAs<hilti::expression::Coerced>() )
        ops = coerced->expression();

    if ( auto* ctor_ = ops->tryAs<hilti::expression::Ctor>() ) {
        auto* ctor = ctor_->ctor();

        // If the argument was the result of a coercion unpack its result.
        if ( auto* x = ctor->tryAs<hilti::ctor::Coerced>() )
            ctor = x->coercedCtor();

        if ( auto* args = ctor->tryAs<hilti::ctor::Tuple>(); args && i < args->value().size() )
            return args->value()[i];
    }

    hilti::util::cannotBeReached();
}

struct VisitorPre : visitor::PreOrder, hilti::validator::VisitorMixIn {
    using hilti::validator::VisitorMixIn::VisitorMixIn;
};

struct VisitorPost : visitor::PreOrder, hilti::validator::VisitorMixIn {
    // Ensures that the node represented by tag is allowed to have all of the
    // provided attributes. This does not use any context, if more information
    // is needed, then do the check elsewhere.
    void checkNodeAttributes(Node* n, AttributeSet* attributes, const std::string_view& where) {
        if ( ! attributes )
            return;

        auto it = allowed_attributes.find(n->nodeTag());

        if ( it == allowed_attributes.end() ) {
            if ( ! attributes->attributes().empty() )
                error(hilti::util::fmt("No attributes expected in %s", where), attributes);

            return;
        }

        auto allowed = it->second;

        for ( const auto& attr : attributes->attributes() )
            if ( ! allowed.contains(attr->kind()) )
                error(hilti::util::fmt("invalid attribute '%s' in %s", to_string(attr->kind()), where), attr);
    }

    // Ensures that the type represented by typeTag can be within a field with
    // the provided attributes. This is necessary since most attributes will apply
    // to the field but not its type, so this gives a bit more context-sensitive
    // validation for a common case.
    void validateFieldTypeAttributes(node::Tag type_tag, AttributeSet* attributes, const std::string_view& clazz) {
        if ( ! attributes )
            return;

        std::unordered_set<hilti::attribute::Kind> type_specific_attrs = {};
        auto it = allowed_attributes.find(type_tag);
        if ( it != allowed_attributes.end() )
            type_specific_attrs = it->second;

        for ( const auto& attr : attributes->attributes() ) {
            if ( ! allowed_attributes_for_any_field.contains(attr->kind()) &&
                 ! type_specific_attrs.contains(attr->kind()) )
                error(hilti::util::fmt("invalid attribute '%s' for field with type '%s'", to_string(attr->kind()),
                                       clazz),
                      attr);
        }
    }

    using hilti::validator::VisitorMixIn::VisitorMixIn;

    template<typename GlobalOrLocalVariable>
    void checkVariable(const GlobalOrLocalVariable& n) {
        // A variable initialized from a struct initializer always needs an explicit type.
        const bool is_typed = ! n->type()->type()->typeID().empty();
        if ( is_typed )
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

    void operator()(hilti::expression::Name* n) final {
        if ( n->id() == ID(HILTI_INTERNAL_ID("dd")) ) {
            if ( auto* hook = n->parent<spicy::declaration::Hook>();
                 hook && hook->hookType() == declaration::hook::Type::ForEach )
                // $$ in "foreach" ok is ok.
                return;

            if ( auto* attr = n->parent<hilti::Attribute>() ) {
                const auto& kind = attr->kind();
                if ( kind == attribute::kind::Until || kind == attribute::kind::UntilIncluding ||
                     kind == attribute::kind::While )
                    // $$ inside these attributes is ok
                    return;
            }

            if ( auto* field = n->parent<spicy::type::unit::item::Field>() ) {
                if ( field->isContainer() && field->isTransient() )
                    error("cannot use $$ with container inside transient field", n);
            }
        }
    }

    void operator()(hilti::declaration::Module* n) final {
        if ( auto* version = n->moduleProperty("%spicy-version") ) {
            if ( ! version->expression() ) {
                error("%spicy-version requires an argument", n);
                return;
            }

            bool ok = false;
            if ( auto* c = version->expression()->tryAs<hilti::expression::Ctor>() ) {
                if ( auto* s = c->ctor()->tryAs<hilti::ctor::String>() ) {
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
                        auto version = (major * 10000) + (minor * 100) + patch;
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
        if ( auto* x = n->parent<declaration::Hook>(); ! (x && x->hookType() == declaration::hook::Type::ForEach) )
            error("'stop' can only be used inside a 'foreach' hook", n);
    }

    void operator()(hilti::declaration::Property* n) final {
        if ( n->id().str() == "%spicy-version" )
            ; // Nothing; handled in validator for `hilti::Module`.

        else if ( n->id().str() == "%skip-implementation" )
            ; // Nothing; just passed on to HILTI

        else if ( n->id().str() == "%byte-order" ) {
            if ( auto* e = n->expression(); ! e ) {
                error("%byte-order requires an argument", n);
                return;
            }
        }

        else if ( n->id().str() == "%cxx-include" ) {
            if ( auto* e = n->expression(); ! e ) {
                error("%cxx-include requires an argument", n);
                return;
            }
        }

        else if ( const auto& prop = n->id().str(); prop == "%skip" || prop == "%skip-post" || prop == "%skip-pre" ) {
            if ( const auto& e = n->expression(); ! e ) {
                error(fmt("%s requires an argument", prop), n);
                return;
            }

            else if ( auto* t = e->type();
                      ! t->type()->isA<hilti::type::RegExp>() && ! t->type()->isA<hilti::type::Null>() ) {
                error(fmt("%s requires a regexp as its argument", prop), n);
                return;
            }
        }

        else if ( const auto& prop = n->id().str(); prop == "%synchronize-at" || prop == "%synchronize-after" ) {
            auto* e = n->expression();
            if ( ! e ) {
                error(fmt("%s requires an argument", prop), n);
                return;
            }

            if ( ! e->isA<hilti::expression::Ctor>() ) {
                error(fmt("%s requires a constant as its argument", prop), n);
                return;
            }

            if ( ! supportsLiterals(e->type()) ) {
                error(fmt("%s requires a constant of a parseable type as its argument", prop), n);
                return;
            }
        }

        else if ( n->id().str() == "%sync-advance-block-size" ) {
            if ( auto* e = n->expression(); ! e || ! e->type()->type()->isA<hilti::type::UnsignedInteger>() ) {
                error("%sync-advance-block-size requires an argument of type uint64", n);
                return;
            }
        }

        else
            error(fmt("unknown property '%s'", n->id().str()), n);
    }

    void operator()(hilti::declaration::Type* n) final {
        checkNodeAttributes(n, n->attributes(), "type declaration");

        if ( n->linkage() == hilti::declaration::Linkage::Public && n->type()->alias() ) {
            if ( auto* resolved = n->type()->alias()->resolvedDeclaration();
                 resolved && resolved->linkage() != hilti::declaration::Linkage::Public )
                error("public unit alias cannot refer to a non-public type", n);
        }
    }

    void operator()(spicy::type::unit::item::Property* n) final {
        checkNodeAttributes(n, n->attributes(), "unit property");

        if ( n->id().str() == "%random-access" ) {
            if ( n->expression() )
                error("%random-access does not accept an argument", n);

            deprecated("%random-access is no longer needed and deprecated", n->meta().location());
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

            if ( auto* x = n->expression()->tryAs<hilti::expression::Ctor>() ) {
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
            if ( auto* e = n->expression(); ! e )
                error("%context requires an argument", n);
            else if ( ! e->type()->type()->isA<hilti::type::Type_>() )
                error("%context requires a type", n);

            auto* decl = n->parent<hilti::declaration::Type>();
            if ( decl && decl->linkage() != hilti::declaration::Linkage::Public )
                error("only public units can have %context", n);
        }

        else if ( const auto& prop = n->id().str(); prop == "%skip" || prop == "%skip-post" || prop == "%skip-pre" ) {
            if ( const auto& e = n->expression(); ! e ) {
                error(fmt("%s requires an argument", prop), n);
                return;
            }

            else if ( auto* t = e->type();
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
            auto* e = n->expression();
            if ( ! e ) {
                error(fmt("%s requires an argument", prop), n);
                return;
            }

            if ( ! e->isA<hilti::expression::Ctor>() ) {
                error(fmt("%s requires a constant as its argument", prop), n);
                return;
            }

            if ( ! supportsLiterals(e->type()) ) {
                error(fmt("%s requires a constant of a parseable type as its argument", prop), n);
                return;
            }
        }

        else if ( n->id().str() == "%sync-advance-block-size" ) {
            if ( auto* e = n->expression(); ! e || ! e->type()->type()->isA<hilti::type::UnsignedInteger>() ) {
                error("%sync-advance-block-size requires an argument of type uint64", n);
                return;
            }
        }

        else
            error(fmt("unknown property '%s'", n->id().str()), n);
    }

    void operator()(spicy::declaration::Hook* n) final {
        checkNodeAttributes(n, n->attributes(), "hook declaration");

        if ( auto* field = n->parent<spicy::type::unit::item::Field>();
             field && n->attributes()->find(attribute::kind::Foreach) && ! field->isContainer() )
            error("'foreach' can only be used with containers", n);

        if ( n->attributes()->find(attribute::kind::Foreach) && n->attributes()->find(attribute::kind::Error) )
            error("hook cannot have both 'foreach' and '%error'", n);

        // Ensure we only have one foreach or one %error
        int foreach_count = 0;
        int err_count = 0;
        if ( auto* attrs = n->attributes() ) {
            for ( const auto& attr : attrs->attributes() ) {
                if ( attr->kind() == attribute::kind::Foreach )
                    foreach_count++;
                else if ( attr->kind() == attribute::kind::Error )
                    err_count++;
            }
        }

        if ( foreach_count > 1 )
            error("hook can only have one 'foreach'", n);

        if ( err_count > 1 )
            error("hook can only have one '%error'", n);
    }

    void operator()(spicy::type::unit::item::UnitHook* n) final {
        auto* decl = n->parent<hilti::declaration::Type>();
        if ( ! decl || ! decl->type()->type()->isA<type::Unit>() )
            return;

        auto* unit = n->parent<type::Unit>(); // note that this can be a different unit than in the decl, when nested
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

        if ( hilti::attribute::isOneOf(n->kind(),
                                       {attribute::kind::Size, attribute::kind::MaxSize, attribute::kind::ByteOrder,
                                        attribute::kind::Convert, attribute::kind::Until, attribute::kind::While,
                                        attribute::kind::UntilIncluding, attribute::kind::ParseFrom,
                                        attribute::kind::ParseAt, attribute::kind::Requires}) &&
             ! n->hasValue() )
            error(fmt("%s must provide an expression", to_string(n->kind())), n);

        else if ( n->kind() == attribute::kind::Default ) {
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

        else if ( n->kind() == attribute::kind::Eod ) {
            if ( auto* f = get_attr_field(n) ) {
                if ( ! (f->parseType()->type()->isA<hilti::type::Bytes>() ||
                        f->parseType()->type()->isA<hilti::type::Vector>()) ||
                     f->ctor() )
                    error("&eod is only valid for bytes and vector fields", n);
            }
        }

        else if ( hilti::attribute::isOneOf(n->kind(), {attribute::kind::While, attribute::kind::UntilIncluding,
                                                        attribute::kind::Until}) ) {
            if ( auto* f = get_attr_field(n) ) {
                if ( ! (f->parseType()->type()->isA<hilti::type::Bytes>() ||
                        f->parseType()->type()->isA<hilti::type::Vector>()) )
                    error(fmt("%s is only valid for fields of type bytes or vector", to_string(n->kind())), n);
            }
        }

        else if ( n->kind() == attribute::kind::Chunked ) {
            if ( auto* f = get_attr_field(n) ) {
                if ( ! f->parseType()->type()->isA<hilti::type::Bytes>() || f->ctor() )
                    error("&chunked is only valid for bytes fields", n);
                else if ( n->hasValue() )
                    error("&chunked cannot have an expression", n);
                else if ( ! (f->attributes()->find(attribute::kind::Eod) ||
                             f->attributes()->find(attribute::kind::Size) ||
                             f->attributes()->find(attribute::kind::Until) ||
                             f->attributes()->find(attribute::kind::UntilIncluding)) )
                    error("&chunked must be used with &eod, &until, &until-including or &size", n);
            }
        }

        else if ( n->kind() == attribute::kind::Transient )
            error("&transient is no longer available, use an anonymous field instead to achieve the same effect", n);

        else if ( hilti::attribute::isOneOf(n->kind(), {attribute::kind::ParseFrom, attribute::kind::ParseAt}) ) {
            if ( get_attr_field(n) ) {
                if ( auto e = n->valueAsExpression();
                     e && ! hilti::type::same((*e)->type()->type(), builder.typeStreamIterator()) &&
                     ! hilti::type::same((*e)->type()->type(), builder.typeBytes()) )
                    error(fmt("%s must have an expression of type either bytes or iterator<stream>",
                              to_string(n->kind())),
                          n);
            }
        }

        else if ( n->kind() == attribute::kind::Requires ) {
            if ( ! n->hasValue() )
                error("&requires must provide an expression", n);
            else {
                auto* e = *n->valueAsExpression();
                assert(e);

                if ( auto* result = e->type()->type()->tryAs<hilti::type::Result>();
                     ! result || ! result->dereferencedType()->type()->isA<hilti::type::Void>() )
                    error(fmt("&requires expression must be of type bool or result<void>, but is of type %d",
                              *e->type()),
                          n);
            }
        }
    }

    void checkBits(const spicy::type::Unit& u, const hilti::node::Set<type::unit::Item>& items,
                   std::set<ID>* seen_bits) {
        for ( const auto& item : items ) {
            if ( auto* f = item->tryAs<spicy::type::unit::item::Field>() ) {
                if ( ! f->isAnonymous() )
                    continue;

                auto* t = f->itemType()->type()->tryAs<hilti::type::Bitfield>();
                if ( ! t )
                    continue;

                for ( const auto& b : t->bits() ) {
                    if ( u.itemByName(b->id()) )
                        error(fmt("bitfield item '%s' shadows unit field", b->id()), item);

                    if ( seen_bits->contains(b->id()) )
                        error(fmt("bitfield item name '%s' appears in multiple anonymous bitfields", b->id()), item);

                    seen_bits->insert(b->id());
                }
            }

            else if ( auto* f = item->tryAs<spicy::type::unit::item::Switch>() ) {
                for ( const auto& c : f->cases() )
                    checkBits(u, {c->block()}, seen_bits);
            }

            else if ( auto* f = item->tryAs<spicy::type::unit::item::Block>() ) {
                checkBits(u, f->allItems(), seen_bits);
            }
        }
    }

    void operator()(spicy::type::Unit* n) final {
        checkNodeAttributes(n, n->attributes(), "unit type");

        if ( ! n->typeID() ) {
            error("unit types must be named", n);
            return;
        }

        if ( auto* attrs = n->attributes() ) {
            if ( attrs->find(attribute::kind::Size) && attrs->find(attribute::kind::MaxSize) )
                error(("attributes cannot be combined: &size, &max-size"), n);

            for ( const auto& a : attrs->attributes() ) {
                if ( a->kind() == attribute::kind::Size || a->kind() == attribute::kind::MaxSize ) {
                    if ( ! a->hasValue() )
                        error(fmt("%s must provide an expression", to_string(a->kind())), n);
                    else {
                        auto v = visitor::PreOrder();
                        for ( auto* i : visitor::range(v, a->value(), {}) )
                            if ( const auto& name = i->tryAs<hilti::expression::Name>();
                                 name && name->id().str() == "self" ) {
                                error(fmt("%s expression cannot use 'self' since it is only available after "
                                          "parsing of "
                                          "unit has started",
                                          to_string(a->kind())),
                                      n);
                                break;
                            }
                    }
                }

                else if ( a->kind() == attribute::kind::Requires ) {
                    auto e = a->valueAsExpression();
                    if ( ! e )
                        error(e.error(), n);
                    else {
                        if ( auto* result = (*e)->type()->type()->tryAs<hilti::type::Result>();
                             ! result || ! result->dereferencedType()->type()->isA<hilti::type::Void>() )
                            error(fmt("&requires expression must be of type bool or result<void>, but is of type %s",
                                      *(*e)->type()),
                                  n);
                    }
                }
                else if ( a->kind() == attribute::kind::ByteOrder ) {
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
                else if ( a->kind() == attribute::kind::Convert ) {
                    if ( ! a->hasValue() )
                        error("&convert must provide an expression", n);
                }
            }
        }

        if ( auto contexts = n->propertyItems("%context"); contexts.size() > 1 )
            error("unit cannot have more than one %context", n);

        const auto& type_id = n->typeID();
        const auto& type_name = type_id.local();
        for ( const auto& item : n->items() )
            if ( auto* field = item->tryAs<spicy::type::unit::item::Field>(); field && field->id() == type_name )
                error(fmt("field name '%s' cannot have name identical to owning unit '%s'", field->id(), type_id), n);

        if ( n->propertyItem("%synchronize-at") && n->propertyItem("%synchronize-after") )
            error("unit cannot specify both %synchronize-at and %synchronize-after", n);

        for ( auto* p : n->parameters() ) {
            if ( p->kind() == hilti::parameter::Kind::InOut ) {
                auto* t = p->type()->type();
                if ( ! t->isA<type::Unit>() )
                    error(fmt("unsupported type for unit parameter '%s': type of inout unit parameters must "
                              "itself be a unit; for other parameter types, use references instead of inout",
                              p->id()),
                          p);
            }
        }

        // Ensure that the items of anonymous bitfields do not lead to ambiguities.
        std::set<ID> seen_bits;
        checkBits(*n, n->items(), &seen_bits);
    }

    void operator()(hilti::operator_::value_reference::Equal* n) final {
        if ( auto* ref = n->op0()->type()->type()->tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType()->type()->isA<type::Unit>() )
            error("units cannot be compared with ==", n);
    }

    void operator()(hilti::operator_::value_reference::Unequal* n) final {
        if ( auto* ref = n->op0()->type()->type()->tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType()->type()->isA<type::Unit>() )
            error("units cannot be compared with !=", n);
    }

    void operator()(hilti::operator_::strong_reference::Equal* n) final {
        if ( auto* ref = n->op0()->type()->type()->tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType()->type()->isA<type::Unit>() )
            error("units cannot be compared with ==", n);
    }

    void operator()(hilti::operator_::strong_reference::Unequal* n) final {
        if ( auto* ref = n->op0()->type()->type()->tryAs<hilti::type::ValueReference>();
             ref && ref->dereferencedType()->type()->isA<type::Unit>() )
            error("units cannot be compared with !=", n);
    }

    void operator()(spicy::type::unit::item::Block* n) final {
        checkNodeAttributes(n, n->attributes(), "unit block");

        if ( n->condition() && ! n->condition()->type()->type()->isA<hilti::type::Bool>() )
            error("block condition must be of type bool", n);
    }

    void operator()(spicy::type::unit::item::Field* n) final {
        checkNodeAttributes(n, n->attributes(), "field");

        auto* type = n->parseType()->type();
        validateFieldTypeAttributes(type->nodeTag(), n->attributes(), type->typeClass());

        if ( n->isSkip() ) {
            if ( ! n->sinks().empty() )
                error("skip field cannot have sinks attached", n);
        }


        auto* const count_attr = n->attributes()->find(attribute::kind::Count);
        auto* const repeat = n->repeatCount();
        if ( count_attr && (repeat && ! repeat->type()->type()->isA<hilti::type::Null>()) )
            error("cannot have both '[..]' and &count", n);

        if ( count_attr )
            deprecated("&count=N is deprecated, prefer '[N]' syntax", count_attr->meta().location());

        if ( n->attributes()->find(attribute::kind::Convert) && n->attributes()->find(attribute::kind::Chunked) )
            deprecated(
                "usage of &convert on &chunked field is ill-defined and deprecated; support will be "
                "removed in future versions",
                n->meta().location());

        if ( n->sinks().size() && ! type->isA<hilti::type::Bytes>() )
            error("only a bytes field can have sinks attached", n);

        for ( auto* s : n->sinks() ) {
            auto* t = s->type();

            if ( t->type()->isReferenceType() )
                t = t->type()->dereferencedType();

            if ( t->isConstant() )
                error("sink must be writable, cannot be a constant value", s);
        }

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
            std::unordered_map<hilti::attribute::Kind, size_t> attrs;
            for ( const auto& a : n->attributes()->attributes() )
                attrs[a->kind()] += 1;

            for ( const auto& [a, count] : attrs ) {
                if ( count <= 1 )
                    continue;

                if ( hilti::attribute::isOneOf(a, {attribute::kind::Convert, attribute::kind::Size,
                                                   attribute::kind::MaxSize, attribute::kind::ParseAt,
                                                   attribute::kind::ParseFrom, attribute::kind::Type,
                                                   attribute::kind::Until, attribute::kind::UntilIncluding,
                                                   attribute::kind::While}) )
                    error(fmt("'%s' can be used at most once", to_string(a)), n);
            }
        }

        if ( auto* t = n->itemType()->type()->tryAs<hilti::type::Bitfield>() ) {
            for ( const auto& b : t->bits() ) {
                if ( b->attributes()->find(attribute::kind::BitOrder) )
                    deprecated(fmt("&bit-order on bitfield item '%s' has no effect and is deprecated", b->id()),
                               b->meta().location());
            }
        }

        if ( auto rc = checkFieldAttributes(n); ! rc )
            error(rc.error(), n);

        if ( auto* t = n->type() ) {
            if ( auto* unit = t->type()->tryAs<type::Unit>() )
                // We disable the actual type checking here because arguments
                // won't have been coerced yet. We are only interested in in
                // the number of arguments being correct, type checking will
                // happen later on the HILTI side.
                checkTypeArguments(n->arguments(), unit->parameters(), n, false, true);
        }
    }

    void operator()(spicy::type::unit::item::UnresolvedField* n) final {
        if ( auto id = n->unresolvedID() ) {
            // Re-lookup ID to see if it exists at all.
            if ( auto resolved = hilti::scope::lookupID<hilti::Declaration>(std::move(id), n, "field"); ! resolved )
                error(resolved.error(), n, node::ErrorPriority::High);

            if ( n->hasErrors() )
                // Report existing error, probably from the resolver.
                return;
        }

        // I believe we can't get here.
        hilti::logger().internalError("unit field left unresolved", n);
    }

    void operator()(spicy::type::unit::item::Switch* n) final {
        checkNodeAttributes(n, n->attributes(), "unit switch");

        if ( n->cases().empty() ) {
            error("switch without cases", n);
            return;
        }

        int defaults = 0;
        std::vector<std::string> seen_exprs;
        std::vector<spicy::type::unit::item::Field*> seen_fields;

        for ( const auto& c : n->cases() ) {
            if ( c->block()->items().empty() )
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

            for ( const auto& i : c->block()->items() ) {
                if ( auto* f = i->tryAs<spicy::type::unit::item::Field>() ) {
                    for ( const auto& x : seen_fields ) {
                        if ( f->id() == x->id() &&
                             (! hilti::type::sameExceptForConstness(f->itemType(), x->itemType())) ) {
                            error(fmt("field '%s' defined multiple times with different types", f->id()), n);
                            break;
                        }
                    }

                    if ( f->attributes()->find(attribute::kind::Synchronize) )
                        error(fmt("unit switch branches cannot be &synchronize"), n);

                    seen_fields.emplace_back(f);
                }
            }
        }

        if ( defaults > 1 )
            error("more than one default case", n);
    }

    void operator()(spicy::type::unit::item::Variable* n) final {
        checkNodeAttributes(n, n->attributes(), "unit variable");

        if ( ! n->parent()->isA<spicy::type::Unit>() )
            error("unit variables must be declared at the top-level of a unit", n);

        if ( n->itemType()->type()->isA<type::Sink>() )
            error(
                "cannot use type 'sink' for unit variables; use either a 'sink' item or a reference to a sink "
                "('sink&')",
                n);
    }

    void operator()(spicy::type::unit::item::Sink* n) final { checkNodeAttributes(n, n->attributes(), "unit sink"); }

    void operator()(spicy::declaration::UnitHook* n) final {
        if ( auto* t = builder()->context()->lookup(n->hook()->unitTypeIndex()) ) {
            auto* ut = t->as<type::Unit>();
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

            else if ( id == "0x25_sync_advance" ) {
                if ( params.size() != 1 ||
                     ! hilti::type::same(params[0]->type()->type(), builder()->typeUnsignedInteger(64)) )
                    error("signature for hook must be: %sync_advance(offset: uint64)", n, location);
            }

            else
                error(fmt("unknown hook '%s'", id_readable), n, location);

            if ( needs_sink_support && ! is_public ) // don't use supportsSink() here, see above
                error(fmt("cannot use hook '%s', unit type does not support sinks because it is not public",
                          id_readable),
                      n, location);
        }

        else if ( hook->hookType() == declaration::hook::Type::Error && ! params.empty() ) {
            if ( params.size() != 1 || ! hilti::type::same(params[0]->type()->type(), builder()->typeString()) )
                error("%error hook must only take a string parameter", n, location);
        }

        else {
            if ( auto* i = unit->itemByName(ID(id)); ! i )
                error(fmt("no field '%s' in unit type", id), n, location);
        }
    }

    void operator()(operator_::sink::ConnectMIMETypeBytes* n) final {
        if ( auto* x = n->op0()->type()->type()->tryAs<type::Unit>() ) {
            if ( x->parameters().size() )
                error("unit types with parameters cannot be connected through MIME type", n);
        }
    }

    void operator()(operator_::sink::ConnectMIMETypeString* n) final {
        if ( auto* x = n->op0()->type()->type()->tryAs<type::Unit>() ) {
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
        if ( auto* x = n->op0()->type()->type()->tryAs<type::Unit>(); x && ! x->contextType() )
            error("context() used with a unit which did not declare %context", n);
    }

    void operator()(operator_::unit::ContextNonConst* n) final {
        if ( auto* x = n->op0()->type()->type()->tryAs<type::Unit>(); x && ! x->contextType() )
            error("context() used with a unit which did not declare %context", n);
    }

    void operator()(operator_::unit::Forward* n) final {
        if ( auto* x = n->op0()->type()->type()->tryAs<type::Unit>(); x && ! x->isFilter() )
            error("unit type cannot be a filter, %filter missing", n);
    }

    void operator()(operator_::unit::ForwardEod* n) final {
        if ( auto* x = n->op0()->type()->type()->tryAs<type::Unit>(); x && ! x->isFilter() )
            error("unit type cannot be a filter, %filter missing", n);
    }

    void operator()(hilti::expression::Keyword* n) final {
        // Validate that captures are only used when we are parsing a regexp.
        // We check the original type since regexps get parsed as bytes.
        if ( n->kind() == hilti::expression::keyword::Kind::Captures ) {
            UnqualifiedType* original_type = nullptr;

            // Check type in hook bodies.
            if ( auto* hook = n->parent<declaration::Hook>() ) {
                auto idx = hook->unitFieldIndex();
                auto* field = context()->lookup(idx)->as<type::unit::item::Field>();
                original_type = field->originalType()->type();
            }

            // Captures can also appear in field attributes.
            else if ( auto* field = n->parent<type::unit::item::Field>() )
                original_type = field->originalType()->type();

            // In all other cases, or when we are not parsing a regexp raise an error.
            if ( ! original_type || ! original_type->isA<hilti::type::RegExp>() )
                error("capture groups can only be used in hooks for fields parsing regexp", n);
        }
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
