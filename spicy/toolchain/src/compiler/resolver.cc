// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ast-context.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/attribute.h>
#include <spicy/ast/builder/builder.h>
#include <spicy/ast/forward.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/resolver.h>

using namespace spicy;

namespace spicy::logging::debug {
inline const hilti::logging::DebugStream Resolver("resolver");
inline const hilti::logging::DebugStream Operator("operator");
} // namespace spicy::logging::debug

namespace {

// Copy a range of nodes into an actual vector.
template<typename T>
auto copy_vector = [](const auto& in) -> NodeVector<T> {
    NodeVector<T> out;
    for ( const auto& i : in )
        out.push_back(i);

    return out;
};

// Turns an unresolved field into a resolved field. The unresolved field passed
// in will be in an invalid state afterwards because we're moving out its
// children.
template<typename T>
auto resolveField(Builder* builder, type::unit::item::UnresolvedField* u, T t) {
    // First unlink nodes from their `UnresolvedField` parent to avoid deep-copying
    // them when adding them to the new field.
    auto arguments = copy_vector<Expression>(u->arguments());
    auto* repeat_count = u->repeatCount();
    auto* attributes = u->attributes();
    auto sinks = copy_vector<Expression>(u->sinks());
    auto* condition = u->condition();
    auto hooks = copy_vector<declaration::Hook>(u->hooks());

    u->removeChildren(0, {});

    auto field = builder->typeUnitItemField(u->fieldID(), std::move(t), u->isSkip(), std::move(arguments), repeat_count,
                                            std::move(sinks), attributes, condition, std::move(hooks), u->meta());
    assert(u->index());
    field->setIndex(*u->index());
    return field;
}

// Helper type to select which type of a unit field we are interested in.
enum class FieldType {
    DDType,    // type for $$
    ItemType,  // final type of the field's value
    ParseType, // type that the field is being parsed at
};

struct VisitorPass2 : visitor::MutatingPostOrder {
    VisitorPass2(Builder* builder, Node* root)
        : visitor::MutatingPostOrder(builder, logging::debug::Resolver), root(root) {}

    Node* root = nullptr;
    std::set<Node*> seen;

    // Sets a declaration fully qualified ID
    void setFqID(Declaration* d, ID id) {
        assert(id);
        d->setFullyQualifiedID(std::move(id));
        recordChange(d, hilti::util::fmt("set declaration's fully qualified ID to %s", d->fullyQualifiedID()));
    }

    // Helper method to compute one of several kinds of a field's types.
    QualifiedType* fieldType(const type::unit::item::Field& f, QualifiedType* type, FieldType ft, bool is_container,
                             const Meta& meta) {
        // Visitor determining a unit field type.
        struct FieldTypeVisitor : public visitor::PreOrder {
            explicit FieldTypeVisitor(Builder* builder, FieldType ft) : builder(builder), ft(ft) {}

            Builder* builder;
            FieldType ft;

            QualifiedType* result = nullptr;

            void operator()(hilti::type::RegExp* n) final {
                result = builder->qualifiedType(builder->typeBytes(), hilti::Constness::Mutable);
            }
        };

        QualifiedType* nt = nullptr;
        FieldTypeVisitor v(builder(), ft);
        v.dispatch(type->type());

        if ( v.result )
            nt = v.result;
        else
            nt = type;

        if ( ! nt->isResolved() ) {
            // Accept as resolved if it's a name that we already know. This
            // avoids getting into unsatisfiable resolution loops.
            if ( auto* name = nt->type(false)->tryAs<hilti::type::Name>(); ! name || ! name->resolvedTypeIndex() )
                return {};
        }

        if ( is_container )
            return builder()->qualifiedType(builder()->typeVector(nt, meta), hilti::Constness::Mutable);
        else
            return nt;
    }

    void operator()(hilti::Attribute* n) final {
        if ( n->kind() == attribute::kind::Size || n->kind() == attribute::kind::MaxSize ) {
            if ( ! n->hasValue() )
                // Caught elsewhere, we don't want to report it here again.
                return;

            if ( auto x = n->coerceValueTo(builder(), builder()->qualifiedType(builder()->typeUnsignedInteger(64),
                                                                               hilti::Constness::Const)) ) {
                if ( *x )
                    recordChange(n, to_string(n->kind()));
            }
            else
                n->addError(x.error());
        }

        else if ( n->kind() == attribute::kind::Requires ) {
            if ( ! n->hasValue() )
                // Caught elsewhere, we don't want to report it here again.
                return;

            auto* cond = *n->valueAsExpression();
            if ( ! cond->isResolved() )
                return;

            if ( cond->type()->type()->isA<hilti::type::Result>() )
                return;

            auto ne = coerceExpression(builder(), cond,
                                       builder()->qualifiedType(builder()->typeBool(), hilti::Constness::Const));
            if ( ! ne.coerced ) {
                n->addError(ne.coerced.error());
                return;
            }

            // Implicitly create an error message from the condition itself.
            auto msg = hilti::util::fmt("&requires failed: %s",
                                        hilti::util::replace(cond->print(), HILTI_INTERNAL_ID("dd"), "$$"));
            auto* new_cond =
                builder()->conditionTest(*ne.coerced, builder()->expression(builder()->ctorError(std::move(msg))),
                                         cond->meta());
            n->replaceChild(context(), cond, new_cond);
            recordChange(n, std::string(to_string(n->kind())));
        }
    }

    void operator()(type::unit::Item* n) final {
        if ( ! n->fullyQualifiedID() ) {
            if ( auto* utype = n->parent<type::Unit>(); utype && utype->typeID() )
                n->setFullyQualifiedID(utype->typeID() + n->id()); // global scope
        }
    }

    void operator()(declaration::Hook* n) final {
        if ( ! n->fullyQualifiedID() ) {
            if ( auto* utype = n->parent<type::Unit>(); utype && utype->typeID() )
                n->setFullyQualifiedID(utype->typeID() + n->id()); // global scope
            else if ( auto* hook = n->parent<declaration::UnitHook>(); hook && hook->fullyQualifiedID() )
                n->setFullyQualifiedID(hook->fullyQualifiedID()); // global scope
        }

        if ( ! n->unitTypeIndex() || ! n->unitFieldIndex() ) {
            // A`%print` hook returns a string as the rendering to print, need
            // to adjust its return type, which defaults to void.
            if ( n->id().local().str() == "0x25_print" ) {
                if ( n->ftype()->result()->type()->isA<hilti::type::Void>() ) {
                    recordChange(n, "setting %print result to string");
                    auto* optional = builder()->typeOptional(
                        builder()->qualifiedType(builder()->typeString(), hilti::Constness::Const));
                    n->setResult(context(), builder()->qualifiedType(optional, hilti::Constness::Const));
                }
            }

            // If an `%error` hook doesn't provide the optional string argument,
            // add it here so that we can treat the two versions the same.
            if ( n->id().local().str() == "0x25_error" ) {
                auto params = n->ftype()->parameters();
                if ( params.size() == 0 ) {
                    recordChange(n, "adding parameter to %error");
                    n->setParameters(context(),
                                     {builder()->parameter(HILTI_INTERNAL_ID("except"), builder()->typeString())});
                }
            }

            // Link hook to its unit type and field.

            auto* unit_type = n->parent<type::Unit>();
            if ( unit_type ) {
                // Produce a tailored error message if `%XXX` is used on a unit field.
                if ( auto id = n->id().namespace_(); id && hilti::util::startsWith(n->id().local(), "0x25_") ) {
                    if ( unit_type->as<type::Unit>()->itemByName(n->id().namespace_().local()) ) {
                        n->addError(hilti::util::fmt("cannot use hook '%s' with a unit field",
                                                     hilti::util::replace(n->id().local(), "0x25_", "%")));
                        return;
                    }
                }
            }
            else {
                // External hook, do name lookup.
                auto ns = n->id().namespace_();
                if ( ! ns )
                    return;

                auto resolved = hilti::scope::lookupID<hilti::declaration::Type>(ns, n, "unit type");
                if ( ! resolved ) {
                    // Look up as a type directly. If found, add explicit `%done`.
                    resolved = hilti::scope::lookupID<hilti::declaration::Type>(n->id(), n, "unit type");
                    if ( resolved ) {
                        recordChange(n, "adding explicit %done hook");
                        n->setID(n->id() + ID("0x25_done"));
                    }
                    else {
                        // Produce a tailored error message if `%XXX` is used on a unit field.
                        if ( auto id = ns.namespace_(); id && hilti::util::startsWith(n->id().local(), "0x25_") ) {
                            if ( auto resolved =
                                     hilti::scope::lookupID<hilti::declaration::Type>(std::move(id), n, "unit type") ) {
                                if ( auto* utype = resolved->first->template as<hilti::declaration::Type>()
                                                       ->type()
                                                       ->type()
                                                       ->tryAs<type::Unit>();
                                     utype && utype->itemByName(ns.local()) ) {
                                    n->addError(hilti::util::fmt("cannot use hook '%s' with a unit field",
                                                                 hilti::util::replace(n->id().local(), "0x25_", "%")));
                                    // We failed to resolve the ID since it refers to a hook.
                                    // Return early here and do not emit below resolution error.
                                    return;
                                }
                            }
                        }

                        n->addError(hilti::util::fmt("hook namespace `%s` does not refer to a type", ns),
                                    node::ErrorPriority::High);
                        return;
                    }
                }

                if ( auto* x = resolved->first->as<hilti::declaration::Type>()->type()->type()->tryAs<type::Unit>() )
                    unit_type = x;
                else {
                    n->addError(hilti::util::fmt("'%s' is not a unit type", ns));
                    return;
                }
            }

            assert(unit_type);

            if ( ! n->unitTypeIndex() ) {
                auto index = context()->register_(unit_type->as<type::Unit>());
                n->setUnitTypeIndex(index);
                recordChange(unit_type, hilti::util::fmt("set unit type to %s", index));
            }

            type::unit::Item* unit_field = n->parent<type::unit::item::Field>();
            if ( ! unit_field ) {
                // External or out-of-line hook.
                if ( ! n->id() ) {
                    n->addError("hook name missing");
                    return;
                }

                unit_field = unit_type->as<type::Unit>()->itemByName(n->id().local());
                if ( ! unit_field )
                    // We do not record an error here because we'd need to account
                    // for %init/%done/etc. We'll leave that to the validator.
                    return;

                if ( ! unit_field->isA<type::unit::item::Field>() ) {
                    n->addError(hilti::util::fmt("'%s' is not a unit field", n->id()));
                    return;
                }
            }

            assert(unit_field);

            if ( unit_field->isA<type::unit::item::Field>() && ! n->unitFieldIndex() ) {
                auto index = context()->register_(unit_field->as<type::unit::item::Field>());
                n->setUnitFieldIndex(index);
                recordChange(n, hilti::util::fmt("set linked unit field to %s", index));
            }
        }

        if ( n->unitFieldIndex() && ! n->dd() ) {
            auto* unit_field = context()->lookup(n->unitFieldIndex())->as<type::unit::item::Field>();

            QualifiedType* dd = nullptr;

            if ( n->hookType() == declaration::hook::Type::ForEach ) {
                dd = unit_field->ddType();
                if ( ! dd || ! dd->isResolved() )
                    return;

                // Validator will catch if the type is not a container.
                dd = dd->type()->elementType();
            }
            else
                dd = unit_field->itemType();

            if ( dd && dd->isResolved() ) {
                auto* dd_ = QualifiedType::createExternal(context(), dd->type(), dd->constness());
                recordChange(n, dd_, "$$ type");
                n->setDDType(context(), dd_);
            }
        }
    }

    void operator()(hilti::declaration::Type* n) final {
        if ( auto* u = n->type()->type()->tryAs<type::Unit>(); u && ! n->type()->alias() ) {
            if ( n->linkage() == hilti::declaration::Linkage::Public && ! u->isPublic() ) {
                recordChange(n, "set public");
                u->setPublic(true);
            }

            // Create unit property items from global module items where the unit
            // does not provide an overriding one.
            std::vector<type::unit::Item> ni;
            for ( const auto& prop : n->parent<hilti::declaration::Module>()->moduleProperties({}) ) {
                if ( u->propertyItem(prop->id()) )
                    continue;

                auto* i = builder()->typeUnitItemProperty(prop->id(), prop->expression(), {}, true, prop->meta());
                recordChange(n, hilti::util::fmt("add module-level property %s", prop->id()));
                u->addItems(context(), {i});
            }
        }
    }

    void operator()(hilti::expression::Name* n) final {
        // Allow `$$` as an alias for `self` in unit convert attributes for symmetry with field convert attributes.
        if ( n->id() == ID(HILTI_INTERNAL_ID("dd")) ) {
            // The following loop searches for `&convert` attribute nodes directly under `Unit` nodes.
            for ( auto* p = n->parent(); p; p = p->parent() ) {
                auto* attr = p->tryAs<hilti::Attribute>();
                if ( ! attr )
                    continue;

                if ( attr->kind() != attribute::kind::Convert )
                    return;

                // The direct parent of the attribute set containing the attribute should be the unit.
                if ( ! p->parent(2)->isA<type::Unit>() )
                    return;

                recordChange(n, "set self");
                n->setID("self");
            }
        }
    }

    void operator()(operator_::unit::ConnectFilter* n) final {
        auto* unit = n->op0()->type()->type()->as<type::Unit>();
        unit->setMayHaveFilter(true);
    }

    void operator()(operator_::unit::HasMember* n) final {
        auto* unit = n->op0()->type()->type()->tryAs<type::Unit>();
        const auto& id = n->op1()->tryAs<hilti::expression::Member>()->id();

        if ( unit && id && ! unit->itemByName(id) ) {
            // See if we got an anonymous bitfield with a member of that
            // name. If so, rewrite the access to transparently refer to the
            // member through the field's internal name.
            if ( auto* field = unit->findRangeInAnonymousBitField(id).first ) {
                const auto* has_member = hilti::operator_::registry().byName("unit::HasMember");
                assert(has_member);
                auto has_field =
                    has_member->instantiate(builder(), {n->op0(), builder()->expressionMember(field->id())}, n->meta());
                replaceNode(n, *has_field);
            }
        }
    }

    void operator()(operator_::unit::MemberConst* n) final {
        auto* unit = n->op0()->type()->type()->tryAs<type::Unit>();
        const auto& id = n->op1()->tryAs<hilti::expression::Member>()->id();

        if ( unit && id && ! unit->itemByName(id) ) {
            // See if we got an anonymous bitfield with a member of that
            // name. If so, rewrite the access to transparently refer to the
            // member through the field's internal name.
            if ( auto* field = unit->findRangeInAnonymousBitField(id).first ) {
                const auto* unit_member = hilti::operator_::registry().byName("unit::MemberConst");
                const auto* bitfield_member = hilti::operator_::registry().byName("bitfield::Member");
                assert(unit_member && bitfield_member);
                auto access_field =
                    unit_member->instantiate(builder(), {n->op0(), builder()->expressionMember(field->id())},
                                             n->meta());
                auto access_bits = bitfield_member->instantiate(builder(), {*access_field, n->op1()}, n->meta());
                replaceNode(n, *access_bits);
            }
        }
    }

    void operator()(operator_::unit::MemberNonConst* n) final {
        auto* unit = n->op0()->type()->type()->tryAs<type::Unit>();
        const auto& id = n->op1()->tryAs<hilti::expression::Member>()->id();

        if ( unit && id && ! unit->itemByName(id) ) {
            // See if we got an anonymous bitfield with a member of that
            // name. If so, rewrite the access to transparently refer to the
            // member through the field's internal name.
            if ( auto* field = unit->findRangeInAnonymousBitField(id).first ) {
                const auto* unit_member = hilti::operator_::registry().byName("unit::MemberNonConst");
                const auto* bitfield_member = hilti::operator_::registry().byName("bitfield::Member");
                assert(unit_member && bitfield_member);
                auto access_field =
                    unit_member->instantiate(builder(), {n->op0(), builder()->expressionMember(field->id())},
                                             n->meta());
                auto access_bits = bitfield_member->instantiate(builder(), {*access_field, n->op1()}, n->meta());
                replaceNode(n, *access_bits);
            }
        }
    }

    void operator()(operator_::unit::TryMember* n) final {
        auto* unit = n->op0()->type()->type()->tryAs<type::Unit>();
        const auto& id = n->op1()->tryAs<hilti::expression::Member>()->id();

        if ( unit && id && ! unit->itemByName(id) ) {
            // See if we we got an anonymous bitfield with a member of that
            // name. If so, rewrite the access to transparently to refer to the
            // member through the field's internal name.
            if ( auto* field = unit->findRangeInAnonymousBitField(id).first ) {
                const auto* try_member = hilti::operator_::registry().byName("unit::TryMember");
                const auto* bitfield_member = hilti::operator_::registry().byName("bitfield::Member");
                assert(try_member && bitfield_member);

                auto try_field =
                    try_member->instantiate(builder(), {n->op0(), builder()->expressionMember(field->id())}, n->meta());
                auto access_bits = bitfield_member->instantiate(builder(), {*try_field, n->op1()}, n->meta());
                replaceNode(n, *access_bits);
            }
        }
    }

    void operator()(hilti::type::Bitfield* n) final {
        if ( auto* field = n->parent(2)->tryAs<type::unit::item::Field>() ) {
            // Transfer any "&bitorder" attribute over to the type.
            if ( auto* a = field->attributes()->find(attribute::kind::BitOrder);
                 a && ! n->attributes()->find(attribute::kind::BitOrder) ) {
                recordChange(n, "transfer &bitorder attribute");
                n->attributes()->add(context(), a);
            }
        }

        if ( auto* decl = n->parent(2)->tryAs<hilti::declaration::Type>() ) {
            // Transfer any "&bitorder" attribute over to the type.
            if ( auto* a = decl->attributes()->find(attribute::kind::BitOrder);
                 a && ! n->attributes()->find(attribute::kind::BitOrder) ) {
                recordChange(n, "transfer &bitorder attribute");
                n->attributes()->add(context(), a);
            }
        }
    }

    void operator()(type::Unit* n) final {
        if ( ! n->contextType() ) {
            if ( auto* ctx = n->propertyItem("%context") ) {
                if ( auto* expr = ctx->expression(); expr && expr->isResolved() ) {
                    if ( auto* ty = expr->type()->type()->tryAs<hilti::type::Type_>() ) {
                        recordChange(n, "set unit's context type");
                        n->setContextType(context(), ty->typeValue()->type());
                    }
                }
            }
        }
    }

    void operator()(type::unit::item::Block* n) final {
        if ( auto* cond = n->condition() ) {
            auto coerced =
                hilti::coerceExpression(builder(), cond,
                                        builder()->qualifiedType(builder()->typeBool(), hilti::Constness::Const),
                                        hilti::CoercionStyle::TryAllForMatching |
                                            hilti::CoercionStyle::ContextualConversion);
            if ( coerced && coerced.nexpr ) {
                recordChange(n, coerced.nexpr, "condition");
                n->setCondition(context(), coerced.nexpr);
            }
        }
    }

    void operator()(type::unit::item::Field* n) final {
        if ( (n->isAnonymous() || n->isSkip()) && ! n->isTransient() ) {
            // Make the field transient if it's either top-level, or a direct
            // parent field is already transient.
            bool make_transient = false;

            if ( n->parent()->isA<type::Unit>() )
                make_transient = true;

            if ( auto* pf = n->parent<type::unit::item::Field>(); pf && pf->isTransient() )
                make_transient = true;

            if ( make_transient ) {
                // Make anonymous top-level fields transient.
                recordChange(n, "set transient");
                n->setTransient(true);
            }
        }

        if ( n->parseType()
                 ->type()
                 ->isA<hilti::type::Auto>() ) { // do not use isResolved(), so that we can deal with loops
            if ( auto* t = fieldType(*n, n->originalType(), FieldType::ParseType, n->isContainer(), n->meta()) ) {
                recordChange(n, "parse type");
                n->setParseType(context(), t);
            }
        }

        if ( ! n->ddType()->isResolved() && n->parseType()->isResolved() ) {
            if ( auto* dd = fieldType(*n, n->originalType(), FieldType::DDType, n->isContainer(), n->meta()) ) {
                recordChange(n, dd, "$$ type");
                n->setDDType(context(), dd);
            }
        }

        if ( n->itemType()->type()->isA<hilti::type::Auto>() &&
             ! n->parseType()
                   ->type()
                   ->isA<hilti::type::Auto>() ) { // do not use isResolved(), so that we can deal with loops
            QualifiedType* t = nullptr;

            if ( auto x = n->convertExpression() ) {
                if ( x->second ) {
                    // Unit-level convert on the sub-item.
                    auto* u = x->second->type()->as<type::Unit>();
                    auto* a = u->attributes()->find(attribute::kind::Convert);
                    assert(a);
                    auto* e = *a->valueAsExpression();
                    if ( e->isResolved() )
                        t = e->type();
                }
                else if ( x->first->isResolved() ) {
                    t = x->first->type();

                    // If there's list comprehension, morph the type into a vector.
                    // Assignment will transparently work.
                    if ( auto* x = t->type()->tryAs<hilti::type::List>() )
                        t = builder()->qualifiedType(builder()->typeVector(x->elementType(), x->meta()),
                                                     t->constness());
                }
            }
            else if ( const auto& i = n->item(); i && i->isA<type::unit::item::Field>() ) {
                const auto& inner_f = i->as<type::unit::item::Field>();
                t = fieldType(*inner_f, i->itemType(), FieldType::ItemType, n->isContainer(), n->meta());
            }
            else
                t = fieldType(*n, n->originalType(), FieldType::ItemType, n->isContainer(), n->meta());

            if ( t ) {
                recordChange(n, "item type");
                n->setItemType(context(), t);
            }
        }
    }

    void operator()(type::unit::item::Property* n) final {
        if ( n->id() == "%sync-advance-block-size" ) {
            if ( auto* expr = n->expression() ) {
                auto* t = expr->type()->type()->tryAs<hilti::type::UnsignedInteger>();
                if ( ! t || t->width() != 64 ) {
                    if ( auto x = hilti::coerceExpression(builder(), expr,
                                                          builder()->qualifiedType(builder()->typeUnsignedInteger(64),
                                                                                   hilti::Constness::Const),
                                                          hilti::CoercionStyle::TryAllForMatching) ) {
                        n->setExpression(context(), *x.coerced);
                        recordChange(n, "coerced property to uint64");
                    }
                }
            }
        }
    }

    void operator()(type::unit::item::UnresolvedField* n) final {
        if ( n->type() && n->type()->type()->isA<hilti::type::Void>() && n->attributes() ) {
            // Transparently map void fields that aim to parse data into
            // skipping bytes fields. Use of such void fields is deprecated and
            // will be removed later.
            size_t ok_attrs = 0;
            const auto& attrs = n->attributes()->attributes();
            for ( const auto& a : attrs ) {
                if ( a->kind() == attribute::kind::Requires )
                    ok_attrs++;
            }

            if ( ok_attrs != attrs.size() ) {
                hilti::logger().deprecated(
                    "using `void` fields with attributes is deprecated and support will be removed in a future "
                    "release; replace 'void ...' with 'skip bytes ...'",
                    n->meta().location());

                n->setSkip(true);
                n->setType(context(), builder()->qualifiedType(builder()->typeBytes(), hilti::Constness::Mutable));
            }
        }

        if ( const auto& id = n->unresolvedID() ) { // check for unresolved IDs first to overrides the other cases below
            auto resolved = hilti::scope::lookupID<hilti::Declaration>(id, n, "field");
            if ( ! resolved ) {
                n->addError(resolved.error());
                return;
            }

            if ( auto* t = resolved->first->template tryAs<hilti::declaration::Type>() ) {
                QualifiedType* tt = builder()->qualifiedType(builder()->typeName(id), hilti::Constness::Mutable);

                // If a unit comes with a &convert attribute, we wrap it into a
                // subitem so that we have our recursive machinery available
                // (which we don't have for pure types).
                if ( auto* unit_type = t->type()->type()->tryAs<type::Unit>();
                     unit_type && unit_type->attributes()->find(attribute::kind::Convert) ) {
                    auto* inner_field =
                        builder()->typeUnitItemField({}, tt, false, n->arguments(), {}, {}, {}, {}, {}, n->meta());
                    inner_field->setIndex(*n->index());

                    auto* outer_field = builder()->typeUnitItemField(n->fieldID(), inner_field, n->isSkip(), {},
                                                                     n->repeatCount(), n->sinks(), n->attributes(),
                                                                     n->condition(), n->hooks(), n->meta());

                    outer_field->setIndex(*n->index());

                    replaceNode(n, outer_field);
                }

                else
                    // Default treatment for types is to create a corresponding field.
                    replaceNode(n, resolveField(builder(), n, tt));
            }

            else if ( auto* c = resolved->first->tryAs<hilti::declaration::Constant>() ) {
                if ( auto* ctor = c->value()->template tryAs<hilti::expression::Ctor>() )
                    replaceNode(n, resolveField(builder(), n, ctor->ctor()));
                else
                    n->addError("field value must be a constant");
            }
            else
                n->addError(hilti::util::fmt("field value must be a constant or type (but is a %s)",
                                             resolved->first->as<hilti::Declaration>()->displayName()));
        }

        else if ( auto* c = n->ctor() )
            replaceNode(n, resolveField(builder(), n, c));

        else if ( auto* t = n->type() ) {
            if ( auto* bf = t->type()->tryAs<hilti::type::Bitfield>() ) {
                // If a bitfield type comes with values for at least one of its
                // items, it's actually a bitfield ctor. Replace the type with the
                // ctor then.
                if ( auto* ctor = bf->ctorValue(context()) ) {
                    replaceNode(n, resolveField(builder(), n, ctor));
                    return;
                }
            }

            replaceNode(n, resolveField(builder(), n, t));
        }

        else if ( auto* i = n->item() )
            replaceNode(n, resolveField(builder(), n, i));

        else
            hilti::logger().internalError("no known type for unresolved field", n->location());
    }
};

} // anonymous namespace

bool detail::resolver::resolve(Builder* builder, Node* root) {
    hilti::util::timing::Collector _("spicy/compiler/ast/resolver");

    bool hilti_modified = (*hilti::plugin::registry().hiltiPlugin().ast_resolve)(builder, root);

    return visitor::visit(VisitorPass2(builder, root), root, ".spicy",
                          [&](const auto& v) { return v.isModified() || hilti_modified; });
}
