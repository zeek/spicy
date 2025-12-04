// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <optional>
#include <utility>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/reference.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/list-comprehension.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/type.h>
#include <hilti/ast/expressions/typeinfo.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operator-registry.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/operators/generic.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/scope.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>
#include <hilti/compiler/coercer.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/constant-folder.h>
#include <hilti/compiler/detail/resolver.h>
#include <hilti/compiler/driver.h>
#include <hilti/compiler/unit.h>

using namespace hilti;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Resolver("resolver");
inline const hilti::logging::DebugStream Operator("operator");
} // namespace hilti::logging::debug

namespace {

// Pass 1 resolves named types first so that the on-heap conversion can take
// place before anything else.
struct VisitorPass1 : visitor::MutatingPostOrder {
    explicit VisitorPass1(Builder* builder) : visitor::MutatingPostOrder(builder, logging::debug::Resolver) {}

    void operator()(type::Name* n) final {
        if ( ! n->resolvedTypeIndex() ) {
            if ( auto resolved = scope::lookupID<declaration::Type>(n->id(), n, "type") ) {
                auto index = context()->register_(resolved->first->type()->type());
                n->setResolvedTypeIndex(index);
                recordChange(n, util::fmt("set resolved type to %s", index));
            }
            else {
                n->addError(resolved.error(), node::ErrorPriority::High);
                return;
            }
        }

        if ( n->resolvedTypeIndex() ) {
            auto* resolved = n->resolvedType();
            if ( ! resolved )
                n->addError(util::fmt("type '%s' cannot be resolved by its name", n->id()));
            else if ( resolved->isOnHeap() ) {
                if ( auto* qtype = n->parent()->tryAs<QualifiedType>() ) {
                    auto* parent = qtype->parent()->tryAs<UnqualifiedType>();
                    if ( ! (parent && parent->isReferenceType()) ) {
                        // Climb up the parent path to see if we are in a
                        // context where we want to wrap the type into a
                        // `value_ref`.
                        auto replace = false;

                        for ( Node* x = n->parent(); x; x = x->parent() ) {
                            if ( x->isA<UnqualifiedType>() || x->isA<Declaration>() ) {
                                replace = true;
                                break;
                            }
                            else if ( auto* ctor = x->tryAs<Ctor>(); ctor && ctor->isReferenceCtor() ) {
                                replace = false;
                                break;
                            }
                            else if ( x->isA<ctor::Default>() || x->isA<ctor::Struct>() ) {
                                replace = false;
                                break;
                            }
                            else if ( x->isA<Statement>() && ! x->isA<statement::Declaration>() ) {
                                replace = false;
                                break;
                            }
                        }

                        if ( replace ) {
                            auto* rt = builder()->typeValueReference(qtype, Location("<on-heap-replacement>"));
                            replaceNode(qtype, builder()->qualifiedType(rt, qtype->constness(), qtype->side()),
                                        "&on-heap replacement");
                        }
                    }
                }
            }
        }
    }
};

// Pass 2 is the main pass implementing most of the resolver's functionality:
// Type inference, name/operator resolution, ID assignment (but not coercion yet).
struct VisitorPass2 : visitor::MutatingPostOrder {
    explicit VisitorPass2(Builder* builder) : visitor::MutatingPostOrder(builder, logging::debug::Resolver) {}

    std::map<ID, QualifiedType*> auto_params; // mapping of `auto` parameters inferred, indexed by canonical ID

    // Sets a declaration fully qualified ID
    void setFqID(Declaration* d, ID id) {
        assert(id);
        d->setFullyQualifiedID(std::move(id));
        recordChange(d, util::fmt("set declaration's fully qualified ID to %s", d->fullyQualifiedID()));
    }

    // If a type is a reference type, dereference it; otherwise return the type
    // itself.
    QualifiedType* skipReferenceType(QualifiedType* t) {
        if ( t && t->type()->isReferenceType() )
            return t->type()->dereferencedType();
        else
            return t;
    }

    // Attempts to infer a common type from a list of expression. Ignores
    // constness of the individual expressions when comparing types, and always
    // returns a non-constant type as the one inferred. If old type is given,
    // returns null if inferred type is the same as the old one.
    QualifiedType* typeForExpressions(Node* n, node::Range<Expression> exprs, QualifiedType* old_type = nullptr) {
        UnqualifiedType* t = nullptr;

        for ( const auto& e : exprs ) {
            if ( ! e->type()->isResolved() )
                return {};

            if ( ! t )
                t = e->type()->type();
            else {
                if ( ! type::same(e->type()->type(), t) ) {
                    t = builder()->typeUnknown(); // inconsistent types, won't be able to resolve here
                    break;
                }
            }
        }

        if ( ! t )
            return nullptr;

        auto* ntype = builder()->qualifiedType(t, Constness::Mutable);

        if ( old_type && type::same(old_type, ntype) )
            return nullptr;

        return ntype;
    }

    // Casts an uint64 to int64, with range check.
    int64_t to_int64(uint64_t x) {
        if ( x > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) )
            throw hilti::rt::OutOfRange("integer value out of range");

        return static_cast<int64_t>(x);
    }

    // Casts an int64 to uint64, with range check.
    uint64_t to_uint64(int64_t x) {
        if ( x < 0 )
            throw hilti::rt::OutOfRange("integer value out of range");

        return static_cast<uint64_t>(x);
    }

    // Overload that doesn't need to do any checking.
    int64_t to_int64(int64_t x) { return x; }

    // Returns the i'th argument of a call expression.
    auto callArgument(const expression::ResolvedOperator* o, int i) {
        auto* ctor = o->op1()->as<expression::Ctor>()->ctor();

        if ( auto* x = ctor->tryAs<ctor::Coerced>() )
            ctor = x->coercedCtor();

        return ctor->as<ctor::Tuple>()->value()[i];
    }

    // Returns a method call's i-th argument.
    Expression* methodArgument(const expression::ResolvedOperator* o, size_t i) {
        auto* ops = o->op2();

        // If the argument list was the result of a coercion unpack its result.
        if ( auto* coerced = ops->tryAs<expression::Coerced>() )
            ops = coerced->expression();

        if ( auto* ctor_ = ops->tryAs<expression::Ctor>() ) {
            auto* ctor = ctor_->ctor();

            // If the argument was the result of a coercion unpack its result.
            if ( auto* x = ctor->tryAs<ctor::Coerced>() )
                ctor = x->coercedCtor();

            if ( auto* args = ctor->tryAs<ctor::Tuple>(); args && i < args->value().size() )
                return args->value()[i];
        }

        util::cannotBeReached();
    }

    // Records the actual type of an `auto` parameter as inferred from a
    // concrete argument value passed to it.
    void recordAutoParameters(const type::Function& ftype, Expression* args) {
        auto arg = args->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value().begin();
        std::vector<type::function::Parameter> params;
        for ( auto& rp : ftype.parameters() ) {
            auto* p = rp->as<declaration::Parameter>();
            if ( ! p->type()->isAuto() )
                continue;

            auto* t = (*arg)->type();
            if ( ! t->isResolved() )
                continue;

            assert(p->canonicalID());
            const auto& i = auto_params.find(p->canonicalID());
            if ( i == auto_params.end() ) {
                auto_params.emplace(p->canonicalID(), t);
                HILTI_DEBUG(logging::debug::Resolver,
                            util::fmt("recording auto parameter %s as of type %s", p->canonicalID(), *t));
            }
            else {
                if ( i->second != t )
                    rp->addError("mismatch for auto parameter");
            }

            ++arg;
        }
    }

    // Matches an unresolved operator against a set of operator candidates,
    // returning instantiations of all matches.
    Expressions matchOperators(expression::UnresolvedOperator* u, const std::vector<const Operator*>& candidates,
                               bool disallow_type_changes = false) {
        const std::array<bitmask<CoercionStyle>, 7> styles = {
            CoercionStyle::TryExactMatch,
            CoercionStyle::TryDeref,
            CoercionStyle::TryCoercionWithinSameType,
            CoercionStyle::TryCoercion,
            CoercionStyle::TryConstPromotion,
            CoercionStyle::TryConstPromotion | CoercionStyle::TryDeref,
            CoercionStyle::TryConstPromotion | CoercionStyle::TryCoercion,
        };

        auto coerce_operands = [&](const Operator* candidate, const auto& operands, const auto& expressions,
                                   bitmask<CoercionStyle> style) {
            // First, match the operands against the operator's general signature.
            auto result = coerceOperands(builder(), candidate->kind(), operands, expressions, style);
            if ( ! result )
                return result;

            // Then, if the operator provides more specific operands through filtering, match against those as well.
            if ( auto filtered = candidate->filter(builder(), result->second) ) {
                assert(filtered->size() == candidate->operands().size());
                result = coerceOperands(builder(), candidate->kind(), operands, *filtered, style);
            }

            return result;
        };

        auto try_candidate = [&](const Operator* candidate, const node::Range<Expression>& operands, auto style,
                                 const Meta& meta, const auto& dbg_msg) -> Expression* {
            auto noperands = coerce_operands(candidate, operands, candidate->operands(), style);
            if ( ! noperands ) {
                HILTI_DEBUG(logging::debug::Operator, util::fmt("-> cannot coerce operands: %s", noperands.error()));
                return {};
            }

            auto r = candidate->instantiate(builder(), noperands->second, meta);
            if ( ! r ) {
                u->addError(r.error());
                return {};
            }

            // Some operators may not be able to determine their type before the
            // resolver had a chance to provide the information needed. They will
            // return "auto" in that case (specifically, that's the case for Spicy
            // unit member access). Note we can't check if ->isResolved() here
            // because operators may legitimately return other unresolved types
            // (e.g., IDs that still need to be looked up).
            if ( (*r)->type()->isAuto() )
                return {};

            Expression* resolved = *r;

            // Fold any constants right here in case downstream resolving depends
            // on finding a constant (like for coercion).
            if ( auto ctor = detail::constant_folder::foldExpression(builder(), resolved); ctor && *ctor ) {
                HILTI_DEBUG(logging::debug::Operator,
                            util::fmt("folded %s -> constant %s (%s)", *resolved, **ctor, resolved->location()));
                resolved = builder()->expressionCtor(*ctor, resolved->meta());
            }

            HILTI_DEBUG(logging::debug::Operator, util::fmt("-> %s, resolves to %s", dbg_msg, *resolved))
            return resolved;
        };

        auto try_all_candidates = [&](Expressions* resolved, std::set<operator_::Kind>* kinds_resolved,
                                      operator_::Priority priority) {
            for ( auto style : styles ) {
                if ( disallow_type_changes )
                    style |= CoercionStyle::DisallowTypeChanges;

                HILTI_DEBUG(logging::debug::Operator, util::fmt("style: %s", to_string(style)));
                logging::DebugPushIndent _(logging::debug::Operator);

                for ( const auto& c : candidates ) {
                    if ( priority != c->signature().priority )
                        // Not looking at operators of this priority right now.
                        continue;

                    if ( priority == operator_::Priority::Low && kinds_resolved->contains(c->kind()) )
                        // Already have a higher priority match for this operator kind.
                        continue;

                    HILTI_DEBUG(logging::debug::Operator, util::fmt("candidate: %s (%s)", c->name(), c->print()));
                    logging::DebugPushIndent _(logging::debug::Operator);

                    if ( auto* r = try_candidate(c, u->operands(), style, u->meta(), "candidate matches") ) {
                        if ( c->signature().priority == operator_::Priority::Normal )
                            kinds_resolved->insert(c->kind());

                        resolved->push_back(r);
                    }
                    else {
                        auto operands = u->operands();
                        // Try to swap the operators for commutative operators.
                        if ( operator_::isCommutative(c->kind()) && operands.size() == 2 ) {
                            Nodes new_operands = {operands[1], operands[0]};
                            if ( auto* r =
                                     try_candidate(c,
                                                   hilti::node::Range<Expression>(new_operands.begin(),
                                                                                  new_operands.end()),
                                                   style, u->meta(), "candidate matches with operands swapped") ) {
                                if ( c->signature().priority == operator_::Priority::Normal )
                                    kinds_resolved->insert(c->kind());

                                resolved->emplace_back(r);
                            }
                        }
                    }
                }

                if ( resolved->size() )
                    return;
            }
        };

        HILTI_DEBUG(logging::debug::Operator,
                    util::fmt("trying to resolve: %s (%s)", u->printSignature(), u->location()));
        logging::DebugPushIndent _(logging::debug::Operator);

        std::set<operator_::Kind> kinds_resolved;
        Expressions resolved;

        try_all_candidates(&resolved, &kinds_resolved, operator_::Priority::Normal);
        if ( resolved.size() )
            return resolved;

        try_all_candidates(&resolved, &kinds_resolved, operator_::Priority::Low);
        return resolved;
    }

    void operator()(Attribute* n) final {
        if ( n->kind() == hilti::attribute::kind::Cxxname && n->hasValue() ) {
            // Normalize values passed as `&cxxname` so they always are interpreted as FQNs by enforcing leading
            // `::`.
            if ( const auto& value = n->valueAsString(); value && ! util::startsWith(*value, "::") ) {
                auto* a = builder()->attribute(hilti::attribute::kind::Cxxname,
                                               builder()->stringLiteral(util::fmt("::%s", *value)));
                replaceNode(n, a);
            }
        }
    }

    void operator()(ctor::List* n) final {
        if ( ! expression::areResolved(n->value()) )
            return; // cannot do anything yet

        if ( ! n->type()->isResolved() ) {
            if ( auto* ntype = typeForExpressions(n, n->value(), n->type()->type()->elementType()) ) {
                recordChange(n, ntype, "type");
                n->setType(context(), builder()->qualifiedType(builder()->typeList(ntype), Constness::Mutable));
            }
        }

        if ( n->elementType()->type()->isA<type::Unknown>() ) {
            // If we use a list to initialize another list/set/vector, and
            // coercion has figured out how to type the list for that coercion
            // even though the list's type on its own isn't known, then
            // transfer the container's element type over.
            if ( auto* parent = n->parent()->tryAs<ctor::Coerced>(); parent && parent->type()->isResolved() ) {
                QualifiedType* etype = nullptr;

                if ( auto* l = parent->type()->type()->tryAs<type::List>() )
                    etype = l->elementType();
                else if ( auto* s = parent->type()->type()->tryAs<type::Set>() )
                    etype = s->elementType();
                else if ( auto* v = parent->type()->type()->tryAs<type::Vector>() )
                    etype = v->elementType();

                if ( etype && ! etype->type()->isA<type::Unknown>() ) {
                    recordChange(n, util::fmt("set type inferred from container to %s", *etype));
                    n->setType(context(), builder()->qualifiedType(builder()->typeList(etype), Constness::Const));
                }
            }
        }
    }

    void operator()(ctor::Map* n) final {
        for ( const auto& e : n->value() ) {
            if ( ! (e->key()->isResolved() && e->value()->isResolved()) )
                return; // cannot do anything yet
        }

        if ( ! n->type()->isResolved() ) {
            QualifiedType* key = nullptr;
            QualifiedType* value = nullptr;

            for ( const auto& e : n->value() ) {
                if ( ! key )
                    key = e->key()->type();
                else if ( ! type::same(e->key()->type(), key) ) {
                    n->addError("inconsistent key types in map");
                    return;
                }

                if ( ! value )
                    value = e->value()->type();
                else if ( ! type::same(e->value()->type(), value) ) {
                    n->addError("inconsistent value types in map");
                    return;
                }
            }

            if ( ! (key && value) ) {
                // empty map
                key = builder()->qualifiedType(builder()->typeUnknown(), Constness::Const);
                value = builder()->qualifiedType(builder()->typeUnknown(), Constness::Const);
            }

            auto* ntype = builder()->qualifiedType(builder()->typeMap(key, value, n->meta()), Constness::Mutable);
            if ( ! type::same(ntype, n->type()) ) {
                recordChange(n, ntype, "type");
                n->setType(context(), ntype);
            }
        }
    }

    void operator()(ctor::Optional* n) final {
        if ( ! n->type()->isResolved() && n->value() && n->value()->isResolved() ) {
            recordChange(n, n->value()->type(), "type");
            n->setType(context(),
                       builder()->qualifiedType(builder()->typeOptional(n->value()->type()), Constness::Mutable));
        }
    }

    void operator()(ctor::Result* n) final {
        if ( ! n->type()->isResolved() && n->value()->isResolved() ) {
            recordChange(n, n->value()->type(), "type");
            n->setType(context(),
                       builder()->qualifiedType(builder()->typeResult(n->value()->type()), Constness::Const));
        }
    }

    void operator()(ctor::Set* n) final {
        if ( ! expression::areResolved(n->value()) )
            return; // cannot do anything yet

        if ( ! n->type()->isResolved() ) {
            if ( auto* ntype = typeForExpressions(n, n->value(), n->type()->type()->elementType()) ) {
                recordChange(n, ntype, "type");
                n->setType(context(), builder()->qualifiedType(builder()->typeSet(ntype), Constness::Mutable));
            }
        }
    }

    void operator()(ctor::Struct* n) final {
        for ( const auto& f : n->fields() ) {
            if ( ! f->expression()->isResolved() )
                return; // cannot do anything yet
        }

        if ( ! n->type()->isResolved() ) {
            Declarations fields;
            for ( const auto& f : n->fields() )
                fields.emplace_back(builder()->declarationField(f->id(), f->expression()->type(),
                                                                builder()->attributeSet({}), f->meta()));

            auto* ntype =
                builder()->qualifiedType(builder()->typeStruct(type::Struct::AnonymousStruct(), fields, n->meta()),
                                         Constness::Mutable);
            recordChange(n, ntype, "type");
            n->setType(context(), ntype);
        }
    }

    void operator()(ctor::Tuple* n) final {
        if ( ! n->type()->isResolved() && expression::areResolved(n->value()) ) {
            auto elems = n->value() | std::views::transform([](const auto& e) { return e->type(); });
            auto* t =
                builder()->qualifiedType(builder()->typeTuple(util::toVector(elems), n->meta()), Constness::Const);
            recordChange(n, t, "type");
            n->setType(context(), t);
        }
    }

    void operator()(ctor::ValueReference* n) final {
        if ( ! n->type()->isResolved() && n->expression()->isResolved() ) {
            auto* t = builder()->typeValueReference(n->expression()->type()->recreateAsNonConst(context()));
            recordChange(n, t, "type");
            n->setType(context(), builder()->qualifiedType(t, Constness::Const));
        }
    }

    void operator()(ctor::Vector* n) final {
        if ( ! expression::areResolved(n->value()) )
            return; // cannot do anything yet

        if ( ! n->type()->isResolved() ) {
            if ( auto* ntype = typeForExpressions(n, n->value(), n->type()->type()->elementType()) ) {
                recordChange(n, ntype, "type");
                n->setType(context(), builder()->qualifiedType(builder()->typeVector(ntype), Constness::Mutable));
            }
        }
    }

    void operator()(Declaration* n) final {
        if ( ! n->canonicalID() ) {
            if ( auto* module = n->parent<declaration::Module>() ) {
                assert(module);
                auto id = module->uid().unique + n->id();
                n->setCanonicalID(context()->uniqueCanononicalID(id));
                recordChange(n, util::fmt("set declaration's canonical ID to %s", n->canonicalID()));
            }
        }
    }

    void operator()(declaration::Constant* n) final {
        if ( ! n->fullyQualifiedID() ) {
            if ( n->type()->type()->isNameType() ) {
                if ( auto tid = n->type()->type()->typeID() )
                    setFqID(n, tid + n->id());
            }
            else if ( n->parent<Function>() )
                setFqID(n, n->id()); // local scope
            else if ( auto* m = n->parent<declaration::Module>() )
                setFqID(n, m->scopeID() + n->id()); // global scope
        }
    }

    void operator()(declaration::Expression* n) final {
        if ( ! n->fullyQualifiedID() ) {
            if ( n->id() == ID("self") || n->id() == ID(HILTI_INTERNAL_ID("dd")) )
                setFqID(n, n->id()); // local scope
            else if ( n->parent<Function>() )
                setFqID(n, n->id()); // local scope
            else if ( auto* m = n->parent<declaration::Module>() )
                setFqID(n, m->scopeID() + n->id()); // global scope
        }
    }

    void operator()(declaration::Field* n) final {
        if ( ! n->fullyQualifiedID() ) {
            if ( auto* ctor = n->parent(3)->tryAs<ctor::Struct>() )
                // special-case anonymous structs
                setFqID(n, ctor->uniqueID() + n->id());
            else if ( auto* ctor = n->parent(3)->tryAs<ctor::Bitfield>() )
                // special-case anonymous bitfields
                setFqID(n, ctor->btype()->uniqueID() + n->id());
            else if ( auto* stype = n->parent()->tryAs<type::Struct>(); stype && stype->typeID() )
                setFqID(n, stype->typeID() + n->id());
            else if ( auto* utype = n->parent()->tryAs<type::Union>(); utype && utype->typeID() )
                setFqID(n, utype->typeID() + n->id());
        }

        if ( ! n->linkedTypeIndex() ) {
            auto* t = n->parent()->as<UnqualifiedType>();
            auto index = context()->register_(t);
            n->setLinkedTypeIndex(index);
            recordChange(n, util::fmt("set linked type to %s", index));
        }

        if ( n->type()->type()->isA<type::Function>() && ! n->operator_() && n->parent(3)->isA<declaration::Type>() &&
             n->type()->type()->isResolved() ) {
            if ( auto idx = n->linkedTypeIndex(); idx && context()->lookup(idx)->typeID() ) {
                // We register operators here so that we have the type ID for
                // the struct available.
                recordChange(n, "creating member call operator");
                std::unique_ptr<struct_::MemberCall> op(new struct_::MemberCall(n));
                n->setOperator(op.get());
                operator_::registry().register_(std::move(op));
            }
        }
    }

    void operator()(declaration::Function* n) final {
        if ( ! n->fullyQualifiedID() ) {
            if ( auto* m = n->parent<declaration::Module>() ) {
                if ( m->scopeID() == n->id().sub(0) )
                    setFqID(n, n->id());
                else
                    setFqID(n, m->scopeID() + n->id()); // global scope
            }
        }

        if ( auto ns = n->id().namespace_() ) {
            // Link namespaced function to its base type and/or prototype.
            declaration::Type* linked_type = nullptr;
            Declaration* linked_prototype = nullptr;

            if ( auto resolved = scope::lookupID<declaration::Type>(std::move(ns), n, "struct type") ) {
                linked_type = resolved->first;

                for ( const auto& field : linked_type->type()->type()->as<type::Struct>()->fields(n->id().local()) ) {
                    auto* method_type = field->type()->type()->tryAs<type::Function>();
                    if ( ! method_type ) {
                        n->addError(util::fmt("'%s' is not a method of type '%s'", n->id().local(), linked_type->id()));
                        return;
                    }

                    if ( areEquivalent(n->function()->ftype(), method_type) )
                        linked_prototype = field;
                }

                if ( ! linked_prototype ) {
                    n->addError(
                        util::fmt("struct type '%s' has no matching method '%s'", linked_type->id(), n->id().local()));
                    return;
                }
            }

            else {
                for ( const auto& x : context()->root()->scope()->lookupAll(n->id()) ) {
                    if ( auto* f = x.node->tryAs<declaration::Function>() ) {
                        if ( areEquivalent(n->function()->ftype(), f->function()->ftype()) ) {
                            if ( ! linked_prototype ||
                                 ! f->function()->body() ) // prefer declarations wo/ implementation
                                linked_prototype = f;
                        }
                    }
                }
            }

            if ( linked_type ) {
                if ( ! n->linkedDeclarationIndex() ) {
                    auto index = context()->register_(linked_type);
                    n->setLinkedDeclarationIndex(index);
                    recordChange(n, util::fmt("set linked declaration to %s", index));

                    n->setLinkage(declaration::Linkage::Struct);
                    recordChange(n, util::fmt("set linkage to struct"));
                }
                else {
                    assert(linked_type->declarationIndex() ==
                           n->linkedDeclarationIndex()); // shouldn't changed once bound
                    assert(n->linkage() == declaration::Linkage::Struct);
                }
            }

            if ( linked_prototype ) {
                if ( ! n->linkedPrototypeIndex() ) {
                    auto index = context()->register_(linked_prototype);
                    n->setLinkedPrototypeIndex(index);
                    recordChange(n, util::fmt("set linked prototype to %s", index));
                }
                else
                    assert(linked_prototype->canonicalID() ==
                           context()->lookup(n->linkedPrototypeIndex())->canonicalID()); // shouldn't changed once bound
            }
        }

        if ( n->linkage() != declaration::Linkage::Struct && ! n->operator_() && n->function()->type()->isResolved() ) {
            recordChange(n, "creating function call operator");
            std::unique_ptr<function::Call> op(new function::Call(n));
            n->setOperator(op.get());
            operator_::registry().register_(std::move(op));
        }
    }

    void operator()(declaration::GlobalVariable* n) final {
        if ( ! n->fullyQualifiedID() ) {
            if ( auto* m = n->parent<declaration::Module>() )
                setFqID(n, m->scopeID() + n->id()); // global scope
        }

        if ( n->type()->isAuto() ) {
            if ( auto* init = n->init(); init && init->isResolved() ) {
                recordChange(n, init->type(), "type");
                n->setType(context(), init->type());
            }
        }
    }

    void operator()(declaration::ImportedModule* n) final {
        if ( ! n->fullyQualifiedID() ) {
            if ( auto* m = n->parent<declaration::Module>() )
                setFqID(n, m->scopeID() + n->id());
        }

        if ( ! n->uid() ) {
            auto* current_module = n->parent<declaration::Module>();
            assert(current_module);

            auto uid = context()->importModule(builder(), n->id(), n->scope(), n->parseExtension(),
                                               current_module->uid().process_extension, n->searchDirectories());

            if ( ! uid ) {
                logger().error(util::fmt("cannot import module '%s': %s", n->id(), uid.error()), n->meta().location());
                return;
            }

            recordChange(n, util::fmt("imported module %s", *uid));
            n->setUID(*uid);
            current_module->addDependency(*uid);

            if ( ! context()->driver()->driverOptions().skip_dependencies )
                context()->driver()->registerUnit(Unit::fromExistingUID(context()->driver()->context(), *uid));
        }
    }

    void operator()(declaration::LocalVariable* n) final {
        if ( ! n->fullyQualifiedID() )
            setFqID(n, n->id()); // local scope

        if ( n->type()->isAuto() ) {
            if ( auto* init = n->init(); init && init->isResolved() ) {
                recordChange(n, init->type(), "type");
                n->setType(context(), init->type());
            }
        }
    }

    void operator()(declaration::Module* n) final {
        if ( ! n->fullyQualifiedID() )
            setFqID(n, n->scopeID());

        if ( ! n->canonicalID() ) {
            n->setCanonicalID(n->uid().unique);
            recordChange(n, util::fmt("set module's canonical ID to %s", n->canonicalID()));
        }

        if ( n->moduleProperty("%skip-implementation") )
            n->setSkipImplementation(true);

        if ( ! n->declarationIndex() ) {
            auto index = context()->register_(n);
            recordChange(n, util::fmt("set module's declaration index to %s", index));
        }
    }

    void operator()(declaration::Parameter* n) final {
        if ( ! n->fullyQualifiedID() )
            setFqID(n, n->id());
    }

    void operator()(declaration::Property* n) final {
        if ( ! n->fullyQualifiedID() ) {
            if ( n->parent<Function>() )
                setFqID(n, n->id()); // local scope
            else if ( auto* m = n->parent<declaration::Module>() )
                setFqID(n, m->scopeID() + n->id()); // global scope
        }
    }

    void operator()(declaration::Type* n) final {
        if ( ! n->fullyQualifiedID() ) {
            if ( n->parent<Function>() )
                setFqID(n, n->id()); // local scope
            else if ( auto* m = n->parent<declaration::Module>() )
                setFqID(n, m->scopeID() + n->id()); // global scope
        }

        if ( ! n->declarationIndex() && ! n->type()->alias() ) {
            auto index = context()->register_(n);
            recordChange(n->type()->type(), util::fmt("set type's declaration to %s", index));
        }

        if ( auto* x = n->type()->type()->tryAs<type::Library>();
             x && ! n->attributes()->find(hilti::attribute::kind::Cxxname) )
            // Transfer the C++ name into an attribute.
            n->attributes()->add(context(), builder()->attribute(hilti::attribute::kind::Cxxname,
                                                                 builder()->stringLiteral(x->cxxName())));
    }

    void operator()(Expression* n) final {
        if ( n->isResolved() && ! n->isA<expression::Ctor>() ) {
            auto ctor = detail::constant_folder::foldExpression(builder(), n);
            if ( ! ctor ) {
                n->addError(ctor.error());
                return;
            }

            if ( *ctor ) {
                auto* nexpr = builder()->expressionCtor(*ctor, (*ctor)->meta());
                replaceNode(n, nexpr);
            }
        }
    }

    void operator()(expression::Keyword* n) final {
        if ( n->kind() == expression::keyword::Kind::Scope && ! n->type()->isResolved() ) {
            auto* ntype = builder()->qualifiedType(builder()->typeUnsignedInteger(64), Constness::Const);
            recordChange(n, ntype);
            n->setType(context(), ntype);
        }
    }

    void operator()(expression::ListComprehension* n) final {
        if ( ! n->type()->isResolved() && n->output()->isResolved() ) {
            auto* ntype = builder()->qualifiedType(builder()->typeList(n->output()->type()), Constness::Mutable);
            recordChange(n, ntype);
            n->setType(context(), ntype);
        }

        if ( ! n->local()->type()->isResolved() && n->input()->isResolved() ) {
            auto* container = n->input()->type();
            if ( ! container->type()->iteratorType() ) {
                n->addError("right-hand side of list comprehension is not iterable");
                return;
            }

            const auto& et = container->type()->elementType();
            recordChange(n->local(), et);
            n->local()->setType(context(), et);
        }
    }


    void operator()(expression::Name* n) final {
        if ( ! n->resolvedDeclarationIndex() ) {
            // If the expression has received a fully qualified ID, we look
            // that up directly at the root if it's scoped, otherwise the
            // original ID at the current location.
            Node* scope_node = n;
            auto id = n->fullyQualifiedID();
            if ( id && id.namespace_() )
                scope_node = builder()->context()->root();
            else
                id = n->id();

            auto resolved = scope::lookupID<Declaration>(std::move(id), scope_node, "declaration");
            if ( resolved ) {
                auto index = context()->register_(resolved->first);
                n->setResolvedDeclarationIndex(context(), index);
                recordChange(n, util::fmt("set resolved declaration to %s", index));
            }
            else {
                // If we are inside a call expression, the name may map to multiple
                // function declarations (overloads and hooks). We leave it to operator
                // resolving to figure that out and don't report an error here.
                auto* op = n->parent()->tryAs<expression::UnresolvedOperator>();
                if ( ! op || op->kind() != operator_::Kind::Call ) {
                    if ( n->id() == ID(HILTI_INTERNAL_ID("dd")) )
                        // Provide better error message
                        n->addError("$$ is not available in this context", node::ErrorPriority::High);
                    else if ( n->id() == ID("self") )
                        n->addError(resolved.error(), node::ErrorPriority::Normal); // let other errors take precedence
                                                                                    // explaining why we didn't set self
                    else
                        n->addError(resolved.error(), node::ErrorPriority::High);
                }
            }
        }
    }


    void operator()(expression::UnresolvedOperator* n) final {
        if ( n->kind() == operator_::Kind::Cast && n->areOperandsUnified() ) {
            // We hardcode that a cast<> operator can always perform any
            // legal coercion. This helps in cases where we need to force a
            // specific coercion to take place.
            static const auto* casted_coercion = operator_::get("generic::CastedCoercion");
            if ( hilti::coerceExpression(builder(), n->operands()[0],
                                         n->op1()->type()->type()->as<type::Type_>()->typeValue(),
                                         CoercionStyle::TryAllForMatching | CoercionStyle::ContextualConversion) ) {
                replaceNode(n, *casted_coercion->instantiate(builder(), n->operands(), n->meta()));
                return;
            }
        }

        // Try to resolve operator.

        std::vector<const Operator*> candidates;

        if ( n->kind() == operator_::Kind::Call ) {
            if ( ! n->op1()->isResolved() )
                return;

            auto [valid, functions] = operator_::registry().functionCallCandidates(n);
            if ( ! valid )
                return;

            candidates = *functions;
        }

        else if ( n->areOperandsUnified() ) {
            if ( n->kind() == operator_::Kind::MemberCall )
                candidates = operator_::registry().byMethodID(n->op1()->as<expression::Member>()->id());
            else
                candidates = operator_::registry().byKind(n->kind());
        }

        if ( candidates.empty() )
            return;

        auto matches = matchOperators(n, candidates, n->kind() == operator_::Kind::Cast);
        if ( matches.empty() )
            return;

        if ( matches.size() > 1 ) {
            std::vector<std::string> context = {"candidates:"};
            for ( const auto& op : matches ) {
                auto* resolved = op->as<hilti::expression::ResolvedOperator>();
                context.emplace_back(util::fmt("- %s [%s]", resolved->printSignature(), resolved->operator_().name()));
            }

            n->addError(util::fmt("operator usage is ambiguous: %s", n->printSignature()), std::move(context));
            return;
        }

        if ( auto* match = matches[0]->tryAs<expression::ResolvedOperator>() ) {
            if ( n->kind() == operator_::Kind::Call ) {
                if ( auto* ftype = match->op0()->type()->type()->tryAs<type::Function>() )
                    recordAutoParameters(*ftype, match->op1());
            }

            if ( n->kind() == operator_::Kind::MemberCall ) {
                if ( auto* stype = match->op0()->type()->type()->tryAs<type::Struct>() ) {
                    const auto& id = match->op1()->as<expression::Member>()->id();
                    if ( auto* field = stype->field(id) ) {
                        auto* ftype = field->type()->type()->as<type::Function>();
                        recordAutoParameters(*ftype, match->op2());
                    }
                }
            }
        }

        replaceNode(n, matches[0]);
    }

    void operator()(Function* n) final {
        if ( n->ftype()->result()->isAuto() ) {
            // Look for a `return` to infer the return type.
            auto v = visitor::PreOrder();
            for ( auto* const i : visitor::range(v, n, {}) ) {
                if ( auto* x = i->tryAs<statement::Return>(); x && x->expression() && x->expression()->isResolved() ) {
                    const auto& rt = x->expression()->type();
                    recordChange(n, rt, "auto return");
                    n->ftype()->setResultType(context(), rt);
                    break;
                }
            }
        }
    }

    void operator()(statement::If* n) final {
        if ( n->init() && ! n->condition() ) {
            auto* cond = builder()->expressionName(n->init()->id());
            n->setCondition(context(), cond);
            recordChange(n, cond);
        }
    }

    void operator()(statement::For* n) final {
        if ( ! n->local()->type()->isResolved() && n->sequence()->isResolved() ) {
            const auto& t = n->sequence()->type();
            if ( ! t->type()->iteratorType() ) {
                n->addError("expression is not iterable");
                return;
            }

            const auto& et = t->type()->iteratorType()->type()->dereferencedType();
            recordChange(n, et);
            n->local()->setType(context(), et);
        }
    }


    void operator()(statement::Switch* n) final { n->preprocessCases(context()); }


    void operator()(type::bitfield::BitRange* n) final {
        if ( ! n->fullyQualifiedID() )
            setFqID(n, n->id()); // local scope

        if ( ! type::isResolved(n->itemType()) ) {
            auto* t = n->ddType();

            if ( auto* a = n->attributes()->find(hilti::attribute::kind::Convert) )
                t = (*a->valueAsExpression())->type();

            if ( t->isResolved() ) {
                recordChange(n, t, "set item type");
                n->setItemTypeWithOptional(context(),
                                           builder()->qualifiedType(builder()->typeOptional(t), Constness::Const));
            }
        }
    }
};

// Pass 3 performs all coercions for expressions, constructors, and statements.
// It assumes that pass 2 has completed type inference and name/operator
// resolution, and these uses the resolved types from the AST to apply
// appropriate coercions.
struct VisitorPass3 : visitor::MutatingPostOrder {
    explicit VisitorPass3(Builder* builder) : visitor::MutatingPostOrder(builder, logging::debug::Resolver) {}

    // Coerces an expression to a given type, returning the new value if it's
    // changed from the old one. Records an error with the node if coercion is
    // not possible, and returns null then. Will indicate no-change if
    // expression or type hasn't been resolved.
    Expression* coerceTo(Node* n, Expression* e, QualifiedType* t, bool contextual, bool assignment) {
        if ( ! (e->isResolved() && t->isResolved()) )
            return nullptr;

        if ( type::same(e->type(), t) )
            return nullptr;

        bitmask<CoercionStyle> style =
            (assignment ? CoercionStyle::TryAllForAssignment : CoercionStyle::TryAllForMatching);

        if ( contextual )
            style |= CoercionStyle::ContextualConversion;

        if ( auto c = hilti::coerceExpression(builder(), e, t, style) )
            return c.nexpr;

        n->addError(util::fmt("cannot coerce expression '%s' of type '%s' to type '%s'", *e, *e->type(), *t));
        return nullptr;
    }

    // Coerces a set if expressions to the types of a corresponding set of
    // function parameters. Returns an empty result reset if coercion succeeded
    // but didn't change any expressions. Will indicate no-change also if the
    // expressions or the type aren't fully resolved yet. Returns an error if a
    // coercion failed with a hard error.
    template<typename Container1, typename Container2>
    Result<std::optional<Expressions>> coerceCallArguments(Container1 exprs, const Container2& params) {
        // Build a tuple to coerce expression according to an OperandList.
        for ( const auto& e : exprs ) {
            if ( ! e->isResolved() )
                return {std::nullopt};
        }

        auto src = builder()->expressionCtor(builder()->ctorTuple(std::move(exprs)));
        auto dst = type::OperandList::fromParameters(context(), std::move(params));

        auto coerced = coerceExpression(builder(), src, builder()->qualifiedType(dst, Constness::Const),
                                        CoercionStyle::TryAllForFunctionCall);
        if ( ! coerced )
            return result::Error("coercion failed");

        if ( ! coerced.nexpr )
            // No change.
            return {std::nullopt};

        return {coerced.nexpr->template as<expression::Ctor>()->ctor()->template as<ctor::Tuple>()->value()};
    }

    // Coerces a set of expressions all to the same destination. Returns an
    // empty result reset if coercion succeeded but didn't change any
    // expressions. Will indicate no-change also if the expressions or the type
    // aren't fully resolved yet. Returns an error if a coercion failed with a
    // hard error.
    template<typename Container>
    Result<std::optional<Expressions>> coerceExpressions(const Container& exprs, QualifiedType* dst) {
        if ( ! (dst->isResolved() && expression::areResolved(exprs)) )
            return {std::nullopt};

        bool changed = false;
        Expressions nexprs;

        for ( const auto& e : exprs ) {
            auto coerced = coerceExpression(builder(), e, dst, CoercionStyle::TryAllForAssignment);
            if ( ! coerced )
                return result::Error("coercion failed");

            if ( coerced.nexpr )
                changed = true;

            nexprs.emplace_back(std::move(*coerced.coerced));
        }

        if ( changed )
            return {std::move(nexprs)};
        else
            // No change.
            return {std::nullopt};
    }

    // Coerces a specific call argument to a given type returning the coerced
    // expression (only) if its type has changed.
    Result<Expression*> coerceMethodArgument(const expression::ResolvedOperator* o, size_t i, QualifiedType* t) {
        auto* ops = o->op2();

        // If the argument list was the result of a coercion unpack its result.
        if ( auto* coerced = ops->tryAs<expression::Coerced>() )
            ops = coerced->expression();

        auto* ctor_ = ops->as<expression::Ctor>()->ctor();

        // If the argument was the result of a coercion unpack its result.
        if ( auto* x = ctor_->tryAs<ctor::Coerced>() )
            ctor_ = x->coercedCtor();

        const auto& args = ctor_->as<ctor::Tuple>()->value();
        if ( i >= args.size() )
            return {nullptr};

        if ( auto narg = hilti::coerceExpression(builder(), args[i], t); ! narg )
            return result::Error(util::fmt("cannot coerce argument %d from %s to %s", i, *args[i]->type(), *t));
        else if ( narg.nexpr ) {
            Expressions nargs = args;
            nargs[i] = narg.nexpr;
            return {builder()->expressionCtor(builder()->ctorTuple(nargs))};
        }

        return {nullptr};
    }

    void operator()(expression::Assign* n) final {
        // Rewrite assignments to map elements to use the `index_assign` operator.
        if ( auto* index_non_const = n->target()->tryAs<operator_::map::IndexNonConst>() ) {
            const auto& map = index_non_const->op0();
            const auto& map_type = map->type()->type()->as<type::Map>();
            const auto& key_type = map_type->keyType();
            const auto& value_type = map_type->valueType();

            auto* key = index_non_const->op1();
            if ( key->type() != key_type ) {
                if ( auto* nexpr = hilti::coerceExpression(builder(), key, key_type).nexpr )
                    key = nexpr;
            }

            auto* value = n->source();
            if ( value->type() != value_type ) {
                if ( auto* nexpr = hilti::coerceExpression(builder(), value, value_type).nexpr )
                    value = nexpr;
            }

            auto* index_assign = builder()->expressionUnresolvedOperator(hilti::operator_::Kind::IndexAssign,
                                                                         {map, key, value}, n->meta());

            replaceNode(n, index_assign);
        }

        // Rewrite assignments involving tuple ctors on the LHS to use the
        // tuple's custom by-element assign operator. We need this to get
        // constness right.
        auto* lhs_ctor = n->target()->tryAs<expression::Ctor>();
        if ( lhs_ctor && lhs_ctor->ctor()->isA<ctor::Tuple>() ) {
            if ( n->source()->isResolved() && n->target()->isResolved() ) {
                const auto* op = operator_::registry().byName("tuple::CustomAssign");
                assert(op);
                auto* x = *op->instantiate(builder(), {n->target(), n->source()}, n->meta());
                replaceNode(n, x);
            }
        }

        if ( auto* x = coerceTo(n, n->source(), n->target()->type(), false, true) ) {
            recordChange(n, x, "source");
            n->setSource(context(), x);
        }
    }

    void operator()(expression::BuiltInFunction* n) final {
        if ( auto coerced = coerceCallArguments(n->arguments(), n->parameters()); coerced && *coerced ) {
            recordChange(n, builder()->ctorTuple(**coerced), "call arguments");
            n->setArguments(context(), **coerced);
        }
    }

    void operator()(expression::LogicalAnd* n) final {
        if ( auto* x = coerceTo(n, n->op0(), n->type(), true, false) ) {
            recordChange(n, x, "op0");
            n->setOp0(context(), x);
        }

        if ( auto* x = coerceTo(n, n->op1(), n->type(), true, false) ) {
            recordChange(n, x, "op1");
            n->setOp1(context(), x);
        }
    }

    void operator()(expression::LogicalNot* n) final {
        if ( auto* x = coerceTo(n, n->expression(), n->type(), true, false) ) {
            recordChange(n, x, "expression");
            n->setExpression(context(), x);
        }
    }

    void operator()(expression::LogicalOr* n) final {
        if ( auto* x = coerceTo(n, n->op0(), n->type(), true, false) ) {
            recordChange(n, x, "op0");
            n->setOp0(context(), x);
        }

        if ( auto* x = coerceTo(n, n->op1(), n->type(), true, false) ) {
            recordChange(n, x, "op1");
            n->setOp1(context(), x);
        }
    }

    void operator()(expression::ConditionTest* n) final {
        if ( n->condition()->isResolved() && ! n->condition()->type()->type()->isA<type::Bool>() ) {
            if ( auto* x = coerceTo(n, n->condition(),
                                    builder()->qualifiedType(builder()->typeBool(), Constness::Const), true, false) ) {
                recordChange(n, x, "condition");
                n->setCondition(context(), x);
            }
        }

        if ( n->error()->isResolved() && ! n->error()->type()->type()->isA<type::Error>() ) {
            if ( auto* x = coerceTo(n, n->error(), builder()->qualifiedType(builder()->typeError(), Constness::Const),
                                    true, false) ) {
                recordChange(n, x, "error");
                n->setError(context(), x);
            }
        }
    }

    void operator()(expression::PendingCoerced* n) final {
        if ( auto ner = hilti::coerceExpression(builder(), n->expression(), n->type()); ner.coerced ) {
            if ( ner.nexpr )
                // A coercion expression was created, use it.
                replaceNode(n, ner.nexpr);
            else
                replaceNode(n, n->expression());
        }
        else
            n->addError(util::fmt("cannot coerce expression '%s' to type '%s'", *n->expression(), *n->type()));
    }

    void operator()(expression::Ternary* n) final {
        if ( n->true_()->isResolved() && n->false_()->isResolved() ) {
            // Coerce the second branch to the type of the first. This isn't quite
            // ideal, but as good as we can do right now.
            if ( auto coerced = coerceExpression(builder(), n->false_(), n->true_()->type());
                 coerced && coerced.nexpr ) {
                recordChange(n, coerced.nexpr, "ternary");
                n->setFalse(context(), coerced.nexpr);
            }
        }
    }

    void operator()(operator_::generic::New* n) final {
        if ( auto* etype = n->op0()->type()->type()->tryAs<type::Type_>();
             etype && ! etype->typeValue()->type()->parameters().empty() ) {
            auto* ctor = n->op1()->as<expression::Ctor>()->ctor();

            if ( auto* x = ctor->tryAs<ctor::Coerced>() )
                ctor = x->coercedCtor();

            auto args = ctor->as<ctor::Tuple>()->value();

            if ( auto coerced = coerceCallArguments(args, etype->typeValue()->type()->parameters());
                 coerced && *coerced ) {
                auto* ntuple = builder()->expressionCtor(builder()->ctorTuple(**coerced), n->op1()->meta());
                recordChange(n, ntuple, "type arguments");
                n->setOp1(context(), ntuple);
            }
        }
    }

    void operator()(operator_::function::Call* n) final {
        auto* ctor = n->op1()->as<expression::Ctor>()->ctor();

        if ( auto* x = ctor->tryAs<ctor::Coerced>() )
            ctor = x->coercedCtor();

        auto args = ctor->as<ctor::Tuple>()->value();

        auto* decl = context()->lookup(n->op0()->as<expression::Name>()->resolvedDeclarationIndex());
        auto* f = decl->as<declaration::Function>();
        if ( auto coerced = coerceCallArguments(args, f->function()->ftype()->parameters()); coerced && *coerced ) {
            auto* ntuple = builder()->expressionCtor(builder()->ctorTuple(**coerced), n->op1()->meta());
            recordChange(n, ntuple, "type arguments");
            n->setOp1(context(), ntuple);
        }
    }

    void operator()(operator_::map::Get* n) final {
        if ( auto nargs = coerceMethodArgument(n, 1, n->result()) ) {
            if ( *nargs ) {
                recordChange(n, *nargs, "default value");
                n->setOp2(context(), *nargs);
            }
        }
        else
            n->addError(nargs.error());
    }

    // TODO(bbannier): Ideally instead of inserting this coercion we would
    // define the operator to take some `keyType` derived from the type of the
    // passed `map` and perform the coercion automatically when resolving the
    // function call.
    void operator()(operator_::map::In* n) final {
        auto* op0 = n->op0()->type()->type()->tryAs<type::Map>();
        if ( ! op0 )
            return;

        if ( auto* x = coerceTo(n, n->op0(), op0->keyType(), true, false) ) {
            recordChange(n, x, "call argument");
            n->setOp0(context(), x);
        }
    }

    // TODO(bbannier): Ideally instead of inserting this coercion we would
    // define the operator to take some `elementType` derived from the type of the
    // passed `set` and perform the coercion automatically when resolving the
    // function call.
    void operator()(operator_::set::In* n) final {
        auto* op1 = n->op1()->type()->type()->tryAs<type::Set>();
        if ( ! op1 )
            return;

        if ( auto* x = coerceTo(n, n->op0(), op1->elementType(), true, false) ) {
            recordChange(n, x, "call argument");
            n->setOp0(context(), x);
        }
    }

    void operator()(operator_::tuple::CustomAssign* n) final {
        if ( n->op0()->isResolved() && n->op1()->isResolved() ) {
            auto* lhs = n->op0()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>();

            if ( ! type::same(lhs->type(), n->op1()->type()) ) {
                auto* lhs_type = lhs->type()->type()->as<type::Tuple>();
                auto* rhs_type = n->op1()->type()->type()->tryAs<type::Tuple>();

                if ( rhs_type && lhs_type->elements().size() ==
                                     rhs_type->elements().size() ) { // validator will report if not same size
                    Expressions new_elems;

                    const auto& lhs_type_elements = lhs_type->elements();
                    const auto& rhs_type_elements = rhs_type->elements();

                    auto [op1, new_rhs] = builder()->groupingWithTmp("tuple", n->op1());

                    for ( auto i = 0U; i < lhs_type->elements().size(); i++ ) {
                        static const auto* op = operator_::get("tuple::Index");
                        const auto& lhs_elem_type = lhs_type_elements[i]->type();
                        auto* rhs_elem_type = rhs_type_elements[i]->type();
                        auto* rhs_elem =
                            builder()->expressionTypeWrapped(*op->instantiate(builder(),
                                                                              {builder()->typeWrapped(op1,
                                                                                                      n->op1()->type()),
                                                                               builder()->integer(i)},
                                                                              n->meta()),
                                                             rhs_elem_type);


                        if ( auto* x = coerceTo(n, rhs_elem, lhs_elem_type, false, true) )
                            new_elems.push_back(x);
                        else
                            new_elems.push_back(rhs_elem);
                    }

                    new_rhs->setExpression(context(), builder()->tuple(new_elems));
                    recordChange(n->op1(), new_rhs, "tuple assign");
                    n->setOp1(context(), new_rhs);
                }
            }
        }
    }

    void operator()(operator_::vector::PushBack* n) final {
        if ( n->op0()->isResolved() && n->op2()->isResolved() ) {
            // Need to coerce the element here as the normal overload resolution
            // couldn't know the element type yet.
            auto* etype = n->op0()->type()->type()->as<type::Vector>()->elementType();
            if ( auto* x =
                     coerceTo(n, n->op2(), builder()->qualifiedType(builder()->typeTuple({etype}), Constness::Const),
                              false, true) ) {
                recordChange(n, x, "element type");
                n->setOp2(context(), x);
            }
        }
    }

    void operator()(statement::Assert* n) final {
        if ( ! n->expectException() && ! n->expression()->type()->type()->isA<type::Result>() ) {
            if ( auto* x = coerceTo(n, n->expression(),
                                    builder()->qualifiedType(builder()->typeBool(), Constness::Const), true, false) ) {
                recordChange(n, x, "expression");
                n->setExpression(context(), x);
            }
        }
    }

    void operator()(statement::If* n) final {
        if ( auto* cond = n->condition() ) {
            if ( auto* x = coerceTo(n, cond, builder()->qualifiedType(builder()->typeBool(), Constness::Const), true,
                                    false) ) {
                recordChange(n, x, "condition");
                n->setCondition(context(), x);
            }
        }

        if ( n->init() && ! n->condition() ) {
            auto* cond = builder()->expressionName(n->init()->id());
            n->setCondition(context(), cond);
            recordChange(n, cond);
        }
    }

    void operator()(statement::Return* n) final {
        auto* func = n->parent<Function>();
        if ( ! func ) {
            n->addError("return outside of function");
            return;
        }

        if ( auto* e = n->expression() ) {
            const auto& t = func->ftype()->result();

            if ( auto* x = coerceTo(n, e, t, false, true) ) {
                recordChange(n, x, "expression");
                n->setExpression(context(), x);
            }
        }
    }

    void operator()(statement::While* n) final {
        if ( auto* cond = n->condition() ) {
            if ( auto* x = coerceTo(n, cond, builder()->qualifiedType(builder()->typeBool(), Constness::Const), true,
                                    false) ) {
                recordChange(n, x, "condition");
                n->setCondition(context(), x);
            }
        }
    }

    void operator()(ctor::Default* n) final {
        // If a type is a reference type, dereference it; otherwise return the type itself.
        auto skip_ref = [](QualifiedType* t) -> QualifiedType* {
            if ( t && t->type()->isReferenceType() )
                return t->type()->dereferencedType();
            else
                return t;
        };

        if ( auto* t = skip_ref(n->type()); t->isResolved() ) {
            if ( ! t->type()->parameters().empty() ) {
                if ( auto x = n->typeArguments(); x.size() ) {
                    if ( auto coerced = coerceCallArguments(x, t->type()->parameters()); coerced && *coerced ) {
                        recordChange(n, builder()->ctorTuple(**coerced), "call arguments");
                        n->setTypeArguments(context(), **coerced);
                    }
                }
            }
        }
    }

    void operator()(ctor::List* n) final {
        if ( auto coerced = coerceExpressions(n->value(), n->elementType()); coerced && *coerced ) {
            recordChange(n, builder()->ctorTuple(**coerced), "elements");
            n->setValue(context(), **coerced);
        }
    }

    void operator()(ctor::Map* n) final {
        bool changed = false;
        ctor::map::Elements nelems;
        for ( const auto& e : n->value() ) {
            auto k = coerceExpression(builder(), e->key(), n->keyType());
            auto v = coerceExpression(builder(), e->value(), n->valueType());
            if ( ! (k && v) ) {
                changed = false;
                break;
            }

            if ( k.nexpr || v.nexpr ) {
                nelems.emplace_back(builder()->ctorMapElement(*k.coerced, *v.coerced));
                changed = true;
            }
            else
                nelems.push_back(e);
        }

        if ( changed ) {
            recordChange(n, builder()->ctorMap(nelems), "value");
            n->setValue(context(), nelems);
        }
    }

    void operator()(ctor::Set* n) final {
        if ( auto coerced = coerceExpressions(n->value(), n->elementType()); coerced && *coerced ) {
            recordChange(n, builder()->ctorTuple(**coerced), "elements");
            n->setValue(context(), **coerced);
        }
    }

    void operator()(ctor::Vector* n) final {
        if ( auto coerced = coerceExpressions(n->value(), n->elementType()); coerced && *coerced ) {
            recordChange(n, builder()->ctorTuple(**coerced), "elements");
            n->setValue(context(), **coerced);
        }
    }

    void operator()(declaration::Constant* n) final {
        if ( auto* x = coerceTo(n, n->value(), n->type()->recreateAsLhs(context()), false, true) ) {
            recordChange(n, x, "value");
            n->setValue(context(), x);
        }
    }

    void operator()(declaration::Field* n) final {
        if ( auto* a = n->attributes()->find(hilti::attribute::kind::Default) ) {
            auto val = a->valueAsExpression();
            if ( auto* x = coerceTo(n, *val, n->type(), false, true) ) {
                recordChange(*val, x, "attribute");
                n->attributes()->remove(hilti::attribute::kind::Default);
                n->attributes()->add(context(), builder()->attribute(hilti::attribute::kind::Default, x));
            }
        }
    }

    void operator()(declaration::GlobalVariable* n) final {
        Expression* init = nullptr;
        std::optional<Expressions> args;

        if ( auto* e = n->init(); e && ! type::sameExceptForConstness(n->type(), e->type()) ) {
            if ( auto* x = coerceTo(n, e, n->type(), false, true) )
                init = x;
        }

        if ( n->type()->isResolved() && (! n->type()->type()->parameters().empty()) && n->typeArguments().size() ) {
            auto coerced = coerceCallArguments(n->typeArguments(), n->type()->type()->parameters());
            if ( coerced && *coerced )
                args = std::move(*coerced);
        }

        if ( init || args ) {
            if ( init ) {
                recordChange(n, init, "init expression");
                n->setInit(context(), init);
            }

            if ( args ) {
                recordChange(n, builder()->ctorTuple(*args), "type arguments");
                n->setTypeArguments(context(), std::move(*args));
            }
        }
    }

    void operator()(declaration::LocalVariable* n) final {
        Expression* init = nullptr;
        std::optional<Expressions> args;

        if ( auto* e = n->init(); e && ! e->isA<expression::Void>() ) {
            if ( auto* x = coerceTo(n, e, n->type(), false, true) )
                init = x;
        }

        if ( (! n->type()->type()->parameters().empty()) && n->typeArguments().size() ) {
            auto coerced = coerceCallArguments(n->typeArguments(), n->type()->type()->parameters());
            if ( coerced && *coerced )
                args = std::move(*coerced);
        }

        if ( init || args ) {
            if ( init ) {
                recordChange(n, init, "init expression");
                n->setInit(context(), init);
            }

            if ( args ) {
                recordChange(n, builder()->ctorTuple(*args), "type arguments");
                n->setTypeArguments(context(), std::move(*args));
            }
        }
    }

    void operator()(declaration::Parameter* n) final {
        if ( auto* def = n->default_() ) {
            if ( auto* x = coerceTo(n, def, n->type(), false, true) ) {
                recordChange(n, x, "default value");
                n->setDefault(context(), x);
            }
        }
    }

    void operator()(type::bitfield::BitRange* n) final {
        if ( n->ctorValue() ) {
            if ( auto* x = coerceTo(n, n->ctorValue(), n->itemType(), false, true) ) {
                recordChange(n, x, "bits value");
                n->setCtorValue(context(), x);
            }
        }
    }
};

// Pass 4 resolves any auto parameters that we inferred during the previous resolver pass.
struct VisitorPass4 : visitor::MutatingPostOrder {
    VisitorPass4(Builder* builder, const ::VisitorPass2& v)
        : visitor::MutatingPostOrder(builder, logging::debug::Resolver), resolver(v) {}

    const ::VisitorPass2& resolver;

    void operator()(declaration::Parameter* n) final {
        if ( ! n->type()->type()->isA<type::Auto>() )
            return;

        auto i = resolver.auto_params.end();

        if ( n->canonicalID() )
            i = resolver.auto_params.find(n->canonicalID());

        if ( i == resolver.auto_params.end() ) {
            if ( auto* d = n->parent<declaration::Function>(); d && d->linkedPrototypeIndex() ) {
                auto* prototype = builder()->context()->lookup(d->linkedPrototypeIndex());

                type::Function* ftype = nullptr;
                if ( auto* f = prototype->tryAs<declaration::Function>() )
                    ftype = f->function()->ftype();

                if ( auto* f = prototype->tryAs<declaration::Field>() )
                    ftype = f->type()->type()->tryAs<type::Function>();

                if ( ftype ) {
                    for ( const auto& p : ftype->parameters() ) {
                        if ( p->canonicalID() && p->id() == n->id() )
                            i = resolver.auto_params.find(p->canonicalID());
                    }
                }
            }
        }

        if ( i != resolver.auto_params.end() ) {
            recordChange(n, i->second);
            n->setType(context(), i->second);
        }
    }
};

} // anonymous namespace

bool detail::resolver::resolve(Builder* builder, Node* node) {
    auto v1 = VisitorPass1(builder);
    hilti::visitor::visit(v1, node);

    auto v2 = VisitorPass2(builder);
    hilti::visitor::visit(v2, node);

    auto v3 = VisitorPass3(builder);
    hilti::visitor::visit(v3, node);

    auto v4 = VisitorPass4(builder, v2);
    hilti::visitor::visit(v4, node);

    return v1.isModified() || v2.isModified() || v3.isModified() || v4.isModified();
}
