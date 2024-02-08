// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <optional>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/list.h>
#include <hilti/ast/types/map.h>
#include <hilti/ast/types/name.h>
#include <hilti/ast/types/optional.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/result.h>
#include <hilti/ast/types/set.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/types/type.h>
#include <hilti/ast/types/union.h>
#include <hilti/ast/types/vector.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/type-unifier.h>

using namespace hilti;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream TypeUnifier("type-unifier");
} // namespace hilti::logging::debug

namespace {

// Computes the unified serialization of single unqualified type.
class VisitorSerializer : public visitor::PostOrder {
public:
    VisitorSerializer(type_unifier::Unifier* unifier) : unifier(unifier) {}

    type_unifier::Unifier* unifier;

    void operator()(type::Auto* n) final {
        // We never set this, so that it will be unified once the actual type
        // has been identified.
        unifier->abort();
    }

    void operator()(type::Bitfield* n) final {
        unifier->add("bitfield(");
        unifier->add(util::fmt("%u", n->width()));
        unifier->add(",");
        for ( const auto& b : n->bits() ) {
            unifier->add(util::fmt("%s:%u:%u", b->id(), b->lower(), b->upper()));
            unifier->add(",");
        }
        unifier->add(")");
    }

    void operator()(type::Function* n) final {
        unifier->add("function(result:");
        unifier->add(n->result());
        for ( const auto& p : n->parameters() ) {
            unifier->add(", ");
            unifier->add(p->type());
        }
        unifier->add(")");
    }

    void operator()(type::List* n) final {
        unifier->add("list(");
        unifier->add(n->elementType());
        unifier->add(")");
    }

    void operator()(type::Map* n) final {
        unifier->add("map(");
        unifier->add(n->keyType());
        unifier->add("->");
        unifier->add(n->valueType());
        unifier->add(")");
    }

    void operator()(type::OperandList* n) final {
        unifier->add("operand-list(");
        for ( const auto& op : n->operands() ) {
            unifier->add(to_string(op->kind()));
            unifier->add(op->id());
            unifier->add(":");
            unifier->add(op->type()->type().get());
            unifier->add(",");
        }
        unifier->add(")");
    }

    void operator()(type::Optional* n) final {
        unifier->add("optional(");
        unifier->add(n->dereferencedType());
        unifier->add(")");
    }

    void operator()(type::Result* n) final {
        unifier->add("result(");
        unifier->add(n->dereferencedType());
        unifier->add(")");
    }

    void operator()(type::Set* n) final {
        unifier->add("set(");
        unifier->add(n->elementType());
        unifier->add(")");
    }

    void operator()(type::StrongReference* n) final {
        unifier->add("strong_ref(");
        unifier->add(n->dereferencedType());
        unifier->add(")");
    }

    void operator()(type::Tuple* n) final {
        unifier->add("tuple(");
        for ( const auto& t : n->elements() ) {
            unifier->add(t->type());
            unifier->add(",");
        }
        unifier->add(")");
    }

    void operator()(type::Type_* n) final {
        unifier->add("type(");
        unifier->add(n->typeValue());
        unifier->add(")");
    }

    void operator()(type::ValueReference* n) final {
        unifier->add("value_ref(");
        unifier->add(n->dereferencedType());
        unifier->add(")");
    }

    void operator()(type::Vector* n) final {
        unifier->add("vector(");
        unifier->add(n->elementType());
        unifier->add(")");
    }

    void operator()(type::WeakReference* n) final {
        unifier->add("weak_ref(");
        unifier->add(n->dereferencedType());
        unifier->add(")");
    }

    void operator()(type::list::Iterator* n) final {
        unifier->add("iterator(list(");
        unifier->add(n->dereferencedType());
        unifier->add("))");
    }

    void operator()(type::map::Iterator* n) final {
        unifier->add("iterator(map(");
        unifier->add(n->keyType());
        unifier->add("->");
        unifier->add(n->valueType());
        unifier->add("))");
    }

    void operator()(type::set::Iterator* n) final {
        unifier->add("iterator(set(");
        unifier->add(n->dereferencedType());
        unifier->add("))");
    }

    void operator()(type::vector::Iterator* n) final {
        unifier->add("iterator(vector(");
        unifier->add(n->dereferencedType());
        unifier->add("))");
    }
};

// Unifies all types in an AST.
class VisitorTypeUnifier : public visitor::MutatingPostOrder {
public:
    explicit VisitorTypeUnifier(ASTContext* ctx) : visitor::MutatingPostOrder(ctx, logging::debug::TypeUnifier) {}

    type_unifier::Unifier unifier;

    void operator()(UnqualifiedType* n) final {
        if ( n->unification() )
            return;

        unifier.reset();
        unifier.add(n);

        if ( unifier.isAborted() )
            return;

        auto serial = unifier.serialization();
        if ( serial.empty() ) {
            std::cerr << n->dump();
            logger().internalError("empty type _serialization for unification, type not implemented?");
        }

        n->setUnification(type::Unification(serial));
        recordChange(n, util::fmt("unified type: %s", n->unification().str()));
    }
};

} // namespace

void type_unifier::Unifier::add(UnqualifiedType* t) {
    if ( _abort )
        return;

    if ( auto name = t->tryAs<type::Name>() ) {
        t = name->resolvedType().get();
        if ( ! t ) {
            abort();
            return;
        }
    }

    if ( t->unification() )
        add(t->unification());

    else if ( t->isNameType() ) {
        if ( const auto& id = t->canonicalID() )
            add(util::fmt("name(%s)", id));

        else if ( auto e = t->tryAs<type::Exception>(); e && ! e->baseType() )
            add("exception"); // special-case because the basic `exception` type by itself doesn't have an associated
                              // type ID
        else
            abort();
    }
    else {
        if ( t->isWildcard() )
            // Should have been preset.
            logger().internalError(util::fmt("unresolved wildcard type during unification: %s", t->typename_()));

        for ( const auto& p : plugin::registry().plugins() ) {
            if ( p.unify_type && (*p.unify_type)(this, t) )
                return;
        }
    }
}

void type_unifier::Unifier::add(const QualifiedTypePtr& t) {
    if ( _abort )
        return;

    if ( t->type()->unification() )
        add(t->type()->unification());
    else
        add(t->type().get());
}

void type_unifier::Unifier::add(const std::string& s) { _serial += s; }

// Public entry function going through all plugins.
bool type_unifier::unify(Builder* builder, const ASTRootPtr& root) {
    util::timing::Collector _("hilti/compiler/ast/type-unifier");

    return hilti::visitor::visit(VisitorTypeUnifier(builder->context()), root, {},
                                 [](const auto& v) { return v.isModified(); });
}

// Public entry function going through all plugins.
bool type_unifier::unify(ASTContext* ctx, const UnqualifiedTypePtr& type) {
    util::timing::Collector _("hilti/compiler/ast/type-unifier");

    if ( ! type->unification() )
        hilti::visitor::visit(VisitorTypeUnifier(ctx), type);

    return type->unification();
}

// Plugin-specific unification.
bool type_unifier::detail::unifyType(type_unifier::Unifier* unifier, UnqualifiedType* t) {
    util::timing::Collector _("hilti/compiler/ast/type-unifier");

    auto old_size = unifier->serialization().size();
    VisitorSerializer(unifier).dispatch(t);
    return old_size != unifier->serialization().size();
}
