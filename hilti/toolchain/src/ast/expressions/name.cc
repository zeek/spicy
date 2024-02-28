// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <functional>

#include <hilti/ast/declarations/all.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/types/type.h>
#include <hilti/base/logger.h>

using namespace hilti;

QualifiedTypePtr expression::Name::type() const {
    struct Visitor : hilti::visitor::PreOrder {
        Visitor(const Name* name) : name(name) {}

        const Name* name = nullptr;
        QualifiedTypePtr result = nullptr;

        void operator()(declaration::Constant* n) final { result = n->type(); }
        void operator()(declaration::Expression* n) final { result = n->expression()->type(); }
        void operator()(declaration::Field* n) final { result = n->type(); }
        void operator()(declaration::Function* n) final { result = n->function()->type(); }
        void operator()(declaration::GlobalVariable* n) final { result = n->type(); }
        void operator()(declaration::LocalVariable* n) final { result = n->type(); }
        void operator()(declaration::Parameter* n) final { result = n->type(); }
        void operator()(declaration::Type* n) final { result = name->child<QualifiedType>(0); }
    };

    if ( auto decl = _context->lookup(_resolved_declaration_index) ) {
        if ( auto type = visitor::dispatch(Visitor(this), decl, [](const auto& x) { return x.result; }) )
            return type;
        else
            logger().internalError(util::fmt("unsupported declaration type %s", decl->typename_()), this);
    }
    else {
        assert(! children().empty()); // setting _resolved should have cleared children
        return child<QualifiedType>(0);
    }
}

void expression::Name::setResolvedDeclarationIndex(ASTContext* ctx, ast::DeclarationIndex index) {
    assert(index);
    _resolved_declaration_index = index;
    clearChildren();

    // Special-case: If the ID refers to a type declaration, we want the
    // expression type to be `type::Type_`, wrapping the target type.
    if ( auto d = resolvedDeclaration()->tryAs<declaration::Type>() )
        addChild(ctx,
                 QualifiedType::create(ctx,
                                       type::Type_::create(ctx, QualifiedType::createExternal(ctx, d->type()->type(),
                                                                                              Constness::Const)),
                                       Constness::Const));
}

node::Properties expression::Name::properties() const {
    auto p = node::Properties{{"id", _id},
                              {"fqid", _fqid},
                              {"resolved-declaration", to_string(_resolved_declaration_index)}};

    if ( auto t = type() )
        p["resolved-unified"] = t->type()->unification().str();
    else
        p["resolved-unified"] = "-";

    return Expression::properties() + p;
}
