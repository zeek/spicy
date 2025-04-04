// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/operand-list.h>

using namespace hilti;
using namespace hilti::type;

QualifiedType* operand_list::Operand::_makeOperandType(ASTContext* ctx, parameter::Kind kind, UnqualifiedType* type,
                                                       bool make_external_type) {
    QualifiedType* qtype = nullptr;

    switch ( kind ) {
        case parameter::Kind::In:
        case parameter::Kind::Copy:
            if ( make_external_type )
                qtype = QualifiedType::createExternal(ctx, type, Constness::Const, Side::RHS, type->meta());
            else
                qtype = QualifiedType::create(ctx, type, Constness::Const, Side::RHS, type->meta());

            break;

        case parameter::Kind::InOut:
            if ( make_external_type )
                qtype = QualifiedType::createExternal(ctx, type, Constness::Mutable, Side::LHS, type->meta());
            else
                qtype = QualifiedType::create(ctx, type, Constness::Mutable, Side::LHS, type->meta());

            break;

        case parameter::Kind::Unknown: logger().internalError("unknown operand kind"); break;
    }

    qtype->type()->unify(ctx, ctx->root());
    return qtype;
}
