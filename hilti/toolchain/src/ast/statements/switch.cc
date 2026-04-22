// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/statements/switch.h>

using namespace hilti;

statement::switch_::Case::~Case() = default;

std::string statement::switch_::Case::_dump() const { return ""; }

Expressions statement::switch_::Case::preprocessedExpressions() const {
    Expressions result;

    for ( const auto* e : preprocessedComparisonOperators() ) {
        if ( const auto* op = e->template tryAs<expression::ResolvedOperator>() ) {
            result.push_back(op->op1());
        }
    }

    return result;
}

void statement::switch_::Case::removeExpression(hilti::Expression* e) {
    for ( int i = 1; i < _end_exprs; i++ ) {
        if ( auto* child_ = child(i); child_ == e ) {
            child(_end_exprs + i - 1)->removeFromParent();
            child_->removeFromParent();
            _end_exprs--;
            return;
        }
    }
}
