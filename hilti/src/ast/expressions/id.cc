// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/all.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/types/type.h>

using namespace hilti;

Type expression::ResolvedID::type() const {
    struct Visitor : hilti::visitor::PreOrder<Type, Visitor> {
        result_t operator()(const declaration::Constant& c) { return c.value().type(); }
        result_t operator()(const declaration::Expression& e) { return e.expression().type(); }
        result_t operator()(const declaration::Forward& f) { return *dispatch(f.callback()()); }
        result_t operator()(const declaration::Function& f) { return f.function().type(); }
        result_t operator()(const declaration::GlobalVariable& v) { return v.type(); }
        result_t operator()(const declaration::LocalVariable& v) { return v.type(); }
        result_t operator()(const declaration::Parameter& p) { return p.type(); }
        result_t operator()(const declaration::Type& t) { return type::Type_(t.type(), t.meta()); }
    };

    if ( ! isValid() )
        return type::unknown;

    if ( auto x = Visitor().dispatch(Node(declaration())) )
        return *x;

    logger().internalError(util::fmt("unsupported declaration type %s", declaration().typename_()), *this);
}

bool expression::ResolvedID::isConstant() const {
    struct Visitor : hilti::visitor::PreOrder<bool, Visitor> {
        result_t operator()(const declaration::Constant& c) { return true; } // NOLINT
        result_t operator()(const declaration::Expression& e) { return e.expression().isConstant(); }
        result_t operator()(const declaration::Forward& f) { return *dispatch(f.callback()()); }
        result_t operator()(const declaration::Function& f) { return true; } // NOLINT
        result_t operator()(const declaration::GlobalVariable& v) { return v.isConstant(); }
        result_t operator()(const declaration::LocalVariable& v) { return v.isConstant(); }
        result_t operator()(const declaration::Parameter& p) { return p.isConstant(); }
    };

    if ( auto x = Visitor().dispatch(declaration()) )
        return *x;

    logger().internalError(util::fmt("unsupported declaration type %s", declaration().typename_()), *this);
}
