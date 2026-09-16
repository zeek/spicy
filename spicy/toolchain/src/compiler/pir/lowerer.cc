// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <string>
#include <variant>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/function.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/statements/return.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/integer.h>
#include <hilti/base/util.h>

#include <spicy/ast/types/unit.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/pir/lowerer.h>

using hilti::util::fmt;

namespace spicy::detail::pir {

namespace {

// Read-only visitor collecting candidate public roots in source order.
struct VisitorRoots : public visitor::PreOrder {
    std::vector<hilti::Declaration*> roots;

    static bool skipsImplementation(hilti::Declaration* n) {
        auto* m = n->parent<hilti::declaration::Module>();
        return m && m->skipImplementation();
    }

    void operator()(hilti::declaration::Function* n) final {
        if ( n->isPublic() && ! skipsImplementation(n) )
            roots.push_back(n);
    }

    void operator()(hilti::declaration::Type* n) final {
        auto* unit = n->type()->type()->tryAs<type::Unit>();
        if ( ! unit )
            return;

        // An alias declaration (`public type Alias = Original;`) has its own linkage, separate
        // from the original unit's. `unit->isPublic()` reflects the *original* declaration, so
        // it must not be used to decide the alias's own visibility.
        bool is_public = n->type()->alias() ? n->isPublic() : unit->isPublic();

        if ( is_public && ! skipsImplementation(n) )
            roots.push_back(n);
    }
};

ir::SourceSpanId internSpan(ir::Package& package, const hilti::Location& loc) {
    if ( ! loc )
        return {};

    auto file = package.sourceManager().internFile(loc.file());
    return package.sourceManager().addSpan(ir::SourceSpan{
        .file = file,
        .begin_line = loc.from(),
        .begin_column = loc.fromCharacter(),
        .end_line = loc.to(),
        .end_column = loc.toCharacter(),
    });
}

UnsupportedFeature unsupported(const std::string& feature, std::string reason, const hilti::Location& loc) {
    return UnsupportedFeature{.feature = feature, .reason = std::move(reason), .location = loc};
}

// Lowers a resolved expression, restricted to int64 literals and signed-integer addition. Returns
// the produced instruction, or the unsupported feature that kept it from being represented.
class ExpressionLowerer {
public:
    ExpressionLowerer(ir::Package& package, ir::BlockId block, std::string function_feature)
        : _package(package), _block(block), _function_feature(std::move(function_feature)) {}

    std::variant<ir::InstId, UnsupportedFeature> lower(hilti::Expression* expr) {
        if ( auto* ctor_expr = expr->tryAs<hilti::expression::Ctor>() )
            return _lowerCtor(ctor_expr->ctor(), expr->meta().location());

        if ( auto* op = expr->tryAs<hilti::expression::ResolvedOperator>() )
            return _lowerSum(op);

        return _unsupported("unsupported return expression", expr->meta().location());
    }

private:
    std::variant<ir::InstId, UnsupportedFeature> _lowerCtor(hilti::Ctor* ctor, const hilti::Location& loc) {
        if ( auto* coerced = ctor->tryAs<hilti::ctor::Coerced>() )
            ctor = coerced->coercedCtor();

        auto* literal = ctor->tryAs<hilti::ctor::SignedInteger>();
        if ( ! literal || literal->width() != 64 )
            return _unsupported("only signed 64-bit integer literals are supported", loc);

        return _package.addConstant(_block, literal->value(), internSpan(_package, loc));
    }

    std::variant<ir::InstId, UnsupportedFeature> _lowerSum(hilti::expression::ResolvedOperator* op) {
        if ( op->kind() != hilti::operator_::Kind::Sum )
            return _unsupported("only signed-integer addition is supported", op->meta().location());

        auto* result_type = op->result()->type()->tryAs<hilti::type::SignedInteger>();
        if ( ! result_type || result_type->width() != 64 )
            return _unsupported("only signed 64-bit integer addition is supported", op->meta().location());

        auto lhs = lower(op->op0());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&lhs) )
            return *feature;

        auto rhs = lower(op->op1());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&rhs) )
            return *feature;

        return _package.addAdd(_block,
                               std::get<ir::InstId>(lhs),
                               std::get<ir::InstId>(rhs),
                               internSpan(_package, op->meta().location()));
    }

    UnsupportedFeature _unsupported(std::string reason, const hilti::Location& loc) {
        return unsupported(_function_feature, std::move(reason), loc);
    }

    ir::Package& _package;
    ir::BlockId _block;
    std::string _function_feature;
};

std::optional<UnsupportedFeature> lowerFunction(hilti::declaration::Function* decl, ir::Package& package) {
    auto feature = fmt("function '%s'", std::string(decl->id()));
    auto* fn = decl->function();
    auto* ftype = fn->ftype();

    if ( ftype->flavor() != hilti::type::function::Flavor::Function )
        return unsupported(feature, "only ordinary functions are supported", decl->meta().location());

    if ( ftype->callingConvention() != hilti::type::function::CallingConvention::Standard )
        return unsupported(feature, "only the standard calling convention is supported", decl->meta().location());

    if ( ! ftype->parameters().empty() )
        return unsupported(feature, "parameters are not supported", decl->meta().location());

    auto* result_type = ftype->result()->type()->tryAs<hilti::type::SignedInteger>();
    if ( ! result_type || result_type->width() != 64 )
        return unsupported(feature, "only a signed 64-bit integer result is supported", decl->meta().location());

    auto* body = fn->body();
    if ( ! body || body->statements().size() != 1 )
        return unsupported(feature,
                           "only a body consisting of a single return statement is supported",
                           decl->meta().location());

    auto* ret = body->statements()[0]->tryAs<hilti::statement::Return>();
    if ( ! ret )
        return unsupported(feature, "only a return statement is supported", decl->meta().location());

    if ( ! ret->expression() )
        return unsupported(feature, "a return value is required", decl->meta().location());

    auto pir_fn = package.createFunction(std::string(decl->id().local()),
                                         package.int64Type(),
                                         internSpan(package, decl->meta().location()));
    auto block = package.createBlock(package.function(pir_fn).root_region);

    ExpressionLowerer lowerer(package, block, feature);
    auto value = lowerer.lower(ret->expression());
    if ( auto* unsupported_feature = std::get_if<UnsupportedFeature>(&value) )
        return *unsupported_feature;

    package.addReturn(block, std::get<ir::InstId>(value), internSpan(package, ret->meta().location()));
    return std::nullopt;
}

} // namespace

std::vector<hilti::Declaration*> discoverRoots(const hilti::ASTContext& ctx) {
    auto v = VisitorRoots();
    visitor::visit(v, ctx.root(), ".spicy");
    return v.roots;
}

std::optional<UnsupportedFeature> lowerRoots(const std::vector<hilti::Declaration*>& roots, ir::Package& package) {
    for ( auto* decl : roots ) {
        if ( auto* fn_decl = decl->tryAs<hilti::declaration::Function>() ) {
            if ( auto feature = lowerFunction(fn_decl, package) )
                return feature;

            continue;
        }

        if ( auto* type_decl = decl->tryAs<hilti::declaration::Type>() ) {
            auto feature = type_decl->type()->alias() ? fmt("public unit alias '%s'", std::string(type_decl->id())) :
                                                        fmt("parser unit '%s'", std::string(type_decl->id()));
            return unsupported(feature, "parser units are not supported yet", type_decl->meta().location());
        }
    }

    return std::nullopt;
}

} // namespace spicy::detail::pir
