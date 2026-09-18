// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
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

#include <spicy/ast/declarations/hook.h>
#include <spicy/ast/declarations/unit-hook.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/pir/lowerer.h>

using hilti::util::fmt;

namespace spicy::detail::pir {

namespace {

// Read-only visitor collecting candidate public roots, plus every unit type targeted by an
// external (module-level) hook declaration, in one AST walk.
struct VisitorRoots : public visitor::PreOrder {
    std::vector<hilti::Declaration*> roots;
    std::vector<hilti::ast::TypeIndex> units_with_external_hooks;

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

    // `on Unit::field { ... }` or `on Unit::%init { ... }` written at module level, outside the
    // unit's own body. `Hook::unitTypeIndex()` is resolved by the compiler's resolver pass ahead
    // of PIR, so it is already valid by the time discovery runs.
    void operator()(spicy::declaration::UnitHook* n) final {
        if ( auto index = n->hook()->unitTypeIndex() )
            units_with_external_hooks.push_back(index);
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

// Validates and lowers a non-alias public unit against Step 3's exact accepted subset: a single
// plain, unsigned 8-bit integer field with no parameters, attributes, context type, or other unit
// items. Any field/unit shape outside that subset is reported precisely and lowers nothing.
std::optional<UnsupportedFeature> lowerUnit(hilti::declaration::Type* decl,
                                            const std::vector<hilti::ast::TypeIndex>& units_with_external_hooks,
                                            ir::Package& package) {
    auto* unit = decl->type()->type()->as<type::Unit>();
    auto feature = fmt("parser unit '%s'", std::string(decl->id()));
    auto unit_loc = decl->meta().location();

    auto unsupported_here = [&](std::string reason, const hilti::Location& loc) {
        return unsupported(feature, std::move(reason), loc);
    };

    // A filter-capable unit or one with a hook attached anywhere (embedded hooks inside the unit
    // body are already excluded below by the single-item check; a hook declared external to the
    // unit is not a child of `unit->items()` at all, so it must be checked against the whole-AST
    // discovery pass instead) may run procedural logic PIR does not yet represent.
    if ( unit->mayHaveFilter() )
        return unsupported_here("units that may have a filter attached are not supported yet", unit_loc);

    if ( std::ranges::find(units_with_external_hooks, unit->typeIndex()) != units_with_external_hooks.end() )
        return unsupported_here("units with an external hook are not supported yet", unit_loc);

    if ( ! unit->parameters().empty() )
        return unsupported_here("parser units with parameters are not supported yet", unit_loc);

    if ( unit->attributes() && *unit->attributes() )
        return unsupported_here("unit attributes are not supported yet", unit_loc);

    if ( unit->contextType() )
        return unsupported_here("a %context type is not supported yet", unit_loc);

    auto items = unit->items();
    if ( items.size() != 1 )
        return unsupported_here("only a unit with exactly one item is supported yet", unit_loc);

    auto* field = (*items.begin())->tryAs<type::unit::item::Field>();
    if ( ! field )
        return unsupported_here("only a plain field item is supported yet", unit_loc);

    auto field_loc = field->meta().location();

    if ( field->isAnonymous() )
        return unsupported_here("an anonymous field is not supported yet", field_loc);
    if ( field->isSkip() )
        return unsupported_here("a skip field is not supported yet", field_loc);
    if ( field->isTransient() )
        return unsupported_here("a transient field is not supported yet", field_loc);
    if ( field->isForwarding() )
        return unsupported_here("a forwarding field is not supported yet", field_loc);
    if ( field->isContainer() )
        return unsupported_here("a container field is not supported yet", field_loc);
    if ( field->condition() )
        return unsupported_here("a field condition is not supported yet", field_loc);
    if ( field->ctor() )
        return unsupported_here("a field constructor is not supported yet", field_loc);
    if ( field->item() )
        return unsupported_here("a nested unit item is not supported yet", field_loc);
    if ( ! field->arguments().empty() )
        return unsupported_here("field arguments are not supported yet", field_loc);
    if ( ! field->sinks().empty() )
        return unsupported_here("sinks are not supported yet", field_loc);
    if ( ! field->hooks().empty() )
        return unsupported_here("hooks are not supported yet", field_loc);
    if ( field->repeatCount() )
        return unsupported_here("a repeat count is not supported yet", field_loc);
    if ( field->attributes() && *field->attributes() )
        return unsupported_here("field attributes are not supported yet", field_loc);

    auto* parse_type = field->parseType();
    auto* item_type = field->itemType();
    auto* parse_uint = parse_type ? parse_type->type()->tryAs<hilti::type::UnsignedInteger>() : nullptr;
    auto* item_uint = item_type ? item_type->type()->tryAs<hilti::type::UnsignedInteger>() : nullptr;

    if ( ! parse_uint || parse_uint->width() != 8 || ! item_uint || item_uint->width() != 8 )
        return unsupported_here("only an unsigned 8-bit integer field is supported yet", field_loc);

    // The accepted subset above rules out every way this slice's source language could override
    // byte order (a field or unit `&byte-order` attribute, or a unit `%byte-order` property), so
    // the resolved default is always the ordinary network byte order.
    auto unit_span = internSpan(package, unit_loc);
    auto field_span = internSpan(package, field_loc);

    auto unit_decl = package.createUnitDecl(std::string(decl->id().local()), unit_span);
    auto field_decl =
        package.createFieldDecl(unit_decl, std::string(field->id().local()), package.uint8Type(), field_span);

    auto state_type = package.parserStateType();
    auto unit_type = package.unitType(unit_decl);
    auto fn = package.createParserFunction(unit_decl, state_type, unit_type, unit_span);
    auto block = package.createBlock(package.function(fn).root_region);

    auto state0 = package.addArgument(fn, block, 0, unit_span);
    auto unit0 = package.addUnitCreate(block, unit_decl, unit_span);
    auto read = package.addReadInteger(block,
                                       state0,
                                       ir::ReadIntegerPayload{
                                           .width = 8,
                                           .signedness = ir::Signedness::Unsigned,
                                           .byte_order = ir::ByteOrder::Network,
                                       },
                                       field_span);
    auto state1 = package.addTupleGet(block, read, 0, field_span);
    auto value = package.addTupleGet(block, read, 1, field_span);
    auto unit1 = package.addPublishField(block, unit0, value, field_decl, field_span);
    package.addParserFinish(block, state1, unit1, unit_span);

    package.addParserRoot(unit_decl, fn);
    return std::nullopt;
}

} // namespace

RootDiscovery discoverRoots(const hilti::ASTContext& ctx) {
    auto v = VisitorRoots();
    visitor::visit(v, ctx.root(), ".spicy");
    return RootDiscovery{.roots = std::move(v.roots),
                         .units_with_external_hooks = std::move(v.units_with_external_hooks)};
}

std::optional<UnsupportedFeature> lowerRoots(const RootDiscovery& discovery, ir::Package& package) {
    for ( auto* decl : discovery.roots ) {
        if ( auto* fn_decl = decl->tryAs<hilti::declaration::Function>() ) {
            if ( auto feature = lowerFunction(fn_decl, package) )
                return feature;

            continue;
        }

        if ( auto* type_decl = decl->tryAs<hilti::declaration::Type>() ) {
            if ( type_decl->type()->alias() )
                return unsupported(fmt("public unit alias '%s'", std::string(type_decl->id())),
                                   "public unit aliases are not supported yet",
                                   type_decl->meta().location());

            if ( auto feature = lowerUnit(type_decl, discovery.units_with_external_hooks, package) )
                return feature;

            continue;
        }
    }

    return std::nullopt;
}

} // namespace spicy::detail::pir
