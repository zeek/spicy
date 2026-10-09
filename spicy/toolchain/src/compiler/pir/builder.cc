// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/function.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/statements/return.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/name.h>
#include <hilti/ast/types/vector.h>
#include <hilti/base/util.h>

#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/pir/builder.h>

using hilti::util::fmt;

namespace spicy::detail::pir {

namespace {

UnsupportedFeature unsupported(const std::string& feature, std::string reason, const hilti::Location& loc) {
    return UnsupportedFeature{.feature = feature, .reason = std::move(reason), .location = loc};
}

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

enum class FieldForm { Integer, Bytes, Vector };

struct FieldSpec {
    type::unit::item::Field* source = nullptr;
    FieldForm form = FieldForm::Integer;
    uint32_t width = 0;
    uint64_t byte_count = 0;
    type::unit::item::Field* bound_field = nullptr;
    type::Unit* child = nullptr;
    ir::DeclId declaration;
};

struct UnitSpec {
    hilti::declaration::Type* source = nullptr;
    type::Unit* unit = nullptr;
    std::vector<FieldSpec> fields;
    ir::TypeDeclId declaration;
    ir::FunctionId function;
};

class UnitBuilder {
public:
    UnitBuilder(const std::vector<hilti::declaration::Type*>& declarations,
                const std::vector<hilti::ast::TypeIndex>& external_hooks,
                ir::Package& package)
        : _declarations(declarations), _external_hooks(external_hooks), _package(package) {}

    std::optional<UnsupportedFeature> build(const std::vector<hilti::declaration::Type*>& roots) {
        for ( auto* root : roots )
            _root_units.insert(root->type()->type()->as<type::Unit>());
        for ( auto* root : roots ) {
            if ( auto error = _discover(root) )
                return error;
        }

        for ( auto& spec : _units )
            spec.declaration = _package.createUnitDecl(std::string(spec.source->id().local()),
                                                       internSpan(_package, spec.source->meta().location()));

        for ( auto& spec : _units ) {
            for ( auto& field : spec.fields ) {
                ir::TypeId field_type;
                switch ( field.form ) {
                    case FieldForm::Integer:
                        field_type = field.width == 8 ? _package.uint8Type() : _package.uint64Type();
                        break;
                    case FieldForm::Bytes: field_type = _package.bytesType(); break;
                    case FieldForm::Vector:
                        field_type = _package.vectorType(_package.unitType(_spec(field.child).declaration));
                        break;
                }
                field.declaration = _package.createFieldDecl(spec.declaration,
                                                             std::string(field.source->id().local()),
                                                             field_type,
                                                             internSpan(_package, field.source->meta().location()));
            }
            spec.function = _package.createParserFunction(spec.declaration,
                                                          _package.parserStateType(),
                                                          _package.unitType(spec.declaration),
                                                          internSpan(_package, spec.source->meta().location()));
        }

        for ( auto& spec : _units )
            _emit(spec);

        for ( auto* root : roots ) {
            const auto& spec = _spec(root->type()->type()->as<type::Unit>());
            _package.addParserRoot(spec.declaration, spec.function);
        }
        return std::nullopt;
    }

private:
    UnitSpec& _spec(type::Unit* unit) {
        for ( auto& spec : _units )
            if ( spec.unit == unit )
                return spec;
        hilti::util::cannotBeReached();
    }

    hilti::declaration::Type* _declaration(type::Unit* unit) const {
        for ( auto* decl : _declarations )
            if ( decl->type()->type() == unit )
                return decl;
        return nullptr;
    }

    std::optional<UnsupportedFeature> _discover(hilti::declaration::Type* decl) {
        auto* unit = decl->type()->type()->as<type::Unit>();
        auto feature = fmt("parser unit '%s'", std::string(decl->id()));
        auto reject = [&](std::string why, const hilti::Location& loc) {
            return unsupported(feature, std::move(why), loc);
        };
        if ( _visiting.contains(unit) )
            return reject("recursive unit dependency", decl->meta().location());
        if ( _seen.contains(unit) )
            return std::nullopt;
        _visiting.insert(unit);

        if ( unit->mayHaveFilter() )
            return reject("units that may have a filter attached are not supported yet", decl->meta().location());
        if ( std::ranges::find(_external_hooks, unit->typeIndex()) != _external_hooks.end() )
            return reject("units with an external hook are not supported yet", decl->meta().location());
        if ( ! unit->parameters().empty() || (unit->attributes() && *unit->attributes()) || unit->contextType() )
            return reject("unit parameters, attributes, and context are not supported", decl->meta().location());

        UnitSpec spec{.source = decl, .unit = unit};
        for ( auto* item : unit->items() ) {
            auto* field = item->tryAs<type::unit::item::Field>();
            if ( ! field )
                return reject("only plain fields are supported", item->meta().location());
            auto field_loc = field->meta().location();
            if ( field->isAnonymous() || field->isSkip() || field->isTransient() || field->isForwarding() ||
                 field->condition() || field->ctor() || ! field->arguments().empty() || ! field->sinks().empty() ||
                 ! field->hooks().empty() )
                return reject("field modifiers, constructors, and hooks are not supported", field_loc);

            FieldSpec f{.source = field};
            auto* parse_type = field->parseType() ? field->parseType()->type() : nullptr;
            auto* item_type = field->itemType() ? field->itemType()->type() : nullptr;
            auto* attrs = field->attributes();
            auto* size = attrs ? attrs->find(attribute::kind::Size) : nullptr;
            if ( auto* integer = parse_type ? parse_type->tryAs<hilti::type::UnsignedInteger>() : nullptr ) {
                if ( attrs && *attrs )
                    return reject("field attributes are not supported yet", field_loc);
                auto* item_integer = item_type ? item_type->tryAs<hilti::type::UnsignedInteger>() : nullptr;
                if ( ! item_integer || item_integer->width() != integer->width() ||
                     (integer->width() != 8 && integer->width() != 64) || size || field->repeatCount() ||
                     field->item() )
                    return reject("unsupported integer field form", field_loc);
                f.form = FieldForm::Integer;
                f.width = integer->width();
            }
            else if ( parse_type && parse_type->isA<hilti::type::Bytes>() ) {
                if ( ! size )
                    return reject("bytes require a nonnegative constant &size", field_loc);
                auto length = size->valueAsInteger();
                if ( ! length || *length < 0 || field->repeatCount() || ! item_type ||
                     ! item_type->isA<hilti::type::Bytes>() || ! _onlySize(attrs) || field->item() )
                    return reject("bytes require a nonnegative constant &size", field_loc);
                f.form = FieldForm::Bytes;
                f.byte_count = static_cast<uint64_t>(*length);
            }
            else if ( auto* vector = parse_type ? parse_type->tryAs<hilti::type::Vector>() : nullptr ) {
                auto* item_vector = item_type ? item_type->tryAs<hilti::type::Vector>() : nullptr;
                if ( ! item_vector || ! size || ! _onlySize(attrs) || ! field->isContainer() ||
                     ! field->repeatCount() || ! field->repeatCount()->isA<hilti::expression::Ctor>() ||
                     ! field->repeatCount()->as<hilti::expression::Ctor>()->ctor()->isA<hilti::ctor::Null>() ||
                     ! _root_units.contains(unit) )
                    return reject("unsupported vector field form", field_loc);
                auto* element = vector->elementType()->type();
                auto* named = element->tryAs<hilti::type::Name>();
                f.child = named ? named->resolvedType()->tryAs<type::Unit>() : element->tryAs<type::Unit>();
                if ( ! f.child )
                    return reject("only vectors of units are supported", field_loc);
                if ( _root_units.contains(f.child) )
                    return reject("vector child must be a private unit", field_loc);
                auto expr = size->valueAsExpression();
                auto* member = expr ? (*expr)->tryAs<hilti::expression::ResolvedOperator>() : nullptr;
                auto* member_name =
                    member && member->op1() ? member->op1()->tryAs<hilti::expression::Member>() : nullptr;
                auto* self_name = member && member->op0() ? member->op0()->tryAs<hilti::expression::Name>() : nullptr;
                if ( ! member || member->kind() != hilti::operator_::Kind::Member || ! member_name || ! self_name ||
                     self_name->id() != hilti::ID("self") )
                    return reject("vector &size must reference a prior unit field", field_loc);
                auto* bound_item = unit->itemByName(member_name->id());
                f.bound_field = bound_item ? bound_item->tryAs<type::unit::item::Field>() : nullptr;
                if ( ! f.bound_field || std::ranges::none_of(spec.fields, [&](const FieldSpec& previous) {
                         return previous.source == f.bound_field && previous.form == FieldForm::Integer;
                     }) )
                    return reject("vector &size must reference a previously published unsigned field", field_loc);
                auto* child_decl = _declaration(f.child);
                if ( ! child_decl )
                    return reject("vector child unit has no source declaration", field_loc);
                if ( auto error = _discover(child_decl) )
                    return error;
                f.form = FieldForm::Vector;
            }
            else
                return reject("unsupported field type", field_loc);
            spec.fields.push_back(f);
        }

        _visiting.erase(unit);
        _seen.insert(unit);
        _units.push_back(std::move(spec));
        return std::nullopt;
    }

    static bool _onlySize(const hilti::AttributeSet* attrs) {
        return attrs && attrs->attributes().size() == 1 && attrs->find(attribute::kind::Size);
    }

    void _emit(UnitSpec& spec) {
        auto unit_span = internSpan(_package, spec.source->meta().location());
        auto block = _package.createBlock(_package.function(spec.function).root_region);
        auto state = _package.addArgument(spec.function, block, 0, unit_span);
        auto unit_value = _package.addUnitCreate(block, spec.declaration, unit_span);
        std::unordered_map<type::unit::item::Field*, ir::InstId> published;
        for ( const auto& field : spec.fields ) {
            auto span = internSpan(_package, field.source->meta().location());
            ir::InstId value;
            if ( field.form == FieldForm::Integer || field.form == FieldForm::Bytes ) {
                auto read = field.form == FieldForm::Integer ?
                                _package.addReadInteger(block,
                                                        state,
                                                        ir::ReadIntegerPayload{.width = field.width,
                                                                               .signedness = ir::Signedness::Unsigned,
                                                                               .byte_order = ir::ByteOrder::Network},
                                                        span) :
                                _package.addReadBytes(block, state, field.byte_count, span);
                state = _package.addTupleGet(block, read, 0, span);
                value = _package.addTupleGet(block, read, 1, span);
            }
            else {
                state = _package.addEnterBound(block, state, published.at(field.bound_field), span);
                auto vector = _package.addVectorEmpty(block, _package.unitType(_spec(field.child).declaration), span);
                auto body = _package.createRegion();
                auto body_block = _package.createBlock(body);
                auto body_state = _package.addRegionArgument(body_block, 0, _package.parserStateType(), span);
                auto body_vector = _package.addRegionArgument(body_block, 1, _package.inst(vector).result_type, span);
                auto child = _package.addParseSubunit(body_block, body_state, _spec(field.child).function, span);
                auto next_state = _package.addTupleGet(body_block, child, 0, span);
                auto element = _package.addTupleGet(body_block, child, 1, span);
                auto next_vector = _package.addVectorAppend(body_block, body_vector, element, span);
                _package.addYield(body_block, {next_state, next_vector}, span);
                auto repeated = _package.addRepeatToBound(block, {state, vector}, body, span);
                state = _package.addTupleGet(block, repeated, 0, span);
                value = _package.addTupleGet(block, repeated, 1, span);
                state = _package.addLeaveBound(block, state, span);
            }
            unit_value = _package.addPublishField(block, unit_value, value, field.declaration, span);
            published[field.source] = value;
        }
        _package.addParserFinish(block, state, unit_value, unit_span);
    }

    const std::vector<hilti::declaration::Type*>& _declarations;
    const std::vector<hilti::ast::TypeIndex>& _external_hooks;
    ir::Package& _package;
    std::vector<UnitSpec> _units;
    std::unordered_set<type::Unit*> _seen;
    std::unordered_set<type::Unit*> _visiting;
    std::unordered_set<type::Unit*> _root_units;
};

} // namespace

std::optional<UnsupportedFeature> buildFunction(hilti::declaration::Function* decl, ir::Package& package) {
    return lowerFunction(decl, package);
}

std::optional<UnsupportedFeature> buildUnits(const std::vector<hilti::declaration::Type*>& roots,
                                             const std::vector<hilti::declaration::Type*>& unit_declarations,
                                             const std::vector<hilti::ast::TypeIndex>& units_with_external_hooks,
                                             ir::Package& package) {
    return UnitBuilder(unit_declarations, units_with_external_hooks, package).build(roots);
}

} // namespace spicy::detail::pir
