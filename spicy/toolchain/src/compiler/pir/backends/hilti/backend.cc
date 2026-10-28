// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/backends/hilti/backend.h>
#include <spicy/compiler/detail/pir/ir/cfg.h>

using ::hilti::util::fmt;

namespace spicy::detail::pir::backend::hilti {

namespace {

::hilti::Meta metaFor(const ir::Package& package, ir::SourceSpanId id) {
    if ( ! package.sourceManager().isValid(id) )
        return {};
    const auto& span = package.sourceManager().span(id);
    std::string file;
    if ( package.sourceManager().isValid(span.file) )
        file = package.sourceManager().file(span.file).diagnostic_path;
    return ::hilti::Meta(::hilti::Location(file, span.begin_line, span.end_line, span.begin_column, span.end_column));
}

// The synthetic module that holds every emitted declaration.
constexpr std::string_view ModuleName = "__spicy_pir_backend";

// A module-level declaration, qualified by its module so that a parameter or local of the same name cannot hide it.
::hilti::ID moduleLevel(const std::string& name) { return ::hilti::ID({ModuleName, name}); }

std::string unitName(ir::TypeDeclId id) { return fmt("Unit_%u", id.index); }
std::string fieldName(ir::DeclId id) { return fmt("field_%u", id.index); }

struct FunctionNames {
    std::string function;
    std::string result;
    bool root = false;
};

using NameMap = std::unordered_map<uint32_t, FunctionNames>;

// Public functions keep their source names where possible. Roots from different source modules may share a local name,
// and a name may collide with a generated one, so a clashing root gets a numeric suffix.
// TODO: Allocate implementation names by PIR identity to avoid collisions
// after target normalization, such as C++ class and class_.
NameMap makeNames(const ir::Package& package) {
    NameMap names;
    std::unordered_set<uint32_t> roots;
    for ( auto root : package.functionRoots() )
        roots.insert(root.index);

    for ( size_t i = 0; i < package.functions().size(); ++i ) {
        auto id = static_cast<uint32_t>(i);
        if ( roots.contains(id) )
            continue;
        if ( package.function(ir::FunctionId{id}).kind == ir::FunctionKind::Parser )
            names.emplace(id,
                          FunctionNames{
                              .function = fmt("parse_child_%zu", i),
                              .result = fmt("ParseResultChild_%zu", i),
                          });
        else
            names.emplace(id, FunctionNames{.function = fmt("proc_%zu", i)});
    }
    for ( size_t i = 0; i < package.parserRoots().size(); ++i ) {
        auto& entry = names.at(package.parserRoots()[i].function.index);
        entry = FunctionNames{.function = fmt("parse_root_%zu", i), .result = fmt("ParseResult_%zu", i), .root = true};
    }

    std::unordered_set<std::string> taken = {"OutcomeKind", "hilti", "spicy_rt"};
    for ( const auto& [_, entry] : names ) {
        taken.insert(entry.function);
        if ( ! entry.result.empty() )
            taken.insert(entry.result);
    }
    for ( size_t i = 0; i < package.typeDecls().size(); ++i )
        taken.insert(unitName(ir::TypeDeclId{static_cast<uint32_t>(i)}));
    for ( size_t i = 0; i < package.foreignFunctions().size(); ++i )
        taken.insert(fmt("foreign_%zu", i));

    for ( auto root : package.functionRoots() ) {
        const auto base = std::string(package.function(root).name);
        auto name = base;
        for ( size_t n = 1; taken.contains(name); ++n )
            name = fmt("%s_%zu", base, n);
        taken.insert(name);
        names.emplace(root.index, FunctionNames{.function = name, .root = true});
    }
    return names;
}

::hilti::QualifiedType* unitReferenceType(::hilti::Builder& b, ir::TypeDeclId unit) {
    return b.qualifiedType(b.typeValueReference(
                               b.qualifiedType(b.typeName(::hilti::ID(unitName(unit))), ::hilti::Constness::Mutable)),
                           ::hilti::Constness::Mutable);
}

::hilti::QualifiedType* targetType(::hilti::Builder& b, const ir::Package& package, ir::TypeId id) {
    const auto& type = package.type(id);
    switch ( type.kind ) {
        case ir::TypeKind::UInt8: return b.qualifiedType(b.typeUnsignedInteger(8), ::hilti::Constness::Mutable);
        case ir::TypeKind::UInt64: return b.qualifiedType(b.typeUnsignedInteger(64), ::hilti::Constness::Mutable);
        case ir::TypeKind::Bytes: return b.qualifiedType(b.typeBytes(), ::hilti::Constness::Mutable);
        case ir::TypeKind::Int64: return b.qualifiedType(b.typeSignedInteger(64), ::hilti::Constness::Mutable);
        case ir::TypeKind::Bool: return b.qualifiedType(b.typeBool(), ::hilti::Constness::Mutable);
        case ir::TypeKind::String: return b.qualifiedType(b.typeString(), ::hilti::Constness::Mutable);
        case ir::TypeKind::Tuple: {
            ::hilti::QualifiedTypes elements;
            for ( auto element : type.type_arguments )
                elements.push_back(targetType(b, package, element));
            return b.qualifiedType(b.typeTuple(elements), ::hilti::Constness::Mutable);
        }
        case ir::TypeKind::Opaque: {
            const auto& info = package.typeDecl(type.declaration).opaque.value();
            // The library type carries its own constness, so the qualifier stays mutable.
            auto constness = info.constant ? ::hilti::Constness::Const : ::hilti::Constness::Mutable;
            return b.qualifiedType(b.typeLibrary(constness, info.cxx_name), ::hilti::Constness::Mutable);
        }
        // A place is the storage it names, so its HILTI type is that storage's type.
        case ir::TypeKind::Place: return targetType(b, package, type.type_arguments[0]);
        case ir::TypeKind::Unit:
            return b.qualifiedType(b.typeName(::hilti::ID(unitName(type.declaration))), ::hilti::Constness::Mutable);
        case ir::TypeKind::Vector:
            return b.qualifiedType(b.typeVector(targetType(b, package, type.type_arguments[0])),
                                   ::hilti::Constness::Mutable);
        default: ::hilti::util::cannotBeReached();
    }
}

::hilti::Declaration* lowerUnitType(::hilti::Builder& b, const ir::Package& package, ir::TypeDeclId id) {
    const auto& unit = package.typeDecl(id);
    ::hilti::Declarations fields;
    for ( auto field_id : unit.fields ) {
        const auto& field = package.declaration(field_id);
        fields.push_back(b.declarationField(::hilti::ID(fieldName(field_id)),
                                            targetType(b, package, field.type),
                                            static_cast<::hilti::AttributeSet*>(nullptr),
                                            metaFor(package, field.span)));
    }
    return b.declarationType(::hilti::ID(unitName(id)),
                             b.qualifiedType(b.typeStruct(fields), ::hilti::Constness::Const),
                             ::hilti::declaration::Linkage::Public,
                             metaFor(package, unit.span));
}

::hilti::Declaration* lowerResultType(::hilti::Builder& b,
                                      const ir::Package& package,
                                      ir::FunctionId id,
                                      const FunctionNames& names) {
    auto* unit_type = names.root ? unitReferenceType(b, package.function(id).parser_unit) :
                                   b.qualifiedType(b.typeName(::hilti::ID(unitName(package.function(id).parser_unit))),
                                                   ::hilti::Constness::Mutable);
    ::hilti::Declarations fields = {
        b.declarationField(::hilti::ID("kind"),
                           b.qualifiedType(b.typeName(::hilti::ID("OutcomeKind")), ::hilti::Constness::Mutable),
                           static_cast<::hilti::AttributeSet*>(nullptr)),
        b.declarationField(::hilti::ID("unit"),
                           b.qualifiedType(b.typeOptional(unit_type), ::hilti::Constness::Mutable),
                           static_cast<::hilti::AttributeSet*>(nullptr)),
        b.declarationField(::hilti::ID("cursor"),
                           b.qualifiedType(b.typeStreamView(), ::hilti::Constness::Mutable),
                           static_cast<::hilti::AttributeSet*>(nullptr)),
        b.declarationField(::hilti::ID("gap_offset"),
                           b.qualifiedType(b.typeUnsignedInteger(64), ::hilti::Constness::Mutable),
                           static_cast<::hilti::AttributeSet*>(nullptr)),
        b.declarationField(::hilti::ID("gap_length"),
                           b.qualifiedType(b.typeUnsignedInteger(64), ::hilti::Constness::Mutable),
                           static_cast<::hilti::AttributeSet*>(nullptr)),
    };
    return b.declarationType(::hilti::ID(names.result),
                             b.qualifiedType(b.typeStruct(fields), ::hilti::Constness::Const),
                             ::hilti::declaration::Linkage::Public);
}

::hilti::Expression* makeResult(::hilti::Builder& b,
                                ::hilti::Expression* kind,
                                ::hilti::Expression* unit,
                                ::hilti::Expression* cursor,
                                ::hilti::Expression* gap_offset,
                                ::hilti::Expression* gap_length,
                                const ::hilti::Meta& meta) {
    ::hilti::ctor::struct_::Fields fields = {
        b.ctorStructField(::hilti::ID("kind"), kind),
        b.ctorStructField(::hilti::ID("unit"), unit ? unit : b.null()),
        b.ctorStructField(::hilti::ID("cursor"), cursor),
        b.ctorStructField(::hilti::ID("gap_offset"), gap_offset),
        b.ctorStructField(::hilti::ID("gap_length"), gap_length),
    };
    return b.struct_(fields, meta);
}

using LocalBuilder = ::hilti::ExtendedBuilderTemplate<::hilti::Builder>;

::hilti::QualifiedType* resultType(::hilti::Builder& b, const ir::Package& package, ir::TypeId id) {
    if ( id == package.voidType() )
        return b.qualifiedType(b.typeVoid(), ::hilti::Constness::Mutable);
    return targetType(b, package, id);
}

// An `inout` parameter is passed by reference, so the caller's place is the storage the callee sees.
::hilti::declaration::Parameter* parameterFor(::hilti::Builder& b,
                                              const ir::Package& package,
                                              const std::string& name,
                                              ir::TypeId id,
                                              const ::hilti::Meta& meta) {
    const auto& type = package.type(id);
    if ( type.kind == ir::TypeKind::Place )
        return b.parameter(::hilti::ID(name),
                           targetType(b, package, type.type_arguments[0])->type(),
                           ::hilti::parameter::Kind::InOut,
                           meta);
    return b.parameter(::hilti::ID(name), targetType(b, package, id)->type(), ::hilti::parameter::Kind::In, meta);
}

// A formal of a foreign function. `any` and `tuple<*>` formals are the HILTI types the runtime declares, so the
// HILTI compiler supplies the concrete type information or tuple elements at each call.
::hilti::declaration::Parameter* foreignParameterFor(::hilti::Builder& b,
                                                     const ir::Package& package,
                                                     const std::string& name,
                                                     const ir::ForeignParameter& parameter,
                                                     const ::hilti::Meta& meta) {
    switch ( parameter.argument ) {
        case ir::ForeignArgument::Value: return parameterFor(b, package, name, parameter.type, meta);
        case ir::ForeignArgument::TypeInfo:
            return b.parameter(::hilti::ID(name), b.typeAny(), ::hilti::parameter::Kind::In, meta);
        case ir::ForeignArgument::AnyPointer: {
            auto* attrs = b.attributeSet({b.attribute(::hilti::attribute::kind::CxxAnyAsPtr, meta)}, meta);
            return b.declarationParameter(::hilti::ID(name),
                                          b.typeAny(),
                                          ::hilti::parameter::Kind::In,
                                          nullptr,
                                          attrs,
                                          meta);
        }
        case ir::ForeignArgument::AnyTuple:
            return b.parameter(::hilti::ID(name),
                               b.typeTuple(::hilti::type::Wildcard{}),
                               ::hilti::parameter::Kind::In,
                               meta);
    }

    ::hilti::util::cannotBeReached();
}

// The native declaration of a foreign function, bound to its C++ symbol through `&cxxname`.
::hilti::Declaration* lowerForeignFunction(::hilti::Builder& b, const ir::Package& package, ir::ForeignFunctionId id) {
    const auto& fn = package.foreignFunction(id);
    auto meta = metaFor(package, fn.span);
    ::hilti::declaration::Parameters params;
    for ( size_t i = 0; i < fn.parameters.size(); ++i )
        params.push_back(foreignParameterFor(b, package, fmt("arg_%zu", i), fn.parameters[i], meta));
    std::vector<::hilti::Attribute*> attributes;
    attributes.push_back(b.attribute(::hilti::attribute::kind::Cxxname, b.stringLiteral(fn.cxx_name), meta));
    if ( fn.have_prototype )
        attributes.push_back(b.attribute(::hilti::attribute::kind::HavePrototype, meta));
    auto* attrs = b.attributeSet(attributes, meta);
    return b.function(::hilti::ID(fmt("foreign_%u", id.index)),
                      resultType(b, package, fn.result_type),
                      params,
                      ::hilti::type::function::Flavor::Function,
                      ::hilti::declaration::Linkage::Private,
                      ::hilti::type::function::CallingConvention::Extern,
                      attrs,
                      meta);
}

// The PIR operations that ordinary function bodies consist of, and that parser byte bounds may compute their
// length from. A value is a named HILTI local, parameter, or cursor, or a field of the unit being parsed, which is
// addressed through its unit.
class ProceduralOps {
protected:
    ProceduralOps(const ir::Package& package, const NameMap& names) : package_(package), names_(names) {}

    ::hilti::Expression* _value(LocalBuilder& b, ir::InstId id) {
        if ( auto field = fields_.find(id.index); field != fields_.end() )
            return b.member(b.id(::hilti::ID(field->second.first)), field->second.second);
        return b.id(::hilti::ID(values_.at(id.index)));
    }

    // Lowers one procedural operation, returning false for an operation that is not procedural.
    bool _lowerProcedural(LocalBuilder& b, ir::InstId id) {
        const auto& inst = package_.inst(id);
        auto meta = metaFor(package_, inst.span);
        switch ( inst.opcode ) {
            case ir::Opcode::Argument:
                values_[id.index] = fmt("arg_%u", std::get<ir::ArgumentPayload>(inst.payload).index);
                return true;
            case ir::Opcode::Constant: {
                auto name = fmt("v_%u", id.index);
                b.addLocal(::hilti::ID(name),
                           targetType(b, package_, inst.result_type),
                           b.integer(std::get<ir::Int64Literal>(inst.payload).value),
                           meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::Add: {
                auto name = fmt("v_%u", id.index);
                b.addLocal(::hilti::ID(name),
                           targetType(b, package_, inst.result_type),
                           b.sum(_value(b, inst.args[0]), _value(b, inst.args[1]), meta),
                           meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::Return:
                if ( inst.args.empty() )
                    b.addReturn(meta);
                else
                    b.addReturn(_value(b, inst.args[0]), meta);
                return true;
            case ir::Opcode::Call:
            case ir::Opcode::OpaqueOp: {
                ::hilti::ID callee =
                    inst.opcode == ir::Opcode::Call ?
                        moduleLevel(names_.at(std::get<ir::FunctionPayload>(inst.payload).function.index).function) :
                        moduleLevel(
                            fmt("foreign_%u", std::get<ir::ForeignFunctionPayload>(inst.payload).function.index));
                ::hilti::Expressions args;
                for ( auto arg : inst.args )
                    args.push_back(_value(b, arg));
                auto* call = b.call(callee, args, meta);
                if ( inst.result_type == package_.voidType() ) {
                    b.addExpression(call);
                    return true;
                }

                auto name = fmt("v_%u", id.index);
                b.addLocal(::hilti::ID(name), targetType(b, package_, inst.result_type), call, meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::LocalPlace: {
                auto name = fmt("p_%u", id.index);
                auto element = package_.type(inst.result_type).type_arguments[0];
                b.addLocal(::hilti::ID(name), targetType(b, package_, element), _value(b, inst.args[0]), meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::Load: {
                auto name = fmt("v_%u", id.index);
                b.addLocal(::hilti::ID(name), targetType(b, package_, inst.result_type), _value(b, inst.args[0]), meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::FieldPlace: {
                auto field = std::get<ir::FieldPayload>(inst.payload).field;
                fields_[id.index] = {values_.at(inst.args[0].index), fieldName(field)};
                return true;
            }
            case ir::Opcode::Store: b.addAssign(_value(b, inst.args[0]), _value(b, inst.args[1]), meta); return true;
            case ir::Opcode::Equal: {
                auto name = fmt("v_%u", id.index);
                b.addLocal(::hilti::ID(name),
                           targetType(b, package_, inst.result_type),
                           b.equal(_value(b, inst.args[0]), _value(b, inst.args[1]), meta),
                           meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::Tuple: {
                ::hilti::Expressions elements;
                for ( auto element : inst.args )
                    elements.push_back(_value(b, element));
                auto name = fmt("v_%u", id.index);
                b.addLocal(::hilti::ID(name), targetType(b, package_, inst.result_type), b.tuple(elements, meta), meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::BoolConstant:
            case ir::Opcode::StringConstant:
            case ir::Opcode::BytesConstant: {
                auto name = fmt("v_%u", id.index);
                ::hilti::Expression* value = nullptr;
                if ( inst.opcode == ir::Opcode::BoolConstant )
                    value = b.bool_(std::get<ir::BoolLiteral>(inst.payload).value, meta);
                else if ( inst.opcode == ir::Opcode::StringConstant )
                    value = b.stringLiteral(std::get<ir::StringLiteral>(inst.payload).value, meta);
                else
                    value = b.bytes(std::get<ir::BytesLiteral>(inst.payload).value, meta);
                b.addLocal(::hilti::ID(name), targetType(b, package_, inst.result_type), value, meta);
                values_[id.index] = std::move(name);
                return true;
            }
            default: return false;
        }

        return true;
    }

    const ir::Package& package_;
    const NameMap& names_;
    std::unordered_map<uint32_t, std::string> values_;
    std::unordered_map<uint32_t, std::pair<std::string, std::string>> fields_;
};

class FunctionEmitter : public ProceduralOps {
public:
    FunctionEmitter(::hilti::Builder& b, const ir::Package& package, const NameMap& names, ir::FunctionId id)
        : ProceduralOps(package, names), _b(b), _id(id) {}

    ::hilti::Declaration* emit() {
        const auto& fn = package_.function(_id);
        const auto& names = names_.at(_id.index);
        auto meta = metaFor(package_, fn.span);
        auto* view_type = _b.qualifiedType(_b.typeStreamView(), ::hilti::Constness::Mutable);
        auto* data = _b.parameter(::hilti::ID("data"),
                                  _b.typeValueReference(_b.qualifiedType(_b.typeStream(), ::hilti::Constness::Mutable)),
                                  ::hilti::parameter::Kind::InOut,
                                  meta);
        ::hilti::declaration::Parameters params{data};
        if ( names.root )
            params.push_back(_b.parameter(::hilti::ID("initial_cursor"),
                                          _b.typeOptional(view_type),
                                          _b.optional(view_type),
                                          ::hilti::parameter::Kind::In,
                                          meta));
        else {
            params.push_back(
                _b.parameter(::hilti::ID("initial_cursor"), _b.typeStreamView(), ::hilti::parameter::Kind::In, meta));
            params.push_back(
                _b.parameter(::hilti::ID("bound_end"),
                             _b.typeOptional(_b.qualifiedType(_b.typeUnsignedInteger(64), ::hilti::Constness::Mutable)),
                             ::hilti::parameter::Kind::In,
                             meta));
        }

        auto* body = _b.statementBlock(meta);
        LocalBuilder fb(_b.context(), body);
        if ( names.root ) {
            fb.addLocal(::hilti::ID("cursor"),
                        view_type,
                        fb.ternary(fb.id(::hilti::ID("initial_cursor")),
                                   fb.deref(fb.id(::hilti::ID("initial_cursor"))),
                                   fb.cast(fb.deref(fb.id(::hilti::ID("data"))), view_type)),
                        meta);
            fb.addLocal(::hilti::ID("bound_end"),
                        fb.qualifiedType(fb.typeOptional(
                                             fb.qualifiedType(fb.typeUnsignedInteger(64), ::hilti::Constness::Mutable)),
                                         ::hilti::Constness::Mutable),
                        fb.optional(fb.qualifiedType(fb.typeUnsignedInteger(64), ::hilti::Constness::Mutable)),
                        meta);
            fb.addLocal(::hilti::ID("outer_cursor"), view_type, meta);
        }
        else
            fb.addLocal(::hilti::ID("cursor"), view_type, fb.id(::hilti::ID("initial_cursor")), meta);
        fb.addLocal(::hilti::ID("filters_"),
                    fb.strongReference(
                        fb.qualifiedType(fb.typeName(::hilti::ID("spicy_rt::Filters")), ::hilti::Constness::Mutable)),
                    meta);

        const auto& region = package_.region(fn.root_region);
        for ( auto inst_id : package_.block(region.blocks[0]).insts )
            _lowerInst(fb, inst_id);

        return _b.function(::hilti::ID(names.function),
                           _b.qualifiedType(_b.typeName(::hilti::ID(names.result)), ::hilti::Constness::Mutable),
                           params,
                           body,
                           ::hilti::type::function::Flavor::Function,
                           ::hilti::declaration::Linkage::Public,
                           names.root ? ::hilti::type::function::CallingConvention::Extern :
                                        ::hilti::type::function::CallingConvention::Standard,
                           {},
                           meta);
    }

private:
    ::hilti::Expression* _member(LocalBuilder& b, std::string_view base, std::string_view member) {
        return b.member(b.id(::hilti::ID(base)), std::string(member));
    }

    void _return(LocalBuilder& b, std::string_view kind, ::hilti::Expression* unit, const ::hilti::Meta& meta) {
        b.addReturn(makeResult(b,
                               b.id(::hilti::ID(fmt("OutcomeKind::%s", kind))),
                               unit,
                               b.id(::hilti::ID("cursor")),
                               b.integer(0U),
                               b.integer(0U),
                               meta),
                    meta);
    }

    void _checkBound(LocalBuilder& b, uint64_t bytes, const ::hilti::Meta& meta) {
        auto inside = b.addIf(b.id(::hilti::ID("bound_end")), meta);
        auto over =
            inside->addIf(inside->greater(inside->integer(bytes),
                                          inside->difference(inside->deref(inside->id(::hilti::ID("bound_end"))),
                                                             inside->memberCall(inside->id(::hilti::ID("cursor")),
                                                                                "offset",
                                                                                ::hilti::Expressions{}))),
                          meta);
        _return(*over, "ParseError", nullptr, meta);
    }

    void _wait(LocalBuilder& b, uint64_t bytes, const ::hilti::Meta& meta) {
        _checkBound(b, bytes, meta);
        auto* call = b.call(::hilti::ID("spicy_rt::waitForInputOrEod"),
                            {b.id(::hilti::ID("data")),
                             b.id(::hilti::ID("cursor")),
                             b.integer(bytes),
                             b.id(::hilti::ID("filters_"))},
                            meta);
        auto eod = b.addIf(b.not_(call), meta);
        _return(*eod, "UnexpectedEod", nullptr, meta);
    }

    void _gapCatch(LocalBuilder& b, ::hilti::Statement* try_body, const ::hilti::Meta& meta) {
        auto* catch_body = _b.statementBlock(meta);
        LocalBuilder cb(_b.context(), catch_body);
        cb.addLocal(::hilti::ID("gap_probe"),
                    cb.qualifiedType(cb.typeStreamView(), ::hilti::Constness::Mutable),
                    cb.id(::hilti::ID("cursor")),
                    meta);
        auto scan = cb.addWhile(cb.bool_(true), meta);
        auto* scan_body = _b.statementBlock(meta);
        LocalBuilder sb(_b.context(), scan_body);
        sb.addExpression(sb.cast(sb.deref(sb.begin(sb.id(::hilti::ID("gap_probe")))),
                                 sb.qualifiedType(sb.typeUnsignedInteger(8), ::hilti::Constness::Mutable)));
        sb.addAssign(sb.id(::hilti::ID("gap_probe")),
                     sb.memberCall(sb.id(::hilti::ID("gap_probe")), "advance", {sb.integer(1U)}, meta),
                     meta);
        auto* scan_catch_body = _b.statementBlock(meta);
        LocalBuilder scan_catch(_b.context(), scan_catch_body);
        scan_catch.addBreak(meta);
        auto* scan_catch_param = _b.parameter(::hilti::ID("e"),
                                              _b.typeName(::hilti::ID("hilti::MissingData")),
                                              ::hilti::parameter::Kind::In);
        auto* scan_clause = _b.statementTryCatch(scan_catch_param, scan_catch_body, meta);
        scan->block()->_add(scan->context(),
                            _b.statementTry(scan_body, ::hilti::statement::try_::Catches{scan_clause}, meta));
        cb.addLocal(::hilti::ID("full_probe"),
                    cb.memberCall(cb.cast(cb.deref(cb.id(::hilti::ID("data"))),
                                          cb.qualifiedType(cb.typeStreamView(), ::hilti::Constness::Mutable)),
                                  "advance",
                                  {cb.memberCall(cb.id(::hilti::ID("gap_probe")),
                                                 "offset",
                                                 ::hilti::Expressions{},
                                                 meta)},
                                  meta),
                    meta);
        cb.addLocal(::hilti::ID("after_gap"),
                    cb.memberCall(cb.id(::hilti::ID("full_probe")),
                                  "advance_to_next_data",
                                  ::hilti::Expressions{},
                                  meta),
                    meta);
        auto* gap_start = cb.memberCall(cb.id(::hilti::ID("gap_probe")), "offset", ::hilti::Expressions{}, meta);
        auto* gap_end = cb.memberCall(cb.id(::hilti::ID("after_gap")), "offset", ::hilti::Expressions{}, meta);
        cb.addReturn(makeResult(cb,
                                cb.id(::hilti::ID("OutcomeKind::Gap")),
                                nullptr,
                                cb.id(::hilti::ID("cursor")),
                                gap_start,
                                cb.difference(gap_end,
                                              cb.memberCall(cb.id(::hilti::ID("gap_probe")),
                                                            "offset",
                                                            ::hilti::Expressions{},
                                                            meta)),
                                meta),
                     meta);
        auto* catch_param = _b.parameter(::hilti::ID("e"),
                                         _b.typeName(::hilti::ID("hilti::MissingData")),
                                         ::hilti::parameter::Kind::In);
        auto* catch_clause = _b.statementTryCatch(catch_param, catch_body, meta);
        b.block()->_add(b.context(), _b.statementTry(try_body, ::hilti::statement::try_::Catches{catch_clause}, meta));
    }

    void _lowerRead(LocalBuilder& b, ir::InstId id, bool integer) {
        const auto& inst = package_.inst(id);
        auto meta = metaFor(package_, inst.span);
        uint64_t bytes = integer ? std::get<ir::ReadIntegerPayload>(inst.payload).width / 8 :
                                   std::get<ir::ReadBytesPayload>(inst.payload).length;
        _wait(b, bytes, meta);
        auto value_name = fmt("v_%u", id.index);
        auto* value_type = integer ? b.qualifiedType(b.typeUnsignedInteger(static_cast<unsigned>(bytes * 8)),
                                                     ::hilti::Constness::Mutable) :
                                     b.qualifiedType(b.typeBytes(), ::hilti::Constness::Mutable);
        b.addLocal(::hilti::ID(value_name), value_type, meta);
        auto* try_body = _b.statementBlock(meta);
        LocalBuilder tb(_b.context(), try_body);
        if ( integer ) {
            auto* unpacked =
                tb.deref(tb.unpack(tb.qualifiedType(tb.typeUnsignedInteger(static_cast<unsigned>(bytes * 8)),
                                                    ::hilti::Constness::Mutable),
                                   {tb.id(::hilti::ID("cursor")), tb.id(::hilti::ID("hilti::ByteOrder::Network"))},
                                   meta));
            tb.addAssign(tb.tuple({tb.id(::hilti::ID(value_name)), tb.id(::hilti::ID("cursor"))}), unpacked, meta);
        }
        else {
            tb.addAssign(tb.id(::hilti::ID(value_name)),
                         tb.call(::hilti::ID("spicy_rt::extractBytes"),
                                 {tb.id(::hilti::ID("data")),
                                  tb.id(::hilti::ID("cursor")),
                                  tb.integer(bytes),
                                  tb.bool_(false),
                                  tb.stringLiteral(""),
                                  tb.id(::hilti::ID("filters_"))},
                                 meta),
                         meta);
            tb.addAssign(tb.id(::hilti::ID("cursor")),
                         tb.memberCall(tb.id(::hilti::ID("cursor")), "advance", {tb.integer(bytes)}, meta),
                         meta);
        }
        _gapCatch(b, try_body, meta);
        _tuples[id.index] = {"cursor", value_name};
    }

    void _lowerInst(LocalBuilder& b, ir::InstId id) {
        const auto& inst = package_.inst(id);
        auto meta = metaFor(package_, inst.span);
        switch ( inst.opcode ) {
            case ir::Opcode::Argument:
            case ir::Opcode::RegionArgument:
                if ( ! values_.contains(id.index) )
                    values_[id.index] = "cursor";
                return;
            case ir::Opcode::TupleGet: {
                auto index = std::get<ir::TupleGetPayload>(inst.payload).index;
                values_[id.index] = _tuples.at(inst.args[0].index).at(index);
                return;
            }
            case ir::Opcode::UnitCreate: {
                auto name = fmt("v_%u", id.index);
                auto unit = std::get<ir::UnitPayload>(inst.payload).unit;
                if ( names_.at(_id.index).root )
                    b.addLocal(::hilti::ID(name), b.new_(b.typeName(::hilti::ID(unitName(unit))), meta), meta);
                else
                    b.addLocal(::hilti::ID(name),
                               b.qualifiedType(b.typeName(::hilti::ID(unitName(unit))), ::hilti::Constness::Mutable),
                               meta);
                values_[id.index] = std::move(name);
                return;
            }
            case ir::Opcode::PublishField: {
                auto field = std::get<ir::FieldPayload>(inst.payload).field;
                b.addAssign(b.member(_value(b, inst.args[0]), fieldName(field)), _value(b, inst.args[1]), meta);
                values_[id.index] = values_.at(inst.args[0].index);
                return;
            }
            case ir::Opcode::ReadInteger: _lowerRead(b, id, true); return;
            case ir::Opcode::ReadBytes: _lowerRead(b, id, false); return;
            case ir::Opcode::VectorEmpty: {
                auto name = fmt("v_%u", id.index);
                auto* type = targetType(b, package_, inst.result_type);
                b.addLocal(::hilti::ID(name), type, b.vector(type, {}, meta), meta);
                values_[id.index] = std::move(name);
                return;
            }
            case ir::Opcode::VectorAppend:
                b.addExpression(b.memberCall(_value(b, inst.args[0]), "push_back", {_value(b, inst.args[1])}, meta));
                values_[id.index] = values_.at(inst.args[0].index);
                return;
            case ir::Opcode::EnterBound: {
                auto* length = _value(b, inst.args[1]);
                auto overflow = b.addIf(b.greater(length,
                                                  b.difference(b.integer(std::numeric_limits<uint64_t>::max()),
                                                               b.memberCall(b.id(::hilti::ID("cursor")),
                                                                            "offset",
                                                                            ::hilti::Expressions{},
                                                                            meta))),
                                        meta);
                _return(*overflow, "ParseError", nullptr, meta);
                b.addAssign(b.id(::hilti::ID("outer_cursor")), b.id(::hilti::ID("cursor")), meta);
                b.addAssign(b.id(::hilti::ID("bound_end")),
                            b.sum(b.memberCall(b.id(::hilti::ID("cursor")), "offset", ::hilti::Expressions{}, meta),
                                  _value(b, inst.args[1])),
                            meta);
                b.addAssign(b.id(::hilti::ID("cursor")),
                            b.memberCall(b.id(::hilti::ID("cursor")), "limit", {length}, meta),
                            meta);
                values_[id.index] = "cursor";
                return;
            }
            case ir::Opcode::LeaveBound: {
                auto incomplete =
                    b.addIf(b.unequal(b.memberCall(b.id(::hilti::ID("cursor")), "offset", ::hilti::Expressions{}, meta),
                                      b.deref(b.id(::hilti::ID("bound_end")))),
                            meta);
                _return(*incomplete, "ParseError", nullptr, meta);
                b.addAssign(b.id(::hilti::ID("cursor")),
                            b.memberCall(b.id(::hilti::ID("outer_cursor")),
                                         "advance",
                                         {b.difference(b.deref(b.id(::hilti::ID("bound_end"))),
                                                       b.memberCall(b.id(::hilti::ID("outer_cursor")),
                                                                    "offset",
                                                                    ::hilti::Expressions{},
                                                                    meta))},
                                         meta),
                            meta);
                b.addAssign(b.id(::hilti::ID("bound_end")), b.null(), meta);
                values_[id.index] = "cursor";
                return;
            }
            case ir::Opcode::ParseSubunit: {
                const auto child = std::get<ir::FunctionPayload>(inst.payload).function;
                const auto& child_names = names_.at(child.index);
                auto name = fmt("v_%u", id.index);
                b.addLocal(::hilti::ID(name),
                           b.call(moduleLevel(child_names.function),
                                  {b.id(::hilti::ID("data")),
                                   b.id(::hilti::ID("cursor")),
                                   b.id(::hilti::ID("bound_end"))},
                                  meta),
                           meta);
                auto failed =
                    b.addIf(b.unequal(_member(b, name, "kind"), b.id(::hilti::ID("OutcomeKind::Success"))), meta);
                failed->addReturn(makeResult(*failed,
                                             _member(*failed, name, "kind"),
                                             nullptr,
                                             _member(*failed, name, "cursor"),
                                             _member(*failed, name, "gap_offset"),
                                             _member(*failed, name, "gap_length"),
                                             meta),
                                  meta);
                b.addAssign(b.id(::hilti::ID("cursor")), _member(b, name, "cursor"), meta);
                auto unit_value = fmt("v_%u_unit", id.index);
                b.addLocal(::hilti::ID(unit_value), b.deref(_member(b, name, "unit")), meta);
                _tuples[id.index] = {"cursor", unit_value};
                return;
            }
            case ir::Opcode::RepeatToBound: {
                std::vector<std::string> carried{"cursor"};
                for ( size_t i = 1; i < inst.args.size(); ++i ) {
                    auto name = fmt("carry_%u_%zu", id.index, i);
                    b.addLocal(::hilti::ID(name),
                               targetType(b, package_, package_.inst(inst.args[i]).result_type),
                               _value(b, inst.args[i]),
                               meta);
                    carried.push_back(std::move(name));
                }
                auto loop = b.addWhile(b.bool_(true), meta);
                auto at_end = loop->addIf(loop->equal(loop->memberCall(loop->id(::hilti::ID("cursor")),
                                                                       "offset",
                                                                       ::hilti::Expressions{},
                                                                       meta),
                                                      loop->deref(loop->id(::hilti::ID("bound_end")))),
                                          meta);
                at_end->addBreak(meta);
                loop->addLocal(::hilti::ID("old_offset"),
                               loop->memberCall(loop->id(::hilti::ID("cursor")),
                                                "offset",
                                                ::hilti::Expressions{},
                                                meta),
                               meta);
                const auto& body = package_.block(package_.region(inst.regions[0]).blocks[0]);
                for ( size_t i = 0; i < inst.args.size(); ++i )
                    values_[body.insts[i].index] = carried[i];
                for ( auto child_id : body.insts ) {
                    if ( package_.inst(child_id).opcode != ir::Opcode::Yield )
                        _lowerInst(*loop, child_id);
                }
                const auto& yielded = package_.inst(body.insts.back());
                // Evaluate all new values before assigning any of them: a yield may read a carried value that an
                // earlier assignment would already have overwritten.
                std::vector<std::pair<size_t, std::string>> updates;
                for ( size_t i = 1; i < carried.size(); ++i ) {
                    if ( values_.at(yielded.args[i].index) == carried[i] )
                        continue;
                    auto name = fmt("next_%u_%zu", id.index, i);
                    loop->addLocal(::hilti::ID(name),
                                   targetType(*loop, package_, package_.inst(inst.args[i]).result_type),
                                   _value(*loop, yielded.args[i]),
                                   meta);
                    updates.emplace_back(i, std::move(name));
                }
                for ( const auto& [i, name] : updates )
                    loop->addAssign(loop->id(::hilti::ID(carried[i])), loop->id(::hilti::ID(name)), meta);
                auto no_progress =
                    loop->addIf(loop->not_(loop->greater(loop->memberCall(loop->id(::hilti::ID("cursor")),
                                                                          "offset",
                                                                          ::hilti::Expressions{},
                                                                          meta),
                                                         loop->id(::hilti::ID("old_offset")))),
                                meta);
                _return(*no_progress, "ParseError", nullptr, meta);
                _tuples[id.index] = std::move(carried);
                return;
            }
            case ir::Opcode::Finish: _return(b, "Success", _value(b, inst.args[1]), meta); return;
            case ir::Opcode::Yield: return;
            default:
                if ( ! _lowerProcedural(b, id) )
                    ::hilti::util::cannotBeReached();
                return;
        }
    }

    ::hilti::Builder& _b;
    ir::FunctionId _id;
    std::unordered_map<uint32_t, std::vector<std::string>> _tuples;
};

// Lowers an ordinary function body. Each value is a named HILTI local or parameter. A place is the
// local (or `inout` parameter) it names, so a store assigns to that name and a native `inout` call
// receives the name by reference.
class ProcedureEmitter : public ProceduralOps {
public:
    ProcedureEmitter(::hilti::Builder& b, const ir::Package& package, const NameMap& names, ir::FunctionId id)
        : ProceduralOps(package, names), _b(b), _id(id) {}

    ::hilti::Declaration* emit() {
        const auto& fn = package_.function(_id);
        const auto& names = names_.at(_id.index);
        auto meta = metaFor(package_, fn.span);
        ::hilti::declaration::Parameters params;
        for ( size_t i = 0; i < fn.parameters.size(); ++i )
            params.push_back(parameterFor(_b, package_, fmt("arg_%zu", i), fn.parameters[i], meta));

        auto* body = _b.statementBlock(meta);
        LocalBuilder fb(_b.context(), body);
        _cfg = ir::buildCfg(package_, fn.root_region);
        _joins = ir::branchJoins(_cfg);
        _emitRange(fb, 0, std::nullopt);

        return _b.function(::hilti::ID(names.function),
                           resultType(_b, package_, fn.result_type),
                           params,
                           body,
                           ::hilti::type::function::Flavor::Function,
                           names.root ? ::hilti::declaration::Linkage::Public : ::hilti::declaration::Linkage::Private,
                           names.root ? ::hilti::type::function::CallingConvention::Extern :
                                        ::hilti::type::function::CallingConvention::Standard,
                           {},
                           meta);
    }

private:
    // Emits the blocks from position `pos` up to `stop`. A branch emits its arms up to its join, which follows them at
    // the same level, so the HILTI output nests exactly where the CFG branches. Coverage ensures every block is emitted
    // once.
    void _emitRange(LocalBuilder& b, size_t pos, std::optional<size_t> stop) {
        while ( pos != stop.value_or(ir::NoPosition) ) {
            const auto& insts = package_.block(_cfg.blocks[pos]).insts;
            for ( size_t i = 0; i + 1 < insts.size(); ++i ) {
                if ( ! _lowerProcedural(b, insts[i]) )
                    ::hilti::util::cannotBeReached();
            }

            const auto terminator = insts.back();
            const auto& inst = package_.inst(terminator);
            if ( inst.opcode == ir::Opcode::Jump ) {
                pos = _cfg.successors[pos][0];
                continue;
            }

            if ( inst.opcode != ir::Opcode::Branch ) {
                if ( ! _lowerProcedural(b, terminator) )
                    ::hilti::util::cannotBeReached();
                return;
            }

            auto arms = b.addIfElse(_value(b, inst.args[0]), metaFor(package_, inst.span));
            _emitRange(*arms.first, _cfg.successors[pos][0], _joins[pos]);
            _emitRange(*arms.second, _cfg.successors[pos][1], _joins[pos]);
            if ( ! _joins[pos] )
                return;

            pos = *_joins[pos];
        }
    }

    ::hilti::Builder& _b;
    ir::FunctionId _id;
    ir::Cfg _cfg;
    std::vector<std::optional<size_t>> _joins;
};

} // namespace

LoweringResult lower(::hilti::Builder& builder, const ir::Package& package) {
    auto unsupported = checkCoverage(package);
    if ( ! unsupported.empty() )
        return Unsupported{std::move(unsupported)};

    auto names = makeNames(package);
    ::hilti::Declarations decls = {builder.import("hilti"), builder.import("spicy_rt")};
    for ( const auto& include : package.cxxIncludes() )
        decls.push_back(builder.declarationProperty(::hilti::ID("%cxx-include"), builder.stringLiteral(include)));
    auto* outcome = builder.typeEnum(::hilti::type::enum_::Labels{
        builder.typeEnumLabel(::hilti::ID("Success")),
        builder.typeEnumLabel(::hilti::ID("UnexpectedEod")),
        builder.typeEnumLabel(::hilti::ID("Gap")),
        builder.typeEnumLabel(::hilti::ID("ParseError")),
    });
    decls.push_back(builder.declarationType(::hilti::ID("OutcomeKind"),
                                            builder.qualifiedType(outcome, ::hilti::Constness::Const),
                                            ::hilti::declaration::Linkage::Public));
    for ( size_t i = 0; i < package.typeDecls().size(); ++i )
        decls.push_back(lowerUnitType(builder, package, ir::TypeDeclId{static_cast<uint32_t>(i)}));
    for ( size_t i = 0; i < package.functions().size(); ++i ) {
        auto id = ir::FunctionId{static_cast<uint32_t>(i)};
        if ( package.function(id).kind == ir::FunctionKind::Parser )
            decls.push_back(lowerResultType(builder, package, id, names.at(id.index)));
    }
    for ( size_t i = 0; i < package.foreignFunctions().size(); ++i )
        decls.push_back(lowerForeignFunction(builder, package, ir::ForeignFunctionId{static_cast<uint32_t>(i)}));
    for ( size_t i = 0; i < package.functions().size(); ++i ) {
        auto id = ir::FunctionId{static_cast<uint32_t>(i)};
        if ( package.function(id).kind == ir::FunctionKind::Parser )
            decls.push_back(FunctionEmitter(builder, package, names, id).emit());
        else
            decls.push_back(ProcedureEmitter(builder, package, names, id).emit());
    }
    auto uid = ::hilti::declaration::module::UID(::hilti::ID(ModuleName), ".hlt", ".hlt");
    return builder.declarationModule(uid, {}, decls);
}

} // namespace spicy::detail::pir::backend::hilti
