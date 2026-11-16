// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cassert>
#include <functional>
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
#include <hilti/base/logger.h>
#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/analyses/field-use.h>
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

// The names of one parser entry: its adapter, its registered record, and its registration.
struct ParserEntryNames {
    std::string parse1;
    std::string parse3;
    std::string parser;
    std::string registration;
    std::string context_new;
};

// Names of the package's functions, plus the module-level names the backend generates for globals and parser entries.
struct NameMap : std::unordered_map<uint32_t, FunctionNames> {
    std::vector<std::string> globals;             /**< by global index */
    std::vector<ParserEntryNames> parser_entries; /**< by parser root index */
    /** Foreign functions that the target realizes itself, by function index. They get no declaration. */
    std::unordered_map<uint32_t, TargetBindingKind> bound;
    /**
     * The module-level types that give contexts their identity, and the root that defines each. The runtime compares
     * the type information of a context that it passes between parsers, so parsers share a type exactly when their
     * contexts share a declared name, or share element names and types if they have none.
     */
    std::vector<std::string> context_types;
    std::vector<size_t> context_type_roots;
    std::unordered_map<uint32_t, size_t> root_context_type; /**< by root function index */
};

// Public functions keep their source names where possible. Roots from different source modules may share a local name,
// and a name may collide with a generated one, so a clashing root gets a numeric suffix.
// TODO: Allocate implementation names by PIR identity to avoid collisions
// after target normalization, such as C++ class and class_.
NameMap makeNames(const ir::Package& package, const std::vector<TargetBinding>& bindings) {
    NameMap names;
    for ( const auto& binding : bindings )
        names.bound.emplace(binding.function.index, binding.kind);
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

    std::unordered_set<std::string> taken = {"OutcomeKind", "hilti", "spicy_rt", "exception_where"};
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

    // Generated names avoid every name that a public function keeps, so that a public function's name is never changed
    // to make room for them.
    auto unique = [&taken](const std::string& base) {
        auto name = base;
        for ( size_t n = 1; taken.contains(name); ++n )
            name = fmt("%s_%zu", base, n);
        taken.insert(name);
        return name;
    };
    for ( size_t i = 0; i < package.globals().size(); ++i )
        names.globals.push_back(unique(fmt("g_%zu", i)));
    for ( size_t i = 0; i < package.parserRoots().size(); ++i )
        names.parser_entries.push_back(ParserEntryNames{.parse1 = unique(fmt("parse1_%zu", i)),
                                                        .parse3 = unique(fmt("parse3_%zu", i)),
                                                        .parser = unique(fmt("parser_%zu", i)),
                                                        .registration = unique(fmt("register_parser_%zu", i)),
                                                        .context_new = unique(fmt("context_new_%zu", i))});
    std::unordered_map<std::string, size_t> context_keys;
    for ( size_t i = 0; i < package.parserRoots().size(); ++i ) {
        const auto& root = package.parserRoots()[i];
        if ( ! root.context )
            continue;

        auto key = root.context->name.empty() ?
                       fmt("tuple:%s:%u",
                           ::hilti::util::join(root.context->elements, ","),
                           package.type(package.function(root.function).parameters[1].type).type_arguments[0].index) :
                       "name:" + root.context->name;
        auto [it, inserted] = context_keys.emplace(key, names.context_types.size());
        if ( inserted ) {
            names.context_types.push_back(unique(fmt("Context_%zu", names.context_types.size())));
            names.context_type_roots.push_back(i);
        }
        names.root_context_type.emplace(root.function.index, it->second);
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
        case ir::TypeKind::Integer:
            return b.qualifiedType(type.integer.signedness == ir::Signedness::Signed ?
                                       static_cast<::hilti::UnqualifiedType*>(b.typeSignedInteger(type.integer.width)) :
                                       b.typeUnsignedInteger(type.integer.width),
                                   ::hilti::Constness::Mutable);
        case ir::TypeKind::Bytes: return b.qualifiedType(b.typeBytes(), ::hilti::Constness::Mutable);
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
            // The native port and protocol types are the HILTI types of the same names, which native calls take as they
            // are.
            if ( info.cxx_name == "hilti::rt::Port" )
                return b.qualifiedType(b.typePort(), ::hilti::Constness::Mutable);
            if ( info.cxx_name == "hilti::rt::Protocol" )
                return b.qualifiedType(b.typeName(::hilti::ID("hilti::Protocol")), ::hilti::Constness::Mutable);
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
        case ir::TypeKind::Set:
            return b.qualifiedType(b.typeSet(targetType(b, package, type.type_arguments[0])),
                                   ::hilti::Constness::Mutable);
        default: ::hilti::util::cannotBeReached();
    }
}

// An integer literal of exactly the PIR integer type `id`.
::hilti::Expression* integerLiteral(::hilti::Builder& b,
                                    const ir::Package& package,
                                    ir::TypeId id,
                                    uint64_t bits,
                                    const ::hilti::Meta& meta) {
    const auto integer = package.type(id).integer;
    if ( integer.signedness == ir::Signedness::Signed )
        return b.expressionCtor(b.ctorSignedInteger(ir::signedValue(bits, integer), integer.width, meta), meta);
    return b.expressionCtor(b.ctorUnsignedInteger(bits, integer.width, meta), meta);
}

// A field that some path does not publish is optional, so that reading it unset fails as in legacy. A field that is
// always present keeps plain storage, whose loads need no check.
::hilti::Declaration* lowerUnitType(::hilti::Builder& b,
                                    const ir::Package& package,
                                    const analyses::FieldPresence& presence,
                                    ir::TypeDeclId id) {
    const auto& unit = package.typeDecl(id);
    ::hilti::Declarations fields;
    for ( auto field_id : unit.fields ) {
        const auto& field = package.declaration(field_id);
        auto meta = metaFor(package, field.span);
        auto* attributes = presence.isConditional(field_id) ?
                               b.attributeSet({b.attribute(::hilti::attribute::kind::Optional, meta)}, meta) :
                               static_cast<::hilti::AttributeSet*>(nullptr);
        fields.push_back(
            b.declarationField(::hilti::ID(fieldName(field_id)), targetType(b, package, field.type), attributes, meta));
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
        // A failure's description and location. Success, which every child call returns, leaves them unset, so it
        // builds and copies no strings.
        b.declarationField(::hilti::ID("failure"),
                           b.qualifiedType(b.typeOptional(
                                               b.qualifiedType(b.typeTuple(::hilti::QualifiedTypes{
                                                                   b.qualifiedType(b.typeString(),
                                                                                   ::hilti::Constness::Mutable),
                                                                   b.qualifiedType(b.typeString(),
                                                                                   ::hilti::Constness::Mutable)}),
                                                               ::hilti::Constness::Mutable)),
                                           ::hilti::Constness::Mutable),
                           static_cast<::hilti::AttributeSet*>(nullptr)),
    };
    auto* result = b.typeStruct(fields);
    // Every outcome explicitly supplies all fields, including empty optionals. Child calls need no extra
    // optional constructor arguments to represent omitted initializers, nor default-then-assign construction.
    if ( ! names.root )
        result->setUsesDirectFieldInitialization();
    return b.declarationType(::hilti::ID(names.result),
                             b.qualifiedType(result, ::hilti::Constness::Const),
                             ::hilti::declaration::Linkage::Public);
}

::hilti::Expression* makeResult(::hilti::Builder& b,
                                ::hilti::Expression* kind,
                                ::hilti::Expression* unit,
                                ::hilti::Expression* cursor,
                                ::hilti::Expression* gap_offset,
                                ::hilti::Expression* gap_length,
                                const ::hilti::Meta& meta,
                                ::hilti::Expression* failure = nullptr) {
    ::hilti::ctor::struct_::Fields fields = {
        b.ctorStructField(::hilti::ID("kind"), kind),
        b.ctorStructField(::hilti::ID("unit"), unit ? unit : b.null()),
        b.ctorStructField(::hilti::ID("cursor"), cursor),
        b.ctorStructField(::hilti::ID("gap_offset"), gap_offset),
        b.ctorStructField(::hilti::ID("gap_length"), gap_length),
        b.ctorStructField(::hilti::ID("failure"), failure ? failure : b.null()),
    };
    return b.struct_(fields, meta);
}

// A failure's `(description, location)`.
::hilti::Expression* makeFailure(::hilti::Builder& b,
                                 ::hilti::Expression* description,
                                 ::hilti::Expression* location,
                                 const ::hilti::Meta& meta) {
    return b.tuple({description, location}, meta);
}

// Element `index` of a result's failure, which must be set.
::hilti::Expression* failurePart(::hilti::Builder& b, ::hilti::Expression* result, unsigned index) {
    return b.index(b.deref(b.member(result, "failure")), b.integer(index));
}

using LocalBuilder = ::hilti::ExtendedBuilderTemplate<::hilti::Builder>;

::hilti::QualifiedType* resultType(::hilti::Builder& b, const ir::Package& package, ir::TypeId id) {
    if ( id == package.voidType() )
        return b.qualifiedType(b.typeVoid(), ::hilti::Constness::Mutable);
    return targetType(b, package, id);
}

// A borrowed parameter is passed by reference, so the caller's storage or object is what the callee sees. HILTI's `in`
// is a constant reference and `inout` a mutable one, so the access follows the parameter's mode and never the
// representation of the argument. A place stands for the storage it names, and a unit for the object, whose
// struct the callee receives.
::hilti::declaration::Parameter* parameterFor(::hilti::Builder& b,
                                              const ir::Package& package,
                                              const std::string& name,
                                              const ir::Parameter& parameter,
                                              const ::hilti::Meta& meta) {
    const auto& type = package.type(parameter.type);
    auto* target = type.kind == ir::TypeKind::Place ? targetType(b, package, type.type_arguments[0])->type() :
                                                      targetType(b, package, parameter.type)->type();
    auto kind =
        parameter.mode == ir::ParameterMode::BorrowMut ? ::hilti::parameter::Kind::InOut : ::hilti::parameter::Kind::In;
    return b.parameter(::hilti::ID(name), target, kind, meta);
}

// A formal of a foreign function. `any` and `tuple<*>` formals are the HILTI types the runtime declares, so the
// HILTI compiler supplies the concrete type information or tuple elements at each call.
::hilti::declaration::Parameter* foreignParameterFor(::hilti::Builder& b,
                                                     const ir::Package& package,
                                                     const std::string& name,
                                                     const ir::ForeignParameter& parameter,
                                                     const ::hilti::Meta& meta) {
    switch ( parameter.argument ) {
        case ir::ForeignArgument::Value:
            // A native `inout` takes the caller's place, which a place type states.
            return parameterFor(b,
                                package,
                                name,
                                ir::Parameter(parameter.type,
                                              package.type(parameter.type).kind == ir::TypeKind::Place ?
                                                  ir::ParameterMode::BorrowMut :
                                                  ir::ParameterMode::Take),
                                meta);
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

// The phase of a module-level function that initialization runs, if the package lists it as an initializer.
std::optional<::hilti::declaration::Linkage> initializerLinkage(const ir::Package& package, ir::FunctionId id) {
    for ( const auto& initializer : package.initializers() ) {
        if ( initializer.function != id )
            continue;
        return initializer.phase == ir::InitPhase::PreInit ? ::hilti::declaration::Linkage::PreInit :
                                                             ::hilti::declaration::Linkage::Init;
    }
    return std::nullopt;
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

    // The unit that a parser root creates is held through a reference, whereas a callee's parameter receives the unit
    // itself. Dereferencing hands over the same object, so the callee's access is to the caller's unit, not a copy.
    ::hilti::Expression* _argument(LocalBuilder& b, ir::InstId id) {
        auto* value = _value(b, id);
        return held_by_reference_.contains(id.index) ? b.deref(value) : value;
    }

    // A local of a value, unless the value is used across blocks: then its local is declared at function entry, and
    // this assigns it.
    void _local(LocalBuilder& b,
                const std::string& name,
                ::hilti::QualifiedType* type,
                ::hilti::Expression* init,
                const ::hilti::Meta& meta) {
        if ( hoisted_.contains(name) ) {
            if ( init )
                b.addAssign(b.id(::hilti::ID(name)), init, meta);
            return;
        }

        if ( init )
            b.addLocal(::hilti::ID(name), type, init, meta);
        else
            b.addLocal(::hilti::ID(name), type, meta);
    }

    // The local that holds a value, and the instruction whose lowering declares it. A value that needs no declaration,
    // such as the cursor or a parameter, has no owner.
    struct Storage {
        std::string name;
        ir::InstId owner;
        ir::TypeId type;
    };

    Storage _argumentStorage(uint32_t index) const {
        if ( auto it = arguments_.find(index); it != arguments_.end() )
            return it->second;
        ::hilti::logger().internalError("unbound PIR function argument");
    }

    Storage _storage(ir::InstId id) {
        const auto& inst = package_.inst(id);
        const Storage self{.name = fmt("v_%u", id.index), .owner = id, .type = inst.result_type};
        const Storage cursor{.name = "cursor"};
        switch ( inst.opcode ) {
            case ir::Opcode::Argument: {
                return _argumentStorage(std::get<ir::ArgumentPayload>(inst.payload).index);
            }
            case ir::Opcode::TupleGet: {
                auto tuple = inst.args[0];
                auto index = std::get<ir::TupleGetPayload>(inst.payload).index;
                switch ( package_.inst(tuple).opcode ) {
                    case ir::Opcode::ReadInteger:
                    case ir::Opcode::ReadBytes:
                    case ir::Opcode::ExpectBytes:
                        return index == 0 ?
                                   cursor :
                                   Storage{.name = fmt("v_%u", tuple.index), .owner = tuple, .type = inst.result_type};
                    case ir::Opcode::ParseSubunit:
                        return index == 0 ? cursor :
                                            Storage{.name = fmt("v_%u_unit", tuple.index),
                                                    .owner = tuple,
                                                    .type = inst.result_type};
                    case ir::Opcode::RepeatToBound:
                        return index == 0 ? cursor :
                                            Storage{.name = fmt("carry_%u_%u", tuple.index, index),
                                                    .owner = tuple,
                                                    .type = inst.result_type};
                    default: return self;
                }
            }
            // These extend or address the storage of their first operand.
            case ir::Opcode::PublishField:
            case ir::Opcode::VectorAppend:
            case ir::Opcode::SetInsert:
            case ir::Opcode::FieldPlace: return _storage(inst.args[0]);
            case ir::Opcode::EnterBound:
            case ir::Opcode::LeaveBound:
            case ir::Opcode::ReleaseInput: return cursor;
            case ir::Opcode::GlobalPlace:
                return Storage{.name = names_.globals.at(std::get<ir::GlobalPayload>(inst.payload).global.index)};
            case ir::Opcode::ForeignConstant: return Storage{.name = std::get<ir::StringLiteral>(inst.payload).value};
            case ir::Opcode::LocalPlace:
                return Storage{.name = fmt("p_%u", id.index),
                               .owner = id,
                               .type = package_.type(inst.result_type).type_arguments[0]};
            case ir::Opcode::Phi: {
                if ( auto coalesced = _coalesced(id) )
                    return *coalesced;
                return self;
            }
            default: return self;
        }
    }

    // The storage that a Phi shares with every value its Upsilons write, if they all have the same one. The Phi and
    // its Upsilons then need no code. This always holds for the parser state, which is the cursor, and for a unit
    // built from one `unit.create`.
    std::optional<Storage> _coalesced(ir::InstId phi) {
        if ( auto it = coalesced_.find(phi.index); it != coalesced_.end() )
            return it->second;

        // A Phi that its own Upsilon writes again names the same storage, so it does not decide.
        coalesced_.emplace(phi.index, std::nullopt);
        std::optional<Storage> shared;
        bool same = true;
        bool any = false;
        for ( auto upsilon : upsilons_[phi.index] ) {
            auto value = package_.inst(upsilon).args[0];
            if ( value == phi )
                continue;
            auto storage = _storage(value);
            if ( any && storage.name != shared->name )
                same = false;
            shared = storage;
            any = true;
        }

        std::optional<Storage> result;
        if ( any && same )
            result = shared;
        coalesced_[phi.index] = result;
        return result;
    }

    // Lowers a body whose control flow is the CFG of `region`. One block is emitted inline. Otherwise each block in
    // reverse postorder becomes a nested block, labeled if a goto targets it. The entry stays at function level, and
    // values used across blocks are declared there, before any label, so no goto jumps into a local's scope.
    template<typename LowerInst>
    void _emitBody(LocalBuilder& fb, ir::RegionId region, LowerInst lower) {
        auto cfg = ir::buildCfg(package_, region);
        auto order = ir::postorder(cfg.successors, 0);
        std::ranges::reverse(order);

        // Unreachable blocks are not emitted, so their Upsilons neither write a shadow nor decide coalescing.
        for ( auto pos : order )
            for ( auto id : package_.block(cfg.blocks[pos]).insts )
                if ( const auto* upsilon = std::get_if<ir::UpsilonPayload>(&package_.inst(id).payload) )
                    upsilons_[upsilon->phi.index].push_back(id);

        std::vector<std::pair<std::string, Storage>> hoisted;
        auto hoist = [&](const Storage& storage) {
            if ( hoisted_.insert(storage.name).second )
                hoisted.emplace_back(storage.name, storage);
        };

        if ( order.size() == 1 ) {
            // A shadow that the block's own Upsilons write still needs its declaration.
            for ( auto id : package_.block(cfg.blocks[0]).insts )
                if ( package_.inst(id).opcode == ir::Opcode::Phi && ! _coalesced(id) )
                    hoist(Storage{.name = fmt("phi_%u", id.index), .owner = id, .type = package_.inst(id).result_type});
            for ( const auto& [name, storage] : hoisted )
                fb.addLocal(::hilti::ID(name), _storageType(fb, storage));
            for ( auto id : package_.block(cfg.blocks[0]).insts )
                lower(fb, id);
            return;
        }

        for ( auto pos : order ) {
            for ( auto id : package_.block(cfg.blocks[pos]).insts ) {
                const auto& inst = package_.inst(id);
                auto use = [&](const Storage& storage) {
                    // The entry's locals are at function level already.
                    auto owner_block = storage.owner.isSet() ? package_.inst(storage.owner).parent : ir::BlockId{};
                    if ( storage.owner.isSet() && owner_block != inst.parent && owner_block != cfg.blocks[0] )
                        hoist(storage);
                };
                // Parser results are virtual tuples: only their projected values have physical storage.
                // In particular, parser.state is the existing cursor, never a tuple element to materialize.
                if ( inst.opcode == ir::Opcode::TupleGet &&
                     package_.type(package_.type(package_.inst(inst.args[0]).result_type).type_arguments[0]).kind ==
                         ir::TypeKind::ParserState )
                    use(_storage(id));
                else
                    for ( auto arg : inst.args )
                        use(_storage(arg));
                if ( inst.opcode == ir::Opcode::Phi && ! _coalesced(id) )
                    hoist(Storage{.name = fmt("phi_%u", id.index), .owner = id, .type = inst.result_type});
            }
        }
        for ( const auto& [name, storage] : hoisted )
            fb.addLocal(::hilti::ID(name), _storageType(fb, storage));

        std::vector<size_t> next(cfg.blocks.size(), ir::NoPosition);
        for ( size_t k = 0; k + 1 < order.size(); ++k )
            next[order[k]] = order[k + 1];

        // A block needs a label only if some goto targets it, which falling through to it avoids.
        auto position = [&](ir::BlockId block) { return cfg.position.at(block.index); };
        std::unordered_set<size_t> targets;
        for ( auto pos : order ) {
            const auto& terminator = package_.inst(package_.block(cfg.blocks[pos]).insts.back());
            if ( terminator.opcode == ir::Opcode::Jump || terminator.opcode == ir::Opcode::Branch ) {
                for ( auto successor : cfg.successors[pos] )
                    if ( successor != next[pos] )
                        targets.insert(successor);
            }
            else
                targets.insert(cfg.successors[pos].begin(), cfg.successors[pos].end());
        }

        auto label = [&](size_t pos) { return ::hilti::ID(fmt("b%u", cfg.blocks[pos].index)); };
        for ( size_t k = 0; k < order.size(); ++k ) {
            auto pos = order[k];
            const auto& insts = package_.block(cfg.blocks[pos]).insts;
            const auto& terminator = package_.inst(insts.back());
            auto meta = metaFor(package_, terminator.span);
            if ( k > 0 && targets.contains(pos) )
                fb.addLabel(label(pos), meta);

            std::shared_ptr<LocalBuilder> nested;
            if ( k > 0 )
                nested = fb.addBlock(meta);
            auto& b = nested ? *nested : fb;

            for ( size_t i = 0; i + 1 < insts.size(); ++i )
                lower(b, insts[i]);

            switch ( terminator.opcode ) {
                case ir::Opcode::Jump: {
                    auto target = position(std::get<ir::JumpPayload>(terminator.payload).target);
                    if ( target != next[pos] )
                        b.addGoto(label(target), meta);
                    break;
                }
                case ir::Opcode::Switch: {
                    // Each case jumps to its target. Cases that share a target share a HILTI case.
                    const auto& payload = std::get<ir::SwitchPayload>(terminator.payload);
                    auto operand_type = package_.inst(terminator.args[0]).result_type;
                    auto cases = b.addSwitch(_value(b, terminator.args[0]), meta);
                    std::vector<std::pair<ir::BlockId, ::hilti::Expressions>> grouped;
                    for ( const auto& c : payload.cases ) {
                        auto it = std::ranges::find_if(grouped, [&](const auto& g) { return g.first == c.target; });
                        if ( it == grouped.end() ) {
                            grouped.emplace_back(c.target, ::hilti::Expressions{});
                            it = std::prev(grouped.end());
                        }
                        it->second.push_back(integerLiteral(b, package_, operand_type, c.value.bits, meta));
                    }
                    for ( auto& [target, values] : grouped )
                        cases.addCase(values, meta)->addGoto(label(position(target)), meta);
                    cases.addDefault(meta)->addGoto(label(position(payload.default_target)), meta);
                    break;
                }
                case ir::Opcode::Branch: {
                    const auto& payload = std::get<ir::BranchPayload>(terminator.payload);
                    auto then_ = position(payload.then_block);
                    auto else_ = position(payload.else_block);
                    auto* condition = _value(b, terminator.args[0]);
                    if ( then_ == else_ ) {
                        if ( then_ != next[pos] )
                            b.addGoto(label(then_), meta);
                    }
                    else if ( else_ == next[pos] )
                        b.addIf(condition, meta)->addGoto(label(then_), meta);
                    else if ( then_ == next[pos] )
                        b.addIf(b.not_(condition, meta), meta)->addGoto(label(else_), meta);
                    else {
                        auto arms = b.addIfElse(condition, meta);
                        arms.first->addGoto(label(then_), meta);
                        arms.second->addGoto(label(else_), meta);
                    }
                    break;
                }
                default: lower(b, insts.back()); break;
            }
        }
    }

    // The HILTI type of a local declared at function entry.
    virtual ::hilti::QualifiedType* _storageType(LocalBuilder& b, const Storage& storage) {
        return targetType(b, package_, storage.type);
    }

    // The value of an operand that the operation consumes. An affine value moves, since nothing uses it again.
    ::hilti::Expression* _consumed(LocalBuilder& b, ir::InstId id, const ::hilti::Meta& meta) {
        auto* value = _value(b, id);
        if ( ir::typeDiscipline(package_, package_.inst(id).result_type) == ir::ValueDiscipline::Affine &&
             ! held_by_reference_.contains(id.index) )
            return b.move(value, meta);
        return value;
    }

    // Lowers one procedural operation, returning false for an operation that is not procedural.
    bool _lowerProcedural(LocalBuilder& b, ir::InstId id) {
        const auto& inst = package_.inst(id);
        auto meta = metaFor(package_, inst.span);
        switch ( inst.opcode ) {
            case ir::Opcode::Argument: values_[id.index] = _storage(id).name; return true;
            case ir::Opcode::Add: {
                auto name = fmt("v_%u", id.index);
                _local(b,
                       name,
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
                if ( inst.opcode == ir::Opcode::OpaqueOp ) {
                    // A call to a function that the target realizes becomes the target's own expression.
                    auto function = std::get<ir::ForeignFunctionPayload>(inst.payload).function;
                    if ( auto bound = names_.bound.find(function.index); bound != names_.bound.end() ) {
                        // The scope of the linked artifact is the only target binding so far.
                        assert(bound->second == TargetBindingKind::LinkedArtifactScope);
                        auto name = fmt("v_%u", id.index);
                        _local(b, name, targetType(b, package_, inst.result_type), b.scope(meta), meta);
                        values_[id.index] = std::move(name);
                        return true;
                    }
                }

                ::hilti::ID callee =
                    inst.opcode == ir::Opcode::Call ?
                        moduleLevel(names_.at(std::get<ir::FunctionPayload>(inst.payload).function.index).function) :
                        moduleLevel(
                            fmt("foreign_%u", std::get<ir::ForeignFunctionPayload>(inst.payload).function.index));
                ::hilti::Expressions args;
                for ( auto arg : inst.args )
                    args.push_back(_argument(b, arg));
                auto* call = b.call(callee, args, meta);
                if ( inst.result_type == package_.voidType() ) {
                    b.addExpression(call);
                    return true;
                }

                auto name = fmt("v_%u", id.index);
                _local(b, name, targetType(b, package_, inst.result_type), call, meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::LocalPlace: {
                auto name = fmt("p_%u", id.index);
                auto element = package_.type(inst.result_type).type_arguments[0];
                _local(b, name, targetType(b, package_, element), _value(b, inst.args[0]), meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::Load: {
                auto name = fmt("v_%u", id.index);
                _local(b, name, targetType(b, package_, inst.result_type), _value(b, inst.args[0]), meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::FieldPlace: {
                auto field = std::get<ir::FieldPayload>(inst.payload).field;
                fields_[id.index] = {values_.at(inst.args[0].index), fieldName(field)};
                return true;
            }
            case ir::Opcode::GlobalPlace:
                values_[id.index] = names_.globals.at(std::get<ir::GlobalPayload>(inst.payload).global.index);
                return true;
            case ir::Opcode::Store: b.addAssign(_value(b, inst.args[0]), _value(b, inst.args[1]), meta); return true;
            case ir::Opcode::Equal: {
                auto name = fmt("v_%u", id.index);
                _local(b,
                       name,
                       targetType(b, package_, inst.result_type),
                       b.equal(_value(b, inst.args[0]), _value(b, inst.args[1]), meta),
                       meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::VectorEmpty: {
                auto name = fmt("v_%u", id.index);
                auto* type = targetType(b, package_, inst.result_type);
                _local(b, name, type, b.vector(type, {}, meta), meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::VectorAppend:
                // The vector is affine, so the append extends the storage its operand names.
                b.addExpression(
                    b.memberCall(_value(b, inst.args[0]), "push_back", {_consumed(b, inst.args[1], meta)}, meta));
                values_[id.index] = values_.at(inst.args[0].index);
                return true;
            case ir::Opcode::SetEmpty: {
                auto name = fmt("v_%u", id.index);
                _local(b, name, targetType(b, package_, inst.result_type), nullptr, meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::SetInsert:
                // As for a vector, the insertion extends the storage its operand names.
                b.addExpression(b.add(_value(b, inst.args[0]), _value(b, inst.args[1]), meta));
                values_[id.index] = values_.at(inst.args[0].index);
                return true;
            case ir::Opcode::Tuple: {
                ::hilti::Expressions elements;
                for ( auto element : inst.args )
                    elements.push_back(_value(b, element));
                auto name = fmt("v_%u", id.index);
                _local(b, name, targetType(b, package_, inst.result_type), b.tuple(elements, meta), meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::TupleGet: {
                auto name = fmt("v_%u", id.index);
                _local(b,
                       name,
                       targetType(b, package_, inst.result_type),
                       b.index(_value(b, inst.args[0]),
                               b.integer(std::get<ir::TupleGetPayload>(inst.payload).index),
                               meta),
                       meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::IntConstant: {
                auto name = fmt("v_%u", id.index);
                _local(b,
                       name,
                       targetType(b, package_, inst.result_type),
                       integerLiteral(b,
                                      package_,
                                      inst.result_type,
                                      std::get<ir::IntegerLiteral>(inst.payload).bits,
                                      meta),
                       meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::Convert: {
                auto name = fmt("v_%u", id.index);
                auto* operand = _value(b, inst.args[0]);
                ::hilti::Expression* converted = nullptr;
                switch ( std::get<ir::ConversionPayload>(inst.payload).rule ) {
                    case ir::ConversionRule::IntegerWiden:
                        converted = b.cast(operand, targetType(b, package_, inst.result_type), meta);
                        break;
                    case ir::ConversionRule::IntegerToBool:
                        converted =
                            b.unequal(operand,
                                      integerLiteral(b, package_, package_.inst(inst.args[0]).result_type, 0, meta),
                                      meta);
                        break;
                }
                _local(b, name, targetType(b, package_, inst.result_type), converted, meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::Phi: {
                // A coalesced Phi names the storage its Upsilons already wrote. Otherwise it reads its shadow into
                // its own local, so that a later write of the shadow cannot change the value it read.
                if ( auto shared = _coalesced(id) ) {
                    auto upsilon = std::ranges::find_if(upsilons_[id.index],
                                                        [&](auto u) { return package_.inst(u).args[0] != id; });
                    auto value = package_.inst(*upsilon).args[0];
                    values_[id.index] = values_.at(value.index);
                    if ( held_by_reference_.contains(value.index) )
                        held_by_reference_.insert(id.index);
                    return true;
                }

                ::hilti::Expression* shadow = b.id(::hilti::ID(fmt("phi_%u", id.index)));
                if ( ir::typeDiscipline(package_, inst.result_type) == ir::ValueDiscipline::Affine )
                    shadow = b.move(shadow, meta);
                auto name = fmt("v_%u", id.index);
                _local(b, name, targetType(b, package_, inst.result_type), shadow, meta);
                values_[id.index] = std::move(name);
                return true;
            }
            case ir::Opcode::Upsilon: {
                auto phi = std::get<ir::UpsilonPayload>(inst.payload).phi;
                if ( _coalesced(phi) )
                    return true;

                auto shadow = fmt("phi_%u", phi.index);
                if ( values_.at(inst.args[0].index) == shadow )
                    return true;

                // An affine value is consumed, so the shadow takes over its storage.
                auto* value = _value(b, inst.args[0]);
                if ( ir::typeDiscipline(package_, package_.inst(inst.args[0]).result_type) ==
                     ir::ValueDiscipline::Affine )
                    value = b.move(value, meta);
                b.addAssign(b.id(::hilti::ID(shadow)), value, meta);
                return true;
            }
            case ir::Opcode::ForeignConstant:
                // A native constant is named where it is used, so it needs no local.
                values_[id.index] = std::get<ir::StringLiteral>(inst.payload).value;
                return true;
            case ir::Opcode::PortConstant: {
                auto name = fmt("v_%u", id.index);
                const auto& port = std::get<ir::PortLiteral>(inst.payload);
                ::hilti::rt::Protocol protocol = ::hilti::rt::Protocol::TCP;
                if ( port.transport == ir::Transport::UDP )
                    protocol = ::hilti::rt::Protocol::UDP;
                else if ( port.transport == ir::Transport::ICMP )
                    protocol = ::hilti::rt::Protocol::ICMP;
                _local(b,
                       name,
                       targetType(b, package_, inst.result_type),
                       b.port(::hilti::rt::Port(port.number, protocol), meta),
                       meta);
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
                _local(b, name, targetType(b, package_, inst.result_type), value, meta);
                values_[id.index] = std::move(name);
                return true;
            }
            default: return false;
        }

        return true;
    }

    const ir::Package& package_;
    const NameMap& names_;
    /** Units that are held through a reference rather than by value, by instruction index. */
    std::unordered_set<uint32_t> held_by_reference_;
    /** Parameter storage, bound by the emitter before planning or lowering the function body. */
    std::unordered_map<uint32_t, Storage> arguments_;
    std::unordered_map<uint32_t, std::string> values_;
    std::unordered_map<uint32_t, std::pair<std::string, std::string>> fields_;
    /** Locals declared at function entry because blocks other than their own use them. */
    std::unordered_set<std::string> hoisted_;
    /** The Upsilons of each Phi, by Phi index. */
    std::unordered_map<uint32_t, std::vector<ir::InstId>> upsilons_;
    std::unordered_map<uint32_t, std::optional<Storage>> coalesced_;
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

        // A parser that shares a context receives it by reference, so every parser of the connection updates one
        // object.
        if ( fn.parameters.size() == 2 )
            params.push_back(
                _b.parameter(::hilti::ID("context"),
                             _b.typeName(::hilti::ID(names_.context_types[names_.root_context_type.at(_id.index)])),
                             ::hilti::parameter::Kind::InOut,
                             meta));

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

        arguments_.emplace(0, Storage{.name = "cursor"});
        if ( fn.parameters.size() == 2 )
            arguments_.emplace(1, Storage{.name = "context"});
        _emitBody(fb, fn.root_region, [this](LocalBuilder& b, ir::InstId id) { _lowerInst(b, id); });

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
    // A root holds the unit it creates through a reference.
    ::hilti::QualifiedType* _storageType(LocalBuilder& b, const Storage& storage) final {
        if ( names_.at(_id.index).root && package_.inst(storage.owner).opcode == ir::Opcode::UnitCreate )
            return unitReferenceType(b, package_.function(_id).parser_unit);
        return ProceduralOps::_storageType(b, storage);
    }

    ::hilti::Expression* _member(LocalBuilder& b, std::string_view base, std::string_view member) {
        return b.member(b.id(::hilti::ID(base)), std::string(member));
    }

    // Returns an outcome. A failure carries its description and the location of the operation that failed.
    void _return(LocalBuilder& b,
                 std::string_view kind,
                 ::hilti::Expression* unit,
                 const ::hilti::Meta& meta,
                 ::hilti::Expression* description = nullptr) {
        auto* failure =
            description ? makeFailure(b, description, b.stringLiteral(std::string(meta.location())), meta) : nullptr;
        b.addReturn(makeResult(b,
                               b.id(::hilti::ID(fmt("OutcomeKind::%s", kind))),
                               unit,
                               b.id(::hilti::ID("cursor")),
                               b.integer(0U),
                               b.integer(0U),
                               meta,
                               failure),
                    meta);
    }

    // An expression of a byte count. Each use needs its own expression node.
    using ByteCount = std::function<::hilti::Expression*(LocalBuilder&)>;

    // The description of a read that failed with `available` bytes left before the end of input or the bound.
    using Describe = std::function<::hilti::Expression*(LocalBuilder&, const ByteCount& available)>;

    // `format % (values...)`, the HILTI formatting that legacy parsing uses for its messages.
    static ::hilti::Expression* _format(LocalBuilder& b, const std::string& format, ::hilti::Expressions values) {
        return b.modulo(b.stringLiteral(format), b.tuple(values));
    }

    // A crossing read sees the bound as the end of input, as legacy does with its limited view. Its available count
    // is measured to the bound.
    void _checkBound(LocalBuilder& b, const ByteCount& bytes, const Describe& describe, const ::hilti::Meta& meta) {
        auto inside = b.addIf(b.id(::hilti::ID("bound_end")), meta);
        ByteCount to_bound = [](LocalBuilder& lb) {
            return lb.difference(lb.deref(lb.id(::hilti::ID("bound_end"))),
                                 lb.memberCall(lb.id(::hilti::ID("cursor")), "offset", ::hilti::Expressions{}));
        };
        auto over = inside->addIf(inside->greater(bytes(*inside), to_bound(*inside)), meta);
        _return(*over, "ParseError", nullptr, meta, describe(*over, to_bound));
    }

    void _wait(LocalBuilder& b, const ByteCount& bytes, const Describe& describe, const ::hilti::Meta& meta) {
        // Keep the common case in generated code, just like the runtime's inline waitForInput wrapper.
        auto slow = b.addIf(b.greater(bytes(b), b.size(b.id(::hilti::ID("cursor")))), meta);
        // EnterBound limits the cursor, and subunits inherit that limited view. Available bytes therefore also
        // satisfy the bound. On insufficient input, check the bound before waiting to preserve failure outcomes.
        _checkBound(*slow, bytes, describe, meta);
        auto* call =
            b.call(::hilti::ID("spicy_rt::waitForInputOrEod"),
                   {b.id(::hilti::ID("data")), b.id(::hilti::ID("cursor")), bytes(b), b.id(::hilti::ID("filters_"))},
                   meta);
        auto eod = slow->addIf(b.not_(call), meta);
        ByteCount in_input = [](LocalBuilder& lb) { return lb.size(lb.id(::hilti::ID("cursor"))); };
        _return(*eod, "UnexpectedEod", nullptr, meta, describe(*eod, in_input));
    }

    // Wraps `try_body` in a `try` that turns a gap into a gap outcome. `extra` are more catch clauses of that `try`.
    void _gapCatch(LocalBuilder& b,
                   ::hilti::Statement* try_body,
                   const ::hilti::Meta& meta,
                   ::hilti::statement::try_::Catches extra = {}) {
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
        // The stream's view starts where retained input does, which is past offset zero once input is released, so
        // the probe's absolute offset is taken relative to it.
        cb.addLocal(::hilti::ID("retained"),
                    cb.qualifiedType(cb.typeStreamView(), ::hilti::Constness::Mutable),
                    cb.cast(cb.deref(cb.id(::hilti::ID("data"))),
                            cb.qualifiedType(cb.typeStreamView(), ::hilti::Constness::Mutable)),
                    meta);
        cb.addLocal(::hilti::ID("full_probe"),
                    cb.memberCall(cb.id(::hilti::ID("retained")),
                                  "advance",
                                  {cb.difference(cb.memberCall(cb.id(::hilti::ID("gap_probe")),
                                                               "offset",
                                                               ::hilti::Expressions{},
                                                               meta),
                                                 cb.memberCall(cb.id(::hilti::ID("retained")),
                                                               "offset",
                                                               ::hilti::Expressions{},
                                                               meta))},
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
                                meta,
                                // The runtime's own description and location, as legacy reports them.
                                makeFailure(cb,
                                            cb.memberCall(cb.id(::hilti::ID("e")),
                                                          "description",
                                                          ::hilti::Expressions{},
                                                          meta),
                                            cb.call(moduleLevel("exception_where"), {cb.id(::hilti::ID("e"))}, meta),
                                            meta)),
                     meta);
        auto* catch_param = _b.parameter(::hilti::ID("e"),
                                         _b.typeName(::hilti::ID("hilti::MissingData")),
                                         ::hilti::parameter::Kind::In);
        auto* catch_clause = _b.statementTryCatch(catch_param, catch_body, meta);
        extra.insert(extra.begin(), catch_clause);
        b.block()->_add(b.context(), _b.statementTry(try_body, extra, meta));
    }

    void _lowerRead(LocalBuilder& b, ir::InstId id, bool integer) {
        const auto& inst = package_.inst(id);
        auto meta = metaFor(package_, inst.span);
        ByteCount bytes = [&](LocalBuilder& lb) {
            return integer ?
                       lb.integer(static_cast<uint64_t>(std::get<ir::ReadIntegerPayload>(inst.payload).width / 8)) :
                       _value(lb, inst.args[1]);
        };
        // The descriptions of `waitForInput` and `extractBytes` in the runtime.
        Describe describe = [&](LocalBuilder& lb, const ByteCount& available) {
            if ( integer )
                return _format(lb,
                               fmt("expecting %u bytes for unpacking value (%%u byte%%s available)",
                                   std::get<ir::ReadIntegerPayload>(inst.payload).width / 8),
                               {available(lb),
                                lb.ternary(lb.unequal(available(lb), lb.integer(1U)),
                                           lb.stringLiteral("s"),
                                           lb.stringLiteral(""))});
            return _format(lb, "expected %u bytes (%u available)", {bytes(lb), available(lb)});
        };
        _wait(b, bytes, describe, meta);
        auto value_name = fmt("v_%u", id.index);
        auto* value_type = targetType(b, package_, package_.type(inst.result_type).type_arguments[1]);
        // Keep the field location on the statement as well as its declaration, so this temporary does not
        // introduce a whole-unit location update between the availability check and the read.
        if ( ! hoisted_.contains(value_name) ) {
            auto* declaration = b.declarationLocalVariable(::hilti::ID(value_name), value_type, {}, meta);
            b.block()->_add(b.context(), b.statementDeclaration(declaration, meta));
        }
        auto* try_body = _b.statementBlock(meta);
        LocalBuilder tb(_b.context(), try_body);
        const auto* read = std::get_if<ir::ReadIntegerPayload>(&inst.payload);
        if ( read && read->width == 8 ) {
            // Availability is established above; dereferencing still detects gaps. A byte needs neither
            // byte-order handling nor unpack's temporary buffer, result tuple, and copied stream view.
            // Iterator dereferences have HILTI type uint<64>. The constructors narrow to eight bits,
            // preserving the signed bit pattern; a cast to int<8> would range-check it instead.
            const auto* ctor = read->signedness == ir::Signedness::Signed ? "int8" : "uint8";
            auto* value = tb.namedCtor(ctor, {tb.deref(tb.begin(tb.id(::hilti::ID("cursor"))))}, meta);
            tb.addAssign(tb.id(::hilti::ID(value_name)), value, meta);
            tb.addAssign(tb.id(::hilti::ID("cursor")),
                         tb.memberCall(tb.id(::hilti::ID("cursor")), "advance", {tb.integer(1U)}, meta),
                         meta);
        }
        else if ( integer ) {
            auto* unpacked =
                tb.deref(tb.unpack(value_type,
                                   {tb.id(::hilti::ID("cursor")), tb.id(::hilti::ID("hilti::ByteOrder::Network"))},
                                   meta));
            tb.addAssign(tb.tuple({tb.id(::hilti::ID(value_name)), tb.id(::hilti::ID("cursor"))}), unpacked, meta);
        }
        else {
            tb.addAssign(tb.id(::hilti::ID(value_name)),
                         tb.call(::hilti::ID("spicy_rt::extractBytes"),
                                 {tb.id(::hilti::ID("data")),
                                  tb.id(::hilti::ID("cursor")),
                                  _value(tb, inst.args[1]),
                                  tb.bool_(false),
                                  tb.stringLiteral(""),
                                  tb.id(::hilti::ID("filters_"))},
                                 meta),
                         meta);
            tb.addAssign(tb.id(::hilti::ID("cursor")),
                         tb.memberCall(tb.id(::hilti::ID("cursor")), "advance", {_value(tb, inst.args[1])}, meta),
                         meta);
        }
        _gapCatch(b, try_body, meta);
        _tuples[id.index] = {"cursor", value_name};
    }

    // The runtime's literal check waits for input and formats mismatches exactly as legacy. Its parse error becomes
    // this parser's failure; a C++ exception costs nothing on success.
    void _lowerExpectBytes(LocalBuilder& b, ir::InstId id) {
        const auto& inst = package_.inst(id);
        auto meta = metaFor(package_, inst.span);
        const auto& literal = std::get<ir::BytesLiteral>(inst.payload).value;
        auto value_name = fmt("v_%u", id.index);
        _local(b,
               value_name,
               b.qualifiedType(b.typeBytes(), ::hilti::Constness::Mutable),
               b.bytes(literal, meta),
               meta);

        auto* try_body = _b.statementBlock(meta);
        LocalBuilder tb(_b.context(), try_body);
        tb.addExpression(tb.call(::hilti::ID("spicy_rt::expectBytesLiteral"),
                                 {tb.id(::hilti::ID("data")),
                                  tb.id(::hilti::ID("cursor")),
                                  tb.id(::hilti::ID(value_name)),
                                  tb.stringLiteral(""),
                                  tb.id(::hilti::ID("filters_"))},
                                 meta));
        tb.addAssign(tb.id(::hilti::ID("cursor")),
                     tb.memberCall(tb.id(::hilti::ID("cursor")),
                                   "advance",
                                   {tb.integer(uint64_t{literal.size()})},
                                   meta),
                     meta);

        auto* mismatch_body = _b.statementBlock(meta);
        LocalBuilder mb(_b.context(), mismatch_body);
        _return(mb,
                "ParseError",
                nullptr,
                meta,
                mb.memberCall(mb.id(::hilti::ID("e")), "description", ::hilti::Expressions{}, meta));
        auto* parameter = _b.parameter(::hilti::ID("e"),
                                       _b.typeName(::hilti::ID("spicy_rt::ParseError")),
                                       ::hilti::parameter::Kind::In);
        _gapCatch(b, try_body, meta, {_b.statementTryCatch(parameter, mismatch_body, meta)});
        _tuples[id.index] = {"cursor", value_name};
    }

    void _lowerInst(LocalBuilder& b, ir::InstId id) {
        const auto& inst = package_.inst(id);
        auto meta = metaFor(package_, inst.span);
        switch ( inst.opcode ) {
            case ir::Opcode::Argument: values_[id.index] = _storage(id).name; return;
            case ir::Opcode::RegionArgument:
                if ( ! values_.contains(id.index) )
                    values_[id.index] = "cursor";
                return;
            case ir::Opcode::TupleGet: {
                auto index = std::get<ir::TupleGetPayload>(inst.payload).index;
                if ( auto tuple = _tuples.find(inst.args[0].index); tuple != _tuples.end() )
                    values_[id.index] = tuple->second.at(index);
                else
                    _lowerProcedural(b, id);
                return;
            }
            case ir::Opcode::UnitCreate: {
                auto name = fmt("v_%u", id.index);
                auto unit = std::get<ir::UnitPayload>(inst.payload).unit;
                if ( names_.at(_id.index).root ) {
                    _local(b,
                           name,
                           unitReferenceType(b, unit),
                           b.new_(b.typeName(::hilti::ID(unitName(unit))), meta),
                           meta);
                    held_by_reference_.insert(id.index);
                }
                else
                    _local(b,
                           name,
                           b.qualifiedType(b.typeName(::hilti::ID(unitName(unit))), ::hilti::Constness::Mutable),
                           nullptr,
                           meta);
                values_[id.index] = std::move(name);
                return;
            }
            case ir::Opcode::PublishField: {
                auto field = std::get<ir::FieldPayload>(inst.payload).field;
                // Publishing consumes an affine value, so the field takes over its storage.
                auto* published = _value(b, inst.args[1]);
                if ( ir::typeDiscipline(package_, package_.inst(inst.args[1]).result_type) ==
                     ir::ValueDiscipline::Affine )
                    published = b.move(published, meta);
                b.addAssign(b.member(_value(b, inst.args[0]), fieldName(field)), published, meta);
                values_[id.index] = values_.at(inst.args[0].index);
                if ( held_by_reference_.contains(inst.args[0].index) )
                    held_by_reference_.insert(id.index);
                return;
            }
            case ir::Opcode::ReadInteger: _lowerRead(b, id, true); return;
            case ir::Opcode::ReadBytes: _lowerRead(b, id, false); return;
            case ir::Opcode::ExpectBytes: _lowerExpectBytes(b, id); return;
            case ir::Opcode::Fail: _return(b, "ParseError", nullptr, meta, _value(b, inst.args[1])); return;
            case ir::Opcode::EnterBound: {
                auto* length = _value(b, inst.args[1]);
                auto overflow = b.addIf(b.greater(length,
                                                  b.difference(b.integer(std::numeric_limits<uint64_t>::max()),
                                                               b.memberCall(b.id(::hilti::ID("cursor")),
                                                                            "offset",
                                                                            ::hilti::Expressions{},
                                                                            meta))),
                                        meta);
                _return(*overflow,
                        "ParseError",
                        nullptr,
                        meta,
                        _format(*overflow,
                                "&size value %u exceeds the remaining stream offset range",
                                {_value(*overflow, inst.args[1])}));
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
                auto offset = [&](LocalBuilder& lb, const char* view) {
                    return lb.memberCall(lb.id(::hilti::ID(view)), "offset", ::hilti::Expressions{}, meta);
                };
                _return(*incomplete,
                        "ParseError",
                        nullptr,
                        meta,
                        _format(*incomplete,
                                "&size amount not consumed: expected %u bytes, but got %u bytes",
                                {incomplete->difference(incomplete->deref(incomplete->id(::hilti::ID("bound_end"))),
                                                        offset(*incomplete, "outer_cursor")),
                                 incomplete->difference(offset(*incomplete, "cursor"),
                                                        offset(*incomplete, "outer_cursor"))}));
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
            case ir::Opcode::ReleaseInput: {
                // The stream drops its chunks before the cursor. Views and extracted values keep their own storage.
                b.addExpression(
                    b.memberCall(b.id(::hilti::ID("data")), "trim", {b.begin(b.id(::hilti::ID("cursor")))}, meta));
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
                                             meta,
                                             _member(*failed, name, "failure")),
                                  meta);
                b.addAssign(b.id(::hilti::ID("cursor")), b.move(_member(b, name, "cursor")), meta);
                auto unit_value = fmt("v_%u_unit", id.index);
                _local(b,
                       unit_value,
                       targetType(b, package_, package_.type(inst.result_type).type_arguments[1]),
                       b.move(b.deref(_member(b, name, "unit")), meta),
                       meta);
                _tuples[id.index] = {"cursor", unit_value};
                return;
            }
            case ir::Opcode::RepeatToBound: {
                std::vector<std::string> carried{"cursor"};
                for ( size_t i = 1; i < inst.args.size(); ++i ) {
                    auto name = fmt("carry_%u_%zu", id.index, i);
                    _local(b,
                           name,
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
                _return(*no_progress,
                        "ParseError",
                        nullptr,
                        meta,
                        no_progress->stringLiteral("loop body did not change input position, possible infinite loop"));
                _tuples[id.index] = std::move(carried);
                return;
            }
            // Finishing consumes the unit, including a root's value reference: copying that reference would
            // deep-copy the completed unit rather than transfer it to the result.
            case ir::Opcode::Finish: _return(b, "Success", b.move(_value(b, inst.args[1]), meta), meta); return;
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
    ProcedureEmitter(::hilti::Builder& b,
                     const ir::Package& package,
                     const NameMap& names,
                     ir::FunctionId id,
                     std::optional<::hilti::declaration::Linkage> linkage = std::nullopt)
        : ProceduralOps(package, names), _b(b), _id(id), _linkage(linkage) {}

    ::hilti::Declaration* emit() {
        const auto& fn = package_.function(_id);
        const auto& names = names_.at(_id.index);
        auto meta = metaFor(package_, fn.span);
        ::hilti::declaration::Parameters params;
        for ( size_t i = 0; i < fn.parameters.size(); ++i ) {
            auto name = fmt("arg_%zu", i);
            params.push_back(parameterFor(_b, package_, name, fn.parameters[i], meta));
            arguments_.emplace(i, Storage{.name = std::move(name)});
        }

        auto* body = _b.statementBlock(meta);
        LocalBuilder fb(_b.context(), body);
        _emitBody(fb, fn.root_region, [this](LocalBuilder& b, ir::InstId id) {
            if ( ! _lowerProcedural(b, id) )
                ::hilti::util::cannotBeReached();
        });

        return _b.function(::hilti::ID(names.function),
                           resultType(_b, package_, fn.result_type),
                           params,
                           body,
                           ::hilti::type::function::Flavor::Function,
                           _linkage   ? *_linkage :
                           names.root ? ::hilti::declaration::Linkage::Public :
                                        ::hilti::declaration::Linkage::Private,
                           names.root ? ::hilti::type::function::CallingConvention::Extern :
                                        ::hilti::type::function::CallingConvention::Standard,
                           {},
                           meta);
    }

private:
    ::hilti::Builder& _b;
    ir::FunctionId _id;
    std::optional<::hilti::declaration::Linkage> _linkage;
};

} // namespace

// The runtime entry of one parser root: a `parse1` adapter with the runtime's endpoint signature, the
// `spicy_rt::Parser` record that describes the parser, and the initialization that registers that record. The record
// must outlive the runtime's use of it, so it is a module-level variable rather than a local of the registration.
void lowerParserEntry(::hilti::Builder& builder,
                      const ir::Package& package,
                      const NameMap& names,
                      const ir::ParserRoot& root,
                      size_t index,
                      ::hilti::Declarations& decls) {
    auto meta = metaFor(package, package.function(root.function).span);
    const auto& names_root = names.at(root.function.index);
    const auto& entry = names.parser_entries.at(index);
    const auto& parse1 = entry.parse1;
    const auto& parser = entry.parser;
    auto* view_type = builder.qualifiedType(builder.typeStreamView(), ::hilti::Constness::Mutable);
    auto* context_type = builder.qualifiedType(builder.typeName("spicy_rt::UnitContext"), ::hilti::Constness::Mutable);

    // The adapter takes the runtime's endpoint arguments, runs the root parser over them, and returns where the parser
    // finished. Resumption needs no adapter state: the root's own input waits suspend the call, and the runtime resumes
    // it with the same input.
    const auto& root_function = package.function(root.function);
    const bool has_context = root_function.parameters.size() == 2;
    ::hilti::QualifiedType* context_value = nullptr;
    if ( has_context )
        context_value =
            builder.qualifiedType(builder.typeName(::hilti::ID(
                                      names.context_types[names.root_context_type.at(root.function.index)])),
                                  ::hilti::Constness::Mutable);

    for ( bool parsed_unit : {false, true} ) {
        ::hilti::declaration::Parameters params = {
            builder.parameter(::hilti::ID("data"),
                              builder.typeValueReference(
                                  builder.qualifiedType(builder.typeStream(), ::hilti::Constness::Mutable)),
                              ::hilti::parameter::Kind::InOut,
                              meta),
            builder.parameter(::hilti::ID("initial_cursor"),
                              builder.typeOptional(view_type),
                              ::hilti::parameter::Kind::In,
                              meta),
            builder.parameter(::hilti::ID("unit_context"),
                              builder.typeOptional(context_type),
                              ::hilti::parameter::Kind::In,
                              meta),
        };
        if ( parsed_unit )
            params.insert(params.begin(),
                          builder.parameter(::hilti::ID("parsed_unit"),
                                            builder.typeValueReference(
                                                builder.qualifiedType(builder.typeName("spicy_rt::ParsedUnit"),
                                                                      ::hilti::Constness::Mutable)),
                                            ::hilti::parameter::Kind::InOut,
                                            meta));
        auto* body = builder.statementBlock(meta);
        LocalBuilder fb(builder.context(), body);
        // A parser with a context shares one instance with the other parsers of the connection: the runtime hands over
        // the instance that the connection's first parser created, and a parser run without one makes its own.
        ::hilti::Expressions arguments = {fb.id(::hilti::ID("data")), fb.id(::hilti::ID("initial_cursor"))};
        if ( has_context ) {
            fb.addLocal(::hilti::ID("context_ref"), fb.strongReference(context_value), meta);
            auto* unit_context_id = fb.id(::hilti::ID("unit_context"));
            auto* created = fb.call("spicy_rt::createContext", {fb.new_(context_value->type(), meta)}, meta);
            fb.addExpression(fb.call("spicy_rt::setContext",
                                     {fb.id(::hilti::ID("context_ref")),
                                      fb.ternary(unit_context_id, fb.deref(unit_context_id), created),
                                      fb.typeinfo(context_value)},
                                     meta));
            arguments.push_back(fb.deref(fb.id(::hilti::ID("context_ref"))));
        }
        else
            fb.addExpression(fb.call("spicy_rt::rejectUnitContext", {fb.id(::hilti::ID("unit_context"))}, meta));
        fb.addLocal(::hilti::ID("result"), fb.call(moduleLevel(names_root.function), arguments, meta), meta);
        auto* success =
            fb.equal(fb.member(fb.id(::hilti::ID("result")), "kind"), fb.id(::hilti::ID("OutcomeKind::Success")), meta);
        auto returned = fb.addIf(success, meta);
        if ( parsed_unit )
            returned->addExpression(
                returned->call("spicy_rt::initializeParsedUnit",
                               {returned->id(::hilti::ID("parsed_unit")),
                                returned->deref(returned->member(returned->id(::hilti::ID("result")), "unit"))},
                               meta));
        returned->addReturn(returned->member(returned->id(::hilti::ID("result")), "cursor"), meta);
        // Input that holds a gap is reported as the runtime reports missing data, and every other ending is a parse
        // error.
        auto gap = fb.addIf(fb.equal(fb.member(fb.id(::hilti::ID("result")), "kind"),
                                     fb.id(::hilti::ID("OutcomeKind::Gap")),
                                     meta),
                            meta);
        gap->addThrow(gap->exception(gap->typeName("hilti::MissingData"),
                                     failurePart(*gap, gap->id(::hilti::ID("result")), 0),
                                     failurePart(*gap, gap->id(::hilti::ID("result")), 1),
                                     meta),
                      meta);
        fb.addThrow(fb.exception(fb.typeName("spicy_rt::ParseError"),
                                 failurePart(fb, fb.id(::hilti::ID("result")), 0),
                                 failurePart(fb, fb.id(::hilti::ID("result")), 1),
                                 meta),
                    meta);
        decls.push_back(builder.function(::hilti::ID(parsed_unit ? entry.parse3 : parse1),
                                         view_type,
                                         params,
                                         body,
                                         ::hilti::type::function::Flavor::Function,
                                         ::hilti::declaration::Linkage::Public,
                                         ::hilti::type::function::CallingConvention::Extern,
                                         {},
                                         meta));
    }

    if ( has_context ) {
        auto* context_body = builder.statementBlock(meta);
        LocalBuilder cb(builder.context(), context_body);
        cb.addReturn(cb.call("spicy_rt::createContext", {cb.new_(context_value->type(), meta)}, meta), meta);
        decls.push_back(builder.function(::hilti::ID(entry.context_new),
                                         builder.qualifiedType(builder.typeName("spicy_rt::UnitContext"),
                                                               ::hilti::Constness::Mutable),
                                         {},
                                         context_body,
                                         ::hilti::type::function::Flavor::Function,
                                         ::hilti::declaration::Linkage::Public,
                                         ::hilti::type::function::CallingConvention::ExternNoSuspend,
                                         {},
                                         meta));
    }

    // The record is what the runtime reads: the parser's exported name, its adapter, and its unit's type information.
    auto* none = builder.null(meta);
    auto* mime = builder.vector(builder.qualifiedType(builder.typeVector(
                                                          builder.qualifiedType(builder.typeName("spicy_rt::MIMEType"),
                                                                                ::hilti::Constness::Const)),
                                                      ::hilti::Constness::Const),
                                {},
                                meta);
    auto* ports =
        builder.vector(builder.qualifiedType(builder.typeVector(
                                                 builder.qualifiedType(builder.typeName("spicy_rt::ParserPort"),
                                                                       ::hilti::Constness::Const)),
                                             ::hilti::Constness::Const),
                       {},
                       meta);
    auto* record =
        builder.struct_({builder.ctorStructField(::hilti::ID("name"), builder.stringLiteral(root.name, meta)),
                         builder.ctorStructField(::hilti::ID("is_public"), builder.bool_(true, meta)),
                         builder.ctorStructField(::hilti::ID("parse1"), builder.id(::hilti::ID(parse1))),
                         builder.ctorStructField(::hilti::ID("parse2"), none),
                         builder.ctorStructField(::hilti::ID("parse3"), builder.id(::hilti::ID(entry.parse3))),
                         builder.ctorStructField(::hilti::ID("context_new"),
                                                 has_context ? static_cast<::hilti::Expression*>(
                                                                   builder.id(::hilti::ID(entry.context_new))) :
                                                               none),
                         builder.ctorStructField(::hilti::ID("type_"), builder.id(::hilti::ID(unitName(root.unit)))),
                         builder.ctorStructField(::hilti::ID("description"), builder.stringMutable("", meta)),
                         builder.ctorStructField(::hilti::ID("mime_types"), mime),
                         builder.ctorStructField(::hilti::ID("ports"), ports)},
                        meta);
    // The runtime keeps a pointer to the record, so the record is a field of a module-level variable, whose storage
    // stays in place for the program's lifetime. The record is assigned in the registration, which runs at
    // initialization.
    decls.push_back(
        builder.global(::hilti::ID(parser),
                       builder.qualifiedType(builder.typeName("spicy_rt::Parser"), ::hilti::Constness::Mutable),
                       ::hilti::declaration::Linkage::Private,
                       meta));

    // Registration runs at initialization, after the record's module-level variable is initialized.
    auto* register_body = builder.statementBlock(meta);
    LocalBuilder rb(builder.context(), register_body);
    rb.addAssign(rb.id(::hilti::ID(parser)), record);
    rb.addExpression(rb.call("spicy_rt::registerParser",
                             {rb.id(::hilti::ID(parser)),
                              rb.scope(meta),
                              rb.strongReference(rb.qualifiedType(rb.typeName(::hilti::ID(unitName(root.unit))),
                                                                  ::hilti::Constness::Const),
                                                 meta)},
                             meta));
    decls.push_back(builder.function(::hilti::ID(entry.registration),
                                     builder.qualifiedType(builder.typeVoid(), ::hilti::Constness::Const),
                                     {},
                                     register_body,
                                     ::hilti::type::function::Flavor::Function,
                                     ::hilti::declaration::Linkage::Init,
                                     ::hilti::type::function::CallingConvention::Standard,
                                     {},
                                     meta));
}

LoweringResult lower(::hilti::Builder& builder,
                     const ir::Package& package,
                     const std::vector<TargetBinding>& bindings) {
    auto unsupported = checkCoverage(package, bindings);
    if ( ! unsupported.empty() )
        return Unsupported{std::move(unsupported)};

    auto names = makeNames(package, bindings);
    auto presence = analyses::fieldPresence(package);
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
    // A context's type is declared under its source name, with its element names, so that its type information is the
    // one the runtime compares. PIR computes with the structural tuple.
    for ( size_t i = 0; i < names.context_types.size(); ++i ) {
        const auto& root = package.parserRoots()[names.context_type_roots[i]];
        auto tuple_type = package.type(package.function(root.function).parameters[1].type).type_arguments[0];
        ::hilti::type::tuple::Elements elements;
        for ( size_t j = 0; j < root.context->elements.size(); ++j )
            elements.push_back(
                builder.typeTupleElement(::hilti::ID(root.context->elements[j]),
                                         targetType(builder, package, package.type(tuple_type).type_arguments[j])));
        decls.push_back(
            builder.declarationType(::hilti::ID(names.context_types[i]),
                                    builder.qualifiedType(builder.typeTuple(elements), ::hilti::Constness::Const),
                                    ::hilti::declaration::Linkage::Public));
    }
    for ( size_t i = 0; i < package.typeDecls().size(); ++i )
        decls.push_back(lowerUnitType(builder, package, presence, ir::TypeDeclId{static_cast<uint32_t>(i)}));
    for ( size_t i = 0; i < package.functions().size(); ++i ) {
        auto id = ir::FunctionId{static_cast<uint32_t>(i)};
        if ( package.function(id).kind == ir::FunctionKind::Parser )
            decls.push_back(lowerResultType(builder, package, id, names.at(id.index)));
    }
    // The location that a caught gap's exception carries, which the runtime's HILTI declaration only offers for other
    // exception types.
    {
        auto* attrs = builder.attributeSet(
            {builder.attribute(::hilti::attribute::kind::Cxxname, builder.stringLiteral("hilti::rt::exception::where")),
             builder.attribute(::hilti::attribute::kind::HavePrototype)});
        decls.push_back(builder.function(::hilti::ID("exception_where"),
                                         builder.qualifiedType(builder.typeString(), ::hilti::Constness::Mutable),
                                         {builder.parameter(::hilti::ID("e"),
                                                            builder.typeName(::hilti::ID("hilti::MissingData")),
                                                            ::hilti::parameter::Kind::In)},
                                         ::hilti::type::function::Flavor::Function,
                                         ::hilti::declaration::Linkage::Private,
                                         ::hilti::type::function::CallingConvention::Extern,
                                         attrs));
    }
    for ( size_t i = 0; i < package.foreignFunctions().size(); ++i )
        if ( ! names.bound.contains(static_cast<uint32_t>(i)) )
            decls.push_back(lowerForeignFunction(builder, package, ir::ForeignFunctionId{static_cast<uint32_t>(i)}));
    for ( size_t i = 0; i < package.functions().size(); ++i ) {
        auto id = ir::FunctionId{static_cast<uint32_t>(i)};
        if ( package.function(id).kind == ir::FunctionKind::Parser )
            decls.push_back(FunctionEmitter(builder, package, names, id).emit());
        else
            decls.push_back(ProcedureEmitter(builder, package, names, id, initializerLinkage(package, id)).emit());
    }
    for ( size_t i = 0; i < package.globals().size(); ++i ) {
        const auto id = ir::GlobalId{static_cast<uint32_t>(i)};
        const auto& global = package.global(id);
        auto meta = metaFor(package, global.span);
        auto* init = builder.call(moduleLevel(names.at(global.initializer.index).function), {}, meta);
        decls.push_back(builder.global(::hilti::ID(names.globals.at(id.index)),
                                       targetType(builder, package, global.type),
                                       init,
                                       ::hilti::declaration::Linkage::Private,
                                       meta));
    }
    for ( size_t i = 0; i < package.parserRoots().size(); ++i )
        lowerParserEntry(builder, package, names, package.parserRoots()[i], i, decls);

    auto uid = ::hilti::declaration::module::UID(::hilti::ID(ModuleName), ".hlt", ".hlt");
    return builder.declarationModule(uid, {}, decls);
}

} // namespace spicy::detail::pir::backend::hilti
