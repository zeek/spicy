// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/attribute.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/ctors/bytes.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/ctors/string.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/assign.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/function.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/ast/statements/expression.h>
#include <hilti/ast/statements/if.h>
#include <hilti/ast/statements/return.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/library.h>
#include <hilti/ast/types/name.h>
#include <hilti/ast/types/string.h>
#include <hilti/ast/types/vector.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/util.h>

#include <spicy/ast/declarations/hook.h>
#include <spicy/ast/declarations/unit-hook.h>
#include <spicy/ast/statements/print.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/lowerer.h>

using hilti::util::fmt;

namespace spicy::detail::pir {

namespace {

UnsupportedFeature unsupported(const std::string& feature, std::string reason, const hilti::Location& loc) {
    return UnsupportedFeature{.feature = feature, .reason = std::move(reason), .location = loc};
}

// Collects candidate roots for lowering PIR, as well as marking known
// unsupported constructs.
struct VisitorRoots : public visitor::PreOrder {
    std::vector<hilti::Declaration*> roots;
    std::vector<hilti::declaration::Type*> unit_declarations;
    std::vector<hilti::ast::TypeIndex> units_with_external_hooks;
    std::optional<UnsupportedFeature> unrepresented_content;
    std::vector<std::string> cxx_includes;
    std::vector<hilti::declaration::GlobalVariable*> globals;
    std::vector<std::pair<hilti::declaration::Function*, ir::InitPhase>> initializers;

    static bool skipsImplementation(hilti::Declaration* n) {
        auto* m = n->parent<hilti::declaration::Module>();
        return m && m->skipImplementation();
    }

    void operator()(hilti::declaration::Function* n) final {
        if ( skipsImplementation(n) )
            return;

        switch ( n->linkage() ) {
            case hilti::declaration::Linkage::PreInit: initializers.emplace_back(n, ir::InitPhase::PreInit); return;
            case hilti::declaration::Linkage::Init: initializers.emplace_back(n, ir::InitPhase::Init); return;
            default: break;
        }

        if ( n->isPublic() )
            roots.push_back(n);
    }

    void operator()(hilti::declaration::Module* n) final {
        for ( auto* property : n->moduleProperties("%cxx-include") ) {
            auto* expr = property->expression();
            auto* ctor = expr ? expr->tryAs<hilti::expression::Ctor>() : nullptr;
            auto* str = ctor ? ctor->ctor()->tryAs<hilti::ctor::String>() : nullptr;
            if ( ! str ) {
                if ( ! unrepresented_content )
                    unrepresented_content = unsupported(fmt("module '%s'", std::string(n->id())),
                                                        "%cxx-include must be a constant string",
                                                        property->meta().location());
                continue;
            }

            cxx_includes.emplace_back(str->value());
        }

        // The PIR backend has no module initialization, so top-level statements must select the legacy output.
        if ( ! n->skipImplementation() && ! n->statements()->statements().empty() && ! unrepresented_content )
            unrepresented_content = unsupported(fmt("module '%s'", std::string(n->id())),
                                                "module initialization is not supported yet",
                                                n->meta().location());
    }

    void operator()(hilti::declaration::Type* n) final {
        auto* unit = n->type()->type()->tryAs<type::Unit>();
        if ( ! unit ) {
            if ( n->isPublic() && ! skipsImplementation(n) && ! unrepresented_content )
                unrepresented_content = unsupported(fmt("public type '%s'", std::string(n->id())),
                                                    "only parser unit types are supported yet",
                                                    n->meta().location());
            return;
        }

        // Aliases may have different linkage than what they alias.
        bool is_public = n->type()->alias() ? n->isPublic() : unit->isPublic();

        if ( ! n->type()->alias() && ! skipsImplementation(n) )
            unit_declarations.push_back(n);

        if ( is_public && ! skipsImplementation(n) )
            roots.push_back(n);
    }

    // External hooks from the unit itself
    void operator()(spicy::declaration::UnitHook* n) final {
        if ( auto index = n->hook()->unitTypeIndex() )
            units_with_external_hooks.push_back(index);
    }

    void operator()(hilti::declaration::GlobalVariable* n) final {
        if ( ! skipsImplementation(n) )
            globals.push_back(n);
    }

    void operator()(hilti::declaration::Constant* n) final {
        if ( n->isPublic() && ! skipsImplementation(n) && ! unrepresented_content )
            unrepresented_content = unsupported(fmt("public constant '%s'", std::string(n->id())),
                                                "constants are not supported yet",
                                                n->meta().location());
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

class ProcedureLowerer;

// A Spicy variable seen by procedural code. A place-backed variable reads and writes through `value`;
// otherwise `value` is the immutable SSA value of a by-value parameter.
struct Variable {
    ir::InstId value;
    bool is_place = false;
};

// Lowers the statements and expressions of one ordinary function body. Statements are appended to `_block`, which
// changes when control flow splits; `_open` is false once control can no longer reach the end of the body.
class BodyLowerer {
public:
    BodyLowerer(ProcedureLowerer& procedures,
                ir::Package& package,
                ir::RegionId region,
                ir::BlockId block,
                std::string feature)
        : _procedures(procedures),
          _package(package),
          _builder(package.builder()),
          _region(region),
          _block(block),
          _feature(std::move(feature)) {}

    void bind(const hilti::Declaration* decl, Variable variable) { _variables.emplace(decl, variable); }

    // Makes `self` the unit being parsed, whose fields are the given published declarations by name.
    void setSelf(ir::InstId unit, std::unordered_map<std::string, ir::DeclId> fields) {
        _self = unit;
        _fields = std::move(fields);
    }

    std::optional<UnsupportedFeature> lowerStatement(hilti::Statement* stmt);

    // Lowers statements in order. Once control has left the current path, any further statement is unreachable.
    template<typename Statements>
    std::optional<UnsupportedFeature> lowerStatements(const Statements& statements) {
        for ( auto* stmt : statements ) {
            if ( ! _open )
                return _unsupported("statements after a return are not supported", stmt->meta().location());
            if ( auto error = lowerStatement(stmt) )
                return error;
        }

        return std::nullopt;
    }

    // Whether control can still reach the end of the body.
    bool open() const { return _open; }

    // Ends the body with `core.return` when it falls off the end, which only a function without a result may do.
    void returnVoidIfOpen(ir::SourceSpanId span) {
        if ( ! _open )
            return;

        _builder.addReturnVoid(_block, span);
        _open = false;
    }

    std::variant<ir::InstId, UnsupportedFeature> lower(hilti::Expression* expr) {
        if ( auto* ctor_expr = expr->tryAs<hilti::expression::Ctor>() )
            return _lowerCtor(ctor_expr->ctor(), expr->meta().location());

        if ( auto* name = expr->tryAs<hilti::expression::Name>() )
            return _read(name);

        if ( auto* op = expr->tryAs<hilti::expression::ResolvedOperator>() ) {
            if ( op->kind() == hilti::operator_::Kind::Call )
                return _lowerCall(op);
            if ( op->kind() == hilti::operator_::Kind::Equal )
                return _lowerEqual(op);
            if ( op->kind() == hilti::operator_::Kind::Member ) {
                auto place = _fieldPlace(op);
                if ( auto* feature = std::get_if<UnsupportedFeature>(&place) )
                    return *feature;
                return _load(std::get<ir::InstId>(place), op->meta().location());
            }
            return _lowerSum(op);
        }

        return _unsupported("unsupported expression", expr->meta().location());
    }

    std::variant<ir::InstId, UnsupportedFeature> _lowerCtor(hilti::Ctor* ctor, const hilti::Location& loc);

private:
    // `==` on two values of the same integer or bool type, which the PIR verifier restricts to the same types.
    std::variant<ir::InstId, UnsupportedFeature> _lowerEqual(hilti::expression::ResolvedOperator* op) {
        auto lhs = lower(op->op0());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&lhs) )
            return *feature;

        auto rhs = lower(op->op1());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&rhs) )
            return *feature;

        auto type = _package.inst(std::get<ir::InstId>(lhs)).result_type;
        if ( type != _package.inst(std::get<ir::InstId>(rhs)).result_type )
            return _unsupported("only operands of the same type can be compared", op->meta().location());

        if ( ! _package.isValid(type) )
            return _unsupported("only integers and bools can be compared", op->meta().location());
        switch ( _package.type(type).kind ) {
            case ir::TypeKind::Int64:
            case ir::TypeKind::UInt8:
            case ir::TypeKind::UInt64:
            case ir::TypeKind::Bool: break;
            default: return _unsupported("only integers and bools can be compared", op->meta().location());
        }

        return _builder.addEqual(_block,
                                 std::get<ir::InstId>(lhs),
                                 std::get<ir::InstId>(rhs),
                                 internSpan(_package, op->meta().location()));
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

        return _builder.addAdd(_block,
                               std::get<ir::InstId>(lhs),
                               std::get<ir::InstId>(rhs),
                               internSpan(_package, op->meta().location()));
    }

    std::variant<ir::InstId, UnsupportedFeature> _read(hilti::expression::Name* name) {
        auto variable = _lookup(name);
        if ( auto* feature = std::get_if<UnsupportedFeature>(&variable) )
            return *feature;

        const auto& var = std::get<Variable>(variable);
        if ( ! var.is_place )
            return var.value;
        return _load(var.value, name->meta().location());
    }

    // Reading a place copies its value, which a native type that declares no copy behavior cannot do.
    std::variant<ir::InstId, UnsupportedFeature> _load(ir::InstId place, const hilti::Location& loc) {
        auto type = _package.inst(place).result_type;
        if ( _package.isValid(type) && _package.type(type).kind == ir::TypeKind::Place )
            type = _package.type(type).type_arguments[0];
        if ( _isNonCopyableOpaque(type) )
            return _unsupported("reading a mutable foreign value by copy", loc);
        return _builder.addLoad(_block, place, internSpan(_package, loc));
    }

    bool _isNonCopyableOpaque(ir::TypeId type) const {
        if ( ! _package.isValid(type) || _package.type(type).kind != ir::TypeKind::Opaque )
            return false;

        const auto& decl = _package.typeDecl(_package.type(type).declaration);
        return ! decl.opaque || ! decl.opaque->lifecycle || ! decl.opaque->lifecycle->copyable;
    }

    // `self.<field>`, addressed through the unit being parsed.
    std::variant<ir::InstId, UnsupportedFeature> _fieldPlace(hilti::expression::ResolvedOperator* op) {
        auto* self = op->op0() ? op->op0()->tryAs<hilti::expression::Name>() : nullptr;
        auto* member = op->op1() ? op->op1()->tryAs<hilti::expression::Member>() : nullptr;
        if ( ! _self || ! self || self->id() != hilti::ID("self") || ! member )
            return _unsupported("only published fields of self can be accessed here", op->meta().location());

        auto field = _fields.find(std::string(member->id()));
        if ( field == _fields.end() )
            return _unsupported(fmt("field '%s' is not published yet", std::string(member->id())),
                                op->meta().location());
        return _builder.addFieldPlace(_block, *_self, field->second, internSpan(_package, op->meta().location()));
    }

    // The place an assignment or `inout` argument writes through; only variables and fields have one.
    std::variant<ir::InstId, UnsupportedFeature> _place(hilti::Expression* expr) {
        if ( auto* op = expr->tryAs<hilti::expression::ResolvedOperator>();
             op && op->kind() == hilti::operator_::Kind::Member )
            return _fieldPlace(op);

        auto* name = expr->tryAs<hilti::expression::Name>();
        if ( ! name )
            return _unsupported("only variables can be assigned or passed as inout arguments", expr->meta().location());

        auto variable = _lookup(name);
        if ( auto* feature = std::get_if<UnsupportedFeature>(&variable) )
            return *feature;

        const auto& var = std::get<Variable>(variable);
        if ( ! var.is_place )
            return _unsupported("only inout parameters and local variables can be written", expr->meta().location());
        return var.value;
    }

    std::variant<Variable, UnsupportedFeature> _lookup(hilti::expression::Name* name) {
        auto* declaration = name->resolvedDeclaration();
        if ( auto* global = declaration ? declaration->tryAs<hilti::declaration::GlobalVariable>() : nullptr )
            return _lookupGlobal(global, name->meta().location());

        auto it = _variables.find(name->resolvedDeclaration());
        if ( it == _variables.end() )
            return _unsupported(fmt("reference to '%s' is not supported", std::string(name->id())),
                                name->meta().location());
        return it->second;
    }

    // A module-level variable is addressed through a place created in the current block.
    std::variant<Variable, UnsupportedFeature> _lookupGlobal(hilti::declaration::GlobalVariable* global,
                                                             const hilti::Location& loc);

    std::variant<ir::InstId, UnsupportedFeature> _lowerCall(hilti::expression::ResolvedOperator* op);

    // Lowers the body of one arm of an `if`, starting at `start`. Yields the block the arm falls through from, or
    // nothing if the arm returns.
    std::variant<std::optional<ir::BlockId>, UnsupportedFeature> _lowerArm(hilti::Statement* body, ir::BlockId start) {
        _block = start;
        _open = true;
        if ( body ) {
            if ( auto error = lowerStatement(body) )
                return *error;
        }

        if ( ! _open )
            return std::optional<ir::BlockId>{};
        return std::optional<ir::BlockId>{_block};
    }

    std::optional<UnsupportedFeature> _lowerIf(hilti::statement::If* stmt);

    UnsupportedFeature _unsupported(std::string reason, const hilti::Location& loc) {
        return unsupported(_feature, std::move(reason), loc);
    }

    ProcedureLowerer& _procedures;
    ir::Package& _package;
    ir::Builder _builder;
    ir::RegionId _region;
    ir::BlockId _block;
    bool _open = true;
    std::string _feature;
    std::unordered_map<const hilti::Declaration*, Variable> _variables;
    std::optional<ir::InstId> _self;
    std::unordered_map<std::string, ir::DeclId> _fields;
};

// Lowers ordinary functions, and the foreign functions they call, once each. A function's identity
// is recorded before its body so that recursive calls resolve to it.
class ProcedureLowerer {
public:
    explicit ProcedureLowerer(ir::Package& package) : _package(package), _builder(package.builder()) {}

    // The PIR type of a Spicy type that procedural code can hold, if PIR can represent it yet.
    std::optional<ir::TypeId> valueType(const hilti::UnqualifiedType* type) {
        if ( const auto* integer = type->tryAs<hilti::type::SignedInteger>(); integer && integer->width() == 64 )
            return _builder.int64Type();
        if ( const auto* integer = type->tryAs<hilti::type::UnsignedInteger>() ) {
            if ( integer->width() == 8 )
                return _builder.uint8Type();
            if ( integer->width() == 64 )
                return _builder.uint64Type();
        }
        if ( type->isA<hilti::type::Bool>() )
            return _builder.boolType();
        if ( type->isA<hilti::type::String>() )
            return _builder.stringType();
        if ( type->isA<hilti::type::Bytes>() )
            return _builder.bytesType();
        if ( type->isA<hilti::type::Void>() )
            return _builder.voidType();
        if ( const auto* library = type->tryAs<hilti::type::Library>() )
            return _opaque(library);
        return std::nullopt;
    }

    std::variant<ir::FunctionId, UnsupportedFeature> function(hilti::declaration::Function* decl) {
        if ( auto it = _functions.find(decl); it != _functions.end() )
            return it->second;

        auto feature = fmt("function '%s'", std::string(decl->id()));
        auto* fn = decl->function();
        auto* ftype = fn->ftype();

        if ( fn->attributes()->find(hilti::attribute::kind::Cxxname) )
            return unsupported(feature, "only ordinary functions can be lowered", decl->meta().location());
        if ( ftype->flavor() != hilti::type::function::Flavor::Function )
            return unsupported(feature, "only ordinary functions are supported", decl->meta().location());
        if ( ftype->callingConvention() != hilti::type::function::CallingConvention::Standard )
            return unsupported(feature, "only the standard calling convention is supported", decl->meta().location());
        if ( ! fn->body() )
            return unsupported(feature, "functions without a body are not supported", decl->meta().location());

        auto parameters = _signature(ftype, feature, decl->meta().location());
        if ( auto* unsupported_feature = std::get_if<UnsupportedFeature>(&parameters) )
            return *unsupported_feature;
        auto signature = std::get<Signature>(parameters);

        auto span = internSpan(_package, decl->meta().location());
        auto id = _builder.createFunction(std::string(decl->id().local()), signature.types, signature.result, span);
        _functions.emplace(decl, id);

        auto region = _package.function(id).root_region;
        auto block = _builder.createBlock(region);
        BodyLowerer body(*this, _package, region, block, feature);
        for ( size_t i = 0; i < signature.declarations.size(); ++i ) {
            auto* param = signature.declarations[i];
            auto arg = _builder.addArgument(id, block, i, internSpan(_package, param->meta().location()));
            body.bind(param, Variable{.value = arg, .is_place = param->kind() == hilti::parameter::Kind::InOut});
        }

        if ( auto error = body.lowerStatements(fn->body()->statements()) )
            return *error;

        // A void function may fall off its end; a value-returning one must end in a return.
        if ( body.open() && signature.result != _builder.voidType() )
            return unsupported(feature, "a function returning a value must end with a return", decl->meta().location());
        body.returnVoidIfOpen(span);

        return id;
    }

    // Gives a module-level variable its identity. Identities follow declaration order, which is the order that module
    // initialization runs in, so they are allocated before any initializer or function body refers to a variable.
    std::variant<ir::GlobalId, UnsupportedFeature> declareGlobal(hilti::declaration::GlobalVariable* decl) {
        if ( auto it = _globals.find(decl); it != _globals.end() )
            return it->second;

        auto feature = fmt("global '%s'", std::string(decl->id()));
        auto type = valueType(decl->type()->type());
        if ( ! type || *type == _builder.voidType() )
            return unsupported(feature, "global type is not supported yet", decl->meta().location());
        if ( ! decl->init() )
            return unsupported(feature,
                               "globals without an initializer are not supported yet",
                               decl->meta().location());

        auto id = _builder.createGlobal(std::string(decl->id().local()),
                                        *type,
                                        internSpan(_package, decl->meta().location()));
        _globals.emplace(decl, id);
        return id;
    }

    // Lowers a module-level variable once, after its identity exists. Its initializer is an ordinary function that
    // module initialization calls.
    std::variant<ir::GlobalId, UnsupportedFeature> global(hilti::declaration::GlobalVariable* decl) {
        auto declared = declareGlobal(decl);
        if ( auto* feature = std::get_if<UnsupportedFeature>(&declared) )
            return *feature;

        auto id = std::get<ir::GlobalId>(declared);
        if ( ! _initialized_globals.insert(decl).second )
            return id;

        auto feature = fmt("global '%s'", std::string(decl->id()));
        auto span = internSpan(_package, decl->meta().location());
        auto type = _package.global(id).type;

        auto init = _builder.createFunction(fmt("%s_init", std::string(decl->id().local())),
                                            std::vector<ir::TypeId>{},
                                            type,
                                            span);
        auto region = _package.function(init).root_region;
        auto block = _builder.createBlock(region);
        BodyLowerer body(*this, _package, region, block, feature);
        auto value = body.lower(decl->init());
        if ( auto* unsupported_feature = std::get_if<UnsupportedFeature>(&value) )
            return *unsupported_feature;

        _builder.addReturn(block, std::get<ir::InstId>(value), span);
        _builder.setGlobalInitializer(id, init);
        return id;
    }

    std::variant<ir::ForeignFunctionId, UnsupportedFeature> foreign(hilti::declaration::Function* decl) {
        if ( auto it = _foreign.find(decl); it != _foreign.end() )
            return it->second;

        auto feature = fmt("function '%s'", std::string(decl->id()));
        auto* fn = decl->function();
        auto cxx_name = fn->attributes()->find(hilti::attribute::kind::Cxxname)->valueAsString();
        if ( ! cxx_name )
            return unsupported(feature, "a foreign function needs a constant &cxxname", decl->meta().location());

        std::vector<ir::ForeignParameter> parameters;
        for ( auto* param : fn->ftype()->parameters() ) {
            if ( param->default_() )
                return unsupported(feature, "default parameter values are not supported", decl->meta().location());

            auto* type = param->type()->type();
            if ( type->isA<hilti::type::Any>() ) {
                if ( param->kind() == hilti::parameter::Kind::InOut )
                    return unsupported(feature, "inout any parameters are not supported", param->meta().location());
                bool as_pointer = param->attributes()->find(hilti::attribute::kind::CxxAnyAsPtr) != nullptr;
                parameters.emplace_back(ir::TypeId(),
                                        as_pointer ? ir::ForeignArgument::AnyPointer : ir::ForeignArgument::TypeInfo);
                continue;
            }

            auto value_type = valueType(type);
            if ( ! value_type || *value_type == _builder.voidType() )
                return unsupported(feature, "parameter type is not supported yet", param->meta().location());

            parameters.emplace_back(param->kind() == hilti::parameter::Kind::InOut ? _builder.placeType(*value_type) :
                                                                                     *value_type);
        }

        auto result = valueType(fn->ftype()->result()->type());
        if ( ! result )
            return unsupported(feature, "result type is not supported yet", decl->meta().location());

        auto id = _builder.createForeignFunction(std::string(decl->id().local()),
                                                 *cxx_name,
                                                 std::move(parameters),
                                                 *result,
                                                 internSpan(_package, decl->meta().location()),
                                                 fn->attributes()->find(hilti::attribute::kind::HavePrototype));
        _foreign.emplace(decl, id);
        return id;
    }

    // The runtime's `hilti::print` (one value) or `hilti::printTuple` (several values) with a newline.
    ir::ForeignFunctionId printer(bool tuple) {
        auto& slot = tuple ? _print_tuple : _print;
        if ( ! slot.isSet() ) {
            std::vector<ir::ForeignParameter> parameters;
            parameters.emplace_back(ir::TypeId(),
                                    tuple ? ir::ForeignArgument::AnyTuple : ir::ForeignArgument::TypeInfo);
            parameters.emplace_back(_builder.boolType());
            slot = _builder.createForeignFunction(tuple ? "printTuple" : "print",
                                                  tuple ? "hilti::rt::tuple::print" : "hilti::rt::print",
                                                  std::move(parameters),
                                                  _builder.voidType(),
                                                  ir::SourceSpanId(),
                                                  true);
        }
        return slot;
    }

private:
    struct Signature {
        std::vector<ir::TypeId> types;
        ir::TypeId result;
        std::vector<hilti::declaration::Parameter*> declarations;
    };

    std::variant<Signature, UnsupportedFeature> _signature(hilti::type::Function* ftype,
                                                           const std::string& feature,
                                                           const hilti::Location& loc) {
        Signature signature;
        for ( auto* param : ftype->parameters() ) {
            if ( param->default_() )
                return unsupported(feature, "default parameter values are not supported", loc);

            auto value_type = valueType(param->type()->type());
            if ( ! value_type || *value_type == _builder.voidType() )
                return unsupported(feature, "parameter type is not supported yet", param->meta().location());

            switch ( param->kind() ) {
                case hilti::parameter::Kind::Copy:
                case hilti::parameter::Kind::In: signature.types.push_back(*value_type); break;
                case hilti::parameter::Kind::InOut: signature.types.push_back(_builder.placeType(*value_type)); break;
                case hilti::parameter::Kind::Unknown:
                    return unsupported(feature, "parameter kind is not known", param->meta().location());
            }
            signature.declarations.push_back(param);
        }

        auto result = valueType(ftype->result()->type());
        if ( ! result )
            return unsupported(feature, "result type is not supported yet", loc);
        signature.result = *result;
        return signature;
    }

    // Opaque types are nominal per native type: the same native name and constness is one declaration.
    ir::TypeId _opaque(const hilti::type::Library* library) {
        auto key = fmt("%s %s", library->isConstant() ? "const" : "mutable", library->cxxName());
        if ( auto it = _opaque_types.find(key); it != _opaque_types.end() )
            return it->second;

        // HILTI copies library values by value, so only a constant native type is assumed copyable.
        ir::OpaqueTypeInfo info;
        info.cxx_name = library->cxxName();
        info.constant = library->isConstant();
        info.lifecycle = ir::OpaqueLifecycle{.copyable = library->isConstant(), .movable = true};
        auto decl = _builder.createOpaqueTypeDecl(library->cxxName(), std::move(info));
        auto type = _builder.opaqueType(decl);
        _opaque_types.emplace(std::move(key), type);
        return type;
    }

    ir::Package& _package;
    ir::Builder _builder;
    std::unordered_map<const hilti::declaration::Function*, ir::FunctionId> _functions;
    std::unordered_map<const hilti::declaration::GlobalVariable*, ir::GlobalId> _globals;
    std::unordered_set<const hilti::declaration::GlobalVariable*> _initialized_globals;
    std::unordered_map<const hilti::declaration::Function*, ir::ForeignFunctionId> _foreign;
    std::unordered_map<std::string, ir::TypeId> _opaque_types;
    ir::ForeignFunctionId _print;
    ir::ForeignFunctionId _print_tuple;
};

std::variant<Variable, UnsupportedFeature> BodyLowerer::_lookupGlobal(hilti::declaration::GlobalVariable* global,
                                                                      const hilti::Location& loc) {
    auto id = _procedures.global(global);
    if ( auto* feature = std::get_if<UnsupportedFeature>(&id) )
        return *feature;

    auto place = _builder.addGlobalPlace(_block, std::get<ir::GlobalId>(id), internSpan(_package, loc));
    return Variable{.value = place, .is_place = true};
}

std::variant<ir::InstId, UnsupportedFeature> BodyLowerer::_lowerCtor(hilti::Ctor* ctor, const hilti::Location& loc) {
    if ( auto* coerced = ctor->tryAs<hilti::ctor::Coerced>() )
        ctor = coerced->coercedCtor();

    if ( auto* literal = ctor->tryAs<hilti::ctor::SignedInteger>() ) {
        if ( literal->width() != 64 )
            return _unsupported("only signed 64-bit integer literals are supported", loc);
        return _builder.addConstant(_block, literal->value(), internSpan(_package, loc));
    }

    if ( auto* literal = ctor->tryAs<hilti::ctor::Bool>() )
        return _builder.addBoolConstant(_block, literal->value(), internSpan(_package, loc));

    if ( auto* literal = ctor->tryAs<hilti::ctor::String>() )
        return _builder.addStringConstant(_block, literal->value(), internSpan(_package, loc));

    if ( auto* literal = ctor->tryAs<hilti::ctor::Bytes>() )
        return _builder.addBytesConstant(_block, literal->value(), internSpan(_package, loc));

    if ( auto* tuple = ctor->tryAs<hilti::ctor::Tuple>() ) {
        std::vector<ir::InstId> elements;
        for ( auto* element : tuple->value() ) {
            auto value = lower(element);
            if ( auto* feature = std::get_if<UnsupportedFeature>(&value) )
                return *feature;
            elements.push_back(std::get<ir::InstId>(value));
        }
        return _builder.addTuple(_block, std::move(elements), internSpan(_package, loc));
    }

    return _unsupported("unsupported literal", loc);
}

std::optional<UnsupportedFeature> BodyLowerer::_lowerIf(hilti::statement::If* stmt) {
    if ( stmt->init() )
        return _unsupported("if statements with an initializer are not supported", stmt->meta().location());

    auto cond = lower(stmt->condition());
    if ( auto* feature = std::get_if<UnsupportedFeature>(&cond) )
        return *feature;

    auto condition = std::get<ir::InstId>(cond);
    if ( _package.inst(condition).result_type != _builder.boolType() )
        return _unsupported("if conditions must be bool", stmt->condition()->meta().location());

    auto span = internSpan(_package, stmt->meta().location());
    auto then_block = _builder.createBlock(_region);
    auto else_block = _builder.createBlock(_region);
    _builder.addBranch(_block, condition, then_block, else_block, span);

    auto then_end = _lowerArm(stmt->true_(), then_block);
    if ( auto* feature = std::get_if<UnsupportedFeature>(&then_end) )
        return *feature;
    auto else_end = _lowerArm(stmt->false_(), else_block);
    if ( auto* feature = std::get_if<UnsupportedFeature>(&else_end) )
        return *feature;

    auto fall_through_then = std::get<std::optional<ir::BlockId>>(then_end);
    auto fall_through_else = std::get<std::optional<ir::BlockId>>(else_end);
    if ( ! fall_through_then && ! fall_through_else ) {
        // Both arms return, so nothing after the statement is reachable.
        _open = false;
        return std::nullopt;
    }

    auto join = _builder.createBlock(_region);
    if ( fall_through_then )
        _builder.addJump(*fall_through_then, join, span);
    if ( fall_through_else )
        _builder.addJump(*fall_through_else, join, span);

    _block = join;
    _open = true;
    return std::nullopt;
}

std::optional<UnsupportedFeature> BodyLowerer::lowerStatement(hilti::Statement* stmt) {
    if ( auto* ret = stmt->tryAs<hilti::statement::Return>() ) {
        if ( ! ret->expression() ) {
            _builder.addReturnVoid(_block, internSpan(_package, ret->meta().location()));
            _open = false;
            return std::nullopt;
        }

        auto value = lower(ret->expression());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&value) )
            return *feature;

        _builder.addReturn(_block, std::get<ir::InstId>(value), internSpan(_package, ret->meta().location()));
        _open = false;
        return std::nullopt;
    }

    if ( auto* block = stmt->tryAs<hilti::statement::Block>() )
        return lowerStatements(block->statements());

    if ( auto* if_stmt = stmt->tryAs<hilti::statement::If>() )
        return _lowerIf(if_stmt);

    if ( auto* decl = stmt->tryAs<hilti::statement::Declaration>() ) {
        auto* local = decl->declaration()->tryAs<hilti::declaration::LocalVariable>();
        if ( ! local || ! local->init() )
            return _unsupported("only local variables with an initializer are supported", stmt->meta().location());

        auto init = lower(local->init());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&init) )
            return *feature;

        auto value = std::get<ir::InstId>(init);
        auto declared = _procedures.valueType(local->type()->type());
        if ( ! declared || *declared != _package.inst(value).result_type )
            return _unsupported("local variable initializer must have the declared type", stmt->meta().location());

        auto place = _builder.addLocalPlace(_block, value, internSpan(_package, stmt->meta().location()));
        bind(local, Variable{.value = place, .is_place = true});
        return std::nullopt;
    }

    if ( auto* print = stmt->tryAs<spicy::statement::Print>() ) {
        std::vector<ir::InstId> values;
        for ( auto* expr : print->expressions() ) {
            auto value = lower(expr);
            if ( auto* feature = std::get_if<UnsupportedFeature>(&value) )
                return *feature;
            values.push_back(std::get<ir::InstId>(value));
        }

        // As the standard code generator does: no operand prints an empty line; several operands print as one tuple.
        auto span = internSpan(_package, stmt->meta().location());
        if ( values.empty() )
            values.push_back(_builder.addStringConstant(_block, "", span));

        auto newline = _builder.addBoolConstant(_block, true, span);
        if ( values.size() == 1 ) {
            _builder.addOpaqueOp(_block, _procedures.printer(false), {values[0], newline}, span);
            return std::nullopt;
        }

        auto tuple = _builder.addTuple(_block, std::move(values), span);
        _builder.addOpaqueOp(_block, _procedures.printer(true), {tuple, newline}, span);
        return std::nullopt;
    }

    if ( auto* expr_stmt = stmt->tryAs<hilti::statement::Expression>() ) {
        auto* expr = expr_stmt->expression();
        if ( auto* assign = expr->tryAs<hilti::expression::Assign>() ) {
            auto target = _place(assign->target());
            if ( auto* feature = std::get_if<UnsupportedFeature>(&target) )
                return *feature;

            auto source = lower(assign->source());
            if ( auto* feature = std::get_if<UnsupportedFeature>(&source) )
                return *feature;

            _builder.addStore(_block,
                              std::get<ir::InstId>(target),
                              std::get<ir::InstId>(source),
                              internSpan(_package, stmt->meta().location()));
            return std::nullopt;
        }

        // A call's result is discarded; the call itself stays because its effects are observable.
        auto value = lower(expr);
        if ( auto* feature = std::get_if<UnsupportedFeature>(&value) )
            return *feature;
        return std::nullopt;
    }

    return _unsupported("only return, print, local declarations, assignments, and calls are supported",
                        stmt->meta().location());
}

std::variant<ir::InstId, UnsupportedFeature> BodyLowerer::_lowerCall(hilti::expression::ResolvedOperator* op) {
    auto* name = op->op0()->tryAs<hilti::expression::Name>();
    auto* callee = name ? name->resolvedDeclaration()->tryAs<hilti::declaration::Function>() : nullptr;
    if ( ! callee )
        return _unsupported("only calls to functions are supported", op->meta().location());

    auto* ctor = op->op1()->tryAs<hilti::expression::Ctor>();
    auto* tuple = ctor ? ctor->ctor()->tryAs<hilti::ctor::Tuple>() : nullptr;
    if ( ! tuple )
        return _unsupported("call arguments must be a tuple", op->meta().location());

    const auto& args = tuple->value();
    const auto params = callee->function()->ftype()->parameters();
    if ( args.size() != params.size() )
        return _unsupported("calls must pass every parameter explicitly", op->meta().location());

    std::vector<ir::InstId> values;
    for ( size_t i = 0; i < args.size(); ++i ) {
        auto arg = params[i]->kind() == hilti::parameter::Kind::InOut ? _place(args[i]) : lower(args[i]);
        if ( auto* feature = std::get_if<UnsupportedFeature>(&arg) )
            return *feature;
        values.push_back(std::get<ir::InstId>(arg));
    }

    auto span = internSpan(_package, op->meta().location());
    if ( callee->function()->attributes()->find(hilti::attribute::kind::Cxxname) ) {
        auto foreign = _procedures.foreign(callee);
        if ( auto* feature = std::get_if<UnsupportedFeature>(&foreign) )
            return *feature;
        return _builder.addOpaqueOp(_block, std::get<ir::ForeignFunctionId>(foreign), std::move(values), span);
    }

    auto ordinary = _procedures.function(callee);
    if ( auto* feature = std::get_if<UnsupportedFeature>(&ordinary) )
        return *feature;
    return _builder.addCall(_block, std::get<ir::FunctionId>(ordinary), std::move(values), span);
}

enum class FieldForm { Integer, Bytes, Vector };

struct FieldSpec {
    type::unit::item::Field* source = nullptr;
    FieldForm form = FieldForm::Integer;
    uint32_t width = 0;
    uint64_t byte_count = 0;
    hilti::Expression* bound = nullptr; /**< a vector's `&size` */
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

class UnitLowerer {
public:
    UnitLowerer(const std::vector<hilti::declaration::Type*>& declarations,
                const std::vector<hilti::ast::TypeIndex>& external_hooks,
                ir::Package& package,
                ProcedureLowerer& procedures)
        : _declarations(declarations),
          _external_hooks(external_hooks),
          _package(package),
          _builder(package.builder()),
          _procedures(procedures) {}

    std::optional<UnsupportedFeature> build(const std::vector<hilti::declaration::Type*>& roots) {
        for ( auto* root : roots )
            _root_units.insert(root->type()->type()->as<type::Unit>());
        for ( auto* root : roots ) {
            if ( auto error = _discover(root) )
                return error;
        }

        for ( auto& spec : _units )
            spec.declaration = _builder.createUnitDecl(std::string(spec.source->id().local()),
                                                       internSpan(_package, spec.source->meta().location()));

        for ( auto& spec : _units ) {
            for ( auto& field : spec.fields ) {
                ir::TypeId field_type;
                switch ( field.form ) {
                    case FieldForm::Integer:
                        field_type = field.width == 8 ? _builder.uint8Type() : _builder.uint64Type();
                        break;
                    case FieldForm::Bytes: field_type = _builder.bytesType(); break;
                    case FieldForm::Vector:
                        field_type = _builder.vectorType(_builder.unitType(_spec(field.child).declaration));
                        break;
                }
                field.declaration = _builder.createFieldDecl(spec.declaration,
                                                             std::string(field.source->id().local()),
                                                             field_type,
                                                             internSpan(_package, field.source->meta().location()));
            }
            spec.function = _builder.createParserFunction(spec.declaration,
                                                          _builder.parserStateType(),
                                                          _builder.unitType(spec.declaration),
                                                          internSpan(_package, spec.source->meta().location()));
        }

        for ( auto& spec : _units ) {
            if ( auto error = _emit(spec) )
                return error;
        }

        for ( auto* root : roots ) {
            const auto& spec = _spec(root->type()->type()->as<type::Unit>());
            _builder.addParserRoot(spec.declaration, spec.function);
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
                if ( ! expr )
                    return reject("vector &size must be an expression", field_loc);
                f.bound = *expr;
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

    std::optional<UnsupportedFeature> _emit(UnitSpec& spec) {
        auto unit_span = internSpan(_package, spec.source->meta().location());
        auto block = _builder.createBlock(_package.function(spec.function).root_region);
        auto state = _builder.addArgument(spec.function, block, 0, unit_span);
        auto unit_value = _builder.addUnitCreate(block, spec.declaration, unit_span);
        // The fields published so far, which a later `&size` may read through `self`.
        std::unordered_map<std::string, ir::DeclId> published;
        for ( const auto& field : spec.fields ) {
            auto span = internSpan(_package, field.source->meta().location());
            ir::InstId value;
            if ( field.form == FieldForm::Integer || field.form == FieldForm::Bytes ) {
                auto read = field.form == FieldForm::Integer ?
                                _builder.addReadInteger(block,
                                                        state,
                                                        ir::ReadIntegerPayload{.width = field.width,
                                                                               .signedness = ir::Signedness::Unsigned,
                                                                               .byte_order = ir::ByteOrder::Network},
                                                        span) :
                                _builder.addReadBytes(block, state, field.byte_count, span);
                state = _builder.addTupleGet(block, read, 0, span);
                value = _builder.addTupleGet(block, read, 1, span);
            }
            else {
                auto feature = fmt("parser unit '%s'", std::string(spec.source->id()));
                // A bound is an expression, so it never adds blocks and needs no region.
                BodyLowerer bound(_procedures, _package, ir::RegionId(), block, feature);
                bound.setSelf(unit_value, published);
                auto length = bound.lower(field.bound);
                if ( auto* unsupported_feature = std::get_if<UnsupportedFeature>(&length) )
                    return *unsupported_feature;

                auto length_value = std::get<ir::InstId>(length);
                if ( _package.inst(length_value).result_type != _builder.uint64Type() )
                    return unsupported(feature,
                                       "vector &size must be an unsigned 64-bit integer",
                                       field.source->meta().location());

                state = _builder.addEnterBound(block, state, length_value, span);
                auto vector = _builder.addVectorEmpty(block, _builder.unitType(_spec(field.child).declaration), span);
                auto body = _builder.createRegion();
                auto body_block = _builder.createBlock(body);
                auto body_state = _builder.addRegionArgument(body_block, 0, _builder.parserStateType(), span);
                auto body_vector = _builder.addRegionArgument(body_block, 1, _package.inst(vector).result_type, span);
                auto child = _builder.addParseSubunit(body_block, body_state, _spec(field.child).function, span);
                auto next_state = _builder.addTupleGet(body_block, child, 0, span);
                auto element = _builder.addTupleGet(body_block, child, 1, span);
                auto next_vector = _builder.addVectorAppend(body_block, body_vector, element, span);
                _builder.addYield(body_block, {next_state, next_vector}, span);
                auto repeated = _builder.addRepeatToBound(block, {state, vector}, body, span);
                state = _builder.addTupleGet(block, repeated, 0, span);
                value = _builder.addTupleGet(block, repeated, 1, span);
                state = _builder.addLeaveBound(block, state, span);
            }
            unit_value = _builder.addPublishField(block, unit_value, value, field.declaration, span);
            published.emplace(std::string(field.source->id().local()), field.declaration);
        }
        _builder.addParserFinish(block, state, unit_value, unit_span);
        return std::nullopt;
    }

    const std::vector<hilti::declaration::Type*>& _declarations;
    const std::vector<hilti::ast::TypeIndex>& _external_hooks;
    ir::Package& _package;
    ir::Builder _builder;
    std::vector<UnitSpec> _units;
    std::unordered_set<type::Unit*> _seen;
    std::unordered_set<type::Unit*> _visiting;
    std::unordered_set<type::Unit*> _root_units;
    ProcedureLowerer& _procedures;
};

std::optional<UnsupportedFeature> lowerUnits(const std::vector<hilti::declaration::Type*>& roots,
                                             const std::vector<hilti::declaration::Type*>& unit_declarations,
                                             const std::vector<hilti::ast::TypeIndex>& units_with_external_hooks,
                                             ir::Package& package,
                                             ProcedureLowerer& procedures) {
    return UnitLowerer(unit_declarations, units_with_external_hooks, package, procedures).build(roots);
}

} // namespace

RootDiscovery discoverRoots(const hilti::ASTContext& ctx) {
    auto v = VisitorRoots();
    visitor::visit(v, ctx.root(), ".spicy");
    return RootDiscovery{
        .roots = std::move(v.roots),
        .unit_declarations = std::move(v.unit_declarations),
        .units_with_external_hooks = std::move(v.units_with_external_hooks),
        .unrepresented_content = std::move(v.unrepresented_content),
        .cxx_includes = std::move(v.cxx_includes),
        .globals = std::move(v.globals),
        .initializers = std::move(v.initializers),
    };
}

std::optional<UnsupportedFeature> lowerRoots(const RootDiscovery& discovery, ir::Package& package) {
    // If discovery doesn't support something, lowering also won't.
    if ( discovery.unrepresented_content )
        return discovery.unrepresented_content;

    for ( const auto& include : discovery.cxx_includes )
        package.builder().addCxxInclude(include);

    ProcedureLowerer procedures(package);

    // Identities first, in declaration order, so that the globals' order does not depend on which function refers to
    // them first.
    for ( auto* decl : discovery.globals ) {
        if ( auto declared = procedures.declareGlobal(decl);
             auto* feature = std::get_if<UnsupportedFeature>(&declared) )
            return *feature;
    }

    std::vector<hilti::declaration::Type*> unit_roots;
    for ( auto* decl : discovery.roots ) {
        if ( auto* fn_decl = decl->tryAs<hilti::declaration::Function>() ) {
            if ( fn_decl->function()->attributes()->find(hilti::attribute::kind::Cxxname) )
                return unsupported(fmt("public foreign function '%s'", std::string(fn_decl->id())),
                                   "public foreign functions are not supported yet",
                                   fn_decl->meta().location());

            // Discovery only reports public declarations, so each one is an exported function.
            auto lowered = procedures.function(fn_decl);
            if ( auto* feature = std::get_if<UnsupportedFeature>(&lowered) )
                return *feature;

            package.builder().addFunctionRoot(std::get<ir::FunctionId>(lowered));
            continue;
        }

        if ( auto* type_decl = decl->tryAs<hilti::declaration::Type>() ) {
            if ( type_decl->type()->alias() )
                return unsupported(fmt("public unit alias '%s'", std::string(type_decl->id())),
                                   "public unit aliases are not supported yet",
                                   type_decl->meta().location());

            unit_roots.push_back(type_decl);

            continue;
        }
    }

    for ( auto* decl : discovery.globals ) {
        if ( auto lowered = procedures.global(decl); auto* feature = std::get_if<UnsupportedFeature>(&lowered) )
            return *feature;
    }

    for ( const auto& [decl, phase] : discovery.initializers ) {
        auto lowered = procedures.function(decl);
        if ( auto* feature = std::get_if<UnsupportedFeature>(&lowered) )
            return *feature;

        package.builder().addInitializer(phase, std::get<ir::FunctionId>(lowered));
    }

    if ( auto feature = lowerUnits(unit_roots,
                                   discovery.unit_declarations,
                                   discovery.units_with_external_hooks,
                                   package,
                                   procedures) )
        return feature;

    return std::nullopt;
}

} // namespace spicy::detail::pir
