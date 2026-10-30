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
#include <hilti/ast/ctors/port.h>
#include <hilti/ast/ctors/string.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/ctors/vector.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/assign.h>
#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/logical-not.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/move.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/function.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/statements/comment.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/ast/statements/expression.h>
#include <hilti/ast/statements/if.h>
#include <hilti/ast/statements/return.h>
#include <hilti/ast/statements/set_location.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/enum.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/library.h>
#include <hilti/ast/types/name.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/set.h>
#include <hilti/ast/types/string.h>
#include <hilti/ast/types/tuple.h>
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

// The named enums that procedural code passes to the runtime, by the enum's name. Their labels are native constants.
bool isNativeEnum(const hilti::ID& enum_id) { return enum_id == hilti::ID("hilti::Protocol"); }

// The PIR transport of a runtime protocol, if a port of that protocol can be a constant.
std::optional<ir::Transport> portTransport(hilti::rt::Protocol protocol) {
    if ( protocol == hilti::rt::Protocol::TCP )
        return ir::Transport::TCP;
    if ( protocol == hilti::rt::Protocol::UDP )
        return ir::Transport::UDP;
    if ( protocol == hilti::rt::Protocol::ICMP )
        return ir::Transport::ICMP;
    return std::nullopt;
}

UnsupportedFeature unsupported(const std::string& feature, std::string reason, const hilti::Location& loc) {
    return UnsupportedFeature{.feature = feature, .reason = std::move(reason), .location = loc};
}

// Collects candidate roots for lowering PIR, as well as marking known
// unsupported constructs.
struct VisitorRoots : public visitor::PreOrder {
    std::vector<hilti::Declaration*> roots;
    std::vector<hilti::declaration::Type*> unit_declarations;
    std::vector<spicy::declaration::UnitHook*> unit_hooks;
    std::optional<UnsupportedFeature> unrepresented_content;
    std::vector<std::string> cxx_includes;
    std::vector<hilti::declaration::GlobalVariable*> globals;
    std::vector<std::pair<hilti::declaration::Function*, ir::InitPhase>> initializers;

    // Declarations of HILTI library modules, and of modules that already have an implementation elsewhere, are not
    // lowered: only the Spicy modules of this compilation are.
    static bool skipsImplementation(hilti::Declaration* n) {
        auto* m = n->parent<hilti::declaration::Module>();
        return m && (m->skipImplementation() || m->uid().parse_extension != ".spicy");
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

    // External hooks; they apply to a lowered unit whose type they name.
    void operator()(spicy::declaration::UnitHook* n) final {
        if ( ! skipsImplementation(n) )
            unit_hooks.push_back(n);
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

// The PIR identity of a lowered unit and of its fields, by name.
struct UnitInfo {
    ir::TypeDeclId declaration;
    std::unordered_map<std::string, ir::DeclId> fields;
};

// A unit object that procedural code names: the unit value, and the unit it is a value of.
struct UnitRef {
    ir::InstId value;
    const UnitInfo* info = nullptr;
    bool is_self = false; /**< the unit being parsed, whose published fields `_fields` lists */
};

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

        if ( auto* name = expr->tryAs<hilti::expression::Name>() ) {
            // Labels of a native enum name the native constant, whether or not they resolve to a declaration.
            if ( isNativeEnum(name->id().namespace_()) )
                return _lowerForeignConstant(name);
            return _read(name);
        }

        if ( auto* keyword = expr->tryAs<hilti::expression::Keyword>();
             keyword && keyword->kind() == hilti::expression::keyword::Kind::Scope )
            return _lowerLinkedArtifactScope(expr->meta().location());

        // A move hands over the value it names. The place it came from is not read again by the program.
        if ( auto* moved = expr->tryAs<hilti::expression::Move>() )
            return lower(moved->expression());

        if ( auto* negation = expr->tryAs<hilti::expression::LogicalNot>() ) {
            auto operand = lower(negation->expression());
            if ( auto* feature = std::get_if<UnsupportedFeature>(&operand) )
                return *feature;

            auto span = internSpan(_package, expr->meta().location());
            auto false_ = _builder.addBoolConstant(_block, false, span);
            return _builder.addEqual(_block, std::get<ir::InstId>(operand), false_, span);
        }

        if ( auto* op = expr->tryAs<hilti::expression::ResolvedOperator>() ) {
            if ( op->kind() == hilti::operator_::Kind::Call )
                return _lowerCall(op);
            if ( op->kind() == hilti::operator_::Kind::Equal )
                return _lowerEqual(op);
            if ( op->kind() == hilti::operator_::Kind::MemberCall )
                return _lowerMemberCall(op);
            if ( op->kind() == hilti::operator_::Kind::Add && op->op0()->type()->type()->isA<hilti::type::Set>() )
                return _lowerSetInsert(op);
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
    // `set += element` on a local set. The insertion is stored back into the set's place, as for `push_back`.
    std::variant<ir::InstId, UnsupportedFeature> _lowerSetInsert(hilti::expression::ResolvedOperator* op) {
        auto place = _place(op->op0());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&place) )
            return *feature;

        auto element = lower(op->op1());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&element) )
            return *feature;

        auto set = _load(std::get<ir::InstId>(place), op->meta().location());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&set) )
            return *feature;

        auto span = internSpan(_package, op->meta().location());
        auto inserted = _builder.addSetInsert(_block, std::get<ir::InstId>(set), std::get<ir::InstId>(element), span);
        return _builder.addStore(_block, std::get<ir::InstId>(place), inserted, span);
    }

    // Methods on a local vector. `push_back` appends to the vector in its place, so the place is stored again.
    // `reserve` only changes capacity, which no value observes, so it leaves no operation behind.
    std::variant<ir::InstId, UnsupportedFeature> _lowerMemberCall(hilti::expression::ResolvedOperator* op) {
        auto loc = op->meta().location();
        auto* member = op->op1() ? op->op1()->tryAs<hilti::expression::Member>() : nullptr;
        auto* ctor = op->op2() ? op->op2()->tryAs<hilti::expression::Ctor>() : nullptr;
        auto* tuple = ctor ? ctor->ctor()->tryAs<hilti::ctor::Tuple>() : nullptr;
        if ( ! member || ! tuple )
            return _unsupported("unsupported method call", loc);

        const auto& args = tuple->value();
        auto method = std::string(member->id());
        if ( method == "push_back" && args.size() == 1 ) {
            auto place = _place(op->op0());
            if ( auto* feature = std::get_if<UnsupportedFeature>(&place) )
                return *feature;

            auto element = lower(args[0]);
            if ( auto* feature = std::get_if<UnsupportedFeature>(&element) )
                return *feature;

            // The element is evaluated before the vector is read, so the append sees every earlier effect.
            auto vector = _load(std::get<ir::InstId>(place), loc);
            if ( auto* feature = std::get_if<UnsupportedFeature>(&vector) )
                return *feature;

            auto span = internSpan(_package, loc);
            auto appended =
                _builder.addVectorAppend(_block, std::get<ir::InstId>(vector), std::get<ir::InstId>(element), span);
            return _builder.addStore(_block, std::get<ir::InstId>(place), appended, span);
        }

        if ( method == "reserve" && args.size() == 1 ) {
            // The receiver must be a place this lowering addresses. Dropping the capacity operation must not drop
            // the receiver's evaluation, nor an access that legacy execution would make.
            auto receiver = _place(op->op0());
            if ( auto* feature = std::get_if<UnsupportedFeature>(&receiver) )
                return *feature;

            // A literal capacity has no effects, and no PIR literal of unsigned type exists yet, so it is not lowered.
            if ( ! args[0]->isA<hilti::expression::Ctor>() ) {
                auto capacity = lower(args[0]);
                if ( auto* feature = std::get_if<UnsupportedFeature>(&capacity) )
                    return *feature;
            }
            return _builder.addTuple(_block, {}, internSpan(_package, loc));
        }

        return _unsupported(fmt("method '%s' is not supported", method), loc);
    }

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

        auto* signed_type = op->result()->type()->tryAs<hilti::type::SignedInteger>();
        auto* unsigned_type = op->result()->type()->tryAs<hilti::type::UnsignedInteger>();
        if ( ! ((signed_type && signed_type->width() == 64) || (unsigned_type && unsigned_type->width() == 64)) )
            return _unsupported("only 64-bit integer addition is supported", op->meta().location());

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
        if ( ! var.is_place ) {
            // A native value that cannot be copied moves out of its variable, which may be read once. A second read
            // would need a copy.
            if ( _isNonCopyableOpaque(_package.inst(var.value).result_type) ) {
                if ( ! _moved.insert(name->resolvedDeclaration()).second )
                    return _unsupported("reading a mutable foreign value by copy", name->meta().location());
            }
            return var.value;
        }
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

    // The unit object that `expr` names: `self`, or a parameter that borrows a unit. A unit has no other form here, so
    // any other expression of unit type is unsupported rather than copied.
    std::variant<UnitRef, UnsupportedFeature> _unit(hilti::Expression* expr);

    // `<unit>.<field>`, addressed through the unit object that the expression names.
    std::variant<ir::InstId, UnsupportedFeature> _fieldPlace(hilti::expression::ResolvedOperator* op) {
        auto* member = op->op1() ? op->op1()->tryAs<hilti::expression::Member>() : nullptr;
        if ( ! member )
            return _unsupported("only fields of a unit can be accessed here", op->meta().location());

        auto unit = _unit(op->op0());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&unit) )
            return *feature;

        const auto& ref = std::get<UnitRef>(unit);
        // The unit being parsed shows the fields that are published so far, and a borrowed unit is complete.
        const auto& fields = ref.is_self ? _fields : ref.info->fields;
        auto field = fields.find(std::string(member->id()));
        if ( field == fields.end() )
            return _unsupported(fmt("field '%s' is not published yet", std::string(member->id())),
                                op->meta().location());
        return _builder.addFieldPlace(_block, ref.value, field->second, internSpan(_package, op->meta().location()));
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

    // A constant of a native type, referred to by its spelling in the runtime.
    std::variant<ir::InstId, UnsupportedFeature> _lowerForeignConstant(hilti::expression::Name* name);
    ir::InstId _lowerLinkedArtifactScope(const hilti::Location& loc);

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
    std::unordered_set<const hilti::Declaration*> _moved; /**< non-copyable variables already read */
    std::optional<ir::InstId> _self;
    std::unordered_map<std::string, ir::DeclId> _fields;
};

// Lowers ordinary functions, and the foreign functions they call, once each. A function's identity
// is recorded before its body so that recursive calls resolve to it.
class ProcedureLowerer {
public:
    explicit ProcedureLowerer(ir::Package& package) : _package(package), _builder(package.builder()) {}

    // The finite set of named enums that procedural code passes to the runtime, by the enum's name.
    std::optional<ir::TypeId> nativeEnum(const hilti::ID& enum_id) {
        if ( isNativeEnum(enum_id) )
            return _opaqueNative("hilti::rt::Protocol", true);
        return std::nullopt;
    }

    // Gives a lowered unit its identity, which procedures that take the unit refer to.
    void declareUnit(const type::Unit* unit,
                     ir::TypeDeclId declaration,
                     std::unordered_map<std::string, ir::DeclId> fields) {
        _units.emplace(unit, UnitInfo{.declaration = declaration, .fields = std::move(fields)});
    }

    // The unit that a type names, if it names a lowered one, directly or through a name or a reference.
    const UnitInfo* unitInfo(const hilti::UnqualifiedType* type) const {
        while ( type ) {
            if ( const auto* name = type->tryAs<hilti::type::Name>() )
                type = name->resolvedType();
            else if ( const auto* reference = type->tryAs<hilti::type::ValueReference>() )
                type = reference->dereferencedType()->type();
            else
                break;
        }

        const auto* unit = type ? type->tryAs<type::Unit>() : nullptr;
        auto it = unit ? _units.find(unit) : _units.end();
        return it == _units.end() ? nullptr : &it->second;
    }

    // The PIR type of a Spicy type that procedural code can hold, if PIR can represent it yet.
    std::optional<ir::TypeId> valueType(const hilti::UnqualifiedType* type) {
        if ( const auto* named = type->tryAs<hilti::type::Name>() ) {
            if ( auto native = nativeEnum(named->id()) )
                return native;
            return named->resolvedType() ? valueType(named->resolvedType()) : std::nullopt;
        }
        if ( type->isA<hilti::type::Enum>() ) {
            if ( auto native = nativeEnum(type->typeID()) )
                return native;
            return std::nullopt;
        }
        if ( type->isA<hilti::type::Port>() )
            return _opaqueNative("hilti::rt::Port", true);
        if ( const auto* vector = type->tryAs<hilti::type::Vector>() ) {
            auto element = valueType(vector->elementType()->type());
            if ( ! element || *element == _builder.voidType() )
                return std::nullopt;
            return _builder.vectorType(*element);
        }
        if ( const auto* set = type->tryAs<hilti::type::Set>() ) {
            auto element = valueType(set->elementType()->type());
            if ( ! element || *element == _builder.voidType() )
                return std::nullopt;
            return _builder.setType(*element);
        }
        if ( const auto* tuple = type->tryAs<hilti::type::Tuple>() ) {
            std::vector<ir::TypeId> elements;
            for ( const auto* element : tuple->elements() ) {
                auto value = valueType(element->type()->type());
                if ( ! value || *value == _builder.voidType() )
                    return std::nullopt;
                elements.push_back(*value);
            }
            return _builder.tupleType(std::move(elements));
        }
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
            // A borrowed unit is the object itself, whatever the access, and not a place that holds one.
            body.bind(param,
                      Variable{.value = arg,
                               .is_place = param->kind() == hilti::parameter::Kind::InOut &&
                                           ! unitInfo(param->type()->type())});
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
                                            std::vector<ir::Parameter>{},
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

    // The accessor for the scope that identifies the linked artifact to the runtime. The target supplies its
    // implementation, so it is reported as a binding.
    ir::ForeignFunctionId linkedArtifactScope() {
        if ( ! _linked_artifact_scope.isSet() ) {
            _linked_artifact_scope =
                _builder.createTargetForeignFunction("linked_artifact_scope", {}, _builder.uint64Type());
            _bindings.push_back({.function = _linked_artifact_scope, .kind = TargetBindingKind::LinkedArtifactScope});
        }
        return _linked_artifact_scope;
    }

    const std::vector<TargetBinding>& bindings() const { return _bindings; }

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
        std::vector<ir::Parameter> types;
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

            // A unit is an object that the callee borrows. It is never copied, nor held by anything but its owner.
            if ( const auto* unit = unitInfo(param->type()->type()) ) {
                if ( param->kind() == hilti::parameter::Kind::In || param->kind() == hilti::parameter::Kind::InOut ) {
                    signature.types.emplace_back(_builder.unitType(unit->declaration),
                                                 param->kind() == hilti::parameter::Kind::In ?
                                                     ir::ParameterMode::Borrow :
                                                     ir::ParameterMode::BorrowMut);
                    signature.declarations.push_back(param);
                    continue;
                }

                return unsupported(feature, "unit parameters can only be borrowed", param->meta().location());
            }

            auto value_type = valueType(param->type()->type());
            if ( ! value_type || *value_type == _builder.voidType() )
                return unsupported(feature, "parameter type is not supported yet", param->meta().location());

            switch ( param->kind() ) {
                case hilti::parameter::Kind::Copy:
                case hilti::parameter::Kind::In:
                    // A copy of an affine value transfers it, which the backend does not take yet.
                    if ( typeDiscipline(_package, *value_type) == ir::ValueDiscipline::Affine )
                        return unsupported(feature,
                                           "affine parameters are not supported yet",
                                           param->meta().location());
                    signature.types.emplace_back(*value_type);
                    break;
                case hilti::parameter::Kind::InOut:
                    signature.types.emplace_back(_builder.placeType(*value_type), ir::ParameterMode::BorrowMut);
                    break;
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
        return _opaqueNative(library->cxxName(), library->isConstant());
    }

    ir::TypeId _opaqueNative(const std::string& cxx_name, bool constant) {
        auto key = fmt("%s %s", constant ? "const" : "mutable", cxx_name);
        if ( auto it = _opaque_types.find(key); it != _opaque_types.end() )
            return it->second;

        // HILTI copies library values by value, so only a constant native type is assumed copyable.
        ir::OpaqueTypeInfo info;
        info.cxx_name = cxx_name;
        info.constant = constant;
        info.lifecycle = ir::OpaqueLifecycle{.copyable = constant, .movable = true};
        auto decl = _builder.createOpaqueTypeDecl(cxx_name, std::move(info));
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
    std::unordered_map<const type::Unit*, UnitInfo> _units;
    ir::ForeignFunctionId _print;
    ir::ForeignFunctionId _print_tuple;
    ir::ForeignFunctionId _linked_artifact_scope;
    std::vector<TargetBinding> _bindings;
};

std::variant<Variable, UnsupportedFeature> BodyLowerer::_lookupGlobal(hilti::declaration::GlobalVariable* global,
                                                                      const hilti::Location& loc) {
    auto id = _procedures.global(global);
    if ( auto* feature = std::get_if<UnsupportedFeature>(&id) )
        return *feature;

    auto place = _builder.addGlobalPlace(_block, std::get<ir::GlobalId>(id), internSpan(_package, loc));
    return Variable{.value = place, .is_place = true};
}

std::variant<UnitRef, UnsupportedFeature> BodyLowerer::_unit(hilti::Expression* expr) {
    while ( auto* coerced = expr->tryAs<hilti::expression::Coerced>() )
        expr = coerced->expression();

    auto* name = expr->tryAs<hilti::expression::Name>();
    const auto* info = _procedures.unitInfo(expr->type()->type());
    if ( ! name || ! info )
        return _unsupported("a unit can only be used through self or a unit parameter", expr->meta().location());

    if ( name->id() == hilti::ID("self") ) {
        if ( ! _self )
            return _unsupported("self is not available here", expr->meta().location());
        return UnitRef{.value = *_self, .info = info, .is_self = true};
    }

    auto it = _variables.find(name->resolvedDeclaration());
    if ( it == _variables.end() || it->second.is_place ||
         ! _package.isValid(_package.inst(it->second.value).result_type) ||
         _package.type(_package.inst(it->second.value).result_type).kind != ir::TypeKind::Unit )
        return _unsupported(fmt("reference to '%s' is not supported", std::string(name->id())),
                            expr->meta().location());
    return UnitRef{.value = it->second.value, .info = info};
}

ir::InstId BodyLowerer::_lowerLinkedArtifactScope(const hilti::Location& loc) {
    return _builder.addOpaqueOp(_block, _procedures.linkedArtifactScope(), {}, internSpan(_package, loc));
}

std::variant<ir::InstId, UnsupportedFeature> BodyLowerer::_lowerForeignConstant(hilti::expression::Name* name) {
    auto loc = name->meta().location();
    // An enum label names its enum, so the label's type follows from that enum.
    auto type = _procedures.nativeEnum(name->id().namespace_());
    if ( ! type || _package.type(*type).kind != ir::TypeKind::Opaque )
        return _unsupported(fmt("reference to '%s' is not supported", std::string(name->id())), loc);
    return _builder.addForeignConstant(_block, *type, std::string(name->id()), internSpan(_package, loc));
}

std::variant<ir::InstId, UnsupportedFeature> BodyLowerer::_lowerCtor(hilti::Ctor* ctor, const hilti::Location& loc) {
    if ( auto* coerced = ctor->tryAs<hilti::ctor::Coerced>() )
        ctor = coerced->coercedCtor();

    if ( auto* literal = ctor->tryAs<hilti::ctor::SignedInteger>() ) {
        if ( literal->width() != 64 )
            return _unsupported("only signed 64-bit integer literals are supported", loc);
        return _builder.addConstant(_block, literal->value(), internSpan(_package, loc));
    }

    if ( auto* literal = ctor->tryAs<hilti::ctor::UnsignedInteger>() ) {
        if ( literal->width() != 64 )
            return _unsupported("only unsigned 64-bit integer literals are supported", loc);
        return _builder.addUint64Constant(_block, literal->value(), internSpan(_package, loc));
    }

    if ( auto* literal = ctor->tryAs<hilti::ctor::Port>() ) {
        auto type = _procedures.valueType(literal->type()->type());
        if ( ! type )
            return _unsupported("unsupported port type", loc);

        const auto& port = literal->value();
        auto transport = portTransport(port.protocol());
        if ( ! transport )
            return _unsupported("unsupported port protocol", loc);
        return _builder.addPortConstant(_block,
                                        *type,
                                        ir::PortLiteral{.number = port.port(), .transport = *transport},
                                        internSpan(_package, loc));
    }

    if ( auto* vector = ctor->tryAs<hilti::ctor::Vector>() ) {
        auto element = _procedures.valueType(vector->elementType()->type());
        if ( ! element )
            return _unsupported("unsupported vector element type", loc);

        auto span = internSpan(_package, loc);
        auto result = _builder.addVectorEmpty(_block, *element, span);
        for ( auto* value : vector->value() ) {
            auto appended = lower(value);
            if ( auto* feature = std::get_if<UnsupportedFeature>(&appended) )
                return *feature;
            result = _builder.addVectorAppend(_block, result, std::get<ir::InstId>(appended), span);
        }
        return result;
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
        if ( local && ! local->init() ) {
            // The only default values a local may have are an empty vector and an empty set.
            auto declared = _procedures.valueType(local->type()->type());
            if ( ! declared || (_package.type(*declared).kind != ir::TypeKind::Vector &&
                                _package.type(*declared).kind != ir::TypeKind::Set) )
                return _unsupported("only local vectors and sets may be declared without an initializer",
                                    stmt->meta().location());

            auto span = internSpan(_package, stmt->meta().location());
            auto element = _package.type(*declared).type_arguments[0];
            auto empty = _package.type(*declared).kind == ir::TypeKind::Vector ?
                             _builder.addVectorEmpty(_block, element, span) :
                             _builder.addSetEmpty(_block, element, span);
            bind(local, Variable{.value = _builder.addLocalPlace(_block, empty, span), .is_place = true});
            return std::nullopt;
        }

        if ( ! local || ! local->init() )
            return _unsupported("only local variables with an initializer are supported", stmt->meta().location());

        auto init = lower(local->init());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&init) )
            return *feature;

        auto value = std::get<ir::InstId>(init);
        auto declared = _procedures.valueType(local->type()->type());
        if ( ! declared || *declared != _package.inst(value).result_type )
            return _unsupported("local variable initializer must have the declared type", stmt->meta().location());

        // A native value that cannot be copied is held as the value itself, so that a later read moves it. It cannot be
        // assigned, since an assignment needs a place, and PIR does not yet give such a place.
        if ( _isNonCopyableOpaque(*declared) ) {
            bind(local, Variable{.value = value, .is_place = false});
            return std::nullopt;
        }

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

    // A location marker around an expression is the expression as a statement, with the location it carries.
    if ( auto* marked = stmt->tryAs<hilti::statement::SetLocation>() ) {
        auto value = lower(marked->expression());
        if ( auto* feature = std::get_if<UnsupportedFeature>(&value) )
            return *feature;
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

    // A comment has no effect on the parser.
    if ( stmt->isA<hilti::statement::Comment>() )
        return std::nullopt;

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
        // A unit parameter borrows the caller's unit object.
        if ( _procedures.unitInfo(params[i]->type()->type()) ) {
            auto unit = _unit(args[i]);
            if ( auto* feature = std::get_if<UnsupportedFeature>(&unit) )
                return *feature;
            // A callee may read any field of the unit it borrows, so the unit must be complete. A unit that is still
            // being parsed has unpublished fields, which legacy execution would find unset.
            const auto& ref = std::get<UnitRef>(unit);
            if ( ref.is_self && _fields.size() != ref.info->fields.size() )
                return _unsupported("a unit that is not fully published cannot be passed to a function",
                                    args[i]->meta().location());
            values.push_back(ref.value);
            continue;
        }

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
    std::vector<ir::FunctionId> hooks; /**< run in order once the unit is complete */
};

class UnitLowerer {
public:
    UnitLowerer(const std::vector<hilti::declaration::Type*>& declarations,
                const std::vector<spicy::declaration::UnitHook*>& hooks,
                ir::Package& package,
                ProcedureLowerer& procedures)
        : _declarations(declarations),
          _hooks(hooks),
          _package(package),
          _builder(package.builder()),
          _procedures(procedures) {}

    // Discovers the units reachable from `roots` and gives them, and their fields, identities. Procedures that take a
    // unit refer to those identities, so this runs before any procedure is lowered.
    std::optional<UnsupportedFeature> declare(const std::vector<hilti::declaration::Type*>& roots) {
        _roots = roots;
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

            std::unordered_map<std::string, ir::DeclId> fields;
            for ( const auto& field : spec.fields )
                fields.emplace(std::string(field.source->id().local()), field.declaration);
            _procedures.declareUnit(spec.unit, spec.declaration, std::move(fields));
        }

        return std::nullopt;
    }

    // Lowers the parsers and the hooks of the declared units.
    std::optional<UnsupportedFeature> define() {
        for ( auto& spec : _units )
            spec.function = _builder.createParserFunction(spec.declaration,
                                                          _builder.parserStateType(),
                                                          _builder.unitType(spec.declaration),
                                                          internSpan(_package, spec.source->meta().location()));

        for ( auto& spec : _units ) {
            if ( auto error = _addHooks(spec) )
                return error;
        }

        for ( auto& spec : _units ) {
            if ( auto error = _emit(spec) )
                return error;
        }

        for ( auto* root : _roots ) {
            const auto& spec = _spec(root->type()->type()->as<type::Unit>());
            _builder.addParserRoot(spec.declaration, spec.function, std::string(spec.unit->typeID().str()));
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
        // Ports, MIME types, and descriptions go into the parser's registration record, which PIR does not build yet.
        for ( const auto* property : {"%port", "%mime-type", "%description"} ) {
            if ( ! unit->propertyItems(property).empty() )
                return reject(fmt("unit property '%s' is not supported yet", property), decl->meta().location());
        }
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

    // Lowers the external `%done`-style hooks of `spec`'s unit into functions, in the order they run: higher
    // priorities first, and equal priorities in source order.
    std::optional<UnsupportedFeature> _addHooks(UnitSpec& spec) {
        struct Pending {
            const spicy::declaration::UnitHook* source;
            int64_t priority;
        };

        std::vector<Pending> pending;
        for ( const auto* hook : _hooks ) {
            if ( hook->hook()->unitTypeIndex() != spec.unit->typeIndex() )
                continue;

            auto feature = fmt("hook of parser unit '%s'", std::string(spec.source->id()));
            auto reject = [&](std::string why, const hilti::Location& loc) {
                return unsupported(feature, std::move(why), loc);
            };
            auto* decl = hook->hook();
            if ( decl->unitFieldIndex() )
                return reject("field hooks are not supported yet", hook->meta().location());
            if ( std::string(decl->id().local()) != "0x25_done" )
                return reject("only %done hooks are supported yet", hook->meta().location());
            if ( decl->hookType() != spicy::declaration::hook::Type::Standard || decl->isDebug() ||
                 ! decl->ftype()->parameters().empty() || ! decl->ftype()->result()->type()->isA<hilti::type::Void>() )
                return reject("only standard hooks without parameters are supported yet", hook->meta().location());

            int64_t priority = 0;
            if ( auto* expr = decl->priority() ) {
                if ( auto* coerced = expr->tryAs<hilti::expression::Coerced>() )
                    expr = coerced->expression();
                auto* ctor = expr->tryAs<hilti::expression::Ctor>();
                auto* value = ctor ? ctor->ctor() : nullptr;
                if ( value && value->tryAs<hilti::ctor::Coerced>() )
                    value = value->as<hilti::ctor::Coerced>()->coercedCtor();
                if ( auto* literal = value ? value->tryAs<hilti::ctor::SignedInteger>() : nullptr )
                    priority = literal->value();
                else if ( auto* unsigned_literal = value ? value->tryAs<hilti::ctor::UnsignedInteger>() : nullptr )
                    priority = static_cast<int64_t>(unsigned_literal->value());
                else
                    return reject("hook priorities must be integer literals", hook->meta().location());
            }

            pending.push_back({hook, priority});
        }

        std::ranges::stable_sort(pending, [](const Pending& a, const Pending& b) { return a.priority > b.priority; });

        for ( const auto& [hook, priority] : pending ) {
            auto lowered = _hook(spec, hook);
            if ( auto* feature = std::get_if<UnsupportedFeature>(&lowered) )
                return *feature;

            spec.hooks.push_back(std::get<ir::FunctionId>(lowered));
        }

        return std::nullopt;
    }

    // Lowers one hook body into an ordinary function that borrows the unit being parsed. The source lets a hook change
    // `self`, so the borrow is writable, and the caller keeps the unit, so the parser can finish it after the hook.
    std::variant<ir::FunctionId, UnsupportedFeature> _hook(const UnitSpec& spec,
                                                           const spicy::declaration::UnitHook* hook) {
        auto feature = fmt("hook of parser unit '%s'", std::string(spec.source->id()));
        auto span = internSpan(_package, hook->meta().location());
        auto unit = _builder.unitType(spec.declaration);
        auto id = _builder.createFunction(fmt("%s_hook", std::string(spec.source->id().local())),
                                          {ir::Parameter(unit, ir::ParameterMode::BorrowMut)},
                                          _builder.voidType(),
                                          span);

        auto region = _package.function(id).root_region;
        auto block = _builder.createBlock(region);
        auto self = _builder.addArgument(id, block, 0, span);
        BodyLowerer body(_procedures, _package, region, block, feature);
        std::unordered_map<std::string, ir::DeclId> fields;
        for ( const auto& field : spec.fields )
            fields.emplace(std::string(field.source->id().local()), field.declaration);
        body.setSelf(self, std::move(fields));

        if ( auto error = body.lowerStatements(hook->hook()->body()->statements()) )
            return *error;

        body.returnVoidIfOpen(span);
        return id;
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
        // The parser chooses where the consumers run and in what order, and calls them like any other procedure.
        for ( auto hook : spec.hooks )
            _builder.addCall(block, hook, {unit_value}, unit_span);
        _builder.addParserFinish(block, state, unit_value, unit_span);
        return std::nullopt;
    }

    const std::vector<hilti::declaration::Type*>& _declarations;
    const std::vector<spicy::declaration::UnitHook*>& _hooks;
    ir::Package& _package;
    ir::Builder _builder;
    std::vector<UnitSpec> _units;
    std::unordered_set<type::Unit*> _seen;
    std::unordered_set<type::Unit*> _visiting;
    std::unordered_set<type::Unit*> _root_units;
    ProcedureLowerer& _procedures;
    std::vector<hilti::declaration::Type*> _roots;
};

} // namespace

RootDiscovery discoverRoots(const hilti::ASTContext& ctx) {
    auto v = VisitorRoots();
    visitor::visit(v, ctx.root(), ".spicy");
    return RootDiscovery{
        .roots = std::move(v.roots),
        .unit_declarations = std::move(v.unit_declarations),
        .unrepresented_content = std::move(v.unrepresented_content),
        .cxx_includes = std::move(v.cxx_includes),
        .unit_hooks = std::move(v.unit_hooks),
        .globals = std::move(v.globals),
        .initializers = std::move(v.initializers),
    };
}

std::optional<UnsupportedFeature> lowerRoots(const RootDiscovery& discovery,
                                             ir::Package& package,
                                             std::vector<TargetBinding>& bindings) {
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

    // Units get their identities before any procedure is lowered, since a procedure may take a unit.
    std::vector<hilti::declaration::Type*> unit_roots;
    for ( auto* decl : discovery.roots ) {
        if ( auto* type_decl = decl->tryAs<hilti::declaration::Type>() ) {
            if ( type_decl->type()->alias() )
                return unsupported(fmt("public unit alias '%s'", std::string(type_decl->id())),
                                   "public unit aliases are not supported yet",
                                   type_decl->meta().location());

            unit_roots.push_back(type_decl);
        }
    }

    UnitLowerer units(discovery.unit_declarations, discovery.unit_hooks, package, procedures);
    if ( auto feature = units.declare(unit_roots) )
        return feature;

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

            // A unit has no public form in a function's signature: the generated unit is not the legacy one.
            for ( auto* param : fn_decl->function()->ftype()->parameters() )
                if ( procedures.unitInfo(param->type()->type()) )
                    return unsupported(fmt("public function '%s'", std::string(fn_decl->id())),
                                       "public functions cannot take a unit",
                                       fn_decl->meta().location());

            package.builder().addFunctionRoot(std::get<ir::FunctionId>(lowered));
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

    if ( auto feature = units.define() )
        return feature;

    bindings = procedures.bindings();
    return std::nullopt;
}

} // namespace spicy::detail::pir
