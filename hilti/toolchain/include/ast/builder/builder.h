// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <hilti/ast/builder/node-factory.h>

namespace hilti {

struct Options;

/**
 * Builder wrapping an AST context to provide convenience factory methods for
 * AST nodes.
 *
 * There are two types of factory methods:
 *
 * 1. All `create()` methods of any Node-derived class gets a corresponding
 * method inside the builder that simply forwards all arguments, just adding
 * the builder's AST context. This allows the caller to use an existing builder
 * without needing to worry about the context parameter that all the
 * `create()` method need. All the forwarding methods are defined in the
 * auto-generated `builder::NodeFactory` base class.
 *
 * 2. Additional convenience methods constructing nodes that don't have a
 * direct 1-to-1 equivalent in any `create()` method, including creating entire
 * subtrees of nodes at once. These methods are defined directly in the
 * `Builder` class.
 */
class Builder : public builder::NodeFactory {
public:
    virtual ~Builder() = default;

    /** Constructs a builder that will use a given context. */
    Builder(ASTContext* ctx) : NodeFactory(ctx) { _static_state.block = statement::Block::create(ctx, {}, {}); }

    /** Construct a builder that adds any flow-level nodes to a given pre-existing block. */
    Builder(ASTContext* context, statement::Block* block) : NodeFactory(context) { _static_state.block = block; }

    /**
     * Returns the current block associated with the builder for creating
     * flow-level nodes, or null if none.
     */
    const auto& block() const { return _state->block; }

    /** Shortcut to retrieve compiler options from the AST context. */
    const Options& options() const;

    /**
     * Expresses the coercion of an expression into a target type. Note that
     * the coercion will not be immediately performed, but just recorded to
     * perform later during AST resolving. This version associated the source
     * expressions meta data with the coercion.
     */
    auto coerceTo(Expression* e, QualifiedType* t) { return expressionPendingCoerced(e, t, e->meta()); }

    /**
     * Expresses the coercion of an expression into a target type. Note that
     * the coercion will not be immediately performed, but just recorded to
     * perform later during AST resolving. This version associated custom meta
     * data with the coercion.
     */
    auto coerceTo(Expression* e, QualifiedType* t, const Meta& m) { return expressionPendingCoerced(e, t, m); }

    //////// Helpers for operators

    /** Constructs a node representing the main node for constructor call operator. */
    auto ctorType(UnqualifiedType* t) { return typeType(qualifiedType(t, Constness::Const)); }

    //////// Declarations

    auto import(const std::string& module, const Meta& m = Meta()) {
        return declarationImportedModule(hilti::ID(module), std::string(".hlt"), m);
    }

    auto import(const std::string& module, const std::string& parse_extension, const Meta& m = Meta()) {
        return declarationImportedModule(hilti::ID(module), parse_extension, m);
    }

    auto import(const std::string& module, const std::string& parse_extension, ID search_scope,
                const Meta& m = Meta()) {
        return declarationImportedModule(hilti::ID(module), parse_extension, std::move(search_scope), m);
    }

    auto local(ID id_, QualifiedType* t, Meta m = Meta()) {
        return statementDeclaration(declarationLocalVariable(std::move(id_), t, {}, std::move(m)));
    }

    auto local(ID id_, Expression* init, const Meta& m = Meta()) {
        return statementDeclaration(declarationLocalVariable(std::move(id_), init, m));
    }

    auto local(ID id_, QualifiedType* t, Expression* init, Meta m = Meta()) {
        return statementDeclaration(declarationLocalVariable(std::move(id_), t, init, std::move(m)));
    }

    auto local(ID id_, QualifiedType* t, Expressions args, Meta m = Meta()) {
        return statementDeclaration(declarationLocalVariable(std::move(id_), t, std::move(args), {}, std::move(m)));
    }

    auto global(ID id_, QualifiedType* t, declaration::Linkage linkage = declaration::Linkage::Private,
                Meta m = Meta()) {
        return declarationGlobalVariable(std::move(id_), t, {}, linkage, std::move(m));
    }

    auto global(ID id_, Expression* init, declaration::Linkage linkage = declaration::Linkage::Private,
                const Meta& m = Meta()) {
        return declarationGlobalVariable(std::move(id_), init, linkage, m);
    }

    auto global(ID id_, QualifiedType* t, Expression* init,
                declaration::Linkage linkage = declaration::Linkage::Private, Meta m = Meta()) {
        return declarationGlobalVariable(std::move(id_), t, init, linkage, std::move(m));
    }

    auto global(ID id_, QualifiedType* t, Expressions args,
                declaration::Linkage linkage = declaration::Linkage::Private, Meta m = Meta()) {
        return declarationGlobalVariable(std::move(id_), t, std::move(args), {}, linkage, std::move(m));
    }

    auto type(ID id, QualifiedType* type, declaration::Linkage linkage = declaration::Linkage::Private,
              Meta m = Meta()) {
        return declarationType(std::move(id), type, linkage, std::move(m));
    }

    auto type(ID id, QualifiedType* type, AttributeSet* attrs,
              declaration::Linkage linkage = declaration::Linkage::Private, Meta m = Meta()) {
        return declarationType(std::move(id), type, attrs, linkage, std::move(m));
    }

    auto constant(ID id_, Expression* init, declaration::Linkage linkage = declaration::Linkage::Private,
                  Meta m = Meta()) {
        return declarationConstant(std::move(id_), init, linkage, std::move(m));
    }

    auto parameter(ID id, UnqualifiedType* type, parameter::Kind kind = parameter::Kind::In, Meta m = Meta()) {
        return declarationParameter(std::move(id), type, kind, {}, {}, std::move(m));
    }

    auto parameter(ID id, UnqualifiedType* type, Expression* default_, parameter::Kind kind = parameter::Kind::In,
                   Meta m = Meta()) {
        return declarationParameter(std::move(id), type, kind, default_, {}, std::move(m));
    }

    template<typename... Params>
    static auto parameters(Params&&... params) {
        return std::vector<hilti::type::function::Parameter*>{std::forward<Params>(params)...};
    }

    using NodeFactory::function;

    auto function(const ID& id, QualifiedType* result, const declaration::Parameters& params,
                  type::function::Flavor flavor = type::function::Flavor::Function,
                  declaration::Linkage linkage = declaration::Linkage::Private,
                  type::function::CallingConvention cc = type::function::CallingConvention::Standard,
                  AttributeSet* attrs = {}, const Meta& m = Meta()) {
        auto* ft = typeFunction(result, params, flavor, cc, m);
        auto* f = function(id, ft, {}, attrs, m);
        return declarationFunction(f, linkage, m);
    }

    auto function(const ID& id, QualifiedType* result, const declaration::Parameters& params, statement::Block* body,
                  type::function::Flavor flavor = type::function::Flavor::Function,
                  declaration::Linkage linkage = declaration::Linkage::Private,
                  type::function::CallingConvention cc = type::function::CallingConvention::Standard,
                  AttributeSet* attrs = {}, const Meta& m = Meta()) {
        auto* ft = typeFunction(result, params, flavor, cc, m);
        auto* f = function(id, ft, body, attrs, m);
        return declarationFunction(f, linkage, m);
    }

    //////// Types

    auto typeTypeInfo(const Meta& m = Meta()) { return typeLibrary(Constness::Const, "hilti::rt::TypeInfo*", m); }

    //////// Expressions

    // Constructors.

    auto id(const ID& id_, const Meta& m = Meta()) { return expressionName(id_, m); }

    auto stringMutable(std::string_view s, const Meta& m = Meta()) {
        return expressionCtor(ctorString({s.data(), s.size()}, false, m), m);
    }

    auto stringLiteral(std::string_view s, const Meta& m = Meta()) {
        // String literals have no location.
        return expressionCtor(ctorString({s.data(), s.size()}, true));
    }

    auto bool_(bool b, const Meta& m = Meta()) { return expressionCtor(ctorBool(b, m), m); }

    auto bytes(std::string s, const Meta& m = Meta()) { return expressionCtor(ctorBytes(std::move(s), m), m); }

    auto default_(UnqualifiedType* t, const Meta& m = Meta()) { return expressionCtor(ctorDefault(t, m), m); }

    auto default_(UnqualifiedType* t, const Expressions& type_args, const Meta& m = Meta()) {
        return expressionCtor(ctorDefault(t, type_args, m), m);
    }

    auto exception(UnqualifiedType* t, const std::string& msg, const Meta& m = Meta()) {
        return expressionCtor(ctorException(t, stringLiteral(msg), m), m);
    }

    auto exception(UnqualifiedType* t, Expression* msg, const Meta& m = Meta()) {
        return expressionCtor(ctorException(t, msg, m), m);
    }

    auto exception(UnqualifiedType* t, Expression* what, Expression* where, const Meta& m = Meta()) {
        return expressionCtor(ctorException(t, what, where, m), m);
    }

    auto integer(int i, const Meta& m = Meta()) {
        return expressionCtor(ctorSignedInteger(static_cast<int64_t>(i), 64, m), m);
    }

    auto integer(int64_t i, const Meta& m = Meta()) { return expressionCtor(ctorSignedInteger(i, 64, m), m); }

    auto integer(unsigned int i, const Meta& m = Meta()) { return expressionCtor(ctorUnsignedInteger(i, 64, m), m); }

    auto integer(uint64_t i, const Meta& m = Meta()) { return expressionCtor(ctorUnsignedInteger(i, 64, m), m); }

    auto null(const Meta& m = Meta()) { return expressionCtor(ctorNull(m), m); }

    auto optional(Expression* e, const Meta& m = Meta()) { return expressionCtor(ctorOptional(e, m), m); }

    auto optional(QualifiedType* t, const Meta& m = Meta()) { return expressionCtor(ctorOptional(t, m), m); }

    auto port(hilti::rt::Port p, const Meta& m = Meta()) { return expressionCtor(ctorPort(p, m), m); }

    auto regexp(std::string p, AttributeSet* attrs = {}, const Meta& m = Meta()) {
        return expressionCtor(ctorRegExp({std::move(p)}, attrs, m), m);
    }

    auto regexp(hilti::ctor::regexp::Patterns p, AttributeSet* attrs = {}, const Meta& m = Meta()) {
        return expressionCtor(ctorRegExp(std::move(p), attrs, m), m);
    }

    auto stream(std::string s, const Meta& m = Meta()) { return expressionCtor(ctorStream(std::move(s), m), m); }

    auto string(std::string s, bool is_literal, const Meta& m = Meta()) {
        return expressionCtor(ctorString(std::move(s), is_literal, m), m);
    }

    auto struct_(const ctor::struct_::Fields& f, const Meta& m = Meta()) { return expressionCtor(ctorStruct(f, m), m); }

    auto struct_(const ctor::struct_::Fields& f, QualifiedType* t, const Meta& m = Meta()) {
        return expressionCtor(ctorStruct(f, t, m), m);
    }

    auto tuple(const Expressions& v, const Meta& m = Meta()) { return expressionCtor(ctorTuple(v, m), m); }

    auto vector(const Expressions& v, const Meta& m = Meta()) { return expressionCtor(ctorVector(v, m), m); }

    auto vector(QualifiedType* t, const Expressions& v, const Meta& m = Meta()) {
        return expressionCtor(ctorVector(t, v, m), m);
    }

    auto vector(QualifiedType* t, const Meta& m = Meta()) { return expressionCtor(ctorVector(t, {}, m), m); }

    auto void_(const Meta& m = Meta()) { return expressionVoid(m); }

    auto strongReference(QualifiedType* t, const Meta& m = Meta()) {
        return expressionCtor(ctorStrongReference(t, m), m);
    }

    auto weakReference(QualifiedType* t, const Meta& m = Meta()) { return expressionCtor(ctorWeakReference(t, m), m); }

    auto valueReference(Expression* e, const Meta& m = Meta()) { return expressionCtor(ctorValueReference(e, m), m); }

    // Operator expressions

    auto add(Expression* target, Expression* index, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Add, {target, index}, m);
    }

    auto and_(Expression* op0, Expression* op1, const Meta& m = Meta()) { return expressionLogicalAnd(op0, op1, m); }

    auto or_(Expression* op0, Expression* op1, const Meta& m = Meta()) { return expressionLogicalOr(op0, op1, m); }

    auto begin(Expression* e, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Begin, {e}, m);
    }

    auto cast(Expression* e, QualifiedType* dst, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Cast, {e, expressionType(dst)}, m);
    }

    auto delete_(Expression* self, const ID& field, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Delete, {self, expressionMember(field)}, m);
    }

    auto deref(Expression* e, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Deref, {e}, m);
    }

    auto end(Expression* e, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::End, {e}, m);
    }

    auto call(const ID& id_, const Expressions& v, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Call, {id(id_, m), tuple(v, m)}, m);
    }

    auto index(Expression* value, Expression* index, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Index, {value, index}, m);
    }

    auto size(Expression* op, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Size, {op}, m);
    }

    auto modulo(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Modulo, {op1, op2}, m);
    }

    auto lowerEqual(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::LowerEqual, {op1, op2}, m);
    }

    auto greaterEqual(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::GreaterEqual, {op1, op2}, m);
    }

    auto lower(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Lower, {op1, op2}, m);
    }

    auto greater(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Greater, {op1, op2}, m);
    }

    auto equal(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Equal, {op1, op2}, m);
    }

    auto unequal(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Unequal, {op1, op2}, m);
    }

    auto member(Expression* self, const std::string& id_, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Member, {self, expressionMember(ID(id_), m)}, m);
    }

    auto hasMember(Expression* self, const std::string& id_, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::HasMember, {self, expressionMember(ID(id_), m)}, m);
    }

    auto tryMember(Expression* self, const std::string& id_, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::TryMember, {self, expressionMember(ID(id_), m)}, m);
    }

    auto memberCall(Expression* self, const std::string& id_, const Expressions& args = {}, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::MemberCall,
                                            {self, expressionMember(ID(id_), m), tuple(args, m)}, m);
    }

    auto memberCall(Expression* self, const std::string& id_, ctor::Tuple* args, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::MemberCall,
                                            {self, expressionMember(ID(id_), m), expressionCtor(args)}, m);
    }

    auto pack(QualifiedType* type, const Expressions& args, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Pack, {expressionType(type, m), tuple(args, m)}, m);
    }

    auto unpack(QualifiedType* type, const Expressions& args, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Unpack,
                                            {expressionType(type, m), tuple(args, m), expressionCtor(ctorBool(false))},
                                            m);
    }

    auto unset(Expression* self, const ID& field, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Unset, {self, expressionMember(field)}, m);
    }

    auto sumAssign(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::SumAssign, {op1, op2}, m);
    }

    auto differenceAssign(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::DifferenceAssign, {op1, op2}, m);
    }

    auto sum(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Sum, {op1, op2}, m);
    }

    auto difference(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Difference, {op1, op2}, m);
    }

    auto decrementPostfix(Expression* op, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::DecrPostfix, {op}, m);
    }

    auto decrementPrefix(Expression* op, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::DecrPrefix, {op}, m);
    }

    auto incrementPostfix(Expression* op, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::IncrPostfix, {op}, m);
    }

    auto incrementPrefix(Expression* op, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::IncrPrefix, {op}, m);
    }

    auto new_(UnqualifiedType* t, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::New,
                                            {expressionType(qualifiedType(t, hilti::Constness::Const), m),
                                             expressionCtor(ctorTuple({}, m))},
                                            m);
    }

    auto new_(UnqualifiedType* t, const Expressions& args, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::New,
                                            {expressionType(qualifiedType(t, hilti::Constness::Const), m),
                                             expressionCtor(ctorTuple(args, m))},
                                            m);
    }

    auto division(Expression* op1, Expression* op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Division, {op1, op2}, m);
    }

    // Other expressions

    auto expression(Ctor* c, const Meta& m = Meta()) { return expressionCtor(c, m); }

    auto expression(const Location& l) { return stringLiteral(std::string(l)); }

    auto expression(const Meta& m) { return expression(m.location()); }

    auto grouping(Expression* e, const Meta& m = Meta()) { return expressionGrouping(e, m); }


    /**
     * Creates a grouping expression that declares a temporary variable that
     * will be valid inside the group. The temporary variable will be created
     * with a unique name and initialized with a given expression.
     *
     * @param prefix prefix for the temporary variable's ID.
     * @param init expression initializing the temporary variable
     * @param m meta data for the grouping expression.
     * @return A pair consisting of (1) an expression referring to the
     * temporary variable's ID and (2) a grouping expression with that
     * temporary initialized, yet the contained expression still unset (it can
     * be set later via `expression::Grouping::setExpression()`)
     */
    std::pair<expression::Name*, expression::Grouping*> groupingWithTmp(const std::string& prefix, Expression* init,
                                                                        const Meta& m = Meta());

    auto move(Expression* e, const Meta& m = Meta()) { return expressionMove(e, m); }

    auto typeinfo(QualifiedType* t, const Meta& m = Meta()) { return expressionTypeInfo(expressionType(t, m), m); }

    auto typeinfo(Expression* e, const Meta& m = Meta()) { return expressionTypeInfo(e, m); }

    auto typeWrapped(Expression* e, QualifiedType* t, const Meta& m = Meta()) {
        return expression::TypeWrapped::create(context(), e, t, m);
    }

    auto assign(Expression* target, Expression* src, const Meta& m = Meta()) {
        return expressionAssign(target, src, m);
    }

    auto not_(Expression* e, const Meta& m = Meta()) { return expressionLogicalNot(e, m); }

    auto ternary(Expression* cond, Expression* true_, Expression* false_, const Meta& m = Meta()) {
        return expressionTernary(cond, true_, false_, m);
    }

    auto conditionTest(Expression* value, Expression* error, const Meta& m = Meta()) {
        return expressionConditionTest(value, error, m);
    }

    auto min(Expression* e1, Expression* e2, const Meta& m = Meta()) {
        return ternary(lowerEqual(e1, e2, m), e1, e2, m);
    }

    auto max(Expression* e1, Expression* e2, const Meta& m = Meta()) {
        return ternary(lowerEqual(e1, e2, m), e2, e1, m);
    }

    auto namedCtor(const std::string& name, const Expressions& args, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Call,
                                            {expressionMember(ID(name)), expressionCtor(ctorTuple(args))}, m);
    }

    auto scope(const Meta& m = Meta()) { return expressionKeyword(hilti::expression::keyword::Kind::Scope, m); }

    //////////// Variables and statements

    Expression* addTmp(const std::string& prefix, Expression* init);
    Expression* addTmp(const std::string& prefix, QualifiedType* t, const Expressions& args = {});
    Expression* addTmp(const std::string& prefix, QualifiedType* t, Expression* init);
    Expression* addTmp(const std::string& prefix, UnqualifiedType* t, const Expressions& args = {}) {
        return addTmp(prefix, qualifiedType(t, Constness::Mutable), args);
    }
    Expression* addTmp(const std::string& prefix, UnqualifiedType* t, Expression* init) {
        return addTmp(prefix, qualifiedType(t, Constness::Mutable), init);
    }

    void addLocal(ID id, QualifiedType* t, Meta m = Meta()) {
        block()->_add(context(), local(std::move(id), t, std::move(m)));
    }

    void addLocal(ID id, Expression* init, const Meta& m = Meta()) {
        block()->_add(context(), local(std::move(id), init, m));
    }

    void addLocal(ID id, QualifiedType* t, Expression* init, Meta m = Meta()) {
        block()->_add(context(), local(std::move(id), t, init, std::move(m)));
    }

    void addLocal(ID id, QualifiedType* t, std::vector<hilti::Expression*> args, Meta m = Meta()) {
        block()->_add(context(), local(std::move(id), t, std::move(args), std::move(m)));
    }

    void addExpression(Expression* expr) { block()->_add(context(), statementExpression(expr, expr->meta())); }

    void addAssert(Expression* cond, std::string_view msg, Meta m = Meta()) {
        block()->_add(context(), statementAssert(cond, stringMutable(msg), std::move(m)));
    }

    void addAssign(Expression* dst, Expression* src, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(assign(dst, src, m), m));
    }

    void addSumAssign(Expression* dst, Expression* src, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(sumAssign(dst, src, m), m));
    }

    void addAssign(const ID& dst, Expression* src, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(assign(id(dst), src, m), m));
    }

    void addBreak(Meta m = Meta()) { block()->_add(context(), statementBreak(std::move(m))); }

    void addContinue(Meta m = Meta()) { block()->_add(context(), statementContinue(std::move(m))); }

    void addSumAssign(const ID& dst, Expression* src, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(sumAssign(id(dst), src, m), m));
    }

    void addCall(const ID& id, const Expressions& v, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(call(id, v, m), m));
    }

    void addMemberCall(Expression* self, const ID& id, const Expressions& v, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(memberCall(self, id, v, m), m));
    }

    void addComment(std::string comment,
                    hilti::statement::comment::Separator separator = hilti::statement::comment::Separator::Before,
                    const Meta& m = Meta()) {
        comment = util::replace(comment, "\n", "");
        block()->_add(context(), statementComment(std::move(comment), separator, m));
    }

    void addReturn(Expression* e, Meta m = Meta()) { block()->_add(context(), statementReturn(e, std::move(m))); }

    void addReturn(Ctor* c, const Meta& m = Meta()) {
        block()->_add(context(), statementReturn(expressionCtor(c, m), m));
    }

    void addReturn(Meta m = Meta()) { block()->_add(context(), statementReturn(std::move(m))); }

    void addThrow(Expression* except, Meta m = Meta()) {
        block()->_add(context(), statementThrow(except, std::move(m)));
    }

    void addRethrow(Meta m = Meta()) { block()->_add(context(), statementThrow(std::move(m))); }

    void addDebugMsg(std::string_view stream, std::string_view fmt, Expressions args = {});
    void addDebugIndent(std::string_view stream);
    void addDebugDedent(std::string_view stream);

    void addPrint(const Expressions& exprs) { addCall("hilti::print", exprs); }
    void addPrint(Expression* expr) { addCall("hilti::print", {expr}); }

    void setLocation(const Location& l);

    bool empty() const { return block()->statements().empty() && _tmps().empty(); }

    Expression* startProfiler(std::string_view name, Expression* size = nullptr);
    void stopProfiler(Expression* profiler, Expression* size = nullptr);

protected:
    Builder(Builder* parent) : NodeFactory(parent->context()), _state(parent->_state) {}

private:
    // Helper to create unique temporary IDs.
    ID _makeTmpID(const std::string& prefix);

    struct State {
        statement::Block* block = nullptr;
        std::map<std::string, int> tmps;
    };

    std::map<std::string, int>& _tmps() const { return _state->tmps; }

    State _static_state;
    State* _state = &_static_state;
};

// Extended version of the `Builder` including any methods that depend on the
// builder's type. We don't use these inside the HILTI infrastructure, but
// it's helpful for external users constructing ASTs. They should derive their
// own `Builder` class from this template and then use that for constructing
// ASTs, potentially adding more methods of their own as needed as well.
template<typename Builder>
class ExtendedBuilderTemplate : public Builder {
public:
    using Builder::Builder;

    auto addWhile(statement::Declaration* init, Expression* cond, const Meta& m = Meta()) {
        auto body = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), Builder::statementWhile(init->declaration(), cond, body, {}, m));
        return _newBuilder(body);
    }

    auto addWhile(Expression* cond, const Meta& m = Meta()) {
        auto body = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), Builder::statementWhile(cond, body, {}, m));
        return _newBuilder(body);
    }

    auto addWhileElse(statement::Declaration* init, Expression* cond, const Meta& m = Meta()) {
        auto body = Builder::statementBlock();
        auto else_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), statementWhile(init->declaration(), cond, body, else_, m));
        return std::make_pair(_newBuilder(body), _newBuilder(else_));
    }

    auto addWhileElse(Expression* cond, const Meta& m = Meta()) {
        auto body = Builder::statementBlock();
        auto else_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), Builder::statementWhile(cond, body, else_, m));
        return std::make_pair(_newBuilder(body), _newBuilder(else_));
    }

    auto addIf(statement::Declaration* init, Expression* cond, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(),
                               Builder::statementIf(init->declaration(), cond, true_, {}, std::move(m)));
        return _newBuilder(true_);
    }

    auto addIf(statement::Declaration* init, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), statementIf(init->declaration(), {}, true_, {}, std::move(m)));
        return _newBuilder(true_);
    }

    auto addIf(Expression* cond, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), Builder::statementIf(cond, true_, {}, std::move(m)));
        return _newBuilder(true_);
    }

    auto addIfElse(statement::Declaration* init, Expression* cond, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        auto false_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(),
                               Builder::statementIf(init->declaration(), cond, true_, false_, std::move(m)));
        return std::make_pair(_newBuilder(true_), _newBuilder(false_));
    }

    auto addIfElse(statement::Declaration* init, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        auto false_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), statementIf(init->declaration(), {}, true_, false_, std::move(m)));
        return std::make_pair(_newBuilder(true_), _newBuilder(false_));
    }

    auto addIfElse(Expression* cond, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        auto false_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), Builder::statementIf(cond, true_, false_, std::move(m)));
        return std::make_pair(_newBuilder(true_), _newBuilder(false_));
    }

    auto newBlock(const Meta& m = Meta()) {
        auto body = Builder::statementBlock(m);
        return _newBuilder(body);
    }

    auto addBlock(const Meta& m = Meta()) {
        auto body = Builder::statementBlock(m);
        Builder::block()->_add(Builder::context(), body);
        return _newBuilder(body);
    }

    class SwitchProxy {
    public:
        SwitchProxy(ExtendedBuilderTemplate* b, statement::Switch* s) : _builder(b), _switch(s) {}

        auto addCase(Expression* expr, const Meta& m = Meta()) { return _addCase({expr}, m); }

        auto addCase(const Expressions& exprs, const Meta& m = Meta()) { return _addCase(exprs, m); }

        auto addDefault(const Meta& m = Meta()) { return _addCase({}, m); }

    private:
        std::shared_ptr<ExtendedBuilderTemplate> _addCase(const Expressions& exprs, const Meta& m = Meta()) {
            auto body = _builder->statementBlock(m);
            _switch->addCase(_builder->context(), _builder->statementSwitchCase(exprs, body, m));
            return _builder->_newBuilder(body);
        }

        ExtendedBuilderTemplate* _builder;
        statement::Switch* _switch = nullptr;
    };

    auto addSwitch(Expression* cond, Meta m = Meta()) {
        auto switch_ = Builder::statementSwitch(cond, {}, std::move(m));
        Builder::block()->_add(Builder::context(), switch_);
        return SwitchProxy(this, switch_);
    }

    auto addSwitch(statement::Declaration* cond, Meta m = Meta()) {
        auto switch_ = Builder::statementSwitch(cond->declaration(), {}, std::move(m));
        Builder::block()->_add(Builder::context(), switch_);
        return SwitchProxy(this, switch_);
    }

    class TryProxy {
    public:
        TryProxy(ExtendedBuilderTemplate* b, statement::Try* s) : _builder(b), _try(s) {}

        auto addCatch(declaration::Parameter* p, const Meta& m = Meta()) {
            auto body = _builder->statementBlock(m);
            _try->addCatch(_builder->context(), _builder->statementTryCatch(p, body, m));
            return _builder->_newBuilder(body);
        }

        auto addCatch(const Meta& m = Meta()) {
            auto body = _builder->statementBlock(m);
            _try->addCatch(_builder->context(), _builder->statementTryCatch(body, m));
            return _builder->_newBuilder(body);
        }

        TryProxy(const TryProxy&) = default;
        TryProxy(TryProxy&&) noexcept = default;
        TryProxy() = delete;
        ~TryProxy() = default;
        TryProxy& operator=(const TryProxy&) = default;
        TryProxy& operator=(TryProxy&&) noexcept = default;

    private:
        ExtendedBuilderTemplate* _builder;
        statement::Try* _try = nullptr;
    };

    auto addTry(Meta m = Meta()) {
        auto body = Builder::statementBlock();
        auto try_ = Builder::statementTry(body, {}, std::move(m));
        Builder::block()->_add(Builder::context(), try_);
        return std::make_pair(_newBuilder(body), TryProxy(this, try_));
    }

private:
    std::shared_ptr<ExtendedBuilderTemplate> _newBuilder(statement::Block* block) {
        return std::make_shared<ExtendedBuilderTemplate>(Builder::context(), block);
    }
};

using BuilderPtr = std::shared_ptr<Builder>;

} // namespace hilti
