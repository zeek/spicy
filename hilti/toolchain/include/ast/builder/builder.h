// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
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
    /** Constructs a builder that will use a given context. */
    Builder(ASTContext* ctx) : NodeFactory(ctx) { _static_state.block = statement::Block::create(ctx, {}, {}); }

    /** Construct a builder that adds any flow-level nodes to a given pre-existing block. */
    Builder(ASTContext* context, std::shared_ptr<statement::Block> block) : NodeFactory(context) {
        _static_state.block = std::move(block);
    }

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
    auto coerceTo(const ExpressionPtr& e, const QualifiedTypePtr& t) {
        return expressionPendingCoerced(e, t, e->meta());
    }

    /**
     * Expresses the coercion of an expression into a target type. Note that
     * the coercion will not be immediately performed, but just recorded to
     * perform later during AST resolving. This version associated custom meta
     * data with the coercion.
     */
    auto coerceTo(const ExpressionPtr& e, const QualifiedTypePtr& t, const Meta& m) {
        return expressionPendingCoerced(e, t, m);
    }

    //////// Helpers for operators

    /** Constructs a node representing the main node for constructor call operator. */
    auto ctorType(const UnqualifiedTypePtr& t) { return typeType(qualifiedType(t, Constness::Const)); }

    //////// Declarations

    auto import(std::string module, const Meta& m = Meta()) {
        return declarationImportedModule(hilti::ID(std::move(module), m), std::string(".hlt"), m);
    }

    auto import(std::string module, const std::string& parse_extension, const Meta& m = Meta()) {
        return declarationImportedModule(hilti::ID(std::move(module), m), parse_extension, m);
    }

    auto import(std::string module, const std::string& parse_extension, ID search_scope, const Meta& m = Meta()) {
        return declarationImportedModule(hilti::ID(std::move(module), m), parse_extension, std::move(search_scope), m);
    }

    auto local(ID id_, const QualifiedTypePtr& t, Meta m = Meta()) {
        return statementDeclaration(declarationLocalVariable(std::move(id_), t, {}, std::move(m)));
    }

    auto local(ID id_, ExpressionPtr init, const Meta& m = Meta()) {
        return statementDeclaration(declarationLocalVariable(std::move(id_), std::move(init), m));
    }

    auto local(ID id_, const QualifiedTypePtr& t, ExpressionPtr init, Meta m = Meta()) {
        return statementDeclaration(declarationLocalVariable(std::move(id_), t, std::move(init), std::move(m)));
    }

    auto local(ID id_, const QualifiedTypePtr& t, Expressions args, Meta m = Meta()) {
        return statementDeclaration(declarationLocalVariable(std::move(id_), t, std::move(args), {}, std::move(m)));
    }

    auto global(ID id_, const QualifiedTypePtr& t, declaration::Linkage linkage = declaration::Linkage::Private,
                Meta m = Meta()) {
        return declarationGlobalVariable(std::move(id_), t, {}, linkage, std::move(m));
    }

    auto global(ID id_, const ExpressionPtr& init, declaration::Linkage linkage = declaration::Linkage::Private,
                const Meta& m = Meta()) {
        return declarationGlobalVariable(std::move(id_), init, linkage, m);
    }

    auto global(ID id_, const QualifiedTypePtr& t, ExpressionPtr init,
                declaration::Linkage linkage = declaration::Linkage::Private, Meta m = Meta()) {
        return declarationGlobalVariable(std::move(id_), t, std::move(init), linkage, std::move(m));
    }

    auto global(ID id_, const QualifiedTypePtr& t, Expressions args,
                declaration::Linkage linkage = declaration::Linkage::Private, Meta m = Meta()) {
        return declarationGlobalVariable(std::move(id_), t, std::move(args), {}, linkage, std::move(m));
    }

    auto type(ID id, const QualifiedTypePtr& type, declaration::Linkage linkage = declaration::Linkage::Private,
              Meta m = Meta()) {
        return declarationType(std::move(id), type, linkage, std::move(m));
    }

    auto type(ID id, const QualifiedTypePtr& type, AttributeSetPtr attrs,
              declaration::Linkage linkage = declaration::Linkage::Private, Meta m = Meta()) {
        return declarationType(std::move(id), type, std::move(attrs), linkage, std::move(m));
    }

    auto constant(ID id_, const ExpressionPtr& init, declaration::Linkage linkage = declaration::Linkage::Private,
                  Meta m = Meta()) {
        return declarationConstant(std::move(id_), init, linkage, std::move(m));
    }

    auto parameter(ID id, const UnqualifiedTypePtr& type, parameter::Kind kind = parameter::Kind::In, Meta m = Meta()) {
        return declarationParameter(std::move(id), type, kind, {}, {}, std::move(m));
    }

    auto parameter(ID id, const UnqualifiedTypePtr& type, const ExpressionPtr& default_,
                   parameter::Kind kind = parameter::Kind::In, Meta m = Meta()) {
        return declarationParameter(std::move(id), type, kind, default_, {}, std::move(m));
    }

    template<typename... Params>
    static auto parameters(Params&&... params) {
        return std::vector<hilti::type::function::ParameterPtr>{std::forward<Params>(params)...};
    }

    using NodeFactory::function;

    auto function(const ID& id, const QualifiedTypePtr& result, const declaration::Parameters& params,
                  type::function::Flavor flavor = type::function::Flavor::Standard,
                  declaration::Linkage linkage = declaration::Linkage::Private,
                  function::CallingConvention cc = function::CallingConvention::Standard,
                  const AttributeSetPtr& attrs = {}, const Meta& m = Meta()) {
        auto ft = typeFunction(result, params, flavor, m);
        auto f = function(id, ft, {}, cc, attrs, m);
        return declarationFunction(f, linkage, m);
    }

    auto function(const ID& id, const QualifiedTypePtr& result, const declaration::Parameters& params,
                  const StatementPtr& body, type::function::Flavor flavor = type::function::Flavor::Standard,
                  declaration::Linkage linkage = declaration::Linkage::Private,
                  function::CallingConvention cc = function::CallingConvention::Standard,
                  const AttributeSetPtr& attrs = {}, const Meta& m = Meta()) {
        auto ft = typeFunction(result, params, flavor, m);
        auto f = function(id, ft, body, cc, attrs, m);
        return declarationFunction(f, linkage, m);
    }

    auto function(const ID& id, const std::shared_ptr<type::Function>& ftype, const StatementPtr& body,
                  declaration::Linkage linkage = declaration::Linkage::Private,
                  function::CallingConvention cc = function::CallingConvention::Standard,
                  const AttributeSetPtr& attrs = {}, const Meta& m = Meta()) {
        auto f = function(id, ftype, body, cc, attrs, m);
        return declarationFunction(f, linkage, m);
    }

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

    auto default_(const UnqualifiedTypePtr& t, const Meta& m = Meta()) { return expressionCtor(ctorDefault(t, m), m); }

    auto default_(const UnqualifiedTypePtr& t, Expressions type_args, const Meta& m = Meta()) {
        return expressionCtor(ctorDefault(t, std::move(type_args), m), m);
    }

    auto exception(const UnqualifiedTypePtr& t, const std::string& msg, const Meta& m = Meta()) {
        return expressionCtor(ctorException(t, stringLiteral(msg), m), m);
    }

    auto exception(const UnqualifiedTypePtr& t, const ExpressionPtr& msg, const Meta& m = Meta()) {
        return expressionCtor(ctorException(t, msg, m), m);
    }

    auto exception(const UnqualifiedTypePtr& t, const ExpressionPtr& what, const ExpressionPtr& where,
                   const Meta& m = Meta()) {
        return expressionCtor(ctorException(t, what, where, m), m);
    }

    auto integer(int i, const Meta& m = Meta()) {
        return expressionCtor(ctorSignedInteger(static_cast<int64_t>(i), 64, m), m);
    }

    auto integer(int64_t i, const Meta& m = Meta()) { return expressionCtor(ctorSignedInteger(i, 64, m), m); }

    auto integer(unsigned int i, const Meta& m = Meta()) { return expressionCtor(ctorUnsignedInteger(i, 64, m), m); }

    auto integer(uint64_t i, const Meta& m = Meta()) { return expressionCtor(ctorUnsignedInteger(i, 64, m), m); }

    auto null(const Meta& m = Meta()) { return expressionCtor(ctorNull(m), m); }

    auto optional(const ExpressionPtr& e, const Meta& m = Meta()) { return expressionCtor(ctorOptional(e, m), m); }

    auto optional(const QualifiedTypePtr& t, const Meta& m = Meta()) { return expressionCtor(ctorOptional(t, m), m); }

    auto port(hilti::rt::Port p, const Meta& m = Meta()) { return expressionCtor(ctorPort(p, m), m); }

    auto regexp(std::string p, const AttributeSetPtr& attrs = {}, const Meta& m = Meta()) {
        return expressionCtor(ctorRegExp({std::move(p)}, attrs, m), m);
    }

    auto regexp(std::vector<std::string> p, const AttributeSetPtr& attrs = {}, const Meta& m = Meta()) {
        return expressionCtor(ctorRegExp(std::move(p), attrs, m), m);
    }

    auto stream(std::string s, const Meta& m = Meta()) { return expressionCtor(ctorStream(std::move(s), m), m); }

    auto struct_(ctor::struct_::Fields f, const Meta& m = Meta()) {
        return expressionCtor(ctorStruct(std::move(f), m), m);
    }

    auto struct_(ctor::struct_::Fields f, QualifiedTypePtr t, const Meta& m = Meta()) {
        return expressionCtor(ctorStruct(std::move(f), std::move(t), m), m);
    }

    auto tuple(const Expressions& v, const Meta& m = Meta()) { return expressionCtor(ctorTuple(v, m), m); }

    auto vector(const Expressions& v, const Meta& m = Meta()) { return expressionCtor(ctorVector(v, m), m); }

    auto vector(const QualifiedTypePtr& t, Expressions v, const Meta& m = Meta()) {
        return expressionCtor(ctorVector(t, std::move(v), m), m);
    }

    auto vector(const QualifiedTypePtr& t, const Meta& m = Meta()) { return expressionCtor(ctorVector(t, {}, m), m); }

    auto void_(const Meta& m = Meta()) { return expressionVoid(m); }

    auto strongReference(const QualifiedTypePtr& t, const Meta& m = Meta()) {
        return expressionCtor(ctorStrongReference(t, m), m);
    }

    auto weakReference(const QualifiedTypePtr& t, const Meta& m = Meta()) {
        return expressionCtor(ctorWeakReference(t, m), m);
    }

    auto valueReference(const ExpressionPtr& e, const Meta& m = Meta()) {
        return expressionCtor(ctorValueReference(e, m), m);
    }

    // Operator expressions

    auto and_(const ExpressionPtr& op0, const ExpressionPtr& op1, const Meta& m = Meta()) {
        return expressionLogicalAnd(op0, op1, m);
    }

    auto or_(const ExpressionPtr& op0, const ExpressionPtr& op1, const Meta& m = Meta()) {
        return expressionLogicalOr(op0, op1, m);
    }

    auto begin(ExpressionPtr e, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Begin, {std::move(e)}, m);
    }

    auto cast(ExpressionPtr e, const QualifiedTypePtr& dst, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Cast, {std::move(e), expressionType(dst)}, m);
    }

    auto delete_(ExpressionPtr self, const ID& field, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Delete, {std::move(self), expressionMember(field)}, m);
    }

    auto deref(ExpressionPtr e, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Deref, {std::move(e)}, m);
    }

    auto end(ExpressionPtr e, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::End, {std::move(e)}, m);
    }

    auto call(const ID& id_, const Expressions& v, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Call, {id(id_, m), tuple(v, m)}, m);
    }

    auto index(ExpressionPtr value, unsigned int index, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Index, {std::move(value), integer(index, m)}, m);
    }

    auto size(ExpressionPtr op, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Size, {std::move(op)}, m);
    }

    auto modulo(ExpressionPtr op1, ExpressionPtr op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Modulo, {std::move(op1), std::move(op2)}, m);
    }

    auto lowerEqual(ExpressionPtr op1, ExpressionPtr op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::LowerEqual, {std::move(op1), std::move(op2)}, m);
    }

    auto greaterEqual(ExpressionPtr op1, ExpressionPtr op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::GreaterEqual, {std::move(op1), std::move(op2)}, m);
    }

    auto lower(ExpressionPtr op1, ExpressionPtr op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Lower, {std::move(op1), std::move(op2)}, m);
    }

    auto greater(ExpressionPtr op1, ExpressionPtr op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Greater, {std::move(op1), std::move(op2)}, m);
    }

    auto equal(ExpressionPtr op1, ExpressionPtr op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Equal, {std::move(op1), std::move(op2)}, m);
    }

    auto unequal(ExpressionPtr op1, ExpressionPtr op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Unequal, {std::move(op1), std::move(op2)}, m);
    }

    auto member(ExpressionPtr self, std::string id_, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Member,
                                            {std::move(self), expressionMember(ID(std::move(id_)), m)}, m);
    }

    auto hasMember(ExpressionPtr self, std::string id_, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::HasMember,
                                            {std::move(self), expressionMember(ID(std::move(id_)), m)}, m);
    }

    auto tryMember(ExpressionPtr self, std::string id_, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::TryMember,
                                            {std::move(self), expressionMember(ID(std::move(id_)), m)}, m);
    }

    auto memberCall(ExpressionPtr self, std::string id_, const Expressions& args = {}, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::MemberCall,
                                            {std::move(self), expressionMember(ID(std::move(id_)), m), tuple(args, m)},
                                            m);
    }

    auto memberCall(ExpressionPtr self, std::string id_, std::shared_ptr<ctor::Tuple> args, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::MemberCall,
                                            {std::move(self), expressionMember(ID(std::move(id_)), m),
                                             expressionCtor(std::move(args))},
                                            m);
    }

    auto pack(const QualifiedTypePtr& type, const Expressions& args, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Pack, {expressionType(type, m), tuple(args, m)}, m);
    }

    auto unpack(const QualifiedTypePtr& type, const Expressions& args, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Unpack,
                                            {expressionType(type, m), tuple(args, m), expressionCtor(ctorBool(false))},
                                            m);
    }

    auto unset(ExpressionPtr self, const ID& field, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Unset, {std::move(self), expressionMember(field)}, m);
    }

    auto sumAssign(ExpressionPtr op1, ExpressionPtr op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::SumAssign, {std::move(op1), std::move(op2)}, m);
    }

    auto deferred(const ExpressionPtr& e, const Meta& m = Meta()) { return expressionDeferred(e, m); }

    auto differenceAssign(ExpressionPtr op1, ExpressionPtr op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::DifferenceAssign, {std::move(op1), std::move(op2)}, m);
    }

    auto sum(ExpressionPtr op1, ExpressionPtr op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Sum, {std::move(op1), std::move(op2)}, m);
    }

    auto difference(ExpressionPtr op1, ExpressionPtr op2, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Difference, {std::move(op1), std::move(op2)}, m);
    }

    auto decrementPostfix(ExpressionPtr op, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::DecrPostfix, {std::move(op)}, m);
    }

    auto decrementPrefix(ExpressionPtr op, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::DecrPrefix, {std::move(op)}, m);
    }

    auto incrementPostfix(ExpressionPtr op, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::IncrPostfix, {std::move(op)}, m);
    }

    auto incrementPrefix(ExpressionPtr op, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::IncrPrefix, {std::move(op)}, m);
    }

    auto new_(const UnqualifiedTypePtr& t, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::New,
                                            {expressionType(qualifiedType(t, hilti::Constness::Const), m),
                                             expressionCtor(ctorTuple({}, m))},
                                            m);
    }

    auto new_(const UnqualifiedTypePtr& t, const Expressions& args, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::New,
                                            {expressionType(qualifiedType(t, hilti::Constness::Const), m),
                                             expressionCtor(ctorTuple(args, m))},
                                            m);
    }

    // Other expressions

    auto expression(const CtorPtr& c, const Meta& m = Meta()) { return expressionCtor(c, m); }

    auto expression(const Location& l) { return stringLiteral(std::string(l)); }

    auto expression(const Meta& m) { return expression(m.location()); }

    auto grouping(const ExpressionPtr& e, const Meta& m = Meta()) { return expressionGrouping(e, m); }

    auto move(const ExpressionPtr& e, const Meta& m = Meta()) { return expressionMove(e, m); }

    auto typeinfo(const QualifiedTypePtr& t, const Meta& m = Meta()) {
        return expressionTypeInfo(expressionType(t, m), m);
    }

    auto typeinfo(const ExpressionPtr& e, const Meta& m = Meta()) { return expressionTypeInfo(e, m); }

    auto assign(const ExpressionPtr& target, const ExpressionPtr& src, const Meta& m = Meta()) {
        return expressionAssign(target, src, m);
    }

    auto not_(const ExpressionPtr& e, const Meta& m = Meta()) { return expressionLogicalNot(e, m); }

    auto ternary(const ExpressionPtr& cond, const ExpressionPtr& true_, const ExpressionPtr& false_,
                 const Meta& m = Meta()) {
        return expressionTernary(cond, true_, false_, m);
    }

    auto min(const ExpressionPtr& e1, const ExpressionPtr& e2, const Meta& m = Meta()) {
        return ternary(lowerEqual(e1, e2, m), e1, e2, m);
    }

    auto max(const ExpressionPtr& e1, const ExpressionPtr& e2, const Meta& m = Meta()) {
        return ternary(lowerEqual(e1, e2, m), e2, e1, m);
    }

    auto namedCtor(const std::string& name, const Expressions& args, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Call,
                                            {expressionMember(ID(name)), expressionCtor(ctorTuple(args))}, m);
    }

    auto scope(const Meta& m = Meta()) { return expressionKeyword(hilti::expression::keyword::Kind::Scope, m); }

    //////////// Variables and statements

    ExpressionPtr addTmp(const std::string& prefix, const ExpressionPtr& init);
    ExpressionPtr addTmp(const std::string& prefix, const QualifiedTypePtr& t, const Expressions& args = {});
    ExpressionPtr addTmp(const std::string& prefix, const QualifiedTypePtr& t, const ExpressionPtr& init);
    ExpressionPtr addTmp(const std::string& prefix, const UnqualifiedTypePtr& t, const Expressions& args = {}) {
        return addTmp(prefix, qualifiedType(t, Constness::Mutable), args);
    }
    ExpressionPtr addTmp(const std::string& prefix, const UnqualifiedTypePtr& t, const ExpressionPtr& init) {
        return addTmp(prefix, qualifiedType(t, Constness::Mutable), init);
    }

    void addLocal(ID id, const QualifiedTypePtr& t, Meta m = Meta()) {
        block()->_add(context(), local(std::move(id), t, std::move(m)));
    }

    void addLocal(ID id, ExpressionPtr init, const Meta& m = Meta()) {
        block()->_add(context(), local(std::move(id), std::move(init), m));
    }

    void addLocal(ID id, const QualifiedTypePtr& t, ExpressionPtr init, Meta m = Meta()) {
        block()->_add(context(), local(std::move(id), t, std::move(init), std::move(m)));
    }

    void addLocal(ID id, const QualifiedTypePtr& t, std::vector<hilti::ExpressionPtr> args, Meta m = Meta()) {
        block()->_add(context(), local(std::move(id), t, std::move(args), std::move(m)));
    }

    void addExpression(const ExpressionPtr& expr) { block()->_add(context(), statementExpression(expr, expr->meta())); }

    void addAssert(const ExpressionPtr& cond, std::string_view msg, Meta m = Meta()) {
        block()->_add(context(), statementAssert(cond, stringMutable(msg), std::move(m)));
    }

    void addAssign(const ExpressionPtr& dst, const ExpressionPtr& src, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(assign(dst, src, m), m));
    }

    void addSumAssign(ExpressionPtr dst, ExpressionPtr src, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(sumAssign(std::move(dst), std::move(src), m), m));
    }

    void addAssign(const ID& dst, const ExpressionPtr& src, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(assign(id(dst), src, m), m));
    }

    void addBreak(Meta m = Meta()) { block()->_add(context(), statementBreak(std::move(m))); }

    void addContinue(Meta m = Meta()) { block()->_add(context(), statementContinue(std::move(m))); }

    void addSumAssign(const ID& dst, ExpressionPtr src, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(sumAssign(id(dst), std::move(src), m), m));
    }

    void addCall(const ID& id, const Expressions& v, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(call(id, v, m), m));
    }

    void addMemberCall(ExpressionPtr self, const ID& id, const Expressions& v, const Meta& m = Meta()) {
        block()->_add(context(), statementExpression(memberCall(std::move(self), id, v, m), m));
    }

    void addComment(std::string comment,
                    hilti::statement::comment::Separator separator = hilti::statement::comment::Separator::Before,
                    const Meta& m = Meta()) {
        comment = util::replace(comment, "\n", "");
        block()->_add(context(), statementComment(std::move(comment), separator, m));
    }

    void addReturn(const ExpressionPtr& e, Meta m = Meta()) {
        block()->_add(context(), statementReturn(e, std::move(m)));
    }

    void addReturn(const CtorPtr& c, const Meta& m = Meta()) {
        block()->_add(context(), statementReturn(expressionCtor(c, m), m));
    }

    void addReturn(Meta m = Meta()) { block()->_add(context(), statementReturn(std::move(m))); }

    void addThrow(const ExpressionPtr& excpt, Meta m = Meta()) {
        block()->_add(context(), statementThrow(excpt, std::move(m)));
    }

    void addRethrow(Meta m = Meta()) { block()->_add(context(), statementThrow(std::move(m))); }

    void addDebugMsg(std::string_view stream, std::string_view fmt, Expressions args = {});
    void addDebugIndent(std::string_view stream);
    void addDebugDedent(std::string_view stream);

    void addPrint(const Expressions& exprs) { addCall("hilti::print", exprs); }
    void addPrint(const ExpressionPtr& expr) { addCall("hilti::print", {expr}); }

    void setLocation(const Location& l);

    bool empty() const { return block()->statements().empty() && _tmps().empty(); }

    std::optional<ExpressionPtr> startProfiler(std::string_view name);
    void stopProfiler(ExpressionPtr profiler);

protected:
    Builder(Builder* parent) : NodeFactory(parent->context()), _state(parent->_state) {}

private:
    struct State {
        std::shared_ptr<statement::Block> block;
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

    auto addWhile(const std::shared_ptr<statement::Declaration>& init, const ExpressionPtr& cond,
                  const Meta& m = Meta()) {
        auto body = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), Builder::statementWhile(init->declaration(), cond, body, {}, m));
        return _newBuilder(body);
    }

    auto addWhile(const ExpressionPtr& cond, const Meta& m = Meta()) {
        auto body = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), Builder::statementWhile(cond, body, {}, m));
        return _newBuilder(body);
    }

    auto addWhileElse(const std::shared_ptr<statement::Declaration>& init, const ExpressionPtr& cond,
                      const Meta& m = Meta()) {
        auto body = Builder::statementBlock();
        auto else_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), statementWhile(init->declaration(), cond, body, else_, m));
        return std::make_pair(_newBuilder(body), _newBuilder(else_));
    }

    auto addWhileElse(const ExpressionPtr& cond, const Meta& m = Meta()) {
        auto body = Builder::statementBlock();
        auto else_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), statementWhile(cond, body, else_, m));
        return std::make_pair(_newBuilder(body), _newBuilder(else_));
    }

    auto addIf(const std::shared_ptr<statement::Declaration>& init, const ExpressionPtr& cond, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(),
                               Builder::statementIf(init->declaration(), cond, true_, {}, std::move(m)));
        return _newBuilder(true_);
    }

    auto addIf(const std::shared_ptr<statement::Declaration>& init, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), statementIf(init->declaration(), {}, true_, {}, std::move(m)));
        return _newBuilder(true_);
    }

    auto addIf(const ExpressionPtr& cond, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), Builder::statementIf(cond, true_, {}, std::move(m)));
        return _newBuilder(true_);
    }

    auto addIfElse(const std::shared_ptr<statement::Declaration>& init, const ExpressionPtr& cond, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        auto false_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(),
                               Builder::statementIf(init->declaration(), cond, true_, false_, std::move(m)));
        return std::make_pair(_newBuilder(true_), _newBuilder(false_));
    }

    auto addIfElse(const std::shared_ptr<statement::Declaration>& init, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        auto false_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), statementIf(init->declaration(), {}, true_, false_, std::move(m)));
        return std::make_pair(_newBuilder(true_), _newBuilder(false_));
    }

    auto addIfElse(const ExpressionPtr& cond, Meta m = Meta()) {
        auto true_ = Builder::statementBlock();
        auto false_ = Builder::statementBlock();
        Builder::block()->_add(Builder::context(), Builder::statementIf(cond, true_, false_, std::move(m)));
        return std::make_pair(_newBuilder(true_), _newBuilder(false_));
    }

    auto newBlock(Meta m = Meta()) {
        auto body = Builder::statementBlock(std::move(m));
        return _newBuilder(body);
    }

    auto addBlock(Meta m = Meta()) {
        auto body = Builder::statementBlock(std::move(m));
        Builder::block()->_add(Builder::context(), body);
        return _newBuilder(body);
    }

    class SwitchProxy {
    public:
        SwitchProxy(ExtendedBuilderTemplate* b, std::shared_ptr<statement::Switch> s)
            : _builder(b), _switch(std::move(s)) {}

        auto addCase(ExpressionPtr expr, const Meta& m = Meta()) { return _addCase({std::move(expr)}, m); }

        auto addCase(const Expressions& exprs, const Meta& m = Meta()) { return _addCase(exprs, m); }

        auto addDefault(const Meta& m = Meta()) { return _addCase({}, m); }

    private:
        std::shared_ptr<ExtendedBuilderTemplate> _addCase(const Expressions& exprs, const Meta& m = Meta()) {
            auto body = _builder->statementBlock(m);
            _switch->addCase(_builder->context(), _builder->statementSwitchCase(exprs, body, m));
            return _builder->_newBuilder(body);
        }

        ExtendedBuilderTemplate* _builder;
        std::shared_ptr<statement::Switch> _switch;
    };

    auto addSwitch(const ExpressionPtr& cond, Meta m = Meta()) {
        auto switch_ = Builder::statementSwitch(cond, {}, std::move(m));
        Builder::block()->_add(Builder::context(), switch_);
        return SwitchProxy(this, switch_);
    }

    auto addSwitch(const std::shared_ptr<statement::Declaration>& cond, Meta m = Meta()) {
        auto switch_ = Builder::statementSwitch(cond->declaration(), {}, std::move(m));
        Builder::block()->_add(Builder::context(), switch_);
        return SwitchProxy(this, switch_);
    }

    class TryProxy {
    public:
        TryProxy(ExtendedBuilderTemplate* b, std::shared_ptr<statement::Try> s) : _builder(b), _try(std::move(s)) {}

        auto addCatch(const declaration::ParameterPtr& p, const Meta& m = Meta()) {
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
        std::shared_ptr<statement::Try> _try;
    };

    auto addTry(Meta m = Meta()) {
        auto body = Builder::statementBlock();
        auto try_ = Builder::statementTry(body, {}, std::move(m));
        Builder::block()->_add(Builder::context(), try_);
        return std::make_pair(_newBuilder(body), TryProxy(this, try_));
    }

private:
    std::shared_ptr<ExtendedBuilderTemplate> _newBuilder(std::shared_ptr<statement::Block> block) {
        return std::make_shared<ExtendedBuilderTemplate>(Builder::context(), block);
    }
};

using BuilderPtr = std::shared_ptr<Builder>;

} // namespace hilti
