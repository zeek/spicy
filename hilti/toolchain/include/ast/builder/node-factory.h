// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/all.h>
#include <hilti/ast/ast-context.h>
#include <hilti/ast/types/function.h>

namespace hilti::builder {

/** Base class making node factory methods available. */
class NodeFactory {
public:
    /**
     * Constructor.
     *
     * @param context AST context to use for creating nodes.
     */
    NodeFactory(ASTContext* context) : _context(context) {}

    /** Returns the AST context in use for creating nodes. */
    ASTContext* context() const { return _context; }

    auto attribute(const hilti::attribute::Kind& kind, Expression* v, const Meta& m = Meta()) {
        return hilti::Attribute::create(context(), kind, v, m);
    }
    auto attribute(const hilti::attribute::Kind& kind, const Meta& m = Meta()) {
        return hilti::Attribute::create(context(), kind, m);
    }
    auto attributeSet(const Attributes& attrs = {}, Meta m = Meta()) {
        return hilti::AttributeSet::create(context(), attrs, std::move(m));
    }
    auto ctorAddress(hilti::rt::Address v, const Meta& meta = {}) {
        return hilti::ctor::Address::create(context(), v, meta);
    }
    auto ctorBitfield(const ctor::bitfield::BitRanges& bits, QualifiedType* type, const Meta& m = Meta()) {
        return hilti::ctor::Bitfield::create(context(), bits, type, m);
    }
    auto ctorBitfieldBitRange(const ID& id, Expression* expr, Meta meta = Meta()) {
        return hilti::ctor::bitfield::BitRange::create(context(), id, expr, std::move(meta));
    }
    auto ctorBool(bool v, const Meta& meta = {}) { return hilti::ctor::Bool::create(context(), v, meta); }
    auto ctorBytes(std::string value, const Meta& meta = {}) {
        return hilti::ctor::Bytes::create(context(), std::move(value), meta);
    }
    auto ctorCoerced(Ctor* orig, Ctor* new_, Meta meta = {}) {
        return hilti::ctor::Coerced::create(context(), orig, new_, std::move(meta));
    }
    auto ctorDefault(UnqualifiedType* type, const Expressions& type_args, const Meta& meta = {}) {
        return hilti::ctor::Default::create(context(), type, type_args, meta);
    }
    auto ctorDefault(UnqualifiedType* type, const Meta& meta = {}) {
        return hilti::ctor::Default::create(context(), type, meta);
    }
    auto ctorEnum(type::enum_::Label* label, const Meta& meta = {}) {
        return hilti::ctor::Enum::create(context(), label, meta);
    }
    auto ctorError(std::string v, const Meta& meta = {}) {
        return hilti::ctor::Error::create(context(), std::move(v), meta);
    }
    auto ctorException(UnqualifiedType* type, Expression* value, Expression* location, const Meta& meta = {}) {
        return hilti::ctor::Exception::create(context(), type, value, location, meta);
    }
    auto ctorException(UnqualifiedType* type, Expression* value, const Meta& meta = {}) {
        return hilti::ctor::Exception::create(context(), type, value, meta);
    }
    auto ctorInterval(hilti::rt::Interval v, const Meta& meta = {}) {
        return hilti::ctor::Interval::create(context(), v, meta);
    }
    auto ctorLibrary(Ctor* ctor, QualifiedType* type, const Meta& meta = {}) {
        return hilti::ctor::Library::create(context(), ctor, type, meta);
    }
    auto ctorList(const Expressions& exprs, Meta meta = {}) {
        return hilti::ctor::List::create(context(), exprs, std::move(meta));
    }
    auto ctorList(QualifiedType* etype, const Expressions& exprs, Meta meta = {}) {
        return hilti::ctor::List::create(context(), etype, exprs, std::move(meta));
    }
    auto ctorMap(QualifiedType* key, QualifiedType* value, const ctor::map::Elements& elements, Meta meta = {}) {
        return hilti::ctor::Map::create(context(), key, value, elements, std::move(meta));
    }
    auto ctorMap(const ctor::map::Elements& elements, Meta meta = {}) {
        return hilti::ctor::Map::create(context(), elements, std::move(meta));
    }
    auto ctorMapElement(Expression* key, Expression* value, Meta meta = {}) {
        return hilti::ctor::map::Element::create(context(), key, value, std::move(meta));
    }
    auto ctorNetwork(hilti::rt::Network v, const Meta& meta = {}) {
        return hilti::ctor::Network::create(context(), v, meta);
    }
    auto ctorNull(const Meta& meta = {}) { return hilti::ctor::Null::create(context(), meta); }
    auto ctorOptional(Expression* expr, const Meta& meta = {}) {
        return hilti::ctor::Optional::create(context(), expr, meta);
    }
    auto ctorOptional(QualifiedType* type, const Meta& meta = {}) {
        return hilti::ctor::Optional::create(context(), type, meta);
    }
    auto ctorPort(hilti::rt::Port v, const Meta& meta = {}) { return hilti::ctor::Port::create(context(), v, meta); }
    auto ctorReal(double v, const Meta& meta = {}) { return hilti::ctor::Real::create(context(), v, meta); }
    auto ctorRegExp(hilti::ctor::regexp::Patterns v, AttributeSet* attrs = nullptr, const Meta& meta = {}) {
        return hilti::ctor::RegExp::create(context(), std::move(v), attrs, meta);
    }
    auto ctorResult(Expression* expr, const Meta& meta = {}) {
        return hilti::ctor::Result::create(context(), expr, meta);
    }
    auto ctorResult(QualifiedType* type, const Meta& meta = {}) {
        return hilti::ctor::Result::create(context(), type, meta);
    }
    auto ctorSet(const Expressions& exprs, Meta meta = {}) {
        return hilti::ctor::Set::create(context(), exprs, std::move(meta));
    }
    auto ctorSet(QualifiedType* etype, const Expressions& exprs, Meta meta = {}) {
        return hilti::ctor::Set::create(context(), etype, exprs, std::move(meta));
    }
    auto ctorSignedInteger(int64_t value, unsigned int width, const Meta& meta = {}) {
        return hilti::ctor::SignedInteger::create(context(), value, width, meta);
    }
    auto ctorStream(std::string value, const Meta& meta = {}) {
        return hilti::ctor::Stream::create(context(), std::move(value), meta);
    }
    auto ctorString(std::string value, bool is_literal, const Meta& meta = {}) {
        return hilti::ctor::String::create(context(), std::move(value), is_literal, meta);
    }
    auto ctorStrongReference(QualifiedType* t, const Meta& meta = {}) {
        return hilti::ctor::StrongReference::create(context(), t, meta);
    }
    auto ctorStruct(const ctor::struct_::Fields& fields, QualifiedType* t, Meta meta = {}) {
        return hilti::ctor::Struct::create(context(), fields, t, std::move(meta));
    }
    auto ctorStruct(const ctor::struct_::Fields& fields, const Meta& meta = {}) {
        return hilti::ctor::Struct::create(context(), fields, meta);
    }
    auto ctorStructField(ID id, Expression* expr, Meta meta = {}) {
        return hilti::ctor::struct_::Field::create(context(), std::move(id), expr, std::move(meta));
    }
    auto ctorTime(hilti::rt::Time v, const Meta& meta = {}) { return hilti::ctor::Time::create(context(), v, meta); }
    auto ctorTuple(const Expressions& exprs, Meta meta = {}) {
        return hilti::ctor::Tuple::create(context(), exprs, std::move(meta));
    }
    auto ctorUnion(QualifiedType* type, Expression* value, Meta meta = {}) {
        return hilti::ctor::Union::create(context(), type, value, std::move(meta));
    }
    auto ctorUnsignedInteger(uint64_t value, unsigned int width, const Meta& meta = {}) {
        return hilti::ctor::UnsignedInteger::create(context(), value, width, meta);
    }
    auto ctorUnsignedInteger(uint64_t value, unsigned int width, UnqualifiedType* t, Meta meta = {}) {
        return hilti::ctor::UnsignedInteger::create(context(), value, width, t, std::move(meta));
    }
    auto ctorValueReference(Expression* expr, Meta meta = {}) {
        return hilti::ctor::ValueReference::create(context(), expr, std::move(meta));
    }
    auto ctorVector(const Expressions& exprs, Meta meta = {}) {
        return hilti::ctor::Vector::create(context(), exprs, std::move(meta));
    }
    auto ctorVector(QualifiedType* etype, const Expressions& exprs, Meta meta = {}) {
        return hilti::ctor::Vector::create(context(), etype, exprs, std::move(meta));
    }
    auto ctorWeakReference(QualifiedType* t, const Meta& meta = {}) {
        return hilti::ctor::WeakReference::create(context(), t, meta);
    }
    auto declarationConstant(ID id, Expression* value, declaration::Linkage linkage = declaration::Linkage::Private,
                             Meta meta = {}) {
        return hilti::declaration::Constant::create(context(), std::move(id), value, linkage, std::move(meta));
    }
    auto declarationConstant(ID id, QualifiedType* type, Expression* value,
                             declaration::Linkage linkage = declaration::Linkage::Private, Meta meta = {}) {
        return hilti::declaration::Constant::create(context(), std::move(id), type, value, linkage, std::move(meta));
    }
    auto declarationExpression(ID id, Expression* expr, declaration::Linkage linkage, Meta meta = {}) {
        return hilti::declaration::Expression::create(context(), std::move(id), expr, linkage, std::move(meta));
    }
    auto declarationField(ID id, type::Function* ftype, AttributeSet* attrs, Meta meta = {}) {
        return hilti::declaration::Field::create(context(), std::move(id), ftype, attrs, std::move(meta));
    }
    auto declarationField(ID id, QualifiedType* type, AttributeSet* attrs, Meta meta = {}) {
        return hilti::declaration::Field::create(context(), std::move(id), type, attrs, std::move(meta));
    }
    auto declarationField(const ID& id, Function* inline_func, AttributeSet* attrs, Meta meta = {}) {
        return hilti::declaration::Field::create(context(), id, inline_func, attrs, std::move(meta));
    }
    auto declarationFunction(hilti::Function* function, declaration::Linkage linkage = declaration::Linkage::Private,
                             Meta meta = {}) {
        return hilti::declaration::Function::create(context(), function, linkage, std::move(meta));
    }
    auto declarationGlobalVariable(ID id, Expression* init,
                                   declaration::Linkage linkage = declaration::Linkage::Private,
                                   const Meta& meta = {}) {
        return hilti::declaration::GlobalVariable::create(context(), std::move(id), init, linkage, meta);
    }
    auto declarationGlobalVariable(ID id, QualifiedType* type, Expression* init = nullptr,
                                   declaration::Linkage linkage = declaration::Linkage::Private, Meta meta = {}) {
        return hilti::declaration::GlobalVariable::create(context(), std::move(id), type, init, linkage,
                                                          std::move(meta));
    }
    auto declarationGlobalVariable(ID id, QualifiedType* type, Expressions args, Expression* init = nullptr,
                                   declaration::Linkage linkage = declaration::Linkage::Private, Meta meta = {}) {
        return hilti::declaration::GlobalVariable::create(context(), std::move(id), type, std::move(args), init,
                                                          linkage, std::move(meta));
    }
    auto declarationGlobalVariable(ID id, QualifiedType* type,
                                   declaration::Linkage linkage = declaration::Linkage::Private, Meta meta = {}) {
        return hilti::declaration::GlobalVariable::create(context(), std::move(id), type, linkage, std::move(meta));
    }
    auto declarationGlobalVariable(ID id, declaration::Linkage linkage = declaration::Linkage::Private,
                                   const Meta& meta = {}) {
        return hilti::declaration::GlobalVariable::create(context(), std::move(id), linkage, meta);
    }
    auto declarationImportedModule(ID id, const std::string& parse_extension, ID search_scope, Meta meta = {}) {
        return hilti::declaration::ImportedModule::create(context(), std::move(id), parse_extension,
                                                          std::move(search_scope), std::move(meta));
    }
    auto declarationImportedModule(ID id, const std::string& parse_extension, Meta meta = {}) {
        return hilti::declaration::ImportedModule::create(context(), std::move(id), parse_extension, std::move(meta));
    }
    auto declarationImportedModule(ID id, hilti::rt::filesystem::path path, Meta meta = {}) {
        return hilti::declaration::ImportedModule::create(context(), std::move(id), std::move(path), std::move(meta));
    }
    auto declarationLocalVariable(ID id, Expression* init, const Meta& meta = {}) {
        return hilti::declaration::LocalVariable::create(context(), std::move(id), init, meta);
    }
    auto declarationLocalVariable(ID id, const Meta& meta = {}) {
        return hilti::declaration::LocalVariable::create(context(), std::move(id), meta);
    }
    auto declarationLocalVariable(ID id, QualifiedType* type, Expression* init, Meta meta = {}) {
        return hilti::declaration::LocalVariable::create(context(), std::move(id), type, init, std::move(meta));
    }
    auto declarationLocalVariable(ID id, QualifiedType* type, Expressions args, Expression* init = nullptr,
                                  Meta meta = {}) {
        return hilti::declaration::LocalVariable::create(context(), std::move(id), type, std::move(args), init,
                                                         std::move(meta));
    }
    auto declarationLocalVariable(ID id, QualifiedType* type, Meta meta = {}) {
        return hilti::declaration::LocalVariable::create(context(), std::move(id), type, std::move(meta));
    }
    auto declarationModule(const declaration::module::UID& uid, const ID& scope = {}, Meta meta = {}) {
        return hilti::declaration::Module::create(context(), uid, scope, std::move(meta));
    }
    auto declarationModule(const declaration::module::UID& uid, const ID& scope, const Declarations& decls,
                           const Statements& stmts, Meta meta = {}) {
        return hilti::declaration::Module::create(context(), uid, scope, decls, stmts, std::move(meta));
    }
    auto declarationModule(const declaration::module::UID& uid, const ID& scope, const Declarations& decls,
                           Meta meta = {}) {
        return hilti::declaration::Module::create(context(), uid, scope, decls, std::move(meta));
    }
    auto declarationParameter(ID id, UnqualifiedType* type, parameter::Kind kind, hilti::Expression* default_,
                              AttributeSet* attrs, Meta meta = {}) {
        return hilti::declaration::Parameter::create(context(), std::move(id), type, kind, default_, attrs,
                                                     std::move(meta));
    }
    auto declarationParameter(ID id, UnqualifiedType* type, parameter::Kind kind, hilti::Expression* default_,
                              bool is_type_param, AttributeSet* attrs, Meta meta = {}) {
        return hilti::declaration::Parameter::create(context(), std::move(id), type, kind, default_, is_type_param,
                                                     attrs, std::move(meta));
    }
    auto declarationProperty(ID id, Meta meta = {}) {
        return hilti::declaration::Property::create(context(), std::move(id), std::move(meta));
    }
    auto declarationProperty(ID id, Expression* expr, Meta meta = {}) {
        return hilti::declaration::Property::create(context(), std::move(id), expr, std::move(meta));
    }
    auto declarationType(ID id, QualifiedType* type, AttributeSet* attrs,
                         declaration::Linkage linkage = declaration::Linkage::Private, Meta meta = {}) {
        return hilti::declaration::Type::create(context(), std::move(id), type, attrs, linkage, std::move(meta));
    }
    auto declarationType(ID id, QualifiedType* type, declaration::Linkage linkage = declaration::Linkage::Private,
                         Meta meta = {}) {
        return hilti::declaration::Type::create(context(), std::move(id), type, linkage, std::move(meta));
    }
    auto expressionAssign(Expression* target, Expression* src, Meta meta = {}) {
        return hilti::expression::Assign::create(context(), target, src, std::move(meta));
    }
    auto expressionBuiltInFunction(const std::string& name, const std::string& cxxname, QualifiedType* type,
                                   const type::function::Parameters& parameters, const Expressions& arguments,
                                   Meta meta = {}) {
        return hilti::expression::BuiltInFunction::create(context(), name, cxxname, type, parameters, arguments,
                                                          std::move(meta));
    }
    auto expressionCoerced(Expression* expr, QualifiedType* target, Meta meta = {}) {
        return hilti::expression::Coerced::create(context(), expr, target, std::move(meta));
    }
    auto expressionCtor(Ctor* ctor, Meta meta = {}) {
        return hilti::expression::Ctor::create(context(), ctor, std::move(meta));
    }
    auto expressionGrouping(Expression* expr, Meta meta = {}) {
        return hilti::expression::Grouping::create(context(), expr, std::move(meta));
    }
    auto expressionKeyword(expression::keyword::Kind kind, const Meta& meta = {}) {
        return hilti::expression::Keyword::create(context(), kind, meta);
    }
    auto expressionKeyword(expression::keyword::Kind kind, QualifiedType* type, Meta meta = {}) {
        return hilti::expression::Keyword::create(context(), kind, type, std::move(meta));
    }
    auto expressionListComprehension(Expression* input, Expression* output, const ID& id, Expression* cond,
                                     Meta meta = {}) {
        return hilti::expression::ListComprehension::create(context(), input, output, id, cond, std::move(meta));
    }
    auto expressionLogicalAnd(Expression* op0, Expression* op1, const Meta& meta = {}) {
        return hilti::expression::LogicalAnd::create(context(), op0, op1, meta);
    }
    auto expressionLogicalNot(Expression* expression, const Meta& meta = {}) {
        return hilti::expression::LogicalNot::create(context(), expression, meta);
    }
    auto expressionLogicalOr(Expression* op0, Expression* op1, const Meta& meta = {}) {
        return hilti::expression::LogicalOr::create(context(), op0, op1, meta);
    }
    auto expressionMember(QualifiedType* member_type, const hilti::ID& id, Meta meta = {}) {
        return hilti::expression::Member::create(context(), member_type, id, std::move(meta));
    }
    auto expressionMember(const hilti::ID& id, const Meta& meta = {}) {
        return hilti::expression::Member::create(context(), id, meta);
    }
    auto expressionMove(Expression* expression, Meta meta = {}) {
        return hilti::expression::Move::create(context(), expression, std::move(meta));
    }
    auto expressionName(const hilti::ID& id, const Meta& meta = {}) {
        return hilti::expression::Name::create(context(), id, meta);
    }
    auto expressionConditionTest(Expression* cond, Expression* error, Meta meta = {}) {
        return hilti::expression::ConditionTest::create(context(), cond, error, std::move(meta));
    }
    auto expressionPendingCoerced(Expression* expr, QualifiedType* type, Meta meta = {}) {
        return hilti::expression::PendingCoerced::create(context(), expr, type, std::move(meta));
    }
    auto expressionTernary(Expression* cond, Expression* true_, Expression* false_, Meta meta = {}) {
        return hilti::expression::Ternary::create(context(), cond, true_, false_, std::move(meta));
    }
    auto expressionType(QualifiedType* type, const Meta& meta = {}) {
        return hilti::expression::Type_::create(context(), type, meta);
    }
    auto expressionTypeInfo(Expression* expr, Meta meta = {}) {
        return hilti::expression::TypeInfo::create(context(), expr, std::move(meta));
    }
    auto expressionTypeWrapped(Expression* expr, QualifiedType* type, Meta meta = {}) {
        return hilti::expression::TypeWrapped::create(context(), expr, type, std::move(meta));
    }
    auto expressionUnresolvedOperator(operator_::Kind kind, Expressions operands, const Meta& meta = {}) {
        return hilti::expression::UnresolvedOperator::create(context(), kind, std::move(operands), meta);
    }
    auto expressionUnresolvedOperator(operator_::Kind kind, hilti::node::Range<Expression> operands,
                                      const Meta& meta = {}) {
        return hilti::expression::UnresolvedOperator::create(context(), kind, operands, meta);
    }
    auto expressionVoid(const Meta& meta = {}) { return hilti::expression::Void::create(context(), meta); }
    auto function(const ID& id, type::Function* ftype, statement::Block* body, AttributeSet* attrs = nullptr,
                  const Meta& meta = {}) {
        return hilti::Function::create(context(), id, ftype, body, attrs, meta);
    }
    auto qualifiedType(UnqualifiedType* t, Constness const_, Meta m = Meta()) {
        return hilti::QualifiedType::create(context(), t, const_, std::move(m));
    }
    auto qualifiedType(UnqualifiedType* t, Constness const_, Side side, const Meta& m = Meta()) {
        return hilti::QualifiedType::create(context(), t, const_, side, m);
    }
    auto statementAssert(Expression* expr, Expression* msg = nullptr, Meta meta = {}) {
        return hilti::statement::Assert::create(context(), expr, msg, std::move(meta));
    }
    auto statementAssert(statement::assert::Exception /* except */, Expression* expr, UnqualifiedType* except,
                         Expression* msg = nullptr, Meta meta = {}) {
        return hilti::statement::Assert::create(context(), statement::assert::Exception{}, expr, except, msg,
                                                std::move(meta));
    }
    auto statementBlock(const Meta& meta = {}) { return hilti::statement::Block::create(context(), meta); }
    auto statementBlock(const Statements& stmts, Meta meta = {}) {
        return hilti::statement::Block::create(context(), stmts, std::move(meta));
    }
    auto statementBreak(Meta meta = {}) { return hilti::statement::Break::create(context(), std::move(meta)); }
    auto statementComment(std::string comment,
                          statement::comment::Separator separator = statement::comment::Separator::Before,
                          Meta meta = {}) {
        return hilti::statement::Comment::create(context(), std::move(comment), separator, std::move(meta));
    }
    auto statementContinue(Meta meta = {}) { return hilti::statement::Continue::create(context(), std::move(meta)); }
    auto statementDeclaration(hilti::Declaration* d, Meta meta = {}) {
        return hilti::statement::Declaration::create(context(), d, std::move(meta));
    }
    auto statementExpression(Expression* e, Meta meta = {}) {
        return hilti::statement::Expression::create(context(), e, std::move(meta));
    }
    auto statementFor(const hilti::ID& id, Expression* seq, Statement* body, Meta meta = {}) {
        return hilti::statement::For::create(context(), id, seq, body, std::move(meta));
    }
    auto statementIf(Declaration* init, Expression* cond, Statement* true_, Statement* false_, Meta meta = {}) {
        return hilti::statement::If::create(context(), init, cond, true_, false_, std::move(meta));
    }
    auto statementIf(Expression* cond, Statement* true_, Statement* false_, Meta meta = {}) {
        return hilti::statement::If::create(context(), cond, true_, false_, std::move(meta));
    }
    auto statementReturn(Meta meta = {}) { return hilti::statement::Return::create(context(), std::move(meta)); }
    auto statementReturn(Expression* expr, Meta meta = {}) {
        return hilti::statement::Return::create(context(), expr, std::move(meta));
    }
    auto statementSetLocation(Expression* expr, Meta meta = {}) {
        return hilti::statement::SetLocation::create(context(), expr, std::move(meta));
    }
    auto statementSwitch(Declaration* cond, const statement::switch_::Cases& cases, Meta meta = {}) {
        return hilti::statement::Switch::create(context(), cond, cases, std::move(meta));
    }
    auto statementSwitch(Expression* cond, const statement::switch_::Cases& cases, Meta meta = {}) {
        return hilti::statement::Switch::create(context(), cond, cases, std::move(meta));
    }
    auto statementSwitchCase(Expression* expr, Statement* body, Meta meta = {}) {
        return hilti::statement::switch_::Case::create(context(), expr, body, std::move(meta));
    }
    auto statementSwitchCase(const Expressions& exprs, Statement* body, Meta meta = {}) {
        return hilti::statement::switch_::Case::create(context(), exprs, body, std::move(meta));
    }
    auto statementSwitchCase(statement::switch_::Default /* default */, Statement* body, Meta meta = {}) {
        return hilti::statement::switch_::Case::create(context(), statement::switch_::Default{}, body, std::move(meta));
    }
    auto statementThrow(Meta meta = {}) { return hilti::statement::Throw::create(context(), std::move(meta)); }
    auto statementThrow(Expression* expr, Meta meta = {}) {
        return hilti::statement::Throw::create(context(), expr, std::move(meta));
    }
    auto statementTry(Statement* body, const statement::try_::Catches& catches, Meta meta = {}) {
        return hilti::statement::Try::create(context(), body, catches, std::move(meta));
    }
    auto statementTryCatch(Declaration* param, Statement* body, Meta meta = {}) {
        return hilti::statement::try_::Catch::create(context(), param, body, std::move(meta));
    }
    auto statementTryCatch(Statement* body, Meta meta = {}) {
        return hilti::statement::try_::Catch::create(context(), body, std::move(meta));
    }
    auto statementWhile(Declaration* init, Expression* cond, Statement* body, Statement* else_ = nullptr,
                        Meta meta = {}) {
        return hilti::statement::While::create(context(), init, cond, body, else_, std::move(meta));
    }
    auto statementWhile(Expression* cond, Statement* body, Meta meta = {}) {
        return hilti::statement::While::create(context(), cond, body, std::move(meta));
    }
    auto statementWhile(Expression* cond, Statement* body, Statement* else_ = nullptr, Meta meta = {}) {
        return hilti::statement::While::create(context(), cond, body, else_, std::move(meta));
    }
    auto statementYield(Meta meta = {}) { return hilti::statement::Yield::create(context(), std::move(meta)); }
    auto typeAddress(const Meta& m = Meta()) { return hilti::type::Address::create(context(), m); }
    auto typeAny(Meta m = Meta()) { return hilti::type::Any::create(context(), std::move(m)); }
    auto typeAuto(const Meta& m = Meta()) { return hilti::type::Auto::create(context(), m); }
    auto typeBitfield(int width, const type::bitfield::BitRanges& bits, AttributeSet* attrs, const Meta& m = Meta()) {
        return hilti::type::Bitfield::create(context(), width, bits, attrs, m);
    }
    auto typeBitfield(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::Bitfield::create(context(), _, m);
    }
    auto typeBitfieldBitRange(const ID& id, int lower, int upper, int field_width, AttributeSet* attrs = {},
                              Expression* ctor_value = nullptr, Meta meta = Meta()) {
        return hilti::type::bitfield::BitRange::create(context(), id, lower, upper, field_width, attrs, ctor_value,
                                                       std::move(meta));
    }
    auto typeBitfieldBitRange(const ID& id, int lower, int upper, int field_width, AttributeSet* attrs = {},
                              Meta meta = Meta()) {
        return hilti::type::bitfield::BitRange::create(context(), id, lower, upper, field_width, attrs,
                                                       std::move(meta));
    }
    auto typeBool(Meta meta = {}) { return hilti::type::Bool::create(context(), std::move(meta)); }
    auto typeBytes(const Meta& meta = {}) { return hilti::type::Bytes::create(context(), meta); }
    auto typeBytesIterator(Meta meta = {}) { return hilti::type::bytes::Iterator::create(context(), std::move(meta)); }
    auto typeDocOnly(const std::string& description, Meta meta = {}) {
        return hilti::type::DocOnly::create(context(), description, std::move(meta));
    }
    auto typeEnum(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Enum::create(context(), _, m); }
    auto typeEnum(type::enum_::Labels labels, Meta meta = {}) {
        return hilti::type::Enum::create(context(), std::move(labels), std::move(meta));
    }
    auto typeEnumLabel(const ID& id, Meta meta = {}) {
        return hilti::type::enum_::Label::create(context(), id, std::move(meta));
    }
    auto typeEnumLabel(const ID& id, int value, Meta meta = {}) {
        return hilti::type::enum_::Label::create(context(), id, value, std::move(meta));
    }
    auto typeError(Meta meta = {}) { return hilti::type::Error::create(context(), std::move(meta)); }
    auto typeException(Meta meta = {}) { return hilti::type::Exception::create(context(), std::move(meta)); }
    auto typeException(UnqualifiedType* base, Meta meta = {}) {
        return hilti::type::Exception::create(context(), base, std::move(meta));
    }
    auto typeException(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::Exception::create(context(), _, m);
    }
    auto typeFunction(QualifiedType* result, const declaration::Parameters& params,
                      type::function::Flavor flavor = type::function::Flavor::Function,
                      type::function::CallingConvention cc = type::function::CallingConvention::Standard,
                      Meta meta = {}) {
        return hilti::type::Function::create(context(), result, params, flavor, cc, std::move(meta));
    }
    auto typeFunction(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::Function::create(context(), _, m);
    }
    auto typeInterval(Meta meta = {}) { return hilti::type::Interval::create(context(), std::move(meta)); }
    auto typeLibrary(std::string cxx_name, Meta meta = {}) {
        return hilti::type::Library::create(context(), Constness::Mutable, std::move(cxx_name), std::move(meta));
    }
    auto typeLibrary(Constness const_, std::string cxx_name, Meta meta = {}) {
        return hilti::type::Library::create(context(), const_, std::move(cxx_name), std::move(meta));
    }
    auto typeList(QualifiedType* t, const Meta& meta = {}) { return hilti::type::List::create(context(), t, meta); }
    auto typeList(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::List::create(context(), _, m); }
    auto typeListIterator(QualifiedType* etype, Meta meta = {}) {
        return hilti::type::list::Iterator::create(context(), etype, std::move(meta));
    }
    auto typeListIterator(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::list::Iterator::create(context(), _, m);
    }
    auto typeMap(QualifiedType* ktype, QualifiedType* vtype, const Meta& meta = {}) {
        return hilti::type::Map::create(context(), ktype, vtype, meta);
    }
    auto typeMap(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Map::create(context(), _, m); }
    auto typeMapIterator(QualifiedType* ktype, QualifiedType* vtype, const Meta& meta = {}) {
        return hilti::type::map::Iterator::create(context(), ktype, vtype, meta);
    }
    auto typeMapIterator(type::Wildcard _, const Meta& meta = Meta()) {
        return hilti::type::map::Iterator::create(context(), _, meta);
    }
    auto typeMember(const ID& id, Meta meta = {}) {
        return hilti::type::Member::create(context(), id, std::move(meta));
    }
    auto typeMember(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Member::create(context(), _, m); }
    auto typeName(const ID& id, Meta meta = {}) { return hilti::type::Name::create(context(), id, std::move(meta)); }
    auto typeNetwork(Meta meta = {}) { return hilti::type::Network::create(context(), std::move(meta)); }
    auto typeNull(Meta meta = {}) { return hilti::type::Null::create(context(), std::move(meta)); }
    auto typeOperandList(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::OperandList::create(context(), _, m);
    }
    auto typeOperandList(type::operand_list::Operands operands, Meta meta = {}) {
        return hilti::type::OperandList::create(context(), std::move(operands), std::move(meta));
    }
    auto typeOperandListOperand(ID id, parameter::Kind kind, UnqualifiedType* type, bool optional = false,
                                std::string doc = "", Meta meta = {}) {
        return hilti::type::operand_list::Operand::create(context(), std::move(id), kind, type, optional,
                                                          std::move(doc), std::move(meta));
    }
    auto typeOperandListOperand(ID id, parameter::Kind kind, UnqualifiedType* type, Expression* default_, bool optional,
                                std::string doc = "", Meta meta = {}) {
        return hilti::type::operand_list::Operand::create(context(), std::move(id), kind, type, default_, optional,
                                                          std::move(doc), std::move(meta));
    }
    auto typeOperandListOperand(ID id, parameter::Kind kind, UnqualifiedType* type, Expression* default_,
                                std::string doc = "", Meta meta = {}) {
        return hilti::type::operand_list::Operand::create(context(), std::move(id), kind, type, default_,
                                                          std::move(doc), std::move(meta));
    }
    auto typeOperandListOperand(parameter::Kind kind, UnqualifiedType* type, bool optional = false,
                                std::string doc = "", Meta meta = {}) {
        return hilti::type::operand_list::Operand::create(context(), kind, type, optional, std::move(doc),
                                                          std::move(meta));
    }
    auto typeOptional(QualifiedType* t, Meta m = Meta()) {
        return hilti::type::Optional::create(context(), t, std::move(m));
    }
    auto typeOptional(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::Optional::create(context(), _, m);
    }
    auto typePort(Meta meta = {}) { return hilti::type::Port::create(context(), std::move(meta)); }
    auto typeReal(Meta meta = {}) { return hilti::type::Real::create(context(), std::move(meta)); }
    auto typeRegExp(Meta meta = {}) { return hilti::type::RegExp::create(context(), std::move(meta)); }
    auto typeResult(QualifiedType* t, Meta m = Meta()) {
        return hilti::type::Result::create(context(), t, std::move(m));
    }
    auto typeResult(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Result::create(context(), _, m); }
    auto typeSet(QualifiedType* t, const Meta& meta = {}) { return hilti::type::Set::create(context(), t, meta); }
    auto typeSet(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Set::create(context(), _, m); }
    auto typeSetIterator(QualifiedType* etype, Meta meta = {}) {
        return hilti::type::set::Iterator::create(context(), etype, std::move(meta));
    }
    auto typeSetIterator(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::set::Iterator::create(context(), _, m);
    }
    auto typeSignedInteger(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::SignedInteger::create(context(), _, m);
    }
    auto typeSignedInteger(unsigned int width, const Meta& m = Meta()) {
        return hilti::type::SignedInteger::create(context(), width, m);
    }
    auto typeStream(const Meta& meta = {}) { return hilti::type::Stream::create(context(), meta); }
    auto typeStreamIterator(Meta meta = {}) {
        return hilti::type::stream::Iterator::create(context(), std::move(meta));
    }
    auto typeStreamView(const Meta& meta = {}) { return hilti::type::stream::View::create(context(), meta); }
    auto typeString(Meta meta = {}) { return hilti::type::String::create(context(), std::move(meta)); }
    auto typeStrongReference(QualifiedType* type, Meta meta = {}) {
        return hilti::type::StrongReference::create(context(), type, std::move(meta));
    }
    auto typeStrongReference(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::StrongReference::create(context(), _, m);
    }
    auto typeStruct(const Declarations& fields, Meta meta = {}) {
        return hilti::type::Struct::create(context(), fields, std::move(meta));
    }
    auto typeStruct(const declaration::Parameters& params, const Declarations& fields, Meta meta = {}) {
        return hilti::type::Struct::create(context(), params, fields, std::move(meta));
    }
    auto typeStruct(type::Struct::AnonymousStruct _, const Declarations& fields, Meta meta = {}) {
        return hilti::type::Struct::create(context(), _, fields, std::move(meta));
    }
    auto typeStruct(type::Wildcard _, Meta meta = {}) {
        return hilti::type::Struct::create(context(), _, std::move(meta));
    }
    auto typeTime(Meta meta = {}) { return hilti::type::Time::create(context(), std::move(meta)); }
    auto typeTuple(const QualifiedTypes& types, Meta meta = {}) {
        return hilti::type::Tuple::create(context(), types, std::move(meta));
    }
    auto typeTuple(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Tuple::create(context(), _, m); }
    auto typeTuple(const type::tuple::Elements& elements, Meta meta = {}) {
        return hilti::type::Tuple::create(context(), elements, std::move(meta));
    }
    auto typeTupleElement(ID id, QualifiedType* type, Meta meta = {}) {
        return hilti::type::tuple::Element::create(context(), std::move(id), type, std::move(meta));
    }
    auto typeTupleElement(QualifiedType* type, Meta meta = {}) {
        return hilti::type::tuple::Element::create(context(), type, std::move(meta));
    }
    auto typeType(QualifiedType* type, Meta meta = {}) {
        return hilti::type::Type_::create(context(), type, std::move(meta));
    }
    auto typeType(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Type_::create(context(), _, m); }
    auto typeUnion(const Declarations& fields, Meta meta = {}) {
        return hilti::type::Union::create(context(), fields, std::move(meta));
    }
    auto typeUnion(const declaration::Parameters& params, const Declarations& fields, Meta meta = {}) {
        return hilti::type::Union::create(context(), params, fields, std::move(meta));
    }
    auto typeUnion(type::Union::AnonymousUnion _, const Declarations& fields, Meta meta = {}) {
        return hilti::type::Union::create(context(), _, fields, std::move(meta));
    }
    auto typeUnion(type::Wildcard _, Meta meta = {}) {
        return hilti::type::Union::create(context(), _, std::move(meta));
    }
    auto typeUnknown(Meta meta = {}) { return hilti::type::Unknown::create(context(), std::move(meta)); }
    auto typeUnsignedInteger(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::UnsignedInteger::create(context(), _, m);
    }
    auto typeUnsignedInteger(unsigned int width, const Meta& m = Meta()) {
        return hilti::type::UnsignedInteger::create(context(), width, m);
    }
    auto typeValueReference(QualifiedType* type, Meta meta = {}) {
        return hilti::type::ValueReference::create(context(), type, std::move(meta));
    }
    auto typeValueReference(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::ValueReference::create(context(), _, m);
    }
    auto typeVector(QualifiedType* t, const Meta& meta = {}) { return hilti::type::Vector::create(context(), t, meta); }
    auto typeVector(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Vector::create(context(), _, m); }
    auto typeVectorIterator(QualifiedType* etype, Meta meta = {}) {
        return hilti::type::vector::Iterator::create(context(), etype, std::move(meta));
    }
    auto typeVectorIterator(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::vector::Iterator::create(context(), _, m);
    }
    auto typeVoid(Meta meta = {}) { return hilti::type::Void::create(context(), std::move(meta)); }
    auto typeWeakReference(QualifiedType* type, Meta meta = {}) {
        return hilti::type::WeakReference::create(context(), type, std::move(meta));
    }
    auto typeWeakReference(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::WeakReference::create(context(), _, m);
    }

private:
    ASTContext* _context;
};

} // namespace hilti::builder
