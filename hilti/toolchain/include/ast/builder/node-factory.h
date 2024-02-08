// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/all.h>
#include <hilti/ast/ast-context.h>

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

    auto attribute(const std::string& tag, const ExpressionPtr& v, const Meta& m = Meta()) {
        return hilti::Attribute::create(context(), tag, v, m);
    }
    auto attribute(const std::string& tag, const Meta& m = Meta()) {
        return hilti::Attribute::create(context(), tag, m);
    }
    auto attributeSet(Attributes attrs = {}, Meta m = Meta()) {
        return hilti::AttributeSet::create(context(), std::move(attrs), std::move(m));
    }
    auto ctorAddress(hilti::rt::Address v, const Meta& meta = {}) {
        return hilti::ctor::Address::create(context(), v, meta);
    }
    auto ctorBitfield(const ctor::bitfield::BitRanges& bits, QualifiedTypePtr type, const Meta& m = Meta()) {
        return hilti::ctor::Bitfield::create(context(), bits, std::move(type), m);
    }
    auto ctorBitfieldBitRange(const ID& id, const ExpressionPtr& expr, const Meta& meta = Meta()) {
        return hilti::ctor::bitfield::BitRange::create(context(), id, expr, meta);
    }
    auto ctorBool(bool v, const Meta& meta = {}) { return hilti::ctor::Bool::create(context(), v, meta); }
    auto ctorBytes(std::string value, const Meta& meta = {}) {
        return hilti::ctor::Bytes::create(context(), std::move(value), meta);
    }
    auto ctorCoerced(const CtorPtr& orig, const CtorPtr& new_, const Meta& meta = {}) {
        return hilti::ctor::Coerced::create(context(), orig, new_, meta);
    }
    auto ctorDefault(const UnqualifiedTypePtr& type, Expressions type_args, const Meta& meta = {}) {
        return hilti::ctor::Default::create(context(), type, std::move(type_args), meta);
    }
    auto ctorDefault(const UnqualifiedTypePtr& type, const Meta& meta = {}) {
        return hilti::ctor::Default::create(context(), type, meta);
    }
    auto ctorEnum(const type::enum_::LabelPtr& label, const Meta& meta = {}) {
        return hilti::ctor::Enum::create(context(), label, meta);
    }
    auto ctorError(std::string v, const Meta& meta = {}) {
        return hilti::ctor::Error::create(context(), std::move(v), meta);
    }
    auto ctorException(const UnqualifiedTypePtr& type, const ExpressionPtr& value, const ExpressionPtr& location,
                       const Meta& meta = {}) {
        return hilti::ctor::Exception::create(context(), type, value, location, meta);
    }
    auto ctorException(const UnqualifiedTypePtr& type, const ExpressionPtr& value, const Meta& meta = {}) {
        return hilti::ctor::Exception::create(context(), type, value, meta);
    }
    auto ctorInterval(hilti::rt::Interval v, const Meta& meta = {}) {
        return hilti::ctor::Interval::create(context(), v, meta);
    }
    auto ctorLibrary(const CtorPtr& ctor, const QualifiedTypePtr& type, const Meta& meta = {}) {
        return hilti::ctor::Library::create(context(), ctor, type, meta);
    }
    auto ctorList(Expressions exprs, const Meta& meta = {}) {
        return hilti::ctor::List::create(context(), std::move(exprs), meta);
    }
    auto ctorList(const QualifiedTypePtr& etype, Expressions exprs, const Meta& meta = {}) {
        return hilti::ctor::List::create(context(), etype, std::move(exprs), meta);
    }
    auto ctorMap(const QualifiedTypePtr& key, const QualifiedTypePtr& value, ctor::map::Elements elements,
                 const Meta& meta = {}) {
        return hilti::ctor::Map::create(context(), key, value, std::move(elements), meta);
    }
    auto ctorMap(ctor::map::Elements elements, const Meta& meta = {}) {
        return hilti::ctor::Map::create(context(), std::move(elements), meta);
    }
    auto ctorMapElement(const ExpressionPtr& key, const ExpressionPtr& value, Meta meta = {}) {
        return hilti::ctor::map::Element::create(context(), key, value, std::move(meta));
    }
    auto ctorNetwork(hilti::rt::Network v, const Meta& meta = {}) {
        return hilti::ctor::Network::create(context(), v, meta);
    }
    auto ctorNull(const Meta& meta = {}) { return hilti::ctor::Null::create(context(), meta); }
    auto ctorOptional(const ExpressionPtr& expr, const Meta& meta = {}) {
        return hilti::ctor::Optional::create(context(), expr, meta);
    }
    auto ctorOptional(const QualifiedTypePtr& type, const Meta& meta = {}) {
        return hilti::ctor::Optional::create(context(), type, meta);
    }
    auto ctorPort(hilti::rt::Port v, const Meta& meta = {}) { return hilti::ctor::Port::create(context(), v, meta); }
    auto ctorReal(double v, const Meta& meta = {}) { return hilti::ctor::Real::create(context(), v, meta); }
    auto ctorRegExp(std::vector<std::string> v, AttributeSetPtr attrs, const Meta& meta = {}) {
        return hilti::ctor::RegExp::create(context(), std::move(v), std::move(attrs), meta);
    }
    auto ctorResult(const ExpressionPtr& expr, const Meta& meta = {}) {
        return hilti::ctor::Result::create(context(), expr, meta);
    }
    auto ctorSet(Expressions exprs, const Meta& meta = {}) {
        return hilti::ctor::Set::create(context(), std::move(exprs), meta);
    }
    auto ctorSet(const QualifiedTypePtr& etype, Expressions exprs, const Meta& meta = {}) {
        return hilti::ctor::Set::create(context(), etype, std::move(exprs), meta);
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
    auto ctorStrongReference(const QualifiedTypePtr& t, const Meta& meta = {}) {
        return hilti::ctor::StrongReference::create(context(), t, meta);
    }
    auto ctorStruct(ctor::struct_::Fields fields, QualifiedTypePtr t, const Meta& meta = {}) {
        return hilti::ctor::Struct::create(context(), std::move(fields), std::move(t), meta);
    }
    auto ctorStruct(ctor::struct_::Fields fields, const Meta& meta = {}) {
        return hilti::ctor::Struct::create(context(), std::move(fields), meta);
    }
    auto ctorStructField(ID id, const ExpressionPtr& expr, Meta meta = {}) {
        return hilti::ctor::struct_::Field::create(context(), std::move(id), expr, std::move(meta));
    }
    auto ctorTime(hilti::rt::Time v, const Meta& meta = {}) { return hilti::ctor::Time::create(context(), v, meta); }
    auto ctorTuple(const Expressions& exprs, const Meta& meta = {}) {
        return hilti::ctor::Tuple::create(context(), exprs, meta);
    }
    auto ctorUnion(const QualifiedTypePtr& type, const ExpressionPtr& value, const Meta& meta = {}) {
        return hilti::ctor::Union::create(context(), type, value, meta);
    }
    auto ctorUnsignedInteger(uint64_t value, unsigned int width, const Meta& meta = {}) {
        return hilti::ctor::UnsignedInteger::create(context(), value, width, meta);
    }
    auto ctorUnsignedInteger(uint64_t value, unsigned int width, const UnqualifiedTypePtr& t, const Meta& meta = {}) {
        return hilti::ctor::UnsignedInteger::create(context(), value, width, t, meta);
    }
    auto ctorValueReference(const ExpressionPtr& expr, const Meta& meta = {}) {
        return hilti::ctor::ValueReference::create(context(), expr, meta);
    }
    auto ctorVector(Expressions exprs, const Meta& meta = {}) {
        return hilti::ctor::Vector::create(context(), std::move(exprs), meta);
    }
    auto ctorVector(const QualifiedTypePtr& etype, Expressions exprs, const Meta& meta = {}) {
        return hilti::ctor::Vector::create(context(), etype, std::move(exprs), meta);
    }
    auto ctorWeakReference(const QualifiedTypePtr& t, const Meta& meta = {}) {
        return hilti::ctor::WeakReference::create(context(), t, meta);
    }
    auto declarationConstant(ID id, const ExpressionPtr& value,
                             declaration::Linkage linkage = declaration::Linkage::Private, Meta meta = {}) {
        return hilti::declaration::Constant::create(context(), std::move(id), value, linkage, std::move(meta));
    }
    auto declarationConstant(ID id, const QualifiedTypePtr& type, const ExpressionPtr& value,
                             declaration::Linkage linkage = declaration::Linkage::Private, Meta meta = {}) {
        return hilti::declaration::Constant::create(context(), std::move(id), type, value, linkage, std::move(meta));
    }
    auto declarationExpression(ID id, const ExpressionPtr& expr, AttributeSetPtr attrs, declaration::Linkage linkage,
                               Meta meta = {}) {
        return hilti::declaration::Expression::create(context(), std::move(id), expr, std::move(attrs), linkage,
                                                      std::move(meta));
    }
    auto declarationExpression(ID id, const ExpressionPtr& expr, declaration::Linkage linkage, Meta meta = {}) {
        return hilti::declaration::Expression::create(context(), std::move(id), expr, linkage, std::move(meta));
    }
    auto declarationField(ID id, ::hilti::function::CallingConvention cc, const type::FunctionPtr& ftype,
                          AttributeSetPtr attrs, Meta meta = {}) {
        return hilti::declaration::Field::create(context(), std::move(id), cc, ftype, std::move(attrs),
                                                 std::move(meta));
    }
    auto declarationField(ID id, QualifiedTypePtr type, AttributeSetPtr attrs, Meta meta = {}) {
        return hilti::declaration::Field::create(context(), std::move(id), std::move(type), std::move(attrs),
                                                 std::move(meta));
    }
    auto declarationField(const ID& id, const FunctionPtr& inline_func, AttributeSetPtr attrs, Meta meta = {}) {
        return hilti::declaration::Field::create(context(), id, inline_func, std::move(attrs), std::move(meta));
    }
    auto declarationFunction(const FunctionPtr& function, declaration::Linkage linkage = declaration::Linkage::Private,
                             const Meta& meta = {}) {
        return hilti::declaration::Function::create(context(), function, linkage, meta);
    }
    auto declarationGlobalVariable(ID id, const ExpressionPtr& init,
                                   declaration::Linkage linkage = declaration::Linkage::Private,
                                   const Meta& meta = {}) {
        return hilti::declaration::GlobalVariable::create(context(), std::move(id), init, linkage, meta);
    }
    auto declarationGlobalVariable(ID id, const QualifiedTypePtr& type, ExpressionPtr init = nullptr,
                                   declaration::Linkage linkage = declaration::Linkage::Private, Meta meta = {}) {
        return hilti::declaration::GlobalVariable::create(context(), std::move(id), type, std::move(init), linkage,
                                                          std::move(meta));
    }
    auto declarationGlobalVariable(ID id, const QualifiedTypePtr& type, Expressions args, ExpressionPtr init = nullptr,
                                   declaration::Linkage linkage = declaration::Linkage::Private, Meta meta = {}) {
        return hilti::declaration::GlobalVariable::create(context(), std::move(id), type, std::move(args),
                                                          std::move(init), linkage, std::move(meta));
    }
    auto declarationGlobalVariable(ID id, const QualifiedTypePtr& type,
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
    auto declarationLocalVariable(ID id, ExpressionPtr init, const Meta& meta = {}) {
        return hilti::declaration::LocalVariable::create(context(), std::move(id), std::move(init), meta);
    }
    auto declarationLocalVariable(ID id, const Meta& meta = {}) {
        return hilti::declaration::LocalVariable::create(context(), std::move(id), meta);
    }
    auto declarationLocalVariable(ID id, const QualifiedTypePtr& type, ExpressionPtr init, Meta meta = {}) {
        return hilti::declaration::LocalVariable::create(context(), std::move(id), type, std::move(init),
                                                         std::move(meta));
    }
    auto declarationLocalVariable(ID id, const QualifiedTypePtr& type, Expressions args, ExpressionPtr init = nullptr,
                                  Meta meta = {}) {
        return hilti::declaration::LocalVariable::create(context(), std::move(id), type, std::move(args),
                                                         std::move(init), std::move(meta));
    }
    auto declarationLocalVariable(ID id, const QualifiedTypePtr& type, Meta meta = {}) {
        return hilti::declaration::LocalVariable::create(context(), std::move(id), type, std::move(meta));
    }
    auto declarationModule(const declaration::module::UID& uid, const ID& scope = {}, const Meta& meta = {}) {
        return hilti::declaration::Module::create(context(), uid, scope, meta);
    }
    auto declarationModule(const declaration::module::UID& uid, const ID& scope, const Declarations& decls,
                           Statements stmts, const Meta& meta = {}) {
        return hilti::declaration::Module::create(context(), uid, scope, decls, std::move(stmts), meta);
    }
    auto declarationModule(const declaration::module::UID& uid, const ID& scope, const Declarations& decls,
                           const Meta& meta = {}) {
        return hilti::declaration::Module::create(context(), uid, scope, decls, meta);
    }
    auto declarationParameter(ID id, const UnqualifiedTypePtr& type, parameter::Kind kind,
                              const hilti::ExpressionPtr& default_, AttributeSetPtr attrs, Meta meta = {}) {
        return hilti::declaration::Parameter::create(context(), std::move(id), type, kind, default_, std::move(attrs),
                                                     std::move(meta));
    }
    auto declarationParameter(ID id, const UnqualifiedTypePtr& type, parameter::Kind kind,
                              const hilti::ExpressionPtr& default_, bool is_type_param, AttributeSetPtr attrs,
                              Meta meta = {}) {
        return hilti::declaration::Parameter::create(context(), std::move(id), type, kind, default_, is_type_param,
                                                     std::move(attrs), std::move(meta));
    }
    auto declarationProperty(ID id, Meta meta = {}) {
        return hilti::declaration::Property::create(context(), std::move(id), std::move(meta));
    }
    auto declarationProperty(ID id, const ExpressionPtr& expr, Meta meta = {}) {
        return hilti::declaration::Property::create(context(), std::move(id), expr, std::move(meta));
    }
    auto declarationType(ID id, const QualifiedTypePtr& type, AttributeSetPtr attrs,
                         declaration::Linkage linkage = declaration::Linkage::Private, Meta meta = {}) {
        return hilti::declaration::Type::create(context(), std::move(id), type, std::move(attrs), linkage,
                                                std::move(meta));
    }
    auto declarationType(ID id, const QualifiedTypePtr& type,
                         declaration::Linkage linkage = declaration::Linkage::Private, Meta meta = {}) {
        return hilti::declaration::Type::create(context(), std::move(id), type, linkage, std::move(meta));
    }
    auto expressionAssign(const ExpressionPtr& target, const ExpressionPtr& src, const Meta& meta = {}) {
        return hilti::expression::Assign::create(context(), target, src, meta);
    }
    auto expressionBuiltInFunction(const std::string& name, const std::string& cxxname, const QualifiedTypePtr& type,
                                   const type::function::Parameters& parameters, const Expressions& arguments,
                                   const Meta& meta = {}) {
        return hilti::expression::BuiltInFunction::create(context(), name, cxxname, type, parameters, arguments, meta);
    }
    auto expressionCoerced(const ExpressionPtr& expr, const QualifiedTypePtr& target, const Meta& meta = {}) {
        return hilti::expression::Coerced::create(context(), expr, target, meta);
    }
    auto expressionCtor(const CtorPtr& ctor, const Meta& meta = {}) {
        return hilti::expression::Ctor::create(context(), ctor, meta);
    }
    auto expressionDeferred(const ExpressionPtr& expr, bool catch_exception, const Meta& meta = {}) {
        return hilti::expression::Deferred::create(context(), expr, catch_exception, meta);
    }
    auto expressionDeferred(const ExpressionPtr& expr, const Meta& meta = {}) {
        return hilti::expression::Deferred::create(context(), expr, meta);
    }
    auto expressionGrouping(const ExpressionPtr& expr, const Meta& meta = {}) {
        return hilti::expression::Grouping::create(context(), expr, meta);
    }
    auto expressionKeyword(expression::keyword::Kind kind, const Meta& meta = {}) {
        return hilti::expression::Keyword::create(context(), kind, meta);
    }
    auto expressionKeyword(expression::keyword::Kind kind, const QualifiedTypePtr& type, const Meta& meta = {}) {
        return hilti::expression::Keyword::create(context(), kind, type, meta);
    }
    auto expressionListComprehension(const ExpressionPtr& input, const ExpressionPtr& output, const ID& id,
                                     const ExpressionPtr& cond, const Meta& meta = {}) {
        return hilti::expression::ListComprehension::create(context(), input, output, id, cond, meta);
    }
    auto expressionLogicalAnd(const ExpressionPtr& op0, const ExpressionPtr& op1, const Meta& meta = {}) {
        return hilti::expression::LogicalAnd::create(context(), op0, op1, meta);
    }
    auto expressionLogicalNot(const ExpressionPtr& expression, const Meta& meta = {}) {
        return hilti::expression::LogicalNot::create(context(), expression, meta);
    }
    auto expressionLogicalOr(const ExpressionPtr& op0, const ExpressionPtr& op1, const Meta& meta = {}) {
        return hilti::expression::LogicalOr::create(context(), op0, op1, meta);
    }
    auto expressionMember(const QualifiedTypePtr& member_type, const hilti::ID& id, const Meta& meta = {}) {
        return hilti::expression::Member::create(context(), member_type, id, meta);
    }
    auto expressionMember(const hilti::ID& id, const Meta& meta = {}) {
        return hilti::expression::Member::create(context(), id, meta);
    }
    auto expressionMove(const ExpressionPtr& expression, const Meta& meta = {}) {
        return hilti::expression::Move::create(context(), expression, meta);
    }
    auto expressionName(const hilti::ID& id, const Meta& meta = {}) {
        return hilti::expression::Name::create(context(), id, meta);
    }
    auto expressionPendingCoerced(const ExpressionPtr& expr, const QualifiedTypePtr& type, const Meta& meta = {}) {
        return hilti::expression::PendingCoerced::create(context(), expr, type, meta);
    }
    auto expressionTernary(const ExpressionPtr& cond, const ExpressionPtr& true_, const ExpressionPtr& false_,
                           const Meta& meta = {}) {
        return hilti::expression::Ternary::create(context(), cond, true_, false_, meta);
    }
    auto expressionType(const QualifiedTypePtr& type, const Meta& meta = {}) {
        return hilti::expression::Type_::create(context(), type, meta);
    }
    auto expressionTypeInfo(const ExpressionPtr& expr, const Meta& meta = {}) {
        return hilti::expression::TypeInfo::create(context(), expr, meta);
    }
    auto expressionTypeWrapped(const ExpressionPtr& expr, const QualifiedTypePtr& type, const Meta& meta = {}) {
        return hilti::expression::TypeWrapped::create(context(), expr, type, meta);
    }
    auto expressionUnresolvedOperator(operator_::Kind kind, Expressions operands, const Meta& meta = {}) {
        return hilti::expression::UnresolvedOperator::create(context(), kind, std::move(operands), meta);
    }
    auto expressionUnresolvedOperator(operator_::Kind kind, hilti::node::Range<Expression> operands,
                                      const Meta& meta = {}) {
        return hilti::expression::UnresolvedOperator::create(context(), kind, operands, meta);
    }
    auto expressionVoid(const Meta& meta = {}) { return hilti::expression::Void::create(context(), meta); }
    auto function(const ID& id, const type::FunctionPtr& ftype, const StatementPtr& body,
                  function::CallingConvention cc = function::CallingConvention::Standard,
                  AttributeSetPtr attrs = nullptr, const Meta& meta = {}) {
        return hilti::Function::create(context(), id, ftype, body, cc, std::move(attrs), meta);
    }
    auto qualifiedType(const UnqualifiedTypePtr& t, Constness const_, Meta m = Meta()) {
        return hilti::QualifiedType::create(context(), t, const_, std::move(m));
    }
    auto qualifiedType(const UnqualifiedTypePtr& t, Constness const_, Side side, const Meta& m = Meta()) {
        return hilti::QualifiedType::create(context(), t, const_, side, m);
    }
    auto statementAssert(const ExpressionPtr& expr, const ExpressionPtr& msg = nullptr, Meta meta = {}) {
        return hilti::statement::Assert::create(context(), expr, msg, std::move(meta));
    }
    auto statementAssert(statement::assert::Exception _unused, const ExpressionPtr& expr,
                         const UnqualifiedTypePtr& excpt, const ExpressionPtr& msg = nullptr, const Meta& meta = {}) {
        return hilti::statement::Assert::create(context(), _unused, expr, excpt, msg, meta);
    }
    auto statementBlock(Meta meta = {}) { return hilti::statement::Block::create(context(), std::move(meta)); }
    auto statementBlock(Statements stmts, Meta meta = {}) {
        return hilti::statement::Block::create(context(), std::move(stmts), std::move(meta));
    }
    auto statementBreak(Meta meta = {}) { return hilti::statement::Break::create(context(), std::move(meta)); }
    auto statementComment(std::string comment,
                          statement::comment::Separator separator = statement::comment::Separator::Before,
                          Meta meta = {}) {
        return hilti::statement::Comment::create(context(), std::move(comment), separator, std::move(meta));
    }
    auto statementContinue(Meta meta = {}) { return hilti::statement::Continue::create(context(), std::move(meta)); }
    auto statementDeclaration(const hilti::DeclarationPtr& d, Meta meta = {}) {
        return hilti::statement::Declaration::create(context(), d, std::move(meta));
    }
    auto statementExpression(const ExpressionPtr& e, Meta meta = {}) {
        return hilti::statement::Expression::create(context(), e, std::move(meta));
    }
    auto statementFor(const hilti::ID& id, const ExpressionPtr& seq, const StatementPtr& body, Meta meta = {}) {
        return hilti::statement::For::create(context(), id, seq, body, std::move(meta));
    }
    auto statementIf(const DeclarationPtr& init, const ExpressionPtr& cond, const StatementPtr& true_,
                     const StatementPtr& false_, Meta meta = {}) {
        return hilti::statement::If::create(context(), init, cond, true_, false_, std::move(meta));
    }
    auto statementIf(const ExpressionPtr& cond, const StatementPtr& true_, const StatementPtr& false_, Meta meta = {}) {
        return hilti::statement::If::create(context(), cond, true_, false_, std::move(meta));
    }
    auto statementReturn(Meta meta = {}) { return hilti::statement::Return::create(context(), std::move(meta)); }
    auto statementReturn(const ExpressionPtr& expr, Meta meta = {}) {
        return hilti::statement::Return::create(context(), expr, std::move(meta));
    }
    auto statementSetLocation(const ExpressionPtr& expr, Meta meta = {}) {
        return hilti::statement::SetLocation::create(context(), expr, std::move(meta));
    }
    auto statementSwitch(DeclarationPtr cond, const statement::switch_::Cases& cases, Meta meta = {}) {
        return hilti::statement::Switch::create(context(), std::move(cond), cases, std::move(meta));
    }
    auto statementSwitch(const ExpressionPtr& cond, const statement::switch_::Cases& cases, Meta meta = {}) {
        return hilti::statement::Switch::create(context(), cond, cases, std::move(meta));
    }
    auto statementSwitchCase(const ExpressionPtr& expr, const StatementPtr& body, Meta meta = {}) {
        return hilti::statement::switch_::Case::create(context(), expr, body, std::move(meta));
    }
    auto statementSwitchCase(const Expressions& exprs, const StatementPtr& body, Meta meta = {}) {
        return hilti::statement::switch_::Case::create(context(), exprs, body, std::move(meta));
    }
    auto statementSwitchCase(statement::switch_::Default _unused, const StatementPtr& body, Meta meta = {}) {
        return hilti::statement::switch_::Case::create(context(), _unused, body, std::move(meta));
    }
    auto statementThrow(Meta meta = {}) { return hilti::statement::Throw::create(context(), std::move(meta)); }
    auto statementThrow(const ExpressionPtr& expr, Meta meta = {}) {
        return hilti::statement::Throw::create(context(), expr, std::move(meta));
    }
    auto statementTry(StatementPtr body, const statement::try_::Catches& catches, Meta meta = {}) {
        return hilti::statement::Try::create(context(), std::move(body), catches, std::move(meta));
    }
    auto statementTryCatch(const DeclarationPtr& param, const StatementPtr& body, Meta meta = {}) {
        return hilti::statement::try_::Catch::create(context(), param, body, std::move(meta));
    }
    auto statementTryCatch(const StatementPtr& body, Meta meta = {}) {
        return hilti::statement::try_::Catch::create(context(), body, std::move(meta));
    }
    auto statementWhile(const DeclarationPtr& init, const ExpressionPtr& cond, const StatementPtr& body,
                        const StatementPtr& else_ = nullptr, const Meta& meta = {}) {
        return hilti::statement::While::create(context(), init, cond, body, else_, meta);
    }
    auto statementWhile(const ExpressionPtr& cond, const StatementPtr& body, const Meta& meta = {}) {
        return hilti::statement::While::create(context(), cond, body, meta);
    }
    auto statementWhile(const ExpressionPtr& cond, const StatementPtr& body, const StatementPtr& else_ = nullptr,
                        const Meta& meta = {}) {
        return hilti::statement::While::create(context(), cond, body, else_, meta);
    }
    auto statementYield(Meta meta = {}) { return hilti::statement::Yield::create(context(), std::move(meta)); }
    auto typeAddress(const Meta& m = Meta()) { return hilti::type::Address::create(context(), m); }
    auto typeAny(Meta m = Meta()) { return hilti::type::Any::create(context(), std::move(m)); }
    auto typeAuto(const Meta& m = Meta()) { return hilti::type::Auto::create(context(), m); }
    auto typeBitfield(int width, type::bitfield::BitRanges bits, AttributeSetPtr attrs, const Meta& m = Meta()) {
        return hilti::type::Bitfield::create(context(), width, std::move(bits), std::move(attrs), m);
    }
    auto typeBitfield(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::Bitfield::create(context(), _, m);
    }
    auto typeBitfieldBitRange(const ID& id, int lower, int upper, int field_width, AttributeSetPtr attrs = {},
                              const ExpressionPtr& ctor_value = nullptr, const Meta& meta = Meta()) {
        return hilti::type::bitfield::BitRange::create(context(), id, lower, upper, field_width, std::move(attrs),
                                                       ctor_value, meta);
    }
    auto typeBitfieldBitRange(const ID& id, int lower, int upper, int field_width, AttributeSetPtr attrs = {},
                              const Meta& meta = Meta()) {
        return hilti::type::bitfield::BitRange::create(context(), id, lower, upper, field_width, std::move(attrs),
                                                       meta);
    }
    auto typeBool(const Meta& meta = {}) { return hilti::type::Bool::create(context(), meta); }
    auto typeBytes(const Meta& meta = {}) { return hilti::type::Bytes::create(context(), meta); }
    auto typeBytesIterator(const Meta& meta = {}) { return hilti::type::bytes::Iterator::create(context(), meta); }
    auto typeDocOnly(const std::string& description, const Meta& meta = {}) {
        return hilti::type::DocOnly::create(context(), description, meta);
    }
    auto typeEnum(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Enum::create(context(), _, m); }
    auto typeEnum(type::enum_::Labels labels, Meta meta = {}) {
        return hilti::type::Enum::create(context(), std::move(labels), std::move(meta));
    }
    auto typeEnumLabel(const ID& id, const Meta& meta = {}) {
        return hilti::type::enum_::Label::create(context(), id, meta);
    }
    auto typeEnumLabel(const ID& id, int value, const Meta& meta = {}) {
        return hilti::type::enum_::Label::create(context(), id, value, meta);
    }
    auto typeError(Meta meta = {}) { return hilti::type::Error::create(context(), std::move(meta)); }
    auto typeException(const Meta& meta = {}) { return hilti::type::Exception::create(context(), meta); }
    auto typeException(const UnqualifiedTypePtr& base, Meta meta = {}) {
        return hilti::type::Exception::create(context(), base, std::move(meta));
    }
    auto typeException(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::Exception::create(context(), _, m);
    }
    auto typeFunction(const QualifiedTypePtr& result, const declaration::Parameters& params,
                      type::function::Flavor flavor = type::function::Flavor::Standard, const Meta& meta = {}) {
        return hilti::type::Function::create(context(), result, params, flavor, meta);
    }
    auto typeFunction(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::Function::create(context(), _, m);
    }
    auto typeInterval(Meta meta = {}) { return hilti::type::Interval::create(context(), std::move(meta)); }
    auto typeLibrary(const std::string& cxx_name, Meta meta = {}) {
        return hilti::type::Library::create(context(), cxx_name, std::move(meta));
    }
    auto typeList(const QualifiedTypePtr& t, const Meta& meta = {}) {
        return hilti::type::List::create(context(), t, meta);
    }
    auto typeList(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::List::create(context(), _, m); }
    auto typeListIterator(const QualifiedTypePtr& etype, Meta meta = {}) {
        return hilti::type::list::Iterator::create(context(), etype, std::move(meta));
    }
    auto typeListIterator(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::list::Iterator::create(context(), _, m);
    }
    auto typeMap(const QualifiedTypePtr& ktype, const QualifiedTypePtr& vtype, const Meta& meta = {}) {
        return hilti::type::Map::create(context(), ktype, vtype, meta);
    }
    auto typeMap(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Map::create(context(), _, m); }
    auto typeMapIterator(const QualifiedTypePtr& ktype, const QualifiedTypePtr& vtype, const Meta& meta = {}) {
        return hilti::type::map::Iterator::create(context(), ktype, vtype, meta);
    }
    auto typeMapIterator(type::Wildcard _, const Meta& meta = Meta()) {
        return hilti::type::map::Iterator::create(context(), _, meta);
    }
    auto typeMember(const ID& id, Meta meta = {}) {
        return hilti::type::Member::create(context(), id, std::move(meta));
    }
    auto typeMember(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Member::create(context(), _, m); }
    auto typeName(const ID& id, const Meta& meta = {}) { return hilti::type::Name::create(context(), id, meta); }
    auto typeNetwork(Meta meta = {}) { return hilti::type::Network::create(context(), std::move(meta)); }
    auto typeNull(Meta meta = {}) { return hilti::type::Null::create(context(), std::move(meta)); }
    auto typeOperandList(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::OperandList::create(context(), _, m);
    }
    auto typeOperandList(type::operand_list::Operands operands, Meta meta = {}) {
        return hilti::type::OperandList::create(context(), std::move(operands), std::move(meta));
    }
    auto typeOperandListOperand(ID id, parameter::Kind kind, const UnqualifiedTypePtr& type, bool optional = false,
                                std::string doc = "", Meta meta = {}) {
        return hilti::type::operand_list::Operand::create(context(), std::move(id), kind, type, optional,
                                                          std::move(doc), std::move(meta));
    }
    auto typeOperandListOperand(ID id, parameter::Kind kind, const UnqualifiedTypePtr& type,
                                const ExpressionPtr& default_, bool optional, std::string doc = "",
                                const Meta& meta = {}) {
        return hilti::type::operand_list::Operand::create(context(), std::move(id), kind, type, default_, optional,
                                                          std::move(doc), meta);
    }
    auto typeOperandListOperand(ID id, parameter::Kind kind, const UnqualifiedTypePtr& type,
                                const ExpressionPtr& default_, std::string doc = "", const Meta& meta = {}) {
        return hilti::type::operand_list::Operand::create(context(), std::move(id), kind, type, default_,
                                                          std::move(doc), meta);
    }
    auto typeOperandListOperand(parameter::Kind kind, const UnqualifiedTypePtr& type, bool optional = false,
                                std::string doc = "", Meta meta = {}) {
        return hilti::type::operand_list::Operand::create(context(), kind, type, optional, std::move(doc),
                                                          std::move(meta));
    }
    auto typeOptional(const QualifiedTypePtr& t, Meta m = Meta()) {
        return hilti::type::Optional::create(context(), t, std::move(m));
    }
    auto typeOptional(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::Optional::create(context(), _, m);
    }
    auto typePort(Meta meta = {}) { return hilti::type::Port::create(context(), std::move(meta)); }
    auto typeReal(Meta meta = {}) { return hilti::type::Real::create(context(), std::move(meta)); }
    auto typeRegExp(Meta meta = {}) { return hilti::type::RegExp::create(context(), std::move(meta)); }
    auto typeResult(const QualifiedTypePtr& t, Meta m = Meta()) {
        return hilti::type::Result::create(context(), t, std::move(m));
    }
    auto typeResult(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Result::create(context(), _, m); }
    auto typeSet(const QualifiedTypePtr& t, const Meta& meta = {}) {
        return hilti::type::Set::create(context(), t, meta);
    }
    auto typeSet(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Set::create(context(), _, m); }
    auto typeSetIterator(const QualifiedTypePtr& etype, Meta meta = {}) {
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
    auto typeStreamIterator(const Meta& meta = {}) { return hilti::type::stream::Iterator::create(context(), meta); }
    auto typeStreamView(const Meta& meta = {}) { return hilti::type::stream::View::create(context(), meta); }
    auto typeString(Meta meta = {}) { return hilti::type::String::create(context(), std::move(meta)); }
    auto typeStrongReference(const QualifiedTypePtr& type, Meta meta = {}) {
        return hilti::type::StrongReference::create(context(), type, std::move(meta));
    }
    auto typeStrongReference(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::StrongReference::create(context(), _, m);
    }
    auto typeStruct(const Declarations& fields, const Meta& meta = {}) {
        return hilti::type::Struct::create(context(), fields, meta);
    }
    auto typeStruct(const declaration::Parameters& params, Declarations fields, const Meta& meta = {}) {
        return hilti::type::Struct::create(context(), params, std::move(fields), meta);
    }
    auto typeStruct(type::Struct::AnonymousStruct _, Declarations fields, const Meta& meta = {}) {
        return hilti::type::Struct::create(context(), _, std::move(fields), meta);
    }
    auto typeStruct(type::Wildcard _, const Meta& meta = {}) { return hilti::type::Struct::create(context(), _, meta); }
    auto typeTime(Meta meta = {}) { return hilti::type::Time::create(context(), std::move(meta)); }
    auto typeTuple(const QualifiedTypes& types, const Meta& meta = {}) {
        return hilti::type::Tuple::create(context(), types, meta);
    }
    auto typeTuple(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Tuple::create(context(), _, m); }
    auto typeTuple(type::tuple::Elements elements, Meta meta = {}) {
        return hilti::type::Tuple::create(context(), std::move(elements), std::move(meta));
    }
    auto typeTupleElement(ID id, const QualifiedTypePtr& type, Meta meta = {}) {
        return hilti::type::tuple::Element::create(context(), std::move(id), type, std::move(meta));
    }
    auto typeTupleElement(const QualifiedTypePtr& type, Meta meta = {}) {
        return hilti::type::tuple::Element::create(context(), type, std::move(meta));
    }
    auto typeType(const QualifiedTypePtr& type, Meta meta = {}) {
        return hilti::type::Type_::create(context(), type, std::move(meta));
    }
    auto typeType(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Type_::create(context(), _, m); }
    auto typeUnion(const Declarations& fields, const Meta& meta = {}) {
        return hilti::type::Union::create(context(), fields, meta);
    }
    auto typeUnion(const declaration::Parameters& params, Declarations fields, const Meta& meta = {}) {
        return hilti::type::Union::create(context(), params, std::move(fields), meta);
    }
    auto typeUnion(type::Union::AnonymousUnion _, Declarations fields, const Meta& meta = {}) {
        return hilti::type::Union::create(context(), _, std::move(fields), meta);
    }
    auto typeUnion(type::Wildcard _, const Meta& meta = {}) { return hilti::type::Union::create(context(), _, meta); }
    auto typeUnknown(Meta meta = {}) { return hilti::type::Unknown::create(context(), std::move(meta)); }
    auto typeUnsignedInteger(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::UnsignedInteger::create(context(), _, m);
    }
    auto typeUnsignedInteger(unsigned int width, const Meta& m = Meta()) {
        return hilti::type::UnsignedInteger::create(context(), width, m);
    }
    auto typeValueReference(const QualifiedTypePtr& type, Meta meta = {}) {
        return hilti::type::ValueReference::create(context(), type, std::move(meta));
    }
    auto typeValueReference(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::ValueReference::create(context(), _, m);
    }
    auto typeVector(const QualifiedTypePtr& t, const Meta& meta = {}) {
        return hilti::type::Vector::create(context(), t, meta);
    }
    auto typeVector(type::Wildcard _, const Meta& m = Meta()) { return hilti::type::Vector::create(context(), _, m); }
    auto typeVectorIterator(const QualifiedTypePtr& etype, Meta meta = {}) {
        return hilti::type::vector::Iterator::create(context(), etype, std::move(meta));
    }
    auto typeVectorIterator(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::vector::Iterator::create(context(), _, m);
    }
    auto typeVoid(Meta meta = {}) { return hilti::type::Void::create(context(), std::move(meta)); }
    auto typeWeakReference(const QualifiedTypePtr& type, Meta meta = {}) {
        return hilti::type::WeakReference::create(context(), type, std::move(meta));
    }
    auto typeWeakReference(type::Wildcard _, const Meta& m = Meta()) {
        return hilti::type::WeakReference::create(context(), _, m);
    }

private:
    ASTContext* _context;
};

} // namespace hilti::builder
