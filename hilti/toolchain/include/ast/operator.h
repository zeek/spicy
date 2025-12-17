// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>
#include <hilti/ast/types/operand-list.h>
#include <hilti/base/logger.h>

namespace hilti {

namespace expression {
class ResolvedOperator;
}

namespace operator_ {
class Registry;

/** Enumeration of all types of operators that HILTI supports. */
enum class Kind {
    Add,
    Begin,
    BitAnd,
    BitOr,
    BitXor,
    Call,
    Cast,
    CustomAssign,
    DecrPostfix,
    DecrPrefix,
    Delete,
    Deref,
    Difference,
    DifferenceAssign,
    Division,
    DivisionAssign,
    Equal,
    End,
    Greater,
    GreaterEqual,
    HasMember,
    In,
    IncrPostfix,
    IncrPrefix,
    Index,
    IndexAssign,
    Lower,
    LowerEqual,
    Member,
    MemberCall,
    Modulo,
    Multiple,
    MultipleAssign,
    Negate,
    New,
    Pack,
    Power,
    ShiftLeft,
    ShiftRight,
    SignNeg,
    SignPos,
    Size,
    Sum,
    SumAssign,
    TryMember,
    Unequal,
    Unknown,
    Unpack,
    Unset
};

/** Returns true for operator types that HILTI considers commutative. */
inline auto isCommutative(Kind k) {
    switch ( k ) {
        case Kind::BitAnd:
        case Kind::BitOr:
        case Kind::BitXor:
        case Kind::Equal:
        case Kind::Unequal:
        case Kind::Multiple:
        case Kind::Sum: return true;

        case Kind::Add:
        case Kind::Begin:
        case Kind::Call:
        case Kind::Cast:
        case Kind::CustomAssign:
        case Kind::DecrPostfix:
        case Kind::DecrPrefix:
        case Kind::Delete:
        case Kind::Deref:
        case Kind::Difference:
        case Kind::DifferenceAssign:
        case Kind::Division:
        case Kind::DivisionAssign:
        case Kind::End:
        case Kind::Greater:
        case Kind::GreaterEqual:
        case Kind::HasMember:
        case Kind::In:
        case Kind::IncrPostfix:
        case Kind::IncrPrefix:
        case Kind::Index:
        case Kind::IndexAssign:
        case Kind::Lower:
        case Kind::LowerEqual:
        case Kind::Member:
        case Kind::MemberCall:
        case Kind::Modulo:
        case Kind::MultipleAssign:
        case Kind::Negate:
        case Kind::New:
        case Kind::Pack:
        case Kind::Power:
        case Kind::ShiftLeft:
        case Kind::ShiftRight:
        case Kind::SignNeg:
        case Kind::SignPos:
        case Kind::Size:
        case Kind::SumAssign:
        case Kind::TryMember:
        case Kind::Unknown:
        case Kind::Unpack:
        case Kind::Unset: return false;
    };

    util::cannotBeReached();
}

namespace detail {
constexpr util::enum_::Value<Kind> Kinds[] =
    {{.value = Kind::Add, .name = "add"},           {.value = Kind::Begin, .name = "begin"},
     {.value = Kind::BitAnd, .name = "&"},          {.value = Kind::BitOr, .name = "|"},
     {.value = Kind::BitXor, .name = "^"},          {.value = Kind::Call, .name = "call"},
     {.value = Kind::Cast, .name = "cast"},         {.value = Kind::CustomAssign, .name = "="},
     {.value = Kind::DecrPostfix, .name = "--"},    {.value = Kind::DecrPrefix, .name = "--"},
     {.value = Kind::Delete, .name = "delete"},     {.value = Kind::Deref, .name = "*"},
     {.value = Kind::Division, .name = "/"},        {.value = Kind::DivisionAssign, .name = "/="},
     {.value = Kind::Equal, .name = "=="},          {.value = Kind::End, .name = "end"},
     {.value = Kind::Greater, .name = ">"},         {.value = Kind::GreaterEqual, .name = ">="},
     {.value = Kind::HasMember, .name = "?."},      {.value = Kind::In, .name = "in"},
     {.value = Kind::IncrPostfix, .name = "++"},    {.value = Kind::IncrPrefix, .name = "++"},
     {.value = Kind::Index, .name = "index"},       {.value = Kind::IndexAssign, .name = "index_assign"},
     {.value = Kind::Lower, .name = "<"},           {.value = Kind::LowerEqual, .name = "<="},
     {.value = Kind::Member, .name = "."},          {.value = Kind::MemberCall, .name = "method call"},
     {.value = Kind::Negate, .name = "~"},          {.value = Kind::New, .name = "new"},
     {.value = Kind::Difference, .name = "-"},      {.value = Kind::DifferenceAssign, .name = "-="},
     {.value = Kind::Modulo, .name = "%"},          {.value = Kind::Multiple, .name = "*"},
     {.value = Kind::MultipleAssign, .name = "*="}, {.value = Kind::Sum, .name = "+"},
     {.value = Kind::Pack, .name = "pack"},         {.value = Kind::Unset, .name = "unset"},
     {.value = Kind::SumAssign, .name = "+="},      {.value = Kind::Power, .name = "**"},
     {.value = Kind::ShiftLeft, .name = "<<"},      {.value = Kind::ShiftRight, .name = ">>"},
     {.value = Kind::SignNeg, .name = "-"},         {.value = Kind::SignPos, .name = "+"},
     {.value = Kind::Size, .name = "size"},         {.value = Kind::TryMember, .name = ".?"},
     {.value = Kind::Unequal, .name = "!="},        {.value = Kind::Unknown, .name = "<unknown>"},
     {.value = Kind::Unpack, .name = "unpack"},     {.value = Kind::Unset, .name = "unset"}};

/** Render an operator with its operand expressions. */
extern std::string print(Kind kind, const Expressions& operands);


/** Render an operator with its operand types. */
extern std::string printSignature(Kind kind, const Expressions& operands, const Meta& meta);

} // namespace detail

/**
 * Returns a descriptive string representation of an operator kind. This is
 * meant just for display purposes, and does not correspond directly to the
 * HILTI code representation (because they may differ based on context).
 */
constexpr auto to_string(Kind m) { return util::enum_::to_string(m, detail::Kinds); }

/** Operator priority during resolving relative to others of the same kind. */
enum class Priority { Low, Normal };

using Operand = type::operand_list::Operand;
using Operands = type::operand_list::Operands;

/** Helper for defining operator signatures. */
struct Signature {
    /** Defines an operator argument. */
    struct QType {
        parameter::Kind kind = parameter::Kind::Unknown; /**< defines passing-style */
        UnqualifiedType* type = nullptr;                 /**< type of the argument */
        std::string doc;                                 /**< documentation string  */
        UnqualifiedType* external_type = nullptr;        /**< alternative way to specify type through an existing one */

        UnqualifiedType* getType() const {
            if ( external_type )
                return external_type;
            else
                return type;
        }

        operator bool() const { return kind != parameter::Kind::Unknown && getType(); }
    };

    struct QResult {
        Constness constness = Constness::Const; /**< constness of the result */
        UnqualifiedType* type = nullptr;        /**< type of the argument */
        std::string doc;                        /**< documentation string  */

        operator bool() const { return type != nullptr; }
    };

    /** Defines an operator parameter for constructor calls. */
    struct QParam {
        std::string name;               /**< ID of parameter */
        QType type;                     /**< type of parameter */
        Expression* default_ = nullptr; /**< optional default value if parameter is not given */
        bool optional = false;          /**< true if parameter is optional */

        operator bool() const { return type; }
    };

    operator_::Kind kind;
    operator_::Priority priority = operator_::Priority::Normal;

    QType self;
    QType op0;
    QType op1;
    QType op2;

    std::optional<std::string> member;
    QParam param0;
    QParam param1;
    QParam param2;
    QParam param3;
    QParam param4;

    QResult result;         /**< result of the method; if not set, `result()` will be called dynamically */
    std::string result_doc; /**< documentation string for the result */

    std::string ns;        /**< namespace where to document this operator */
    std::string doc;       /**< documentation string describing the operator */
    bool skip_doc = false; /**< if true, do not include this operator into any documentation */
};

namespace detail {

/** Internal representation of an operator signature after it has been processed. */
struct ProcessedSignature {
    operator_::Kind kind = operator_::Kind::Unknown;
    node::RetainedPtr<QualifiedType>
        result; /**< result of the method; if null, `result()` will be called dynamically */
    node::RetainedPtr<type::OperandList> operands; /**< null for operators to be instantiated only manually */
    operator_::Priority priority;
    std::string doc;        /**< documentation string */
    std::string result_doc; /**< explicitly set documentation string for result type */
    std::string namespace_; /**< namespace where to document this operator */
    bool skip_doc;          /**< if true, do not include this operator into any documentation */
};
} // namespace detail

} // namespace operator_

/**
 * Class representing available HILTI operators.
 *
 * Operators aren't AST nodes themselves, but they define an operator that's
 * available for instantiation as an AST expression node. Given an operator,
 * one can instantiate a corresponding AST node by passing the concrete
 * operands to the `instantiate()` method.
 */
class Operator {
public:
    template<typename T>
    using Result = ::hilti::Result<T>;

    /**
     * Constructor.
     *
     * @param meta meta data associated with the operator
     * @param builtin true if the operator is predefined statically by the compiler; false if it's generated from user
     * code (like functions and methods)
     */
    Operator(Meta meta = Meta(), bool builtin = true) : _meta(std::move(meta)), _builtin(builtin) {}

    /** Destructor. */
    virtual ~Operator() {}

    Operator(const Operator& other) = delete;
    Operator(Operator&& other) = delete;

    Operator& operator=(const Operator& other) = delete;
    Operator& operator=(Operator&& other) = delete;

    /** Returns true if `init()` has run and returned success. */
    auto isInitialized() const { return _signature.has_value(); }

    /**
     * Returns true if operator's signature has operands defined. If that's not
     * the case, the operator can be instantiated only manually, not through
     * the resolver.
     **/
    auto hasOperands() const { return _signature->operands; }

    /** Returns the operator's signature. */
    const auto& signature() const {
        assert(_signature);
        return *_signature;
    }

    /** Returns the operator's kind. */
    auto kind() const { return signature().kind; }

    /**
     * Returns if the operator is predefined statically by the compiler, rather
     * than created through user code (like functions or methods).
     */
    auto isBuiltIn() const { return _builtin; }

    /** Returns the operator's operands. */
    auto operands() const { return signature().operands->operands(); }

    /** Returns the operator's first operand. */
    auto op0() const { return operands()[0]; }

    /** Returns the operator's second operand. */
    auto op1() const { return operands()[1]; }

    /** Returns the operator's third operand. */
    auto op2() const { return operands()[2]; }

    /** Returns the operator's meta information. */
    const auto& meta() const { return _meta; }

    /** Returns the operator's documentation string. */
    const auto& doc() const { return signature().doc; }

    /**
     * Returns the C++-level name of the operator's class. Should be used only
     * for debugging purposes.
     */
    auto typename_() const { return _typename(); }

    /**
     * Returns the operator's result type, given specific operand expressions.
     * Must be implemented by operators if the signature does not define a
     * static result type.
     */
    virtual QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const;

    /**
     * Refines the operator's signature based on the given operands. This can
     * be used to change the signature to more specific types given concreate
     * operands. To not change anything, return an empty optional
     */
    virtual std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const {
        return {};
    }

    /**
     * Performs semantics validation of an instantiated operator. To record any
     * errors, add them to the given AST node.
     */
    virtual void validate(expression::ResolvedOperator* n) const {};

    /** Instantiates the operator as an AST node, given specific operand expressions. */
    virtual Result<expression::ResolvedOperator*> instantiate(Builder* builder, Expressions operands,
                                                              Meta meta) const = 0;

    /**
     * Returns a readable name describing the operator. Must be provided by
     * derived classes.
     */
    virtual std::string name() const = 0;

    /** Prints the operator in a human-readable format. */
    virtual std::string print() const;

    /** Dumps out the operator's operands in their AST node representation. */
    virtual std::string dump() const;

protected:
    friend class operator_::Registry;

    /** Initializes the operator. To be called only from the registry. */
    bool init(Builder* builder, Node* scope_root = nullptr);

    /**
     * Returns the operator's signature. Must be overridden by derived
     * classes.
     */
    virtual operator_::Signature signature(Builder* builder) const = 0;

    /** Backend for `typename_()`. Must be overridden by derived classes. */
    virtual std::string _typename() const { return util::typename_(*this); }

    /**
     * Helper to create an signature operand matching a given type.
     *
     * @param kind kind of the operand specifying passing style
     * @param t type of the operand
     */
    static operator_::Operand* operandForType(Builder* builder, parameter::Kind kind, UnqualifiedType* t,
                                              std::string doc = "");

    /**
     * Helper to create an signature operand matching the type of a given expression.
     *
     * @param kind kind of the operand specifying passing style
     * @param e expression whose type to use
     */
    static operator_::Operand* operandForExpression(Builder* builder, parameter::Kind kind, const Expressions& e,
                                                    size_t i) {
        return operandForType(builder, kind, e[i]->type()->type(), "");
    }

private:
    Meta _meta;
    bool _builtin;
    std::optional<operator_::detail::ProcessedSignature> _signature;
};

/**
 * Base class for operators representing built-in method calls on a type. The
 * base class exists so that `print()` can be customized for these.
 */
class BuiltInMemberCall : public Operator {
public:
    ~BuiltInMemberCall() override {}

    /** Customized version of `print()`. */
    std::string print() const final;
};

} // namespace hilti
