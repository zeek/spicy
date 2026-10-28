// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <variant>

#include <spicy/compiler/detail/pir/ir/declaration.h>

namespace spicy::detail::pir::ir {

enum class Opcode {
    Constant,
    Add,
    Return,
    Argument,
    TupleGet,
    ReadInteger,
    Finish,
    UnitCreate,
    PublishField,
    RegionArgument,
    Yield,
    VectorEmpty,
    VectorAppend,
    EnterBound,
    LeaveBound,
    RepeatToBound,
    ParseSubunit,
    ReadBytes,
    OpaqueOp,
    Call,
    LocalPlace,
    Load,
    Store,
    Tuple,
    BoolConstant,
    StringConstant,
    BytesConstant,
    FieldPlace,
    Branch,
    Jump,
    Equal,
    GlobalPlace,
};

enum class TypeKind {
    Void,
    Int64,
    UInt8,
    UInt64,
    Bytes,
    ParserState,
    Unit,
    Tuple,
    Vector,
    Opaque,
    Place,
    Bool,
    String
};

enum class TypeConstraintKind {
    Any,
    Fixed,
    SameAsOperand,
    SameAsFunctionResult,
};

struct TypeConstraint {
    TypeConstraintKind kind = TypeConstraintKind::Any;
    TypeKind fixed = TypeKind::Void;
};

constexpr TypeConstraint anyType() { return TypeConstraint{.kind = TypeConstraintKind::Any}; }
constexpr TypeConstraint fixedType(TypeKind type) {
    return TypeConstraint{.kind = TypeConstraintKind::Fixed, .fixed = type};
}
constexpr TypeConstraint sameAsOperand() { return TypeConstraint{.kind = TypeConstraintKind::SameAsOperand}; }
constexpr TypeConstraint sameAsFunctionResult() {
    return TypeConstraint{.kind = TypeConstraintKind::SameAsFunctionResult};
}

/**
 * Whether a type's values follow single-consumption ("affine") discipline or ordinary copyable
 * discipline. `parser.state` and a unit-in-progress value are affine: PIR's verifier must be able
 * to prove each such value reaches at most one consuming operation, since a stale-state fork
 * (the same logical state consumed by two operations) is a PIR-level semantic error regardless of
 * how any backend happens to represent the value. A tuple inherits affine discipline from any
 * affine element it carries (e.g. `tuple<parser.state, uint8>`), since projecting that element out
 * is itself a consuming operation on the affine slot.
 */
enum class ValueDiscipline { Copyable, Affine };

/** The affine discipline intrinsic to a `TypeKind` in isolation (a `Tuple` depends on its elements). */
constexpr ValueDiscipline typeKindDiscipline(TypeKind kind) {
    switch ( kind ) {
        case TypeKind::ParserState:
        case TypeKind::Unit:
        case TypeKind::Vector: return ValueDiscipline::Affine;
        case TypeKind::Void:
        case TypeKind::Int64:
        case TypeKind::UInt8:
        case TypeKind::UInt64:
        case TypeKind::Bytes:
        case TypeKind::Tuple:
        case TypeKind::Opaque:
        case TypeKind::Place:
        case TypeKind::Bool:
        case TypeKind::String: return ValueDiscipline::Copyable;
    }

    return ValueDiscipline::Copyable;
}

/**
 * How an instruction's operand relates to that operand's affine discipline, if any. Ignored for a
 * `Copyable`-discipline operand.
 */
enum class OperandRole {
    /** The operand's affine value, if any, is read without being consumed. */
    Borrow,
    /** The operand's affine value, if any, is fully consumed. It must not be used again anywhere. */
    Consume,
    /**
     * The operand's affine discipline, if any, comes from its structure (e.g. a tuple carrying an
     * affine element) rather than from the value as a whole; the consumer derives new affine
     * values from specific slots of the operand instead of consuming the operand outright.
     */
    Forward,
};

// Every opcode gets its own payload (if necessary) so that the verifier
// and printer never infers the payload meaning.
struct Int64Literal {
    int64_t value = 0;

    friend constexpr bool operator==(Int64Literal, Int64Literal) = default;
};

/** An explicit invalid sentinel distinguishes "no real index yet" from index 0. */
struct ArgumentPayload {
    static constexpr uint32_t Invalid = UINT32_MAX;

    uint32_t index = Invalid;

    friend constexpr bool operator==(ArgumentPayload, ArgumentPayload) = default;
};

/** An explicit invalid sentinel distinguishes "no real index yet" from index 0. */
struct TupleGetPayload {
    static constexpr uint32_t Invalid = UINT32_MAX;

    uint32_t index = Invalid;

    friend constexpr bool operator==(TupleGetPayload, TupleGetPayload) = default;
};

enum class Signedness { Signed, Unsigned };

// PIR's own byte order so that it doesn't depend on hilti
enum class ByteOrder { Little, Big, Network, Host };

struct ReadIntegerPayload {
    uint32_t width = 0;
    Signedness signedness = Signedness::Unsigned;
    ByteOrder byte_order = ByteOrder::Network;

    friend constexpr bool operator==(ReadIntegerPayload, ReadIntegerPayload) = default;
};

struct UnitPayload {
    TypeDeclId unit;

    friend constexpr bool operator==(UnitPayload, UnitPayload) = default;
};

struct FieldPayload {
    DeclId field;

    friend constexpr bool operator==(FieldPayload, FieldPayload) = default;
};

struct GlobalPayload {
    GlobalId global;

    friend constexpr bool operator==(GlobalPayload, GlobalPayload) = default;
};

struct FunctionPayload {
    FunctionId function;

    friend constexpr bool operator==(FunctionPayload, FunctionPayload) = default;
};

struct ForeignFunctionPayload {
    ForeignFunctionId function;

    friend constexpr bool operator==(ForeignFunctionPayload, ForeignFunctionPayload) = default;
};

/** Successors of `core.branch`: `then_block` when its condition is true, `else_block` otherwise. */
struct BranchPayload {
    BlockId then_block;
    BlockId else_block;

    friend constexpr bool operator==(BranchPayload, BranchPayload) = default;
};

/** The successor of `core.jump`. */
struct JumpPayload {
    BlockId target;

    friend constexpr bool operator==(JumpPayload, JumpPayload) = default;
};

struct BoolLiteral {
    bool value = false;

    friend constexpr bool operator==(BoolLiteral, BoolLiteral) = default;
};

struct StringLiteral {
    std::string value;

    friend bool operator==(const StringLiteral&, const StringLiteral&) = default;
};

struct BytesLiteral {
    std::string value;

    friend bool operator==(const BytesLiteral&, const BytesLiteral&) = default;
};

struct ReadBytesPayload {
    uint64_t length = 0;

    friend constexpr bool operator==(ReadBytesPayload, ReadBytesPayload) = default;
};

using InstPayload = std::variant<std::monostate,
                                 Int64Literal,
                                 ArgumentPayload,
                                 TupleGetPayload,
                                 ReadIntegerPayload,
                                 UnitPayload,
                                 FieldPayload,
                                 FunctionPayload,
                                 ReadBytesPayload,
                                 ForeignFunctionPayload,
                                 BoolLiteral,
                                 StringLiteral,
                                 BytesLiteral,
                                 BranchPayload,
                                 JumpPayload,
                                 GlobalPayload>;

enum class PayloadKind {
    None,
    Int64Literal,
    Argument,
    TupleGet,
    ReadInteger,
    Unit,
    Field,
    Function,
    ReadBytes,
    ForeignFunction,
    BoolLiteral,
    StringLiteral,
    BytesLiteral,
    Branch,
    Jump,
    Global,
};

/** Whether a suspending parser read consumes bytes and how it resumes. */
enum class SuspendBehavior { SuspendAndRetry };

/** How a parser operation completes when its outcome is a failure rather than a value. */
enum class FailureOutcome { UnexpectedEod, Gap, BoundExceeded, InvalidBound };
enum class FailureCursor { OperationStart, Current };

/**
 * Each opcode has a contract for how it behaves on success, insufficient
 * input, etc. This is high-level in the parser rather than modelled as procedural
 * code. The same contract applies to ALL opcodes of the same type. Any new
 * contract expectations may be added as the need arises.
 */
struct ParserOperationContract {
    /** Bytes consumed and the cursor advanced by on success; -1 means "not exactly-N-bytes." */
    int64_t success_consumption_bytes = 0;
    SuspendBehavior insufficient_input = SuspendBehavior::SuspendAndRetry;
    FailureOutcome eod = FailureOutcome::UnexpectedEod;
    FailureOutcome gap = FailureOutcome::Gap;
    FailureOutcome bound = FailureOutcome::BoundExceeded;
    FailureCursor failure_cursor = FailureCursor::OperationStart;

    friend constexpr bool operator==(const ParserOperationContract&, const ParserOperationContract&) = default;
};

struct OpcodeSchema {
    Opcode opcode;
    std::string_view spelling;
    std::span<const TypeConstraint> operand_types; /**< one per operand, in order */
    std::span<const OperandRole> operand_roles;    /**< one per operand, in order; parallel to `operand_types` */
    TypeConstraint result_type;
    PayloadKind payload_kind;
    bool is_terminator;
    bool is_pure;
    bool variadic = false;
    /** Absent means the opcode has no parser-input outcome contract at all. */
    std::optional<ParserOperationContract> parser_contract;

    constexpr size_t operandCount() const { return operand_types.size(); }
};

/** Whether `payload` holds the alternative expected for `kind`. */
constexpr bool payloadMatchesKind(const InstPayload& payload, PayloadKind kind) {
    switch ( kind ) {
        case PayloadKind::None: return std::holds_alternative<std::monostate>(payload);
        case PayloadKind::Int64Literal: return std::holds_alternative<Int64Literal>(payload);
        case PayloadKind::Argument: return std::holds_alternative<ArgumentPayload>(payload);
        case PayloadKind::TupleGet: return std::holds_alternative<TupleGetPayload>(payload);
        case PayloadKind::ReadInteger: return std::holds_alternative<ReadIntegerPayload>(payload);
        case PayloadKind::Unit: return std::holds_alternative<UnitPayload>(payload);
        case PayloadKind::Field: return std::holds_alternative<FieldPayload>(payload);
        case PayloadKind::Function: return std::holds_alternative<FunctionPayload>(payload);
        case PayloadKind::ReadBytes: return std::holds_alternative<ReadBytesPayload>(payload);
        case PayloadKind::ForeignFunction: return std::holds_alternative<ForeignFunctionPayload>(payload);
        case PayloadKind::BoolLiteral: return std::holds_alternative<BoolLiteral>(payload);
        case PayloadKind::StringLiteral: return std::holds_alternative<StringLiteral>(payload);
        case PayloadKind::BytesLiteral: return std::holds_alternative<BytesLiteral>(payload);
        case PayloadKind::Branch: return std::holds_alternative<BranchPayload>(payload);
        case PayloadKind::Jump: return std::holds_alternative<JumpPayload>(payload);
        case PayloadKind::Global: return std::holds_alternative<GlobalPayload>(payload);
    }

    return false;
}

namespace detail {

inline constexpr std::span<const TypeConstraint> KNoOperandTypes{};
inline constexpr std::span<const OperandRole> KNoOperandRoles{};

inline constexpr TypeConstraint KAddOperandTypes[] = {fixedType(TypeKind::Int64), fixedType(TypeKind::Int64)};
inline constexpr OperandRole KAddOperandRoles[] = {OperandRole::Borrow, OperandRole::Borrow};

inline constexpr TypeConstraint KReturnOperandTypes[] = {sameAsFunctionResult()};
inline constexpr OperandRole KReturnOperandRoles[] = {OperandRole::Borrow};

inline constexpr TypeConstraint KTupleGetOperandTypes[] = {anyType()};
inline constexpr OperandRole KTupleGetOperandRoles[] = {OperandRole::Forward};

inline constexpr TypeConstraint KReadIntegerOperandTypes[] = {fixedType(TypeKind::ParserState)};
inline constexpr OperandRole KReadIntegerOperandRoles[] = {OperandRole::Consume};

inline constexpr TypeConstraint KFinishOperandTypes[] = {fixedType(TypeKind::ParserState), sameAsFunctionResult()};
inline constexpr OperandRole KFinishOperandRoles[] = {OperandRole::Consume, OperandRole::Consume};

inline constexpr TypeConstraint KPublishFieldOperandTypes[] = {anyType(), anyType()};
inline constexpr OperandRole KPublishFieldOperandRoles[] = {OperandRole::Consume, OperandRole::Consume};

inline constexpr TypeConstraint KVectorAppendOperandTypes[] = {fixedType(TypeKind::Vector), anyType()};
inline constexpr OperandRole KVectorAppendOperandRoles[] = {OperandRole::Consume, OperandRole::Consume};

inline constexpr TypeConstraint KEnterBoundOperandTypes[] = {fixedType(TypeKind::ParserState), anyType()};
inline constexpr OperandRole KEnterBoundOperandRoles[] = {OperandRole::Consume, OperandRole::Borrow};

inline constexpr TypeConstraint KParseStateOperandTypes[] = {fixedType(TypeKind::ParserState)};
inline constexpr OperandRole KParseStateOperandRoles[] = {OperandRole::Consume};

inline constexpr TypeConstraint KPlaceOperandTypes[] = {anyType()};
inline constexpr OperandRole KPlaceOperandRoles[] = {OperandRole::Borrow};

inline constexpr TypeConstraint KFieldPlaceOperandTypes[] = {anyType()};
inline constexpr OperandRole KFieldPlaceOperandRoles[] = {OperandRole::Borrow};

inline constexpr TypeConstraint KStoreOperandTypes[] = {anyType(), anyType()};
inline constexpr OperandRole KStoreOperandRoles[] = {OperandRole::Borrow, OperandRole::Borrow};

inline constexpr TypeConstraint KBranchOperandTypes[] = {fixedType(TypeKind::Bool)};
inline constexpr OperandRole KBranchOperandRoles[] = {OperandRole::Borrow};
inline constexpr TypeConstraint KEqualOperandTypes[] = {anyType(), anyType()};
inline constexpr OperandRole KEqualOperandRoles[] = {OperandRole::Borrow, OperandRole::Borrow};
inline constexpr TypeConstraint KVariadicOperandTypes[] = {anyType()};
inline constexpr OperandRole KVariadicOperandRoles[] = {OperandRole::Consume};

inline constexpr ParserOperationContract KReadIntegerContract{
    .success_consumption_bytes = -1,
    .insufficient_input = SuspendBehavior::SuspendAndRetry,
    .eod = FailureOutcome::UnexpectedEod,
    .gap = FailureOutcome::Gap,
};

inline constexpr ParserOperationContract KReadBytesContract{
    .success_consumption_bytes = -1,
    .insufficient_input = SuspendBehavior::SuspendAndRetry,
    .eod = FailureOutcome::UnexpectedEod,
    .gap = FailureOutcome::Gap,
    .bound = FailureOutcome::BoundExceeded,
    .failure_cursor = FailureCursor::OperationStart,
};

inline constexpr ParserOperationContract KSubunitContract{
    .success_consumption_bytes = -1,
    .insufficient_input = SuspendBehavior::SuspendAndRetry,
    .eod = FailureOutcome::UnexpectedEod,
    .gap = FailureOutcome::Gap,
    .bound = FailureOutcome::BoundExceeded,
    .failure_cursor = FailureCursor::Current,
};

// One entry per `Opcode` value, in declaration order, so `schemaFor()` can index directly without
// per-call allocation.
inline constexpr std::array<OpcodeSchema, 32> KSchemas{{
    OpcodeSchema{
        .opcode = Opcode::Constant,
        .spelling = "core.constant",
        .operand_types = KNoOperandTypes,
        .operand_roles = KNoOperandRoles,
        .result_type = fixedType(TypeKind::Int64),
        .payload_kind = PayloadKind::Int64Literal,
        .is_terminator = false,
        .is_pure = true,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::Add,
        .spelling = "core.add",
        .operand_types = KAddOperandTypes,
        .operand_roles = KAddOperandRoles,
        .result_type = sameAsOperand(),
        .payload_kind = PayloadKind::None,
        .is_terminator = false,
        .is_pure = false,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::Return,
        .spelling = "core.return",
        .operand_types = KReturnOperandTypes,
        .operand_roles = KReturnOperandRoles,
        .result_type = fixedType(TypeKind::Void),
        .payload_kind = PayloadKind::None,
        .is_terminator = true,
        .is_pure = false,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::Argument,
        .spelling = "core.argument",
        .operand_types = KNoOperandTypes,
        .operand_roles = KNoOperandRoles,
        .result_type = anyType(),
        .payload_kind = PayloadKind::Argument,
        .is_terminator = false,
        .is_pure = true,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::TupleGet,
        .spelling = "core.tuple_get",
        .operand_types = KTupleGetOperandTypes,
        .operand_roles = KTupleGetOperandRoles,
        .result_type = anyType(),
        .payload_kind = PayloadKind::TupleGet,
        .is_terminator = false,
        .is_pure = true,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::ReadInteger,
        .spelling = "parser.read_integer",
        .operand_types = KReadIntegerOperandTypes,
        .operand_roles = KReadIntegerOperandRoles,
        .result_type = anyType(),
        .payload_kind = PayloadKind::ReadInteger,
        .is_terminator = false,
        .is_pure = false,
        .parser_contract = KReadIntegerContract,
    },
    OpcodeSchema{
        .opcode = Opcode::Finish,
        .spelling = "parser.finish",
        // Operand 0 is the parser state; operand 1 is the unit value, which must match the
        // owning parser function's result type, exactly like `core.return`'s value operand.
        .operand_types = KFinishOperandTypes,
        .operand_roles = KFinishOperandRoles,
        .result_type = fixedType(TypeKind::Void),
        .payload_kind = PayloadKind::None,
        .is_terminator = true,
        .is_pure = false,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::UnitCreate,
        .spelling = "unit.create",
        .operand_types = KNoOperandTypes,
        .operand_roles = KNoOperandRoles,
        .result_type = anyType(),
        .payload_kind = PayloadKind::Unit,
        .is_terminator = false,
        .is_pure = false,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::PublishField,
        .spelling = "unit.publish_field",
        // Operand 0 is the unit value being published into; operand 1 is the field value, whose
        // exact required type depends on the payload's field declaration, so the verifier checks
        // it dynamically.
        .operand_types = KPublishFieldOperandTypes,
        .operand_roles = KPublishFieldOperandRoles,
        .result_type = sameAsOperand(),
        .payload_kind = PayloadKind::Field,
        .is_terminator = false,
        .is_pure = false,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{.opcode = Opcode::RegionArgument,
                 .spelling = "core.region_argument",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = anyType(),
                 .payload_kind = PayloadKind::Argument,
                 .is_terminator = false,
                 .is_pure = true},
    OpcodeSchema{.opcode = Opcode::Yield,
                 .spelling = "core.yield",
                 .operand_types = KVariadicOperandTypes,
                 .operand_roles = KVariadicOperandRoles,
                 .result_type = fixedType(TypeKind::Void),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = true,
                 .is_pure = false,
                 .variadic = true},
    OpcodeSchema{.opcode = Opcode::VectorEmpty,
                 .spelling = "core.vector_empty",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = fixedType(TypeKind::Vector),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::VectorAppend,
                 .spelling = "core.vector_append",
                 .operand_types = KVectorAppendOperandTypes,
                 .operand_roles = KVectorAppendOperandRoles,
                 .result_type = sameAsOperand(),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::EnterBound,
                 .spelling = "parser.enter_bound",
                 .operand_types = KEnterBoundOperandTypes,
                 .operand_roles = KEnterBoundOperandRoles,
                 .result_type = fixedType(TypeKind::ParserState),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::LeaveBound,
                 .spelling = "parser.leave_bound",
                 .operand_types = KParseStateOperandTypes,
                 .operand_roles = KParseStateOperandRoles,
                 .result_type = fixedType(TypeKind::ParserState),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::RepeatToBound,
                 .spelling = "parser.repeat_to_bound",
                 .operand_types = KVariadicOperandTypes,
                 .operand_roles = KVariadicOperandRoles,
                 .result_type = fixedType(TypeKind::Tuple),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false,
                 .variadic = true,
                 .parser_contract = KSubunitContract},
    OpcodeSchema{.opcode = Opcode::ParseSubunit,
                 .spelling = "parser.parse_subunit",
                 .operand_types = KParseStateOperandTypes,
                 .operand_roles = KParseStateOperandRoles,
                 .result_type = fixedType(TypeKind::Tuple),
                 .payload_kind = PayloadKind::Function,
                 .is_terminator = false,
                 .is_pure = false,
                 .parser_contract = KSubunitContract},
    OpcodeSchema{.opcode = Opcode::ReadBytes,
                 .spelling = "parser.read_bytes",
                 .operand_types = KParseStateOperandTypes,
                 .operand_roles = KParseStateOperandRoles,
                 .result_type = fixedType(TypeKind::Tuple),
                 .payload_kind = PayloadKind::ReadBytes,
                 .is_terminator = false,
                 .is_pure = false,
                 .parser_contract = KReadBytesContract},
    OpcodeSchema{.opcode = Opcode::OpaqueOp,
                 .spelling = "opaque.op",
                 // The operands are checked against the payload's declaration rather than a static constraint,
                 // so an arbitrary count is allowed here. The result is that declaration's result type.
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = anyType(),
                 .payload_kind = PayloadKind::ForeignFunction,
                 .is_terminator = false,
                 .is_pure = false,
                 .variadic = true},
    OpcodeSchema{.opcode = Opcode::Call,
                 .spelling = "core.call",
                 // Operands follow the callee's parameters, which the verifier checks against the payload.
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = anyType(),
                 .payload_kind = PayloadKind::Function,
                 .is_terminator = false,
                 .is_pure = false,
                 .variadic = true},
    OpcodeSchema{.opcode = Opcode::LocalPlace,
                 .spelling = "core.local_place",
                 .operand_types = KPlaceOperandTypes,
                 .operand_roles = KPlaceOperandRoles,
                 .result_type = anyType(),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::Load,
                 .spelling = "core.load",
                 .operand_types = KPlaceOperandTypes,
                 .operand_roles = KPlaceOperandRoles,
                 .result_type = anyType(),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::Store,
                 .spelling = "core.store",
                 .operand_types = KStoreOperandTypes,
                 .operand_roles = KStoreOperandRoles,
                 .result_type = fixedType(TypeKind::Void),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::Tuple,
                 .spelling = "core.tuple",
                 // Operands are the elements, in order; the result is the tuple of their types.
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = fixedType(TypeKind::Tuple),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = true,
                 .variadic = true},
    OpcodeSchema{.opcode = Opcode::BoolConstant,
                 .spelling = "core.bool_constant",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = fixedType(TypeKind::Bool),
                 .payload_kind = PayloadKind::BoolLiteral,
                 .is_terminator = false,
                 .is_pure = true},
    OpcodeSchema{.opcode = Opcode::StringConstant,
                 .spelling = "core.string_constant",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = fixedType(TypeKind::String),
                 .payload_kind = PayloadKind::StringLiteral,
                 .is_terminator = false,
                 .is_pure = true},
    OpcodeSchema{.opcode = Opcode::BytesConstant,
                 .spelling = "core.bytes_constant",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = fixedType(TypeKind::Bytes),
                 .payload_kind = PayloadKind::BytesLiteral,
                 .is_terminator = false,
                 .is_pure = true},
    OpcodeSchema{.opcode = Opcode::FieldPlace,
                 .spelling = "unit.field_place",
                 // Operand 0 is the unit being parsed, borrowed to address one of its fields as a place.
                 .operand_types = KFieldPlaceOperandTypes,
                 .operand_roles = KFieldPlaceOperandRoles,
                 .result_type = anyType(),
                 .payload_kind = PayloadKind::Field,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::Branch,
                 .spelling = "core.branch",
                 // Operand 0 is the condition; both successors are in the payload.
                 .operand_types = KBranchOperandTypes,
                 .operand_roles = KBranchOperandRoles,
                 .result_type = fixedType(TypeKind::Void),
                 .payload_kind = PayloadKind::Branch,
                 .is_terminator = true,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::Jump,
                 .spelling = "core.jump",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = fixedType(TypeKind::Void),
                 .payload_kind = PayloadKind::Jump,
                 .is_terminator = true,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::Equal,
                 .spelling = "core.equal",
                 // Both operands have the same type, which the verifier checks against the comparable types.
                 .operand_types = KEqualOperandTypes,
                 .operand_roles = KEqualOperandRoles,
                 .result_type = fixedType(TypeKind::Bool),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = true},
    OpcodeSchema{.opcode = Opcode::GlobalPlace,
                 .spelling = "core.global_place",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = anyType(),
                 .payload_kind = PayloadKind::Global,
                 .is_terminator = false,
                 .is_pure = false},
}};

} // namespace detail

/** Returns no schema for an unrecognized opcode. */
constexpr const OpcodeSchema* schemaFor(Opcode opcode) {
    auto index = static_cast<size_t>(opcode);
    if ( index >= detail::KSchemas.size() )
        return nullptr;

    return &detail::KSchemas[index];
}

/** The effects used by passes that must preserve parser outcomes and publication order. */
struct OperationEffects {
    bool reads_input = false;
    bool changes_parser_state = false;
    bool allocates = false;
    bool publishes = false;
    bool may_suspend = false;
    bool may_fail = false;
    bool reads_world = false;
    bool writes_world = false;
    bool reads_places = false;
    bool writes_places = false;
};

constexpr OperationEffects effectsFor(Opcode opcode) {
    switch ( opcode ) {
        case Opcode::ReadInteger:
        case Opcode::ReadBytes:
        case Opcode::ParseSubunit:
            return {.reads_input = true, .changes_parser_state = true, .may_suspend = true, .may_fail = true};
        case Opcode::RepeatToBound:
            return {.reads_input = true,
                    .changes_parser_state = true,
                    .allocates = true,
                    .may_suspend = true,
                    .may_fail = true};
        case Opcode::EnterBound:
        case Opcode::LeaveBound: return {.changes_parser_state = true, .may_fail = true};
        case Opcode::VectorEmpty:
        case Opcode::VectorAppend:
        case Opcode::UnitCreate: return {.allocates = true};
        case Opcode::PublishField: return {.publishes = true};
        // A foreign function may read and write any state, so it is opaque to every analysis.
        case Opcode::OpaqueOp:
        case Opcode::Call:
            return {.may_fail = true,
                    .reads_world = true,
                    .writes_world = true,
                    .reads_places = true,
                    .writes_places = true};
        case Opcode::LocalPlace: return {.allocates = true};
        case Opcode::Load: return {.reads_places = true};
        case Opcode::Store: return {.writes_places = true};
        case Opcode::Tuple:
        case Opcode::BoolConstant:
        case Opcode::StringConstant:
        case Opcode::BytesConstant: return {};
        case Opcode::FieldPlace:
        case Opcode::GlobalPlace: return {.reads_places = true};
        case Opcode::Finish:
        case Opcode::Yield:
        case Opcode::Return:
        case Opcode::Add:
        case Opcode::Constant:
        case Opcode::Argument:
        case Opcode::RegionArgument:
        case Opcode::TupleGet:
        case Opcode::Branch:
        case Opcode::Jump:
        case Opcode::Equal: return {};
    }
    return {.reads_input = true,
            .changes_parser_state = true,
            .allocates = true,
            .publishes = true,
            .may_suspend = true,
            .may_fail = true};
}

/** Returns the per-instance input contract for operations with immediate byte counts. */
constexpr std::optional<ParserOperationContract> parserContractFor(Opcode opcode, const InstPayload& payload) {
    const auto* schema = schemaFor(opcode);
    if ( ! schema || ! schema->parser_contract )
        return std::nullopt;
    auto contract = *schema->parser_contract;
    if ( opcode == Opcode::ReadInteger ) {
        if ( const auto* read = std::get_if<ReadIntegerPayload>(&payload) )
            contract.success_consumption_bytes = read->width / 8;
    }
    else if ( opcode == Opcode::ReadBytes ) {
        if ( const auto* read = std::get_if<ReadBytesPayload>(&payload) )
            contract.success_consumption_bytes = read->length <= INT64_MAX ? static_cast<int64_t>(read->length) : -1;
    }
    return contract;
}

} // namespace spicy::detail::pir::ir
