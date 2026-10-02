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
};

enum class TypeKind { Void, Int64, UInt8, ParserState, Unit, Tuple };

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
        case TypeKind::Unit: return ValueDiscipline::Affine;
        case TypeKind::Void:
        case TypeKind::Int64:
        case TypeKind::UInt8:
        case TypeKind::Tuple: return ValueDiscipline::Copyable;
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

using InstPayload = std::variant<std::monostate,
                                 Int64Literal,
                                 ArgumentPayload,
                                 TupleGetPayload,
                                 ReadIntegerPayload,
                                 UnitPayload,
                                 FieldPayload>;

enum class PayloadKind {
    None,
    Int64Literal,
    Argument,
    TupleGet,
    ReadInteger,
    Unit,
    Field,
};

/** Whether a suspending parser read consumes bytes and how it resumes. */
enum class SuspendBehavior { SuspendAndRetry };

/** How a parser operation completes when its outcome is a failure rather than a value. */
enum class FailureOutcome { UnexpectedEod, Gap };

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
inline constexpr OperandRole KPublishFieldOperandRoles[] = {OperandRole::Consume, OperandRole::Borrow};

inline constexpr ParserOperationContract KReadIntegerContract{
    .success_consumption_bytes = 1,
    .insufficient_input = SuspendBehavior::SuspendAndRetry,
    .eod = FailureOutcome::UnexpectedEod,
    .gap = FailureOutcome::Gap,
};

// One entry per `Opcode` value, in declaration order, so `schemaFor()` can index directly without
// per-call allocation.
inline constexpr std::array<OpcodeSchema, 9> KSchemas{{
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
}};

} // namespace detail

/** Returns no schema for an unrecognized opcode. */
constexpr const OpcodeSchema* schemaFor(Opcode opcode) {
    auto index = static_cast<size_t>(opcode);
    if ( index >= detail::KSchemas.size() )
        return nullptr;

    return &detail::KSchemas[index];
}

} // namespace spicy::detail::pir::ir
