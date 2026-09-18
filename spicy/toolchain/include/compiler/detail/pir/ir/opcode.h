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
    /** The operand's affine value, if any, is read without being consumed. Unused in this slice. */
    Borrow,
    /** The operand's affine value, if any, is fully consumed; it must not be used again anywhere. */
    Consume,
    /**
     * The operand's affine discipline, if any, comes from its structure (e.g. a tuple carrying an
     * affine element) rather than from the value as a whole; the consumer derives new affine
     * values from specific slots of the operand instead of consuming the operand outright.
     */
    Forward,
};

/**
 * A closed instruction payload. Every opcode's payload shape is a dedicated struct even where two
 * opcodes happen to share an integer representation (`ArgumentPayload` vs. `TupleGetPayload`), so
 * verifier and printer code never infers payload meaning from an opcode plus a raw integer.
 */
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

/**
 * A portable byte-order value. This is PIR's own vocabulary, independent of HILTI's runtime
 * `ByteOrder` type, matching the architectural invariant that PIR does not depend on runtime
 * representations.
 */
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
 * The closed outcome contract for a parser-input operation: what happens on success, on
 * insufficient input, at premature EOD, and at a gap. This is schema-level semantics, not
 * per-instruction CFG: the same contract applies to every instance of the opcode.
 *
 * This holds only the fields the verifier, printer, or a consumer actually reads today
 * (`success_consumption_bytes` documents the read's byte width; `eod`/`gap` distinguish the two
 * failure kinds the semantic table requires to stay distinguishable). The resume condition and a
 * gap's runtime payload are real semantics (see the Semantic Contract in
 * `PLAN-parser-ir-3.md`) but are not modeled as typed fields here, since nothing in this slice
 * varies or reads them per contract; recoverable-rejection and other-fatal outcomes are omitted
 * outright rather than represented as an always-`Impossible` placeholder, since unsigned width-8
 * decoding cannot produce either.
 */
struct ParserOperationContract {
    /** Bytes consumed and the cursor advanced by on success; -1 means "not exactly-N-bytes" (unused in Step 3). */
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

inline constexpr std::span<const TypeConstraint> kNoOperandTypes{};
inline constexpr std::span<const OperandRole> kNoOperandRoles{};

inline constexpr TypeConstraint kAddOperandTypes[] = {fixedType(TypeKind::Int64), fixedType(TypeKind::Int64)};
inline constexpr OperandRole kAddOperandRoles[] = {OperandRole::Borrow, OperandRole::Borrow};

inline constexpr TypeConstraint kReturnOperandTypes[] = {sameAsFunctionResult()};
inline constexpr OperandRole kReturnOperandRoles[] = {OperandRole::Borrow};

inline constexpr TypeConstraint kTupleGetOperandTypes[] = {anyType()};
inline constexpr OperandRole kTupleGetOperandRoles[] = {OperandRole::Forward};

inline constexpr TypeConstraint kReadIntegerOperandTypes[] = {fixedType(TypeKind::ParserState)};
inline constexpr OperandRole kReadIntegerOperandRoles[] = {OperandRole::Consume};

inline constexpr TypeConstraint kFinishOperandTypes[] = {fixedType(TypeKind::ParserState), sameAsFunctionResult()};
inline constexpr OperandRole kFinishOperandRoles[] = {OperandRole::Consume, OperandRole::Consume};

inline constexpr TypeConstraint kPublishFieldOperandTypes[] = {anyType(), anyType()};
inline constexpr OperandRole kPublishFieldOperandRoles[] = {OperandRole::Consume, OperandRole::Borrow};

inline constexpr ParserOperationContract kReadIntegerContract{
    .success_consumption_bytes = 1,
    .insufficient_input = SuspendBehavior::SuspendAndRetry,
    .eod = FailureOutcome::UnexpectedEod,
    .gap = FailureOutcome::Gap,
};

// One entry per `Opcode` value, in declaration order, so `schemaFor()` can index directly without
// per-call allocation.
inline constexpr std::array<OpcodeSchema, 9> kSchemas{{
    OpcodeSchema{
        .opcode = Opcode::Constant,
        .spelling = "core.constant",
        .operand_types = kNoOperandTypes,
        .operand_roles = kNoOperandRoles,
        .result_type = fixedType(TypeKind::Int64),
        .payload_kind = PayloadKind::Int64Literal,
        .is_terminator = false,
        .is_pure = true,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::Add,
        .spelling = "core.add",
        .operand_types = kAddOperandTypes,
        .operand_roles = kAddOperandRoles,
        .result_type = sameAsOperand(),
        .payload_kind = PayloadKind::None,
        .is_terminator = false,
        .is_pure = false,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::Return,
        .spelling = "core.return",
        .operand_types = kReturnOperandTypes,
        .operand_roles = kReturnOperandRoles,
        .result_type = fixedType(TypeKind::Void),
        .payload_kind = PayloadKind::None,
        .is_terminator = true,
        .is_pure = false,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::Argument,
        .spelling = "core.argument",
        .operand_types = kNoOperandTypes,
        .operand_roles = kNoOperandRoles,
        // Its result is the indexed function parameter, not a fixed/structural constraint; the
        // verifier checks that dynamically against `Function::parameters`.
        .result_type = anyType(),
        .payload_kind = PayloadKind::Argument,
        .is_terminator = false,
        .is_pure = true,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::TupleGet,
        .spelling = "core.tuple_get",
        // Must be some tuple type; the verifier checks the payload index and selected element
        // type dynamically.
        .operand_types = kTupleGetOperandTypes,
        .operand_roles = kTupleGetOperandRoles,
        .result_type = anyType(),
        .payload_kind = PayloadKind::TupleGet,
        .is_terminator = false,
        .is_pure = true,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::ReadInteger,
        .spelling = "parser.read_integer",
        .operand_types = kReadIntegerOperandTypes,
        .operand_roles = kReadIntegerOperandRoles,
        // `tuple<parser.state, uint8>`; the verifier checks the exact structural shape, since it
        // depends on this slice's fixed width-8 payload contract.
        .result_type = anyType(),
        .payload_kind = PayloadKind::ReadInteger,
        .is_terminator = false,
        .is_pure = false,
        .parser_contract = kReadIntegerContract,
    },
    OpcodeSchema{
        .opcode = Opcode::Finish,
        .spelling = "parser.finish",
        // Operand 0 is the parser state; operand 1 is the unit value, which must match the
        // owning parser function's result type, exactly like `core.return`'s value operand.
        .operand_types = kFinishOperandTypes,
        .operand_roles = kFinishOperandRoles,
        .result_type = fixedType(TypeKind::Void),
        .payload_kind = PayloadKind::None,
        .is_terminator = true,
        .is_pure = false,
        .parser_contract = std::nullopt,
    },
    OpcodeSchema{
        .opcode = Opcode::UnitCreate,
        .spelling = "unit.create",
        .operand_types = kNoOperandTypes,
        .operand_roles = kNoOperandRoles,
        // Its result is the nominal `unit<...>` type named by the payload; the verifier checks
        // that dynamically.
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
        .operand_types = kPublishFieldOperandTypes,
        .operand_roles = kPublishFieldOperandRoles,
        .result_type = sameAsOperand(),
        .payload_kind = PayloadKind::Field,
        .is_terminator = false,
        .is_pure = false,
        .parser_contract = std::nullopt,
    },
}};

} // namespace detail

/** Returns no schema for an unrecognized opcode; never allocates. */
constexpr const OpcodeSchema* schemaFor(Opcode opcode) {
    auto index = static_cast<size_t>(opcode);
    if ( index >= detail::kSchemas.size() )
        return nullptr;

    return &detail::kSchemas[index];
}

} // namespace spicy::detail::pir::ir
