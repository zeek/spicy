// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

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
 * A closed instruction payload. Every opcode's payload shape is a dedicated struct even where two
 * opcodes happen to share an integer representation (`ArgumentPayload` vs. `TupleGetPayload`), so
 * verifier and printer code never infers payload meaning from an opcode plus a raw integer.
 */
struct Int64Literal {
    int64_t value = 0;

    friend constexpr bool operator==(Int64Literal, Int64Literal) = default;
};

struct ArgumentPayload {
    uint32_t index = 0;

    friend constexpr bool operator==(ArgumentPayload, ArgumentPayload) = default;
};

struct TupleGetPayload {
    uint32_t index = 0;

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
enum class FailureOutcome { UnexpectedEod, Gap, Impossible };

/**
 * The closed outcome contract for a parser-input operation: what happens on success, on
 * insufficient input, at premature EOD, at a gap, on a recoverable rejection, and on any other
 * fatal decoding failure. This is schema-level semantics, not per-instruction CFG: the same
 * contract applies to every instance of the opcode.
 */
struct ParserOperationContract {
    /** Bytes consumed and the cursor advanced by on success; -1 means "not exactly-N-bytes" (unused in Step 3). */
    int64_t success_consumption_bytes = 0;
    SuspendBehavior insufficient_input = SuspendBehavior::SuspendAndRetry;
    FailureOutcome eod = FailureOutcome::UnexpectedEod;
    FailureOutcome gap = FailureOutcome::Gap;
    FailureOutcome recoverable_rejection = FailureOutcome::Impossible;
    FailureOutcome fatal = FailureOutcome::Impossible;

    friend constexpr bool operator==(const ParserOperationContract&, const ParserOperationContract&) = default;
};

struct OpcodeSchema {
    Opcode opcode;
    std::string_view spelling;
    size_t operand_count;
    std::vector<TypeConstraint> operand_types; /**< one per operand, in order; size == operand_count */
    TypeConstraint result_type;
    PayloadKind payload_kind;
    bool is_terminator;
    bool is_pure;
    bool has_parser_contract = false;
    ParserOperationContract parser_contract = {};
};

/** Whether `payload` holds the alternative expected for `kind`. */
inline bool payloadMatchesKind(const InstPayload& payload, PayloadKind kind) {
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

/** Returns no schema for an unrecognized opcode. */
inline std::optional<OpcodeSchema> lookupSchema(Opcode opcode) {
    switch ( opcode ) {
        case Opcode::Constant:
            return OpcodeSchema{
                .opcode = Opcode::Constant,
                .spelling = "core.constant",
                .operand_count = 0,
                .operand_types = {},
                .result_type = fixedType(TypeKind::Int64),
                .payload_kind = PayloadKind::Int64Literal,
                .is_terminator = false,
                .is_pure = true,
            };

        case Opcode::Add:
            return OpcodeSchema{
                .opcode = Opcode::Add,
                .spelling = "core.add",
                .operand_count = 2,
                .operand_types = {fixedType(TypeKind::Int64), fixedType(TypeKind::Int64)},
                .result_type = sameAsOperand(),
                .payload_kind = PayloadKind::None,
                .is_terminator = false,
                .is_pure = false,
            };

        case Opcode::Return:
            return OpcodeSchema{
                .opcode = Opcode::Return,
                .spelling = "core.return",
                .operand_count = 1,
                .operand_types = {sameAsFunctionResult()},
                .result_type = fixedType(TypeKind::Void),
                .payload_kind = PayloadKind::None,
                .is_terminator = true,
                .is_pure = false,
            };

        case Opcode::Argument:
            return OpcodeSchema{
                .opcode = Opcode::Argument,
                .spelling = "core.argument",
                .operand_count = 0,
                .operand_types = {},
                // Its result is the indexed function parameter, not a fixed/structural constraint;
                // the verifier checks that dynamically against `Function::parameters`.
                .result_type = anyType(),
                .payload_kind = PayloadKind::Argument,
                .is_terminator = false,
                .is_pure = true,
            };

        case Opcode::TupleGet:
            return OpcodeSchema{
                .opcode = Opcode::TupleGet,
                .spelling = "core.tuple_get",
                .operand_count = 1,
                // Must be some tuple type; the verifier checks the payload index and selected
                // element type dynamically.
                .operand_types = {anyType()},
                .result_type = anyType(),
                .payload_kind = PayloadKind::TupleGet,
                .is_terminator = false,
                .is_pure = true,
            };

        case Opcode::ReadInteger:
            return OpcodeSchema{
                .opcode = Opcode::ReadInteger,
                .spelling = "parser.read_integer",
                .operand_count = 1,
                .operand_types = {fixedType(TypeKind::ParserState)},
                // `tuple<parser.state, uint8>`; the verifier checks the exact structural shape,
                // since it depends on this slice's fixed width-8 payload contract.
                .result_type = anyType(),
                .payload_kind = PayloadKind::ReadInteger,
                .is_terminator = false,
                .is_pure = false,
                .has_parser_contract = true,
                .parser_contract =
                    ParserOperationContract{
                        .success_consumption_bytes = 1,
                        .insufficient_input = SuspendBehavior::SuspendAndRetry,
                        .eod = FailureOutcome::UnexpectedEod,
                        .gap = FailureOutcome::Gap,
                        .recoverable_rejection = FailureOutcome::Impossible,
                        .fatal = FailureOutcome::Impossible,
                    },
            };

        case Opcode::Finish:
            return OpcodeSchema{
                .opcode = Opcode::Finish,
                .spelling = "parser.finish",
                .operand_count = 2,
                // Operand 0 is the parser state; operand 1 is the unit value, which must match the
                // owning parser function's result type, exactly like `core.return`'s value operand.
                .operand_types = {fixedType(TypeKind::ParserState), sameAsFunctionResult()},
                .result_type = fixedType(TypeKind::Void),
                .payload_kind = PayloadKind::None,
                .is_terminator = true,
                .is_pure = false,
            };

        case Opcode::UnitCreate:
            return OpcodeSchema{
                .opcode = Opcode::UnitCreate,
                .spelling = "unit.create",
                .operand_count = 0,
                .operand_types = {},
                // Its result is the nominal `unit<...>` type named by the payload; the verifier
                // checks that dynamically.
                .result_type = anyType(),
                .payload_kind = PayloadKind::Unit,
                .is_terminator = false,
                .is_pure = false,
            };

        case Opcode::PublishField:
            return OpcodeSchema{
                .opcode = Opcode::PublishField,
                .spelling = "unit.publish_field",
                .operand_count = 2,
                // Operand 0 is the unit value being published into; operand 1 is the field value,
                // whose exact required type depends on the payload's field declaration, so the
                // verifier checks it dynamically.
                .operand_types = {anyType(), anyType()},
                .result_type = sameAsOperand(),
                .payload_kind = PayloadKind::Field,
                .is_terminator = false,
                .is_pure = false,
            };
    }

    return std::nullopt;
}

} // namespace spicy::detail::pir::ir
