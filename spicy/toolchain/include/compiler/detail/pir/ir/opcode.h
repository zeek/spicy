// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <optional>
#include <string_view>

namespace spicy::detail::pir::ir {

enum class Opcode {
    Constant,
    Add,
    Return,
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

enum class PayloadKind {
    None,
    Int64Literal,
};

struct OpcodeSchema {
    Opcode opcode;
    std::string_view spelling;
    size_t operand_count;
    TypeConstraint operand_type;
    TypeConstraint result_type;
    PayloadKind payload_kind;
    bool is_terminator;
    bool is_pure;
};

/** Returns no schema for an unrecognized opcode. */
constexpr std::optional<OpcodeSchema> lookupSchema(Opcode opcode) {
    switch ( opcode ) {
        case Opcode::Constant:
            return OpcodeSchema{
                .opcode = Opcode::Constant,
                .spelling = "core.constant",
                .operand_count = 0,
                .operand_type = anyType(),
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
                .operand_type = fixedType(TypeKind::Int64),
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
                .operand_type = sameAsFunctionResult(),
                .result_type = fixedType(TypeKind::Void),
                .payload_kind = PayloadKind::None,
                .is_terminator = true,
                .is_pure = false,
            };
    }

    return std::nullopt;
}

} // namespace spicy::detail::pir::ir
