// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

#include <spicy/compiler/detail/pir/ir/declaration.h>

namespace spicy::detail::pir::ir {

/**
 * @defgroup pir_opcodes PIR opcodes
 *
 * PIR instruction semantics
 */

/**
 * A PIR instruction's operation
 *
 * @ingroup pir_opcodes
 */
enum class Opcode {
    /**
     * Adds two values of the same integer type, with the result in that type. Overflow fails at runtime.
     */
    Add,
    /**
     * Returns from a function. The operand must have the same type as function return.
     */
    Return,
    /**
     * Gets the argument at the provided position. Same type as the resulting value.
     */
    Argument,
    /**
     * Gets the tuple value at the provided position. Same type as that tuple position's value.
     */
    TupleGet,
    /**
     * Parses an integer from the provided parser state. Returns a tuple with the updated
     * parser state and the parsed value.
     *
     * Fails at the end of input or its bound with `expecting N bytes for unpacking value (A byte(s) available)`.
     */
    ReadInteger,
    /**
     * Finishes parsing for the unit and returns the parsed value. This is an alternative
     * to a simple function return, but for parse functions.
     */
    Finish,
    /**
     * Initializes a unit for parsing.
     */
    UnitCreate,
    /**
     * Marks the field as done parsing and returns the updated unit value. This is the
     * point where the field will get stored and is its fully parsed value.
     */
    PublishField,
    /**
     * Retrieves an argument to a nested region. Same as Argument, but for the region.
     */
    RegionArgument,
    /**
     * Supplies the value(s) of a nested region. Must return what the owning operation
     * expects.
     */
    Yield,
    /**
     * Creates an empty vector of the specified type.
     */
    VectorEmpty,
    /**
     * Appends an element to the supplied vector. It consumes the collection and returns
     * the updated collection.
     */
    VectorAppend,
    /**
     * Enters a bounded region, where the parser state is bounded to a certain byte
     * length. The returned bounded parser state is used for various other bounded
     * operations.
     *
     * Fails with `&size value N exceeds the remaining stream offset range` if the bound is past the largest offset.
     */
    EnterBound,
    /**
     * Leaves a bounded region, which was entered via EnterBound. Must consume the full
     * bounded parser state.
     *
     * Fails with `&size amount not consumed: expected N bytes, but got M bytes` otherwise.
     */
    LeaveBound,
    /**
     * Repeats until a bound is reached. Returns a tuple containing the parser state and
     * the carried value.
     *
     * Fails with `loop body did not change input position, possible infinite loop` if an iteration consumes nothing.
     */
    RepeatToBound,
    /**
     * Parses a unit from within some other unit. Returns a tuple with the updated parser
     * state and the parsed value.
     */
    ParseSubunit,
    /**
     * Parses as many bytes as its `uint64` length operand says. Returns a tuple with the updated parser state and the
     * parsed value.
     *
     * Fails at the end of input or its bound with `expected N bytes (A available)`.
     */
    ReadBytes,
    /**
     * Invokes a foreign function (via its payload). Operands are call arguments. Result
     * type matches the declared result.
     *
     * PIR does not inspect opaque calls and their implementation. These may potentially
     * read or write external state.
     */
    OpaqueOp,
    /**
     * A simple call for a user-defined function. Operands are call operands.
     */
    Call,
    /**
     * A local storage location. This distinguishes SSA values from the legitimate user-defined variables.
     */
    LocalPlace,
    /**
     * Retrieves the value from a place.
     */
    Load,
    /**
     * Stores the value into a place.
     */
    Store,
    /**
     * Creates a tuple with the provided operands.
     */
    Tuple,
    /**
     * Creates a boolean.
     */
    BoolConstant,
    /**
     * Creates a string.
     */
    StringConstant,
    /**
     * Creates a bytes constant.
     */
    BytesConstant,
    /**
     * Storage of a field.
     */
    FieldPlace,
    /**
     * If-then-else. First operand is the condition. The payload contains two blocks for
     * the then/else results.
     */
    Branch,
    /**
     * An unconditional jump. Used, for example, in an if statement to jump to
     * the next block.
     */
    Jump,
    /**
     * Checks for equality.
     */
    Equal,
    /**
     * A reference to a global variable.
     */
    GlobalPlace,
    /**
     * An integer constant. The result type gives its width and signedness.
     */
    IntConstant,
    /**
     * A constant for foreign values, such as hilti::Protocol.
     */
    ForeignConstant,
    /**
     * A port constant.
     */
    PortConstant,
    /**
     * Produces an empty set.
     */
    SetEmpty,
    /**
     * Inserts an element into a set. Consumes the collection and returns the updated
     * set.
     */
    SetInsert,
    /**
     * Tells the runtime that it is done with input before the current cursor. Returns
     * new parser state.
     */
    ReleaseInput,
    /**
     * Converts its operand to the result type by the rule its payload names. Each rule is one primitive step; the
     * frontend has already chosen it, so PIR never selects or ranks conversions.
     */
    Convert,
    /**
     * Reads the value that the last `core.upsilon` targeting this Phi wrote into its shadow. Every path to a Phi must
     * write the shadow after the Phi's previous execution, and no path may write it twice without the Phi in between.
     * A Phi may appear anywhere in its function's body.
     */
    Phi,
    /**
     * Writes its operand into the shadow of the `core.phi` that its payload names. The target is not an operand and not
     * a use of the Phi's result. An affine operand is consumed.
     */
    Upsilon,
    /**
     * Transfers control to the target of the case whose value equals the integer operand, or to the default target if
     * no case does. Several cases may share a target.
     */
    Switch,
    /**
     * Parses the bytes literal of its payload. Returns a tuple with the updated parser state and the literal.
     *
     * Fails at the end of input or its bound with `expected N bytes for bytes literal "L" (A available)`, and with
     * `expected bytes literal "L" but input starts with "I"` on other input.
     */
    ExpectBytes,
    /**
     * Ends the parser function with a parse error whose description is its string operand.
     */
    Fail,
    /**
     * Matches the regular expression of its payload at the start of the input. Returns a tuple with the updated
     * parser state and the matched bytes, which end at the cursor.
     *
     * The match is anchored and the longest one. It is decided as soon as no transition is possible from the current
     * state, or at the end of input or its bound, whichever comes first. An empty match succeeds. Suspending for more
     * input continues the match instead of retrying it. Fails with `failed to match regular expression`.
     */
    MatchRegExp,
    /**
     * Consumes the longest run of bytes that are in the set of its payload, and returns a tuple with the updated parser
     * state and the run. The run ends at the first byte outside the set, at the end of input, or at the bound. An empty
     * run fails with `failed to match regular expression` if the payload says that a run needs a byte.
     *
     * It is `parser.match_regexp` of a single byte class repeated, without the matcher.
     */
    ScanBytes,
    /**
     * Looks at the input without consuming it, and returns an `int64` that tells which literal of its payload the input
     * starts with: `k` in 1..n is the index of the longest literal that matches, `0` is no match, and `-1` is the end
     * of input with no byte available. It waits until the longest literal's length is available or the input ends, and
     * an active byte bound ends the input. Its only failure is a gap. Borrows the parser state.
     */
    PeekLiterals,
    /**
     * The offset of the cursor of its parser state, as a `uint64`. Borrows the parser state.
     */
    Offset,
    /**
     * Passes its parser state through, unless the state's offset equals its second operand, a `uint64` offset that was
     * read earlier. Then it fails with `loop body did not change input position, possible infinite loop`.
     */
    RequireProgress,
};

enum class TypeKind { Void, Integer, Bytes, ParserState, Unit, Tuple, Vector, Set, Opaque, Place, Bool, String };

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
        case TypeKind::Vector:
        case TypeKind::Set: return ValueDiscipline::Affine;
        case TypeKind::Void:
        case TypeKind::Integer:
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

/**
 * The bits of an integer constant in two's complement, truncated to the width of the constant's type. Bits above
 * that width are zero. The type says whether the bits are signed.
 */
struct IntegerLiteral {
    uint64_t bits = 0;

    friend constexpr bool operator==(IntegerLiteral, IntegerLiteral) = default;
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

/** The regular expression that `parser.match_regexp` matches. */
struct RegExpPayload {
    RegExpId regexp;

    friend constexpr bool operator==(RegExpPayload, RegExpPayload) = default;
};

/** The byte set and minimum length of `parser.scan_bytes`. */
struct ScanBytesPayload {
    /** Byte `b` is a member if bit `b % 64` of word `b / 64` is set. */
    std::array<uint64_t, 4> set{};
    bool at_least_one = false; /**< an empty run fails */

    friend constexpr bool operator==(const ScanBytesPayload&, const ScanBytesPayload&) = default;
};

/** The literals that `parser.peek_literals` tells apart. They are distinct and not empty. */
struct LiteralSetPayload {
    std::vector<std::string> literals;

    friend bool operator==(const LiteralSetPayload&, const LiteralSetPayload&) = default;
};

struct GlobalPayload {
    GlobalId global;

    friend constexpr bool operator==(GlobalPayload, GlobalPayload) = default;
};

/** The transport protocol of a port, as the runtime's `hilti::rt::Protocol` names it. */
enum class Transport { TCP, UDP, ICMP };

struct PortLiteral {
    uint16_t number = 0;
    Transport transport = Transport::TCP;

    friend constexpr bool operator==(PortLiteral, PortLiteral) = default;
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

/**
 * A primitive conversion. Each rule states which operand and result types it accepts.
 *
 * - `IntegerWiden`: `uintN` to `uintM` or `intM`, or `intN` to `intM`, with M > N. It cannot fail.
 * - `IntegerToBool`: any integer to `bool`, true when nonzero. It cannot fail.
 */
enum class ConversionRule { IntegerWiden, IntegerToBool };

struct ConversionPayload {
    ConversionRule rule = ConversionRule::IntegerWiden;

    friend constexpr bool operator==(ConversionPayload, ConversionPayload) = default;
};

/** The `core.phi` that a `core.upsilon` writes. */
struct UpsilonPayload {
    InstId phi;

    friend constexpr bool operator==(UpsilonPayload, UpsilonPayload) = default;
};

/** One case of `core.switch`: the value it matches, in its operand's type, and its target. */
struct SwitchCase {
    IntegerLiteral value;
    BlockId target;

    friend constexpr bool operator==(SwitchCase, SwitchCase) = default;
};

/** The successors of `core.switch`. */
struct SwitchPayload {
    std::vector<SwitchCase> cases;
    BlockId default_target;

    friend bool operator==(const SwitchPayload&, const SwitchPayload&) = default;
};

using InstPayload = std::variant<std::monostate,
                                 IntegerLiteral,
                                 ArgumentPayload,
                                 TupleGetPayload,
                                 ReadIntegerPayload,
                                 UnitPayload,
                                 FieldPayload,
                                 FunctionPayload,
                                 ForeignFunctionPayload,
                                 BoolLiteral,
                                 StringLiteral,
                                 BytesLiteral,
                                 BranchPayload,
                                 JumpPayload,
                                 GlobalPayload,
                                 PortLiteral,
                                 ConversionPayload,
                                 UpsilonPayload,
                                 SwitchPayload,
                                 RegExpPayload,
                                 ScanBytesPayload,
                                 LiteralSetPayload>;

enum class PayloadKind {
    None,
    IntegerLiteral,
    Argument,
    TupleGet,
    ReadInteger,
    Unit,
    Field,
    Function,
    ForeignFunction,
    BoolLiteral,
    StringLiteral,
    BytesLiteral,
    Branch,
    Jump,
    Global,
    Port,
    Conversion,
    Upsilon,
    Switch,
    RegExp,
    ScanBytes,
    LiteralSet,
};

/** Whether a suspending parser read consumes bytes and how it resumes. */
enum class SuspendBehavior {
    /** The operation starts over on resumption, so it only needs the input that it has not yet consumed. */
    SuspendAndRetry,
    /** The operation resumes with its internal progress intact. Only the backend holds that progress. */
    SuspendAndContinue,
};

/** How a parser operation completes when its outcome is a failure rather than a value. */
enum class FailureOutcome {
    UnexpectedEod,
    Gap,
    BoundExceeded,
    InvalidBound,
    Mismatch,
    Result, /**< not a failure: the operation completes with a result that says so */
};
enum class FailureCursor { OperationStart, Current };

/**
 * Each opcode has a contract for how it behaves on success, insufficient
 * input, etc. A failure carries a description, which each opcode's documentation gives as legacy parsing words it, and
 * the location of the failing operation. A read that crosses a bound fails as if the input ended there, with the bytes
 * up to the bound available. This is high-level in the parser rather than modelled as procedural
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
    /** The outcome when the input does not match what the operation expects, if it expects anything. */
    std::optional<FailureOutcome> mismatch;
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
        case PayloadKind::IntegerLiteral: return std::holds_alternative<IntegerLiteral>(payload);
        case PayloadKind::Argument: return std::holds_alternative<ArgumentPayload>(payload);
        case PayloadKind::TupleGet: return std::holds_alternative<TupleGetPayload>(payload);
        case PayloadKind::ReadInteger: return std::holds_alternative<ReadIntegerPayload>(payload);
        case PayloadKind::Unit: return std::holds_alternative<UnitPayload>(payload);
        case PayloadKind::Field: return std::holds_alternative<FieldPayload>(payload);
        case PayloadKind::Function: return std::holds_alternative<FunctionPayload>(payload);
        case PayloadKind::ForeignFunction: return std::holds_alternative<ForeignFunctionPayload>(payload);
        case PayloadKind::BoolLiteral: return std::holds_alternative<BoolLiteral>(payload);
        case PayloadKind::StringLiteral: return std::holds_alternative<StringLiteral>(payload);
        case PayloadKind::BytesLiteral: return std::holds_alternative<BytesLiteral>(payload);
        case PayloadKind::Branch: return std::holds_alternative<BranchPayload>(payload);
        case PayloadKind::Jump: return std::holds_alternative<JumpPayload>(payload);
        case PayloadKind::Global: return std::holds_alternative<GlobalPayload>(payload);
        case PayloadKind::Port: return std::holds_alternative<PortLiteral>(payload);
        case PayloadKind::Conversion: return std::holds_alternative<ConversionPayload>(payload);
        case PayloadKind::Upsilon: return std::holds_alternative<UpsilonPayload>(payload);
        case PayloadKind::Switch: return std::holds_alternative<SwitchPayload>(payload);
        case PayloadKind::RegExp: return std::holds_alternative<RegExpPayload>(payload);
        case PayloadKind::ScanBytes: return std::holds_alternative<ScanBytesPayload>(payload);
        case PayloadKind::LiteralSet: return std::holds_alternative<LiteralSetPayload>(payload);
    }

    return false;
}

namespace detail {

inline constexpr std::span<const TypeConstraint> KNoOperandTypes{};
inline constexpr std::span<const OperandRole> KNoOperandRoles{};

// Both operands have the same integer type, which the verifier checks; the result has that type too.
inline constexpr TypeConstraint KAddOperandTypes[] = {anyType(), anyType()};
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
inline constexpr TypeConstraint KSetInsertOperandTypes[] = {fixedType(TypeKind::Set), anyType()};
inline constexpr OperandRole KSetInsertOperandRoles[] = {OperandRole::Consume, OperandRole::Consume};

inline constexpr TypeConstraint KEnterBoundOperandTypes[] = {fixedType(TypeKind::ParserState), anyType()};
inline constexpr OperandRole KEnterBoundOperandRoles[] = {OperandRole::Consume, OperandRole::Borrow};

// The length is a `uint64`, which the verifier checks.
inline constexpr TypeConstraint KReadBytesOperandTypes[] = {fixedType(TypeKind::ParserState),
                                                            fixedType(TypeKind::Integer)};
inline constexpr OperandRole KReadBytesOperandRoles[] = {OperandRole::Consume, OperandRole::Borrow};

inline constexpr TypeConstraint KParseStateOperandTypes[] = {fixedType(TypeKind::ParserState)};
inline constexpr OperandRole KParseStateOperandRoles[] = {OperandRole::Consume};

// These only look at the state, so it stays valid for the operations that follow.
inline constexpr OperandRole KBorrowStateOperandRoles[] = {OperandRole::Borrow};

// The offset is a `uint64`, which the verifier checks.
inline constexpr TypeConstraint KRequireProgressOperandTypes[] = {fixedType(TypeKind::ParserState),
                                                                  fixedType(TypeKind::Integer)};
inline constexpr OperandRole KRequireProgressOperandRoles[] = {OperandRole::Consume, OperandRole::Borrow};

inline constexpr TypeConstraint KPlaceOperandTypes[] = {anyType()};
inline constexpr OperandRole KPlaceOperandRoles[] = {OperandRole::Borrow};

inline constexpr TypeConstraint KFieldPlaceOperandTypes[] = {anyType()};
inline constexpr OperandRole KFieldPlaceOperandRoles[] = {OperandRole::Borrow};

inline constexpr TypeConstraint KStoreOperandTypes[] = {anyType(), anyType()};
inline constexpr OperandRole KStoreOperandRoles[] = {OperandRole::Borrow, OperandRole::Consume};
inline constexpr OperandRole KLocalPlaceOperandRoles[] = {OperandRole::Consume};

inline constexpr TypeConstraint KBranchOperandTypes[] = {fixedType(TypeKind::Bool)};
inline constexpr OperandRole KBranchOperandRoles[] = {OperandRole::Borrow};
inline constexpr TypeConstraint KEqualOperandTypes[] = {anyType(), anyType()};
inline constexpr OperandRole KEqualOperandRoles[] = {OperandRole::Borrow, OperandRole::Borrow};
inline constexpr TypeConstraint KConvertOperandTypes[] = {anyType()};
inline constexpr OperandRole KConvertOperandRoles[] = {OperandRole::Borrow};
inline constexpr TypeConstraint KUpsilonOperandTypes[] = {anyType()};
inline constexpr OperandRole KUpsilonOperandRoles[] = {OperandRole::Consume};
inline constexpr TypeConstraint KSwitchOperandTypes[] = {fixedType(TypeKind::Integer)};
inline constexpr OperandRole KSwitchOperandRoles[] = {OperandRole::Borrow};
inline constexpr TypeConstraint KFailOperandTypes[] = {fixedType(TypeKind::ParserState), fixedType(TypeKind::String)};
inline constexpr OperandRole KFailOperandRoles[] = {OperandRole::Consume, OperandRole::Borrow};
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

inline constexpr ParserOperationContract KExpectBytesContract{
    .success_consumption_bytes = -1,
    .insufficient_input = SuspendBehavior::SuspendAndRetry,
    .eod = FailureOutcome::UnexpectedEod,
    .gap = FailureOutcome::Gap,
    .bound = FailureOutcome::BoundExceeded,
    .mismatch = FailureOutcome::Mismatch,
    .failure_cursor = FailureCursor::OperationStart,
};

// The end of input and the bound finish the match instead of failing it, so a failure there is a mismatch.
inline constexpr ParserOperationContract KMatchRegExpContract{
    .success_consumption_bytes = -1,
    .insufficient_input = SuspendBehavior::SuspendAndContinue,
    .eod = FailureOutcome::Mismatch,
    .gap = FailureOutcome::Gap,
    .bound = FailureOutcome::Mismatch,
    .mismatch = FailureOutcome::Mismatch,
    .failure_cursor = FailureCursor::OperationStart,
};

// The end of input and the bound end the wait and make the result, so only a gap fails.
inline constexpr ParserOperationContract KPeekLiteralsContract{
    .success_consumption_bytes = 0,
    .insufficient_input = SuspendBehavior::SuspendAndRetry,
    .eod = FailureOutcome::Result,
    .gap = FailureOutcome::Gap,
    .bound = FailureOutcome::Result,
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
inline constexpr std::array<OpcodeSchema, 49> KSchemas{{
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
                 .operand_types = KReadBytesOperandTypes,
                 .operand_roles = KReadBytesOperandRoles,
                 .result_type = fixedType(TypeKind::Tuple),
                 .payload_kind = PayloadKind::None,
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
                 .operand_roles = KLocalPlaceOperandRoles,
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
    OpcodeSchema{.opcode = Opcode::IntConstant,
                 .spelling = "core.int_constant",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = fixedType(TypeKind::Integer),
                 .payload_kind = PayloadKind::IntegerLiteral,
                 .is_terminator = false,
                 .is_pure = true},
    OpcodeSchema{.opcode = Opcode::ForeignConstant,
                 .spelling = "core.foreign_constant",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = fixedType(TypeKind::Opaque),
                 .payload_kind = PayloadKind::StringLiteral,
                 .is_terminator = false,
                 .is_pure = true},
    OpcodeSchema{.opcode = Opcode::PortConstant,
                 .spelling = "core.port_constant",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = fixedType(TypeKind::Opaque),
                 .payload_kind = PayloadKind::Port,
                 .is_terminator = false,
                 .is_pure = true},
    OpcodeSchema{.opcode = Opcode::SetEmpty,
                 .spelling = "core.set_empty",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = fixedType(TypeKind::Set),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::SetInsert,
                 .spelling = "core.set_insert",
                 .operand_types = KSetInsertOperandTypes,
                 .operand_roles = KSetInsertOperandRoles,
                 .result_type = sameAsOperand(),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::ReleaseInput,
                 .spelling = "parser.release_input",
                 .operand_types = KParseStateOperandTypes,
                 .operand_roles = KParseStateOperandRoles,
                 .result_type = fixedType(TypeKind::ParserState),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::Convert,
                 .spelling = "core.convert",
                 // The rule decides which operand and result types are valid, which the verifier checks.
                 .operand_types = KConvertOperandTypes,
                 .operand_roles = KConvertOperandRoles,
                 .result_type = anyType(),
                 .payload_kind = PayloadKind::Conversion,
                 .is_terminator = false,
                 .is_pure = true},
    OpcodeSchema{.opcode = Opcode::Phi,
                 .spelling = "core.phi",
                 .operand_types = KNoOperandTypes,
                 .operand_roles = KNoOperandRoles,
                 .result_type = anyType(),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::Upsilon,
                 .spelling = "core.upsilon",
                 // The operand has the target Phi's type, which the verifier checks.
                 .operand_types = KUpsilonOperandTypes,
                 .operand_roles = KUpsilonOperandRoles,
                 .result_type = fixedType(TypeKind::Void),
                 .payload_kind = PayloadKind::Upsilon,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::Switch,
                 .spelling = "core.switch",
                 .operand_types = KSwitchOperandTypes,
                 .operand_roles = KSwitchOperandRoles,
                 .result_type = fixedType(TypeKind::Void),
                 .payload_kind = PayloadKind::Switch,
                 .is_terminator = true,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::ExpectBytes,
                 .spelling = "parser.expect_bytes",
                 .operand_types = KParseStateOperandTypes,
                 .operand_roles = KParseStateOperandRoles,
                 .result_type = fixedType(TypeKind::Tuple),
                 .payload_kind = PayloadKind::BytesLiteral,
                 .is_terminator = false,
                 .is_pure = false,
                 .parser_contract = KExpectBytesContract},
    OpcodeSchema{.opcode = Opcode::Fail,
                 .spelling = "parser.fail",
                 .operand_types = KFailOperandTypes,
                 .operand_roles = KFailOperandRoles,
                 .result_type = fixedType(TypeKind::Void),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = true,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::MatchRegExp,
                 .spelling = "parser.match_regexp",
                 .operand_types = KParseStateOperandTypes,
                 .operand_roles = KParseStateOperandRoles,
                 .result_type = fixedType(TypeKind::Tuple),
                 .payload_kind = PayloadKind::RegExp,
                 .is_terminator = false,
                 .is_pure = false,
                 .parser_contract = KMatchRegExpContract},
    OpcodeSchema{.opcode = Opcode::ScanBytes,
                 .spelling = "parser.scan_bytes",
                 .operand_types = KParseStateOperandTypes,
                 .operand_roles = KParseStateOperandRoles,
                 .result_type = fixedType(TypeKind::Tuple),
                 .payload_kind = PayloadKind::ScanBytes,
                 .is_terminator = false,
                 .is_pure = false,
                 .parser_contract = KMatchRegExpContract},
    OpcodeSchema{.opcode = Opcode::PeekLiterals,
                 .spelling = "parser.peek_literals",
                 .operand_types = KParseStateOperandTypes,
                 .operand_roles = KBorrowStateOperandRoles,
                 .result_type = fixedType(TypeKind::Integer),
                 .payload_kind = PayloadKind::LiteralSet,
                 .is_terminator = false,
                 .is_pure = false,
                 .parser_contract = KPeekLiteralsContract},
    OpcodeSchema{.opcode = Opcode::Offset,
                 .spelling = "parser.offset",
                 .operand_types = KParseStateOperandTypes,
                 .operand_roles = KBorrowStateOperandRoles,
                 .result_type = fixedType(TypeKind::Integer),
                 .payload_kind = PayloadKind::None,
                 .is_terminator = false,
                 .is_pure = false},
    OpcodeSchema{.opcode = Opcode::RequireProgress,
                 .spelling = "parser.require_progress",
                 .operand_types = KRequireProgressOperandTypes,
                 .operand_roles = KRequireProgressOperandRoles,
                 .result_type = fixedType(TypeKind::ParserState),
                 .payload_kind = PayloadKind::None,
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
    /** Lets the host drop retained input before the cursor. Later parser operations cannot read it again. */
    bool releases_input = false;
    bool changes_parser_state = false;
    bool allocates = false;
    bool publishes = false;
    bool may_suspend = false;
    bool may_fail = false;
    bool reads_world = false;
    bool writes_world = false;
    bool reads_places = false;
    bool writes_places = false;
    /** Reads or writes the shadow of a Phi. */
    bool reads_shadow = false;
    bool writes_shadow = false;
};

constexpr OperationEffects effectsFor(Opcode opcode) {
    switch ( opcode ) {
        case Opcode::ReadInteger:
        case Opcode::ReadBytes:
        case Opcode::ExpectBytes:
        case Opcode::ParseSubunit:
        // A scan reads input as a match does, but has no matcher to allocate.
        case Opcode::ScanBytes:
            return {.reads_input = true, .changes_parser_state = true, .may_suspend = true, .may_fail = true};
        // A peek reads input and waits for it like a read, but consumes nothing.
        case Opcode::PeekLiterals: return {.reads_input = true, .may_suspend = true, .may_fail = true};
        case Opcode::Offset: return {};
        case Opcode::RequireProgress: return {.changes_parser_state = true, .may_fail = true};
        // The runtime's matcher is allocated for each match.
        case Opcode::MatchRegExp:
            return {.reads_input = true,
                    .changes_parser_state = true,
                    .allocates = true,
                    .may_suspend = true,
                    .may_fail = true};
        case Opcode::RepeatToBound:
            return {.reads_input = true,
                    .changes_parser_state = true,
                    .allocates = true,
                    .may_suspend = true,
                    .may_fail = true};
        case Opcode::EnterBound:
        case Opcode::LeaveBound: return {.changes_parser_state = true, .may_fail = true};
        case Opcode::ReleaseInput: return {.releases_input = true, .changes_parser_state = true};
        case Opcode::VectorEmpty:
        case Opcode::VectorAppend:
        case Opcode::SetEmpty:
        case Opcode::SetInsert:
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
        case Opcode::Phi: return {.reads_shadow = true};
        case Opcode::Fail: return {.may_fail = true};
        case Opcode::Upsilon: return {.writes_shadow = true};
        // HILTI integers are checked, so an overflow fails at runtime. That is a logic error, not a parse error.
        case Opcode::Add: return {.may_fail = true};
        // A load of a conditional field fails if the field is unset. Whether a field is conditional is a property of
        // the package, so every load may fail here, and the backend drops the check for a field that is always present.
        case Opcode::Load: return {.may_fail = true, .reads_places = true};
        case Opcode::Store: return {.writes_places = true};
        case Opcode::Tuple:
        case Opcode::BoolConstant:
        case Opcode::StringConstant:
        case Opcode::BytesConstant:
        case Opcode::IntConstant:
        case Opcode::Convert:
        case Opcode::ForeignConstant:
        case Opcode::PortConstant: return {};
        case Opcode::FieldPlace:
        case Opcode::GlobalPlace: return {.reads_places = true};
        case Opcode::Finish:
        case Opcode::Yield:
        case Opcode::Return:
        case Opcode::Argument:
        case Opcode::RegionArgument:
        case Opcode::TupleGet:
        case Opcode::Branch:
        case Opcode::Jump:
        case Opcode::Switch:
        case Opcode::Equal: return {};
    }
    return {.reads_input = true,
            .changes_parser_state = true,
            .allocates = true,
            .publishes = true,
            .may_suspend = true,
            .may_fail = true};
}

} // namespace spicy::detail::pir::ir
