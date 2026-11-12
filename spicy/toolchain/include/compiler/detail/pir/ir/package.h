// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <vector>

#include <spicy/compiler/detail/pir/ir/arena.h>
#include <spicy/compiler/detail/pir/ir/declaration.h>
#include <spicy/compiler/detail/pir/ir/id.h>
#include <spicy/compiler/detail/pir/ir/opcode.h>
#include <spicy/compiler/detail/pir/ir/source.h>

namespace spicy::detail::pir::ir {

struct RegionTag {};

using RegionId = ID<RegionTag>;

static_assert(std::is_trivially_copyable_v<TypeId> && sizeof(TypeId) == 4);
static_assert(std::is_trivially_copyable_v<FunctionId> && sizeof(FunctionId) == 4);
static_assert(std::is_trivially_copyable_v<RegionId> && sizeof(RegionId) == 4);
static_assert(std::is_trivially_copyable_v<BlockId> && sizeof(BlockId) == 4);
static_assert(std::is_trivially_copyable_v<InstId> && sizeof(InstId) == 4);

/** The width and signedness of an integer type. Widths are 8, 16, 32, or 64 bits. */
struct IntegerType {
    uint8_t width = 0;
    Signedness signedness = Signedness::Unsigned;

    friend constexpr bool operator==(IntegerType, IntegerType) = default;
};

/**
 * A structurally interned type. `type_arguments` is populated for `Tuple` and `Vector`; `declaration`
 * only for `Unit` and `Opaque`; `integer` only for `Integer`. Compare by `TypeId`, not by rendered name.
 */
struct Type {
    TypeKind kind;
    std::vector<TypeId> type_arguments; /**< `Tuple` or `Vector` */
    TypeDeclId declaration;             /**< `Unit` only; invalid otherwise */
    IntegerType integer;                /**< `Integer` only; zero otherwise */
};

struct Inst {
    Opcode opcode;
    TypeId result_type;
    std::vector<InstId> args;
    // Cached; Block::insts is canonical.
    BlockId parent;
    InstPayload payload;
    std::vector<RegionId> regions; /**< regions owned by a structured operation */
    /** Invalid means absent. */
    SourceSpanId span;
};

struct Block {
    std::vector<InstId> insts;
};

struct Region {
    std::vector<BlockId> blocks;
};

/**
 * `Normal` functions are ordinary procedures. `Parser` functions are parser states that consume input.
 */
enum class FunctionKind { Normal, Parser };

/** How a procedure receives an argument. */
enum class ParameterMode {
    /**
     * An independent value. A copyable value is copied; an affine value (a unit, vector, or set) is transferred, so the
     * caller cannot use it afterward.
     */
    Take,
    /**
     * Nonescaping read access to the caller's value for the duration of the call. The callee can neither consume the
     * value nor write through it, and the caller keeps ownership.
     */
    Borrow,
    /** As `Borrow`, and the callee may also write through the value. */
    BorrowMut,
};

/**
 * A formal parameter of a procedure. A borrowed parameter's `type` is the type of the access it receives: the affine
 * value itself, such as a unit, whose identity the borrow preserves, or the `place<T>` of copyable storage, which
 * the callee reads and writes in the caller's storage. A `Take` parameter is never a place, so a place never means an
 * owned value, and `Borrow` and `BorrowMut` parameters do not accept independent copyable values.
 */
struct Parameter {
    TypeId type;
    ParameterMode mode = ParameterMode::Take;

    Parameter(TypeId t = {}, ParameterMode m = ParameterMode::Take) : type(t), mode(m) {}

    friend constexpr bool operator==(const Parameter&, const Parameter&) = default;
};

struct Function {
    std::string name;
    TypeId result_type;
    RegionId root_region;
    FunctionKind kind = FunctionKind::Normal;
    std::vector<Parameter> parameters;
    TypeDeclId parser_unit; /**< set only for `FunctionKind::Parser` */
    /** Invalid means absent. */
    SourceSpanId span;
};

/**
 * What the runtime needs to tell contexts apart: the runtime compares the type information of a context that it hands
 * from one parser to another, so a context keeps the identity that its source declared even though PIR computes with
 * a structural tuple.
 */
struct ContextIdentity {
    std::string name;                  /**< the declared type's qualified name; empty for an unnamed tuple */
    std::vector<std::string> elements; /**< the names of the tuple's elements, in order */
};

/** One selected, fully lowered parser implementation, in source order. */
struct ParserRoot {
    TypeDeclId unit;
    FunctionId function;
    std::string name;                       /**< the parser's exported, qualified name */
    std::optional<ContextIdentity> context; /**< set exactly when the parser function takes a context */
};

/**
 * A module initialization phase. Pre-initialization functions run before any global is initialized, and
 * initialization functions run after all of them.
 */
enum class InitPhase { PreInit, Init };

/** One module-level function run during initialization, in the order of `Package::initializers()`. */
struct Initializer {
    InitPhase phase;
    FunctionId function;
};

class Builder;

/** The central place that stores the PIR arenas and outputs. */
class Package {
public:
    Package();

    TypeId voidType() const noexcept { return _void_type; }
    TypeId int64Type() const noexcept { return _int64_type; }

    SourceManager& sourceManager() { return _sources; }
    const SourceManager& sourceManager() const { return _sources; }
    Builder builder();

    const Type& type(TypeId id) const { return _types.get(id); }
    const Function& function(FunctionId id) const { return _functions.get(id); }
    const Region& region(RegionId id) const { return _regions.get(id); }
    const Block& block(BlockId id) const { return _blocks.get(id); }
    const Inst& inst(InstId id) const { return _instructions.get(id); }
    const TypeDecl& typeDecl(TypeDeclId id) const { return _type_decls.get(id); }
    const Declaration& declaration(DeclId id) const { return _declarations.get(id); }
    const ForeignFunction& foreignFunction(ForeignFunctionId id) const { return _foreign_functions.get(id); }
    const Global& global(GlobalId id) const { return _globals.get(id); }

    /** Replaces an instruction while preserving its ID and result type. */
    void replaceInst(InstId id, Opcode opcode, std::vector<InstId> args, InstPayload payload = {});

    /**
     * Removes `block` from `region`, with its instructions and any regions they own. Erased entries keep their IDs but
     * belong to nothing, and are not orphans.
     */
    void eraseBlock(RegionId region, BlockId block);
    /** Removes an instruction from its block. It must not own regions. */
    void eraseInst(InstId id);
    /** Whether an entry was erased. */
    bool isErased(BlockId id) const { return _erased_blocks.contains(id.index); }
    bool isErased(InstId id) const { return _erased_insts.contains(id.index); }
    bool isErased(RegionId id) const { return _erased_regions.contains(id.index); }
    size_t erasedBlocks() const { return _erased_blocks.size(); }
    size_t erasedInsts() const { return _erased_insts.size(); }
    size_t erasedRegions() const { return _erased_regions.size(); }

    const Arena<Type, TypeId>& types() const { return _types; }
    const Arena<Function, FunctionId>& functions() const { return _functions; }
    const Arena<Region, RegionId>& regions() const { return _regions; }
    const Arena<Block, BlockId>& blocks() const { return _blocks; }
    const Arena<Inst, InstId>& instructions() const { return _instructions; }
    const Arena<TypeDecl, TypeDeclId>& typeDecls() const { return _type_decls; }
    const Arena<Declaration, DeclId>& declarations() const { return _declarations; }
    const Arena<ForeignFunction, ForeignFunctionId>& foreignFunctions() const { return _foreign_functions; }
    const Arena<Global, GlobalId>& globals() const { return _globals; }
    /** Selected parser implementations, in source order. */
    const std::vector<ParserRoot>& parserRoots() const { return _parser_roots; }
    /** Module-level functions run at initialization, in order. */
    const std::vector<Initializer>& initializers() const { return _initializers; }
    /** Selected public ordinary functions, in source order. */
    const std::vector<FunctionId>& functionRoots() const { return _function_roots; }
    /** Native headers that the foreign declarations depend on, in source order without duplicates. */
    const std::vector<std::string>& cxxIncludes() const { return _cxx_includes; }

    bool isValid(TypeId id) const { return _types.isValid(id); }
    bool isValid(FunctionId id) const { return _functions.isValid(id); }
    bool isValid(RegionId id) const { return _regions.isValid(id); }
    bool isValid(BlockId id) const { return _blocks.isValid(id); }
    bool isValid(InstId id) const { return _instructions.isValid(id); }
    bool isValid(TypeDeclId id) const { return _type_decls.isValid(id); }
    bool isValid(DeclId id) const { return _declarations.isValid(id); }
    bool isValid(ForeignFunctionId id) const { return _foreign_functions.isValid(id); }
    bool isValid(GlobalId id) const { return _globals.isValid(id); }

private:
    friend class Builder;

    Arena<Type, TypeId> _types;
    Arena<Function, FunctionId> _functions;
    Arena<Region, RegionId> _regions;
    Arena<Block, BlockId> _blocks;
    Arena<Inst, InstId> _instructions;
    Arena<TypeDecl, TypeDeclId> _type_decls;
    Arena<Declaration, DeclId> _declarations;
    Arena<ForeignFunction, ForeignFunctionId> _foreign_functions;
    Arena<Global, GlobalId> _globals;
    std::vector<ParserRoot> _parser_roots;
    std::vector<Initializer> _initializers;
    std::vector<FunctionId> _function_roots;
    std::vector<std::string> _cxx_includes;
    std::unordered_set<uint32_t> _erased_blocks;
    std::unordered_set<uint32_t> _erased_insts;
    std::unordered_set<uint32_t> _erased_regions;

    TypeId _void_type;
    TypeId _int64_type;
    TypeId _bytes_type;        /**< invalid until first requested */
    TypeId _parser_state_type; /**< invalid until first requested */
    TypeId _bool_type;         /**< invalid until first requested */
    TypeId _string_type;       /**< invalid until first requested */

    SourceManager _sources;
};

/** `value`'s two's complement bits, truncated to `width` bits. */
constexpr uint64_t truncateBits(uint64_t value, unsigned width) {
    return width >= 64 ? value : value & ((uint64_t{1} << width) - 1);
}

/** The value of an integer constant's `bits` in `type`, sign-extended when the type is signed. */
constexpr int64_t signedValue(uint64_t bits, IntegerType type) {
    if ( type.signedness == Signedness::Unsigned || type.width >= 64 || ! (bits >> (type.width - 1U) & 1U) )
        return static_cast<int64_t>(bits);
    return static_cast<int64_t>(bits | ~((uint64_t{1} << type.width) - 1));
}

/**
 * The width of the value that `parser.read_integer` produces for a read of `read_width` bits: the narrowest supported
 * integer that holds it. Zero if there is none.
 */
constexpr uint8_t readIntegerValueWidth(uint32_t read_width) {
    for ( uint8_t width : {8, 16, 32, 64} )
        if ( read_width != 0 && read_width <= width )
            return width;
    return 0;
}

/** Whether `width` is the width of a PIR integer type. */
constexpr bool isIntegerWidth(unsigned width) { return width == 8 || width == 16 || width == 32 || width == 64; }

/**
 * The input contract of one parser operation. An exact byte count comes from the payload of `parser.read_integer`
 * and from a constant length operand of `parser.read_bytes`; any other length is not exactly known.
 */
std::optional<ParserOperationContract> parserContractFor(const Package& package, const Inst& inst);

/** Whether `rule` converts a value of type `from` to type `to`. */
bool conversionAccepts(const Package& package, ConversionRule rule, TypeId from, TypeId to);

/** The affine discipline of an instantiated type: a tuple inherits it from any element that has it. */
ValueDiscipline typeDiscipline(const Package& package, TypeId id);

/**
 * How `inst` treats its operand `index`. The role of a call's operand follows the callee's parameter: a taken affine
 * value is consumed, and a borrowed or copied one is not. Every other opcode has the role its schema gives. Callers
 * that check ownership use this one query so that they agree.
 */
OperandRole operandRole(const Package& package, const Inst& inst, size_t index);

} // namespace spicy::detail::pir::ir
