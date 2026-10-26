// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <type_traits>
#include <vector>

#include <spicy/compiler/detail/pir/ir/arena.h>
#include <spicy/compiler/detail/pir/ir/declaration.h>
#include <spicy/compiler/detail/pir/ir/id.h>
#include <spicy/compiler/detail/pir/ir/opcode.h>
#include <spicy/compiler/detail/pir/ir/source.h>

namespace spicy::detail::pir::ir {

struct RegionTag {};
struct BlockTag {};
struct InstTag {};

using RegionId = ID<RegionTag>;
using BlockId = ID<BlockTag>;
using InstId = ID<InstTag>;

static_assert(std::is_trivially_copyable_v<TypeId> && sizeof(TypeId) == 4);
static_assert(std::is_trivially_copyable_v<FunctionId> && sizeof(FunctionId) == 4);
static_assert(std::is_trivially_copyable_v<RegionId> && sizeof(RegionId) == 4);
static_assert(std::is_trivially_copyable_v<BlockId> && sizeof(BlockId) == 4);
static_assert(std::is_trivially_copyable_v<InstId> && sizeof(InstId) == 4);

/**
 * A structurally interned type. `type_arguments` is populated for `Tuple` and `Vector`; `declaration`
 * only for `Unit`. Compare by `TypeId`, not by rendered name.
 */
struct Type {
    TypeKind kind;
    std::vector<TypeId> type_arguments; /**< `Tuple` or `Vector` */
    TypeDeclId declaration;             /**< `Unit` only; invalid otherwise */
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

enum class FunctionKind { Normal, Parser };

struct Function {
    std::string name;
    TypeId result_type;
    RegionId root_region;
    FunctionKind kind = FunctionKind::Normal;
    std::vector<TypeId> parameters;
    TypeDeclId parser_unit; /**< set only for `FunctionKind::Parser` */
    /** Invalid means absent. */
    SourceSpanId span;
};

/** One selected, fully lowered parser implementation, in source order. */
struct ParserRoot {
    TypeDeclId unit;
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

    /** Replaces an instruction while preserving its ID and result type. */
    void replaceInst(InstId id, Opcode opcode, std::vector<InstId> args, InstPayload payload = {});

    const Arena<Type, TypeId>& types() const { return _types; }
    const Arena<Function, FunctionId>& functions() const { return _functions; }
    const Arena<Region, RegionId>& regions() const { return _regions; }
    const Arena<Block, BlockId>& blocks() const { return _blocks; }
    const Arena<Inst, InstId>& instructions() const { return _instructions; }
    const Arena<TypeDecl, TypeDeclId>& typeDecls() const { return _type_decls; }
    const Arena<Declaration, DeclId>& declarations() const { return _declarations; }
    /** Selected parser implementations, in source order. */
    const std::vector<ParserRoot>& parserRoots() const { return _parser_roots; }

    bool isValid(TypeId id) const { return _types.isValid(id); }
    bool isValid(FunctionId id) const { return _functions.isValid(id); }
    bool isValid(RegionId id) const { return _regions.isValid(id); }
    bool isValid(BlockId id) const { return _blocks.isValid(id); }
    bool isValid(InstId id) const { return _instructions.isValid(id); }
    bool isValid(TypeDeclId id) const { return _type_decls.isValid(id); }
    bool isValid(DeclId id) const { return _declarations.isValid(id); }

private:
    friend class Builder;

    Arena<Type, TypeId> _types;
    Arena<Function, FunctionId> _functions;
    Arena<Region, RegionId> _regions;
    Arena<Block, BlockId> _blocks;
    Arena<Inst, InstId> _instructions;
    Arena<TypeDecl, TypeDeclId> _type_decls;
    Arena<Declaration, DeclId> _declarations;
    std::vector<ParserRoot> _parser_roots;

    TypeId _void_type;
    TypeId _int64_type;
    TypeId _uint8_type;        /**< invalid until first requested */
    TypeId _uint64_type;       /**< invalid until first requested */
    TypeId _bytes_type;        /**< invalid until first requested */
    TypeId _parser_state_type; /**< invalid until first requested */

    SourceManager _sources;
};

} // namespace spicy::detail::pir::ir
