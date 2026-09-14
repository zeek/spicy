// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include <spicy/compiler/detail/pir/ir/arena.h>
#include <spicy/compiler/detail/pir/ir/id.h>
#include <spicy/compiler/detail/pir/ir/opcode.h>

namespace spicy::detail::pir::ir {

struct TypeTag {};
struct FunctionTag {};
struct RegionTag {};
struct BlockTag {};
struct InstTag {};

using TypeId = ID<TypeTag>;
using FunctionId = ID<FunctionTag>;
using RegionId = ID<RegionTag>;
using BlockId = ID<BlockTag>;
using InstId = ID<InstTag>;

static_assert(std::is_trivially_copyable_v<TypeId> && sizeof(TypeId) == 4);
static_assert(std::is_trivially_copyable_v<FunctionId> && sizeof(FunctionId) == 4);
static_assert(std::is_trivially_copyable_v<RegionId> && sizeof(RegionId) == 4);
static_assert(std::is_trivially_copyable_v<BlockId> && sizeof(BlockId) == 4);
static_assert(std::is_trivially_copyable_v<InstId> && sizeof(InstId) == 4);

struct Type {
    TypeKind kind;
};

using InstPayload = std::variant<std::monostate, int64_t>;

struct Inst {
    Opcode opcode;
    TypeId result_type;
    std::vector<InstId> args;
    // Cached; Block::insts is canonical.
    BlockId parent;
    InstPayload payload;
};

struct Block {
    std::vector<InstId> insts;
};

struct Region {
    std::vector<BlockId> blocks;
};

struct Function {
    std::string name;
    TypeId result_type;
    RegionId root_region;
};

/** Owns the flat arenas of a PIR package. */
class Package {
public:
    Package();

    TypeId voidType() const noexcept { return _void_type; }
    TypeId int64Type() const noexcept { return _int64_type; }

    FunctionId createFunction(std::string name, TypeId result_type);
    RegionId createRegion();
    BlockId createBlock(RegionId region);

    InstId addInst(BlockId block,
                   Opcode opcode,
                   std::vector<InstId> args,
                   TypeId result_type,
                   InstPayload payload = {});

    /** Adds unchecked IR for verifier tests. */
    InstId addInstForTesting(BlockId block,
                             Opcode opcode,
                             std::vector<InstId> args,
                             TypeId result_type,
                             InstPayload payload = {});

    InstId addConstant(BlockId block, int64_t value);
    InstId addAdd(BlockId block, InstId lhs, InstId rhs);
    InstId addReturn(BlockId block, InstId value);

    const Type& type(TypeId id) const { return _types.get(id); }
    const Function& function(FunctionId id) const { return _functions.get(id); }
    const Region& region(RegionId id) const { return _regions.get(id); }
    const Block& block(BlockId id) const { return _blocks.get(id); }
    const Inst& inst(InstId id) const { return _instructions.get(id); }

    /** Replaces an instruction while preserving its ID and result type. */
    void replaceInst(InstId id, Opcode opcode, std::vector<InstId> args, InstPayload payload = {});

    const Arena<Type, TypeId>& types() const { return _types; }
    const Arena<Function, FunctionId>& functions() const { return _functions; }
    const Arena<Region, RegionId>& regions() const { return _regions; }
    const Arena<Block, BlockId>& blocks() const { return _blocks; }
    const Arena<Inst, InstId>& instructions() const { return _instructions; }

    bool isValid(TypeId id) const { return _types.isValid(id); }
    bool isValid(FunctionId id) const { return _functions.isValid(id); }
    bool isValid(RegionId id) const { return _regions.isValid(id); }
    bool isValid(BlockId id) const { return _blocks.isValid(id); }
    bool isValid(InstId id) const { return _instructions.isValid(id); }

private:
    Arena<Type, TypeId> _types;
    Arena<Function, FunctionId> _functions;
    Arena<Region, RegionId> _regions;
    Arena<Block, BlockId> _blocks;
    Arena<Inst, InstId> _instructions;

    TypeId _void_type;
    TypeId _int64_type;
};

} // namespace spicy::detail::pir::ir
