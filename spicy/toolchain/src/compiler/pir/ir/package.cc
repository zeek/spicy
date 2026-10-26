// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <utility>

#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

Package::Package() {
    _void_type = _types.add(Type{.kind = TypeKind::Void});
    _int64_type = _types.add(Type{.kind = TypeKind::Int64});
}

Builder Package::builder() { return Builder(*this); }

// Useful for optimization
void Package::replaceInst(InstId id, Opcode opcode, std::vector<InstId> args, InstPayload payload) {
    auto& inst = _instructions.get(id);
    inst.opcode = opcode;
    inst.args = std::move(args);
    inst.payload = payload;
}

} // namespace spicy::detail::pir::ir
