// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

#include <spicy/compiler/detail/pir/ir/id.h>
#include <spicy/compiler/detail/pir/ir/source.h>

// `TypeId` (used by `Declaration::type`) is defined in `id.h` alongside the generic `ID`
// template so this header and `package.h` do not depend on each other.

namespace spicy::detail::pir::ir {

struct TypeDeclTag {};
struct DeclTag {};

using TypeDeclId = ID<TypeDeclTag>;
using DeclId = ID<DeclTag>;

enum class TypeDeclKind { Unit };
enum class DeclKind { Field };

/** A nominal type declaration. Its name is printer/diagnostic sugar only; identity is `TypeDeclId`. */
struct TypeDecl {
    TypeDeclKind kind = TypeDeclKind::Unit;
    std::string name;
    std::vector<DeclId> fields; /**< canonical source order */
    /** Invalid means absent. */
    SourceSpanId span;
};

/** A declaration owned by a `TypeDecl`, currently only a unit field. */
struct Declaration {
    DeclKind kind = DeclKind::Field;
    TypeDeclId owner;
    std::string name; /**< printer/diagnostic sugar only */
    TypeId type;
    /** Invalid means absent. */
    SourceSpanId span;
};

} // namespace spicy::detail::pir::ir
