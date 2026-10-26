// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <spicy/compiler/detail/pir/ir/id.h>
#include <spicy/compiler/detail/pir/ir/source.h>

// `TypeId` (used by `Declaration::type`) is defined in `id.h` alongside the generic `ID`
// template so this header and `package.h` do not depend on each other.

namespace spicy::detail::pir::ir {

struct TypeDeclTag {};
struct DeclTag {};
struct ForeignFunctionTag {};

using TypeDeclId = ID<TypeDeclTag>;
using DeclId = ID<DeclTag>;
using ForeignFunctionId = ID<ForeignFunctionTag>;

enum class TypeDeclKind { Unit, Opaque };
enum class DeclKind { Field };

/**
 * Ownership behavior that a native opaque type declares. PIR does not infer copy or move
 * behavior from the native type, so a lifecycle that was not declared stays absent.
 */
struct OpaqueLifecycle {
    bool copyable = false;
    bool movable = false;

    friend constexpr bool operator==(OpaqueLifecycle, OpaqueLifecycle) = default;
};

/** The native binding and lifecycle of a foreign value type. */
struct OpaqueTypeInfo {
    std::string cxx_name;                     /**< native type name; empty if undeclared */
    bool constant = false;                    /**< whether the native type is `const` */
    std::optional<OpaqueLifecycle> lifecycle; /**< absent until declared */
};

/**
 * A nominal type declaration. Its name is printer/diagnostic sugar only; identity is `TypeDeclId`.
 * Unit declarations own fields; opaque declarations carry `opaque`.
 */
struct TypeDecl {
    TypeDeclKind kind = TypeDeclKind::Unit;
    std::string name;
    std::vector<DeclId> fields;           /**< canonical source order; units only */
    std::optional<OpaqueTypeInfo> opaque; /**< opaque types only */
    /** Invalid means absent. */
    SourceSpanId span;
};

/**
 * A function implemented outside PIR. Calls to it are `opaque.op` operations; `cxx_name` is the
 * native symbol that a backend binds to.
 */
struct ForeignFunction {
    std::string name;     /**< printer/diagnostic sugar only */
    std::string cxx_name; /**< native symbol; empty if undeclared */
    std::vector<TypeId> parameters;
    TypeId result_type;
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
