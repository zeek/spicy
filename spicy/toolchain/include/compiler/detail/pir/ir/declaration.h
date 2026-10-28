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
struct GlobalTag {};

using TypeDeclId = ID<TypeDeclTag>;
using DeclId = ID<DeclTag>;
using ForeignFunctionId = ID<ForeignFunctionTag>;
using GlobalId = ID<GlobalTag>;

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

/** How a native call receives an argument, beyond the parameter's declared type. */
enum class ForeignArgument {
    Value,      /**< a value of the parameter's declared type */
    TypeInfo,   /**< any copyable value; the native call also receives its runtime type information */
    AnyPointer, /**< any copyable value passed by pointer to its storage, plus its runtime type information */
    AnyTuple,   /**< any tuple; the native call takes a wildcard tuple whose element types the operand carries */
};

/** A formal parameter of a foreign function. `type` is invalid for the `any` and tuple conventions, which check
 * operands by convention. */
struct ForeignParameter {
    TypeId type;
    ForeignArgument argument = ForeignArgument::Value;

    ForeignParameter(TypeId t = {}, ForeignArgument a = ForeignArgument::Value) : type(t), argument(a) {}
};

/**
 * A function implemented outside PIR. Calls to it are `opaque.op` operations; `cxx_name` is the
 * native symbol that a backend binds to. A function that only the target adapter can implement, such as
 * one that returns the identity of the linked artifact, has no native symbol. It is `target_provided`
 * instead, and a backend that has no binding for it cannot lower the package.
 */
struct ForeignFunction {
    std::string name;     /**< printer/diagnostic sugar only */
    std::string cxx_name; /**< native symbol; empty if undeclared or `target_provided` */
    bool target_provided = false;
    std::vector<ForeignParameter> parameters;
    TypeId result_type;
    /** The native prototype is provided by the runtime's headers rather than generated for the module. */
    bool have_prototype = false;
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

/**
 * A package-level variable. Its value comes from `initializer`, a function without parameters that module
 * initialization runs once. Reads and writes go through a place that `core.global_place` addresses.
 */
struct Global {
    std::string name; /**< printer/diagnostic sugar only */
    TypeId type;
    FunctionId initializer; /**< invalid until the initializer is lowered */
    /** Invalid means absent. */
    SourceSpanId span;
};

} // namespace spicy::detail::pir::ir
