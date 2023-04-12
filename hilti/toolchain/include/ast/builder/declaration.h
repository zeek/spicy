// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/filesystem.h>

#include <hilti/ast/declarations/all.h>
#include <hilti/ast/function.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/ast/types/function.h>

namespace hilti::builder {

inline auto import(std::string module, const Meta& m = Meta()) {
    return declaration::ImportedModule(hilti::ID(std::move(module), m), std::string(".hlt"), m);
}

inline auto import(std::string module, const std::string& parse_extension, const Meta& m = Meta()) {
    return declaration::ImportedModule(hilti::ID(std::move(module), m), parse_extension, m);
}

inline auto import(std::string module, const std::string& parse_extension,
                   std::vector<hilti::rt::filesystem::path> search_dirs, const Meta& m = Meta()) {
    return declaration::ImportedModule(hilti::ID(std::move(module), m), parse_extension, {}, std::move(search_dirs), m);
}

inline auto import(std::string module, const std::string& parse_extension, std::optional<ID> search_scope,
                   std::vector<hilti::rt::filesystem::path> search_dirs, const Meta& m = Meta()) {
    return declaration::ImportedModule(hilti::ID(std::move(module), m), parse_extension, std::move(search_scope),
                                       std::move(search_dirs), m);
}

inline auto local(ID id_, Type t, Meta m = Meta()) {
    return statement::Declaration(declaration::LocalVariable(std::move(id_), std::move(t), {}, false, std::move(m)));
}

inline auto local(ID id_, Expression init, Meta m = Meta()) {
    return statement::Declaration(declaration::LocalVariable(std::move(id_), std::move(init), false, std::move(m)));
}

inline auto local(ID id_, Type t, Expression init, Meta m = Meta()) {
    return statement::Declaration(
        declaration::LocalVariable(std::move(id_), std::move(t), std::move(init), false, std::move(m)));
}

inline auto local(ID id_, Type t, std::vector<hilti::Expression> args, Meta m = Meta()) {
    return statement::Declaration(
        declaration::LocalVariable(std::move(id_), std::move(t), std::move(args), {}, false, std::move(m)));
}

inline auto global(ID id_, Type t, declaration::Linkage linkage = declaration::Linkage::Private, Meta m = Meta()) {
    return declaration::GlobalVariable(std::move(id_), std::move(t), {}, linkage, std::move(m));
}

inline auto global(ID id_, Expression init, declaration::Linkage linkage = declaration::Linkage::Private,
                   Meta m = Meta()) {
    return declaration::GlobalVariable(std::move(id_), std::move(init), linkage, std::move(m));
}

inline auto global(ID id_, Type t, Expression init, declaration::Linkage linkage = declaration::Linkage::Private,
                   Meta m = Meta()) {
    return declaration::GlobalVariable(std::move(id_), std::move(t), std::move(init), linkage, std::move(m));
}

inline auto global(ID id_, Type t, std::vector<hilti::Expression> args,
                   declaration::Linkage linkage = declaration::Linkage::Private, Meta m = Meta()) {
    return declaration::GlobalVariable(std::move(id_), std::move(t), std::move(args), {}, linkage, std::move(m));
}

inline auto type(ID id, ::hilti::Type type, declaration::Linkage linkage = declaration::Linkage::Private,
                 Meta m = Meta()) {
    return declaration::Type(std::move(id), std::move(type), linkage, std::move(m));
}

inline auto type(ID id, ::hilti::Type type, std::optional<AttributeSet> attrs,
                 declaration::Linkage linkage = declaration::Linkage::Private, Meta m = Meta()) {
    return declaration::Type(std::move(id), std::move(type), std::move(attrs), linkage, std::move(m));
}

inline auto constant(ID id_, Expression init, declaration::Linkage linkage = declaration::Linkage::Private,
                     Meta m = Meta()) {
    return declaration::Constant(std::move(id_), std::move(init), linkage, std::move(m));
}

inline auto parameter(ID id, Type type, type::function::parameter::Kind kind = type::function::parameter::Kind::In,
                      Meta m = Meta()) {
    return type::function::Parameter(std::move(id), std::move(type), kind, {}, std::move(m));
}

inline auto parameter(ID id, Type type, Expression default_,
                      type::function::parameter::Kind kind = type::function::parameter::Kind::In, Meta m = Meta()) {
    return type::function::Parameter(std::move(id), std::move(type), kind, std::move(default_), std::move(m));
}

template<typename... Params>
static auto parameters(Params&&... params) {
    return std::vector<hilti::type::function::Parameter>{std::forward<Params>(params)...};
}

inline auto function(ID id, Type result, const std::vector<type::function::Parameter>& params,
                     type::function::Flavor flavor = type::function::Flavor::Standard,
                     declaration::Linkage linkage = declaration::Linkage::Private,
                     function::CallingConvention cc = function::CallingConvention::Standard,
                     std::optional<AttributeSet> attrs = {}, const Meta& m = Meta()) {
    auto ft = type::Function(type::function::Result(std::move(result), m), params, flavor, m);
    auto f = Function(std::move(id), std::move(ft), {}, cc, std::move(attrs), m);
    return declaration::Function(std::move(f), linkage, m);
}

inline auto function(ID id, Type result, const std::vector<type::function::Parameter>& params, Statement body,
                     type::function::Flavor flavor = type::function::Flavor::Standard,
                     declaration::Linkage linkage = declaration::Linkage::Private,
                     function::CallingConvention cc = function::CallingConvention::Standard,
                     std::optional<AttributeSet> attrs = {}, const Meta& m = Meta()) {
    auto ft = type::Function(type::function::Result(std::move(result), m), params, flavor, m);
    auto f = Function(std::move(id), std::move(ft), std::move(body), cc, std::move(attrs), m);
    return declaration::Function(std::move(f), linkage, m);
}

inline auto function(ID id, type::Function ftype, Statement body,
                     declaration::Linkage linkage = declaration::Linkage::Private,
                     function::CallingConvention cc = function::CallingConvention::Standard,
                     std::optional<AttributeSet> attrs = {}, const Meta& m = Meta()) {
    auto f = Function(std::move(id), std::move(ftype), std::move(body), cc, std::move(attrs), m);
    return declaration::Function(std::move(f), linkage, m);
}

} // namespace hilti::builder
