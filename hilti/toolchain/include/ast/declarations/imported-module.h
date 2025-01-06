// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/module.h>

namespace hilti {

class Unit;

namespace declaration {

/**
 * AST node for a declaration of an imported module.
 *
 * We associate an explicit "parse extension" with an imported module that
 * specifies which plugin is to parse the code into an AST. Note that this does
 * *not* specify the semantics of the resulting AST. The imported AST will
 * always be processed by the same plugin that is in charge of the declaration
 * itself as well. This separation allows, for example, to import a piece of
 * HILTI source code into a Spicy AST.
 */
class ImportedModule : public Declaration {
public:
    const auto& path() const { return _path; }
    const auto& scope() const { return _scope; }
    const auto& searchDirectories() const { return _dirs; }
    const auto& parseExtension() const { return _parse_extension; }

    auto uid() const { return _uid; }
    void setUID(declaration::module::UID uid) { _uid = std::move(uid); }
    void clearUID() { _uid.reset(); }
    void setSearchDirectories(std::vector<hilti::rt::filesystem::path> dirs) { _dirs = std::move(dirs); }

    std::string_view displayName() const final { return "imported module"; }

    node::Properties properties() const final {
        auto p = node::Properties{
            {"path", _path.native()},
            {"ext", _parse_extension.native()},
            {"scope", _scope ? _scope.str() : std::string("<n/a>")},
            {"dirs", util::join(_dirs)},
            {"uid", _uid ? _uid->str() : std::string("<n/a>")},
        };
        return Declaration::properties() + p;
    }

    static auto create(ASTContext* ctx, ID id, const std::string& parse_extension, Meta meta = {}) {
        return ctx->make<ImportedModule>(ctx, std::move(id), hilti::rt::filesystem::path{}, parse_extension, ID{},
                                         std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, const std::string& parse_extension, ID search_scope, Meta meta = {}) {
        return ctx->make<ImportedModule>(ctx, std::move(id), hilti::rt::filesystem::path{}, parse_extension,
                                         std::move(search_scope), std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, hilti::rt::filesystem::path path, Meta meta = {}) {
        auto extension = path.extension();
        return ctx->make<ImportedModule>(ctx, std::move(id), std::move(path), std::move(extension), ID{},
                                         std::move(meta));
    }

protected:
    ImportedModule(ASTContext* ctx, ID id, hilti::rt::filesystem::path path, const std::string& parse_extension,
                   ID search_scope, Meta meta)
        : Declaration(ctx, NodeTags, {}, std::move(id), Linkage::Private, std::move(meta)),
          _path(std::move(path)),
          _parse_extension(parse_extension),
          _scope(std::move(search_scope)) {}

    HILTI_NODE_1(declaration::ImportedModule, Declaration, final);

private:
    hilti::rt::filesystem::path _path;
    hilti::rt::filesystem::path _parse_extension;
    ID _scope;
    std::vector<hilti::rt::filesystem::path> _dirs;

    std::optional<declaration::module::UID> _uid;
};

} // namespace declaration

} // namespace hilti
