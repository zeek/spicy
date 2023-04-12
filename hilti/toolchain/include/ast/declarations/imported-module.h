// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/filesystem.h>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/module.h>
#include <hilti/base/result.h>

namespace hilti {

class Unit;

namespace declaration {

/**
 * AST node for a declaration of imported module.
 *
 * We associate an explicit "parse extension" with an imported module that
 * specifies which plugin is to parse the code into an AST. Note that this does
 * *not* specify the semantics of the resulting AST. The imported AST will
 * always be processed by the same plugin that is in charge of the declaration
 * itself as well. This separation allows, for example, to import a piece of
 * HILTI source code into a Spicy AST.
 */
class ImportedModule : public DeclarationBase {
public:
    ImportedModule(ID id, const std::string& parse_extension, Meta m = Meta())
        : DeclarationBase({std::move(id)}, std::move(m)), _parse_extension(parse_extension) {}

    ImportedModule(ID id, const std::string& parse_extension, std::optional<ID> search_scope, Meta m = Meta())
        : DeclarationBase({std::move(id)}, std::move(m)),
          _parse_extension(parse_extension),
          _scope(std::move(search_scope)) {}

    ImportedModule(ID id, const std::string& parse_extension, std::optional<ID> search_scope,
                   std::vector<hilti::rt::filesystem::path> search_dirs, Meta m = Meta())
        : DeclarationBase({std::move(id)}, std::move(m)),
          _parse_extension(parse_extension),
          _scope(std::move(search_scope)),
          _dirs(std::move(search_dirs)) {}

    ImportedModule(ID id, const hilti::rt::filesystem::path& path, Meta m = Meta())
        : DeclarationBase({std::move(id)}, std::move(m)), _parse_extension(path.extension()), _path(path) {}

    hilti::rt::filesystem::path parseExtension() const { return _parse_extension; }

    auto path() const { return _path; }
    auto scope() const { return _scope; }
    auto unit() const { return _unit.lock(); }
    const auto& searchDirectories() const { return _dirs; }

    /** Sets both extensions to the same value. */
    void setUnit(const std::shared_ptr<Unit>& unit) { _unit = unit; }

    bool operator==(const ImportedModule& other) const { return id() == other.id(); }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    const ID& id() const { return child<ID>(0); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return Linkage::Private; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "imported module"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    node::Properties properties() const;

private:
    std::weak_ptr<hilti::Unit> _unit;
    hilti::rt::filesystem::path _parse_extension;
    hilti::rt::filesystem::path _path;
    std::optional<ID> _scope;
    std::vector<hilti::rt::filesystem::path> _dirs;
};

} // namespace declaration
} // namespace hilti
