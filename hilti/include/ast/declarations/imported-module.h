// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/module.h>
#include <hilti/base/result.h>

namespace hilti {
namespace declaration {

/** AST node for a declaration of imported module. */
class ImportedModule : public NodeBase, public hilti::trait::isDeclaration {
public:
    ImportedModule(ID id, const std::string& search_extension, Meta m = Meta())
        : NodeBase({std::move(id)}, std::move(m)), _extension(search_extension) {}

    ImportedModule(ID id, const std::string& search_extension, std::optional<ID> search_scope, Meta m = Meta())
        : NodeBase({std::move(id)}, std::move(m)), _extension(search_extension), _scope(std::move(search_scope)) {}

    ImportedModule(ID id, const std::string& search_extension, std::optional<ID> search_scope,
                   std::vector<std::filesystem::path> search_dirs, Meta m = Meta())
        : NodeBase({std::move(id)}, std::move(m)),
          _extension(search_extension),
          _scope(std::move(search_scope)),
          _dirs(std::move(search_dirs)) {}

    ImportedModule(ID id, std::filesystem::path path, Meta m = Meta())
        : NodeBase({std::move(id)}, std::move(m)), _path(std::move(path)) {}

    Result<hilti::Module> module() const {
        if ( _module )
            return _module->template as<hilti::Module>();

        return result::Error("module reference not initialized yet");
    }

    auto extension() const { return _extension; }
    auto path() const { return _path; }
    auto scope() const { return _scope; }
    const auto& searchDirectories() const { return _dirs; }

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
    auto properties() const {
        return node::Properties{{"extension", _extension.native()},
                                {"path", _path.native()},
                                {"scope", (_scope ? _scope->str() : std::string("-"))}};
    }

    /**
     * Returns a new imported module declaration with the module reference replaced.
     *
     * @param d original declaration
     * @param n new module reference
     * @return new declaration that's equal to original one but with the module reference replaced
     */
    static Declaration setModule(const ImportedModule& d, NodeRef n) {
        auto x = Declaration(d)._clone().as<ImportedModule>();
        x._module = std::move(n);
        return x;
    }

private:
    NodeRef _module;
    std::filesystem::path _extension;
    std::filesystem::path _path;
    std::optional<ID> _scope;
    std::vector<std::filesystem::path> _dirs;
};

} // namespace declaration
} // namespace hilti
