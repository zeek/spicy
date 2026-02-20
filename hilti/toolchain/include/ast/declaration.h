// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/id.h>
#include <hilti/ast/node.h>

namespace hilti {

namespace declaration {

/** Linkage defining visibility/accessibility of a declaration. */
enum class Linkage {
    Export,  /// accessible across modules and guaranteed not to be modified by the optimizer
    Init,    /// executes automatically at startup, not otherwise accessible
    PreInit, /// executes automatically at load time, even before the runtime library is fully set up
    Private, /// accessible only locally
    Public,  /// accessible across modules (note: prefer to test for this with `isPublic()` rather than direct
             /// comparison)
    Struct,  /// method inside a method
};

namespace detail {
constexpr util::enum_::Value<Linkage> Linkages[] = {
    {.value = Linkage::Export, .name = "exported"}, {.value = Linkage::Init, .name = "init"},
    {.value = Linkage::PreInit, .name = "preinit"}, {.value = Linkage::Private, .name = "private"},
    {.value = Linkage::Public, .name = "public"},   {.value = Linkage::Struct, .name = "struct"},
};
} // namespace detail

/** Returns the HILTI string representation corresponding to a linkage. */
constexpr auto to_string(Linkage f) { return util::enum_::to_string(f, detail::Linkages); }

namespace linkage {
/**
 * Parses a HILTI string representation of a linkage.
 *
 * @exception `std::out_of_range` if the string does not map to a linkage
 */
constexpr auto from_string(std::string_view s) { return util::enum_::from_string<Linkage>(s, detail::Linkages); }
} // namespace linkage
} // namespace declaration

/** Base class for implementing declaration nodes. */
class Declaration : public Node, public node::WithDocString {
public:
    ~Declaration() override;

    /** Returns the declaration's ID. */
    const auto& id() const { return _id; }

    /** Returns the declaration's linkage. */
    auto linkage() const { return _linkage; }

    /** Returns true if the declaration's linkage is either `Public` or `Exported`. */
    auto isPublic() const {
        return _linkage == declaration::Linkage::Public || _linkage == declaration::Linkage::Export;
    }

    /**
     * Returns the declaration's fully qualified ID once it has been set during
     * AST processing. The ID is guaranteed to be stable only after AST
     * processing has finished. Returns an empty ID if not yet set.
     */
    const auto& fullyQualifiedID() const { return _fqid; }

    /**
     * Returns the canonical ID associated with the declaration once it has
     * been set during AST processing. Canonical IDs are guaranteed to be
     * globally unique within one instance of an AST context. However, the ID
     * is guaranteed to be unique and stable only once AST processing has
     * finished. Returns an empty ID if not yet set.
     */
    const auto& canonicalID() const { return _canonical_id; }

    /**
     * Returns the index the AST context associates with the declaration. This
     * may become set during AST resolving. If not set yet, returns `None`.
     */
    auto declarationIndex() const { return _declaration_index; }

    /**
     * Sets the declaration's ID. This clears fully-qualified and canonical IDs
     * as they likely need to be recomputed now.
     */
    void setID(const ID& id) {
        _id = id;
        _fqid = {}, _canonical_id = {};
    }

    /** Sets the declaration's linkage. */
    void setLinkage(declaration::Linkage linkage) { _linkage = linkage; }

    /**
     * Sets the declaration's fully qualified ID. Should be used only by the ID
     * assigner during AST processing.
     *
     * @param id fully qualified ID
     */
    void setFullyQualifiedID(ID id) { _fqid = std::move(id); }

    /**
     * Associates a canonical ID with the declaration. Should be used only by
     * the ID assigner during AST processing.
     *
     * @param id canonical ID, which must be globally unique for this declaration
     */
    void setCanonicalID(ID id) { _canonical_id = std::move(id); }

    /**
     * Returns a user-friendly descriptive name for the type of object the
     * declaration refers to (e.g., "local variable"). This can be used in
     * messages to the user.
     */
    virtual std::string_view displayName() const = 0;

    /** Implements the node interface. */
    node::Properties properties() const override {
        auto p = node::Properties{{"id", _id},
                                  {"linkage", declaration::to_string(_linkage)},
                                  {"declaration", to_string(_declaration_index)},
                                  {"fqid", _fqid},
                                  {"canonical-id", _canonical_id}};

        return Node::properties() + std::move(p);
    }

    Declaration(const Declaration& other) : Node(other), node::WithDocString(other) {
        _id = other._id;
        _linkage = other._linkage;
        // Do not copy computed state, we'll want to recompute that eventually.
    }

    Declaration(Declaration&& other) = default;

    Declaration& operator=(const Declaration& other) = delete;
    Declaration& operator=(Declaration&& other) = delete;

protected:
    friend class ASTContext;

    Declaration(ASTContext* ctx, node::Tags node_tags, Nodes children, ID id, declaration::Linkage linkage,
                Meta meta = {})
        : Node(ctx, node_tags, std::move(children), std::move(meta)), _id(std::move(id)), _linkage(linkage) {}

    // For the AST context to set the declaration index.
    void setDeclarationIndex(ast::DeclarationIndex index) {
        assert(index);
        _declaration_index = index;
    }

    std::string _dump() const override;

    HILTI_NODE_0(Declaration, override);

private:
    ID _id;
    declaration::Linkage _linkage;

    ast::DeclarationIndex _declaration_index; // index registered by the context
    ID _fqid;                                 // computed during AST processing
    ID _canonical_id;                         // computed during AST processing
};

} // namespace hilti
