// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/ctors/interval.h>
#include <hilti/ast/ctors/time.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/detail/operator-registry.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/unit.h>

using namespace hilti;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Normalizer("normalizer");
} // namespace hilti::logging::debug
namespace {

struct VisitorConstants : public visitor::PreOrder<void, VisitorConstants> {
    bool modified = false;

    // Log debug message recording resolving a expression.
    void logChange(const Node& old, const Ctor& ctor) {
        HILTI_DEBUG(logging::debug::Normalizer,
                    util::fmt("[%s] %s -> constant %s (%s)", old.typename_(), old, ctor, old.location()));
    }

    void operator()(const Expression& d, position_t p) {
        if ( ! expression::isResolved(d) )
            return;

        if ( d.isA<expression::Ctor>() )
            return;

        auto ctor = detail::foldConstant(p.node);
        if ( ! ctor ) {
            p.node.addError(ctor.error());
            return;
        }

        if ( ! *ctor )
            return;

        logChange(p.node, **ctor);
        auto nexpr = expression::Ctor(**ctor, (*ctor)->meta());
        p.node = nexpr;
        modified = true;
    }
};

struct VisitorNormalizer : public visitor::PreOrder<void, VisitorNormalizer> {
    bool modified = false;

    // Log debug message recording resolving a expression.
    void logChange(const Node& old, const Expression& nexpr) {
        HILTI_DEBUG(logging::debug::Normalizer,
                    util::fmt("[%s] %s -> expression %s (%s)", old.typename_(), old, nexpr, old.location()));
    }

    // Log debug message recording resolving a ctor.
    void logChange(const Node& old, const Ctor& nexpr) {
        HILTI_DEBUG(logging::debug::Normalizer,
                    util::fmt("[%s] %s -> ctor %s (%s)", old.typename_(), old, nexpr, old.location()));
    }

    // Log debug message recording resolving a statement.
    void logChange(const Node& old, const Statement& nstmt) {
        HILTI_DEBUG(logging::debug::Normalizer,
                    util::fmt("[%s] %s -> statement %s (%s)", old.typename_(), old, nstmt, old.location()));
    }

    // Log debug message recording resolving a type.
    void logChange(const Node& old, const Type& ntype) {
        HILTI_DEBUG(logging::debug::Normalizer,
                    util::fmt("[%s] %s -> type %s (%s)", old.typename_(), old, ntype, old.location()));
    }

    // Log debug message recording attribute normalizations.
    void logChange(const Node& old, const Attribute& nattr) {
        HILTI_DEBUG(logging::debug::Normalizer, util::fmt("%s -> %s (%s)", old, nattr, old.location()));
    }

    auto callArgument(const expression::ResolvedOperatorBase& o, int i) {
        auto ctor = o.op1().as<expression::Ctor>().ctor();

        if ( auto x = ctor.tryAs<ctor::Coerced>() )
            ctor = x->coercedCtor();

        return ctor.as<ctor::Tuple>().value()[i];
    }

    // Helper to cast an uint64 to int64, with range check.
    int64_t to_int64(uint64_t x, position_t& p) {
        if ( x > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) )
            throw hilti::rt::OutOfRange("integer value out of range");

        return static_cast<int64_t>(x);
    }

    // Overload that doesn't need to do any checking.
    int64_t to_int64(int64_t x, position_t& p) { return x; }

    // Helper to cast an int64 to uint64, with range check.
    uint64_t to_uint64(int64_t x, position_t& p) {
        if ( x < 0 )
            throw hilti::rt::OutOfRange("integer value out of range");

        return static_cast<uint64_t>(x);
    }

    void operator()(const declaration::Function& u, position_t p) {
        if ( u.linkage() == declaration::Linkage::Struct ) {
            // Link method implementations to their parent type.
            auto ns = u.id().namespace_();
            if ( ! ns )
                return;

            auto resolved = scope::lookupID<declaration::Type>(ns, p, "struct type");
            if ( ! resolved ) {
                p.node.addError(resolved.error());
                return;
            }

            if ( ! resolved->first->isA<declaration::Type>() ) {
                p.node.addError(
                    util::fmt("namespace %s does not resolve to a type (but to %s)", ns, resolved->first->typename_()));
                return;
            }

            p.node.as<declaration::Function>().setParentRef(NodeRef(resolved->first));
        }
    }

    void operator()(const expression::Assign& assign, position_t p) {
        // Rewrite assignments to map elements to use the `index_assign` operator.
        auto& lhs = assign.children().front();
        if ( auto index_non_const = lhs.tryAs<operator_::map::IndexNonConst>() ) {
            const auto& map = index_non_const->op0();
            const auto& map_type = map.type().as<type::Map>();
            const auto& key_type = map_type.keyType();
            const auto& value_type = map_type.valueType();

            auto key = index_non_const->op1();
            if ( key.type() != key_type ) {
                if ( auto nexpr = hilti::coerceExpression(key, key_type).nexpr )
                    key = std::move(*nexpr);
            }

            auto value = assign.source();
            if ( value.type() != value_type ) {
                if ( auto nexpr = hilti::coerceExpression(value, value_type).nexpr )
                    value = std::move(*nexpr);
            }

            Expression index_assign =
                hilti::expression::UnresolvedOperator(hilti::operator_::Kind::IndexAssign,
                                                      {map, std::move(key), std::move(value)}, assign.meta());

            logChange(p.node, index_assign);
            p.node = index_assign;
            modified = true;
            return;
        }

        // Rewrite assignments involving struct elements to use the non-const member operator.
        if ( auto member_const = lhs.tryAs<operator_::struct_::MemberConst>() ) {
            auto new_lhs = operator_::struct_::MemberNonConst::Operator().instantiate(member_const->operands().copy(),
                                                                                      member_const->meta());
            Expression n = expression::Assign(new_lhs, assign.source(), assign.meta());
            logChange(p.node, n);
            p.node = n;
            modified = true;
            return;
        }

        // Rewrite assignments involving tuple ctors on the LHS to use the
        // tuple's custom by-element assign operator. We need this to get
        // constness right.
        auto lhs_ctor = lhs.tryAs<expression::Ctor>();
        if ( lhs_ctor && lhs_ctor->ctor().isA<ctor::Tuple>() ) {
            if ( expression::isResolved(assign.source()) && expression::isResolved(assign.target()) ) {
                auto n = operator_::tuple::CustomAssign::Operator().instantiate({assign.target(), assign.source()},
                                                                                assign.meta());
                logChange(p.node, n);
                p.node = n;
                modified = true;
                return;
            }
        }
    }

    void operator()(const statement::If& n, position_t p) {
        if ( n.init() && ! n.condition() ) {
            auto cond = expression::UnresolvedID(n.init()->id());
            logChange(p.node, cond);
            p.node.as<statement::If>().setCondition(std::move(cond));
            modified = true;
        }
    }

    void operator()(const statement::Switch& s, position_t p) { p.node.as<statement::Switch>().preprocessCases(); }

    void operator()(const type::Library& t, position_t p) {
        auto& type = p.node.as<Type>();

        if ( ! type.cxxID() )
            // Make it equal to types with the same C++ representation.
            type.setCxxID(ID(t.cxxName()));
    }

    void operator()(const type::Struct& t, position_t p) {
        if ( ! t.selfRef() )
            type::Struct::setSelf(&p.node);
    }

    void operator()(const Attribute& n, position_t p) {
        // Normalize values passed as `&cxxname` so they always are interpreted as FQNs by enforcing leading `::`.
        if ( const auto& tag = n.tag(); tag == "&cxxname" && n.hasValue() ) {
            if ( const auto& value = n.valueAsString(); value && ! util::startsWith(*value, "::") ) {
                auto n = Attribute(tag, builder::string(util::fmt("::%s", *value)));
                logChange(p.node, n);
                p.node = n;
                modified = true;
            }
        }
    }
};

} // anonymous namespace

struct VisitorComputeCanonicalIDs;
static void _computeCanonicalIDs(VisitorComputeCanonicalIDs* v, Node* node, ID current);

// Visitor to unset all canonical IDs in preparation for their recalculation.
struct VisitorClearCanonicalIDs : public visitor::PreOrder<void, VisitorClearCanonicalIDs> {
    result_t operator()(const Declaration& d, position_t p) { p.node.as<Declaration>().setCanonicalID(ID()); };
};

// Visitor computing canonical IDs.
struct VisitorComputeCanonicalIDs : public visitor::PreOrder<ID, VisitorComputeCanonicalIDs> {
    // This visitor runs twice, with slightly different behaviour by pass.
    VisitorComputeCanonicalIDs(int pass) : pass(pass) { assert(pass == 1 || pass == 2); }

    int pass;
    ID parent_id;
    ID module_id;
    int ctor_struct_count = 0;
    Scope* module_scope = nullptr;

    result_t operator()(const Module& m, position_t p) {
        module_id = m.id();
        module_scope = p.node.scope().get();
        return m.id();
    }

    result_t operator()(const Declaration& d, position_t p) {
        if ( const auto& id = d.canonicalID() )
            return id;

        ID id;

        // A couple of special-cases for top-level declarations.
        if ( parent_id.length() == 1 ) {
            // 1. If the ID is qualified with the current module, the ID is
            // fine as it is.
            if ( d.id().sub(0) == module_id )
                id = d.id();

            // 2. If the ID refers to something inside an imported module, we
            // likewise use the ID as it is.
            else if ( auto x = module_scope->lookup(d.id().sub(0)); x && x->node->isA<declaration::ImportedModule>() )
                id = d.id();
        }

        if ( auto x = d.tryAs<declaration::ImportedModule>() )
            // Use the namespace to the imported module as our ID.
            id = x->id();

        if ( ! id )
            // By default, prefix the ID with the current parent.
            id = ID(parent_id, d.id());

        // Record the ID if we don't have one yet.
        if ( ! d.canonicalID() )
            p.node.as<Declaration>().setCanonicalID(id);

        // During the 1st pass, we also prefer shorter IDs over longer ones to
        // avoid ambiguous if we have multiple paths reaching the node.
        else if ( pass == 1 && id.length() < d.canonicalID().length() )
            p.node.as<Declaration>().setCanonicalID(id);

        return d.canonicalID();
    }

    result_t operator()(const expression::Ctor& d, position_t p) {
        // Special-case: Struct ctors are creating temporary struct types,
        // inside which our standard scheme wouldn't assign any canonical IDs
        // because we don't descend down into expressions. So we do this
        // manually here. However, we need to "invent" a random ID for the type
        // as theirs no globally reachable declaration.
        if ( ! d.type().isA<type::Struct>() )
            return {};

        // Create a fake current ID and then restart ID computation below the
        // current node.
        auto id = ID(util::fmt("%s::<anon-struct-%d>", parent_id, ++ctor_struct_count));
        _computeCanonicalIDs(this, const_cast<Node*>(d.children().data()), std::move(id));
        return {};
    }
};

// Visitor double-checking that all declarations have their canonical IDs set.
struct VisitorCheckCanonicalIDs : public visitor::PreOrder<void, VisitorCheckCanonicalIDs> {
    result_t operator()(const Declaration& d, position_t p) {
        if ( ! d.canonicalID() )
            hilti::render(std::cerr, p.node);
        assert(d.canonicalID());
    };
};

static void _computeCanonicalIDs(VisitorComputeCanonicalIDs* v, Node* node, ID current) {
    v->parent_id = current;

    if ( auto x = v->dispatch(node) )
        current = *x;

    if ( node->pruneWalk() )
        return;

    if ( v->pass == 1 && node->isA<Expression>() )
        // During the 1st pass we don't descend into expressions to avoid
        // ambiguities with multiple paths reaching the same node.
        return;

    for ( auto& c : node->children() )
        _computeCanonicalIDs(v, &c, current);
}

bool hilti::detail::ast::normalize(Node* root, Unit* unit) {
    util::timing::Collector _("hilti/compiler/ast/normalizer");

    auto v0 = VisitorConstants();
    for ( auto i : v0.walk(root) )
        v0.dispatch(i);

    if ( logger().errors() )
        return v0.modified;

    auto v1 = VisitorNormalizer();
    for ( auto i : v1.walk(root) )
        v1.dispatch(i);

    auto v2 = VisitorComputeCanonicalIDs(1);
    _computeCanonicalIDs(&v2, root, ID());

    auto v3 = VisitorComputeCanonicalIDs(2);
    _computeCanonicalIDs(&v3, root, ID());

#ifndef NDEBUG
    auto v4 = VisitorCheckCanonicalIDs();
    for ( auto i : v4.walk(root) )
        v4.dispatch(i);
#endif

    return v0.modified || v1.modified;
}
