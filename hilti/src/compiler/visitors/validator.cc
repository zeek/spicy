// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <unordered_set>

#include <hilti/ast/detail/visitor.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/global.h>

using namespace hilti;
using util::fmt;

namespace {

struct Visitor : public visitor::PostOrder<void, Visitor> {
    void preDispatch(const Node& n, int level) override {
        // Validate that identifier names are not reused.
        for ( const auto& [id, nodes] : n.scope()->items() ) {
            if ( nodes.size() <= 1 )
                continue;

            const auto& firstNode = nodes.front();
            for ( auto it = std::next(nodes.begin()); it != nodes.end(); ++it ) {
                const auto& node = *it;

                // We whitelist functions and import declarations as they can legitimately appear multiple times.
                // To not permit shadowing of e.g., variable declarations with function declarations, we require nodes
                // with identical names to have identical types unless we are in an `ImportedModule` declaration
                // referring to a previously declared `Module` of the same name.
                if ( node->isA<declaration::Function>() && node->typeid_() == firstNode->typeid_() )
                    continue;
                else if ( node->isA<declaration::ImportedModule>() &&
                          (node->typeid_() == firstNode->typeid_() || firstNode->isA<Module>()) )
                    continue;

                logger().error(fmt("redefinition of '%s' defined in %s", id, firstNode->location()), node->location());
            }
        }
    };

    ////// Declarations

    void operator()(const declaration::Constant& n) {
        if ( n.value().type().isWildcard() )
            logger().error("cannot use wildcard type for constants", n);
    }

    void operator()(const declaration::LocalVariable& n) {
        if ( ! type::isAllocable(n.type()) )
            logger().error(fmt("type '%s' cannot be used for variable declaration", n.type()), n);

        if ( n.type().isWildcard() )
            logger().error("cannot use wildcard type for variables", n);

        if ( ! n.typeArguments().empty() ) {
            auto t = n.type();

            if ( type::isReferenceType(t) )
                t = t.dereferencedType();

            if ( ! t.isA<type::Struct>() )
                logger().error("only struct types can have arguments", n);
        }
    }

    void operator()(const declaration::Parameter& n, const_position_t p) {
        if ( ! type::isAllocable(n.type()) && n.type() != type::Any() )
            logger().error(fmt("type '%s' cannot be used for function parameter", n.type()), n);

        if ( n.type().isWildcard() ) {
            if ( auto d = p.parent(3).tryAs<declaration::Function>() ) {
                if ( ! AttributeSet::find(d->function().attributes(), "&cxxname") )
                    logger().error(fmt("parameter '%s' cannot have wildcard type; only allowed with runtime library "
                                       "functions declared with &cxxname",
                                       n.id()),
                                   n);
            }

            if ( auto d = p.parent(4).tryAs<declaration::Type>() ) {
                if ( ! AttributeSet::find(d->attributes(), "&cxxname") )
                    logger().error(fmt("parameter '%s' cannot have wildcard type; only allowed with methods in runtime "
                                       "library structs declared with &cxxname",
                                       n.id()),
                                   n);
            }
        }
    }

    void operator()(const declaration::GlobalVariable& n) {
        if ( ! type::isAllocable(n.type()) )
            logger().error(fmt("type '%s' cannot be used for variable declaration", n.type()), n);

        if ( n.type().isWildcard() )
            logger().error("cannot use wildcard type for variables", n);

        if ( auto args = n.typeArguments(); args.size() ) {
            if ( ! n.type().isA<type::Struct>() )
                logger().error("only struct types can have arguments", n);
        }
    }

    ////// Ctors

    void operator()(const ctor::Default& c, const_position_t p) {}

    void operator()(const ctor::List& n) {
        auto t = n.elementType();

        if ( ! n.value().empty() && t == type::unknown )
            logger().error("non-empty list cannot have unknown type", n);
    }

    void operator()(const ctor::Null& c, const_position_t p) {}

    void operator()(const ctor::SignedInteger& n) {
        auto [min, max] = util::signed_integer_range(n.type().width());

        if ( n.value() < min || n.value() > max )
            logger().error("integer value out of range for type", n);
    }

    void operator()(const ctor::Struct& n) {
        // TODO(robin): .
    }

    void operator()(const ctor::UnsignedInteger& n) {
        auto [min, max] = util::unsigned_integer_range(n.type().width());

        if ( n.value() < min || n.value() > max )
            logger().error("integer value out of range for type", n);
    }

    void operator()(const ctor::Vector& n) {
        auto t = n.elementType();

        if ( ! n.value().empty() && t == type::unknown )
            logger().error("non-empty vector cannot have unknown type", n);
    }

    ////// Expressions

    void operator()(const expression::Assign& n) {
        if ( ! n.target().isLhs() )
            logger().error(fmt("cannot assign to expression: %s", to_node(n)), n);
    }

    void operator()(const expression::ListComprehension& n) {
        if ( ! type::isIterable(n.input().type()) )
            logger().error("input value not iterable", n);
    }

    void operator()(const expression::Ternary& n) {
        if ( ! hilti::type::sameExceptForConstness(n.true_().type(), n.false_().type()) )
            logger().error(fmt("types of alternatives do not match in ternary expression (%s vs. %s)", n.true_().type(),
                               n.false_().type()),
                           n);
    }

    void operator()(const expression::TypeWrapped& n) {
        if ( n.validateTypeMatch() && n.expression().type() != n.type() )
            logger().error(fmt("type mismatch, expression has type '%s', but expected '%s'", n.expression().type(),
                               n.type()),
                           n);
    }

    void operator()(const expression::UnresolvedID& n, position_t p) {
        if ( ! p.node.error() )
            logger().error("expression left unresolved", n);
    }

    ////// Statements

    void operator()(const statement::For& n) {
        if ( ! type::isIterable(n.sequence().type()) )
            logger().error("value not iterable", n);
    }

    void operator()(const statement::If& n) {
        if ( ! (n.init() || n.condition()) )
            logger().error("'if' header lacking both condition and declaration", n);
    }

    void operator()(const statement::Break& n, const_position_t p) {
        auto w = p.findParent<statement::While>();
        auto f = p.findParent<statement::For>();

        if ( ! (f || w) ) {
            logger().error("'break' outside of loop", n);
            return;
        }
    }

    void operator()(const statement::Continue& n, const_position_t p) {
        auto w = p.findParent<statement::While>();
        auto f = p.findParent<statement::For>();

        if ( ! (f || w) ) {
            logger().error("'continue' outside of loop", n);
            return;
        }
    }

    void operator()(const statement::Return& n, const_position_t p) {
        auto func = p.findParent<Function>();

        if ( ! func ) {
            logger().error("'return' outside of function", n);
            return;
        }

        if ( func->get().type().result().type() == type::Void() ) {
            if ( n.expression() )
                logger().error("void function cannot return a value", n);
        }
        else {
            if ( ! n.expression() )
                logger().error("function must return a value", n);
        }
    }

    void operator()(const statement::Switch& n) {
        if ( n.cases().empty() )
            logger().error("switch statement has no cases", n);
    }

    void operator()(const statement::Throw& n, const_position_t p) {
        if ( auto e = n.expression() ) {
            if ( ! e->type().isA<type::Exception>() )
                logger().error("'throw' argument must be an exception");
        }
        else {
            if ( ! p.findParent<statement::try_::Catch>() )
                logger().error("'throw' without expression can only be inside 'catch'", n);
        }
    }

    void operator()(const statement::try_::Catch& n) {
        if ( n.parameter() && ! n.parameter()->type().isA<type::Exception>() )
            logger().error("type of catch parameter must be an exception", n.meta().location());
    }

    void operator()(const statement::Try& n) {
        if ( n.catches().empty() ) {
            logger().error("'try' statement without any 'catch'");
            return;
        }

        auto defaults = 0;

        for ( const auto& c : n.catches() ) {
            if ( ! c.parameter() )
                ++defaults;
        }

        if ( defaults > 1 )
            logger().error("'try` statement cannot have more than one defaullt `catch`");
    }

    void operator()(const statement::While& n) {
        if ( ! (n.init() || n.condition()) )
            logger().error("'while' header lacking both condition and declaration");
    }

    void operator()(const expression::ResolvedOperator& n, const_position_t p) {
        // We are running after both overload resolution and the
        // apply-coercion pass, so operands types are ensured to be fine at
        // this point, so only need to run operator-specific validation.
        n.operator_().validate(n, p);
    }

    void operator()(const expression::UnresolvedOperator& n, const_position_t p) {
        if ( ! p.node.error() )
            logger().error("operator left unresolved", n);
    }

    ////// Types

    void operator()(const type::Exception& n) {
        if ( n.baseType() && ! n.baseType()->isA<type::Exception>() )
            logger().error("exception's base type must be an exception type as well");
    }

    void operator()(const type::Function& n) {
        if ( n.flavor() == type::function::Flavor::Hook ) {
            auto r = n.result().type();
            if ( ! (r == type::Void() || r.isA<type::Optional>()) )
                logger().error(fmt("hooks must have return type either void or optional<T>"));
        }
    }

    void operator()(const type::SignedInteger& n) {
        auto w = n.width();

        if ( w != 8 && w != 16 && w != 32 && w != 64 && ! n.isWildcard() )
            logger().error(fmt("integer type's width must be one of 8/16/32/64, but is %d", n.width()), n);
    }

    void operator()(const type::UnsignedInteger& n) {
        auto w = n.width();

        if ( w != 8 && w != 16 && w != 32 && w != 64 && ! n.isWildcard() )
            logger().error(fmt("integer type's width must be one of 8/16/32/64, but is %d", n.width()), n);
    }

    void operator()(const type::Optional& n) {
        if ( n.isWildcard() )
            return;

        if ( auto t = n.dereferencedType(); ! type::isAllocable(t) )
            logger().error(fmt("type %s cannot be used inside optional", t), n);
    }

    void operator()(const type::StrongReference& n) {
        if ( n.isWildcard() )
            return;

        if ( auto t = n.dereferencedType(); ! type::isAllocable(t) )
            logger().error(fmt("type %s is not allocable and can thus not be used with references", t), n);
    }

    void operator()(const type::Result& n) {
        if ( n.isWildcard() )
            return;

        if ( auto t = n.dereferencedType(); ! type::isAllocable(t) )
            logger().error(fmt("type %s cannot be used inside result", t), n);
    }

    void operator()(const type::Struct& n) {
        std::set<ID> seen;

        for ( const auto& f : n.fields() ) {
            if ( seen.find(f.id()) != seen.end() && ! f.type().isA<type::Function>() )
                logger().error("duplicate attribute in struct type", n);

            seen.insert(f.id());

            if ( f.isStatic() && f.default_() )
                logger().error("&default is currently not supported for static fields", n);
        }

        for ( const auto& p : n.parameters() ) {
            switch ( p.kind() ) {
                case declaration::parameter::Kind::Copy:
                case declaration::parameter::Kind::In:
                    // Nothing to check.
                    break;

                case declaration::parameter::Kind::InOut:
                    if ( ! type::isReferenceType(p.type()) )
                        logger().error("only parameters of reference type can be 'inout' for struct parameters", n);
                    break;

                case declaration::parameter::Kind::Unknown:
                    logger().error("parameter kind unexpectedly not known", n);
                    break;
            }
        }
    }

    void operator()(const type::Union& n) {
        std::set<ID> seen;

        for ( const auto& f : n.fields() ) {
            if ( seen.find(f.id()) != seen.end() )
                logger().error("duplicate attribute in union type", n);

            seen.insert(f.id());
        }
    }

    void operator()(const type::Tuple& n) {
        for ( const auto& t : n.types() ) {
            if ( ! type::isAllocable(t) )
                logger().error(fmt("type '%s' cannot be used inside a tuple", t), n);
        }
    }

    void operator()(const type::UnresolvedID& n, position_t p) {
        if ( ! p.node.error() )
            logger().error("ID left unresolved", n);
    }

    void operator()(const type::WeakReference& n) {
        if ( n.isWildcard() )
            return;

        if ( auto t = n.dereferencedType(); ! type::isAllocable(t) )
            logger().error(fmt("type %s is not allocable and can thus not be used with weak references", t), n);
    }
};

} // anonymous namespace

static int _validateAST(const Node& root, bool do_dispatch) {
    util::timing::Collector _("hilti/compiler/validator");

    std::unordered_set<std::string> errors;

    auto v = Visitor();
    for ( auto i : v.walk(root) ) {
        if ( auto e = i.node.error() ) {
            // To avoid showing chains of errors triggering each other, we
            // report only the 1st error per source location. (The more
            // precise way would be: do not report current node if any child
            // has an error, but this is easier and should be good enough for
            // now.)
            if ( errors.find(i.node.location()) == errors.end() ) {
                logger().error(*e, i.node.errorContext(), i.node.location());
                errors.insert(i.node.location());
            }
        }

        if ( do_dispatch )
            v.dispatch(i);
    }

    return static_cast<int>(errors.size());
}

void hilti::detail::validateAST(const Node& root) { _validateAST(root, true); }

bool hilti::reportErrorsInAST(const Node& root) { return _validateAST(root, false) != 0; }

int64_t detail::errorsInAST(const Node& n) {
    int64_t errors = 0;

    for ( const auto& i : ::hilti::visitor::PreOrder<>().walk(n) ) {
        if ( i.node.error() )
            ++errors;
    }

    return errors;
}

uint64_t detail::hashAST(const Node& n) {
    uint64_t hash = 0;

    for ( const auto& i : ::hilti::visitor::PreOrder<>().walk(n) ) {
        hash = (hash << 1U) | (hash >> 63U);
        hash ^= static_cast<uint64_t>(i.node.identity());
    }

    return hash;
}

int64_t detail::unresolvedInAST(const Node& n) {
    int64_t unresolved = 0;

    for ( const auto& i : ::hilti::visitor::PreOrder<>().walk(n) ) {
        if ( i.node.isA<::hilti::expression::UnresolvedID>() || i.node.isA<::hilti::expression::UnresolvedOperator>() ||
             i.node.isA<::hilti::type::UnresolvedID>() )
            ++unresolved;
    }

    return unresolved;
}
