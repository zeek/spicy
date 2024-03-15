// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <unordered_set>
#include <utility>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/default.h>
#include <hilti/ast/ctors/exception.h>
#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/ctors/list.h>
#include <hilti/ast/ctors/map.h>
#include <hilti/ast/ctors/set.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/ctors/vector.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/expressions/assign.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/list-comprehension.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/ternary.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operators/all.h>
#include <hilti/ast/statements/break.h>
#include <hilti/ast/statements/continue.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/ast/statements/for.h>
#include <hilti/ast/statements/if.h>
#include <hilti/ast/statements/return.h>
#include <hilti/ast/statements/throw.h>
#include <hilti/ast/statements/try.h>
#include <hilti/ast/statements/while.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/bitfield.h>
#include <hilti/ast/types/enum.h>
#include <hilti/ast/types/exception.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/name.h>
#include <hilti/ast/types/null.h>
#include <hilti/ast/types/optional.h>
#include <hilti/ast/types/result.h>
#include <hilti/ast/types/string.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/union.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/validator.h>

using namespace hilti;
using util::fmt;

void validator::VisitorMixIn::error(std::string msg, Node* n, node::ErrorPriority priority) {
    n->addError(std::move(msg), n->location(), priority);
    ++_errors;
}

void validator::VisitorMixIn::error(std::string msg, std::vector<std::string> context, Node* n,
                                    node::ErrorPriority priority) {
    n->addError(std::move(msg), n->location(), priority, std::move(context));
    ++_errors;
}

void validator::VisitorMixIn::error(std::string msg, Node* n, const Node* other, node::ErrorPriority priority) {
    n->addError(std::move(msg), other->location(), priority);
    ++_errors;
}

void validator::VisitorMixIn::error(std::string msg, Node* n, Location l, node::ErrorPriority priority) {
    n->addError(std::move(msg), std::move(l), priority);
    ++_errors;
}

namespace {
struct VisitorPre : visitor::PreOrder, public validator::VisitorMixIn {
    using hilti::validator::VisitorMixIn::VisitorMixIn;
};

struct VisitorPost : visitor::PreOrder, public validator::VisitorMixIn {
    using hilti::validator::VisitorMixIn::VisitorMixIn;

    // Returns an error if the given type cannot be used for ordering at
    // runtime.
    Result<Nothing> isSortable(QualifiedType* t) {
        if ( ! t->type()->isSortable() )
            return result::Error(fmt("type '%s' is not sortable", *t));

        // Sortability of tuples requires sortable element types.
        if ( auto tt = t->type()->tryAs<type::Tuple>() ) {
            for ( const auto& e : tt->elements() ) {
                if ( auto rc = isSortable(e->type()); ! rc )
                    return rc;
            }
        }

        return Nothing();
    }

    void checkStructArguments(const node::Range<Expression>& have, const node::Set<type::function::Parameter>& want,
                              Node* n) {
        if ( have.size() > want.size() ) {
            error(fmt("type expects %u parameter%s, but receives %u", want.size(), (want.size() > 1 ? "s" : ""),
                      have.size()),
                  n);
        }

        for ( size_t i = 0; i < want.size(); i++ ) {
            if ( i < have.size() ) {
                if ( type::same(have[i]->type(), want[i]->type()) )
                    continue;

                if ( type::sameExceptForConstness(have[i]->type(), want[i]->type()) && want[i]->type()->isConstant() )
                    continue;

                error(fmt("type expects %s for parameter %u, but receives %s", *want[i]->type(), i + 1,
                          *have[i]->type()),
                      n);
            }
            else if ( ! want[i]->default_() )
                error(fmt("type parameter %u is missing (%s)", i + 1, want[i]->id()), n);
        }
    }

    void operator()(Node* n) final {
        if ( ! n->scope() )
            return;

        // Validate that identifier names are not reused.
        for ( const auto& [id, nodes] : n->scope()->items() ) {
            if ( nodes.size() <= 1 )
                continue;

            const auto& first_node = *std::min_element(nodes.begin(), nodes.end(), [](const auto& a, const auto& b) {
                return a->location() < b->location();
            });

            for ( const auto& node : nodes ) {
                if ( node->location() == first_node->location() )
                    continue;

                // Functions can legitimately be overloaded.
                if ( node->isA<declaration::Function>() ) {
                    if ( first_node->tryAs<declaration::Function>() )
                        continue;
                }

                // Modules of the same name can be imported if they come with different scopes.
                if ( const auto& m1 = node->tryAs<declaration::Module>() ) {
                    if ( const auto& m2 = first_node->tryAs<declaration::Module>(); m2 && m1->scope() != m2->scope() )
                        continue;
                }

                error(fmt("redefinition of '%s' defined in %s", id, first_node->location()), node);
            }
        }
    }

    void operator()(Function* n) final {
        if ( auto attrs = n->attributes() ) {
            if ( auto prio = attrs->find("&priority") ) {
                if ( n->ftype()->flavor() != type::function::Flavor::Hook )
                    error("only hooks can have priorities", n);

                else if ( auto x = prio->valueAsInteger(); ! x )
                    error(x.error(), n);
            }
        }
    }

    ////// Declarations

    // Perform validation of ID names suitable for all types of declarations.
    void operator()(Declaration* n) final {
        // 'self' is only ok for our internally created 'self' declarations,
        // which are expressions.
        if ( n->id().str() == "self" && ! n->isA<declaration::Expression>() )
            error("cannot use 'self' as identifier", n);
    }

    void operator()(declaration::Constant* n) final {
        if ( n->value()->type()->isWildcard() )
            error("cannot use wildcard type for constants", n);
    }

    void operator()(declaration::Function* n) final {
        if ( ! operator_::registry().byBuiltinFunctionID(n->id().local()).empty() )
            error("function uses reserved ID", n);

        if ( n->id().namespace_() && ! n->linkedPrototypeIndex() && n->errors().empty() )
            n->addError(util::fmt("no such function: '%s'", n->id()));
    }

    void operator()(declaration::LocalVariable* n) final {
        if ( auto t = n->type()->type();
             ! t->isAllocable() && ! t->isA<type::Unknown>() ) // unknown will be reported elsewhere
            error(fmt("type '%s' cannot be used for variable declaration", *n->type()), n);

        if ( n->type()->isWildcard() )
            error("cannot use wildcard type for variables", n);

        if ( n->parent()->isA<statement::Block>() ) {
            // If we're at the block level, check type arguments. If not, we're
            // part of another statement (like if/while/...) where
            // initialization happens internally.
            if ( ! n->typeArguments().empty() ) {
                auto t = n->type();

                if ( t->type()->isReferenceType() )
                    t = t->type()->dereferencedType();

                if ( t->type()->parameters().empty() )
                    error("type does not take arguments", n);
            }

            if ( ! n->type()->type()->parameters().empty() )
                checkStructArguments(n->typeArguments(), n->type()->type()->parameters(), n);
        }

        // Check whether this local variable was declared at module scope. We
        // need to match exact parent nodes here to not match other locals
        // three levels under a `Module` (e.g., a local in a `while` statement
        // at module scope).
        if ( n->pathLength() > 3 && n->parent(1)->isA<statement::Declaration>() &&
             n->parent(2)->isA<statement::Block>() && n->parent(3)->isA<declaration::Module>() )
            error("local variables cannot be declared at module scope", n);
    }

    void operator()(declaration::ImportedModule* n) final {
        if ( ! n->uid() )
            error(fmt("could not import module %s", n->id()), n);
    }

    void operator()(declaration::Parameter* n) final {
        if ( ! n->type()->type()->isA<type::Auto>() ) {
            if ( ! n->type()->type()->isAllocable() && ! n->type()->type()->isA<type::Any>() )
                error(fmt("type '%s' cannot be used for function parameter", *n->type()), n);
        }

        if ( n->type()->isWildcard() ) {
            if ( auto d = n->parent(4)->tryAs<declaration::Function>() ) {
                if ( ! d->function()->attributes()->has("&cxxname") )
                    error(fmt("parameter '%s' cannot have wildcard type; only allowed with runtime library "
                              "functions declared with &cxxname",
                              n->id()),
                          n);
            }

            if ( auto d = n->parent(4)->tryAs<declaration::Type>() ) {
                if ( ! d->attributes()->has("&cxxname") )
                    error(fmt("parameter '%s' cannot have wildcard type; only allowed with methods in runtime "
                              "library structs declared with &cxxname",
                              n->id()),
                          n);
            }
        }

        if ( auto attrs = n->attributes() )
            for ( const auto& attr : attrs->attributes() ) {
                if ( attr->tag() != "&requires-type-feature" )
                    error(fmt("invalid attribute '%s' for function parameter", attr->tag()), n);

                else {
                    if ( auto x = attr->valueAsString(); ! x )
                        error(x.error(), n);
                }
            }
    }

    void operator()(declaration::GlobalVariable* n) final {
        if ( auto t = n->type()->type();
             ! t->isAllocable() && ! t->isA<type::Unknown>() ) // unknown will be reported elsewhere
            error(fmt("type '%s' cannot be used for variable declaration", *n->type()), n);

        if ( n->type()->isWildcard() )
            error("cannot use wildcard type for variables", n);

        if ( auto args = n->typeArguments(); args.size() ) {
            if ( n->type()->type()->parameters().empty() )
                error("type does not take arguments", n);
        }

        if ( ! n->type()->type()->parameters().empty() )
            checkStructArguments(n->typeArguments(), n->type()->type()->parameters(), n);
    }

    ////// Ctors

    void operator()(ctor::Default* n) final {
        auto t = n->type()->type();

        if ( auto vr = t->tryAs<type::ValueReference>() )
            t = vr->dereferencedType()->type();

        if ( auto args = n->typeArguments(); args.size() ) {
            if ( t->parameters().empty() )
                error("type does not take arguments", n);
        }

        if ( ! t->parameters().empty() )
            checkStructArguments(n->typeArguments(), t->parameters(), n);
    }

    void operator()(hilti::ctor::Exception* n) final {
        if ( auto x = n->value()->tryAs<hilti::expression::Ctor>() )
            if ( ! x->type()->type()->isA<type::String>() )
                error("exceptions need to be a string", n);
    }

    void operator()(ctor::List* n) final {
        if ( ! n->value().empty() && n->elementType()->type()->isA<type::Unknown>() ) {
            // List constructors are often used to initialize other elements,
            // and those may coerce them into the right type even if the
            // elements aren't consistent. We assume we are all good in that
            // case.
            if ( auto c = n->parent()->tryAs<ctor::Coerced>(); ! c || c->type()->type()->isA<type::Unknown>() )
                error("list elements have inconsistent types", n);
        }
    }

    void operator()(ctor::Map* n) final {
        if ( ! n->value().empty() &&
             (n->keyType()->type()->isA<type::Unknown>() || n->valueType()->type()->isA<type::Unknown>()) )
            error("map elements have inconsistent types", n);
    }

    void operator()(ctor::Null* n) final {}

    void operator()(ctor::SignedInteger* n) final {
        auto [min, max] = util::signedIntegerRange(n->width());

        if ( n->value() < min || n->value() > max )
            error("integer value out of range for type", n);
    }

    void operator()(ctor::Set* n) final {
        if ( ! n->value().empty() && n->elementType()->type()->isA<type::Unknown>() )
            error("set elements have inconsistent types", n);
    }

    void operator()(ctor::UnsignedInteger* n) final {
        auto [min, max] = util::unsignedIntegerRange(n->width());

        if ( n->value() < min || n->value() > max )
            error("integer value out of range for type", n);
    }

    void operator()(ctor::Vector* n) final {
        if ( ! n->value().empty() && n->elementType()->type()->isA<type::Unknown>() )
            error("vector elements have inconsistent types", n);
    }

    ////// Expressions

    void operator()(expression::Assign* n) final {
        if ( n->target()->type()->constness() == Constness::Const )
            error(fmt("cannot assign to constant expression: %s", *n), n);

        else if ( n->target()->type()->side() != Side::LHS )
            error(fmt("cannot assign to RHS expression: %s", *n), n);

        if ( ! n->hasErrors() ) { // no need for more checks if coercer has already flagged it
            if ( ! type::sameExceptForConstness(n->source()->type(), n->target()->type()) )
                error(fmt("type mismatch for assignment, expected type %s but got %s", *n->target()->type(),
                          *n->source()->type()),
                      n);
        }
    }

    void operator()(expression::ListComprehension* n) final {
        if ( ! n->input()->type()->type()->iteratorType() )
            error("input value not iterable", n);
    }

    void operator()(expression::Ternary* n) final {
        if ( ! hilti::type::sameExceptForConstness(n->true_()->type(), n->false_()->type()) ) {
            error(fmt("types of alternatives do not match in ternary expression (%s vs. %s)", *n->true_()->type(),
                      *n->false_()->type()),
                  n);
        }
    }

    void operator()(expression::Name* n) final {
        if ( auto decl = n->resolvedDeclaration() ) {
            if ( auto parent = n->parent<Declaration>();
                 decl == parent && ! decl->isA<declaration::Function>() && n->id() != ID("__dd") ) {
                error(fmt("ID '%s' cannot be used inside its own declaration", n->id()), n);
                return;
            }
        }
        else {
            // We prefer the error message from a parent's unresolved call operator.
            auto op = n->parent()->tryAs<expression::UnresolvedOperator>();
            if ( ! op || op->kind() != operator_::Kind::Call )
                error(fmt("unknown ID '%s'", n->id()), n);
        }
    }

    ////// Statements

    void operator()(statement::For* n) final {
        if ( ! n->sequence()->type()->type()->iteratorType() )
            error("value not iterable", n);
    }

    void operator()(statement::If* n) final {
        if ( ! (n->init() || n->condition()) )
            error("'if' header lacking both condition and declaration", n);
    }

    void operator()(statement::Break* n) final {
        auto w = n->parent<statement::While>();
        auto f = n->parent<statement::For>();

        if ( ! (f || w) ) {
            error("'break' outside of loop", n);
            return;
        }
    }

    void operator()(statement::Continue* n) final {
        auto w = n->parent<statement::While>();
        auto f = n->parent<statement::For>();

        if ( ! (f || w) ) {
            error("'continue' outside of loop", n);
            return;
        }
    }

    void operator()(statement::Return* n) final {
        auto func = n->parent<Function>();

        if ( ! func ) {
            error("'return' outside of function", n);
            return;
        }

        if ( func->ftype()->result()->type()->isA<type::Void>() ) {
            if ( n->expression() )
                error("void function cannot return a value", n);
        }
        else {
            if ( ! n->expression() )
                error("function must return a value", n);
        }
    }

    void operator()(statement::Switch* n) final {}

    void operator()(statement::Throw* n) final {
        if ( auto e = n->expression() ) {
            if ( ! e->type()->type()->isA<type::Exception>() ) {
                error("'throw' argument must be an exception", n);
            }
        }
        else {
            if ( ! n->parent<statement::try_::Catch>() )
                error("'throw' without expression can only be inside 'catch'", n);
        }
    }

    void operator()(statement::try_::Catch* n) final {
        if ( n->parameter() && ! n->parameter()->type()->type()->isA<type::Exception>() )
            error("type of catch parameter must be an exception", n);
    }

    void operator()(statement::Try* n) final {
        if ( n->catches().empty() ) {
            error("'try' statement without any 'catch'", n);
            return;
        }

        auto defaults = 0;

        for ( const auto& c : n->catches() ) {
            if ( ! c->parameter() )
                ++defaults;
        }

        if ( defaults > 1 )
            error("'try` statement cannot have more than one default `catch`", n);
    }

    void operator()(statement::While* n) final {
        if ( ! (n->init() || n->condition()) )
            error("'while' header lacking both condition and declaration", n);
    }

    void operator()(expression::ResolvedOperator* n) final {
        // We are running after both overload resolution and the
        // apply-coercion pass, so operands types are ensured to be fine at
        // this point, so only need to run operator-specific validation.
        n->operator_().validate(n);
    }

    void operator()(expression::UnresolvedOperator* n) final {
        if ( ! n->errors().empty() )
            return;

        if ( n->kind() == operator_::Kind::Call ) {
            // Customized error message for calls to functions.
            std::vector<std::string> context;
            if ( auto [valid, candidates] = operator_::registry().functionCallCandidates(n);
                 valid && ! candidates->empty() ) {
                context.emplace_back("candidates:");
                for ( auto op : *candidates )
                    context.emplace_back(util::fmt("- %s", op->print()));
            }

            error(fmt("call does not match any function: %s", n->printSignature()), std::move(context), n);
        }
        else if ( n->kind() == operator_::Kind::MemberCall ) {
            // Customized error message for calls to methods.
            std::vector<std::string> context;

            if ( auto candidates = operator_::registry().byMethodID(n->op1()->as<expression::Member>()->id());
                 ! candidates.empty() ) {
                // Apply heuristic on op0 to limit the candidates reported.
                std::vector<std::string> cands;
                for ( auto op : candidates ) {
                    if ( type::same(op->op0()->type()->type(), n->op0()->type()->type()) )
                        cands.emplace_back(util::fmt("- %s", op->print()));
                    else {
                        if ( auto vt = n->op0()->type()->type()->tryAs<type::ValueReference>();
                             vt && type::same(op->op0()->type()->type(), vt->dereferencedType()->type()) )
                            cands.emplace_back(util::fmt("- %s", op->print()));
                    }
                }

                if ( ! cands.empty() ) {
                    context.emplace_back("candidates:");
                    for ( const auto& c : cands )
                        context.emplace_back(c);
                }
            }

            error(fmt("call does not match any method: %s", n->printSignature()), std::move(context), n);
        }
        else
            error(fmt("unsupported operator: %s", n->printSignature()), n);
    }

    ////// Types

    void operator()(type::Auto* n) final { error("automatic type has not been resolved", n, node::ErrorPriority::Low); }

    void operator()(type::bitfield::BitRange* n) final {
        const auto lower = n->lower();
        const auto upper = n->upper();

        if ( lower > upper )
            error("lower limit needs to be lower than upper limit", n);

        if ( upper >= n->fieldWidth() )
            error("upper limit is beyond the width of the bitfield", n);

        if ( auto expr = n->ctorValue() ) {
            if ( auto expr_ = expr->tryAs<expression::Ctor>() ) {
                auto ctor = expr_->ctor();

                if ( auto x = ctor->tryAs<ctor::Coerced>() )
                    ctor = x->coercedCtor();

                if ( auto i = ctor->tryAs<ctor::UnsignedInteger>() ) {
                    if ( i->value() > (1U << (upper - lower + 1)) - 1 )
                        error("value is outside of bitfield element's range", n);
                }
            }
        }
    }

    void operator()(type::Enum* n) final {
        std::unordered_set<int> seen;

        for ( const auto& label : n->labels() ) {
            auto [it, inserted] = seen.insert(label->value());
            if ( ! inserted ) {
                error(fmt("enum values are not unique"), n);
            }
        }
    }

    void operator()(type::Exception* n) final {
        if ( n->baseType() && ! type::follow(n->baseType())->isA<type::Exception>() ) {
            error("exception's base type must be an exception type as well", n);
        }
    }

    void operator()(type::Function* n) final {
        if ( n->flavor() == type::function::Flavor::Hook ) {
            auto r = n->result()->type();
            if ( ! (r->isA<type::Void>() || r->isA<type::Optional>()) )
                error(fmt("hooks must have return type either void or optional<T>"), n);
        }
    }

    void operator()(type::Map* n) final {
        if ( auto rc = isSortable(n->keyType()); ! rc )
            error(fmt("type cannot be used as key type for maps (because %s)", rc.error()), n);
    }

    void operator()(type::SignedInteger* n) final {
        auto w = n->width();

        if ( w != 8 && w != 16 && w != 32 && w != 64 && ! n->isWildcard() )
            error(fmt("integer type's width must be one of 8/16/32/64, but is %d", n->width()), n);
    }

    void operator()(type::UnsignedInteger* n) final {
        auto w = n->width();

        if ( w != 8 && w != 16 && w != 32 && w != 64 && ! n->isWildcard() )
            error(fmt("integer type's width must be one of 8/16/32/64, but is %d", n->width()), n);
    }

    void operator()(type::Optional* n) final {
        if ( n->isWildcard() )
            return;

        if ( const auto& t = n->dereferencedType(); ! t->type()->isAllocable() )
            error(fmt("type %s cannot be used inside optional", *t), n);
    }

    void operator()(type::StrongReference* n) final {
        if ( n->isWildcard() )
            return;

        if ( const auto& t = n->dereferencedType(); ! t->type()->isAllocable() )
            error(fmt("type %s is not allocable and can thus not be used with references", *t), n);
    }

    void operator()(type::Result* n) final {
        if ( n->isWildcard() )
            return;

        if ( const auto& t = n->dereferencedType(); ! t->type()->isAllocable() )
            error(fmt("type %s cannot be used inside result", *t), n);
    }

    void operator()(type::Struct* n) final {
        std::set<ID> seen;

        for ( const auto& f : n->fields() ) {
            if ( seen.find(f->id()) != seen.end() && ! f->type()->type()->isA<type::Function>() )
                error("duplicate attribute in struct type", n);

            seen.insert(f->id());

            if ( f->isStatic() && f->default_() )
                error("&default is currently not supported for static fields", n);

            if ( auto d = f->default_(); d && ! type::sameExceptForConstness(d->type(), f->type()) )
                error(fmt("type mismatch for &default expression, expecting type %s, got %s", *f->type(), *d->type()),
                      n);

            if ( f->id().str() == "~finally" ) {
                auto ft = f->type()->type()->tryAs<type::Function>();
                if ( ! ft ) {
                    error("~finally must be a hook", n);
                    continue;
                }

                if ( ft->flavor() != type::function::Flavor::Hook )
                    error("~finally must be a hook", n);

                if ( ! ft->result()->type()->isA<type::Void>() )
                    error("~finally must have return type void", n);

                if ( ft->parameters().size() )
                    error("~finally cannot take any parameters", n);
            }
        }

        for ( const auto& param : n->parameters() ) {
            switch ( param->kind() ) {
                case parameter::Kind::Copy:
                case parameter::Kind::In:
                case parameter::Kind::InOut:
                    // Nothing to check.
                    break;

                case parameter::Kind::Unknown: error("parameter kind unexpectedly not known", n); break;
            }
        }
    }

    void operator()(type::Union* n) final {
        std::set<ID> seen;

        for ( const auto& f : n->fields() ) {
            if ( seen.find(f->id()) != seen.end() )
                error("duplicate attribute in union type", n);

            seen.insert(f->id());
        }
    }

    void operator()(type::Tuple* n) final {
        for ( const auto& e : n->elements() ) {
            if ( ! e->type()->type()->isAllocable() && ! e->type()->type()->isA<type::Null>() )
                error(fmt("type '%s' cannot be used inside a tuple", *e->type()), n, node::ErrorPriority::Low);
        }
    }

    void operator()(type::Name* n) final {
        if ( ! n->resolvedTypeIndex() && ! n->hasErrors() )
            error(fmt("unknown ID '%s'", n->id()), n);
    }

    void operator()(type::WeakReference* n) final {
        if ( n->isWildcard() )
            return;

        if ( const auto& t = n->dereferencedType(); ! t->type()->isAllocable() )
            error(fmt("type %s is not allocable and can thus not be used with weak references", *t), n);
    }

    // Operators (only special cases here, most validation happens where they are defined)

    void operator()(operator_::generic::New* n) final {
        // We reuse the _checkStructArguments() here, that's why this operator is covered here.
        if ( auto t = n->operands()[0]->type()->type()->tryAs<type::Type_>() ) {
            if ( ! t->typeValue()->type()->parameters().empty() ) {
                node::Range<Expression> args;
                if ( n->operands().size() > 1 ) {
                    auto ctor = n->operands()[1]->as<expression::Ctor>()->ctor();
                    if ( auto x = ctor->tryAs<ctor::Coerced>() )
                        ctor = x->coercedCtor();

                    args = ctor->as<ctor::Tuple>()->value();
                }

                checkStructArguments(args, t->typeValue()->type()->parameters(), n);
            }
        }
    }
};

} // anonymous namespace

void validator::detail::validatePre(Builder* builder, ASTRoot* root) {
    util::timing::Collector _("hilti/compiler/ast/validator");
    ::hilti::visitor::visit(VisitorPre(builder), root);
}

void validator::detail::validatePost(Builder* builder, ASTRoot* root) {
    util::timing::Collector _("hilti/compiler/ast/validator");
    ::hilti::visitor::visit(VisitorPost(builder), root);
}
