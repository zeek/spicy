// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/operators/function.h>
#include <hilti/ast/operators/struct.h>
#include <hilti/ast/types/bitfield.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/regexp.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/driver.h>

#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/grammar-builder.h>
#include <spicy/compiler/detail/codegen/grammar.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

using hilti::util::fmt;

namespace spicy::logging::debug {
inline const hilti::logging::DebugStream CodeGen("spicy-codegen");
} // namespace spicy::logging::debug

namespace {

// Visitor that runs over each module's AST at the beginning of their
// transformations. All module will be processed by this visitor before the
// subsequent passes execute.
struct VisitorPass1 : public visitor::MutatingPostOrder {
    VisitorPass1(CodeGen* cg, hilti::declaration::Module* module)
        : visitor::MutatingPostOrder(cg->builder(), logging::debug::CodeGen), cg(cg), module(module) {}

    CodeGen* cg;
    hilti::declaration::Module* module = nullptr;
    ID module_id = ID("<no module>");

    void operator()(hilti::declaration::Type* n) final {
        // Replace unit type with compiled struct type.
        auto u = n->type()->type()->tryAs<type::Unit>();
        if ( ! u )
            return;

        if ( auto r = cg->grammarBuilder()->run(u); ! r ) {
            hilti::logger().error(r.error().description(), n->location());
            return;
        }

        bool declare_only = false;
        if ( auto m = n->parent<hilti::declaration::Module>(); m && m->skipImplementation() )
            declare_only = true;

        auto struct_ = cg->compileUnit(u, declare_only);
        struct_->setDeclarationIndex(n->declarationIndex());

        auto qstruct = builder()->qualifiedType(struct_, n->type()->constness());

        n->setType(context(), qstruct);
        n->addAttribute(context(), builder()->attribute("&on-heap"));
        cg->recordTypeMapping(u, struct_);

        recordChange(n, "replaced unit type with struct");
    }

    void operator()(spicy::ctor::Unit* n) final {
        // Replace unit ctor with an equivalent struct ctor.
        auto new_n = builder()->ctorStruct(n->fields(), n->meta());
        replaceNode(n, new_n);
    }
};

// Visitor that runs repeatedly over the AST of a module until no further
// changes are made by it for that module.
struct VisitorPass2 : public visitor::MutatingPostOrder {
    VisitorPass2(CodeGen* cg, hilti::declaration::Module* module)
        : visitor::MutatingPostOrder(cg->builder(), logging::debug::CodeGen), cg(cg), module(module) {}

    CodeGen* cg;
    hilti::declaration::Module* module = nullptr;
    ID module_id = ID("<no module>");

    Expression* argument(Expression* args, unsigned int i, std::optional<Expression*> def = {}) {
        auto ctor = args->as<hilti::expression::Ctor>()->ctor();

        if ( auto x = ctor->tryAs<hilti::ctor::Coerced>() )
            ctor = x->coercedCtor();

        auto value = ctor->as<hilti::ctor::Tuple>()->value();

        if ( i < value.size() )
            return ctor->as<hilti::ctor::Tuple>()->value()[i];

        if ( def )
            return *def;

        hilti::logger().internalError(fmt("missing argument %d", i));
    }

    void operator()(hilti::declaration::Property* n) final { cg->recordModuleProperty(*n); }

    void operator()(declaration::UnitHook* n) final {
        const auto& hook = n->hook();
        const auto& unit_type = context()->lookup(n->hook()->unitTypeIndex());
        assert(unit_type);

        auto func =
            cg->compileHook(*unit_type->as<type::Unit>(), n->hook()->id(), {}, hook->isForEach(), hook->isDebug(),
                            hook->ftype()->parameters(), hook->body(), hook->priority(), n->meta());

        replaceNode(n, func);
    }

    void operator()(operator_::unit::Unset* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        replaceNode(n, builder()->unset(n->op0(), id, n->meta()));
    }

    void operator()(operator_::unit::MemberConst* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        replaceNode(n, builder()->member(n->op0(), id, n->meta()));
    }

    void operator()(operator_::unit::MemberNonConst* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        replaceNode(n, builder()->member(n->op0(), id, n->meta()));
    }

    void operator()(operator_::unit::TryMember* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        replaceNode(n, builder()->tryMember(n->op0(), id, n->meta()));
    }

    void operator()(operator_::unit::HasMember* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        replaceNode(n, builder()->hasMember(n->op0(), id, n->meta()));
    }

    void operator()(operator_::unit::MemberCall* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        const auto& args = n->op2()->as<hilti::expression::Ctor>()->ctor()->as<hilti::ctor::Tuple>();
        replaceNode(n, builder()->memberCall(n->op0(), id, args, n->meta()));
    }

    void operator()(operator_::unit::Offset* n) final { replaceNode(n, builder()->member(n->op0(), ID("__offset"))); }

    void operator()(operator_::unit::Position* n) final {
        auto begin = builder()->member(n->op0(), ID("__begin"));
        auto offset = builder()->member(n->op0(), ID("__offset"));
        replaceNode(n, builder()->grouping(builder()->sum(begin, offset)));
    }

    void operator()(operator_::unit::Input* n) final {
        auto begin = builder()->member(n->op0(), ID("__begin"));
        replaceNode(n, begin);
    }

    void operator()(operator_::unit::SetInput* n) final {
        auto cur = builder()->member(n->op0(), ID("__position_update"));
        replaceNode(n, builder()->assign(cur, argument(n->op2(), 0)));
    }

    void operator()(operator_::unit::Find* n) final {
        auto begin = builder()->member(n->op0(), ID("__begin"));
        auto offset = builder()->member(n->op0(), ID("__offset"));
        auto end = builder()->sum(begin, offset);
        auto needle = argument(n->op2(), 0);
        auto direction = argument(n->op2(), 1, builder()->id("spicy::Direction::Forward"));
        auto i = argument(n->op2(), 2, builder()->null());
        auto x = builder()->call("spicy_rt::unit_find", {begin, end, i, needle, direction});
        replaceNode(n, x);
    }

    void operator()(operator_::unit::ContextConst* n) final {
        auto x = builder()->member(n->op0(), ID("__context"));
        replaceNode(n, x);
    }

    void operator()(operator_::unit::ContextNonConst* n) final {
        auto x = builder()->member(n->op0(), ID("__context"));
        replaceNode(n, x);
    }

    void operator()(operator_::unit::Backtrack* n) final {
        auto x = builder()->call("spicy_rt::backtrack", {});
        replaceNode(n, x);
    }

    void operator()(spicy::ctor::Unit* n) final {
        // Replace unit ctor with an equivalent struct ctor.
        auto x = builder()->ctorStruct(n->fields(), n->meta());
        replaceNode(n, x);
    }

    void operator()(operator_::unit::ConnectFilter* n) final {
        auto x = builder()->call("spicy_rt::filter_connect", {n->op0(), argument(n->op2(), 0)});
        replaceNode(n, x);
    }

    void operator()(operator_::unit::Forward* n) final {
        auto x = builder()->call("spicy_rt::filter_forward", {n->op0(), argument(n->op2(), 0)});
        replaceNode(n, x);
    }

    void operator()(operator_::unit::ForwardEod* n) final {
        auto x = builder()->call("spicy_rt::filter_forward_eod", {n->op0()});
        replaceNode(n, x);
    }

    void operator()(operator_::sink::Close* n) final {
        auto x = builder()->memberCall(n->op0(), "close");
        replaceNode(n, x);
    }

    void operator()(operator_::sink::Connect* n) final {
        auto x = builder()->memberCall(n->op0(), "connect", {argument(n->op2(), 0)});
        replaceNode(n, x);
    }

    void operator()(operator_::sink::ConnectMIMETypeBytes* n) final {
        auto x = builder()->memberCall(n->op0(), "connect_mime_type", {argument(n->op2(), 0), builder()->scope()});
        replaceNode(n, x);
    }

    void operator()(operator_::sink::ConnectMIMETypeString* n) final {
        auto x = builder()->memberCall(n->op0(), "connect_mime_type", {argument(n->op2(), 0), builder()->scope()});
        replaceNode(n, x);
    }

    void operator()(operator_::sink::ConnectFilter* n) final {
        auto x = builder()->memberCall(n->op0(), "connect_filter", {argument(n->op2(), 0)});
        replaceNode(n, x);
    }

    void operator()(operator_::sink::Gap* n) final {
        auto x = builder()->memberCall(n->op0(), "gap", {argument(n->op2(), 0), argument(n->op2(), 1)});
        replaceNode(n, x);
    }

    void operator()(operator_::sink::SequenceNumber* n) final {
        auto x = builder()->memberCall(n->op0(), "sequence_number");
        replaceNode(n, x);
    }

    void operator()(operator_::sink::SetAutoTrim* n) final {
        auto x = builder()->memberCall(n->op0(), "set_auto_trim", {argument(n->op2(), 0)});
        replaceNode(n, x);
    }

    void operator()(operator_::sink::SetInitialSequenceNumber* n) final {
        auto x = builder()->memberCall(n->op0(), "set_initial_sequence_number", {argument(n->op2(), 0)});
        replaceNode(n, x);
    }

    void operator()(operator_::sink::SetPolicy* n) final {
        auto x = builder()->memberCall(n->op0(), "set_policy", {argument(n->op2(), 0)});
        replaceNode(n, x);
    }

    void operator()(operator_::sink::SizeValue* n) final {
        auto x = builder()->memberCall(n->op0(), "size");
        replaceNode(n, x);
    }

    void operator()(operator_::sink::SizeReference* n) final {
        auto x = builder()->memberCall(n->op0(), "size");
        replaceNode(n, x);
    }

    void operator()(operator_::sink::Skip* n) final {
        auto x = builder()->memberCall(n->op0(), "skip", {argument(n->op2(), 0)});
        replaceNode(n, x);
    }

    void operator()(operator_::sink::Trim* n) final {
        auto x = builder()->memberCall(n->op0(), "trim", {argument(n->op2(), 0)});
        replaceNode(n, x);
    }

    void operator()(operator_::sink::Write* n) final {
        auto x = builder()->memberCall(n->op0(), "write",
                                       {argument(n->op2(), 0), argument(n->op2(), 1, builder()->null()),
                                        argument(n->op2(), 2, builder()->null())});
        replaceNode(n, x);
    }

    void operator()(statement::Print* n) final {
        auto exprs = n->expressions();

        switch ( exprs.size() ) {
            case 0: {
                auto call = builder()->call("hilti::print", {builder()->stringLiteral("")});
                replaceNode(n, builder()->statementExpression(call, n->location()));
                break;
            }

            case 1: {
                auto call = builder()->call("hilti::print", exprs);
                replaceNode(n, builder()->statementExpression(call, n->location()));
                break;
            }

            default: {
                auto call = builder()->call("hilti::printValues", {builder()->tuple(exprs)});
                replaceNode(n, builder()->statementExpression(call, n->location()));
                break;
            }
        }
    }

    void operator()(statement::Confirm* n) final {
        // TODO(bbannier): Add validation checking whether `self` is actually a valid identifier here.
        auto call = builder()->call("spicy_rt::confirm", {builder()->deref(builder()->id("self"))});
        replaceNode(n, builder()->statementExpression(call, n->location()));
    }

    void operator()(statement::Reject* n) final {
        // TODO(bbannier): Add validation checking whether `self` is actually a valid identifier here.
        auto call = builder()->call("spicy_rt::reject", {builder()->deref(builder()->id("self"))});
        replaceNode(n, builder()->statementExpression(call, n->location()));
    }

    void operator()(statement::Stop* n) final {
        auto b = builder()->newBlock();
        b->addAssign(builder()->id("__stop"), builder()->bool_(true), n->meta());
        b->addReturn(n->meta());
        replaceNode(n, b->block());
    }

    void operator()(type::Sink* n) final {
        // Strong reference (instead of value reference) so that copying unit
        // instances doesn't copy the sink.
        auto sink = builder()->typeStrongReference(
            builder()->qualifiedType(builder()->typeName("spicy_rt::Sink", n->meta()), hilti::Constness::Mutable));
        replaceNode(n, sink);
    }

    void operator()(type::Unit* n) final {
        // Replace usage of the unit type with a reference to the compiled struct.
        if ( auto t = n->parent()->tryAs<hilti::declaration::Type>();
             ! t && ! n->parent(2)->tryAs<hilti::declaration::Type>() ) {
            auto old = context()->lookup(n->declarationIndex());
            assert(old->fullyQualifiedID());

            auto name = builder()->typeName(old->fullyQualifiedID(), n->meta());
            name->setResolvedTypeIndex(n->typeIndex());
            replaceNode(n, name);
        }
    }
};

// Visitor that runs once over every module at the very end once the ASTs are
// pure HILTI.
struct VisitorPass3 : public visitor::MutatingPostOrder {
    VisitorPass3(CodeGen* cg, hilti::declaration::Module* module)
        : visitor::MutatingPostOrder(cg->builder(), logging::debug::CodeGen), cg(cg), module(module) {}

    CodeGen* cg;
    hilti::declaration::Module* module = nullptr;

    void operator()(hilti::ctor::Coerced* n) final {
        // Replace coercions with their final result, so that HILTI will not
        // see them (because if it did, it wouldn't apply further HILTI-side
        // coercions to the result anymore).
        replaceNode(n, n->coercedCtor(), "removed coercion");
    }

    void operator()(hilti::expression::Name* n) final {
        if ( auto d = n->resolvedDeclaration() ) {
            // We need to re-resolve IDs (except function calls) during
            // subsequent HILTI pass, so we clear out the current resolution.
            // Because these IDs may now reside in a different context than
            // originally, we record their fully qualified name for subsequent
            // resolutions.
            if ( ! n->parent()->isA<hilti::operator_::function::Call>() ) {
                recordChange(n, "reverted to unresolved");
                n->setFullyQualifiedID(d->fullyQualifiedID());
                n->clearResolvedDeclarationIndex(context());
            }
        }
    }
};

} // anonymous namespace

bool CodeGen::_compileModule(hilti::declaration::Module* module, int pass) {
    switch ( pass ) {
        case 1: {
            auto v1 = VisitorPass1(this, module);
            visitor::visit(v1, module, ".spicy");
            _updateDeclarations(&v1, module);
            return v1.isModified();
        }

        case 2: {
            bool is_modified = false;

            auto v2 = VisitorPass2(this, module);
            while ( true ) {
                v2.clearModified();

                visitor::visit(v2, module, ".spicy");
                _updateDeclarations(&v2, module);

                if ( v2.isModified() )
                    is_modified = true;
                else
                    return is_modified;
            }
        }

        case 3: {
            module->add(context(), builder()->import("hilti"));
            module->add(context(), builder()->import("spicy_rt"));

            auto v3 = VisitorPass3(this, module);
            visitor::visit(v3, module, ".spicy");
            _updateDeclarations(&v3, module);

            if ( driver()->lookupUnit(module->uid()) ) {
                driver()->updateProcessExtension(module->uid(), ".hlt");
                assert(module->uid().process_extension == ".hlt");
            }
            else {
                auto new_uid = module->uid();
                new_uid.process_extension = ".hlt";
                module->setUID(std::move(new_uid));
            }

            return v3.isModified();
        }

        default: hilti::logger().internalError("unknown codegen pass");
    }

    hilti::util::cannotBeReached();
}

void CodeGen::_updateDeclarations(visitor::MutatingPostOrder* v, hilti::declaration::Module* module) {
    if ( hilti::logger().errors() || _new_decls.empty() )
        return;

    for ( const auto& n : _new_decls )
        module->add(builder()->context(), n);

    _new_decls.clear();
    v->recordChange("new declarations added");
}

bool CodeGen::compileAST(hilti::ASTRoot* root) {
    hilti::util::timing::Collector _("spicy/compiler/codegen");

    // Find all the Spicy modules and transform them one by one. We do this in
    // two passes, each going over all modules one time. That way the 1st pass
    // can work cross-module before any changes done by the 2nd pass.
    struct VisitorModule : public visitor::PostOrder {
        VisitorModule(CodeGen* cg, int pass) : cg(cg), pass(pass) {}

        CodeGen* cg;
        int pass;
        bool modified = false;

        void operator()(hilti::declaration::Module* n) final {
            if ( n->uid().process_extension == ".spicy" ) {
                auto module = n;
                HILTI_DEBUG(logging::debug::CodeGen,
                            fmt("[pass %d] processing module '%s'", pass, module->canonicalID()));
                hilti::logging::DebugPushIndent _(logging::debug::CodeGen);

                cg->_hilti_module = module;
                modified = modified | cg->_compileModule(module, pass);
                cg->_hilti_module = nullptr;
            }
        }
    };

    auto modified = visitor::visit(VisitorModule(this, 1), root, ".spicy", [](const auto& v) { return v.modified; });
    modified |= visitor::visit(VisitorModule(this, 2), root, ".spicy", [](const auto& v) { return v.modified; });
    modified |= visitor::visit(VisitorModule(this, 3), root, ".spicy", [](const auto& v) { return v.modified; });

    // Update the context with type changes record by any of the passes.
    for ( auto [old, new_] : _type_mappings )
        context()->replace(old, new_);

    return modified;
}

hilti::declaration::Function* CodeGen::compileHook(const type::Unit& unit, const ID& id, type::unit::item::Field* field,
                                                   bool foreach, bool debug, hilti::type::function::Parameters params,
                                                   Statement* body, Expression* priority, const hilti::Meta& meta) {
    if ( debug && ! options().debug )
        return {};

    bool is_container = false;
    QualifiedType* original_field_type = nullptr;

    if ( field ) {
        if ( ! field->parseType()->type()->isA<hilti::type::Void>() && ! field->isSkip() )
            original_field_type = field->originalType();

        is_container = field->isContainer();
    }
    else {
        // Try to locate field by ID.
        if ( auto i = unit.itemByName(id.local()) ) {
            if ( auto f = i->tryAs<type::unit::item::Field>() ) {
                if ( ! f->parseType()->type()->isA<hilti::type::Void>() && ! f->isSkip() ) {
                    is_container = f->isContainer();
                    field = f;
                    original_field_type = f->originalType();
                }
            }
        }
    }

    if ( foreach ) {
        params.push_back(
            builder()->parameter("__dd", field->ddType()->type()->elementType()->type(), hilti::parameter::Kind::In));
        params.push_back(builder()->parameter("__stop", builder()->typeBool(), hilti::parameter::Kind::InOut));
    }
    else if ( original_field_type ) {
        params.push_back(builder()->parameter("__dd", field->itemType()->type(), hilti::parameter::Kind::In));

        // Pass on captures for fields of type regexp, which are the only
        // ones that have it (for vector of regexps, it wouldn't be clear what
        // to bind to).
        if ( original_field_type->type()->isA<hilti::type::RegExp>() && ! is_container )
            params.push_back(
                builder()->parameter("__captures", builder()->typeName("hilti::Captures"), hilti::parameter::Kind::In));
    }

    std::string hid;
    QualifiedType* result = nullptr;

    if ( id.local().str() == "0x25_print" ) {
        // Special-case: We simply translate this into HITLI's __str__ hook.
        auto string_ = builder()->qualifiedType(builder()->typeString(), hilti::Constness::Const);
        result = builder()->qualifiedType(builder()->typeOptional(string_), hilti::Constness::Const);
        hid = "__str__";
    }
    else {
        result = builder()->qualifiedType(builder()->typeVoid(), hilti::Constness::Const);
        hid = fmt("__on_%s%s", id.local(), (foreach ? "_foreach" : ""));
    }

    if ( ! id.namespace_().empty() )
        hid = fmt("%s::%s", id.namespace_(), hid);

    auto ft = builder()->typeFunction(result, params, hilti::type::function::Flavor::Hook, meta);

    AttributeSet* attrs = builder()->attributeSet();

    if ( priority )
        attrs->add(context(), builder()->attribute("&priority", priority));

    auto f = builder()->function(ID(hid), ft, body, hilti::function::CallingConvention::Standard, attrs, meta);
    return builder()->declarationFunction(f, hilti::declaration::Linkage::Struct, meta);
}

hilti::declaration::Module* CodeGen::hiltiModule() const {
    if ( ! _hilti_module )
        hilti::logger().internalError("not compiling a HILTI unit");

    return _hilti_module;
}
