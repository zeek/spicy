// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

// TODO:
//   (*self).fxx = default<Foo>();
//   (_t_cur, _t_lah, _t_lahe, _t_error) = (*(*self).fxx)._t_parse_stage1(_t_data, _t_cur, _t_trim, _t_lah, _t_lahe,
//   _t_error);
//
//   Should we change this to always work on a stack variable first so that we can tag this as a write that can be
//   removed if unused?


#include <hilti/ast/attribute.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/operators/struct.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

namespace {

struct Collector : public optimizer::visitor::Collector {
    using optimizer::visitor::Collector::Collector;

    struct Field {
        declaration::Field* decl = nullptr;
        type::Struct* struct_ = nullptr;
        std::vector<Node*> reads;
        std::vector<Node*> writes;
        std::vector<Node*> unsets;
    };

    std::map<ID, Field> fields;

    void done() override {
        if ( ! logger().isEnabled(logging::debug::OptimizerPasses) )
            return;

        HILTI_DEBUG(logging::debug::OptimizerPasses, "Struct variables:");
        for ( const auto& [id, field] : fields ) {
            assert(field.decl && field.struct_);
            HILTI_DEBUG(logging::debug::OptimizerPasses,
                        util::fmt("    %s  #reads=%zu #writes=%zu #unsets=%zu", field.decl->fullyQualifiedID(),
                                  field.reads.size(), field.writes.size(), field.unsets.size()));
        }
    }

    bool considerField(declaration::Field* field) {
        if ( ! field->parent()->isA<type::Struct>() )
            return false;

        if ( field->isNoEmit() )
            return false; // already being skipped

        if ( field->isStatic() )
            return false; // leave it in, won't really hurt

        if ( field->type()->type()->isA<type::Function>() )
            return false; // unused function are removed by other passes

        if ( field->attributes()->find(hilti::attribute::kind::NeededByFeature) )
            return false; // features are handled by other passes

        if ( field->attributes()->find(hilti::attribute::kind::AlwaysEmit) )
            return false; // somebody definitely wants this

        auto* struct_ = field->parent()->as<type::Struct>();
        auto* sdecl = struct_->typeDeclaration();
        if ( ! sdecl )
            return false; // some anonymous struct

        if ( sdecl->attributes()->find(hilti::attribute::kind::Cxxname) )
            return false; // don't change fields defined in external C++ structs

        return true;
    }

    Field* fieldForOperator(expression::ResolvedOperator* op) {
        const auto& id = op->op1()->as<expression::Member>()->id();
        auto* t = op->op0()->type()->type();

        if ( auto* x = t->tryAs<type::ValueReference>() )
            t = x->dereferencedType()->type();

        auto* struct_ = t->tryAs<type::Struct>();
        assert(struct_);

        auto* sfield = struct_->field(id);
        if ( ! sfield )
            return nullptr; // might have been removed already elsewhere

        if ( considerField(sfield) )
            return &fields[sfield->canonicalID()];
        else
            return nullptr;
    }

    void operator()(ctor::struct_::Field* n) final {
        auto* struct_ = n->parent()->as<ctor::Struct>()->stype();
        auto* sfield = struct_->field(n->id());
        if ( ! sfield )
            return; // might have been removed already elsewhere
                    //
        if ( ! considerField(sfield) )
            return;

        auto& field = fields[sfield->canonicalID()];
        field.writes.push_back(n);
    }

    void operator()(declaration::Field* n) final {
        if ( ! considerField(n) )
            return;

        if ( auto* struct_ = n->parent()->tryAs<type::Struct>() ) {
            auto& field = fields[n->canonicalID()];
            field.decl = n;
            field.struct_ = struct_;
        }
    }

    void operator()(operator_::struct_::HasMember* n) final {
        if ( auto* field = fieldForOperator(n) )
            field->reads.push_back(n);
    }

    // We don't track methods.
    // void operator()(operator_::struct_::MemberCall* n) final {
    // }

    void operator()(operator_::struct_::MemberConst* n) final {
        if ( auto* field = fieldForOperator(n) )
            field->reads.push_back(n);
    }

    void operator()(operator_::struct_::MemberNonConst* n) final {
        if ( auto* field = fieldForOperator(n) ) {
            if ( auto* tuple_assign = n->parent(3)->tryAs<operator_::tuple::CustomAssign>();
                 tuple_assign && tuple_assign->op0()->hasChild(n, true) )
                field->writes.push_back(n);
            else if ( auto* assign = n->parent<expression::Assign>(); assign && assign->target() == n )
                field->writes.push_back(n);
            else
                field->reads.push_back(n);
        }
    }

    void operator()(operator_::struct_::TryMember* n) final {
        if ( auto* field = fieldForOperator(n) )
            field->reads.push_back(n);
    }

    void operator()(operator_::struct_::Unset* n) final {
        auto* field = fieldForOperator(n);
        field->unsets.push_back(n);
    }
};

struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const Collector* collector)
        : optimizer::visitor::Mutator(optimizer), collector(collector) {}

    const Collector* collector = nullptr;

    bool run(Node* node = nullptr) override {
        // This is an unusual mutator in that it doesn't iterate the AST
        // itself, but works directly on the nodes identified by the collector.
        for ( const auto& [id, field] : collector->fields ) {
            if ( field.decl->isNoEmit() )
                continue;

            bool emit_field = true;

            if ( field.reads.empty() && field.writes.empty() && field.unsets.empty() )
                emit_field = false;

            if ( ! emit_field ) {
                recordChange(field.decl, "field unused, setting to &noemit");
                field.decl->attributes()->add(context(), builder()->attribute(attribute::kind::NoEmit,
                                                                              builder()->string("optimized", true)));
                setModified();
            }
        }

        return isModified();
    }
};

bool run(Optimizer* optimizer) {
    if ( *optimizer->context()->compilerContext()->options().strict_public_api )
        return false;

    Collector collector(optimizer);
    collector.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass remove_unused_fields({.id = PassID::RemoveUnusedFields,
                                              .guarantees = Guarantees::None,
                                              .run = run});

} // namespace
