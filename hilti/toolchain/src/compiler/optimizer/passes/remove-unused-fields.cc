// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

// TODO:
//   (*self).fxx = default<Foo>();
//   (_t_cur, _t_lah, _t_lahe, _t_error) = (*(*self).fxx)._t_parse_stage1(_t_data, _t_cur, _t_trim, _t_lah, _t_lahe,
//   _t_error);
//
//   Should we change this to always work on a stack variable first so that we can tag this as a write that can be
//   removed if unused?
//
//   Replace checks for constants with a hasSideEffect() that may take flow into account as well.


#include <hilti/ast/attribute.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/operators/struct.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

namespace {

// Records read, writes, and unset operations on all relevant struct fields.
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
        if ( logger().isEnabled(logging::debug::OptimizerPasses) ) {
            HILTI_DEBUG(logging::debug::OptimizerPasses, "Struct variables:");
            for ( const auto& [id, field] : fields ) {
                assert(field.decl && field.struct_);
                HILTI_DEBUG(logging::debug::OptimizerPasses,
                            util::fmt("    %s  #reads=%zu #writes=%zu #unsets=%zu", field.decl->fullyQualifiedID(),
                                      field.reads.size(), field.writes.size(), field.unsets.size()));
            }
        }
    }

    // Returns true if a field should be considered for removal.
    bool considerField(declaration::Field* field) const {
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

        if ( sdecl->linkage() == declaration::Linkage::Export )
            return false; // don't change fields defined in exported type

        if ( sdecl->attributes()->find(hilti::attribute::kind::Cxxname) )
            return false; // don't change fields defined in external C++ structs

        return true;
    }

    // Given a struct field access operator, returns the corresponding field
    // declaration if the field is being considered for removal. Returns null
    // otherwise.
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
            return &fields[sfield->fullyQualifiedID()];
        else
            return nullptr;
    }

    void operator()(ctor::struct_::Field* n) final {
        auto* struct_ = n->parent()->as<ctor::Struct>()->stype();
        auto* sfield = struct_->field(n->id());
        if ( ! sfield )
            return; // might have been removed already elsewhere

        if ( ! considerField(sfield) )
            return;

        auto& field = fields[sfield->fullyQualifiedID()];
        field.writes.push_back(n);
    }

    void operator()(declaration::Field* n) final {
        if ( ! considerField(n) )
            return;

        if ( auto* struct_ = n->parent()->tryAs<type::Struct>() ) {
            auto& field = fields[n->fullyQualifiedID()];
            field.decl = n;
            field.struct_ = struct_;

            if ( auto* default_ = n->default_(); default_ && ! default_->isA<expression::Ctor>() )
                // Non-constant default is like a write.
                field.writes.push_back(default_->parent<Attribute>());
        }
    }

    void operator()(operator_::struct_::HasMember* n) final {
        if ( auto* field = fieldForOperator(n) )
            field->reads.push_back(n);
    }

    void operator()(operator_::struct_::MemberConst* n) final {
        if ( auto* field = fieldForOperator(n) )
            field->reads.push_back(n);
    }

    void operator()(operator_::struct_::MemberNonConst* n) final {
        if ( auto* field = fieldForOperator(n) ) {
            if ( auto* tuple_assign = n->parent<operator_::tuple::CustomAssign>();
                 tuple_assign && tuple_assign->op0()->hasChild(n, true) )
                field->writes.push_back(n);
            else if ( auto* assign = n->parent<expression::Assign>(); assign && assign->target() == n )
                field->writes.push_back(n);
            else {
                field->reads.push_back(n);

                if ( const auto* transfer = state()->cfgCache()->dataflow(n); ! transfer || ! transfer->write.empty() )
                    field->writes.push_back(n);
            }
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

// Removes unused struct fields based on data collected by the Collector,
// replacing any remaining access operations with appropriate defaults/no-ops.
struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const Collector* collector)
        : optimizer::visitor::Mutator(optimizer), collector(collector) {}

    const Collector* collector = nullptr;

    // Removes a field from a struct.
    void removeField(const Collector::Field& field) {
        recordChange(field.decl, "field unused, setting to &noemit");
        field.decl->attributes()->add(context(), builder()->attribute(attribute::kind::NoEmit,
                                                                      builder()->stringLiteral("optimized")));
    }

    // Removes reads to a given field. Handles all read cases identified by the
    // collector (and only those), and assumes there are no reads to the field.
    void removeReads(const Collector::Field& field) {
        for ( auto* read : field.reads ) {
            if ( read->isA<operator_::struct_::MemberConst>() || read->isA<operator_::struct_::MemberNonConst>() ||
                 read->isA<operator_::struct_::TryMember>() ) {
                if ( field.decl->isOptional() ) {
                    Expression* default_ = field.decl->default_();
                    if ( default_ )
                        replaceNode(read, default_, "replacing read of unwritten optional field with default");

                    else {
                        Expression* throw_;
                        if ( read->isA<operator_::struct_::TryMember>() )
                            throw_ = builder()->call("hilti::throw_attribute_not_set", {});
                        else
                            throw_ = builder()->call("hilti::throw_unset_optional", {});

                        default_ = builder()->default_(field.decl->type()->type());
                        auto* always_throw = builder()->grouping({throw_, default_});
                        replaceNode(read, always_throw, "replacing read of unwritten optional field with exception");
                    }
                }
                else {
                    Expression* default_ = field.decl->default_();
                    if ( ! default_ )
                        default_ = builder()->default_(field.decl->type()->type());

                    replaceNode(read, default_, "replacing read of unwritten field with default");
                }
            }

            else if ( auto* n = read->tryAs<operator_::struct_::HasMember>() ) {
                if ( field.decl->isOptional() )
                    replaceNode(n, builder()->bool_(false),
                                "replacing has-member check of unwritten optional field with false");
                else
                    replaceNode(n, builder()->bool_(true),
                                "replacing has-member check of unwritten optional field with true");
            }

            else
                // All cases identified by the collector should be handled above.
                hilti::rt::cannot_be_reached();
        }
    }

    // Removes writes to a given field. Handles all write cases identified by
    // the collector (and only those), and assumes there are no writes to the
    // field.
    void removeWrites(const Collector::Field& field) {
        for ( auto* write : field.writes ) {
            if ( auto* n = write->tryAs<ctor::struct_::Field>() ) {
                // Remove field initialization from struct constructor. We
                // limit this to the simple case where the removed
                // initialization value is a constant value. In that case it
                // has no side effects, so it's safe to just drop it. For other
                // expression we'd need to move the initialization value to
                // some other place to evaluate, which doesn't seem worth  the
                // effort.
                if ( const auto* expr = n->expression(); ! state()->cfgCache()->mayHaveSideEffects(expr) ) {
                    auto* ctor = n->parent()->as<ctor::Struct>();
                    ctor->removeField(n->id());

                    if ( auto* coerced = ctor->parent()->tryAs<ctor::Coerced>() )
                        // If part of a coercion, remove from original
                        // ctor as well as that's what's being rendered
                        // when printing the AST.
                        coerced->originalCtor()->as<ctor::Struct>()->removeField(n->id());

                    recordChange(n, "removing initialization of field never read");
                }
            }

            else if ( auto* n = write->tryAs<operator_::struct_::MemberNonConst>() ) {
                if ( auto* tuple_assign = n->parent<operator_::tuple::CustomAssign>() ) {
                    // Remove field assignment from inside LHS tuple .
                    auto* lhs = tuple_assign->op0()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>();
                    auto idx = lhs->index(n);
                    assert(idx >= 0);

                    bool rhs_handled = false;
                    if ( auto* x = tuple_assign->op1()->tryAs<expression::Ctor>() ) {
                        if ( auto* rhs = x->ctor()->tryAs<ctor::Tuple>() ) {
                            auto* old_element = rhs->removeElement(idx);
                            rhs->setType(context(),
                                         QualifiedType::createAuto(context())); // let type re-resolve
                            rhs_handled = true;

                            // If the old value can have side effects, we need
                            // to still evaluate it, so create a group
                            // expression.
                            if ( state()->cfgCache()->mayHaveSideEffects(old_element) ) {
                                auto* old_rhs = tuple_assign->removeOp1();
                                auto* new_rhs = builder()->grouping({old_element, old_rhs});
                                tuple_assign->setOp1(context(), new_rhs);
                            }
                        }
                    }

                    if ( ! rhs_handled ) {
                        // Not a tuple ctor on the RHS, need to decompose tuple manually.
                        auto* old_tuple_type = tuple_assign->op1()->type()->type()->as<type::Tuple>();
                        auto new_rhs = builder()->groupingWithTmp("elem", tuple_assign->op1());

                        Expressions new_elements;
                        for ( uint64_t i = 0; i < old_tuple_type->elements().size(); i++ ) {
                            if ( std::cmp_not_equal(i, idx) )
                                new_elements.push_back(builder()->index(new_rhs.first, builder()->integer(i)));
                        }

                        new_rhs.second->setExpressions(context(),
                                                       {builder()->tuple(new_elements, tuple_assign->meta())});
                        tuple_assign->setOp1(context(), new_rhs.second);
                    }

                    recordChange(n, "removing assign to field never read");
                    lhs->removeElement(idx);
                    lhs->setType(context(), QualifiedType::createAuto(context())); // let type re-resolve
                }

                else if ( auto* assign = n->parent<expression::Assign>() ) {
                    // "target = source" -> "source"
                    auto* source = assign->removeSource();
                    replaceNode(assign, source, "removing write to field never read");
                }
                else
                    // All cases identified by the collector should be handled above.
                    hilti::rt::cannot_be_reached();
            }
            else if ( auto* attr = write->tryAs<Attribute>() ) {
                assert(attr->kind() == attribute::kind::Default);
                recordChange(attr, "removing default for field never read");
                field.decl->attributes()->remove(attr);
            }
            else
                // All cases identified by the collector should be handled above.
                hilti::rt::cannot_be_reached();
        }
    }

    // Removes unsets of a given field.
    void removeUnsets(const Collector::Field& field) {
        for ( auto* unset : field.unsets ) {
            // "unset op.field" -> "op"
            auto* op0 = unset->as<operator_::struct_::Unset>()->removeOp0();
            replaceNode(unset, op0, "removing unsetting of removed field");
        }
    }

    bool run(Node* node = nullptr) override {
        // This is an unusual mutator in that it doesn't iterate the AST itself
        // but works directly on the nodes identified by the collector.
        for ( const auto& [id, field] : collector->fields ) {
            if ( field.decl->isNoEmit() )
                continue;

            if ( field.reads.empty() && field.writes.empty() ) {
                removeField(field);
                removeUnsets(field);
            }

            else if ( field.reads.empty() && ! field.writes.empty() )
                removeWrites(field);

            else if ( ! field.reads.empty() && field.writes.empty() )
                removeReads(field);
        }

        return isModified();
    }
};

bool run(Optimizer* optimizer) {
    if ( optimizer->context()->compilerContext()->options().public_api_mode == Options::PublicAPIMode::Strict )
        return false;

    Collector collector(optimizer);
    collector.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass remove_unused_fields({.id = PassID::RemoveUnusedFields,
                                              .guarantees = Guarantees::None,
                                              .run = run});

} // namespace
