// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <ranges>
#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/base/util.h>

using namespace hilti;
using namespace hilti::util;
using namespace hilti::operator_;

namespace {
std::string printOperator(operator_::Kind kind, const std::vector<std::string>& ops, const Meta& meta) {
    auto render = [&]() {
        switch ( kind ) {
            case operator_::Kind::Add: return fmt("add %s[%s]", ops[0], ops[1]);
            case operator_::Kind::Begin: return fmt("begin(%s)", ops[0]);
            case operator_::Kind::BitAnd: return fmt("%s & %s", ops[0], ops[1]);
            case operator_::Kind::BitOr: return fmt("%s | %s", ops[0], ops[1]);
            case operator_::Kind::BitXor: return fmt("%s ^ %s", ops[0], ops[1]);
            case operator_::Kind::Call: return fmt("%s%s", ops[0], ops[1]);
            case operator_::Kind::Cast: return fmt("cast<%s>(%s)", ops[1], ops[0]);
            case operator_::Kind::CustomAssign: return fmt("%s = %s", ops[0], ops[1]);
            case operator_::Kind::DecrPostfix: return fmt("%s--", ops[0]);
            case operator_::Kind::DecrPrefix: return fmt("--%s", ops[0]);
            case operator_::Kind::Delete: return fmt("delete %s[%s]", ops[0], ops[1]);
            case operator_::Kind::Deref: return fmt("(*%s)", ops[0]);
            case operator_::Kind::Difference: return fmt("%s - %s", ops[0], ops[1]);
            case operator_::Kind::DifferenceAssign: return fmt("%s -= %s", ops[0], ops[1]);
            case operator_::Kind::Division: return fmt("%s / %s", ops[0], ops[1]);
            case operator_::Kind::DivisionAssign: return fmt("%s /= %s", ops[0], ops[1]);
            case operator_::Kind::Equal: return fmt("%s == %s", ops[0], ops[1]);
            case operator_::Kind::End: return fmt("end(%s)", ops[0]);
            case operator_::Kind::Greater: return fmt("%s > %s", ops[0], ops[1]);
            case operator_::Kind::GreaterEqual: return fmt("%s >= %s", ops[0], ops[1]);
            case operator_::Kind::HasMember: return fmt("%s?.%s", ops[0], ops[1]);
            case operator_::Kind::In: return fmt("%s in %s", ops[0], ops[1]);
            case operator_::Kind::IncrPostfix: return fmt("%s++", ops[0]);
            case operator_::Kind::IncrPrefix: return fmt("++%s", ops[0]);
            case operator_::Kind::Index: return fmt("%s[%s]", ops[0], ops[1]);
            case operator_::Kind::IndexAssign: return fmt("%s[%s] = %s", ops[0], ops[1], ops[2]);
            case operator_::Kind::Lower: return fmt("%s < %s", ops[0], ops[1]);
            case operator_::Kind::LowerEqual: return fmt("%s <= %s", ops[0], ops[1]);
            case operator_::Kind::Member: return fmt("%s.%s", ops[0], ops[1]);
            case operator_::Kind::MemberCall: return fmt("%s.%s%s", ops[0], ops[1], ops[2]);
            case operator_::Kind::Modulo: return fmt("%s %% %s", ops[0], ops[1]);
            case operator_::Kind::Multiple: return fmt("%s * %s", ops[0], ops[1]);
            case operator_::Kind::MultipleAssign: return fmt("%s *= %s", ops[0], ops[1]);
            case operator_::Kind::Negate: return fmt("~%s", ops[0]);
            case operator_::Kind::New: return fmt("new %s%s", ops[0], ops[1]);
            case operator_::Kind::Pack: return fmt("pack%s", ops[0]);
            case operator_::Kind::Power: return fmt("%s ** %s", ops[0], ops[1]);
            case operator_::Kind::ShiftLeft: return fmt("%s << %s", ops[0], ops[1]);
            case operator_::Kind::ShiftRight: return fmt("%s >> %s", ops[0], ops[1]);
            case operator_::Kind::SignNeg: return fmt("-%s", ops[0]);
            case operator_::Kind::SignPos: return fmt("+%s", ops[0]);
            case operator_::Kind::Size: return fmt("|%s|", ops[0]);
            case operator_::Kind::Sum: return fmt("%s + %s", ops[0], ops[1]);
            case operator_::Kind::SumAssign: return fmt("%s += %s", ops[0], ops[1]);
            case operator_::Kind::TryMember: return fmt("%s.?%s", ops[0], ops[1]);
            case operator_::Kind::Unequal: return fmt("%s != %s", ops[0], ops[1]);
            case operator_::Kind::Unpack: return fmt("unpack<%s>(%s)", ops[0], ops[1]);
            case operator_::Kind::Unknown: logger().internalError("\"unknown\" operator");
            case operator_::Kind::Unset: return fmt("unset %s.%s", ops[0], ops[1]);
        }

        util::cannotBeReached();
    };

    if ( meta )
        return fmt("%s [%s]", render(), meta.location());
    else
        return render();
}

std::string printOperator(operator_::Kind kind, const Expressions& operands, bool print_signature, const Meta& meta) {
    if ( ! print_signature )
        return printOperator(kind, toVector(operands | std::views::transform([](const auto& x) { return x->print(); })),
                             meta);

    auto render_one = [](QualifiedType* t) {
        if ( t->type()->template isA<type::Member>() )
            return t->print();
        else
            return fmt("<%s>", t->print());
    };

    switch ( kind ) {
        case operator_::Kind::MemberCall: {
            assert(operands.size() == 3);
            std::string args;
            if ( auto* ttype = operands[2]->type()->type()->tryAs<type::Tuple>() )
                args = util::join(ttype->elements() | std::views::transform([&render_one](const auto& x) {
                                      return render_one(x->type());
                                  }),
                                  ", ");
            else
                args = render_one(operands[2]->type());

            return printOperator(kind, {render_one(operands[0]->type()), operands[1]->print(), util::fmt("(%s)", args)},
                                 meta);
        }

        case operator_::Kind::Call: {
            assert(operands.size() == 2);
            std::string args;
            if ( auto* ttype = operands[1]->type()->type()->tryAs<type::Tuple>() )
                args = util::join(ttype->elements() | std::views::transform([&render_one](const auto& x) {
                                      return render_one(x->type());
                                  }),
                                  ", ");
            else
                args = render_one(operands[1]->type());

            return printOperator(kind, {operands[0]->print(), util::fmt("(%s)", args)}, meta);
        }


        default:
            return printOperator(kind, toVector(operands | std::views::transform([&render_one](const auto& op) {
                                                    return render_one(op->type());
                                                })),
                                 meta);
    }
}

std::string printOperator(operator_::Kind kind, const Operands& operands, const Meta& meta) {
    auto render_one = [](Operand* t) {
        if ( t->type()->type()->template isA<type::Member>() )
            return t->print();
        else if ( auto* ft = t->type()->type()->tryAs<type::Function>(); ft && ft->functionNameForPrinting() )
            return ft->functionNameForPrinting().str();
        else
            return fmt("<%s>", t->print());
    };

    switch ( kind ) {
        case operator_::Kind::MemberCall: {
            assert(operands.size() == 3);
            std::string args;
            if ( auto* ttype = operands[2]->type()->type()->tryAs<type::OperandList>() )
                args = util::join(ttype->operands() | std::views::transform([](const auto& x) { return x->print(); }),
                                  ", ");
            else
                args = render_one(operands[2]);

            return printOperator(kind, {render_one(operands[0]), render_one(operands[1]), util::fmt("(%s)", args)},
                                 meta);
        }

        case operator_::Kind::Call: {
            assert(operands.size() == 2);
            std::string args;
            if ( auto* ttype = operands[1]->type()->type()->tryAs<type::OperandList>() )
                args = util::join(ttype->operands() | std::views::transform([](const auto& x) { return x->print(); }),
                                  ", ");
            else
                args = render_one(operands[1]);

            return printOperator(kind, {render_one(operands[0]), util::fmt("(%s)", args)}, meta);
        }


        default: return printOperator(kind, toVector(operands | std::views::transform(render_one)), meta);
    }
}

} // namespace

std::string operator_::detail::print(Kind kind, const Expressions& operands) {
    return printOperator(kind, operands, false, {});
}

std::string operator_::detail::printSignature(Kind kind, const Expressions& operands, const Meta& meta) {
    return printOperator(kind, operands, true, meta);
}

class OperandResolver : public visitor::PreOrder {
public:
    OperandResolver(Builder* builder) : builder(builder) {}

    Builder* builder;
    bool result = true;

    void operator()(type::Name* t) final {
        if ( t->resolvedTypeIndex() )
            return;

        if ( auto resolved =
                 scope::lookupID<declaration::Type>(t->id(), builder->context()->root(), "built-in type") ) {
            auto index = builder->context()->register_(resolved->first->type()->type());
            t->setResolvedTypeIndex(index);
        }
        else
            result = false;
    }

    void operator()(expression::Name* e) final {
        if ( e->resolvedDeclarationIndex() )
            return;

        if ( auto resolved =
                 scope::lookupID<declaration::Constant>(e->id(), builder->context()->root(), "built-in constant") ) {
            auto index = builder->context()->register_(resolved->first);
            e->setResolvedDeclarationIndex(builder->context(), index);
        }
        else
            result = false;
    }
};

bool Operator::init(Builder* builder, Node* scope_root) {
    auto sig = signature(builder);
    assert(sig.skip_doc || ! sig.ns.empty());

    _signature = operator_::detail::ProcessedSignature();
    _signature->kind = sig.kind;
    _signature->priority = sig.priority;
    _signature->doc = sig.doc;
    _signature->result_doc = sig.result_doc;
    _signature->namespace_ = sig.ns;
    _signature->skip_doc = sig.skip_doc;

    type::operand_list::Operands ops;

    if ( sig.kind == Kind::MemberCall || (sig.kind == Kind::Call && ! sig.op0) ) {
        if ( sig.kind == Kind::MemberCall ) {
            // Needs self set to type, member to method name.
            assert(sig.self);
            assert(sig.member || sig.op1);
        }

        if ( sig.kind == Kind::Call )
            // Needs either self set to type, or member to function name.
            assert(sig.self || sig.member);

        if ( sig.self )
            ops.emplace_back(operandForType(builder, sig.self.kind, sig.self.getType(), sig.self.doc));

        if ( sig.member ) {
            assert(! sig.op0);
            ops.emplace_back(operandForType(builder, parameter::Kind::In, builder->typeMember(ID(*sig.member)), ""));
        }

        if ( sig.op1 ) {
            assert(! sig.member);
            ops.emplace_back(operandForType(builder, sig.op1.kind, sig.op1.getType(), sig.op1.doc));
        }

        if ( sig.op2 )
            ops.emplace_back(operandForType(builder, sig.op2.kind, sig.op2.getType(), sig.op2.doc));
        else {
            type::operand_list::Operands params;
            for ( const auto& p : {sig.param0, sig.param1, sig.param2, sig.param3, sig.param4} ) {
                if ( p ) {
                    if ( p.default_ )
                        params.emplace_back(builder->typeOperandListOperand(ID(p.name), p.type.kind, p.type.getType(),
                                                                            p.default_, p.type.doc,
                                                                            p.type.getType()->meta()));
                    else
                        params.emplace_back(builder->typeOperandListOperand(ID(p.name), p.type.kind, p.type.getType(),
                                                                            p.optional, p.type.doc,
                                                                            p.type.getType()->meta()));
                }
                else
                    break;
            }

            ops.emplace_back(
                operandForType(builder, parameter::Kind::In, builder->typeOperandList(std::move(params)), ""));
        }
    }
    else {
        if ( sig.op0 ) {
            for ( const auto& op : {sig.op0, sig.op1, sig.op2} ) {
                if ( op )
                    ops.emplace_back(operandForType(builder, op.kind, op.getType(), op.doc));
                else
                    break;
            }
        }
        else if ( sig.op0.doc.empty() )
            logger().internalError(fmt("operator with dynamic parameters must give op doc: %s", print()));
    }

    _signature->operands = builder->typeOperandList(std::move(ops));

    if ( sig.result.type )
        _signature->result = builder->qualifiedType(sig.result.type, sig.result.constness);
    else if ( sig.result_doc.empty() )
        logger().internalError(fmt("operator with dynamic result must give result doc: %s", print()));

    auto v = OperandResolver(builder);

    for ( const auto& op : _signature->operands->operands() ) {
        if ( ! visitor::visit(v, op, {}, [](auto& v) { return v.result; }) )
            return false;

        op->type()->type()->unify(builder->context(), scope_root);
    }

    if ( _signature->result ) {
        if ( ! visitor::visit(v, _signature->result.get(), {}, [](auto& v) { return v.result; }) )
            return false;

        if ( ! _signature->result->type(false)->unify(builder->context(), scope_root) )
            return false;
    }

    return true;
}

QualifiedType* Operator::result(Builder* builder, const Expressions& operands, const Meta& meta) const {
    assert(_signature);
    if ( _signature->result )
        return _signature->result;
    else
        logger().internalError("operator::Operator::result() not overridden for dynamic operator result");
}


std::string Operator::print() const {
    if ( ! hasOperands() )
        return "<dynamic>";

    return printOperator(kind(), operands(), meta());
}

std::string Operator::dump() const {
    std::string x;
    for ( const auto& op : operands() )
        x += op->dump();

    return x;
}

Operand* Operator::operandForType(Builder* builder, parameter::Kind kind, UnqualifiedType* t, std::string doc) {
    if ( t->isNameType() && ! t->isWildcard() )
        // create external type for potentially complex types involving many nodes
        return type::operand_list::Operand::createExternal(builder->context(), kind, t, false, std::move(doc),
                                                           t->meta());
    else
        return type::operand_list::Operand::create(builder->context(), kind, t, false, std::move(doc), t->meta());
}

std::string BuiltInMemberCall::print() const { return printOperator(kind(), operands(), meta()); }
