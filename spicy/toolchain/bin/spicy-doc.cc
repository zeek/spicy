// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/json.h>

#include <hilti/ast/detail/operator-registry.h>
#include <hilti/compiler/init.h>
#include <hilti/hilti.h>

#include <spicy/compiler/init.h>
#include <spicy/spicy.h>

using nlohmann::json;

template<typename T>
static std::string to_string(const T& t) {
    return std::string(hilti::Node(t));
}

static std::string formatType(const hilti::Type& t) {
    if ( auto d = t.tryAs<hilti::type::DocOnly>() )
        return d->description();

    return to_string(t);
}

#define KIND_TO_STRING(k)                                                                                              \
    case k: return hilti::util::split(#k, "::").back();

static std::string kindToString(hilti::operator_::Kind kind) {
    switch ( kind ) {
        KIND_TO_STRING(hilti::operator_::Kind::Add);
        KIND_TO_STRING(hilti::operator_::Kind::Begin);
        KIND_TO_STRING(hilti::operator_::Kind::BitAnd);
        KIND_TO_STRING(hilti::operator_::Kind::BitOr);
        KIND_TO_STRING(hilti::operator_::Kind::BitXor);
        KIND_TO_STRING(hilti::operator_::Kind::Call);
        KIND_TO_STRING(hilti::operator_::Kind::Cast);
        KIND_TO_STRING(hilti::operator_::Kind::CustomAssign);
        KIND_TO_STRING(hilti::operator_::Kind::DecrPostfix);
        KIND_TO_STRING(hilti::operator_::Kind::DecrPrefix);
        KIND_TO_STRING(hilti::operator_::Kind::Delete);
        KIND_TO_STRING(hilti::operator_::Kind::Deref);
        KIND_TO_STRING(hilti::operator_::Kind::Difference);
        KIND_TO_STRING(hilti::operator_::Kind::DifferenceAssign);
        KIND_TO_STRING(hilti::operator_::Kind::Division);
        KIND_TO_STRING(hilti::operator_::Kind::DivisionAssign);
        KIND_TO_STRING(hilti::operator_::Kind::Equal);
        KIND_TO_STRING(hilti::operator_::Kind::End);
        KIND_TO_STRING(hilti::operator_::Kind::Greater);
        KIND_TO_STRING(hilti::operator_::Kind::GreaterEqual);
        KIND_TO_STRING(hilti::operator_::Kind::HasMember);
        KIND_TO_STRING(hilti::operator_::Kind::In);
        KIND_TO_STRING(hilti::operator_::Kind::IncrPostfix);
        KIND_TO_STRING(hilti::operator_::Kind::IncrPrefix);
        KIND_TO_STRING(hilti::operator_::Kind::Index);
        KIND_TO_STRING(hilti::operator_::Kind::IndexAssign);
        KIND_TO_STRING(hilti::operator_::Kind::Lower);
        KIND_TO_STRING(hilti::operator_::Kind::LowerEqual);
        KIND_TO_STRING(hilti::operator_::Kind::Member);
        KIND_TO_STRING(hilti::operator_::Kind::MemberCall);
        KIND_TO_STRING(hilti::operator_::Kind::Modulo);
        KIND_TO_STRING(hilti::operator_::Kind::Multiple);
        KIND_TO_STRING(hilti::operator_::Kind::MultipleAssign);
        KIND_TO_STRING(hilti::operator_::Kind::Negate);
        KIND_TO_STRING(hilti::operator_::Kind::New);
        KIND_TO_STRING(hilti::operator_::Kind::Pack);
        KIND_TO_STRING(hilti::operator_::Kind::Power);
        KIND_TO_STRING(hilti::operator_::Kind::ShiftLeft);
        KIND_TO_STRING(hilti::operator_::Kind::ShiftRight);
        KIND_TO_STRING(hilti::operator_::Kind::SignNeg);
        KIND_TO_STRING(hilti::operator_::Kind::SignPos);
        KIND_TO_STRING(hilti::operator_::Kind::Size);
        KIND_TO_STRING(hilti::operator_::Kind::Sum);
        KIND_TO_STRING(hilti::operator_::Kind::SumAssign);
        KIND_TO_STRING(hilti::operator_::Kind::TryMember);
        KIND_TO_STRING(hilti::operator_::Kind::Unequal);
        KIND_TO_STRING(hilti::operator_::Kind::Unpack);
        KIND_TO_STRING(hilti::operator_::Kind::Unknown);
        KIND_TO_STRING(hilti::operator_::Kind::Unset);

        default: hilti::util::cannot_be_reached();
    }
}

static json operandToJSON(const hilti::operator_::Operand& o) {
    json op;

    hilti::Type t;

    if ( auto f = std::get_if<std::function<std::optional<hilti::Type>(const hilti::node::Range<hilti::Expression>&,
                                                                       const hilti::node::Range<hilti::Expression>&)>>(
             &o.type) )
        t = *(*f)(hilti::node::Range<hilti::Expression>{}, hilti::node::Range<hilti::Expression>{});
    else
        t = std::get<hilti::Type>(o.type);

    op["type"] = formatType(hilti::type::nonConstant(t));
    op["const"] = hilti::type::isConstant(t);
    op["mutable"] = hilti::type::isMutable(t);

    if ( o.id )
        op["id"] = std::string(*o.id);
    else
        op["id"] = nullptr;

    op["optional"] = o.optional;

    if ( o.default_ )
        op["default"] = to_string(*o.default_);
    else
        op["default"] = nullptr;

    if ( o.doc )
        op["doc"] = *o.doc;
    else
        op["doc"] = nullptr;

    return op;
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main(int argc, char** argv) {
    hilti::init();
    spicy::init();

    json all_operators;

    // Helper function adding one operator to all_operators.
    auto add_operator = [&](const std::string& namespace_, const hilti::Operator& op) {
        json jop;
        jop["kind"] = kindToString(op.kind());
        jop["doc"] = op.doc();
        jop["namespace"] = namespace_;
        jop["rtype"] = formatType(op.result(hilti::node::Range<hilti::Expression>()));
        jop["commutative"] = hilti::operator_::isCommutative(op.kind());
        jop["operands"] = json();

        if ( op.kind() == hilti::operator_::Kind::Call ) {
            auto operands = op.operands();
            auto callee = operands[0];
            auto params = std::get<hilti::Type>(operands[1].type).as<hilti::type::OperandList>();

            jop["operands"].push_back(operandToJSON(callee));

            for ( const auto& p : params.operands() )
                jop["operands"].push_back(operandToJSON(p));
        }
        else if ( op.kind() == hilti::operator_::Kind::MemberCall ) {
            auto operands = op.operands();
            auto self = operands[0];
            auto method = std::get<hilti::Type>(operands[1].type).as<hilti::type::Member>();

            if ( ! std::get<hilti::Type>(operands[2].type).isA<hilti::type::OperandList>() )
                return;

            auto params = std::get<hilti::Type>(operands[2].type).as<hilti::type::OperandList>();

            jop["self"] = operandToJSON(self);
            jop["id"] = method.id();
            jop["args"] = std::list<json>();

            for ( const auto& p : params.operands() )
                jop["args"].push_back(operandToJSON(p));
        }
        else {
            jop["operands"] = json();

            for ( const auto& x : op.operands() )
                jop["operands"].push_back(operandToJSON(x));
        }

        all_operators.push_back(std::move(jop));
    };

    // Iterate through all available operators.
    auto operators = hilti::operator_::registry().all();
    for ( const auto& [kind, operators] : operators )
        for ( const auto& op : operators )
            add_operator(op.docNamespace(), op);

    // Hardcode concrete instances of generic operators. They need to be
    // associated with the corresponding types, but there's no generic way to
    // do that.
    for ( const auto& type_ : std::vector({"bytes", "list", "map", "set", "stream", "vector"}) ) {
        add_operator(type_, hilti::operator_::generic::Begin::Operator());
        add_operator(type_, hilti::operator_::generic::End::Operator());
    }

    std::cout << all_operators.dump(4) << std::endl;
    return 0;
}
