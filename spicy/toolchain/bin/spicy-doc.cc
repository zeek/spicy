// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/json.h>

#include <hilti/ast/detail/operator-registry.h>
#include <hilti/hilti.h>

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
        KIND_TO_STRING(hilti::operator_::Kind::Lower);
        KIND_TO_STRING(hilti::operator_::Kind::LowerEqual);
        KIND_TO_STRING(hilti::operator_::Kind::Member);
        KIND_TO_STRING(hilti::operator_::Kind::MemberCall);
        KIND_TO_STRING(hilti::operator_::Kind::Modulo);
        KIND_TO_STRING(hilti::operator_::Kind::Multiple);
        KIND_TO_STRING(hilti::operator_::Kind::MultipleAssign);
        KIND_TO_STRING(hilti::operator_::Kind::Negate);
        KIND_TO_STRING(hilti::operator_::Kind::New);
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

    if ( auto f =
             std::get_if<std::function<std::optional<hilti::Type>(const std::vector<hilti::Expression>&,
                                                                  const std::vector<hilti::Expression>&)>>(&o.type) )
        t = *(*f)({}, {});
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

int main(int argc, char** argv) {
    json all_operators;

    auto operators = hilti::operator_::registry().all();

    for ( const auto& [kind, operators] : operators ) {
        for ( const auto& o : operators ) {
            json operator_;
            operator_["kind"] = kindToString(o.kind());
            operator_["doc"] = o.doc();
            operator_["namespace"] = o.docNamespace();
            operator_["rtype"] = formatType(o.result({}));
            operator_["commutative"] = hilti::operator_::isCommutative(o.kind());

            if ( o.kind() == hilti::operator_::Kind::Call ) {
                auto operands = o.operands();
                auto callee = operands[0];
                auto params = std::get<hilti::Type>(operands[1].type).as<hilti::type::OperandList>();

                operator_["operands"].push_back(operandToJSON(callee));

                for ( const auto& p : params.operands() )
                    operator_["operands"].push_back(operandToJSON(p));
            }
            else if ( o.kind() == hilti::operator_::Kind::MemberCall ) {
                auto operands = o.operands();
                auto self = operands[0];
                auto method = std::get<hilti::Type>(operands[1].type).as<hilti::type::Member>();

                if ( ! std::get<hilti::Type>(operands[2].type).isA<hilti::type::OperandList>() )
                    continue; // XXX

                auto params = std::get<hilti::Type>(operands[2].type).as<hilti::type::OperandList>();

                operator_["self"] = operandToJSON(self);
                operator_["id"] = method.id();
                operator_["args"] = std::list<json>();

                for ( const auto& p : params.operands() )
                    operator_["args"].push_back(operandToJSON(p));
            }
            else {
                operator_["operands"] = json();

                for ( const auto& x : o.operands() )
                    operator_["operands"].push_back(operandToJSON(x));
            }

            all_operators.push_back(std::move(operator_));
        }
    }

    std::cout << all_operators.dump(4) << std::endl;
    return 0;
}
