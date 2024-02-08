// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/json.h>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/operator-registry.h>
#include <hilti/compiler/init.h>
#include <hilti/hilti.h>

#include <spicy/compiler/init.h>
#include <spicy/spicy.h>

using nlohmann::json;

static std::string formatType(const hilti::UnqualifiedTypePtr& t) {
    if ( auto d = t->tryAs<hilti::type::DocOnly>() )
        return d->description();

    return t->print();
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

        default: hilti::util::cannotBeReached();
    }
}

static json operandToJSON(const hilti::operator_::Operand& o, const std::string& default_name) {
    json op;

    auto t = o.type()->type();

    op["type"] = formatType(t);
    op["kind"] = to_string(o.kind());

    if ( o.id() )
        op["id"] = std::string(o.id());
    else
        op["id"] = default_name;

    op["optional"] = o.isOptional();

    if ( o.default_() )
        op["default"] = o.default_()->print();
    else
        op["default"] = nullptr;

    if ( ! o.doc().empty() )
        op["doc"] = o.doc();
    else
        op["doc"] = nullptr;

    return op;
}

class SpicyDoc : public spicy::Driver {
public:
    SpicyDoc() : spicy::Driver("spicy-doc", hilti::util::currentExecutable()) {
        spicy::Configuration::extendHiltiConfiguration();
    }
};

// NOLINTNEXTLINE(bugprone-exception-escape)
int main(int argc, char** argv) {
    hilti::init();
    spicy::init();

    // Initialize and run a driver so that our operators gets registered and resolved.
    SpicyDoc driver;
    if ( auto rc = driver.run(); ! rc ) {
        std::cerr << "driver error: " << rc.error() << '\n';
        exit(1);
    }

    hilti::Builder builder(driver.context()->astContext().get());
    json all_operators;

    // Helper function adding one operator to all_operators.
    auto add_operator = [&](const std::string& namespace_, const hilti::Operator& op) {
        if ( op.signature().skip_doc )
            return;

        json jop;
        jop["kind"] = kindToString(op.kind());
        jop["doc"] = op.doc();
        jop["namespace"] = namespace_;
        jop["commutative"] = hilti::operator_::isCommutative(op.kind());
        jop["operands"] = json::array();

        if ( auto rtype = op.signature().result_doc; ! rtype.empty() )
            jop["rtype"] = rtype;
        else
            jop["rtype"] = formatType(op.result(&builder, {}, hilti::Meta())->type());

        if ( op.kind() == hilti::operator_::Kind::Call ) {
            auto operands = op.operands();
            auto callee = operands[0];
            auto args = operands[1]->type()->type()->tryAs<hilti::type::OperandList>()->operands();

            jop["operands"].push_back(operandToJSON(*callee, {}));

            for ( const auto& p : args )
                jop["operands"].push_back(operandToJSON(*p, {}));
        }
        else if ( op.kind() == hilti::operator_::Kind::MemberCall ) {
            auto operands = op.operands();
            auto self = operands[0];
            auto args = operands[2]->type()->type()->tryAs<hilti::type::OperandList>()->operands();

            jop["self"] = operandToJSON(*self, "self");
            jop["id"] = operands[1]->print();

            jop["args"] = std::list<json>();

            auto i = 0;
            for ( const auto& p : args )
                jop["args"].push_back(operandToJSON(*p, hilti::util::fmt("arg%d", i++)));
        }
        else {
            auto i = 0;
            for ( const auto& x : op.operands() )
                jop["operands"].push_back(operandToJSON(*x, hilti::util::fmt("op%d", i++)));
        }

        all_operators.push_back(std::move(jop));
    };

    if ( argc > 1 ) {
        for ( auto i = 1; i < argc; i++ ) {
            auto op = hilti::operator_::registry().byName(argv[i]);
            if ( op )
                add_operator(op->signature().namespace_, *op);
            else
                std::cerr << "no operator '" << argv[i] << "'" << '\n';
        }
    }

    else {
        // Iterate through all available operators.
        const auto& operators = hilti::operator_::registry().operators();
        for ( const auto& op : operators )
            add_operator(op->signature().namespace_, *op);

        // Hardcode concrete instances of generic operators. They need to be
        // associated with the corresponding types, but there's no generic way to
        // do that.
        for ( const auto& type_ : std::vector({"bytes", "list", "map", "set", "stream", "vector"}) ) {
            add_operator(type_, *hilti::operator_::registry().byName("generic::Begin"));
            add_operator(type_, *hilti::operator_::registry().byName("generic::End"));
        }
    }

    std::cout << all_operators.dump(4) << '\n';
    return 0;
}
