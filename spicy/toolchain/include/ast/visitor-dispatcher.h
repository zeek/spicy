// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/node.h>

#include <spicy/ast/forward.h>

namespace spicy::visitor {

class Dispatcher : public hilti::visitor::Dispatcher {
public:
    /** Tag for the Spicy dispatcher. */
    static constexpr unsigned int Spicy = 100;

    Dispatcher() : hilti::visitor::Dispatcher(Spicy) {}

    using hilti::visitor::Dispatcher::operator();

    virtual void operator()(spicy::operator_::unit::MemberCall*) {}
    virtual void operator()(spicy::operator_::sink::Size*) {}
    virtual void operator()(spicy::operator_::sink::Close*) {}
    virtual void operator()(spicy::operator_::sink::Connect*) {}
    virtual void operator()(spicy::operator_::sink::ConnectMIMETypeString*) {}
    virtual void operator()(spicy::operator_::sink::ConnectMIMETypeBytes*) {}
    virtual void operator()(spicy::operator_::sink::ConnectFilter*) {}
    virtual void operator()(spicy::operator_::sink::Gap*) {}
    virtual void operator()(spicy::operator_::sink::SequenceNumber*) {}
    virtual void operator()(spicy::operator_::sink::SetAutoTrim*) {}
    virtual void operator()(spicy::operator_::sink::SetInitialSequenceNumber*) {}
    virtual void operator()(spicy::operator_::sink::SetPolicy*) {}
    virtual void operator()(spicy::operator_::sink::Skip*) {}
    virtual void operator()(spicy::operator_::sink::Trim*) {}
    virtual void operator()(spicy::operator_::sink::Write*) {}
    virtual void operator()(spicy::operator_::unit::Unset*) {}
    virtual void operator()(spicy::operator_::unit::MemberNonConst*) {}
    virtual void operator()(spicy::operator_::unit::MemberConst*) {}
    virtual void operator()(spicy::operator_::unit::TryMember*) {}
    virtual void operator()(spicy::operator_::unit::HasMember*) {}
    virtual void operator()(spicy::operator_::unit::Offset*) {}
    virtual void operator()(spicy::operator_::unit::Position*) {}
    virtual void operator()(spicy::operator_::unit::Input*) {}
    virtual void operator()(spicy::operator_::unit::SetInput*) {}
    virtual void operator()(spicy::operator_::unit::Find*) {}
    virtual void operator()(spicy::operator_::unit::ConnectFilter*) {}
    virtual void operator()(spicy::operator_::unit::Forward*) {}
    virtual void operator()(spicy::operator_::unit::ForwardEod*) {}
    virtual void operator()(spicy::operator_::unit::Backtrack*) {}
    virtual void operator()(spicy::operator_::unit::ContextConst*) {}
    virtual void operator()(spicy::operator_::unit::ContextNonConst*) {}
    virtual void operator()(spicy::operator_::unit::Stream*) {}
    virtual void operator()(spicy::declaration::Hook*) {}
    virtual void operator()(spicy::ctor::Unit*) {}
    virtual void operator()(spicy::declaration::UnitHook*) {}
    virtual void operator()(spicy::statement::Confirm*) {}
    virtual void operator()(spicy::statement::Print*) {}
    virtual void operator()(spicy::statement::Reject*) {}
    virtual void operator()(spicy::statement::Stop*) {}
    virtual void operator()(spicy::type::Sink*) {}
    virtual void operator()(spicy::type::Unit*) {}
    virtual void operator()(spicy::type::unit::Item*) {}
    virtual void operator()(spicy::type::unit::item::Block*) {}
    virtual void operator()(spicy::type::unit::item::Field*) {}
    virtual void operator()(spicy::type::unit::item::Property*) {}
    virtual void operator()(spicy::type::unit::item::Sink*) {}
    virtual void operator()(spicy::type::unit::item::Switch*) {}
    virtual void operator()(spicy::type::unit::item::UnitHook*) {}
    virtual void operator()(spicy::type::unit::item::UnresolvedField*) {}
    virtual void operator()(spicy::type::unit::item::Variable*) {}
    virtual void operator()(spicy::type::unit::item::switch_::Case*) {}
};

} // namespace spicy::visitor
