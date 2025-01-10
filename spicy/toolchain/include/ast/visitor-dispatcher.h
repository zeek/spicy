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
    virtual void operator()(spicy::operator_::sink::Size* n) {}
    virtual void operator()(spicy::operator_::sink::Close* n) {}
    virtual void operator()(spicy::operator_::sink::Connect* n) {}
    virtual void operator()(spicy::operator_::sink::ConnectMIMETypeString* n) {}
    virtual void operator()(spicy::operator_::sink::ConnectMIMETypeBytes* n) {}
    virtual void operator()(spicy::operator_::sink::ConnectFilter* n) {}
    virtual void operator()(spicy::operator_::sink::Gap* n) {}
    virtual void operator()(spicy::operator_::sink::SequenceNumber* n) {}
    virtual void operator()(spicy::operator_::sink::SetAutoTrim* n) {}
    virtual void operator()(spicy::operator_::sink::SetInitialSequenceNumber* n) {}
    virtual void operator()(spicy::operator_::sink::SetPolicy* n) {}
    virtual void operator()(spicy::operator_::sink::Skip* n) {}
    virtual void operator()(spicy::operator_::sink::Trim* n) {}
    virtual void operator()(spicy::operator_::sink::Write* n) {}
    virtual void operator()(spicy::operator_::unit::Unset* n) {}
    virtual void operator()(spicy::operator_::unit::MemberNonConst* n) {}
    virtual void operator()(spicy::operator_::unit::MemberConst* n) {}
    virtual void operator()(spicy::operator_::unit::TryMember* n) {}
    virtual void operator()(spicy::operator_::unit::HasMember* n) {}
    virtual void operator()(spicy::operator_::unit::Offset* n) {}
    virtual void operator()(spicy::operator_::unit::Position* n) {}
    virtual void operator()(spicy::operator_::unit::Input* n) {}
    virtual void operator()(spicy::operator_::unit::SetInput* n) {}
    virtual void operator()(spicy::operator_::unit::Find* n) {}
    virtual void operator()(spicy::operator_::unit::ConnectFilter* n) {}
    virtual void operator()(spicy::operator_::unit::Forward* n) {}
    virtual void operator()(spicy::operator_::unit::ForwardEod* n) {}
    virtual void operator()(spicy::operator_::unit::Backtrack* n) {}
    virtual void operator()(spicy::operator_::unit::ContextConst* n) {}
    virtual void operator()(spicy::operator_::unit::ContextNonConst* n) {}
    virtual void operator()(spicy::operator_::unit::Stream* n) {}
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
