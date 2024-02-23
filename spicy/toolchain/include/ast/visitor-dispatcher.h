// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/visitor-dispatcher.h>

#include <spicy/ast/forward.h>

#define SPICY_NODE_IMPLEMENTATION_0(NS, CLASS)                                                                         \
    void ::NS::CLASS::dispatch(::hilti::visitor::Dispatcher& v) {                                                      \
        if ( auto sv = dynamic_cast<spicy::visitor::Dispatcher*>(&v) ) {                                               \
            (*sv)(static_cast<::hilti::Node*>(this));                                                                  \
            (*sv)(this);                                                                                               \
        }                                                                                                              \
        else {                                                                                                         \
            v(static_cast<::hilti::Node*>(this));                                                                      \
            v(this);                                                                                                   \
        }                                                                                                              \
    }

#define SPICY_NODE_IMPLEMENTATION_1(NS, CLASS, BASE)                                                                   \
    void ::NS::CLASS::dispatch(::hilti::visitor::Dispatcher& v) {                                                      \
        if ( auto sv = dynamic_cast<spicy::visitor::Dispatcher*>(&v) ) {                                               \
            (*sv)(static_cast<::hilti::Node*>(this));                                                                  \
            (*sv)(static_cast<BASE*>(this));                                                                           \
            (*sv)(this);                                                                                               \
        }                                                                                                              \
        else {                                                                                                         \
            v(static_cast<::hilti::Node*>(this));                                                                      \
            v(static_cast<BASE*>(this));                                                                               \
            v(this);                                                                                                   \
        }                                                                                                              \
    }

#define SPICY_NODE_IMPLEMENTATION_2(NS, CLASS, BASE1, BASE2)                                                           \
    void ::NS::CLASS::dispatch(::hilti::visitor::Dispatcher& v) {                                                      \
        if ( auto sv = dynamic_cast<spicy::visitor::Dispatcher*>(&v) ) {                                               \
            (*sv)(static_cast<::hilti::Node*>(this));                                                                  \
            (*sv)(static_cast<BASE1*>(this));                                                                          \
            (*sv)(static_cast<BASE2*>(this));                                                                          \
            (*sv)(this);                                                                                               \
        }                                                                                                              \
        else {                                                                                                         \
            v(static_cast<::hilti::Node*>(this));                                                                      \
            v(static_cast<BASE1*>(this));                                                                              \
            v(static_cast<BASE2*>(this));                                                                              \
        }                                                                                                              \
    }

namespace spicy::visitor {

class Dispatcher : public hilti::visitor::Dispatcher {
public:
    using hilti::visitor::Dispatcher::operator();

    virtual void operator()(spicy::operator_::unit::MemberCall*) {}
    virtual void operator()(spicy::operator_::sink::SizeValue* n) {}
    virtual void operator()(spicy::operator_::sink::SizeReference* n) {}
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
