// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>

namespace hilti::visitor {

class Dispatcher {
public:
    /** Numerical tag identifying a type of dispatcher. */
    using Tag = unsigned int;

    /** Tag for the HILTI dispatcher. */
    static constexpr unsigned int HILTI = 1;

    /**
     * Constructor.
     *
     * @param tag tag identifying the type of dispatcher; derived classes can
     * pick a value of their choice
     */
    Dispatcher(Tag tag = HILTI) : _tag(tag) {}

    /**
     * Returns a tag identifying the dispatcher. By default, this returns
     * `dispatcher::HILTI`. A derived class can have it return a different tag
     * of its choice by passing the desired value into the constructor.
     */
    unsigned int dispatcherTag() const { return _tag; }

    virtual void operator()(hilti::ASTRoot*) {}
    virtual void operator()(hilti::Attribute*) {}
    virtual void operator()(hilti::AttributeSet*) {}
    virtual void operator()(hilti::Ctor*) {}
    virtual void operator()(hilti::Declaration*) {}
    virtual void operator()(hilti::Expression*) {}
    virtual void operator()(hilti::Function*) {}
    virtual void operator()(hilti::QualifiedType*) {}
    virtual void operator()(hilti::Statement*) {}
    virtual void operator()(hilti::UnqualifiedType*) {}
    virtual void operator()(hilti::ctor::Address*) {}
    virtual void operator()(hilti::ctor::bitfield::BitRange*) {}
    virtual void operator()(hilti::ctor::Bitfield*) {}
    virtual void operator()(hilti::ctor::Bool*) {}
    virtual void operator()(hilti::ctor::Bytes*) {}
    virtual void operator()(hilti::ctor::Coerced*) {}
    virtual void operator()(hilti::ctor::Default*) {}
    virtual void operator()(hilti::ctor::Enum*) {}
    virtual void operator()(hilti::ctor::Error*) {}
    virtual void operator()(hilti::ctor::Exception*) {}
    virtual void operator()(hilti::ctor::Interval*) {}
    virtual void operator()(hilti::ctor::Library*) {}
    virtual void operator()(hilti::ctor::List*) {}
    virtual void operator()(hilti::ctor::Map*) {}
    virtual void operator()(hilti::ctor::Network*) {}
    virtual void operator()(hilti::Node*) {}
    virtual void operator()(hilti::ctor::Null*) {}
    virtual void operator()(hilti::ctor::Optional*) {}
    virtual void operator()(hilti::ctor::Port*) {}
    virtual void operator()(hilti::ctor::Real*) {}
    virtual void operator()(hilti::ctor::RegExp*) {}
    virtual void operator()(hilti::ctor::Result*) {}
    virtual void operator()(hilti::ctor::Set*) {}
    virtual void operator()(hilti::ctor::SignedInteger*) {}
    virtual void operator()(hilti::ctor::Stream*) {}
    virtual void operator()(hilti::ctor::String*) {}
    virtual void operator()(hilti::ctor::StrongReference*) {}
    virtual void operator()(hilti::ctor::Struct*) {}
    virtual void operator()(hilti::ctor::Time*) {}
    virtual void operator()(hilti::ctor::Tuple*) {}
    virtual void operator()(hilti::ctor::Union*) {}
    virtual void operator()(hilti::ctor::UnsignedInteger*) {}
    virtual void operator()(hilti::ctor::ValueReference*) {}
    virtual void operator()(hilti::ctor::Vector*) {}
    virtual void operator()(hilti::ctor::WeakReference*) {}
    virtual void operator()(hilti::ctor::map::Element*) {}
    virtual void operator()(hilti::ctor::struct_::Field*) {}
    virtual void operator()(hilti::declaration::Constant*) {}
    virtual void operator()(hilti::declaration::Export*) {}
    virtual void operator()(hilti::declaration::Expression*) {}
    virtual void operator()(hilti::declaration::Field*) {}
    virtual void operator()(hilti::declaration::Function*) {}
    virtual void operator()(hilti::declaration::GlobalVariable*) {}
    virtual void operator()(hilti::declaration::ImportedModule*) {}
    virtual void operator()(hilti::declaration::LocalVariable*) {}
    virtual void operator()(hilti::declaration::Module*) {}
    virtual void operator()(hilti::declaration::Property*) {}
    virtual void operator()(hilti::declaration::Type*) {}
    virtual void operator()(hilti::expression::Assign*) {}
    virtual void operator()(hilti::expression::Coerced*) {}
    virtual void operator()(hilti::expression::Ctor*) {}
    virtual void operator()(hilti::expression::Grouping*) {}
    virtual void operator()(hilti::expression::Keyword*) {}
    virtual void operator()(hilti::expression::ListComprehension*) {}
    virtual void operator()(hilti::expression::LogicalAnd*) {}
    virtual void operator()(hilti::expression::LogicalNot*) {}
    virtual void operator()(hilti::expression::LogicalOr*) {}
    virtual void operator()(hilti::expression::Member*) {}
    virtual void operator()(hilti::expression::Move*) {}
    virtual void operator()(hilti::expression::Name*) {}
    virtual void operator()(hilti::expression::ConditionTest*) {}
    virtual void operator()(hilti::expression::PendingCoerced*) {}
    virtual void operator()(hilti::expression::ResolvedOperator*) {}
    virtual void operator()(hilti::expression::Ternary*) {}
    virtual void operator()(hilti::expression::TypeInfo*) {}
    virtual void operator()(hilti::expression::TypeWrapped*) {}
    virtual void operator()(hilti::expression::Type_*) {}
    virtual void operator()(hilti::expression::UnresolvedOperator*) {}
    virtual void operator()(hilti::expression::Void*) {}
    virtual void operator()(hilti::operator_::function::Call*) {}
    virtual void operator()(hilti::operator_::struct_::MemberCall*) {}
    virtual void operator()(hilti::operator_::generic::CastedCoercion*) {}
    virtual void operator()(hilti::operator_::address::Equal* n) {}
    virtual void operator()(hilti::operator_::address::Unequal* n) {}
    virtual void operator()(hilti::operator_::address::Family* n) {}
    virtual void operator()(hilti::operator_::bitfield::Member* n) {}
    virtual void operator()(hilti::operator_::bitfield::HasMember* n) {}
    virtual void operator()(hilti::operator_::bool_::Equal* n) {}
    virtual void operator()(hilti::operator_::bool_::Unequal* n) {}
    virtual void operator()(hilti::operator_::bool_::BitAnd* n) {}
    virtual void operator()(hilti::operator_::bool_::BitOr* n) {}
    virtual void operator()(hilti::operator_::bool_::BitXor* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::Deref* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::IncrPostfix* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::IncrPrefix* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::Equal* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::Unequal* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::Lower* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::LowerEqual* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::Greater* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::GreaterEqual* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::Difference* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::Sum* n) {}
    virtual void operator()(hilti::operator_::bytes::iterator::SumAssign* n) {}
    virtual void operator()(hilti::operator_::bytes::Size* n) {}
    virtual void operator()(hilti::operator_::bytes::Equal* n) {}
    virtual void operator()(hilti::operator_::bytes::Unequal* n) {}
    virtual void operator()(hilti::operator_::bytes::Greater* n) {}
    virtual void operator()(hilti::operator_::bytes::GreaterEqual* n) {}
    virtual void operator()(hilti::operator_::bytes::In* n) {}
    virtual void operator()(hilti::operator_::bytes::Lower* n) {}
    virtual void operator()(hilti::operator_::bytes::LowerEqual* n) {}
    virtual void operator()(hilti::operator_::bytes::Sum* n) {}
    virtual void operator()(hilti::operator_::bytes::SumAssignBytes* n) {}
    virtual void operator()(hilti::operator_::bytes::SumAssignStreamView* n) {}
    virtual void operator()(hilti::operator_::bytes::SumAssignUInt8* n) {}
    virtual void operator()(hilti::operator_::bytes::Find* n) {}
    virtual void operator()(hilti::operator_::bytes::LowerCase* n) {}
    virtual void operator()(hilti::operator_::bytes::UpperCase* n) {}
    virtual void operator()(hilti::operator_::bytes::At* n) {}
    virtual void operator()(hilti::operator_::bytes::Split* n) {}
    virtual void operator()(hilti::operator_::bytes::Split1* n) {}
    virtual void operator()(hilti::operator_::bytes::StartsWith* n) {}
    virtual void operator()(hilti::operator_::bytes::EndsWith*) {}
    virtual void operator()(hilti::operator_::bytes::Strip* n) {}
    virtual void operator()(hilti::operator_::bytes::SubIterators* n) {}
    virtual void operator()(hilti::operator_::bytes::SubIterator* n) {}
    virtual void operator()(hilti::operator_::bytes::SubOffsets* n) {}
    virtual void operator()(hilti::operator_::bytes::Join* n) {}
    virtual void operator()(hilti::operator_::bytes::ToIntAscii* n) {}
    virtual void operator()(hilti::operator_::bytes::ToUIntAscii* n) {}
    virtual void operator()(hilti::operator_::bytes::ToIntBinary* n) {}
    virtual void operator()(hilti::operator_::bytes::ToUIntBinary* n) {}
    virtual void operator()(hilti::operator_::bytes::ToRealAscii* n) {}
    virtual void operator()(hilti::operator_::bytes::ToTimeAscii* n) {}
    virtual void operator()(hilti::operator_::bytes::ToTimeBinary* n) {}
    virtual void operator()(hilti::operator_::bytes::Decode* n) {}
    virtual void operator()(hilti::operator_::bytes::Match* n) {}
    virtual void operator()(hilti::operator_::enum_::Equal* n) {}
    virtual void operator()(hilti::operator_::enum_::Unequal* n) {}
    virtual void operator()(hilti::operator_::enum_::CastToSignedInteger* n) {}
    virtual void operator()(hilti::operator_::enum_::CastToUnsignedInteger* n) {}
    virtual void operator()(hilti::operator_::enum_::CtorSigned* n) {}
    virtual void operator()(hilti::operator_::enum_::CtorUnsigned* n) {}
    virtual void operator()(hilti::operator_::enum_::HasLabel* n) {}
    virtual void operator()(hilti::operator_::error::Ctor* n) {}
    virtual void operator()(hilti::operator_::error::Equal* n) {}
    virtual void operator()(hilti::operator_::error::Unequal* n) {}
    virtual void operator()(hilti::operator_::error::Description* n) {}
    virtual void operator()(hilti::operator_::exception::Ctor* n) {}
    virtual void operator()(hilti::operator_::exception::Description* n) {}
    virtual void operator()(hilti::operator_::generic::Pack* n) {}
    virtual void operator()(hilti::operator_::generic::Unpack* n) {}
    virtual void operator()(hilti::operator_::generic::Begin* n) {}
    virtual void operator()(hilti::operator_::generic::End* n) {}
    virtual void operator()(hilti::operator_::generic::New* n) {}
    virtual void operator()(hilti::operator_::interval::Equal* n) {}
    virtual void operator()(hilti::operator_::interval::Unequal* n) {}
    virtual void operator()(hilti::operator_::interval::Sum* n) {}
    virtual void operator()(hilti::operator_::interval::Difference* n) {}
    virtual void operator()(hilti::operator_::interval::Greater* n) {}
    virtual void operator()(hilti::operator_::interval::GreaterEqual* n) {}
    virtual void operator()(hilti::operator_::interval::Lower* n) {}
    virtual void operator()(hilti::operator_::interval::LowerEqual* n) {}
    virtual void operator()(hilti::operator_::interval::MultipleUnsignedInteger* n) {}
    virtual void operator()(hilti::operator_::interval::MultipleReal* n) {}
    virtual void operator()(hilti::operator_::interval::CtorSignedIntegerNs* n) {}
    virtual void operator()(hilti::operator_::interval::CtorSignedIntegerSecs* n) {}
    virtual void operator()(hilti::operator_::interval::CtorUnsignedIntegerNs* n) {}
    virtual void operator()(hilti::operator_::interval::CtorUnsignedIntegerSecs* n) {}
    virtual void operator()(hilti::operator_::interval::CtorRealSecs* n) {}
    virtual void operator()(hilti::operator_::interval::Seconds* n) {}
    virtual void operator()(hilti::operator_::interval::Nanoseconds* n) {}
    virtual void operator()(hilti::operator_::list::iterator::Deref* n) {}
    virtual void operator()(hilti::operator_::list::iterator::IncrPostfix* n) {}
    virtual void operator()(hilti::operator_::list::iterator::IncrPrefix* n) {}
    virtual void operator()(hilti::operator_::list::iterator::Equal* n) {}
    virtual void operator()(hilti::operator_::list::iterator::Unequal* n) {}
    virtual void operator()(hilti::operator_::list::Size* n) {}
    virtual void operator()(hilti::operator_::list::Equal* n) {}
    virtual void operator()(hilti::operator_::list::Unequal* n) {}
    virtual void operator()(hilti::operator_::map::iterator::Deref* n) {}
    virtual void operator()(hilti::operator_::map::iterator::IncrPostfix* n) {}
    virtual void operator()(hilti::operator_::map::iterator::IncrPrefix* n) {}
    virtual void operator()(hilti::operator_::map::iterator::Equal* n) {}
    virtual void operator()(hilti::operator_::map::iterator::Unequal* n) {}
    virtual void operator()(hilti::operator_::map::Size* n) {}
    virtual void operator()(hilti::operator_::map::Equal* n) {}
    virtual void operator()(hilti::operator_::map::Unequal* n) {}
    virtual void operator()(hilti::operator_::map::In* n) {}
    virtual void operator()(hilti::operator_::map::Delete* n) {}
    virtual void operator()(hilti::operator_::map::IndexConst* n) {}
    virtual void operator()(hilti::operator_::map::IndexNonConst* n) {}
    virtual void operator()(hilti::operator_::map::IndexAssign* n) {}
    virtual void operator()(hilti::operator_::map::Get* n) {}
    virtual void operator()(hilti::operator_::map::GetOptional* n) {}
    virtual void operator()(hilti::operator_::map::Clear* n) {}
    virtual void operator()(hilti::operator_::network::Equal* n) {}
    virtual void operator()(hilti::operator_::network::Unequal* n) {}
    virtual void operator()(hilti::operator_::network::In* n) {}
    virtual void operator()(hilti::operator_::network::Family* n) {}
    virtual void operator()(hilti::operator_::network::Prefix* n) {}
    virtual void operator()(hilti::operator_::network::Length* n) {}
    virtual void operator()(hilti::operator_::optional::Deref* n) {}
    virtual void operator()(hilti::operator_::port::Equal* n) {}
    virtual void operator()(hilti::operator_::port::Unequal* n) {}
    virtual void operator()(hilti::operator_::port::Ctor* n) {}
    virtual void operator()(hilti::operator_::port::Protocol* n) {}
    virtual void operator()(hilti::operator_::real::SignNeg* n) {}
    virtual void operator()(hilti::operator_::real::Difference* n) {}
    virtual void operator()(hilti::operator_::real::DifferenceAssign* n) {}
    virtual void operator()(hilti::operator_::real::Division* n) {}
    virtual void operator()(hilti::operator_::real::DivisionAssign* n) {}
    virtual void operator()(hilti::operator_::real::Equal* n) {}
    virtual void operator()(hilti::operator_::real::Greater* n) {}
    virtual void operator()(hilti::operator_::real::GreaterEqual* n) {}
    virtual void operator()(hilti::operator_::real::Lower* n) {}
    virtual void operator()(hilti::operator_::real::LowerEqual* n) {}
    virtual void operator()(hilti::operator_::real::Modulo* n) {}
    virtual void operator()(hilti::operator_::real::Multiple* n) {}
    virtual void operator()(hilti::operator_::real::MultipleAssign* n) {}
    virtual void operator()(hilti::operator_::real::Power* n) {}
    virtual void operator()(hilti::operator_::real::Sum* n) {}
    virtual void operator()(hilti::operator_::real::SumAssign* n) {}
    virtual void operator()(hilti::operator_::real::Unequal* n) {}
    virtual void operator()(hilti::operator_::real::CastToUnsignedInteger* n) {}
    virtual void operator()(hilti::operator_::real::CastToSignedInteger* n) {}
    virtual void operator()(hilti::operator_::real::CastToTime* n) {}
    virtual void operator()(hilti::operator_::real::CastToInterval* n) {}
    virtual void operator()(hilti::operator_::strong_reference::Deref* n) {}
    virtual void operator()(hilti::operator_::strong_reference::Equal* n) {}
    virtual void operator()(hilti::operator_::strong_reference::Unequal* n) {}
    virtual void operator()(hilti::operator_::weak_reference::Deref* n) {}
    virtual void operator()(hilti::operator_::weak_reference::Equal* n) {}
    virtual void operator()(hilti::operator_::weak_reference::Unequal* n) {}
    virtual void operator()(hilti::operator_::value_reference::Deref* n) {}
    virtual void operator()(hilti::operator_::value_reference::Equal* n) {}
    virtual void operator()(hilti::operator_::value_reference::Unequal* n) {}
    virtual void operator()(hilti::operator_::regexp::Match* n) {}
    virtual void operator()(hilti::operator_::regexp::Find* n) {}
    virtual void operator()(hilti::operator_::regexp::MatchGroups* n) {}
    virtual void operator()(hilti::operator_::regexp::TokenMatcher* n) {}
    virtual void operator()(hilti::operator_::regexp_match_state::AdvanceBytes* n) {}
    virtual void operator()(hilti::operator_::regexp_match_state::AdvanceView* n) {}
    virtual void operator()(hilti::operator_::result::Deref* n) {}
    virtual void operator()(hilti::operator_::result::Error* n) {}
    virtual void operator()(hilti::operator_::set::iterator::Deref* n) {}
    virtual void operator()(hilti::operator_::set::iterator::IncrPostfix* n) {}
    virtual void operator()(hilti::operator_::set::iterator::IncrPrefix* n) {}
    virtual void operator()(hilti::operator_::set::iterator::Equal* n) {}
    virtual void operator()(hilti::operator_::set::iterator::Unequal* n) {}
    virtual void operator()(hilti::operator_::set::Size* n) {}
    virtual void operator()(hilti::operator_::set::Equal* n) {}
    virtual void operator()(hilti::operator_::set::Unequal* n) {}
    virtual void operator()(hilti::operator_::set::In* n) {}
    virtual void operator()(hilti::operator_::set::Add* n) {}
    virtual void operator()(hilti::operator_::set::Delete* n) {}
    virtual void operator()(hilti::operator_::set::Clear* n) {}
    virtual void operator()(hilti::operator_::signed_integer::DecrPostfix* n) {}
    virtual void operator()(hilti::operator_::signed_integer::DecrPrefix* n) {}
    virtual void operator()(hilti::operator_::signed_integer::IncrPostfix* n) {}
    virtual void operator()(hilti::operator_::signed_integer::IncrPrefix* n) {}
    virtual void operator()(hilti::operator_::signed_integer::SignNeg* n) {}
    virtual void operator()(hilti::operator_::signed_integer::Difference* n) {}
    virtual void operator()(hilti::operator_::signed_integer::DifferenceAssign* n) {}
    virtual void operator()(hilti::operator_::signed_integer::Division* n) {}
    virtual void operator()(hilti::operator_::signed_integer::DivisionAssign* n) {}
    virtual void operator()(hilti::operator_::signed_integer::Equal* n) {}
    virtual void operator()(hilti::operator_::signed_integer::Greater* n) {}
    virtual void operator()(hilti::operator_::signed_integer::GreaterEqual* n) {}
    virtual void operator()(hilti::operator_::signed_integer::Lower* n) {}
    virtual void operator()(hilti::operator_::signed_integer::LowerEqual* n) {}
    virtual void operator()(hilti::operator_::signed_integer::Modulo* n) {}
    virtual void operator()(hilti::operator_::signed_integer::Multiple* n) {}
    virtual void operator()(hilti::operator_::signed_integer::MultipleAssign* n) {}
    virtual void operator()(hilti::operator_::signed_integer::Power* n) {}
    virtual void operator()(hilti::operator_::signed_integer::Sum* n) {}
    virtual void operator()(hilti::operator_::signed_integer::SumAssign* n) {}
    virtual void operator()(hilti::operator_::signed_integer::Unequal* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CastToSigned* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CastToUnsigned* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CastToReal* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CastToEnum* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CastToInterval* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CastToBool* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CtorSigned8* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CtorSigned16* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CtorSigned32* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CtorSigned64* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CtorUnsigned8* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CtorUnsigned16* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CtorUnsigned32* n) {}
    virtual void operator()(hilti::operator_::signed_integer::CtorUnsigned64* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::Deref* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::IncrPostfix* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::IncrPrefix* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::Equal* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::Unequal* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::Lower* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::LowerEqual* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::Greater* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::GreaterEqual* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::Difference* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::Sum* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::SumAssign* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::Offset* n) {}
    virtual void operator()(hilti::operator_::stream::iterator::IsFrozen* n) {}
    virtual void operator()(hilti::operator_::stream::view::Size* n) {}
    virtual void operator()(hilti::operator_::stream::view::InBytes* n) {}
    virtual void operator()(hilti::operator_::stream::view::InView* n) {}
    virtual void operator()(hilti::operator_::stream::view::EqualView* n) {}
    virtual void operator()(hilti::operator_::stream::view::EqualBytes* n) {}
    virtual void operator()(hilti::operator_::stream::view::UnequalView* n) {}
    virtual void operator()(hilti::operator_::stream::view::UnequalBytes* n) {}
    virtual void operator()(hilti::operator_::stream::view::Offset* n) {}
    virtual void operator()(hilti::operator_::stream::view::AdvanceBy* n) {}
    virtual void operator()(hilti::operator_::stream::view::AdvanceToNextData* n) {}
    virtual void operator()(hilti::operator_::stream::view::Limit* n) {}
    virtual void operator()(hilti::operator_::stream::view::AdvanceTo* n) {}
    virtual void operator()(hilti::operator_::stream::view::Find* n) {}
    virtual void operator()(hilti::operator_::stream::view::At* n) {}
    virtual void operator()(hilti::operator_::stream::view::StartsWith* n) {}
    virtual void operator()(hilti::operator_::stream::view::SubIterators* n) {}
    virtual void operator()(hilti::operator_::stream::view::SubIterator* n) {}
    virtual void operator()(hilti::operator_::stream::view::SubOffsets* n) {}
    virtual void operator()(hilti::operator_::stream::Ctor* n) {}
    virtual void operator()(hilti::operator_::stream::Size* n) {}
    virtual void operator()(hilti::operator_::stream::Unequal* n) {}
    virtual void operator()(hilti::operator_::stream::SumAssignView* n) {}
    virtual void operator()(hilti::operator_::stream::SumAssignBytes* n) {}
    virtual void operator()(hilti::operator_::stream::Freeze* n) {}
    virtual void operator()(hilti::operator_::stream::Unfreeze* n) {}
    virtual void operator()(hilti::operator_::stream::IsFrozen* n) {}
    virtual void operator()(hilti::operator_::stream::At* n) {}
    virtual void operator()(hilti::operator_::stream::Trim* n) {}
    virtual void operator()(hilti::operator_::stream::Statistics* n) {}
    virtual void operator()(hilti::operator_::string::Equal* n) {}
    virtual void operator()(hilti::operator_::string::Unequal* n) {}
    virtual void operator()(hilti::operator_::string::Size* n) {}
    virtual void operator()(hilti::operator_::string::Sum* n) {}
    virtual void operator()(hilti::operator_::string::SumAssign* n) {}
    virtual void operator()(hilti::operator_::string::Modulo* n) {}
    virtual void operator()(hilti::operator_::string::Encode* n) {}
    virtual void operator()(hilti::operator_::string::Split* n) {}
    virtual void operator()(hilti::operator_::string::Split1* n) {}
    virtual void operator()(hilti::operator_::string::StartsWith* n) {}
    virtual void operator()(hilti::operator_::string::EndsWith* n) {}
    virtual void operator()(hilti::operator_::string::LowerCase* n) {}
    virtual void operator()(hilti::operator_::string::UpperCase* n) {}
    virtual void operator()(hilti::operator_::struct_::Unset* n) {}
    virtual void operator()(hilti::operator_::struct_::MemberNonConst* n) {}
    virtual void operator()(hilti::operator_::struct_::MemberConst* n) {}
    virtual void operator()(hilti::operator_::struct_::TryMember* n) {}
    virtual void operator()(hilti::operator_::struct_::HasMember* n) {}
    virtual void operator()(hilti::operator_::time::Equal* n) {}
    virtual void operator()(hilti::operator_::time::Unequal* n) {}
    virtual void operator()(hilti::operator_::time::SumInterval* n) {}
    virtual void operator()(hilti::operator_::time::DifferenceTime* n) {}
    virtual void operator()(hilti::operator_::time::DifferenceInterval* n) {}
    virtual void operator()(hilti::operator_::time::Greater* n) {}
    virtual void operator()(hilti::operator_::time::GreaterEqual* n) {}
    virtual void operator()(hilti::operator_::time::Lower* n) {}
    virtual void operator()(hilti::operator_::time::LowerEqual* n) {}
    virtual void operator()(hilti::operator_::time::CtorSignedIntegerNs* n) {}
    virtual void operator()(hilti::operator_::time::CtorSignedIntegerSecs* n) {}
    virtual void operator()(hilti::operator_::time::CtorUnsignedIntegerNs* n) {}
    virtual void operator()(hilti::operator_::time::CtorUnsignedIntegerSecs* n) {}
    virtual void operator()(hilti::operator_::time::CtorRealSecs* n) {}
    virtual void operator()(hilti::operator_::time::Seconds* n) {}
    virtual void operator()(hilti::operator_::time::Nanoseconds* n) {}
    virtual void operator()(hilti::operator_::tuple::Equal* n) {}
    virtual void operator()(hilti::operator_::tuple::Unequal* n) {}
    virtual void operator()(hilti::operator_::tuple::Index* n) {}
    virtual void operator()(hilti::operator_::tuple::Member* n) {}
    virtual void operator()(hilti::operator_::tuple::CustomAssign* n) {}
    virtual void operator()(hilti::operator_::union_::Equal* n) {}
    virtual void operator()(hilti::operator_::union_::Unequal* n) {}
    virtual void operator()(hilti::operator_::union_::MemberConst* n) {}
    virtual void operator()(hilti::operator_::union_::MemberNonConst* n) {}
    virtual void operator()(hilti::operator_::union_::HasMember* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::DecrPostfix* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::DecrPrefix* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::IncrPostfix* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::IncrPrefix* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::SignNeg* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::Difference* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::DifferenceAssign* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::Division* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::DivisionAssign* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::Equal* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::Greater* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::GreaterEqual* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::Lower* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::LowerEqual* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::Modulo* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::Multiple* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::MultipleAssign* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::Power* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::Sum* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::SumAssign* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::Unequal* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::Negate* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::BitAnd* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::BitOr* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::BitXor* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::ShiftLeft* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::ShiftRight* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CastToUnsigned* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CastToSigned* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CastToReal* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CastToEnum* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CastToInterval* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CastToTime* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CastToBool* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CtorSigned8* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CtorSigned16* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CtorSigned32* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CtorSigned64* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CtorUnsigned8* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CtorUnsigned16* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CtorUnsigned32* n) {}
    virtual void operator()(hilti::operator_::unsigned_integer::CtorUnsigned64* n) {}
    virtual void operator()(hilti::operator_::vector::iterator::Deref* n) {}
    virtual void operator()(hilti::operator_::vector::iterator::IncrPostfix* n) {}
    virtual void operator()(hilti::operator_::vector::iterator::IncrPrefix* n) {}
    virtual void operator()(hilti::operator_::vector::iterator::Equal* n) {}
    virtual void operator()(hilti::operator_::vector::iterator::Unequal* n) {}
    virtual void operator()(hilti::operator_::vector::Size* n) {}
    virtual void operator()(hilti::operator_::vector::Equal* n) {}
    virtual void operator()(hilti::operator_::vector::Unequal* n) {}
    virtual void operator()(hilti::operator_::vector::IndexConst* n) {}
    virtual void operator()(hilti::operator_::vector::IndexNonConst* n) {}
    virtual void operator()(hilti::operator_::vector::Sum* n) {}
    virtual void operator()(hilti::operator_::vector::SumAssign* n) {}
    virtual void operator()(hilti::operator_::vector::Assign* n) {}
    virtual void operator()(hilti::operator_::vector::PushBack* n) {}
    virtual void operator()(hilti::operator_::vector::PopBack* n) {}
    virtual void operator()(hilti::operator_::vector::Front* n) {}
    virtual void operator()(hilti::operator_::vector::Back* n) {}
    virtual void operator()(hilti::operator_::vector::Reserve* n) {}
    virtual void operator()(hilti::operator_::vector::Resize* n) {}
    virtual void operator()(hilti::operator_::vector::At* n) {}
    virtual void operator()(hilti::operator_::vector::SubRange* n) {}
    virtual void operator()(hilti::operator_::vector::SubEnd* n) {}
    virtual void operator()(hilti::statement::Assert*) {}
    virtual void operator()(hilti::statement::Block*) {}
    virtual void operator()(hilti::statement::Break*) {}
    virtual void operator()(hilti::statement::Comment*) {}
    virtual void operator()(hilti::statement::Continue*) {}
    virtual void operator()(hilti::statement::Declaration*) {}
    virtual void operator()(hilti::statement::Expression*) {}
    virtual void operator()(hilti::statement::For*) {}
    virtual void operator()(hilti::statement::If*) {}
    virtual void operator()(hilti::statement::Return*) {}
    virtual void operator()(hilti::statement::SetLocation*) {}
    virtual void operator()(hilti::statement::Switch*) {}
    virtual void operator()(hilti::statement::Throw*) {}
    virtual void operator()(hilti::statement::Try*) {}
    virtual void operator()(hilti::statement::While*) {}
    virtual void operator()(hilti::statement::Yield*) {}
    virtual void operator()(hilti::statement::switch_::Case*) {}
    virtual void operator()(hilti::statement::try_::Catch*) {}
    virtual void operator()(hilti::type::Address*) {}
    virtual void operator()(hilti::type::Any*) {}
    virtual void operator()(hilti::type::Auto*) {}
    virtual void operator()(hilti::type::bitfield::BitRange*) {}
    virtual void operator()(hilti::type::Bitfield*) {}
    virtual void operator()(hilti::type::Bool*) {}
    virtual void operator()(hilti::type::Bytes*) {}
    virtual void operator()(hilti::type::DocOnly*) {}
    virtual void operator()(hilti::type::Enum*) {}
    virtual void operator()(hilti::type::Error*) {}
    virtual void operator()(hilti::type::Exception*) {}
    virtual void operator()(hilti::type::Function*) {}
    virtual void operator()(hilti::type::Interval*) {}
    virtual void operator()(hilti::type::Library*) {}
    virtual void operator()(hilti::type::List*) {}
    virtual void operator()(hilti::type::Map*) {}
    virtual void operator()(hilti::type::Member*) {}
    virtual void operator()(hilti::type::Name*) {}
    virtual void operator()(hilti::type::Network*) {}
    virtual void operator()(hilti::type::Null*) {}
    virtual void operator()(hilti::type::OperandList*) {}
    virtual void operator()(hilti::type::operand_list::Operand* n) {}
    virtual void operator()(hilti::type::Optional*) {}
    virtual void operator()(hilti::type::Port*) {}
    virtual void operator()(hilti::type::Real*) {}
    virtual void operator()(hilti::type::RegExp*) {}
    virtual void operator()(hilti::type::Result*) {}
    virtual void operator()(hilti::type::Set*) {}
    virtual void operator()(hilti::type::SignedInteger*) {}
    virtual void operator()(hilti::type::Stream*) {}
    virtual void operator()(hilti::type::String*) {}
    virtual void operator()(hilti::type::StrongReference*) {}
    virtual void operator()(hilti::type::Struct*) {}
    virtual void operator()(hilti::type::Time*) {}
    virtual void operator()(hilti::type::Tuple*) {}
    virtual void operator()(hilti::type::Type_*) {}
    virtual void operator()(hilti::type::Union*) {}
    virtual void operator()(hilti::type::Unknown*) {}
    virtual void operator()(hilti::type::UnsignedInteger*) {}
    virtual void operator()(hilti::type::ValueReference*) {}
    virtual void operator()(hilti::type::Vector*) {}
    virtual void operator()(hilti::type::Void*) {}
    virtual void operator()(hilti::type::WeakReference*) {}
    virtual void operator()(hilti::type::bytes::Iterator*) {}
    virtual void operator()(hilti::type::enum_::Label*) {}
    virtual void operator()(hilti::type::function::Parameter*) {}
    virtual void operator()(hilti::type::list::Iterator*) {}
    virtual void operator()(hilti::type::map::Iterator*) {}
    virtual void operator()(hilti::type::set::Iterator*) {}
    virtual void operator()(hilti::type::stream::Iterator*) {}
    virtual void operator()(hilti::type::stream::View*) {}
    virtual void operator()(hilti::type::tuple::Element*) {}
    virtual void operator()(hilti::type::vector::Iterator*) {}

private:
    const Tag _tag = HILTI;
};

} // namespace hilti::visitor
