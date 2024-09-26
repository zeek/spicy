// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/node-tag.h>

namespace hilti::node::tag {

namespace type::unit::item::switch_ {
constexpr Tag Case = 10000;
}

namespace ctor {
constexpr Tag Unit = 10100;
}

namespace declaration {
constexpr Tag Hook = 10200;
constexpr Tag UnitHook = 10201;
} // namespace declaration

namespace operator_::sink {
constexpr unsigned int Close = 10301;
constexpr unsigned int Connect = 10302;
constexpr unsigned int ConnectFilter = 10303;
constexpr unsigned int ConnectMIMETypeBytes = 10304;
constexpr unsigned int ConnectMIMETypeString = 10305;
constexpr unsigned int Gap = 10306;
constexpr unsigned int SequenceNumber = 10307;
constexpr unsigned int SetAutoTrim = 10308;
constexpr unsigned int SetInitialSequenceNumber = 10309;
constexpr unsigned int SetPolicy = 10310;
constexpr unsigned int Size = 10312;
constexpr unsigned int Skip = 10313;
constexpr unsigned int Trim = 10314;
constexpr unsigned int Write = 10315;
} // namespace operator_::sink

namespace operator_::unit {
constexpr unsigned int Backtrack = 10316;
constexpr unsigned int ConnectFilter = 10317;
constexpr unsigned int ContextConst = 10318;
constexpr unsigned int ContextNonConst = 10319;
constexpr unsigned int Find = 10320;
constexpr unsigned int Forward = 10321;
constexpr unsigned int ForwardEod = 10322;
constexpr unsigned int HasMember = 10323;
constexpr unsigned int Input = 10324;
constexpr unsigned int MemberCall = 10325;
constexpr unsigned int MemberConst = 10326;
constexpr unsigned int MemberNonConst = 10327;
constexpr unsigned int Offset = 10328;
constexpr unsigned int Position = 10329;
constexpr unsigned int SetInput = 10330;
constexpr unsigned int Stream = 10331;
constexpr unsigned int TryMember = 10332;
constexpr unsigned int Unset = 10333;
} // namespace operator_::unit

namespace statement {
constexpr Tag Confirm = 10500;
constexpr Tag Print = 10501;
constexpr Tag Reject = 10502;
constexpr Tag Stop = 10503;
} // namespace statement

namespace type {
constexpr Tag Sink = 10600;
constexpr Tag Unit = 10601;

namespace unit {
constexpr Tag Item = 10700;
}

namespace unit::item {
constexpr Tag Field = 10800;
}

namespace unit::item {
constexpr Tag Property = 10900;
}

namespace unit::item {
constexpr Tag Sink = 11000;
}

namespace unit::item {
constexpr Tag Block = 11100;
constexpr Tag Switch = 11101;
} // namespace unit::item

namespace unit::item {
constexpr Tag UnitHook = 11200;
}

namespace unit::item {
constexpr Tag UnresolvedField = 11300;
}

namespace unit::item {
constexpr Tag Variable = 11400;
}

} // namespace type
} // namespace hilti::node::tag
