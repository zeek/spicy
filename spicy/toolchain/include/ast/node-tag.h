// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/node-tag.h>

namespace hilti::node::tag {

namespace type::unit::item::switch_ {
const Tag Case = 10000;
}

namespace ctor {
const Tag Unit = 10100;
}

namespace declaration {
const Tag Hook = 10200;
const Tag UnitHook = 10201;
} // namespace declaration

namespace operator_::sink {
const unsigned int Close = 10301;
const unsigned int Connect = 10302;
const unsigned int ConnectFilter = 10303;
const unsigned int ConnectMIMETypeBytes = 10304;
const unsigned int ConnectMIMETypeString = 10305;
const unsigned int Gap = 10306;
const unsigned int SequenceNumber = 10307;
const unsigned int SetAutoTrim = 10308;
const unsigned int SetInitialSequenceNumber = 10309;
const unsigned int SetPolicy = 10310;
const unsigned int SizeReference = 10311;
const unsigned int SizeValue = 10312;
const unsigned int Skip = 10313;
const unsigned int Trim = 10314;
const unsigned int Write = 10315;
} // namespace operator_::sink

namespace operator_::unit {
const unsigned int Backtrack = 10316;
const unsigned int ConnectFilter = 10317;
const unsigned int ContextConst = 10318;
const unsigned int ContextNonConst = 10319;
const unsigned int Find = 10320;
const unsigned int Forward = 10321;
const unsigned int ForwardEod = 10322;
const unsigned int HasMember = 10323;
const unsigned int Input = 10324;
const unsigned int MemberCall = 10325;
const unsigned int MemberConst = 10326;
const unsigned int MemberNonConst = 10327;
const unsigned int Offset = 10328;
const unsigned int Position = 10329;
const unsigned int SetInput = 1033;
const unsigned int TryMember = 10331;
const unsigned int Unset = 10332;
} // namespace operator_::unit

namespace statement {
const Tag Confirm = 10500;
const Tag Print = 10501;
const Tag Reject = 10502;
const Tag Stop = 10503;
} // namespace statement

namespace type {
const Tag Sink = 10600;
const Tag Unit = 10601;

namespace unit {
const Tag Item = 10700;
}

namespace unit::item {
const Tag Field = 10800;
}

namespace unit::item {
const Tag Property = 10900;
}

namespace unit::item {
const Tag Sink = 11000;
}

namespace unit::item {
const Tag Switch = 11100;
}

namespace unit::item {
const Tag UnitHook = 11200;
}

namespace unit::item {
const Tag UnresolvedField = 11300;
}

namespace unit::item {
const Tag Variable = 11400;
}

} // namespace type
} // namespace hilti::node::tag
