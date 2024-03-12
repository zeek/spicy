// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <array>
#include <string>

namespace hilti::node {

/** Tag value uniquely identifying a Node-derived class. */
using Tag = uint16_t;

/**
 * Inheritance path for a Node-derived class. We only support an max. of 4
 * inheritance levels for now, so that this fits into an uint64.
 */
using Tags = std::array<Tag, 4>;

/** Turns the tag path into a readable representation for debugging purposes. */
extern std::string to_string(const Tags& ti);

namespace tag {

const Tag Node = 1;

const Tag ASTRoot = 100;
const Tag Attribute = 101;
const Tag AttributeSet = 102;
const Tag Ctor = 103;
const Tag Declaration = 104;
const Tag Expression = 105;
const Tag Function = 106;
const Tag QualifiedType = 107;
const Tag Statement = 108;
const Tag UnqualifiedType = 109;

namespace ctor::bitfield {
const Tag BitRange = 110;
}

namespace ctor::map {
const Tag Element = 111;
}

namespace ctor::struct_ {
const Tag Field = 112;
}

namespace statement::switch_ {
const Tag Case = 113;
}

namespace statement::try_ {
const Tag Catch = 114;
}

namespace type::bitfield {
const Tag BitRange = 115;
}

namespace type::enum_ {
const Tag Label = 116;
}

namespace type::operand_list {
const Tag Operand = 117;
}

namespace type::tuple {
const Tag Element = 118;
}

namespace ctor {
const Tag Address = 200;
const Tag Bitfield = 201;
const Tag Bool = 202;
const Tag Bytes = 203;
const Tag Coerced = 204;
const Tag Default = 205;
const Tag Enum = 206;
const Tag Error = 207;
const Tag Exception = 208;
const Tag Interval = 209;
const Tag Library = 210;
const Tag List = 211;
const Tag Map = 212;
const Tag Network = 213;
const Tag Null = 214;
const Tag Optional = 215;
const Tag Port = 216;
const Tag Real = 217;
const Tag RegExp = 218;
const Tag Result = 219;
const Tag Set = 220;
const Tag SignedInteger = 221;
const Tag Stream = 222;
const Tag String = 223;
const Tag StrongReference = 224;
const Tag Struct = 225;
const Tag Time = 226;
const Tag Tuple = 227;
const Tag Union = 228;
const Tag UnsignedInteger = 229;
const Tag ValueReference = 230;
const Tag Vector = 231;
const Tag WeakReference = 232;
} // namespace ctor

namespace declaration {
const Tag Constant = 300;
const Tag Expression = 301;
const Tag Field = 302;
const Tag Function = 303;
const Tag GlobalVariable = 304;
const Tag ImportedModule = 305;
const Tag LocalVariable = 306;
const Tag Module = 307;
const Tag Parameter = 308;
const Tag Property = 309;
const Tag Type = 310;
} // namespace declaration

namespace expression {
const Tag Assign = 400;
const Tag BuiltInFunction = 401;
const Tag Coerced = 402;
const Tag Ctor = 403;
const Tag Deferred = 404;
const Tag Grouping = 405;
const Tag Keyword = 406;
const Tag ListComprehension = 407;
const Tag LogicalAnd = 408;
const Tag LogicalNot = 409;
const Tag LogicalOr = 410;
const Tag Member = 411;
const Tag Move = 412;
const Tag Name = 413;
const Tag PendingCoerced = 414;
const Tag Ternary = 415;
const Tag TypeInfo = 416;
const Tag TypeWrapped = 417;
const Tag Type_ = 418;
const Tag ResolvedOperator = 419;
const Tag UnresolvedOperator = 420;
const Tag Void = 421;
} // namespace expression

namespace operator_ {

namespace address {
const Tag Equal = 600;
const Tag Family = 601;
const Tag Unequal = 602;
} // namespace address

namespace bitfield {
const Tag HasMember = 700;
const Tag Member = 701;
} // namespace bitfield

namespace bool_ {
const Tag BitAnd = 800;
const Tag BitOr = 801;
const Tag BitXor = 802;
const Tag Equal = 803;
const Tag Unequal = 804;
} // namespace bool_

namespace bytes {
const Tag At = 900;
const Tag Decode = 901;
const Tag Equal = 902;
const Tag Find = 903;
const Tag Greater = 904;
const Tag GreaterEqual = 905;
const Tag In = 906;
const Tag Join = 907;
const Tag Lower = 908;
const Tag LowerCase = 909;
const Tag LowerEqual = 910;
const Tag Match = 911;
const Tag Size = 912;
const Tag Split = 913;
const Tag Split1 = 914;
const Tag StartsWith = 915;
const Tag Strip = 916;
const Tag SubIterator = 917;
const Tag SubIterators = 918;
const Tag SubOffsets = 919;
const Tag Sum = 920;
const Tag SumAssignBytes = 921;
const Tag SumAssignStreamView = 922;
const Tag SumAssignUInt8 = 923;
const Tag ToIntAscii = 924;
const Tag ToIntBinary = 925;
const Tag ToTimeAscii = 926;
const Tag ToTimeBinary = 927;
const Tag ToUIntAscii = 928;
const Tag ToUIntBinary = 929;
const Tag Unequal = 930;
const Tag UpperCase = 931;

namespace iterator {
const Tag Deref = 1000;
const Tag Difference = 1001;
const Tag Equal = 1002;
const Tag Greater = 1003;
const Tag GreaterEqual = 1004;
const Tag IncrPostfix = 1005;
const Tag IncrPrefix = 1006;
const Tag Lower = 1007;
const Tag LowerEqual = 1008;
const Tag Sum = 1009;
const Tag SumAssign = 1010;
const Tag Unequal = 1011;
} // namespace iterator
} // namespace bytes

namespace enum_ {
const Tag CastToSignedInteger = 1100;
const Tag CastToUnsignedInteger = 1101;
const Tag CtorSigned = 1102;
const Tag CtorUnsigned = 1103;
const Tag Equal = 1104;
const Tag HasLabel = 1105;
const Tag Unequal = 1106;
} // namespace enum_

namespace error {
const Tag Ctor = 1200;
const Tag Description = 1201;
} // namespace error

namespace exception {
const Tag Ctor = 1300;
const Tag Description = 1301;
} // namespace exception

namespace function {
const Tag Call = 1400;
}

namespace generic {
const Tag Begin = 1500;
const Tag CastedCoercion = 1501;
const Tag End = 1502;
const Tag New = 1503;
const Tag Pack = 1504;
const Tag Unpack = 1505;
} // namespace generic

namespace interval {
const Tag CtorRealSecs = 1600;
const Tag CtorSignedIntegerNs = 1601;
const Tag CtorSignedIntegerSecs = 1602;
const Tag CtorUnsignedIntegerNs = 1603;
const Tag CtorUnsignedIntegerSecs = 1604;
const Tag Difference = 1605;
const Tag Equal = 1606;
const Tag Greater = 1607;
const Tag GreaterEqual = 1608;
const Tag Lower = 1609;
const Tag LowerEqual = 1610;
const Tag MultipleReal = 1611;
const Tag MultipleUnsignedInteger = 1612;
const Tag Nanoseconds = 1613;
const Tag Seconds = 1614;
const Tag Sum = 1615;
const Tag Unequal = 1616;
} // namespace interval

namespace list {
const Tag Equal = 1700;
const Tag Size = 1701;
const Tag Unequal = 1702;

namespace iterator {
const Tag Deref = 1800;
const Tag Equal = 1801;
const Tag IncrPostfix = 1802;
const Tag IncrPrefix = 1803;
const Tag Unequal = 1804;
} // namespace iterator
} // namespace list

namespace map {
const Tag Clear = 1900;
const Tag Delete = 1901;
const Tag Equal = 1902;
const Tag Get = 1903;
const Tag In = 1904;
const Tag IndexAssign = 1905;
const Tag IndexConst = 1906;
const Tag IndexNonConst = 1907;
const Tag Size = 1908;
const Tag Unequal = 1909;

namespace iterator {
const Tag Deref = 2000;
const Tag Equal = 2001;
const Tag IncrPostfix = 2002;
const Tag IncrPrefix = 2003;
const Tag Unequal = 2004;
} // namespace iterator
} // namespace map

namespace network {
const Tag Equal = 2100;
const Tag Family = 2101;
const Tag In = 2102;
const Tag Length = 2103;
const Tag Prefix = 2104;
const Tag Unequal = 2105;
} // namespace network

namespace optional {
const Tag Deref = 2200;
}

namespace port {
const Tag Ctor = 2300;
const Tag Equal = 2301;
const Tag Protocol = 2302;
const Tag Unequal = 2303;
} // namespace port

namespace real {
const Tag CastToInterval = 2400;
const Tag CastToSignedInteger = 2401;
const Tag CastToTime = 2402;
const Tag CastToUnsignedInteger = 2403;
const Tag Difference = 2404;
const Tag DifferenceAssign = 2405;
const Tag Division = 2406;
const Tag DivisionAssign = 2407;
const Tag Equal = 2408;
const Tag Greater = 2409;
const Tag GreaterEqual = 2410;
const Tag Lower = 2411;
const Tag LowerEqual = 2412;
const Tag Modulo = 2413;
const Tag Multiple = 2414;
const Tag MultipleAssign = 2415;
const Tag Power = 2416;
const Tag SignNeg = 2417;
const Tag Sum = 2418;
const Tag SumAssign = 2419;
const Tag Unequal = 2420;
} // namespace real

namespace regexp {
const Tag Find = 2500;
const Tag Match = 2501;
const Tag MatchGroups = 2502;
const Tag TokenMatcher = 2503;
} // namespace regexp

namespace regexp_match_state {
const Tag AdvanceBytes = 2600;
const Tag AdvanceView = 2601;
} // namespace regexp_match_state

namespace result {
const Tag Deref = 2700;
const Tag Error = 2701;
} // namespace result

namespace set {
const Tag Add = 2800;
const Tag Clear = 2801;
const Tag Delete = 2802;
const Tag Equal = 2803;
const Tag In = 2804;
const Tag Size = 2805;
const Tag Unequal = 2806;

namespace iterator {
const Tag Deref = 2900;
const Tag Equal = 2901;
const Tag IncrPostfix = 2902;
const Tag IncrPrefix = 2903;
const Tag Unequal = 2904;
} // namespace iterator
} // namespace set

namespace signed_integer {
const Tag CastToBool = 3000;
const Tag CastToEnum = 3001;
const Tag CastToInterval = 3002;
const Tag CastToReal = 3003;
const Tag CastToSigned = 3004;
const Tag CastToUnsigned = 3005;
const Tag CtorSigned16 = 3006;
const Tag CtorSigned32 = 3007;
const Tag CtorSigned64 = 3008;
const Tag CtorSigned8 = 3009;
const Tag CtorUnsigned16 = 3010;
const Tag CtorUnsigned32 = 3011;
const Tag CtorUnsigned64 = 3012;
const Tag CtorUnsigned8 = 3013;
const Tag DecrPostfix = 3014;
const Tag DecrPrefix = 3015;
const Tag Difference = 3016;
const Tag DifferenceAssign = 3017;
const Tag Division = 3018;
const Tag DivisionAssign = 3019;
const Tag Equal = 3020;
const Tag Greater = 3021;
const Tag GreaterEqual = 3022;
const Tag IncrPostfix = 3023;
const Tag IncrPrefix = 3024;
const Tag Lower = 3025;
const Tag LowerEqual = 3026;
const Tag Modulo = 3027;
const Tag Multiple = 3028;
const Tag MultipleAssign = 3029;
const Tag Power = 3030;
const Tag SignNeg = 3031;
const Tag Sum = 3032;
const Tag SumAssign = 3033;
const Tag Unequal = 3034;
} // namespace signed_integer

namespace stream {
const Tag At = 3100;
const Tag Ctor = 3101;
const Tag Freeze = 3102;
const Tag IsFrozen = 3103;
const Tag Size = 3104;
const Tag SumAssignBytes = 3105;
const Tag SumAssignView = 3106;
const Tag Trim = 3107;
const Tag Unequal = 3108;
const Tag Unfreeze = 3109;

namespace iterator {
const Tag Deref = 3200;
const Tag Difference = 3201;
const Tag Equal = 3202;
const Tag Greater = 3203;
const Tag GreaterEqual = 3204;
const Tag IncrPostfix = 3205;
const Tag IncrPrefix = 3206;
const Tag IsFrozen = 3207;
const Tag Lower = 3208;
const Tag LowerEqual = 3209;
const Tag Offset = 3210;
const Tag Sum = 3211;
const Tag SumAssign = 3212;
const Tag Unequal = 3213;
} // namespace iterator

namespace view {
const Tag AdvanceBy = 3300;
const Tag AdvanceTo = 3301;
const Tag AdvanceToNextData = 3302;
const Tag At = 3303;
const Tag EqualBytes = 3304;
const Tag EqualView = 3305;
const Tag Find = 3306;
const Tag InBytes = 3307;
const Tag InView = 3308;
const Tag Limit = 3309;
const Tag Offset = 3310;
const Tag Size = 3311;
const Tag StartsWith = 3312;
const Tag SubIterator = 3313;
const Tag SubIterators = 3314;
const Tag SubOffsets = 3315;
const Tag UnequalBytes = 3316;
const Tag UnequalView = 3317;
} // namespace view

} // namespace stream

namespace string {
const Tag Encode = 3400;
const Tag Equal = 3401;
const Tag Modulo = 3402;
const Tag Size = 3403;
const Tag Sum = 3404;
const Tag SumAssign = 3405;
const Tag Unequal = 3406;
} // namespace string

namespace strong_reference {
const Tag Deref = 3500;
const Tag Equal = 3501;
const Tag Unequal = 3502;
} // namespace strong_reference

namespace struct_ {
const Tag HasMember = 3600;
const Tag MemberCall = 3601;
const Tag MemberConst = 3602;
const Tag MemberNonConst = 3603;
const Tag TryMember = 3604;
const Tag Unset = 3605;
} // namespace struct_

namespace time {
const Tag CtorRealSecs = 3700;
const Tag CtorSignedIntegerNs = 3701;
const Tag CtorSignedIntegerSecs = 3702;
const Tag CtorUnsignedIntegerNs = 3703;
const Tag CtorUnsignedIntegerSecs = 3704;
const Tag DifferenceInterval = 3705;
const Tag DifferenceTime = 3706;
const Tag Equal = 3707;
const Tag Greater = 3708;
const Tag GreaterEqual = 3709;
const Tag Lower = 3710;
const Tag LowerEqual = 3711;
const Tag Nanoseconds = 3712;
const Tag Seconds = 3713;
const Tag SumInterval = 3714;
const Tag Unequal = 3715;
} // namespace time

namespace tuple {
const Tag CustomAssign = 3800;
const Tag Equal = 3801;
const Tag Index = 3802;
const Tag Member = 3803;
const Tag Unequal = 3804;
} // namespace tuple

namespace union_ {
const Tag Equal = 3900;
const Tag HasMember = 3901;
const Tag MemberConst = 3902;
const Tag MemberNonConst = 3903;
const Tag Unequal = 3904;
} // namespace union_

namespace unsigned_integer {
const Tag BitAnd = 4000;
const Tag BitOr = 4001;
const Tag BitXor = 4002;
const Tag CastToBool = 4003;
const Tag CastToEnum = 4004;
const Tag CastToInterval = 4005;
const Tag CastToReal = 4006;
const Tag CastToSigned = 4007;
const Tag CastToTime = 4008;
const Tag CastToUnsigned = 4009;
const Tag CtorSigned16 = 4010;
const Tag CtorSigned32 = 4011;
const Tag CtorSigned64 = 4012;
const Tag CtorSigned8 = 4013;
const Tag CtorUnsigned16 = 4014;
const Tag CtorUnsigned32 = 4015;
const Tag CtorUnsigned64 = 4016;
const Tag CtorUnsigned8 = 4017;
const Tag DecrPostfix = 4018;
const Tag DecrPrefix = 4019;
const Tag Difference = 4020;
const Tag DifferenceAssign = 4021;
const Tag Division = 4022;
const Tag DivisionAssign = 4023;
const Tag Equal = 4024;
const Tag Greater = 4025;
const Tag GreaterEqual = 4026;
const Tag IncrPostfix = 4027;
const Tag IncrPrefix = 4028;
const Tag Lower = 4029;
const Tag LowerEqual = 4030;
const Tag Modulo = 4031;
const Tag Multiple = 4032;
const Tag MultipleAssign = 4033;
const Tag Negate = 4034;
const Tag Power = 4035;
const Tag ShiftLeft = 4036;
const Tag ShiftRight = 4037;
const Tag SignNeg = 4038;
const Tag Sum = 4039;
const Tag SumAssign = 4040;
const Tag Unequal = 4041;
} // namespace unsigned_integer

namespace value_reference {
const Tag Deref = 4100;
const Tag Equal = 4101;
const Tag Unequal = 4102;
} // namespace value_reference

namespace vector {
const Tag Assign = 4200;
const Tag At = 4201;
const Tag Back = 4202;
const Tag Equal = 4203;
const Tag Front = 4204;
const Tag IndexConst = 4205;
const Tag IndexNonConst = 4206;
const Tag PopBack = 4207;
const Tag PushBack = 4208;
const Tag Reserve = 4209;
const Tag Resize = 4210;
const Tag Size = 4211;
const Tag SubEnd = 4212;
const Tag SubRange = 4213;
const Tag Sum = 4214;
const Tag SumAssign = 4215;
const Tag Unequal = 4216;

namespace iterator {
const Tag Deref = 4300;
const Tag Equal = 4301;
const Tag IncrPostfix = 4302;
const Tag IncrPrefix = 4303;
const Tag Unequal = 4304;
} // namespace iterator
} // namespace vector

namespace weak_reference {
const Tag Deref = 4400;
const Tag Equal = 4401;
const Tag Unequal = 4402;
} // namespace weak_reference

} // namespace operator_

namespace statement {
const Tag Assert = 4500;
const Tag Block = 4501;
const Tag Break = 4502;
const Tag Comment = 4503;
const Tag Continue = 4504;
const Tag Declaration = 4505;
const Tag Expression = 4506;
const Tag For = 4507;
const Tag If = 4508;
const Tag Return = 4509;
const Tag SetLocation = 4510;
const Tag Switch = 4511;
const Tag Throw = 4512;
const Tag Try = 4513;
const Tag While = 4514;
const Tag Yield = 4515;
} // namespace statement

namespace type {
const Tag Address = 4600;
const Tag Any = 4601;
const Tag Auto = 4602;
const Tag Bitfield = 4603;
const Tag Bool = 4604;
const Tag Bytes = 4605;
const Tag DocOnly = 4606;
const Tag Enum = 4607;
const Tag Error = 4608;
const Tag Exception = 4609;
const Tag Function = 4610;
const Tag Interval = 4611;
const Tag Library = 4612;
const Tag List = 4613;
const Tag Map = 4614;
const Tag Member = 4615;
const Tag Name = 4616;
const Tag Network = 4617;
const Tag Null = 4618;
const Tag OperandList = 4619;
const Tag Optional = 4620;
const Tag Port = 4621;
const Tag Real = 4622;
const Tag RegExp = 4623;
const Tag Result = 4624;
const Tag Set = 4625;
const Tag SignedInteger = 4626;
const Tag Stream = 4627;
const Tag String = 4628;
const Tag StrongReference = 4629;
const Tag Struct = 4630;
const Tag Time = 4631;
const Tag Tuple = 4632;
const Tag Type_ = 4633;
const Tag Union = 4634;
const Tag Unknown = 4635;
const Tag UnsignedInteger = 4636;
const Tag ValueReference = 4637;
const Tag Vector = 4638;
const Tag Void = 4639;
const Tag WeakReference = 4640;

namespace bytes {
const Tag Iterator = 4700;
}
namespace list {
const Tag Iterator = 4800;
}
namespace map {
const Tag Iterator = 4900;
}
namespace set {
const Tag Iterator = 5000;
}
namespace stream {
const Tag Iterator = 5100;
}
namespace stream {
const Tag View = 5200;
}
namespace vector {
const Tag Iterator = 5300;
}
} // namespace type

} // namespace tag

} // namespace hilti::node
