// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <array>
#include <cstdint>
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

constexpr Tag Node = 1;

constexpr Tag ASTRoot = 100;
constexpr Tag Attribute = 101;
constexpr Tag AttributeSet = 102;
constexpr Tag Ctor = 103;
constexpr Tag Declaration = 104;
constexpr Tag Expression = 105;
constexpr Tag Function = 106;
constexpr Tag QualifiedType = 107;
constexpr Tag Statement = 108;
constexpr Tag UnqualifiedType = 109;

namespace ctor::bitfield {
constexpr Tag BitRange = 110;
}

namespace ctor::map {
constexpr Tag Element = 111;
}

namespace ctor::struct_ {
constexpr Tag Field = 112;
}

namespace statement::switch_ {
constexpr Tag Case = 113;
}

namespace statement::try_ {
constexpr Tag Catch = 114;
}

namespace type::bitfield {
constexpr Tag BitRange = 115;
}

namespace type::enum_ {
constexpr Tag Label = 116;
}

namespace type::operand_list {
constexpr Tag Operand = 117;
}

namespace type::tuple {
constexpr Tag Element = 118;
}

namespace ctor {
constexpr Tag Address = 200;
constexpr Tag Bitfield = 201;
constexpr Tag Bool = 202;
constexpr Tag Bytes = 203;
constexpr Tag Coerced = 204;
constexpr Tag Default = 205;
constexpr Tag Enum = 206;
constexpr Tag Error = 207;
constexpr Tag Exception = 208;
constexpr Tag Interval = 209;
constexpr Tag Library = 210;
constexpr Tag List = 211;
constexpr Tag Map = 212;
constexpr Tag Network = 213;
constexpr Tag Null = 214;
constexpr Tag Optional = 215;
constexpr Tag Port = 216;
constexpr Tag Real = 217;
constexpr Tag RegExp = 218;
constexpr Tag Result = 219;
constexpr Tag Set = 220;
constexpr Tag SignedInteger = 221;
constexpr Tag Stream = 222;
constexpr Tag String = 223;
constexpr Tag StrongReference = 224;
constexpr Tag Struct = 225;
constexpr Tag Time = 226;
constexpr Tag Tuple = 227;
constexpr Tag Union = 228;
constexpr Tag UnsignedInteger = 229;
constexpr Tag ValueReference = 230;
constexpr Tag Vector = 231;
constexpr Tag WeakReference = 232;
} // namespace ctor

namespace declaration {
constexpr Tag Constant = 300;
constexpr Tag Expression = 301;
constexpr Tag Field = 302;
constexpr Tag Function = 303;
constexpr Tag GlobalVariable = 304;
constexpr Tag ImportedModule = 305;
constexpr Tag LocalVariable = 306;
constexpr Tag Module = 307;
constexpr Tag Parameter = 308;
constexpr Tag Property = 309;
constexpr Tag Type = 310;
} // namespace declaration

namespace expression {
constexpr Tag Assign = 400;
constexpr Tag Coerced = 401;
constexpr Tag ConditionTest = 402;
constexpr Tag Ctor = 403;
constexpr Tag Grouping = 404;
constexpr Tag Keyword = 405;
constexpr Tag ListComprehension = 406;
constexpr Tag LogicalAnd = 407;
constexpr Tag LogicalNot = 408;
constexpr Tag LogicalOr = 409;
constexpr Tag Member = 410;
constexpr Tag Move = 411;
constexpr Tag Name = 412;
constexpr Tag PendingCoerced = 413;
constexpr Tag Ternary = 414;
constexpr Tag TypeInfo = 415;
constexpr Tag TypeWrapped = 416;
constexpr Tag Type_ = 417;
constexpr Tag ResolvedOperator = 418;
constexpr Tag UnresolvedOperator = 419;
constexpr Tag Void = 420;
} // namespace expression

namespace operator_ {

namespace address {
constexpr Tag Equal = 600;
constexpr Tag Family = 601;
constexpr Tag Unequal = 602;
} // namespace address

namespace bitfield {
constexpr Tag HasMember = 700;
constexpr Tag Member = 701;
} // namespace bitfield

namespace bool_ {
constexpr Tag BitAnd = 800;
constexpr Tag BitOr = 801;
constexpr Tag BitXor = 802;
constexpr Tag Equal = 803;
constexpr Tag Unequal = 804;
} // namespace bool_

namespace bytes {
constexpr Tag At = 900;
constexpr Tag Decode = 901;
constexpr Tag Equal = 902;
constexpr Tag Find = 903;
constexpr Tag Greater = 904;
constexpr Tag GreaterEqual = 905;
constexpr Tag In = 906;
constexpr Tag Join = 907;
constexpr Tag Lower = 908;
constexpr Tag LowerCase = 909;
constexpr Tag LowerEqual = 910;
constexpr Tag Match = 911;
constexpr Tag Size = 912;
constexpr Tag Split = 913;
constexpr Tag Split1 = 914;
constexpr Tag StartsWith = 915;
constexpr Tag EndsWith = 916;
constexpr Tag Strip = 917;
constexpr Tag SubIterator = 918;
constexpr Tag SubIterators = 919;
constexpr Tag SubOffsets = 920;
constexpr Tag Sum = 921;
constexpr Tag SumAssignBytes = 922;
constexpr Tag SumAssignStreamView = 923;
constexpr Tag SumAssignUInt8 = 924;
constexpr Tag ToIntAscii = 925;
constexpr Tag ToIntBinary = 926;
constexpr Tag ToRealAscii = 927;
constexpr Tag ToTimeAscii = 928;
constexpr Tag ToTimeBinary = 929;
constexpr Tag ToUIntAscii = 930;
constexpr Tag ToUIntBinary = 931;
constexpr Tag Unequal = 932;
constexpr Tag UpperCase = 933;

namespace iterator {
constexpr Tag Deref = 1000;
constexpr Tag Difference = 1001;
constexpr Tag Equal = 1002;
constexpr Tag Greater = 1003;
constexpr Tag GreaterEqual = 1004;
constexpr Tag IncrPostfix = 1005;
constexpr Tag IncrPrefix = 1006;
constexpr Tag Lower = 1007;
constexpr Tag LowerEqual = 1008;
constexpr Tag Sum = 1009;
constexpr Tag SumAssign = 1010;
constexpr Tag Unequal = 1011;
} // namespace iterator
} // namespace bytes

namespace enum_ {
constexpr Tag CastToSignedInteger = 1100;
constexpr Tag CastToUnsignedInteger = 1101;
constexpr Tag CtorSigned = 1102;
constexpr Tag CtorUnsigned = 1103;
constexpr Tag Equal = 1104;
constexpr Tag HasLabel = 1105;
constexpr Tag Unequal = 1106;
} // namespace enum_

namespace error {
constexpr Tag Ctor = 1200;
constexpr Tag Description = 1201;
constexpr Tag Equal = 2702;
constexpr Tag Unequal = 2703;
} // namespace error

namespace exception {
constexpr Tag Ctor = 1300;
constexpr Tag Description = 1301;
} // namespace exception

namespace function {
constexpr Tag Call = 1400;
}

namespace generic {
constexpr Tag Begin = 1500;
constexpr Tag CastedCoercion = 1501;
constexpr Tag End = 1502;
constexpr Tag New = 1503;
constexpr Tag Pack = 1504;
constexpr Tag Unpack = 1505;
} // namespace generic

namespace interval {
constexpr Tag CtorRealSecs = 1600;
constexpr Tag CtorSignedIntegerNs = 1601;
constexpr Tag CtorSignedIntegerSecs = 1602;
constexpr Tag CtorUnsignedIntegerNs = 1603;
constexpr Tag CtorUnsignedIntegerSecs = 1604;
constexpr Tag Difference = 1605;
constexpr Tag Equal = 1606;
constexpr Tag Greater = 1607;
constexpr Tag GreaterEqual = 1608;
constexpr Tag Lower = 1609;
constexpr Tag LowerEqual = 1610;
constexpr Tag MultipleReal = 1611;
constexpr Tag MultipleUnsignedInteger = 1612;
constexpr Tag Nanoseconds = 1613;
constexpr Tag Seconds = 1614;
constexpr Tag Sum = 1615;
constexpr Tag Unequal = 1616;
} // namespace interval

namespace list {
constexpr Tag Equal = 1700;
constexpr Tag Size = 1701;
constexpr Tag Unequal = 1702;

namespace iterator {
constexpr Tag Deref = 1800;
constexpr Tag Equal = 1801;
constexpr Tag IncrPostfix = 1802;
constexpr Tag IncrPrefix = 1803;
constexpr Tag Unequal = 1804;
} // namespace iterator
} // namespace list

namespace map {
constexpr Tag Clear = 1900;
constexpr Tag Delete = 1901;
constexpr Tag Equal = 1902;
constexpr Tag Get = 1903;
constexpr Tag In = 1904;
constexpr Tag IndexAssign = 1905;
constexpr Tag IndexConst = 1906;
constexpr Tag IndexNonConst = 1907;
constexpr Tag Size = 1908;
constexpr Tag Unequal = 1909;
constexpr Tag GetOptional = 1910;

namespace iterator {
constexpr Tag Deref = 2000;
constexpr Tag Equal = 2001;
constexpr Tag IncrPostfix = 2002;
constexpr Tag IncrPrefix = 2003;
constexpr Tag Unequal = 2004;
} // namespace iterator
} // namespace map

namespace network {
constexpr Tag Equal = 2100;
constexpr Tag Family = 2101;
constexpr Tag In = 2102;
constexpr Tag Length = 2103;
constexpr Tag Prefix = 2104;
constexpr Tag Unequal = 2105;
} // namespace network

namespace optional {
constexpr Tag Deref = 2200;
}

namespace port {
constexpr Tag Ctor = 2300;
constexpr Tag Equal = 2301;
constexpr Tag Protocol = 2302;
constexpr Tag Unequal = 2303;
} // namespace port

namespace real {
constexpr Tag CastToInterval = 2400;
constexpr Tag CastToSignedInteger = 2401;
constexpr Tag CastToTime = 2402;
constexpr Tag CastToUnsignedInteger = 2403;
constexpr Tag Difference = 2404;
constexpr Tag DifferenceAssign = 2405;
constexpr Tag Division = 2406;
constexpr Tag DivisionAssign = 2407;
constexpr Tag Equal = 2408;
constexpr Tag Greater = 2409;
constexpr Tag GreaterEqual = 2410;
constexpr Tag Lower = 2411;
constexpr Tag LowerEqual = 2412;
constexpr Tag Modulo = 2413;
constexpr Tag Multiple = 2414;
constexpr Tag MultipleAssign = 2415;
constexpr Tag Power = 2416;
constexpr Tag SignNeg = 2417;
constexpr Tag Sum = 2418;
constexpr Tag SumAssign = 2419;
constexpr Tag Unequal = 2420;
} // namespace real

namespace regexp {
constexpr Tag Find = 2500;
constexpr Tag Match = 2501;
constexpr Tag MatchGroups = 2502;
constexpr Tag TokenMatcher = 2503;
} // namespace regexp

namespace regexp_match_state {
constexpr Tag AdvanceBytes = 2600;
constexpr Tag AdvanceView = 2601;
} // namespace regexp_match_state

namespace result {
constexpr Tag Deref = 2700;
constexpr Tag Error = 2701;
} // namespace result

namespace set {
constexpr Tag Add = 2800;
constexpr Tag Clear = 2801;
constexpr Tag Delete = 2802;
constexpr Tag Equal = 2803;
constexpr Tag In = 2804;
constexpr Tag Size = 2805;
constexpr Tag Unequal = 2806;

namespace iterator {
constexpr Tag Deref = 2900;
constexpr Tag Equal = 2901;
constexpr Tag IncrPostfix = 2902;
constexpr Tag IncrPrefix = 2903;
constexpr Tag Unequal = 2904;
} // namespace iterator
} // namespace set

namespace signed_integer {
constexpr Tag CastToBool = 3000;
constexpr Tag CastToEnum = 3001;
constexpr Tag CastToInterval = 3002;
constexpr Tag CastToReal = 3003;
constexpr Tag CastToSigned = 3004;
constexpr Tag CastToUnsigned = 3005;
constexpr Tag CtorSigned16 = 3006;
constexpr Tag CtorSigned32 = 3007;
constexpr Tag CtorSigned64 = 3008;
constexpr Tag CtorSigned8 = 3009;
constexpr Tag CtorUnsigned16 = 3010;
constexpr Tag CtorUnsigned32 = 3011;
constexpr Tag CtorUnsigned64 = 3012;
constexpr Tag CtorUnsigned8 = 3013;
constexpr Tag DecrPostfix = 3014;
constexpr Tag DecrPrefix = 3015;
constexpr Tag Difference = 3016;
constexpr Tag DifferenceAssign = 3017;
constexpr Tag Division = 3018;
constexpr Tag DivisionAssign = 3019;
constexpr Tag Equal = 3020;
constexpr Tag Greater = 3021;
constexpr Tag GreaterEqual = 3022;
constexpr Tag IncrPostfix = 3023;
constexpr Tag IncrPrefix = 3024;
constexpr Tag Lower = 3025;
constexpr Tag LowerEqual = 3026;
constexpr Tag Modulo = 3027;
constexpr Tag Multiple = 3028;
constexpr Tag MultipleAssign = 3029;
constexpr Tag Power = 3030;
constexpr Tag SignNeg = 3031;
constexpr Tag Sum = 3032;
constexpr Tag SumAssign = 3033;
constexpr Tag Unequal = 3034;
} // namespace signed_integer

namespace stream {
constexpr Tag At = 3100;
constexpr Tag Ctor = 3101;
constexpr Tag Freeze = 3102;
constexpr Tag IsFrozen = 3103;
constexpr Tag Size = 3104;
constexpr Tag Statistics = 3105;
constexpr Tag SumAssignBytes = 3106;
constexpr Tag SumAssignView = 3107;
constexpr Tag Trim = 3108;
constexpr Tag Unequal = 3109;
constexpr Tag Unfreeze = 3110;

namespace iterator {
constexpr Tag Deref = 3200;
constexpr Tag Difference = 3201;
constexpr Tag Equal = 3202;
constexpr Tag Greater = 3203;
constexpr Tag GreaterEqual = 3204;
constexpr Tag IncrPostfix = 3205;
constexpr Tag IncrPrefix = 3206;
constexpr Tag IsFrozen = 3207;
constexpr Tag Lower = 3208;
constexpr Tag LowerEqual = 3209;
constexpr Tag Offset = 3210;
constexpr Tag Sum = 3211;
constexpr Tag SumAssign = 3212;
constexpr Tag Unequal = 3213;
} // namespace iterator

namespace view {
constexpr Tag AdvanceBy = 3300;
constexpr Tag AdvanceTo = 3301;
constexpr Tag AdvanceToNextData = 3302;
constexpr Tag At = 3303;
constexpr Tag EqualBytes = 3304;
constexpr Tag EqualView = 3305;
constexpr Tag Find = 3306;
constexpr Tag InBytes = 3307;
constexpr Tag InView = 3308;
constexpr Tag Limit = 3309;
constexpr Tag Offset = 3310;
constexpr Tag Size = 3311;
constexpr Tag StartsWith = 3312;
constexpr Tag SubIterator = 3313;
constexpr Tag SubIterators = 3314;
constexpr Tag SubOffsets = 3315;
constexpr Tag UnequalBytes = 3316;
constexpr Tag UnequalView = 3317;
} // namespace view

} // namespace stream

namespace string {
constexpr Tag Encode = 3400;
constexpr Tag Equal = 3401;
constexpr Tag Modulo = 3402;
constexpr Tag Size = 3403;
constexpr Tag Sum = 3404;
constexpr Tag SumAssign = 3405;
constexpr Tag Unequal = 3406;
constexpr Tag Split = 3407;
constexpr Tag Split1 = 3408;
constexpr Tag StartsWith = 3409;
constexpr Tag EndsWith = 3410;
constexpr Tag LowerCase = 3411;
constexpr Tag UpperCase = 3412;
} // namespace string

namespace strong_reference {
constexpr Tag Deref = 3500;
constexpr Tag Equal = 3501;
constexpr Tag Unequal = 3502;
} // namespace strong_reference

namespace struct_ {
constexpr Tag HasMember = 3600;
constexpr Tag MemberCall = 3601;
constexpr Tag MemberConst = 3602;
constexpr Tag MemberNonConst = 3603;
constexpr Tag TryMember = 3604;
constexpr Tag Unset = 3605;
} // namespace struct_

namespace time {
constexpr Tag CtorRealSecs = 3700;
constexpr Tag CtorSignedIntegerNs = 3701;
constexpr Tag CtorSignedIntegerSecs = 3702;
constexpr Tag CtorUnsignedIntegerNs = 3703;
constexpr Tag CtorUnsignedIntegerSecs = 3704;
constexpr Tag DifferenceInterval = 3705;
constexpr Tag DifferenceTime = 3706;
constexpr Tag Equal = 3707;
constexpr Tag Greater = 3708;
constexpr Tag GreaterEqual = 3709;
constexpr Tag Lower = 3710;
constexpr Tag LowerEqual = 3711;
constexpr Tag Nanoseconds = 3712;
constexpr Tag Seconds = 3713;
constexpr Tag SumInterval = 3714;
constexpr Tag Unequal = 3715;
} // namespace time

namespace tuple {
constexpr Tag CustomAssign = 3800;
constexpr Tag Equal = 3801;
constexpr Tag Index = 3802;
constexpr Tag Member = 3803;
constexpr Tag Unequal = 3804;
} // namespace tuple

namespace union_ {
constexpr Tag Equal = 3900;
constexpr Tag HasMember = 3901;
constexpr Tag MemberConst = 3902;
constexpr Tag MemberNonConst = 3903;
constexpr Tag Unequal = 3904;
} // namespace union_

namespace unsigned_integer {
constexpr Tag BitAnd = 4000;
constexpr Tag BitOr = 4001;
constexpr Tag BitXor = 4002;
constexpr Tag CastToBool = 4003;
constexpr Tag CastToEnum = 4004;
constexpr Tag CastToInterval = 4005;
constexpr Tag CastToReal = 4006;
constexpr Tag CastToSigned = 4007;
constexpr Tag CastToTime = 4008;
constexpr Tag CastToUnsigned = 4009;
constexpr Tag CtorSigned16 = 4010;
constexpr Tag CtorSigned32 = 4011;
constexpr Tag CtorSigned64 = 4012;
constexpr Tag CtorSigned8 = 4013;
constexpr Tag CtorUnsigned16 = 4014;
constexpr Tag CtorUnsigned32 = 4015;
constexpr Tag CtorUnsigned64 = 4016;
constexpr Tag CtorUnsigned8 = 4017;
constexpr Tag DecrPostfix = 4018;
constexpr Tag DecrPrefix = 4019;
constexpr Tag Difference = 4020;
constexpr Tag DifferenceAssign = 4021;
constexpr Tag Division = 4022;
constexpr Tag DivisionAssign = 4023;
constexpr Tag Equal = 4024;
constexpr Tag Greater = 4025;
constexpr Tag GreaterEqual = 4026;
constexpr Tag IncrPostfix = 4027;
constexpr Tag IncrPrefix = 4028;
constexpr Tag Lower = 4029;
constexpr Tag LowerEqual = 4030;
constexpr Tag Modulo = 4031;
constexpr Tag Multiple = 4032;
constexpr Tag MultipleAssign = 4033;
constexpr Tag Negate = 4034;
constexpr Tag Power = 4035;
constexpr Tag ShiftLeft = 4036;
constexpr Tag ShiftRight = 4037;
constexpr Tag SignNeg = 4038;
constexpr Tag Sum = 4039;
constexpr Tag SumAssign = 4040;
constexpr Tag Unequal = 4041;
} // namespace unsigned_integer

namespace value_reference {
constexpr Tag Deref = 4100;
constexpr Tag Equal = 4101;
constexpr Tag Unequal = 4102;
} // namespace value_reference

namespace vector {
constexpr Tag Assign = 4200;
constexpr Tag At = 4201;
constexpr Tag Back = 4202;
constexpr Tag Equal = 4203;
constexpr Tag Front = 4204;
constexpr Tag IndexConst = 4205;
constexpr Tag IndexNonConst = 4206;
constexpr Tag PopBack = 4207;
constexpr Tag PushBack = 4208;
constexpr Tag Reserve = 4209;
constexpr Tag Resize = 4210;
constexpr Tag Size = 4211;
constexpr Tag SubEnd = 4212;
constexpr Tag SubRange = 4213;
constexpr Tag Sum = 4214;
constexpr Tag SumAssign = 4215;
constexpr Tag Unequal = 4216;

namespace iterator {
constexpr Tag Deref = 4300;
constexpr Tag Equal = 4301;
constexpr Tag IncrPostfix = 4302;
constexpr Tag IncrPrefix = 4303;
constexpr Tag Unequal = 4304;
} // namespace iterator
} // namespace vector

namespace weak_reference {
constexpr Tag Deref = 4400;
constexpr Tag Equal = 4401;
constexpr Tag Unequal = 4402;
} // namespace weak_reference

} // namespace operator_

namespace statement {
constexpr Tag Assert = 4500;
constexpr Tag Block = 4501;
constexpr Tag Break = 4502;
constexpr Tag Comment = 4503;
constexpr Tag Continue = 4504;
constexpr Tag Declaration = 4505;
constexpr Tag Expression = 4506;
constexpr Tag For = 4507;
constexpr Tag If = 4508;
constexpr Tag Return = 4509;
constexpr Tag SetLocation = 4510;
constexpr Tag Switch = 4511;
constexpr Tag Throw = 4512;
constexpr Tag Try = 4513;
constexpr Tag While = 4514;
constexpr Tag Yield = 4515;
} // namespace statement

namespace type {
constexpr Tag Address = 4600;
constexpr Tag Any = 4601;
constexpr Tag Auto = 4602;
constexpr Tag Bitfield = 4603;
constexpr Tag Bool = 4604;
constexpr Tag Bytes = 4605;
constexpr Tag DocOnly = 4606;
constexpr Tag Enum = 4607;
constexpr Tag Error = 4608;
constexpr Tag Exception = 4609;
constexpr Tag Function = 4610;
constexpr Tag Interval = 4611;
constexpr Tag Library = 4612;
constexpr Tag List = 4613;
constexpr Tag Map = 4614;
constexpr Tag Member = 4615;
constexpr Tag Name = 4616;
constexpr Tag Network = 4617;
constexpr Tag Null = 4618;
constexpr Tag OperandList = 4619;
constexpr Tag Optional = 4620;
constexpr Tag Port = 4621;
constexpr Tag Real = 4622;
constexpr Tag RegExp = 4623;
constexpr Tag Result = 4624;
constexpr Tag Set = 4625;
constexpr Tag SignedInteger = 4626;
constexpr Tag Stream = 4627;
constexpr Tag String = 4628;
constexpr Tag StrongReference = 4629;
constexpr Tag Struct = 4630;
constexpr Tag Time = 4631;
constexpr Tag Tuple = 4632;
constexpr Tag Type_ = 4633;
constexpr Tag Union = 4634;
constexpr Tag Unknown = 4635;
constexpr Tag UnsignedInteger = 4636;
constexpr Tag ValueReference = 4637;
constexpr Tag Vector = 4638;
constexpr Tag Void = 4639;
constexpr Tag WeakReference = 4640;

namespace bytes {
constexpr Tag Iterator = 4700;
}
namespace list {
constexpr Tag Iterator = 4800;
}
namespace map {
constexpr Tag Iterator = 4900;
}
namespace set {
constexpr Tag Iterator = 5000;
}
namespace stream {
constexpr Tag Iterator = 5100;
}
namespace stream {
constexpr Tag View = 5200;
}
namespace vector {
constexpr Tag Iterator = 5300;
}
} // namespace type

} // namespace tag

} // namespace hilti::node
