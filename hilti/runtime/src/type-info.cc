// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cinttypes>

#include <hilti/rt/type-info.h>
#include <hilti/rt/types/all.h>

using namespace hilti::rt;

// Helper to create a `to_string()` callback for a given type.
#define TO_STRING(type) [](const void* self) { return hilti::rt::to_string(*reinterpret_cast<const type*>(self)); }

// Helper to create a `to_string()` callback that just returns a constant string.
#define TO_STRING_CONST(str) [](const void* self) { return std::string(str); }

const TypeInfo type_info::address{std::nullopt, "address", TO_STRING(hilti::rt::Address), new type_info::Address()};
const TypeInfo type_info::any{std::nullopt, "any", TO_STRING_CONST("any"), new type_info::Any()};
const TypeInfo type_info::bool_{std::nullopt, "bool", TO_STRING(hilti::rt::Bool), new type_info::Bool()};
const TypeInfo type_info::bytes{std::nullopt, "bytes", TO_STRING(hilti::rt::Bytes), new type_info::Bytes()};
const TypeInfo type_info::bytes_iterator{std::nullopt, "iterator<bytes>", TO_STRING(hilti::rt::bytes::SafeIterator),
                                         new type_info::BytesIterator()};
const TypeInfo type_info::error{std::nullopt, "error", TO_STRING(hilti::rt::result::Error), new type_info::Error()};
const TypeInfo type_info::int16{std::nullopt, "int16", TO_STRING(hilti::rt::integer::safe<int16_t>),
                                new type_info::SignedInteger<int16_t>()};
const TypeInfo type_info::int32{std::nullopt, "int32", TO_STRING(hilti::rt::integer::safe<int32_t>),
                                new type_info::SignedInteger<int32_t>()};
const TypeInfo type_info::int64{std::nullopt, "int64", TO_STRING(hilti::rt::integer::safe<int64_t>),
                                new type_info::SignedInteger<int64_t>()};
const TypeInfo type_info::int8{std::nullopt, "int8", TO_STRING(hilti::rt::integer::safe<int8_t>),
                               new type_info::SignedInteger<int8_t>()};
const TypeInfo type_info::interval{std::nullopt, "interval", TO_STRING(hilti::rt::Interval), new type_info::Interval()};
const TypeInfo type_info::network{std::nullopt, "network", TO_STRING(hilti::rt::Network), new type_info::Network()};
const TypeInfo type_info::null{std::nullopt, "null", TO_STRING(hilti::rt::Null), new type_info::Null()};
const TypeInfo type_info::port{std::nullopt, "port", TO_STRING(hilti::rt::Port), new type_info::Port()};
const TypeInfo type_info::real{std::nullopt, "real", TO_STRING(double), new type_info::Real()};
const TypeInfo type_info::regexp{std::nullopt, "regexp", TO_STRING(hilti::rt::RegExp), new type_info::RegExp()};
const TypeInfo type_info::stream{std::nullopt, "stream", TO_STRING(hilti::rt::Stream), new type_info::Stream()};
const TypeInfo type_info::stream_iterator{std::nullopt, "iterator<stream>",
                                          TO_STRING(hilti::rt::stream::SafeConstIterator),
                                          new type_info::StreamIterator()};
const TypeInfo type_info::stream_view{std::nullopt, "view<stream>", TO_STRING(hilti::rt::stream::View),
                                      new type_info::StreamView()};
const TypeInfo type_info::string{std::nullopt, "string", TO_STRING(std::string), new type_info::String()};
const TypeInfo type_info::time{std::nullopt, "time", TO_STRING(hilti::rt::Time), new type_info::Time()};
const TypeInfo type_info::uint8{std::nullopt, "uint8", TO_STRING(hilti::rt::integer::safe<uint8_t>),
                                new type_info::UnsignedInteger<uint8_t>()};
const TypeInfo type_info::uint16{std::nullopt, "uint16", TO_STRING(hilti::rt::integer::safe<uint16_t>),
                                 new type_info::UnsignedInteger<uint16_t>()};
const TypeInfo type_info::uint32{std::nullopt, "uint32", TO_STRING(hilti::rt::integer::safe<uint32_t>),
                                 new type_info::UnsignedInteger<uint32_t>()};
const TypeInfo type_info::uint64{std::nullopt, "uint64", TO_STRING(hilti::rt::integer::safe<uint64_t>),
                                 new type_info::UnsignedInteger<uint64_t>()};
const TypeInfo type_info::void_{std::nullopt, "void", TO_STRING_CONST("void"), new type_info::Void()};


std::vector<std::pair<const type_info::bitfield::Bits&, type_info::Value>> type_info::Bitfield::iterate(
    const type_info::Value& v) const {
    auto elements = _tuple_ti->tuple->iterate(v);

    std::vector<std::pair<const bitfield::Bits&, Value>> values;
    values.reserve(std::min(bits().size(), elements.size()));

    auto b = bits().begin();
    auto e = elements.begin();
    for ( ; b != bits().end() && e != elements.end(); ++b, ++e )
        values.emplace_back(*b, e->second);

    return values;
}
