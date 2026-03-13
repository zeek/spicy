// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cinttypes>

#include <hilti/rt/type-info.h>
#include <hilti/rt/types/all.h>

using namespace hilti::rt;

// Helper to create a `to_string()` callback for a given type.
#define TO_STRING(type) [](const void* self) { return hilti::rt::to_string(*reinterpret_cast<const type*>(self)); }

// Helper to create a `to_string()` callback that just returns a constant string.
#define TO_STRING_CONST(str) [](const void* self) { return std::string(str); }

const TypeInfo hilti::rt::type_info::address{std::nullopt, "address", TO_STRING(hilti::rt::Address),
                                             new hilti::rt::type_info::Address()};
const TypeInfo hilti::rt::type_info::any{std::nullopt, "any", TO_STRING_CONST("any"), new hilti::rt::type_info::Any()};
const TypeInfo hilti::rt::type_info::bool_{std::nullopt, "bool", TO_STRING(hilti::rt::Bool),
                                           new hilti::rt::type_info::Bool()};
const TypeInfo hilti::rt::type_info::bytes{std::nullopt, "bytes", TO_STRING(hilti::rt::Bytes),
                                           new hilti::rt::type_info::Bytes()};
const TypeInfo hilti::rt::type_info::bytes_iterator{std::nullopt, "iterator<bytes>",
                                                    TO_STRING(hilti::rt::bytes::SafeIterator),
                                                    new hilti::rt::type_info::BytesIterator()};
const TypeInfo hilti::rt::type_info::error{std::nullopt, "error", TO_STRING(hilti::rt::result::Error),
                                           new hilti::rt::type_info::Error()};
const TypeInfo hilti::rt::type_info::int16{std::nullopt, "int16", TO_STRING(hilti::rt::integer::safe<int16_t>),
                                           new hilti::rt::type_info::SignedInteger<int16_t>()};
const TypeInfo hilti::rt::type_info::int32{std::nullopt, "int32", TO_STRING(hilti::rt::integer::safe<int32_t>),
                                           new hilti::rt::type_info::SignedInteger<int32_t>()};
const TypeInfo hilti::rt::type_info::int64{std::nullopt, "int64", TO_STRING(hilti::rt::integer::safe<int64_t>),
                                           new hilti::rt::type_info::SignedInteger<int64_t>()};
const TypeInfo hilti::rt::type_info::int8{std::nullopt, "int8", TO_STRING(hilti::rt::integer::safe<int8_t>),
                                          new hilti::rt::type_info::SignedInteger<int8_t>()};
const TypeInfo hilti::rt::type_info::interval{std::nullopt, "interval", TO_STRING(hilti::rt::Interval),
                                              new hilti::rt::type_info::Interval()};
const TypeInfo hilti::rt::type_info::network{std::nullopt, "network", TO_STRING(hilti::rt::Network),
                                             new hilti::rt::type_info::Network()};
const TypeInfo hilti::rt::type_info::null{std::nullopt, "null", TO_STRING(hilti::rt::Null),
                                          new hilti::rt::type_info::Null()};
const TypeInfo hilti::rt::type_info::port{std::nullopt, "port", TO_STRING(hilti::rt::Port),
                                          new hilti::rt::type_info::Port()};
const TypeInfo hilti::rt::type_info::real{std::nullopt, "real", TO_STRING(double), new hilti::rt::type_info::Real()};
const TypeInfo hilti::rt::type_info::regexp{std::nullopt, "regexp", TO_STRING(hilti::rt::RegExp),
                                            new hilti::rt::type_info::RegExp()};
const TypeInfo hilti::rt::type_info::stream{std::nullopt, "stream", TO_STRING(hilti::rt::Stream),
                                            new hilti::rt::type_info::Stream()};
const TypeInfo hilti::rt::type_info::stream_iterator{std::nullopt, "iterator<stream>",
                                                     TO_STRING(hilti::rt::stream::SafeConstIterator),
                                                     new hilti::rt::type_info::StreamIterator()};
const TypeInfo hilti::rt::type_info::stream_view{std::nullopt, "view<stream>", TO_STRING(hilti::rt::stream::View),
                                                 new hilti::rt::type_info::StreamView()};
const TypeInfo hilti::rt::type_info::string{std::nullopt, "string", TO_STRING(std::string),
                                            new hilti::rt::type_info::String()};
const TypeInfo hilti::rt::type_info::time{std::nullopt, "time", TO_STRING(hilti::rt::Time),
                                          new hilti::rt::type_info::Time()};
const TypeInfo hilti::rt::type_info::uint8{std::nullopt, "uint8", TO_STRING(hilti::rt::integer::safe<uint8_t>),
                                           new hilti::rt::type_info::UnsignedInteger<uint8_t>()};
const TypeInfo hilti::rt::type_info::uint16{std::nullopt, "uint16", TO_STRING(hilti::rt::integer::safe<uint16_t>),
                                            new hilti::rt::type_info::UnsignedInteger<uint16_t>()};
const TypeInfo hilti::rt::type_info::uint32{std::nullopt, "uint32", TO_STRING(hilti::rt::integer::safe<uint32_t>),
                                            new hilti::rt::type_info::UnsignedInteger<uint32_t>()};
const TypeInfo hilti::rt::type_info::uint64{std::nullopt, "uint64", TO_STRING(hilti::rt::integer::safe<uint64_t>),
                                            new hilti::rt::type_info::UnsignedInteger<uint64_t>()};
const TypeInfo hilti::rt::type_info::void_{std::nullopt, "void", TO_STRING_CONST("void"),
                                           new hilti::rt::type_info::Void()};


std::vector<std::pair<const hilti::rt::type_info::bitfield::Bits&, hilti::rt::type_info::Value>> hilti::rt::type_info::
    Bitfield::iterate(const hilti::rt::type_info::Value& v) const {
    auto elements = _tuple_ti->tuple->iterate(v);

    std::vector<std::pair<const bitfield::Bits&, Value>> values;
    values.reserve(std::min(bits().size(), elements.size()));

    auto b = bits().begin();
    auto e = elements.begin();
    for ( ; b != bits().end() && e != elements.end(); ++b, ++e )
        values.emplace_back(*b, e->second);

    return values;
}
