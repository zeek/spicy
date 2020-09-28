// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <cinttypes>

#include <hilti/rt/type-info.h>

using namespace hilti::rt;

TypeInfo type_info::address = {std::nullopt, "address", type_info::Address()};
TypeInfo type_info::any = {std::nullopt, "any", type_info::Any()};
TypeInfo type_info::bool_ = {std::nullopt, "bool", type_info::Bool()};
TypeInfo type_info::bytes = {std::nullopt, "bytes", type_info::Bytes()};
TypeInfo type_info::bytes_iterator = {std::nullopt, "iterator<bytes>", type_info::BytesIterator()};
TypeInfo type_info::error = {std::nullopt, "error", type_info::Error()};
TypeInfo type_info::int16 = {std::nullopt, "int16", type_info::SignedInteger<int16_t>()};
TypeInfo type_info::int32 = {std::nullopt, "int32", type_info::SignedInteger<int32_t>()};
TypeInfo type_info::int64 = {std::nullopt, "int64", type_info::SignedInteger<int64_t>()};
TypeInfo type_info::int8 = {std::nullopt, "int8", type_info::SignedInteger<int8_t>()};
TypeInfo type_info::interval = {std::nullopt, "interval", type_info::Interval()};
TypeInfo type_info::network = {std::nullopt, "network", type_info::Network()};
TypeInfo type_info::port = {std::nullopt, "port", type_info::Port()};
TypeInfo type_info::real = {std::nullopt, "real", type_info::Real()};
TypeInfo type_info::regexp = {std::nullopt, "regexp", type_info::RegExp()};
TypeInfo type_info::stream = {std::nullopt, "stream", type_info::Stream()};
TypeInfo type_info::stream_iterator = {std::nullopt, "iterator<stream>", type_info::StreamIterator()};
TypeInfo type_info::stream_view = {std::nullopt, "view<stream>", type_info::StreamView()};
TypeInfo type_info::string = {std::nullopt, "string", type_info::String()};
TypeInfo type_info::time = {std::nullopt, "time", type_info::Time()};
TypeInfo type_info::uint16 = {std::nullopt, "uint16", type_info::UnsignedInteger<uint16_t>()};
TypeInfo type_info::uint32 = {std::nullopt, "uint32", type_info::UnsignedInteger<uint32_t>()};
TypeInfo type_info::uint64 = {std::nullopt, "uint64", type_info::UnsignedInteger<uint64_t>()};
TypeInfo type_info::uint8 = {std::nullopt, "uint8", type_info::UnsignedInteger<uint8_t>()};
TypeInfo type_info::void_ = {std::nullopt, "void", type_info::Void()};
