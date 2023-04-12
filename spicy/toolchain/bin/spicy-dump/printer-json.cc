// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "printer-json.h"

#include <string>

#include <hilti/rt/json.h>
#include <hilti/rt/libhilti.h>

#include <spicy/rt/util.h>

using namespace hilti::rt;

using json = nlohmann::json;

void JSONPrinter::print(const type_info::Value& v) { out() << convert(v) << std::endl; }

nlohmann::json JSONPrinter::convert(const hilti::rt::type_info::Value& v) {
    const auto& type = v.type();

    switch ( v.type().tag ) {
        case TypeInfo::Undefined: throw RuntimeError("unhandled type");
        case TypeInfo::Address: return type.address->get(v);
        case TypeInfo::Any: return "<any>";
        case TypeInfo::Bool: return type.bool_->get(v);
        case TypeInfo::Bytes: return to_string_for_print(type.bytes->get(v));
        case TypeInfo::BytesIterator: return to_string(type.bytes_iterator->get(v));
        case TypeInfo::Enum: return type.enum_->get(v).name;
        case TypeInfo::Error: return to_string(type.error->get(v));
        case TypeInfo::Exception: return to_string(type.exception->get(v));
        case TypeInfo::Function: return "<function>";
        case TypeInfo::Interval: return type.interval->get(v).seconds();
        case TypeInfo::Library: return "<library value>";
        case TypeInfo::Map: {
            auto j = json::array();

            for ( auto [key, value] : type.map->iterate(v) )
                j.push_back({convert(key), convert(value)});
            return j;
        }
        case TypeInfo::MapIterator: {
            auto [key, value] = type.map_iterator->value(v);
            return json::array({convert(key), convert(value)});
        }
        case TypeInfo::Network: {
            Network n = type.network->get(v);
            return json::object({{"prefix", n.prefix()}, {"length", n.length()}});
        }
        case TypeInfo::Optional: {
            auto y = type.optional->value(v);
            return y ? convert(y) : json();
        }
        case TypeInfo::Port: {
            Port p = type.port->get(v);
            return json::object({{"port", p.port()}, {"protocol", to_string(p.protocol())}});
        }
        case TypeInfo::Real: return type.real->get(v);
        case TypeInfo::RegExp: return to_string(type.regexp->get(v));
        case TypeInfo::Result: {
            auto y = type.result->value(v);
            return y ? convert(y) : json();
        }
        case TypeInfo::Set: {
            auto j = json::array();

            for ( auto i : type.set->iterate(v) )
                j.push_back(convert(i));

            return j;
        }
        case TypeInfo::SetIterator: return convert(type.set_iterator->value(v));
        case TypeInfo::SignedInteger_int8: return type.signed_integer_int8->get(v);
        case TypeInfo::SignedInteger_int16: return type.signed_integer_int16->get(v);
        case TypeInfo::SignedInteger_int32: return type.signed_integer_int32->get(v);
        case TypeInfo::SignedInteger_int64: return type.signed_integer_int64->get(v);
        case TypeInfo::Stream: return to_string_for_print(type.stream->get(v));
        case TypeInfo::StreamIterator: return to_string_for_print(type.stream_iterator->get(v));
        case TypeInfo::StreamView: return to_string_for_print(type.stream_view->get(v));
        case TypeInfo::String: return type.string->get(v);
        case TypeInfo::StrongReference: {
            auto y = type.strong_reference->value(v);
            return y ? convert(y) : json();
        }
        case TypeInfo::Struct: {
            auto j = json::object();

            const auto* struct_ = type.struct_;

            for ( const auto& [f, y] : struct_->iterate(v) ) {
                if ( ! y )
                    // Field not set.
                    continue;

                j[f.name] = convert(y);
            }

            auto offsets = json::array();
            const auto& __offsets = spicy::rt::get_offsets_for_unit(*struct_, v);
            if ( _options.include_offsets && __offsets ) {
                for ( const auto&& [index, offset] : enumerate(*__offsets) ) {
                    auto o = json::object();

                    if ( offset ) {
                        o["start"] = std::get<0>(*offset).Ref();
                        if ( auto& end = std::get<1>(*offset) )
                            o["end"] = end->Ref();
                    }

                    offsets.push_back(std::move(o));
                }
                j["__offsets"] = offsets;
            }

            return j;
        }
        case TypeInfo::Time: return type.time->get(v).seconds();
        case TypeInfo::Tuple: {
            auto j = json::array();

            for ( const auto& i : type.tuple->iterate(v) )
                j.push_back(convert(i.second));

            return j;
        }
        case TypeInfo::Union: {
            auto y = type.union_->value(v);
            return y ? convert(y) : json();
        }
        case TypeInfo::UnsignedInteger_uint8: return type.unsigned_integer_uint8->get(v);
        case TypeInfo::UnsignedInteger_uint16: return type.unsigned_integer_uint16->get(v);
        case TypeInfo::UnsignedInteger_uint32: return type.unsigned_integer_uint32->get(v);
        case TypeInfo::UnsignedInteger_uint64: return type.unsigned_integer_uint64->get(v);
        case TypeInfo::ValueReference: {
            auto y = type.value_reference->value(v);
            return y ? convert(y) : json();
        }
        case TypeInfo::Vector: {
            auto j = json::array();

            for ( auto i : type.vector->iterate(v) )
                j.push_back(convert(i));

            return j;
        }
        case TypeInfo::VectorIterator: return convert(type.vector_iterator->value(v));
        case TypeInfo::Void: return "<void>";
        case TypeInfo::WeakReference: {
            auto y = type.weak_reference->value(v);
            return y ? convert(y) : json();
        }
    }

    throw RuntimeError("unhandled type");
}
