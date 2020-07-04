// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/libhilti.h>

#include "printer-json.h"

using namespace hilti::rt;

using json = nlohmann::json;

void JSONPrinter::print(const type_info::Value& v) { out() << convert(v) << std::endl; }

nlohmann::json JSONPrinter::convert(const hilti::rt::type_info::Value& v) {
    json j;

    std::visit(type_info::overload{[&](const hilti::rt::type_info::Address& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::Any& x) { j = "<any>"; },
                                   [&](const hilti::rt::type_info::Bool& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::Bytes& x) { j = to_string_for_print(x.get(v)); },
                                   [&](const hilti::rt::type_info::BytesIterator& x) { j = to_string(x.get(v)); },
                                   [&](const hilti::rt::type_info::Enum& x) { j = x.get(v).name; },
                                   [&](const hilti::rt::type_info::Error& x) { j = to_string(x.get(v)); },
                                   [&](const hilti::rt::type_info::Exception& x) { j = to_string(x.get(v)); },
                                   [&](const hilti::rt::type_info::Function& x) { j = "<function>"; },
                                   [&](const hilti::rt::type_info::Interval& x) { j = x.get(v).seconds(); },
                                   [&](const hilti::rt::type_info::Library& x) { j = "<library value>"; },
                                   [&](const hilti::rt::type_info::Map& x) {
                                       j = json::array();

                                       for ( auto [key, value] : x.iterate(v) )
                                           j.push_back({convert(key), convert(value)});
                                   },
                                   [&](const hilti::rt::type_info::MapIterator& x) {
                                       auto [key, value] = x.value(v);
                                       j = json::array({convert(key), convert(value)});
                                   },
                                   [&](const hilti::rt::type_info::Network& x) {
                                       Network n = x.get(v);
                                       j = json::object({{"prefix", n.prefix()}, {"length", n.length()}});
                                   },
                                   [&](const hilti::rt::type_info::Optional& x) {
                                       auto y = x.value(v);
                                       j = y ? convert(y) : json();
                                   },
                                   [&](const hilti::rt::type_info::Port& x) {
                                       Port p = x.get(v);
                                       j = json::object({{"port", p.port()}, {"protocol", to_string(p.protocol())}});
                                   },
                                   [&](const hilti::rt::type_info::Real& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::RegExp& x) { j = to_string(x.get(v)); },
                                   [&](const hilti::rt::type_info::Result& x) {
                                       auto y = x.value(v);
                                       j = y ? convert(y) : json();
                                   },
                                   [&](const hilti::rt::type_info::Set& x) {
                                       j = json::array();

                                       for ( auto i : x.iterate(v) )
                                           j.push_back(convert(i));
                                   },
                                   [&](const hilti::rt::type_info::SetIterator& x) { j = convert(x.value(v)); },
                                   [&](const hilti::rt::type_info::SignedInteger<int8_t>& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::SignedInteger<int16_t>& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::SignedInteger<int32_t>& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::SignedInteger<int64_t>& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::Stream& x) { j = to_string_for_print(x.get(v)); },
                                   [&](const hilti::rt::type_info::StreamIterator& x) {
                                       j = to_string_for_print(x.get(v));
                                   },
                                   [&](const hilti::rt::type_info::StreamView& x) {
                                       j = to_string_for_print(x.get(v));
                                   },
                                   [&](const hilti::rt::type_info::String& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::StrongReference& x) {
                                       auto y = x.value(v);
                                       j = y ? convert(y) : json();
                                   },
                                   [&](const hilti::rt::type_info::Struct& x) {
                                       j = json::object();

                                       for ( const auto& [f, y] : x.iterate(v) ) {
                                           if ( ! y )
                                               // Field not set.
                                               continue;

                                           j[f.name] = convert(y);
                                       }
                                   },
                                   [&](const hilti::rt::type_info::Time& x) { j = x.get(v).seconds(); },
                                   [&](const hilti::rt::type_info::Tuple& x) {
                                       j = json::array();

                                       for ( auto i : x.iterate(v) )
                                           j.push_back(convert(i.second));
                                   },
                                   [&](const hilti::rt::type_info::Union& x) {
                                       auto y = x.value(v);
                                       j = y ? convert(y) : json();
                                   },
                                   [&](const hilti::rt::type_info::UnsignedInteger<uint8_t>& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::UnsignedInteger<uint16_t>& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::UnsignedInteger<uint32_t>& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::UnsignedInteger<uint64_t>& x) { j = x.get(v); },
                                   [&](const hilti::rt::type_info::ValueReference& x) {
                                       auto y = x.value(v);
                                       j = y ? convert(y) : json();
                                   },
                                   [&](const hilti::rt::type_info::Vector& x) {
                                       j = json::array();

                                       for ( auto i : x.iterate(v) )
                                           j.push_back(convert(i));
                                   },
                                   [&](const hilti::rt::type_info::VectorIterator& x) { j = convert(x.value(v)); },
                                   [&](const hilti::rt::type_info::Void& x) { j = "<void>"; },
                                   [&](const hilti::rt::type_info::WeakReference& x) {
                                       auto y = x.value(v);
                                       j = y ? convert(y) : json();
                                   },
                                   [&](const auto& x) {
                                       std::cerr << hilti::rt::fmt("internal error: type %s not handled by JSON writer",
                                                                   v.type().display)
                                                 << std::endl;
                                       exit(1);
                                   }},
               v.type().aux_type_info);

    return j;
}
