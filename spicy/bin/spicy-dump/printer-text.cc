// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/libhilti.h>

#include "printer-text.h"

using namespace hilti::rt;

void TextPrinter::print(const type_info::Value& v) {
    std::visit(type_info::overload{[&](const hilti::rt::type_info::Address& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::Any& x) { out() << "<any>"; },
                                   [&](const hilti::rt::type_info::Bool& x) { out() << (x.get(v) ? "True" : "False"); },
                                   [&](const hilti::rt::type_info::Bytes& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::BytesIterator& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::Enum& x) { out() << x.get(v).name; },
                                   [&](const hilti::rt::type_info::Error& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::Exception& x) {
                                       out() << "<exception: " << x.get(v).description() << ">";
                                   },
                                   [&](const hilti::rt::type_info::Function& x) { out() << "<function>"; },
                                   [&](const hilti::rt::type_info::Interval& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::Library& x) { out() << "<library value>"; },
                                   [&](const hilti::rt::type_info::Map& x) {
                                       auto first = true;

                                       out() << '{';

                                       for ( auto i : x.iterate(v) ) {
                                           if ( ! first )
                                               out() << ", ";
                                           else
                                               first = false;

                                           auto [key, value] = type_info::Map::getKeyValue(i);
                                           print(key);
                                           out() << ": ";
                                           print(value);
                                       }

                                       out() << '}';
                                   },
                                   [&](const hilti::rt::type_info::MapIterator& x) {
                                       auto [key, value] = type_info::Map::getKeyValue(x.value(v));
                                       print(key);
                                       out() << ": ";
                                       print(value);
                                   },
                                   [&](const hilti::rt::type_info::Network& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::Optional& x) {
                                       if ( auto y = x.value(v) )
                                           print(y);
                                       else
                                           out() << "(not set)";
                                   },
                                   [&](const hilti::rt::type_info::Port& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::Real& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::RegExp& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::Result& x) {
                                       if ( auto y = x.value(v) )
                                           print(y);
                                       else
                                           out() << "<error>";
                                   },
                                   [&](const hilti::rt::type_info::Set& x) {
                                       auto first = true;

                                       out() << '{';

                                       for ( auto i : x.iterate(v) ) {
                                           if ( ! first )
                                               out() << ", ";
                                           else
                                               first = false;

                                           print(i);
                                       }

                                       out() << '}';
                                   },
                                   [&](const hilti::rt::type_info::SetIterator& x) { print(x.value(v)); },
                                   [&](const hilti::rt::type_info::SignedInteger<int8_t>& x) {
                                       out() << static_cast<int16_t>(x.get(v));
                                   },
                                   [&](const hilti::rt::type_info::SignedInteger<int16_t>& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::SignedInteger<int32_t>& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::SignedInteger<int64_t>& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::Stream& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::StreamIterator& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::StreamView& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::String& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::StrongReference& x) {
                                       if ( auto y = x.value(v) )
                                           print(x.value(v));
                                       else
                                           out() << "Null";
                                   },
                                   [&](const hilti::rt::type_info::Struct& x) {
                                       out() << v.type().display << " {";

                                       bool empty = true;
                                       indent([&]() {
                                           for ( const auto& [f, y] : x.iterate(v) ) {
                                               if ( ! y )
                                                   // Field not set.
                                                   continue;

                                               out() << '\n';
                                               outputIndent();
                                               out() << f.name << ": ";
                                               print(y);
                                               empty = false;
                                           }
                                       });

                                       if ( ! empty ) {
                                           out() << '\n';
                                           outputIndent();
                                       }

                                       out() << "}";
                                   },
                                   [&](const hilti::rt::type_info::Time& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::Tuple& x) {
                                       auto first = true;

                                       out() << '(';

                                       for ( auto i : x.iterate(v) ) {
                                           if ( ! first )
                                               out() << ", ";
                                           else
                                               first = false;

                                           if ( i.first.name.size() )
                                               out() << i.first.name << ": ";

                                           print(i.second);
                                       }

                                       out() << ')';
                                   },
                                   [&](const hilti::rt::type_info::Union& x) {
                                       if ( auto y = x.value(v) )
                                           print(x.value(v));
                                       else
                                           out() << "(not set)";
                                   },
                                   [&](const hilti::rt::type_info::UnsignedInteger<uint8_t>& x) {
                                       out() << static_cast<int16_t>(x.get(v));
                                   },
                                   [&](const hilti::rt::type_info::UnsignedInteger<uint16_t>& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::UnsignedInteger<uint32_t>& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::UnsignedInteger<uint64_t>& x) { out() << x.get(v); },
                                   [&](const hilti::rt::type_info::ValueReference& x) {
                                       if ( auto y = x.value(v) )
                                           print(x.value(v));
                                       else
                                           out() << "Null";
                                   },
                                   [&](const hilti::rt::type_info::Vector& x) {
                                       out() << "[";

                                       bool empty = true;
                                       indent([&]() {
                                           for ( auto i : x.iterate(v) ) {
                                               out() << "\n";
                                               outputIndent();
                                               print(i);
                                               empty = false;
                                           }
                                       });

                                       if ( ! empty ) {
                                           out() << '\n';
                                           outputIndent();
                                       }
                                       out() << "]";
                                   },
                                   [&](const hilti::rt::type_info::VectorIterator& x) { print(x.value(v)); },
                                   [&](const hilti::rt::type_info::Void& x) { out() << "<void>"; },
                                   [&](const hilti::rt::type_info::WeakReference& x) {
                                       if ( auto y = x.value(v) )
                                           print(x.value(v));
                                       else
                                           out() << "Null";
                                   },

                                   [&](const auto& x) {
                                       std::cerr << hilti::rt::fmt("internal error: type %s not handled by text writer",
                                                                   v.type().display)
                                                 << std::endl;
                                       exit(1);
                                   }},
               v.type().aux_type_info);
}
