// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "printer-text.h"

#include <hilti/rt/libhilti.h>

#include <spicy/rt/util.h>

using namespace hilti::rt;

void TextPrinter::print(const type_info::Value& v) {
    const auto& type = v.type();

    switch ( v.type().tag ) {
        case TypeInfo::Undefined: throw RuntimeError("unhandled type");
        case TypeInfo::Address: out() << type.address->get(v); break;
        case TypeInfo::Any: out() << "<any>"; break;
        case TypeInfo::Bool: out() << (type.bool_->get(v) ? "True" : "False"); break;
        case TypeInfo::Bytes: out() << to_string_for_print(type.bytes->get(v)); break;
        case TypeInfo::BytesIterator: out() << to_string(type.bytes_iterator->get(v)); break;
        case TypeInfo::Enum: out() << type.enum_->get(v).name; break;
        case TypeInfo::Error: out() << to_string(type.error->get(v)); break;
        case TypeInfo::Exception: out() << "<exception: " << type.exception->get(v).description() << '>'; break;
        case TypeInfo::Function: out() << "<function>"; break;
        case TypeInfo::Interval: out() << type.interval->get(v); break;
        case TypeInfo::Library: out() << "<library value>"; break;
        case TypeInfo::Map: {
            auto first = true;

            out() << '{';

            for ( auto [key, value] : type.map->iterate(v) ) {
                if ( ! first )
                    out() << ", ";
                else
                    first = false;

                print(key);
                out() << ": ";
                print(value);
            }

            out() << '}';
            break;
        }
        case TypeInfo::MapIterator: {
            auto [key, value] = type.map_iterator->value(v);
            print(key);
            out() << ": ";
            print(value);
            break;
        }
        case TypeInfo::Network: out() << type.network->get(v); break;
        case TypeInfo::Optional: {
            if ( auto y = type.optional->value(v) )
                print(y);
            else
                out() << "(not set)";
            break;
        }
        case TypeInfo::Port: out() << type.port->get(v); break;
        case TypeInfo::Real: out() << type.real->get(v); break;
        case TypeInfo::RegExp: out() << type.regexp->get(v); break;
        case TypeInfo::Result: {
            if ( auto y = type.result->value(v) )
                print(y);
            else
                out() << "<error>";
            break;
        }
        case TypeInfo::Set: {
            auto first = true;

            out() << '{';

            for ( auto i : type.set->iterate(v) ) {
                if ( ! first )
                    out() << ", ";
                else
                    first = false;

                print(i);
            }

            out() << '}';
            break;
        }
        case TypeInfo::SetIterator: print(type.set_iterator->value(v)); break;
        case TypeInfo::SignedInteger_int8: out() << static_cast<int16_t>(type.signed_integer_int8->get(v)); break;
        case TypeInfo::SignedInteger_int16: out() << type.signed_integer_int16->get(v); break;
        case TypeInfo::SignedInteger_int32: out() << type.signed_integer_int32->get(v); break;
        case TypeInfo::SignedInteger_int64: out() << type.signed_integer_int64->get(v); break;
        case TypeInfo::Stream: out() << type.stream->get(v); break;
        case TypeInfo::StreamIterator: out() << type.stream_iterator->get(v); break;
        case TypeInfo::StreamView: out() << type.stream_view->get(v); break;
        case TypeInfo::String: out() << type.string->get(v); break;
        case TypeInfo::StrongReference: {
            const auto* x = type.strong_reference;
            if ( auto y = x->value(v) )
                print(x->value(v));
            else
                out() << "Null";
            break;
        }
        case TypeInfo::Struct: {
            out() << v.type().display << " {";

            const auto* x = type.struct_;

            const auto& offsets = spicy::rt::get_offsets_for_unit(*x, v);

            bool empty = true;
            uint64_t index = 0;
            indent([&]() {
                for ( const auto& [f, y] : x->iterate(v) ) {
                    if ( y ) {
                        out() << '\n';
                        outputIndent();
                        out() << f.name << ": ";
                        print(y);

                        const auto& offset = offsets && offsets->size() > index ? offsets->at(index) : std::nullopt;

                        if ( _options.include_offsets && offset ) {
                            const auto& start = std::get<0>(*offset);
                            const auto& end = std::get<1>(*offset);

                            out() << " [" << start << ", ";

                            if ( end )
                                out() << *end;
                            else
                                out() << "-";
                            out() << "]";
                        }

                        empty = false;
                    }

                    ++index;
                }
            });

            if ( ! empty ) {
                out() << '\n';
                outputIndent();
            }

            out() << "}";
            break;
        }
        case TypeInfo::Time: out() << type.time->get(v); break;
        case TypeInfo::Tuple: {
            auto first = true;

            out() << '(';

            for ( const auto& i : type.tuple->iterate(v) ) {
                if ( ! first )
                    out() << ", ";
                else
                    first = false;

                if ( i.first.name.size() )
                    out() << i.first.name << ": ";

                print(i.second);
            }

            out() << ')';
            break;
        }
        case TypeInfo::Union: {
            if ( auto y = type.union_->value(v) )
                print(y);
            else
                out() << "(not set)";
            break;
        }
        case TypeInfo::UnsignedInteger_uint8: out() << static_cast<int16_t>(type.unsigned_integer_uint8->get(v)); break;
        case TypeInfo::UnsignedInteger_uint16: out() << type.unsigned_integer_uint16->get(v); break;
        case TypeInfo::UnsignedInteger_uint32: out() << type.unsigned_integer_uint32->get(v); break;
        case TypeInfo::UnsignedInteger_uint64: out() << type.unsigned_integer_uint64->get(v); break;
        case TypeInfo::ValueReference: {
            const auto* x = type.value_reference;
            if ( auto y = x->value(v) )
                print(x->value(v));
            else
                out() << "Null";
            break;
        }
        case TypeInfo::Vector: {
            out() << "[";

            bool empty = true;
            indent([&]() {
                for ( auto i : type.vector->iterate(v) ) {
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
            break;
        }
        case TypeInfo::VectorIterator: print(type.vector_iterator->value(v)); break;
        case TypeInfo::Void: out() << "<void>"; break;
        case TypeInfo::WeakReference: {
            const auto* x = type.weak_reference;
            if ( auto y = x->value(v) )
                print(x->value(v));
            else
                out() << "Null";
            break;
        }
    }
}
