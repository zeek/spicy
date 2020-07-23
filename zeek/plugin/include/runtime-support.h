// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

/**
 * Functions and types available to generated Spicy/Zeek glue code.
 */

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

#if ZEEK_DEBUG_BUILD
#define DEBUG
#endif
#include <Desc.h>
#include <EventHandler.h>
#include <IPAddr.h>
#include <Type.h>
#include <Val.h>
#include <Var.h>
#undef DEBUG

#include "cookie.h"

#include <hilti/rt/deferred-expression.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/types/all.h>

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/zeek-compat.h>

namespace spicy::zeek::rt {

/**
 * Exception thrown by event generation code if the value of an `$...`
 * expression isn't available.
 */
class ValueUnavailable : public hilti::rt::UserException {
public:
    using hilti::rt::UserException::UserException;
};

/**
 * Exception thrown by event generation code if the values can't be converted
 * to Zeek.
 */
class InvalidValue : public hilti::rt::UserException {
public:
    using hilti::rt::UserException::UserException;
};

/**
 * Exception thrown by event generation code if there's a type mismatch
 * between the Spicy-side value and what the Zeek event expects.
 */
class TypeMismatch : public hilti::rt::UserException {
public:
    TypeMismatch(const std::string_view& msg, std::string_view location = "")
        : hilti::rt::UserException(hilti::rt::fmt("Event parameter mismatch, %s", msg), location) {}
    TypeMismatch(const std::string_view& have, ::zeek::TypePtr want, std::string_view location = "")
        : TypeMismatch(_fmt(have, want), location) {}

private:
    std::string _fmt(const std::string_view& have, ::zeek::TypePtr want) {
        ::ODesc d;
        want->Describe(&d);
        return hilti::rt::fmt("cannot convert Spicy value of type '%s' to Zeek value of type '%s'", have,
                              d.Description());
    }
};

/**
 * Registers an Spicy protocol analyzer with its EVT meta information the
 * plugin's runtime.
 */
void register_protocol_analyzer(const std::string& name, hilti::rt::Protocol proto,
                                const hilti::rt::Vector<hilti::rt::Port>& ports, const std::string& parser_orig,
                                const std::string& parser_resp, const std::string& replaces = "");

/**
 * Registers an Spicy file analyzer with its EVT meta information the
 * plugin's runtime.
 */
void register_file_analyzer(const std::string& name, const hilti::rt::Vector<std::string>& mime_types,
                            const std::string& parser);

/** Registers a Spicy enum type to make it available inside Zeek. */
void register_enum_type(const std::string& ns, const std::string& id,
                        const hilti::rt::Vector<std::tuple<std::string, hilti::rt::integer::safe<int64_t>>>& labels);

/** Returns true if an event has at least one handler defined. */
inline bool have_handler(EventHandlerPtr handler) { return static_cast<bool>(handler); }

/**
 * Looks up an event handler by name. This will always return a handler; if
 * none exist yet under that name, it'll be created.
 */
::EventHandlerPtr internal_handler(const std::string& name);

/** Raises a Zeek event, given the handler and arguments. */
void raise_event(EventHandlerPtr handler, const hilti::rt::Vector<::zeek::ValPtr>& args, std::string_view location);

/**
 * Returns the Zeek type of an event's i'th argument. The result's ref count
 * is not increased.
 */
::zeek::TypePtr event_arg_type(EventHandlerPtr handler, uint64_t idx, std::string_view location);

/**
 * Retrieves the connection ID for the currently processed Zeek connection.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @return Zeek value of record type
 */
::zeek::ValPtr current_conn(std::string_view location);

/**
 * Retrieves the direction of the currently processed Zeek connection.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @return Zeek value of boolean type
 */
::zeek::ValPtr current_is_orig(std::string_view location);

/**
 * Logs a string through the Spicy plugin's debug output.
 *
 * @param cookie refers to the connection or file that the message is associated with
 * @param msg message to log
 */
void debug(const Cookie& cookie, const std::string_view& msg);

/**
 * Logs a string through the Spicy plugin's debug output. This version logs
 * the information the currently processed connection or file.
 *
 * @param msg message to log
 */
void debug(const std::string_view& msg);

/**
 * Retrieves the fa_file instance for the currently processed Zeek file.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @return Zeek value of record type
 */
::zeek::ValPtr current_file(std::string_view location);

/**
 * Returns true if we're currently parsing the originator side of a
 * connection.
 */
bool is_orig();

/** Instructs to Zeek to flip the directionality of the current connecction. */
void flip_roles();

/**
 * Returns the number of packets seen so far on the current side of the
 * current connection.
 */
uint64_t number_packets();

/**
 * Triggers a DPD protocol confirmation for the currently processed
 * connection. Assumes that the HILTI context's cookie value has been set
 * accordingly.
 */
void confirm_protocol();

/**
 * Triggers a DPD protocol violation for the currently processed connection.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @param reason short description of what went wrong
 */
void reject_protocol(const std::string& reason);

/**
 * Signals the beginning of a file to Zeek's file analysis, associating it
 * with the current connection.
 */
void file_begin();

/**
 * Signals the expected size of a file to Zeek's file analysis.
 *
 * @param size expected final size of the file
 */
void file_set_size(uint64_t size);

/**
 * Passes file content on to Zeek's file analysis.
 *
 * @param data next chunk of data
 */
void file_data_in(const hilti::rt::Bytes& data);

/**
 * Passes file content at a specific offset on to Zeek's file analysis.
 *
 * @param data next chunk of data
 * @param offset file offset of the data geing passed in
 */
void file_data_in_at_offset(const hilti::rt::Bytes& data, uint64_t offset);

/**
 * Signals a gap in a file to Zeek's file analysis.
 *
 * @param offset of the gap
 * @param length of the gap
 */
void file_gap(uint64_t offset, uint64_t len);

/** Signals the end of a file to Zeek's file analysis. */
void file_end();

// Forward-declare to_val() functions.
template<typename T, typename std::enable_if_t<hilti::rt::is_tuple<T>::value>* = nullptr>
::zeek::ValPtr to_val(const T& t, ::zeek::TypePtr target, std::string_view location);
template<typename T, typename std::enable_if_t<std::is_enum<T>::value>* = nullptr>
::zeek::ValPtr to_val(const T& t, ::zeek::TypePtr target, std::string_view location);
template<typename K, typename V>
::zeek::ValPtr to_val(const hilti::rt::Map<K, V>& s, ::zeek::TypePtr target, std::string_view location);
template<typename T>
::zeek::ValPtr to_val(const hilti::rt::Set<T>& s, ::zeek::TypePtr target, std::string_view location);
template<typename T>
::zeek::ValPtr to_val(const hilti::rt::Vector<T>& v, ::zeek::TypePtr target, std::string_view location);
template<typename T>
::zeek::ValPtr to_val(const std::optional<T>& t, ::zeek::TypePtr target, std::string_view location);
template<typename T>
::zeek::ValPtr to_val(const hilti::rt::DeferredExpression<T>& t, ::zeek::TypePtr target, std::string_view location);
template<typename T>
::zeek::ValPtr to_val(hilti::rt::integer::safe<T> i, ::zeek::TypePtr target, std::string_view location);

inline ::zeek::ValPtr to_val(bool b, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(const hilti::rt::Address& d, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(const hilti::rt::Bytes& b, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(const hilti::rt::Interval& t, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(const hilti::rt::Port& d, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(const hilti::rt::Time& t, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(const std::string& s, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(double r, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(int16_t i, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(int32_t i, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(int64_t i, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(int8_t i, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(uint16_t i, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(uint32_t i, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(uint64_t i, ::zeek::TypePtr target, std::string_view location);
inline ::zeek::ValPtr to_val(uint8_t i, ::zeek::TypePtr target, std::string_view location);

/**
 * Converts a Spicy-side optional value to a Zeek value. This assumes the
 * optional is set, and will throw an exception if not. The result is
 * returned with ref count +1.
 */
template<typename T>
inline ::zeek::ValPtr to_val(const std::optional<T>& t, ::zeek::TypePtr target, std::string_view location) {
    if ( t.has_value() )
        return to_val(hilti::rt::optional::value(t, location.data()), target, location);

    return nullptr;
}

/**
 * Converts a Spicy-side DeferredExpression<T> value to a Zeek value. Such
 * result values are returned by the ``.?`` operator. If the result is not
 * set, this will convert into nullptr (which the tuple-to-record to_val()
 * picks up on).
 */
template<typename T>
inline ::zeek::ValPtr to_val(const hilti::rt::DeferredExpression<T>& t, ::zeek::TypePtr target,
                             std::string_view location) {
    try {
        return to_val(t(), target, location);
    } catch ( const hilti::rt::AttributeNotSet& ) {
        return nullptr;
    }
}

/**
 * Converts a Spicy-side string to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const std::string& s, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_STRING )
        throw TypeMismatch("string", target, location);

    return zeek::compat::StringVal_New(s);
}

/**
 * Converts a Spicy-side bytes instance to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const hilti::rt::Bytes& b, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_STRING )
        throw TypeMismatch("string", target, location);

    return zeek::compat::StringVal_New(b.str());
}

/**
 * Converts a Spicy-side integer to a Zeek value. The result is
 * returned with ref count +1.
 */
template<typename T>
inline ::zeek::ValPtr to_val(hilti::rt::integer::safe<T> i, ::zeek::TypePtr target, std::string_view location) {
    ::zeek::ValPtr v = nullptr;
    if constexpr ( std::is_unsigned<T>::value ) {
        if ( target->Tag() == ::zeek::TYPE_COUNT )
            return zeek::compat::val_mgr_Count(i);

        if ( target->Tag() == ::zeek::TYPE_INT )
            return zeek::compat::val_mgr_Int(i);

        throw TypeMismatch("uint64", target, location);
    }
    else {
        if ( target->Tag() == ::zeek::TYPE_INT )
            return zeek::compat::val_mgr_Int(i);

        if ( target->Tag() == ::zeek::TYPE_COUNT ) {
            if ( i >= 0 )
                return zeek::compat::val_mgr_Count(i);
            else
                throw TypeMismatch("negative int64", target, location);
        }

        throw TypeMismatch("int64", target, location);
    }
}

/**
 * Converts a Spicy-side signed bool to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ::zeek::ValPtr to_val(bool b, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_BOOL )
        throw TypeMismatch("bool", target, location);

    return zeek::compat::val_mgr_Bool(b);
}

/**
 * Converts a Spicy-side real to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(double r, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_DOUBLE )
        throw TypeMismatch("double", target, location);

    return zeek::compat::DoubleVal_New(r);
}

/**
 * Converts a Spicy-side address to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const hilti::rt::Address& d, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_ADDR )
        throw TypeMismatch("addr", target, location);

    auto in_addr = d.asInAddr();
    if ( auto v4 = std::get_if<struct in_addr>(&in_addr) )
        return zeek::compat::AddrVal_New(IPAddr(*v4));
    else {
        auto v6 = std::get<struct in6_addr>(in_addr);
        return zeek::compat::AddrVal_New(IPAddr(v6));
    }
}

/**
 * Converts a Spicy-side address to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const hilti::rt::Port& p, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_PORT )
        throw TypeMismatch("port", target, location);

    switch ( p.protocol() ) {
        case hilti::rt::Protocol::TCP: return zeek::compat::val_mgr_Port(p.port(), ::TransportProto::TRANSPORT_TCP);

        case hilti::rt::Protocol::UDP: return zeek::compat::val_mgr_Port(p.port(), ::TransportProto::TRANSPORT_UDP);

        case hilti::rt::Protocol::ICMP: return zeek::compat::val_mgr_Port(p.port(), ::TransportProto::TRANSPORT_ICMP);

        default: throw InvalidValue("port value with undefined protocol", location);
    }
}

/**
 * Converts a Spicy-side signed integer to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ::zeek::ValPtr to_val(int8_t i, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_INT )
        throw TypeMismatch("int", target, location);

    return zeek::compat::val_mgr_Int(i);
}

/**
 * Converts a Spicy-side signed integer to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ::zeek::ValPtr to_val(int16_t i, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_INT )
        throw TypeMismatch("int", target, location);

    return zeek::compat::val_mgr_Int(i);
}

/**
 * Converts a Spicy-side signed integer to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ::zeek::ValPtr to_val(int32_t i, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_INT )
        throw TypeMismatch("int", target, location);

    return zeek::compat::val_mgr_Int(i);
}

/**
 * Converts a Spicy-side signed integer to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ::zeek::ValPtr to_val(int64_t i, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_INT )
        throw TypeMismatch("int", target, location);

    return zeek::compat::val_mgr_Int(i);
}

/**
 * Converts a Spicy-side time to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const hilti::rt::Interval& i, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_INTERVAL )
        throw TypeMismatch("interval", target, location);

    return zeek::compat::IntervalVal_New(i.seconds());
}

/**
 * Converts a Spicy-side time to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ::zeek::ValPtr to_val(const hilti::rt::Time& t, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_TIME )
        throw TypeMismatch("time", target, location);

    return zeek::compat::TimeVal_New(t.seconds());
}

/**
 * Converts a Spicy-side signed integer to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ::zeek::ValPtr to_val(uint8_t i, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_COUNT )
        throw TypeMismatch("int", target, location);

    return zeek::compat::val_mgr_Count(i);
}

/**
 * Converts a Spicy-side signed integer to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ::zeek::ValPtr to_val(uint16_t i, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_COUNT )
        throw TypeMismatch("int", target, location);

    return zeek::compat::val_mgr_Count(i);
}

/**
 * Converts a Spicy-side signed integer to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ::zeek::ValPtr to_val(uint32_t i, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_COUNT )
        throw TypeMismatch("int", target, location);

    return zeek::compat::val_mgr_Count(i);
}

/**
 * Converts a Spicy-side signed integer to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ::zeek::ValPtr to_val(uint64_t i, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_COUNT )
        throw TypeMismatch("int", target, location);

    return zeek::compat::val_mgr_Count(i);
}

/**
 * Converts a Spicy-side vector to a Zeek value. The result is returned with
 * ref count +1.
 */
template<typename T>
inline ::zeek::ValPtr to_val(const hilti::rt::Vector<T>& v, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_VECTOR && target->Tag() != ::zeek::TYPE_LIST )
        throw TypeMismatch("expected vector or list", target, location);

    auto vt = target->AsVectorType();
    auto zv = std::make_unique<::zeek::VectorVal>(vt);
    for ( auto i : v )
        zv->Assign(zv->Size(), to_val(i, zeek::compat::VectorType_Yield(vt), location));

    return zeek::compat::ToValPtr(std::move(zv));
}

/**
 * Converts a Spicy-side map to a Zeek value. The result is returned with
 * ref count +1.
 */
template<typename K, typename V>
inline ::zeek::ValPtr to_val(const hilti::rt::Map<K, V>& m, ::zeek::TypePtr target, std::string_view location) {
    if constexpr ( hilti::rt::is_tuple<K>::value )
        throw TypeMismatch("internal error: sets with tuples not yet supported in to_val()");

    if ( target->Tag() != ::zeek::TYPE_TABLE )
        throw TypeMismatch("map", target, location);

    auto tt = target->AsTableType();
    if ( tt->IsSet() )
        throw TypeMismatch("map", target, location);

    if ( zeek::compat::TableType_GetIndexTypesLength(tt) != 1 )
        throw TypeMismatch("map with non-tuple elements", target, location);

    auto zv = std::make_unique<::zeek::TableVal>(tt);

    for ( auto i : m ) {
        auto k = to_val(i.first, zeek::compat::TableType_GetIndexTypes(tt)[0], location);
        auto v = to_val(i.second, zeek::compat::TableType_Yield(tt), location);
        zv->Assign(k, v);
        Unref(k);
    }

    return zeek::compat::ToValPtr(std::move(zv));
} // namespace spicy::zeek::rt

/**
 * Converts a Spicy-side set to a Zeek value. The result is returned with
 * ref count +1.
 */
template<typename T>
inline ::zeek::ValPtr to_val(const hilti::rt::Set<T>& s, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_TABLE )
        throw TypeMismatch("set", target, location);

    auto tt = target->AsTableType();
    if ( ! tt->IsSet() )
        throw TypeMismatch("set", target, location);

    auto zv = std::make_unique<::zeek::TableVal>(tt);

    for ( auto i : s ) {
        if constexpr ( hilti::rt::is_tuple<T>::value )
            throw TypeMismatch("internal error: sets with tuples not yet supported in to_val()");
        else {
            if ( zeek::compat::TableType_GetIndexTypesLength(tt) != 1 )
                throw TypeMismatch("set with non-tuple elements", target, location);

            auto idx = to_val(i, zeek::compat::TableType_GetIndexTypes(tt)[0], location);
            zv->Assign(idx, nullptr);
            Unref(idx);
        }
    }

    return zeek::compat::ToValPtr(std::move(zv));
}

/**
 * Converts a Spicy-side tuple to a Zeek record value. The result is returned
 * with ref count +1.
 */
template<typename T, typename std::enable_if_t<hilti::rt::is_tuple<T>::value>*>
inline ::zeek::ValPtr to_val(const T& t, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_RECORD )
        throw TypeMismatch("tuple", target, location);

    auto rtype = target->AsRecordType();

    if ( std::tuple_size<T>::value != rtype->NumFields() )
        throw TypeMismatch("tuple", target, location);

    auto rval = std::make_unique<::zeek::RecordVal>(rtype);
    int idx = 0;
    hilti::rt::tuple_for_each(t, [&](const auto& x) {
        ::zeek::ValPtr v = nullptr;

        if constexpr ( std::is_same<decltype(x), const hilti::rt::Null&>::value ) {
            // "Null" turns into an unset optional record field.
        }
        else
            // This may return a nullptr in cases where the field is to be left unset.
            v = to_val(x, zeek::compat::RecordType_GetFieldType(rtype, idx), location);

        if ( v )
            rval->Assign(idx, v);
        else {
            // Field must be &optional or &default.
            auto attrs = rtype->FieldDecl(idx)->attrs;
            if ( ! (zeek::compat::Attribute_Find(attrs, ::zeek::detail::ATTR_DEFAULT) ||
                    zeek::compat::Attribute_Find(attrs, ::zeek::detail::ATTR_OPTIONAL)) )
                throw TypeMismatch(hilti::rt::fmt("missing initialization for field '%s'", rtype->FieldName(idx)),
                                   location);
        }

        idx++;
    });


    return zeek::compat::ToValPtr(std::move(rval));
}

/**
 * Converts a Spicy-side tuple to a Zeek record value. The result is returned
 * with ref count +1.
 */
template<typename T, typename std::enable_if_t<std::is_enum<T>::value>*>
inline ::zeek::ValPtr to_val(const T& t, ::zeek::TypePtr target, std::string_view location) {
    if ( target->Tag() != ::zeek::TYPE_ENUM )
        throw TypeMismatch("enum", target, location);

    return zeek::compat::EnumTypeGetEnumVal(target->AsEnumType(), static_cast<int>(t));
}

} // namespace spicy::zeek::rt
