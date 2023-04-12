// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/fmt.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/real.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

Bytes real::pack(double d, real::Type type, ByteOrder fmt) {
    switch ( type.value() ) {
        case real::Type::IEEE754_Single: {
            auto f = static_cast<float>(d);
            auto i = reinterpret_cast<uint32_t*>(&f);
            return integer::pack<uint32_t>(*i, fmt);
        }

        case real::Type::IEEE754_Double: {
            auto i = reinterpret_cast<uint64_t*>(&d);
            return integer::pack<uint64_t>(*i, fmt);
        }

        case real::Type::Undef:; // Intentional fall through.
    }

    throw RuntimeError("attempt to pack real value of undefined type");
}

template<typename T>
Result<std::tuple<double, T>> _unpack(const T& data, real::Type type, ByteOrder fmt) {
    switch ( type.value() ) {
        case real::Type::IEEE754_Single: {
            if ( data.size() < 4 )
                return result::Error("insufficient data to unpack single precision real");

            if ( auto x = integer::unpack<uint32_t>(data, fmt) ) {
                auto d = reinterpret_cast<float*>(&std::get<0>(*x));
                return std::make_tuple(static_cast<double>(*d), std::get<1>(*x));
            }
            else
                return x.error();
        }

        case real::Type::IEEE754_Double: {
            if ( data.size() < 8 )
                return result::Error("insufficient data to unpack double precision real");

            if ( auto x = integer::unpack<uint64_t>(data, fmt) ) {
                auto d = reinterpret_cast<double*>(&std::get<0>(*x));
                return std::make_tuple(*d, std::get<1>(*x));
            }
            else
                return x.error();
        }

        case real::Type::Undef: return result::Error("undefined real type for unpacking");
    }

    cannot_be_reached();
}

Result<std::tuple<double, Bytes>> real::unpack(const Bytes& data, real::Type type, ByteOrder fmt) {
    return _unpack(data, type, fmt);
}

Result<std::tuple<double, stream::View>> real::unpack(const stream::View& data, real::Type type, ByteOrder fmt) {
    return _unpack(data, type, fmt);
}

std::string detail::adl::to_string(double x, tag /*unused*/) {
    // %g general floating point format drops '.'
    return fmt("%g", x);
}

std::string detail::adl::to_string(const real::Type& x, adl::tag /*unused*/) {
    switch ( x.value() ) {
        case real::Type::IEEE754_Double: return "Type::IEEE754_Double";
        case real::Type::IEEE754_Single: return "Type::IEEE754_Single";
        case real::Type::Undef: return "Type::Undef";
    }

    cannot_be_reached();
}
