// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/real.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

template<typename T>
Result<std::tuple<double, T>> _unpack(const T& data, real::Type type, ByteOrder fmt) {
    switch ( type ) {
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
            if ( auto x = integer::unpack<uint64_t>(data, fmt) ) {
                auto d = reinterpret_cast<double*>(&std::get<0>(*x));
                return std::make_tuple(*d, std::get<1>(*x));
            }
            else
                return x.error();
        }

        case real::Type::Undef: throw RuntimeError("undefined real type for unpacking");
    }

    cannot_be_reached();
}

Result<std::tuple<double, Bytes>> real::unpack(const Bytes& data, real::Type type, ByteOrder fmt) {
    return _unpack(data, type, fmt);
}

Result<std::tuple<double, stream::View>> real::unpack(const stream::View& data, real::Type type, ByteOrder fmt) {
    return _unpack(data, type, fmt);
}
