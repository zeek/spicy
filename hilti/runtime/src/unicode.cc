// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/unicode.h"

namespace hilti::rt::detail::adl {

std::string to_string(const unicode::DecodeErrorStrategy& x, tag /*unused*/) {
    switch ( x.value() ) {
        case unicode::DecodeErrorStrategy::IGNORE: return "DecodeErrorStrategy::IGNORE";
        case unicode::DecodeErrorStrategy::REPLACE: return "DecodeErrorStrategy::REPLACE";
        case unicode::DecodeErrorStrategy::STRICT: return "DecodeErrorStrategy::STRICT";
    }

    cannot_be_reached();
}

std::string to_string(const unicode::Charset& x, tag /*unused*/) {
    switch ( x.value() ) {
        case unicode::Charset::ASCII: return "Charset::ASCII";
        case unicode::Charset::UTF8: return "Charset::UTF8";
        case unicode::Charset::UTF16BE: return "Charset::UTF16BE";
        case unicode::Charset::UTF16LE: return "Charset::UTF16LE";
        case unicode::Charset::Undef: return "Charset::Undef";
    }

    cannot_be_reached();
}

} // namespace hilti::rt::detail::adl
