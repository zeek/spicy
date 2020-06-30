// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/rt/types/stream.h>

#include <spicy/rt/parsed-unit.h>

namespace spicy::rt {

template<typename T>
using UnitType = hilti::rt::ValueReference<T>;

template<typename T>
using UnitRef = hilti::rt::StrongReference<T>;

/** Defines the type of the generic version of units' public parsing functions. */
using Parse1Function = hilti::rt::Resumable (*)(hilti::rt::ValueReference<hilti::rt::Stream>&,
                                                const std::optional<hilti::rt::stream::View>&);

/** Defines the type of the generic version of units' public parsing functions. */
template<typename T>
using Parse2Function = hilti::rt::Resumable (*)(UnitType<T>&, hilti::rt::ValueReference<hilti::rt::Stream>&,
                                                const std::optional<hilti::rt::stream::View>&);

using Parse3Function = hilti::rt::Resumable (*)(ParsedUnit&, hilti::rt::ValueReference<hilti::rt::Stream>&,
                                                const std::optional<hilti::rt::stream::View>&);

/**
 * Exception thrown by generated parser code when an parsing failed.
 */
class ParseError : public hilti::rt::UserException {
public:
    ParseError(const std::string& msg) : UserException(hilti::rt::fmt("parse error: %s", msg)) {}

    ParseError(const std::string& msg, const std::string& location)
        : UserException(hilti::rt::fmt("parse error: %s", msg), location) {}

    ParseError(const hilti::rt::result::Error& e) : UserException(hilti::rt::fmt("parse error: %s", e.description())) {}
};

namespace sink::detail {
struct State;
} // namespace sink::detail

namespace detail {

/**
 *
 * Defines the type of a unit's parse function used when connected to a sink.
 * This is for internal use only.
 */
using ParseSinkFunction =
    std::function<std::pair<hilti::rt::StrongReferenceGeneric, spicy::rt::sink::detail::State*>()>;
} // namespace detail

} // namespace spicy::rt
