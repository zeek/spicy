// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/result.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/null.h>
#include <hilti/rt/types/port.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/struct.h>

#include <spicy/rt/filter.h>
#include <spicy/rt/global-state.h>
#include <spicy/rt/mime.h>
#include <spicy/rt/sink.h>
#include <spicy/rt/typedefs.h>

namespace spicy::rt {

/**
 * Runtime information about an available parser.
 *
 * Note: When changing this struct, adapt the Spicy-side `spicy_rt::Parser`
 * as well.
 */
struct Parser {
    Parser(std::string name, Parse1Function parse1, std::any parse2, std::string description,
           hilti::rt::Vector<MIMEType> mime_types, hilti::rt::Vector<hilti::rt::Port> ports)
        : name(std::move(name)),
          parse1(parse1),
          parse2(std::move(parse2)),
          description(std::move(description)),
          mime_types(std::move(mime_types)),
          ports(std::move(ports)) {}

    Parser(std::string name, hilti::rt::Null /* null */, std::any parse2, std::string description,
           hilti::rt::Vector<MIMEType> mime_types, hilti::rt::Vector<hilti::rt::Port> ports)
        : Parser(std::move(name), nullptr, parse2, std::move(description), std::move(mime_types), std::move(ports)) {}

    Parser(const Parser&) = default;

    Parser() = default;
    ~Parser() = default;
    Parser(Parser&&) noexcept = default;
    Parser& operator=(const Parser&) = default;
    Parser& operator=(Parser&&) noexcept = default;

    /** Short descriptive name. */
    std::string name;

    /** Function performing parsing of given input into a temporary instance. */
    Parse1Function parse1{};

    /**
     * Function performing parsing of given input into a provided instance.
     * The actual type of this member is Parse2Function<T>.
     */
    std::any parse2;

    /**
     * Human-readable description associated with this parser.
     */
    std::string description;

    /**
     * MIME types this parer can handle.
     */
    hilti::rt::Vector<MIMEType> mime_types;

    /**
     * Well-known ports associated with this parser.
     */
    hilti::rt::Vector<hilti::rt::Port> ports;

    /**
     * For internal use only. Set by `registerParser()` for units that's don't
     * receive arguments.
     */
    std::optional<detail::ParseSinkFunction> __parse_sink;

    /** For internal use only. Dispatcher for the corresponding unit hook. */
    std::optional<std::function<void(hilti::rt::StrongReferenceGeneric, uint64_t, uint64_t)>> __hook_gap;

    /** For internal use only. Dispatcher for the corresponding unit hook. */
    std::optional<std::function<void(hilti::rt::StrongReferenceGeneric, uint64_t, const hilti::rt::Bytes&,
                                     const hilti::rt::Bytes&)>>
        __hook_overlap;

    /** For internal use only. Dispatcher for the corresponding unit hook. */
    std::optional<std::function<void(hilti::rt::StrongReferenceGeneric, uint64_t)>> __hook_skipped;

    /** For internal use only. Dispatcher for the corresponding unit hook. */
    std::optional<std::function<void(hilti::rt::StrongReferenceGeneric, uint64_t, const hilti::rt::Bytes&)>>
        __hook_undelivered;
};

/** Returns all available parsers. */
inline const auto& parsers() { return detail::globalState()->parsers; }

namespace detail {

/**
 * Registers a parser with the runtime as being available. This is
 * automatically called for generated parsers during their initialization.
 *
 * @tparam UnitRef The `UnitRef<T>` type for the unit that the parser parses, as
 * passed when calling into the runtime.
 *
 * @param p parser to register.
 *
 * @param instance arbitrary instance of `Unit`; this is not actually used,
 * we add the parameters just so that the template parameter `Unit` can be
 * automatically inferred.
 */
template<typename UnitRef>
inline void registerParser(::spicy::rt::Parser& p, // NOLINT(google-runtime-references)
                           UnitRef /* not used, just for template instantiation */ instance) {
    // Note: This may may be called before spicy::rt::init(), and during
    // hilti::rt::init(). Cannot rely on any library functionality being
    // intialized yet.
    globalState()->parsers.emplace_back(&p);

    using unit_type = typename UnitRef::element_type;

    if constexpr ( sink::detail::supports_sinks<unit_type>::value ) {
        if constexpr ( ! std::is_base_of<hilti::rt::trait::hasParameters, unit_type>::value )
            p.__parse_sink = sink::detail::parseFunction<unit_type>();

        p.__hook_gap = sink::detail::hookFunction<unit_type, &unit_type::__on_0x25_gap, uint64_t, uint64_t>();
        p.__hook_skipped = sink::detail::hookFunction<unit_type, &unit_type::__on_0x25_skipped, uint64_t>();
        p.__hook_overlap = sink::detail::hookFunction<unit_type, &unit_type::__on_0x25_overlap, uint64_t,
                                                      const hilti::rt::Bytes&, const hilti::rt::Bytes&>();
        p.__hook_undelivered = sink::detail::hookFunction<unit_type, &unit_type::__on_0x25_undelivered, uint64_t,
                                                          const hilti::rt::Bytes&>();
    }

    for ( const auto& mt : p.mime_types ) {
        SPICY_RT_DEBUG_VERBOSE(hilti::rt::fmt("registering parser %s for MIME type %s", p.name, std::string(mt)));
        auto& parsers = globalState()->parsers_by_mime_type[mt.asKey()];
        parsers.push_back(&p);
    }
}

/**
 * Prints the current parser state, as passed in through arguments, to the
 * spicy-verbose debug stream.
 */
void printParserState(const std::string& unit_id, const hilti::rt::ValueReference<hilti::rt::Stream>& data,
                      const hilti::rt::stream::View& cur, int64_t lahead,
                      const hilti::rt::stream::SafeConstIterator& lahead_end, const std::string& literal_mode,
                      bool trim);

/**
 * Used by generated parsers to wait until a minimum amount of input becomes
 * available or end-of-data is reached.
 *
 * @param data current input data
 * @param cur view of *data* that's being parsed
 * @param min desired number of bytes
 * @param filters filter state associated with current unit instance (which may be null)
 * @return true if mininum number of bytes are available; false if end-of-data
 * has been reached
 */
extern bool waitForInputOrEod(hilti::rt::ValueReference<hilti::rt::Stream>& data, // NOLINT(google-runtime-references)
                              const hilti::rt::stream::View& cur, uint64_t min,
                              hilti::rt::StrongReference<spicy::rt::filter::detail::Filters> filters);

/**
 * Used by generated parsers to wait until end-of-data is obtained, but not
 * necessarily reached.
 *
 * @param data current input data
 * @param cur view of *data* that's being parsed
 * @param filters filter state associated with current unit instance (which may be null)
 */
extern void waitForEod(hilti::rt::ValueReference<hilti::rt::Stream>& data, // NOLINT(google-runtime-references)
                       const hilti::rt::stream::View& cur,
                       hilti::rt::StrongReference<spicy::rt::filter::detail::Filters> filters);

/**
 * Used by generated parsers to wait until a minimum amount of input becomes
 * available. If a end-of-data is reached before that, will trigger a parse
 * error.
 *
 * @param data current input data
 * @param cur view of *data* that's being parsed
 * @param min desired number of bytes
 * @param error_msg message to report with parse error if end-of-data is been reached
 * @param location location associated with the situation
 * @param filters filter state associated with current unit instance (which may be null)
 */
extern void waitForInput(hilti::rt::ValueReference<hilti::rt::Stream>& data, // NOLINT(google-runtime-references)
                         const hilti::rt::stream::View& cur, uint64_t min, const std::string& error_msg,
                         const std::string& location,
                         hilti::rt::StrongReference<spicy::rt::filter::detail::Filters> filters);

/**
 * Used by generated parsers to wait more input becomes available or
 * end-of-data is reached.
 *
 * @param data current input data
 * @param cur view of *data* that's being parsed
 * @param filters filter state associated with current unit instance (which may be null)
 * @return true if mininum number of bytes are available; false if end-of-data
 * has been reached
 */
extern bool waitForInputOrEod(hilti::rt::ValueReference<hilti::rt::Stream>& data, // NOLINT(google-runtime-references)
                              const hilti::rt::stream::View& cur,
                              const hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>& filters);

/**
 * Used by generated parsers to wait until more input becomes available. If a
 * end-of-data is reached before any more data becomes available, will
 * trigger a parse error.
 *
 * @param data current input data
 * @param cur view of *data* that's being parsed
 * @param error_msg message to report with parse error if end-of-data is been reached
 * @param location location associated with the situation
 * @param filters filters state associated with current unit instance (which may be null)
 */
extern void waitForInput(hilti::rt::ValueReference<hilti::rt::Stream>& data, // NOLINT(google-runtime-references)
                         const hilti::rt::stream::View& cur, const std::string& error_msg, const std::string& location,
                         const hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>& filters);

/**
 * Used by generated parsers to recognize end-of-data.
 *
 * @param data current input data
 * @param cur view of *data* that's being parsed
 * @return true if end-of-data has been reached
 */
extern bool atEod(const hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur);

/**
 * Used by generated parsers to recognize when end-of-data has been seen,
 * but possibly not reached.
 *
 * @param data current input data
 * @param cur view of *data* that's being parsed
 * @return true if end-of-data has been seen, but not necessarily reached.
 */
extern bool haveEod(const hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur);
} // namespace detail
} // namespace spicy::rt
