// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/result.h>
#include <hilti/rt/type-info.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/null.h>
#include <hilti/rt/types/port.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/struct.h>

#include <spicy/rt/filter.h>
#include <spicy/rt/global-state.h>
#include <spicy/rt/mime.h>
#include <spicy/rt/parser-fwd.h>
#include <spicy/rt/sink.h>
#include <spicy/rt/typedefs.h>

namespace spicy::rt {

/** Defines the direction a `ParserPort` applies to. */
enum class Direction { Originator, Responder, Both, Undef };

} // namespace spicy::rt

namespace hilti::rt::detail::adl {

inline std::string to_string(const ::spicy::rt::Direction& x, adl::tag /*unused*/) {
    switch ( x ) {
        case spicy::rt::Direction::Originator: return "originator";
        case spicy::rt::Direction::Responder: return "responder";
        case spicy::rt::Direction::Both: return "both";
        case spicy::rt::Direction::Undef: return "undefined";
    }

    cannot_be_reached();
};

} // namespace hilti::rt::detail::adl

namespace spicy::rt {

inline std::ostream& operator<<(std::ostream& out, const Direction& d) { return out << hilti::rt::to_string(d); }

/** Defines port & direction a parser can handle.  */
struct ParserPort {
    hilti::rt::Port port;
    Direction direction;

    // Constructor used by code generator.
    ParserPort(std::tuple<hilti::rt::Port, Direction> args) : port(std::get<0>(args)), direction(std::get<1>(args)) {}
};

inline std::ostream& operator<<(std::ostream& out, const ParserPort& p) { return out << hilti::rt::to_string(p); }

} // namespace spicy::rt

namespace hilti::rt::detail::adl {

inline std::string to_string(const spicy::rt::ParserPort& x, adl::tag /*unused*/) {
    // TODO: Not sure why we need to explicit to_string() here.
    if ( x.direction == spicy::rt::Direction::Both )
        return x.port;
    else
        return fmt("%s (%s direction)", x.port, x.direction);
}

} // namespace hilti::rt::detail::adl

namespace spicy::rt {

namespace detail {

// Helper traits to detect whether a parser implements sink hooks.

template<typename P>
struct has_on_gap {
    template<typename U>
    // If `->` gets wrapped to the next line cpplint misdetects this as a C-style cast.
    // clang-format off
    static auto test(int) -> decltype(
        std::declval<U>().__on_0x25_gap(std::declval<uint64_t>(), std::declval<uint64_t>()), std::true_type());
    // clang-format on
    template<typename U>
    static std::false_type test(...);
    static constexpr bool value = std::is_same_v<decltype(test<P>(0)), std::true_type>;
};

template<typename P>
struct has_on_skipped {
    template<typename U>
    static auto test(int) -> decltype(std::declval<U>().__on_0x25_skipped(std::declval<uint64_t>()), std::true_type());
    template<typename U>
    static std::false_type test(...);
    static constexpr bool value = std::is_same_v<decltype(test<P>(0)), std::true_type>;
};

template<typename P>
struct has_on_overlap {
    template<typename U>
    static auto test(int) -> decltype(std::declval<U>().__on_0x25_overlap(std::declval<uint64_t>(),
                                                                          std::declval<const hilti::rt::Bytes&>(),
                                                                          std::declval<const hilti::rt::Bytes&>()),
                                      std::true_type());
    template<typename U>
    static std::false_type test(...);
    static constexpr bool value = std::is_same_v<decltype(test<P>(0)), std::true_type>;
};

template<typename P>
struct has_on_undelivered {
    template<typename U>
    static auto test(int) -> decltype(std::declval<U>().__on_0x25_undelivered(std::declval<uint64_t>(),
                                                                              std::declval<const hilti::rt::Bytes&>()),
                                      std::true_type());
    template<typename U>
    static std::false_type test(...);
    static constexpr bool value = std::is_same_v<decltype(test<P>(0)), std::true_type>;
};

} // namespace detail

/**
 * Runtime information about an available parser.
 *
 * Note: When changing this struct, adapt the Spicy-side `spicy_rt::Parser`
 * as well.
 */
struct Parser {
    Parser(std::string name, Parse1Function parse1, hilti::rt::any parse2, Parse3Function parse3,
           ContextNewFunction context_new, const hilti::rt::TypeInfo* type, std::string description,
           hilti::rt::Vector<MIMEType> mime_types, hilti::rt::Vector<ParserPort> ports)
        : name(std::move(name)),
          parse1(parse1),
          parse2(std::move(parse2)),
          parse3(parse3),
          context_new(context_new),
          type(type),
          description(std::move(description)),
          mime_types(std::move(mime_types)),
          ports(std::move(ports)) {}

    Parser(std::string name, Parse1Function parse1, hilti::rt::any parse2, Parse3Function parse3,
           hilti::rt::Null /* null */, const hilti::rt::TypeInfo* type, std::string description,
           hilti::rt::Vector<MIMEType> mime_types, hilti::rt::Vector<ParserPort> ports)
        : name(std::move(name)),
          parse1(parse1),
          parse2(std::move(parse2)),
          parse3(parse3),
          type(type),
          description(std::move(description)),
          mime_types(std::move(mime_types)),
          ports(std::move(ports)) {}

    Parser(std::string name, hilti::rt::Null /* null */, hilti::rt::any parse2, hilti::rt::Null /* null */,
           hilti::rt::Null /* null */, const hilti::rt::TypeInfo* type, std::string description,
           hilti::rt::Vector<MIMEType> mime_types, hilti::rt::Vector<ParserPort> ports)
        : Parser(std::move(name), nullptr, parse2, nullptr, nullptr, type, std::move(description),
                 std::move(mime_types), std::move(ports)) {}

    Parser(const Parser&) = default;

    Parser() = default;
    ~Parser() = default;
    Parser(Parser&&) noexcept = default;
    Parser& operator=(const Parser&) = default;
    Parser& operator=(Parser&&) noexcept = default;

    /**
     * Create a new instance of the `%context` type defined for the parser. If
     * there's no context defined, returns an unset optional.
     */
    std::optional<UnitContext> createContext() const {
        if ( context_new )
            return (*context_new)();
        else
            return {};
    }

    /** Short descriptive name. */
    std::string name;

    /**
     * Linker scope of the unit registering the parser. This can be used for
     * disambiguation between linked units. Will be set/overidden by
     * `registerParser()`.
     */
    std::string linker_scope;

    /**
     * Function performing parsing of given input into a temporary instance.
     * This will remain unset if the unit type cannot be used through a
     * `parse1`-style function because it receives parameters.
     */
    Parse1Function parse1{};

    /**
     * Function performing parsing of given input into a provided instance.
     * The actual type of this member is Parse2Function<T>.
     */
    hilti::rt::any parse2;

    /**
     * Function performing parsing of given input into a ParsedUnited
     * that will be returned. This will remain unset if the unit type
     * cannot be used through a `parse3`-style function because it
     * receives parameters.
     */
    Parse3Function parse3{};

    /**
     * Function instantantiating a new instance of the `%context` defined for
     * the parse. Unset if no context is defined.
     */
    ContextNewFunction context_new = nullptr;

    const hilti::rt::TypeInfo* type;

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
    hilti::rt::Vector<ParserPort> ports;

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

/**
 * Exception thrown by generated parser code when an parsing failed.
 */
class ParseError : public hilti::rt::UserException {
public:
    ParseError(const std::string& msg, const std::string& location = "")
        : UserException(hilti::rt::fmt("parse error: %s", msg), location) {}

    ParseError(const hilti::rt::result::Error& e) : UserException(hilti::rt::fmt("parse error: %s", e.description())) {}

    virtual ~ParseError(); /* required to create vtable, see hilti::rt::Exception */
};

/**
 * Exception triggering backtracking to the most recent ``&try``. Derived from
 * ``ParseError`` so that if it's not caught, it turns into a regular parsing
 * error.
 */
class Backtrack : public ParseError {
public:
    Backtrack() : ParseError("backtracking outside of &try scope") {}
    virtual ~Backtrack();
};

namespace detail {

/**
 * Registers a parser with the runtime as being available. This is
 * automatically called for generated parsers during their initialization.
 *
 * @tparam The `UnitRef<T>` type for the unit that the parser parses, as
 * passed when calling into the runtime.
 *
 * @param parser parser to register.
 *
 * @param instance arbitrary instance of `Unit`; this is not actually used,
 * we add the parameters just so that the template parameter `Unit` can be
 * automatically inferred.
 */
template<typename UnitRef>
inline void registerParser(::spicy::rt::Parser& p, // NOLINT(google-runtime-references)
                           std::string linker_scope, UnitRef /* not used, just for template instantiation */) {
    // Note: This may may be called before spicy::rt::init(), and during
    // hilti::rt::init(). Cannot rely on any library functionality being
    // initialized yet.

    p.linker_scope = std::move(linker_scope);
    globalState()->parsers.emplace_back(&p);

    using unit_type = typename UnitRef::element_type;

    if constexpr ( sink::detail::supports_sinks<unit_type>::value &&
                   ! std::is_base_of<hilti::rt::trait::hasParameters, unit_type>::value )
        p.__parse_sink = sink::detail::parseFunction<unit_type>();

    if constexpr ( detail::has_on_gap<unit_type>::value )
        p.__hook_gap = sink::detail::hookFunction<unit_type, &unit_type::__on_0x25_gap, uint64_t, uint64_t>();

    if constexpr ( detail::has_on_skipped<unit_type>::value )
        p.__hook_skipped = sink::detail::hookFunction<unit_type, &unit_type::__on_0x25_skipped, uint64_t>();

    if constexpr ( detail::has_on_overlap<unit_type>::value )
        p.__hook_overlap = sink::detail::hookFunction<unit_type, &unit_type::__on_0x25_overlap, uint64_t,
                                                      const hilti::rt::Bytes&, const hilti::rt::Bytes&>();

    if constexpr ( detail::has_on_undelivered<unit_type>::value )
        p.__hook_undelivered = sink::detail::hookFunction<unit_type, &unit_type::__on_0x25_undelivered, uint64_t,
                                                          const hilti::rt::Bytes&>();
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
 * @param filter filter state associated with current unit instance (which may be null)
 * @return true if minimum number of bytes are available; false if end-of-data
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
 * @param filter filter state associated with current unit instance (which may be null)
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
 * @param filter filter state associated with current unit instance (which may be null)
 * @return true if mininum number of bytes are available; false if end-of-data
 * has been reached
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
 * @param filter filter state associated with current unit instance (which may be null)
 * @return true if minimum number of bytes are available; false if end-of-data
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
 * @param filter filter state associated with current unit instance (which may be null)
 * @return true if minimum number of bytes are available; false if end-of-data
 * has been reached
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
extern bool atEod(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                  hilti::rt::StrongReference<spicy::rt::filter::detail::Filters> filters);

/**
 * Manually trigger a backtrack operation, reverting back to the most revent &try.
 */
inline void backtrack() { throw Backtrack(); }

/**
 * Wrapper around hilti::rt::stream::View::find() that's more convinient to
 * call from Spicy's generated code.
 *
 * @param begin start of stream view to search
 * @param end end of stream view to search
 * @param i starting position to search from; must be inside the begin/end view
 * @param needle data to search
 * @param d direction to search from starting position
 * @returns position of first byte where needle was found, or unset optional if not found
 */
std::optional<hilti::rt::stream::SafeConstIterator> unitFind(
    const hilti::rt::stream::SafeConstIterator& begin, const hilti::rt::stream::SafeConstIterator& end,
    const std::optional<hilti::rt::stream::SafeConstIterator>& i, const hilti::rt::Bytes& needle,
    hilti::rt::stream::Direction d);
} // namespace detail
} // namespace spicy::rt
