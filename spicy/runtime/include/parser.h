// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <hilti/rt/exception.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/result.h>
#include <hilti/rt/type-info.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/null.h>
#include <hilti/rt/types/port.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/struct.h>
#include <hilti/rt/util.h>

#include <spicy/rt/filter.h>
#include <spicy/rt/global-state.h>
#include <spicy/rt/mime.h>
#include <spicy/rt/parser-fwd.h>
#include <spicy/rt/sink.h>
#include <spicy/rt/typedefs.h>

namespace spicy::rt {

/** Defines the direction a `ParserPort` applies to. */
HILTI_RT_ENUM(Direction, Originator, Responder, Both, Undef);

} // namespace spicy::rt

namespace hilti::rt::detail::adl {

std::string to_string(const ::spicy::rt::Direction& x, adl::tag /*unused*/);

} // namespace hilti::rt::detail::adl

namespace spicy::rt {

std::ostream& operator<<(std::ostream& out, const Direction& d);

/** Defines port & direction a parser can handle.  */
struct ParserPort {
    hilti::rt::Port port;
    Direction direction;

    // Constructor used by code generator.
    ParserPort(std::tuple<hilti::rt::Port, Direction> args);
};

std::ostream& operator<<(std::ostream& out, const ParserPort& p);

} // namespace spicy::rt

namespace hilti::rt::detail::adl {

std::string to_string(const spicy::rt::ParserPort& x, adl::tag /*unused*/);

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
    Parser(std::string_view name, bool is_public, Parse1Function parse1, hilti::rt::any parse2, Parse3Function parse3,
           ContextNewFunction context_new, const hilti::rt::TypeInfo* type, std::string description,
           hilti::rt::Vector<MIMEType> mime_types, hilti::rt::Vector<ParserPort> ports);

    Parser(std::string_view name, bool is_public, Parse1Function parse1, hilti::rt::any parse2, Parse3Function parse3,
           hilti::rt::Null /* null */, const hilti::rt::TypeInfo* type, std::string description,
           hilti::rt::Vector<MIMEType> mime_types, hilti::rt::Vector<ParserPort> ports);

    Parser(std::string_view name, bool is_public, hilti::rt::Null /* null */, hilti::rt::any parse2,
           hilti::rt::Null /* null */, hilti::rt::Null /* null */, const hilti::rt::TypeInfo* type,
           std::string description, hilti::rt::Vector<MIMEType> mime_types, hilti::rt::Vector<ParserPort> ports);

    Parser(std::string_view name, bool is_public, hilti::rt::Null /* null */, hilti::rt::any parse2,
           hilti::rt::Null /* null */, ContextNewFunction context_new, const hilti::rt::TypeInfo* type,
           std::string description, hilti::rt::Vector<MIMEType> mime_types, hilti::rt::Vector<ParserPort> ports);

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
    std::optional<UnitContext> createContext() const;

    /** Short descriptive name. */
    std::string_view name;

    /** Whether this parser is public. */
    bool is_public;

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

    /** Type-information for puarser's unit. */
    const hilti::rt::TypeInfo* type_info;

    /** Pre-computed profiler tags used by the runtime driver. */
    struct {
        std::string prepare_block = "spicy/prepare/block/";
        std::string prepare_input = "spicy/prepare/input/";
        std::string prepare_stream = "spicy/prepare/stream/";

        operator bool() const {
            // ensure initialization code has run
            return ! prepare_input.empty();
        }
    } profiler_tags;

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
    detail::ParseSinkFunction __parse_sink = nullptr;

    /** For internal use only. Dispatcher for the corresponding unit hook. */
    void (*__hook_gap)(const hilti::rt::StrongReferenceGeneric&, uint64_t, uint64_t) = nullptr;

    /** For internal use only. Dispatcher for the corresponding unit hook. */
    void (*__hook_overlap)(const hilti::rt::StrongReferenceGeneric&, uint64_t, const hilti::rt::Bytes&,
                           const hilti::rt::Bytes&) = nullptr;

    /** For internal use only. Dispatcher for the corresponding unit hook. */
    void (*__hook_skipped)(const hilti::rt::StrongReferenceGeneric&, uint64_t) = nullptr;

    /** For internal use only. Dispatcher for the corresponding unit hook. */
    void (*__hook_undelivered)(const hilti::rt::StrongReferenceGeneric&, uint64_t, const hilti::rt::Bytes&) = nullptr;

private:
    void _initProfiling();
};

/** Returns all available public parsers. */
std::vector<const Parser*> parsers();

/**
 * Exception thrown by generated parser code when an parsing failed.
 */
class ParseError : public hilti::rt::RecoverableFailure {
public:
    ParseError(std::string_view msg, std::string_view location = "");

    ParseError(const hilti::rt::result::Error& e);

    ~ParseError() override; /* required to create vtable, see hilti::rt::Exception */
};

/**
 * Exception triggering backtracking to the most recent ``&try``. Derived from
 * ``ParseError`` so that if it's not caught, it turns into a regular parsing
 * error.
 */
class Backtrack : public ParseError {
public:
    Backtrack();
    ~Backtrack() override;
};

class MissingData : public ParseError {
public:
    MissingData(std::string_view location = "");
    ~MissingData() override; /* required to create vtable, see hilti::rt::Exception */
};

/**
 * Reports a confirmation to the host application indicating that the parser
 * appears to be processing the expected input format.
 */
extern void accept_input();

/**
 * Reports a violation to the host application indicating that the parser
 * appears to not be processing the expected input format.
 *
 * @param reason user-presentable description of the violation
 */
extern void decline_input(const std::string& reason);

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
                   ! std::is_base_of_v<hilti::rt::trait::hasParameters, unit_type> )
        p.__parse_sink = []() {
            auto unit = spicy::rt::UnitRef<unit_type>(unit_type());
            return std::make_pair(hilti::rt::StrongReferenceGeneric(unit), spicy::rt::sink::detail::connectUnit(unit));
        };

    if constexpr ( detail::has_on_gap<unit_type>::value )
        p.__hook_gap = [](const hilti::rt::StrongReferenceGeneric& u, uint64_t seq, uint64_t len) -> void {
            (u.as<unit_type>()->__on_0x25_gap)(seq, len);
        };

    if constexpr ( detail::has_on_skipped<unit_type>::value )
        p.__hook_skipped = [](const hilti::rt::StrongReferenceGeneric& u, uint64_t seq) -> void {
            (u.as<unit_type>()->__on_0x25_skipped)(seq);
        };

    if constexpr ( detail::has_on_overlap<unit_type>::value )
        p.__hook_overlap = [](const hilti::rt::StrongReferenceGeneric& u, uint64_t seq, const hilti::rt::Bytes& old,
                              const hilti::rt::Bytes& new_) -> void {
            (u.as<unit_type>()->__on_0x25_overlap)(seq, old, new_);
        };

    if constexpr ( detail::has_on_undelivered<unit_type>::value )
        p.__hook_undelivered = [](const hilti::rt::StrongReferenceGeneric& u, uint64_t seq,
                                  const hilti::rt::Bytes& bytes) -> void {
            (u.as<unit_type>()->__on_0x25_undelivered)(seq, bytes);
        };
}

/**
 * Prints the current parser state, as passed in through arguments, to the
 * spicy-verbose debug stream.
 */
void printParserState(std::string_view unit_id, const hilti::rt::ValueReference<hilti::rt::Stream>& data,
                      const std::optional<hilti::rt::stream::SafeConstIterator>& begin,
                      const hilti::rt::stream::View& cur, int64_t lahead,
                      const hilti::rt::stream::SafeConstIterator& lahead_end, std::string_view literal_mode, bool trim,
                      const std::optional<hilti::rt::RecoverableFailure>& error);

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
 * @return true if minimum number of bytes are available; false if end-of-data
 * has been reached
 */
extern void waitForInput(hilti::rt::ValueReference<hilti::rt::Stream>& data, // NOLINT(google-runtime-references)
                         const hilti::rt::stream::View& cur, uint64_t min, std::string_view error_msg,
                         std::string_view location,
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
                         const hilti::rt::stream::View& cur, std::string_view error_msg, std::string_view location,
                         const hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>& filters);

/**
 * Used by generated parsers to recognize end-of-data.
 *
 * @param data current input data
 * @param cur view of *data* that's being parsed
 * @return true if end-of-data has been reached
 */
extern bool atEod(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                  const hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>& filters);

/**
 * Manually trigger a backtrack operation, reverting back to the most revent &try.
 */
void backtrack();

/**
 * Wrapper around hilti::rt::stream::View::find() that's more convenient to
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
