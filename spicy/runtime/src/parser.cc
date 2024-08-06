// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <limits>
#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>

#include <spicy/rt/configuration.h>
#include <spicy/rt/debug.h>
#include <spicy/rt/global-state.h>
#include <spicy/rt/parser.h>

using namespace spicy::rt;
using namespace spicy::rt::detail;

HILTI_EXCEPTION_IMPL(Backtrack)
HILTI_EXCEPTION_IMPL(MissingData);
HILTI_EXCEPTION_IMPL(ParseError)

void spicy::rt::Parser::_initProfiling() {
    // Cache profiler tags to avoid recomputing them frequently.
    assert(! name.empty());
    profiler_tags.prepare_block.append(name);
    profiler_tags.prepare_input.append(name);
    profiler_tags.prepare_stream.append(name);
}

void spicy::rt::accept_input() {
    if ( const auto& hook = configuration::detail::unsafeGet().hook_accept_input )
        (*hook)();
}

void spicy::rt::decline_input(const std::string& reason) {
    if ( const auto& hook = configuration::detail::unsafeGet().hook_decline_input )
        (*hook)(reason);
}

void detail::printParserState(std::string_view unit_id, const hilti::rt::ValueReference<hilti::rt::Stream>& data,
                              const std::optional<hilti::rt::stream::SafeConstIterator>& begin,
                              const hilti::rt::stream::View& cur, int64_t lahead,
                              const hilti::rt::stream::SafeConstIterator& lahead_end, std::string_view literal_mode,
                              bool trim, const std::optional<hilti::rt::RecoverableFailure>& error) {
    auto msg = [&]() {
        auto str = [&](const hilti::rt::stream::SafeConstIterator& begin,
                       const hilti::rt::stream::SafeConstIterator& end) {
            auto i = begin + 10;
            if ( i >= end )
                return std::make_pair(hilti::rt::stream::View(begin, end), "");

            return std::make_pair(hilti::rt::stream::View(begin, i), "...");
        };

        auto na = hilti::rt::Stream("n/a");
        hilti::rt::stream::View lah_data = na.view();
        std::string lah_str = "n/a";
        std::string lah_dots;

        auto [input_data, input_dots] = str(cur.begin(), cur.end());

        if ( lahead && ! cur.begin().isEnd() ) {
            std::tie(lah_data, lah_dots) = str(cur.begin(), lahead_end);
            lah_str = hilti::rt::fmt("%" PRId32, lahead);
        }

        std::string begin_ = "-";
        if ( begin.has_value() )
            begin_ = hilti::rt::fmt("%" PRId64, begin->offset());

        return hilti::rt::fmt("- state: type=%s input=\"%s%s\" stream=%p offsets=%" PRId64 "/%s/%" PRId64 "/%" PRId64
                              "/%" PRId64 " chunks=%d frozen=%s mode=%s trim=%s lah=%" PRId64
                              " lah_token=\"%s%s\" recovering=%s",
                              unit_id, input_data, input_dots, data.get(), data->begin().offset(), begin_,
                              cur.begin().offset(), data->end().offset(), cur.end().offset(), data->numberOfChunks(),
                              (data->isFrozen() ? "yes" : "no"), literal_mode, (trim ? "yes" : "no"), lah_str, lah_data,
                              lah_dots, (error.has_value() ? "yes" : "no"));
    };

    SPICY_RT_DEBUG_VERBOSE(msg());
}

void detail::waitForEod(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                        hilti::rt::StrongReference<spicy::rt::filter::detail::Filters> filters) {
    auto min = std::numeric_limits<uint64_t>::max();

    if ( auto end_offset = cur.endOffset() )
        min = *end_offset - cur.offset();

    waitForInputOrEod(data, cur, min, std::move(filters));
}

void detail::waitForInput(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                          uint64_t min, std::string_view error_msg, std::string_view location,
                          hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>
                              filters) { // NOLINT(performance-unnecessary-value-param)
    while ( min > cur.size() )
        if ( ! waitForInputOrEod(data, cur, filters) ) {
            SPICY_RT_DEBUG_VERBOSE(
                hilti::rt::fmt("insufficient input at end of data for stream %p (which is not ok here)", data.get()));
            auto msg =
                hilti::rt::fmt("%s (%" PRIu64 " byte%s available)", error_msg, cur.size(), cur.size() != 1 ? "s" : "");
            throw ParseError(msg, std::string(location));
        }
}

bool detail::waitForInputOrEod(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                               uint64_t min,
                               hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>
                                   filters) { // NOLINT(performance-unnecessary-value-param)
    while ( min > cur.size() ) {
        if ( ! waitForInputOrEod(data, cur, filters) )
            return false;
    }

    return true;
}

bool detail::waitForInputOrEod(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                               const hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>& filters) {
    auto old = cur.size();
    auto new_ = cur.size();

    while ( old == new_ ) {
        if ( cur.isComplete() )
            return false;

        SPICY_RT_DEBUG_VERBOSE(hilti::rt::fmt("suspending to wait for more input for stream %p, currently have %lu",
                                              data.get(), cur.size()));
        hilti::rt::detail::yield();

        if ( filters ) {
            SPICY_RT_DEBUG_VERBOSE("resuming filter execution");
            spicy::rt::filter::flush(filters);
        }

        SPICY_RT_DEBUG_VERBOSE(
            hilti::rt::fmt("resuming after insufficient input, now have %lu for stream %p", cur.size(), data.get()));

        new_ = cur.size();
    }

    return true;
}

void detail::waitForInput(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                          std::string_view error_msg, std::string_view location,
                          const hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>& filters) {
    if ( ! waitForInputOrEod(data, cur, filters) ) {
        SPICY_RT_DEBUG_VERBOSE(
            hilti::rt::fmt("insufficient input at end of data for stream %p (which is not ok here)", data.get()));
        auto msg =
            hilti::rt::fmt("%s (%" PRIu64 " byte%s available)", error_msg, cur.size(), cur.size() != 1 ? "s" : "");
        throw ParseError(msg, std::string(location));
    }
}

bool detail::atEod(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                   const hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>& filters) {
    if ( cur.size() > 0 )
        return false;

    if ( cur.isComplete() )
        return true;

    // Wait until we have at least one byte available, because otherwise the
    // EOD could still come immediately with the next update of the input
    // stream.
    return ! waitForInputOrEod(data, cur, filters);
}

std::optional<hilti::rt::stream::SafeConstIterator> detail::unitFind(
    const hilti::rt::stream::SafeConstIterator& begin, const hilti::rt::stream::SafeConstIterator& end,
    const std::optional<hilti::rt::stream::SafeConstIterator>& i, const hilti::rt::Bytes& needle,
    hilti::rt::stream::Direction d) {
    std::tuple<bool, hilti::rt::stream::SafeConstIterator> v;
    if ( i )
        v = hilti::rt::stream::View(begin, end).find(needle, *i, d);
    else
        v = hilti::rt::stream::View(begin, end).find(needle, d);

    if ( std::get<0>(v) )
        return std::get<1>(v);
    else
        return {};
}
spicy::rt::ParseError::ParseError(std::string_view msg, std::string_view location)
    : RecoverableFailure(msg, location) {}
spicy::rt::ParseError::ParseError(const hilti::rt::result::Error& e) : RecoverableFailure(e.description()) {}
std::string hilti::rt::detail::adl::to_string(const ::spicy::rt::Direction& x, adl::tag /*unused*/) {
    switch ( x.value() ) {
        case spicy::rt::Direction::Originator: return "originator";
        case spicy::rt::Direction::Responder: return "responder";
        case spicy::rt::Direction::Both: return "both";
        case spicy::rt::Direction::Undef: return "undefined";
    }

    cannot_be_reached();
};
std::ostream& spicy::rt::operator<<(std::ostream& out, const Direction& d) { return out << hilti::rt::to_string(d); }
spicy::rt::ParserPort::ParserPort(std::tuple<hilti::rt::Port, Direction> args)
    : port(std::get<0>(args)), direction(std::get<1>(args)) {}
std::ostream& spicy::rt::operator<<(std::ostream& out, const ParserPort& p) { return out << hilti::rt::to_string(p); }
std::string hilti::rt::detail::adl::to_string(const spicy::rt::ParserPort& x, adl::tag /*unused*/) {
    // TODO: Not sure why we need to explicit to_string() here.
    if ( x.direction == spicy::rt::Direction::Both )
        return x.port;
    else
        return fmt("%s (%s direction)", x.port, x.direction);
}
spicy::rt::Parser::Parser(std::string_view name, bool is_public, Parse1Function parse1, hilti::rt::any parse2,
                          Parse3Function parse3, ContextNewFunction context_new, const hilti::rt::TypeInfo* type,
                          std::string description, hilti::rt::Vector<MIMEType> mime_types,
                          hilti::rt::Vector<ParserPort> ports)
    : name(name),
      is_public(is_public),
      parse1(parse1),
      parse2(std::move(parse2)),
      parse3(parse3),
      context_new(context_new),
      type_info(type),
      description(std::move(description)),
      mime_types(std::move(mime_types)),
      ports(std::move(ports)) {
    _initProfiling();
}
spicy::rt::Parser::Parser(std::string_view name, bool is_public, Parse1Function parse1, hilti::rt::any parse2,
                          Parse3Function parse3, hilti::rt::Null /* null */, const hilti::rt::TypeInfo* type,
                          std::string description, hilti::rt::Vector<MIMEType> mime_types,
                          hilti::rt::Vector<ParserPort> ports)
    : name(name),
      is_public(is_public),
      parse1(parse1),
      parse2(std::move(parse2)),
      parse3(parse3),
      type_info(type),
      description(std::move(description)),
      mime_types(std::move(mime_types)),
      ports(std::move(ports)) {
    _initProfiling();
}
spicy::rt::Parser::Parser(std::string_view name, bool is_public, hilti::rt::Null /* null */, hilti::rt::any parse2,
                          hilti::rt::Null /* null */, hilti::rt::Null /* null */, const hilti::rt::TypeInfo* type,
                          std::string description, hilti::rt::Vector<MIMEType> mime_types,
                          hilti::rt::Vector<ParserPort> ports)
    : Parser(name, is_public, nullptr, std::move(parse2), nullptr, nullptr, type, std::move(description),
             std::move(mime_types), std::move(ports)) {
    _initProfiling();
}
spicy::rt::Parser::Parser(std::string_view name, bool is_public, hilti::rt::Null /* null */, hilti::rt::any parse2,
                          hilti::rt::Null /* null */, ContextNewFunction context_new, const hilti::rt::TypeInfo* type,
                          std::string description, hilti::rt::Vector<MIMEType> mime_types,
                          hilti::rt::Vector<ParserPort> ports)
    : Parser(name, is_public, nullptr, std::move(parse2), nullptr, context_new, type, std::move(description),
             std::move(mime_types), std::move(ports)) {
    _initProfiling();
}
std::optional<UnitContext> spicy::rt::Parser::createContext() const {
    if ( context_new )
        return (*context_new)();
    else
        return {};
}
std::vector<const Parser*> spicy::rt::parsers() {
    const auto& parsers = detail::globalState()->parsers;

    std::vector<const Parser*> public_parsers;
    std::copy_if(parsers.begin(), parsers.end(), std::back_inserter(public_parsers),
                 [](const auto& p) { return p->is_public; });

    return public_parsers;
}
spicy::rt::Backtrack::Backtrack() : ParseError("backtracking outside of &try scope") {}
spicy::rt::MissingData::MissingData(std::string_view location) : ParseError("missing data", location) {}
void spicy::rt::detail::backtrack() { throw Backtrack(); }
