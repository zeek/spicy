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

        auto begin_offset = data->begin().offset();
        auto end_offset = data->end().offset();

        return hilti::rt::fmt("- state: type=%s input=\"%s%s\" stream=%p offsets=%" PRId64 "/%s/%" PRId64 "/%" PRId64
                              "/%" PRId64 " chunks=%d frozen=%s mode=%s trim=%s lah=%" PRId64
                              " lah_token=\"%s%s\" recovering=%s",
                              unit_id, input_data, input_dots, data.get(), begin_offset, begin_, cur.begin().offset(),
                              end_offset, cur.end().offset(), data->numberOfChunks(), (data->isFrozen() ? "yes" : "no"),
                              literal_mode, (trim ? "yes" : "no"), lah_str, lah_data, lah_dots,
                              (error.has_value() ? "yes" : "no"));
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

hilti::rt::Bytes detail::extractBytes(hilti::rt::ValueReference<hilti::rt::Stream>& data,
                                      const hilti::rt::stream::View& cur, uint64_t size, bool eod_ok,
                                      std::string_view location,
                                      const hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>& filters) {
    if ( eod_ok )
        detail::waitForInputOrEod(data, cur, size, filters);
    else
        detail::waitForInput(data, cur, size, hilti::rt::fmt("expected %" PRIu64 " bytes", size), location, filters);

    return cur.sub(cur.begin() + size).data();
}

void detail::expectBytesLiteral(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                                const hilti::rt::Bytes& literal, std::string_view location,
                                const hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>& filters) {
    detail::waitForInput(data, cur, literal.size(),
                         hilti::rt::fmt("expected %" PRIu64 R"( bytes for bytes literal "%s")", literal.size(),
                                        literal),
                         location, filters);
    if ( ! cur.startsWith(literal) ) {
        auto content = cur.sub(cur.begin() + literal.size()).data();
        throw ParseError(hilti::rt::fmt(R"(expected bytes literal "%s" but input starts with "%s")", literal, content),
                         location);
    }
}
