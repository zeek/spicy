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

void spicy::rt::accept_input() {
    if ( const auto& hook = configuration::detail::unsafeGet().hook_accept_input )
        (*hook)();
}

void spicy::rt::decline_input(const std::string& reason) {
    if ( const auto& hook = configuration::detail::unsafeGet().hook_decline_input )
        (*hook)(reason);
}

// Returns true if EOD can be seen already, even if not reached yet.
static bool _haveEod(const hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur) {
    // We've the reached end-of-data if either (1) the bytes object is frozen
    // (then the input won't change anymore), or (2) our view is limited to
    // something before the current end (then even appending more data to the
    // input won't help).
    if ( data->isFrozen() )
        return true;

    if ( auto end_offset = cur.endOffset() )
        return *end_offset <= data->endOffset();
    else
        return false;
}

void detail::printParserState(const std::string& unit_id, const hilti::rt::ValueReference<hilti::rt::Stream>& data,
                              const std::optional<hilti::rt::stream::SafeConstIterator>& begin,
                              const hilti::rt::stream::View& cur, int64_t lahead,
                              const hilti::rt::stream::SafeConstIterator& lahead_end, const std::string& literal_mode,
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
                              " chunks=%d frozen=%s mode=%s trim=%s lah=%" PRId64 " lah_token=\"%s%s\" recovering=%s",
                              unit_id, input_data, input_dots, data.get(), data->begin().offset(), begin_,
                              cur.begin().offset(), data->end().offset(), data->numberOfChunks(),
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
                          uint64_t min, const std::string& error_msg, const std::string& location,
                          hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>
                              filters) { // NOLINT(performance-unnecessary-value-param)
    while ( min > cur.size() )
        if ( ! waitForInputOrEod(data, cur, filters) ) {
            SPICY_RT_DEBUG_VERBOSE(
                hilti::rt::fmt("insufficient input at end of data for stream %p (which is not ok here)", data.get()));
            throw ParseError(error_msg, location);
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
        if ( _haveEod(data, cur) )
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
                          const std::string& error_msg, const std::string& location,
                          const hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>& filters) {
    if ( ! waitForInputOrEod(data, cur, filters) ) {
        SPICY_RT_DEBUG_VERBOSE(
            hilti::rt::fmt("insufficient input at end of data for stream %p (which is not ok here)", data.get()));
        throw ParseError(error_msg, location);
    }
}

bool detail::atEod(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                   const hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>& filters) {
    if ( cur.size() > 0 )
        return false;

    if ( _haveEod(data, cur) )
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
