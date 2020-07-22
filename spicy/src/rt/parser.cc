// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <limits>
#include <utility>

#include <hilti/rt/types/bytes.h>

#include <spicy/rt/debug.h>
#include <spicy/rt/parser.h>

using namespace spicy::rt;
using namespace spicy::rt::detail;

void detail::printParserState(const std::string& unit_id, const hilti::rt::ValueReference<hilti::rt::Stream>& data,
                              const hilti::rt::stream::View& cur, int64_t lahead,
                              const hilti::rt::stream::SafeConstIterator& lahead_end, const std::string& literal_mode,
                              bool trim) {
    auto str = [&](const hilti::rt::stream::SafeConstIterator& begin, const hilti::rt::stream::SafeConstIterator& end) {
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

    auto msg = hilti::rt::fmt("- state: type=%s input=\"%s%s\" stream=%p offsets=%" PRId64 "/%" PRId64 "/%" PRId64
                              " chunks=%d frozen=%s mode=%s trim=%s lah=%" PRId64 " lah_token=\"%s%s\"",
                              unit_id, input_data, input_dots, data.get(), data->begin().offset(), cur.begin().offset(),
                              data->end().offset(), data->numberChunks(), (data->isFrozen() ? "yes" : "no"),
                              literal_mode, (trim ? "yes" : "no"), lah_str, lah_data, lah_dots);

    SPICY_RT_DEBUG_VERBOSE(msg);
}

void detail::waitForEod(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                        hilti::rt::StrongReference<spicy::rt::filter::detail::Filters> filters) {
    auto min = std::numeric_limits<uint64_t>::max();

    if ( ! cur.isOpenEnded() )
        min = cur.unsafeEnd().offset() - cur.unsafeBegin().offset();

    waitForInputOrEod(data, cur, min, std::move(filters));
}

void detail::waitForInput(hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur,
                          uint64_t min, const std::string& error_msg, const std::string& location,
                          hilti::rt::StrongReference<spicy::rt::filter::detail::Filters>
                              filters) { // NOLINT(performance-unnecessary-value-param)
    while ( min > cur.size() )
        if ( ! waitForInputOrEod(data, cur, filters) ) {
            SPICY_RT_DEBUG_VERBOSE(
                hilti::rt::fmt("insufficent input at end of data for stream %p (which is not ok here)", data.get()));
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
        if ( detail::haveEod(data, cur) )
            return false;

        SPICY_RT_DEBUG_VERBOSE(hilti::rt::fmt("suspending to wait for more input for stream %p, currently have %lu",
                                              data.get(), cur.size()));
        hilti::rt::detail::yield();

        auto x = cur.end();
        x += 0;

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
            hilti::rt::fmt("insufficent input at end of data for stream %p (which is not ok here)", data.get()));
        throw ParseError(error_msg, location);
    }
}

bool detail::atEod(const hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur) {
    return cur.size() == 0 && detail::haveEod(data, cur);
}

bool detail::haveEod(const hilti::rt::ValueReference<hilti::rt::Stream>& data, const hilti::rt::stream::View& cur) {
    return data->isFrozen() || cur.unsafeEnd().offset() < data->unsafeEnd().offset();
    // We've the reached end-of-data if either (1) the bytes object is frozen
    // (then the input won't change anymore), or (2) our view is limited to
    // something before the current end (then even appending more data to the
    // input won't help).
    if ( data->isFrozen() )
        return true;

    if ( cur.isOpenEnded() )
        return false;

    return cur.unsafeEnd().offset() <= data->unsafeEnd().offset();
}
