// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <spicy/rt/parser.h>
#include <spicy/rt/sink.h>

using namespace spicy::rt;
using namespace spicy::rt::detail;

using hilti::rt::fmt;

HILTI_EXCEPTION_IMPL(SinkError)

void Sink::_init() {
    assert(_states.empty() && _units.empty()); // must have been release already

    _policy = sink::ReassemblerPolicy::First;
    _auto_trim = true;
    _size = 0;
    _initial_seq = 0;
    _cur_rseq = 0;
    _last_reassem_rseq = 0;
    _trim_rseq = 0;
    _chunks.clear();
}

Sink::ChunkList::iterator Sink::_addAndCheck(hilti::rt::Optional<hilti::rt::Bytes> data, uint64_t rseq, uint64_t rupper,
                                             ChunkList::iterator c) {
    assert(! _chunks.empty());

    // Special check for the common case of appending to the end.
    if ( rseq == _chunks.back().rupper ) {
        _chunks.emplace_back(std::move(data), rseq, rupper);
        return std::next(_chunks.end(), -1);
    }

    // Find the first block that doesn't come completely before the new data.
    for ( ; c != _chunks.end() && c->rupper <= rseq; c++ )
        ;

    if ( c == _chunks.end() ) {
        // c is the last block, and it comes completely before the new block.
        _chunks.emplace_back(std::move(data), rseq, rupper);
        return std::next(_chunks.end(), -1);
    }

    if ( rupper <= c->rseq )
        // The new block comes completely before c.
        return _chunks.insert(c, Chunk(std::move(data), rseq, rupper));

    ChunkList::iterator new_c;

    // The blocks overlap, complain & break up.

    if ( rseq < c->rseq ) {
        // The new block has a prefix that comes before c.
        uint64_t prefix_len = c->rseq - rseq;

        if ( data ) {
            auto prefix = data->sub(data->begin() + prefix_len);
            new_c = _chunks.insert(c, Chunk(std::move(prefix), rseq, rseq + prefix_len));
            data = data->sub(data->begin() + prefix_len, data->end());
        }

        rseq += prefix_len;
    }

    else
        new_c = c;

    auto overlap_start = rseq;
    auto new_c_len = rupper - rseq;
    auto c_len = (c->rupper - overlap_start);
    auto overlap_len = (new_c_len < c_len ? new_c_len : c_len);

    hilti::rt::Bytes old_data;
    hilti::rt::Bytes new_data;

    if ( c->data )
        old_data = c->data->sub(overlap_start - c->rseq, overlap_start - c->rseq + overlap_len);

    if ( data )
        new_data = data->sub(overlap_len);

    _reportOverlap(overlap_start, old_data, new_data);

    if ( data && overlap_len < new_c_len ) {
        // Recurse to resolve remainder of the new data.
        data = data->sub(data->begin() + overlap_len, data->end());
        rseq += overlap_len;

        if ( new_c == c )
            new_c = _addAndCheck(std::move(data), rseq, rupper, c);
        else
            _addAndCheck(std::move(data), rseq, rupper, c);
    }

    return new_c;
}

bool Sink::_deliver(hilti::rt::Optional<hilti::rt::Bytes> data, uint64_t rseq, uint64_t rupper) {
    if ( ! data ) {
        // A gap.
        SPICY_RT_DEBUG_VERBOSE(fmt("hit gap with sink %p at rseq %" PRIu64, this, rseq));

        if ( _cur_rseq != rupper ) {
            _reportGap(rseq, (rupper - rseq));
            _cur_rseq = rupper;
        }

        return false;
    }

    if ( data->size() == 0 )
        // Empty chunk, nothing to do.
        return true;

    SPICY_RT_DEBUG_VERBOSE(
        fmt("starting to deliver %" PRIu64 " bytes to sink %p at rseq %" PRIu64, data->size(), this, rseq));

    if ( _filter ) {
        if ( ! _filter_data ) {
            // Initialize on first data.
            _filter_data = FilterData();
            _filter_data->output =
                spicy::rt::filter::init(_filter, nullptr, _filter_data->input, _filter_data->input->view());
            _filter_data->output_cur = (*_filter_data->output).view();
        }

        _filter_data->input->append(std::move(*data));
        spicy::rt::filter::flush(_filter, nullptr);

        data = _filter_data->output_cur.data();
        _filter_data->output_cur = _filter_data->output_cur.advance(data->size());

        if ( data->size() == 0 )
            // Empty chunk coming out of filter, nothing to do.
            return true;
    }

    _size += data->size();

    std::vector<sink::detail::State*> states;
    states.reserve(_states.size());
    for ( auto* s : _states ) {
        if ( s->skip_delivery )
            continue;

        if ( s->resumable )
            throw ParseError("more data after sink's unit has already completed parsing");

        states.push_back(s);
    }

    for ( auto* s : states ) {
        if ( states.size() == 1 )
            s->data->append(std::move(*data));
        else
            s->data->append(*data);

        try {
            // Sinks are operating independently from the writer, so we
            // don't forward errors on.
            s->resumable.resume();
        } catch ( const hilti::rt::RuntimeError& err ) {
            SPICY_RT_DEBUG_VERBOSE(
                fmt("error in connected unit %s, aborting delivery (%s)", s->parser->name, err.what()));
            s->skip_delivery = true;
        }
    }

    _cur_rseq = rupper;
    _last_reassem_rseq = rupper;

    SPICY_RT_DEBUG_VERBOSE(fmt("done delivering to sink %p", this));
    return true;
}

void Sink::_newData(hilti::rt::Optional<hilti::rt::Bytes> data, uint64_t rseq, uint64_t len) {
    if ( len == 0 )
        // Nothing to do.
        return;

    // Fast-path: if it's right at the end of the input stream, we
    // haven't anything buffered, and we do auto-trimming, just pass on.
    if ( _auto_trim && _chunks.empty() && rseq == _cur_rseq ) {
        _debugReassembler("fastpath new data", data, rseq, len);
        _deliver(std::move(data), rseq, rseq + len);
        return;
    }

    _debugReassembler("buffering data", data, rseq, len);

    ChunkList::iterator c;
    auto rupper_rseq = rseq + len;

    if ( rupper_rseq <= _trim_rseq )
        // Old data, don't do any work for it.
        goto exit;

    if ( rseq < _trim_rseq ) {
        // Partially old data, just keep the good stuff.
        auto amount_old = _trim_rseq - rseq;
        rseq += amount_old;

        if ( data )
            data = data->sub(data->begin() + amount_old, data->end());
    }

    if ( _chunks.empty() ) {
        _chunks.emplace_back(std::move(data), rseq, rseq + len);
        c = std::next(_chunks.end(), -1);
    }
    else
        c = _addAndCheck(std::move(data), rseq, rupper_rseq, _chunks.begin());

    // See if we have data in order now to deliver.

    if ( c->rseq > _last_reassem_rseq || c->rupper <= _last_reassem_rseq )
        goto exit;

    // We've filled a leading hole. Deliver as much as possible.
    _debugReassemblerBuffer("buffer content");

    _tryDeliver(c);
    return;

exit:
    _debugReassemblerBuffer("buffer content");
}

void Sink::_skip(uint64_t rseq) {
    SPICY_RT_DEBUG_VERBOSE(fmt("skipping sink %p to rseq %" PRIu64, this, rseq));

    if ( _auto_trim )
        _trim(rseq); // will report undelivered
    else
        _reportUndeliveredUpTo(rseq);

    _cur_rseq = rseq;
    _last_reassem_rseq = rseq;

    _reportSkipped(rseq);
    _tryDeliver(_chunks.begin());
}

void Sink::_trim(uint64_t rseq) {
    if ( rseq != UINT64_MAX ) {
        SPICY_RT_DEBUG_VERBOSE(fmt("trimming sink %p to rseq %" PRIu64, this, rseq));
    }
    else {
        SPICY_RT_DEBUG_VERBOSE(fmt("trimming sink %p to EOD", this));
    }

    for ( auto c = _chunks.begin(); c != _chunks.end(); c = _chunks.erase(c) ) {
        if ( c->rseq >= rseq )
            break;

        if ( c->data && _cur_rseq < c->rseq )
            _reportUndelivered(c->rseq, *c->data);
    }

    _trim_rseq = rseq;
}

void Sink::_tryDeliver(ChunkList::iterator c) {
    // Note that a new block may include both some old stuff and some new
    // stuff. _addAndCheck() will have split the new stuff off into its own
    // block(s), but in the following loop we have to take care not to
    // deliver already-delivered data.

    for ( ; c != _chunks.end(); c++ ) {
        if ( c->rseq == _last_reassem_rseq ) {
            // New stuff.
            _last_reassem_rseq += (c->rupper - c->rseq);
            if ( ! _deliver(c->data, c->rseq, c->rupper) ) {
                // Hit gap.
                if ( _auto_trim )
                    // We trim just up to the gap here, excluding the gap itself.
                    // This will prevent future data beyond the gap from being
                    // delivered until we explicitly skip over it.
                    _trim(c->rseq);

                break;
            }
        }
    }

    if ( _auto_trim )
        _trim(_last_reassem_rseq);
}

void Sink::_reportGap(uint64_t rseq, uint64_t len) const {
    SPICY_RT_DEBUG_VERBOSE(fmt("reporting gap in sink %p at rseq %" PRIu64, this, rseq));

    for ( size_t i = 0; i < _states.size(); i++ ) {
        if ( auto h = *_states[i]->parser->__hook_gap )
            h(_units[i], _aseq(rseq), len);
    }
}

void Sink::_reportOverlap(uint64_t rseq, const hilti::rt::Bytes& old, const hilti::rt::Bytes& new_) const {
    SPICY_RT_DEBUG_VERBOSE(fmt("reporting overlap in sink %p at rseq %" PRIu64, this, rseq));

    for ( size_t i = 0; i < _states.size(); i++ )
        if ( auto h = (*_states[i]->parser->__hook_overlap) )
            h(_units[i], _aseq(rseq), old, new_);
}

void Sink::_reportSkipped(uint64_t rseq) const {
    SPICY_RT_DEBUG_VERBOSE(fmt("reporting skipped in sink %p to rseq %" PRIu64, this, rseq));

    for ( size_t i = 0; i < _states.size(); i++ )
        if ( auto h = (*_states[i]->parser->__hook_skipped) )
            h(_units[i], _aseq(rseq));
}

void Sink::_reportUndelivered(uint64_t rseq, const hilti::rt::Bytes& data) const {
    SPICY_RT_DEBUG_VERBOSE(fmt("reporting undelivered in sink %p at rseq %" PRIu64, this, rseq));

    for ( size_t i = 0; i < _states.size(); i++ )
        if ( auto h = (*_states[i]->parser->__hook_undelivered) )
            h(_units[i], _aseq(rseq), data);
}

void Sink::_reportUndeliveredUpTo(uint64_t rupper) const {
    for ( const auto& c : _chunks ) {
        if ( c.rseq >= rupper )
            break;

        if ( ! c.data )
            continue;

        hilti::rt::Bytes b;

        if ( c.rupper <= rupper )
            b = *c.data;

        else
            b = c.data->sub(c.rupper - rupper);

        _reportUndelivered(c.rseq, b);
    }
}

void Sink::_debugReassembler(std::string_view msg, const hilti::rt::Optional<hilti::rt::Bytes>& data, uint64_t rseq,
                             uint64_t len) const {
    if ( ! debug::wantVerbose() )
        return;

    if ( data ) {
        auto escaped = hilti::rt::escapeBytes(data->str());
        if ( escaped.size() > 50 )
            escaped = escaped.substr(0, 50) + "...";

        SPICY_RT_DEBUG_VERBOSE(fmt("reassembler/%p: %s rseq=% " PRIu64 " upper=%" PRIu64 " |%s| (%" PRIu64 " bytes)",
                                   this, msg, rseq, rseq + len, escaped, data->size()));
    }
    else
        SPICY_RT_DEBUG_VERBOSE(
            fmt("reassembler/%p: %s rseq=% " PRIu64 " upper=%" PRIu64 " <gap>", this, msg, rseq, rseq + len));
}

void Sink::_debugReassemblerBuffer(std::string_view msg) const {
    if ( ! debug::wantVerbose() )
        return;

    if ( _chunks.empty() ) {
        SPICY_RT_DEBUG_VERBOSE(fmt("reassembler/%p: no data buffered", this));
        return;
    }

    SPICY_RT_DEBUG_VERBOSE(
        fmt("reassembler/%p: %s: ("
            "cur_rseq=%" PRIu64 " "
            "last_reassem_rseq=%" PRIu64 " "
            "trim_rseq=%" PRIu64 ")",
            this, msg, _cur_rseq, _last_reassem_rseq, _trim_rseq));

    for ( const auto&& [i, c] : hilti::rt::enumerate(_chunks) ) // not auto&, always copied anyways
        _debugReassembler(fmt("  * chunk %d:", i), c.data, c.rseq, (c.rupper - c.rseq));
}

void Sink::connect_mime_type(const MIMEType& mt, uint64_t scope) {
    auto connect_matching = [&](const auto& mt) {
        if ( const auto& x = detail::globalState()->parsers_by_mime_type.find(mt.asKey());
             x != detail::globalState()->parsers_by_mime_type.end() ) {
            for ( const auto& p : x->second ) {
                // We only connect to public parsers or parsers in the same linker scope.
                if ( ! p->is_public && p->linker_scope != scope )
                    continue;

                if ( auto h = *p->__parse_sink ) {
                    auto m = (*p->__parse_sink)(); // using a structured binding here triggers what seems to be a
                                                   // clang-tidy false positive

                    SPICY_RT_DEBUG_VERBOSE(fmt("connecting parser %s [%p] to sink %p for MIME type %s", p->name,
                                               &m.first, this, std::string(mt)));
                    _units.emplace_back(std::move(m.first));
                    _states.emplace_back(m.second);
                }
            }
        }
    };

    connect_matching(mt);
    connect_matching(MIMEType(mt.mainType(), "*"));
    connect_matching(MIMEType("*", "*"));
}

void Sink::_close(bool orderly) {
    spicy::rt::filter::disconnect(_filter, nullptr);
    _filter_data = hilti::rt::Null();

    if ( _states.size() ) {
        SPICY_RT_DEBUG_VERBOSE(
            fmt("closing sink, disconnecting parsers from sink %p%s", this, (orderly ? "" : " (abort)")));

        for ( auto* s : _states ) {
            if ( ! s->resumable ) {
                s->data->freeze();

                try {
                    // Sinks are operating independently from the writer, so we
                    // don't forward errors on.
                    if ( orderly && ! s->skip_delivery )
                        s->resumable.resume();
                    else
                        s->resumable.abort();
                } catch ( const hilti::rt::RuntimeError& err ) {
                    SPICY_RT_DEBUG_VERBOSE(
                        fmt("error in connected unit %s during close (%s)", s->parser->name, err.what()));
                }

                assert(s->resumable); // must have conluded after freezing/aborting
            }

            delete s; // NOLINT
        }

        _states.clear();
        _units.clear();
    }

    _init();
}

void Sink::gap(uint64_t seq, uint64_t len) { _newData({}, _rseq(seq), len); }

void Sink::skip(uint64_t seq) {
    _skip(_rseq(seq));
    _debugReassemblerBuffer("buffer after skip");
}

void Sink::trim(uint64_t seq) {
    _trim(_rseq(seq));
    _debugReassemblerBuffer("buffer after trim");
}

void Sink::write(hilti::rt::Bytes data, hilti::rt::Optional<uint64_t> seq, hilti::rt::Optional<uint64_t> len) {
    if ( ! data.size() )
        return;

    uint64_t n;

    if ( len )
        n = *len;
    else
        n = data.size();

    if ( seq )
        _newData(std::move(data), _rseq(*seq), n);
    else
        // Just append.
        _newData(std::move(data), _cur_rseq, n);
}

namespace hilti::rt::detail::adl {
std::string to_string(const Sink& /*x*/, tag /*unused*/) { return "<sink>"; }

std::string to_string(const sink::ReassemblerPolicy& x, tag /*unused*/) {
    switch ( x ) {
        case spicy::rt::sink::ReassemblerPolicy::First: return "sink::ReassemblerPolicy::First";
    }

    cannot_be_reached();
}
} // namespace hilti::rt::detail::adl
