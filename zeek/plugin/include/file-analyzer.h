// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>

// Zeek headers
#include "cookie.h"
#include <file_analysis/Manager.h>

#include <hilti/rt/types/stream.h>

#include <spicy/rt/parser.h>

#include <zeek-spicy/zeek-compat.h>

namespace spicy::zeek::rt {

/** A Spicy fil analyzer. */
class FileAnalyzer : public ::file_analysis::Analyzer {
public:
    FileAnalyzer(::zeek::RecordValPtr arg_args, file_analysis::File* arg_file);
    virtual ~FileAnalyzer();

    static file_analysis::Analyzer* InstantiateAnalyzer(::zeek::RecordValPtr args, file_analysis::File* file);

protected:
    // Overriden from Zeek's file analyzer.
    void Init() override;
    void Done() override;
    bool DeliverStream(const u_char* data, uint64_t len) override;
    bool Undelivered(uint64_t offset, uint64_t len) override;
    bool EndOfFile() override;

    /**
     * Feeds a chunk of data into parsing.
     *
     * @param len number of bytes valid in *data*
     * @param data pointer to data
     * @param eod true if not more data will be coming for this side of the session
     *
     * @return 1 if parsing finished succesfully; -1 0 if parsing failed; and
     * 0 if parsing is not yet complete, and hence yielded waiting for more
     * input. In the former two cases, no further input will be accepted.
     */
    int FeedChunk(int len, const u_char* data, bool eod);

    /** Records a debug message, optionally displaying input data. */
    void DebugMsg(const std::string_view& msg, int len = 0, const u_char* data = nullptr, bool eod = false);

private:
    const spicy::rt::Parser* _parser = nullptr;
    Cookie _cookie;
    bool _done = false;
    bool _skip = false;
    std::optional<hilti::rt::ValueReference<hilti::rt::Stream>> _data;
    std::optional<hilti::rt::Resumable> _resumable;

    ::zeek::RecordVal* _args; // ???
};

} // namespace spicy::zeek::rt
