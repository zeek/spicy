// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <unordered_map>

#include <spicy/compiler/detail/pir/ir/arena.h>
#include <spicy/compiler/detail/pir/ir/id.h>

namespace spicy::detail::pir::ir {

struct SourceFileTag {};
struct SourceSpanTag {};

using SourceFileId = ID<SourceFileTag>;
using SourceSpanId = ID<SourceSpanTag>;

/** A source file referenced by diagnostic path only; it does not own file contents. */
struct SourceFile {
    std::string diagnostic_path;
};

/**
 * A source range. Unknown positions use `-1`, matching `hilti::Location`'s convention.
 *
 * Byte offsets are deliberately not tracked yet: the resolved AST does not currently provide
 * them, PIR has no source-content capture, and there is no stable serialization contract that
 * would need them. Add them alongside actual source-content capture, with defined encoding,
 * indexing, and range semantics, rather than speculatively now.
 */
struct SourceSpan {
    SourceFileId file;
    int begin_line = -1;
    int begin_column = -1;
    int end_line = -1;
    int end_column = -1;
};

/** Owns a package's source files and spans. Interning is construction support; arena order is canonical. */
class SourceManager {
public:
    SourceFileId internFile(std::string diagnostic_path);
    SourceSpanId addSpan(SourceSpan span);

    const SourceFile& file(SourceFileId id) const { return _files.get(id); }
    const SourceSpan& span(SourceSpanId id) const { return _spans.get(id); }

    bool isValid(SourceFileId id) const { return _files.isValid(id); }
    bool isValid(SourceSpanId id) const { return _spans.isValid(id); }

    const Arena<SourceFile, SourceFileId>& files() const { return _files; }
    const Arena<SourceSpan, SourceSpanId>& spans() const { return _spans; }

private:
    Arena<SourceFile, SourceFileId> _files;
    Arena<SourceSpan, SourceSpanId> _spans;
    std::unordered_map<std::string, SourceFileId> _file_by_path;
};

} // namespace spicy::detail::pir::ir
