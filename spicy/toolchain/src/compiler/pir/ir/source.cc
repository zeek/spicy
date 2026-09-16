// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <utility>

#include <spicy/compiler/detail/pir/ir/source.h>

namespace spicy::detail::pir::ir {

SourceFileId SourceManager::internFile(std::string diagnostic_path) {
    if ( auto it = _file_by_path.find(diagnostic_path); it != _file_by_path.end() )
        return it->second;

    auto id = _files.add(SourceFile{.diagnostic_path = diagnostic_path});
    _file_by_path.emplace(std::move(diagnostic_path), id);
    return id;
}

SourceSpanId SourceManager::addSpan(SourceSpan span) { return _spans.add(span); }

} // namespace spicy::detail::pir::ir
