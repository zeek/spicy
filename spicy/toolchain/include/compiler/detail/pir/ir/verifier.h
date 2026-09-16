// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

enum class DiagnosticCode {
    InvalidFunctionResultType,
    InvalidRootRegion,
    RegionBlockCountMismatch,
    InvalidBlockId,
    EmptyBlock,
    InvalidInstructionId,
    CachedParentMismatch,
    UnrecognizedOpcode,
    TerminatorNotLast,
    MissingTerminator,
    OperandCountMismatch,
    UnexpectedPayload,
    MissingPayload,
    InvalidOperandId,
    OperandNotSameBlock,
    OperandUsedBeforeDefinition,
    VoidOperandUsed,
    OperandTypeMismatch,
    ResultTypeMismatch,
    ReturnTypeMismatch,
    DuplicateRegionOwnership,
    DuplicateBlockOwnership,
    DuplicateInstructionOwnership,
    OrphanRegions,
    OrphanBlocks,
    OrphanInstructions,
    InvalidSourceSpanId,
    InvalidSourceFileId,
    MalformedSourceSpanRange,
};

struct Diagnostic {
    DiagnosticCode code;
    std::string message;
};

/** Returns all structural and typing errors in `package`. */
std::vector<Diagnostic> verify(const Package& package);

} // namespace spicy::detail::pir::ir
