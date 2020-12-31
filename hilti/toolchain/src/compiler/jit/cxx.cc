// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/base/logger.h>
#include <hilti/base/result.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/jit/cxx.h>
#include <hilti/compiler/jit.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::jit;

Cxx::Cxx(std::shared_ptr<Context> context) {}

Cxx::~Cxx() {}

bool Cxx::compile(const CxxCode& code) { return false; }

bool Cxx::compile(const hilti::rt::filesystem::path& p) { return false; }

Result<Nothing> Cxx::jit() { return result::Error(); }

std::shared_ptr<const Library> Cxx::retrieveLibrary() const { return nullptr; }

void Cxx::setDumpCode() {}
std::string Cxx::compilerVersion() { return "HOST_COMPILER_TODO"; }
