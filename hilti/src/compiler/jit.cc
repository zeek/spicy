// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <fstream>
#include <utility>

#include <hilti/base/timing.h>
#include <hilti/compiler/detail/cxx/unit.h>
#include <hilti/compiler/jit.h>
#include <hilti/rt/init.h>

using namespace hilti;

CxxCode::CxxCode(const detail::cxx::Unit& u) {
    std::stringstream buffer;
    u.print(buffer);
    load(u.moduleID(), buffer);
}

bool CxxCode::load(const std::filesystem::path& path) {
    std::ifstream in;
    in.open(path);

    if ( ! in )
        return false;

    if ( ! load(path, in) )
        return false;

    _id = path;
    return true;
}

bool CxxCode::load(const std::string& id, std::istream& in) {
    std::string code{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};

    if ( in.fail() )
        return false;

    _id = id;
    _code = std::move(code);
    return true;
}

bool CxxCode::save(const std::filesystem::path& p) const {
    if ( ! _code )
        return false;

    std::ofstream out(p);

    if ( ! out )
        return false;

    out << *_code;
    out.close();
    return ! out.fail();
}

bool CxxCode::save(std::ostream& out) const {
    if ( ! _code )
        return false;

    out << *_code;
    return ! out.fail();
}

#ifdef HILTI_HAVE_JIT
#include <hilti/compiler/detail/clang.h>

JIT::JIT(std::shared_ptr<Context> context) : _context(std::move(context)) {
    _jit = std::make_unique<detail::ClangJIT>(_context);
}

JIT::~JIT() {
    if ( _jit )
        finishRuntime();
}

bool JIT::compile() {
    util::timing::Collector _("hilti/jit/compile");

    if ( ! _jit )
        return false;

    if ( _codes.empty() && _files.empty() )
        return false;

    for ( const auto& c : _codes ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("jitting %s", c.id()));

        if ( ! _jit->compile(c) ) {
            logger().error(util::fmt("jit: failed to compile C++ code unit %s to bitcode", c.id()));
            return false;
        }
    }

    for ( const auto& c : _files ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("jitting %s", c));

        if ( ! _jit->compile(c) ) {
            logger().error(util::fmt("jit: failed to compile C++ file %s to bitcode", c));
            return false;
        }
    }

    return true;
}

void JIT::setDumpCode() {
    if ( _jit )
        _jit->setDumpCode();
}

hilti::Result<Nothing> JIT::jit() {
    util::timing::Collector _("hilti/jit/jit");

    if ( ! _jit )
        return result::Error("jit not initialized");

    return _jit->jit();
}

Result<std::reference_wrapper<const Library>> JIT::retrieveLibrary() const {
    if ( ! _jit ) {
        return result::Error("no JIT object code available");
    }

    if ( ! _jit->retrieveLibrary() )
        return result::Error("no library available");

    return *_jit->retrieveLibrary();
}

bool JIT::initRuntime() {
    if ( ! _jit )
        return false;

    return _jit->initRuntime();
}

bool JIT::finishRuntime() {
    if ( ! _jit )
        return false;

    _jit->finishRuntime();
    _jit.reset();
    return true;
}

std::string JIT::compilerVersion() { return detail::ClangJIT::compilerVersion(); }

#else

class detail::ClangJIT {};

JIT::JIT(std::shared_ptr<Context> context) : _context(std::move(context)) {}

JIT::~JIT() {}

bool JIT::compile() {
    logger().error("jit: support for just-in-time compilation not available");
    return false;
}

Result<Nothing> JIT::jit() {
    logger().error("jit: support for just-in-time compilation not available");
    return Nothing();
}

void JIT::setDumpCode() { logger().error("jit: support for just-in-time compilation not available"); }

Result<std::reference_wrapper<const Library>> JIT::retrieveLibrary() const {
    constexpr char message[] = "jit: support for just-in-time compilation not available";
    logger().error(message);
    return result::Error(message);
}

std::string JIT::compilerVersion() { return "<no JIT compiler>"; }

#endif
