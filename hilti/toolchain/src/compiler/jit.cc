// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <fstream>
#include <utility>

#include <hilti/rt/init.h>

#include <hilti/base/timing.h>
#include <hilti/compiler/detail/cxx/unit.h>
#include <hilti/compiler/jit.h>
#include <hilti/compiler/detail/jit/cxx.h>

using namespace hilti;

CxxCode::CxxCode(const detail::cxx::Unit& u) {
    std::stringstream buffer;
    u.print(buffer);
    load(u.moduleID(), buffer);
}

bool CxxCode::load(const hilti::rt::filesystem::path& path) {
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

bool CxxCode::save(const hilti::rt::filesystem::path& p) const {
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


JIT::JIT(std::shared_ptr<Context> context) : _context(std::move(context)) {
    _jit = std::make_unique<detail::jit::Cxx>(_context);
}

JIT::~JIT() {}

bool JIT::compile() {
    util::timing::Collector _("hilti/jit/compile");

    if ( ! _jit )
        return false;

    if ( _codes.empty() && _files.empty() )
        return false;

    for ( const auto& c : _codes ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("jitting %s", c.id()));

        if ( ! _jit->compile(c) ) {
            logger().error(util::fmt("jit: failed to compile C++ code unit %s", c.id()));
            return false;
        }
    }

    for ( const auto& c : _files ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("jitting %s", c));

        if ( ! _jit->compile(c) ) {
            logger().error(util::fmt("jit: failed to compile C++ file %s", c));
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
    util::timing::Collector _("hilti/jit/codegen");

    if ( ! _jit )
        return result::Error("jit not initialized");

    return _jit->jit();
}

Result<std::shared_ptr<const Library>> JIT::retrieveLibrary() const {
    if ( ! _jit ) {
        return result::Error("no JIT object code available");
    }

    auto library = _jit->retrieveLibrary();
    if ( ! library )
        return result::Error("no library available");

    return std::move(library);
}

std::string JIT::compilerVersion() { return detail::jit::Cxx::compilerVersion(); }
