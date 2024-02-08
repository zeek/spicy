// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <fstream>
#include <utility>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/node.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/unit.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::context;
using util::fmt;

namespace hilti::logging::debug {
inline const DebugStream AstCodegen("ast-codegen");
inline const DebugStream Compiler("compiler");
} // namespace hilti::logging::debug


Result<std::shared_ptr<Unit>> Unit::fromSource(const std::shared_ptr<Context>& context, Builder* builder,
                                               const hilti::rt::filesystem::path& path) {
    auto uid = context->astContext()->parseSource(builder, path);
    if ( ! uid )
        return uid.error();

    return std::shared_ptr<Unit>(new Unit(context, *uid));
}

Result<std::shared_ptr<Unit>> Unit::fromCXX(const std::shared_ptr<Context>& context, const detail::cxx::Unit& cxx,
                                            const hilti::rt::filesystem::path& path) {
    auto uid = declaration::module::UID("<from-cpp-code>", path.native());
    return std::shared_ptr<Unit>(new Unit(context, uid, cxx));
}

std::shared_ptr<Unit> Unit::fromExistingUID(const std::shared_ptr<Context>& context, declaration::module::UID uid) {
    return std::shared_ptr<Unit>(new Unit(context, std::move(uid)));
}

Unit::~Unit() {}

ModulePtr Unit::module() const { return context()->astContext()->module(_uid); }

bool Unit::isCompiledHILTI() const {
    if ( ! _uid.id )
        return false;

    auto module = context()->astContext()->module(_uid);
    return module && module->uid().process_extension == ".hlt" && ! module->skipImplementation();
}

Result<Nothing> Unit::print(std::ostream& out) const {
    if ( auto m = module() )
        printer::print(out, module());

    return Nothing();
}

Result<Nothing> Unit::createPrototypes(std::ostream& out) {
    if ( ! _cxx_unit )
        return result::Error("no C++ code available for unit");

    return _cxx_unit->createPrototypes(out);
}

Result<detail::cxx::Unit> Unit::_codegenModule(const declaration::module::UID& uid) {
    auto module = context()->astContext()->module(uid);
    assert(module);

    HILTI_DEBUG(logging::debug::Compiler, fmt("compiling module %s to C++", uid));
    logging::DebugPushIndent _(logging::debug::Compiler);

    auto cxx = detail::CodeGen(context()).compileModule(module, ! module->skipImplementation());

    if ( logger().errors() )
        return result::Error("errors encountered during code generation");

    if ( ! cxx )
        logger().internalError(
            fmt("code generation for module %s failed, but did not log error (%s)", uid, cxx.error().description()));

    return cxx;
}

Result<Nothing> Unit::codegen() {
    if ( ! _uid )
        return Nothing();

    auto cxx = _codegenModule(_uid);
    if ( ! cxx )
        return cxx.error();

    // Import declarations from our dependencies. They will have been compiled
    // at this point.
    //
    // TODO(robin): Would be nice if we had a "cheap" compilation mode that
    // only generated declarations.
    for ( const auto& d : dependencies(true) ) {
        HILTI_DEBUG(logging::debug::Compiler, fmt("importing declarations from module %s", d));
        if ( auto other_cxx = _codegenModule(d) )
            cxx->importDeclarations(*other_cxx);
        else
            return other_cxx.error();
    }

    HILTI_DEBUG(logging::debug::Compiler, fmt("finalizing module %s", _uid));
    if ( auto x = cxx->finalize(); ! x )
        return x.error();

    _cxx_unit = *cxx;
    return Nothing();
}

std::vector<declaration::module::UID> Unit::dependencies(bool recursive) const {
    return context()->astContext()->dependencies(_uid, recursive);
}

Result<CxxCode> Unit::cxxCode() const {
    if ( ! _cxx_unit )
        return result::Error("no C++ code available for unit");

    std::stringstream cxx;
    _cxx_unit->print(cxx);

    if ( logger().errors() )
        return result::Error("errors during prototype creation");

    return CxxCode{_cxx_unit->moduleID(), cxx};
}

bool Unit::requiresCompilation() {
    if ( _requires_compilation )
        return true;

    auto m = module();
    if ( ! m )
        return false;

    // Visitor that goes over an AST and flags whether any node provides
    // code that needs compilation.
    struct Visitor : hilti::visitor::PreOrder {
        bool result = false;

        void operator()(declaration::GlobalVariable* n) final { result = true; }
        void operator()(declaration::Function* n) final {
            if ( n->function()->body() )
                result = true;
        }
    };

    return visitor::visit(Visitor(), m, {}, [](const auto& v) { return v.result; });
}

Result<std::shared_ptr<Unit>> Unit::link(const std::shared_ptr<Context>& context,
                                         const std::vector<linker::MetaData>& mds) {
    HILTI_DEBUG(logging::debug::Compiler, fmt("linking %u modules", mds.size()));
    auto cxx_unit = detail::CodeGen(context).linkUnits(mds);

    if ( ! cxx_unit )
        return result::Error("no C++ code available for unit");

    return fromCXX(context, *cxx_unit, "<linker>");
}

std::pair<bool, std::optional<linker::MetaData>> Unit::readLinkerMetaData(std::istream& input,
                                                                          const hilti::rt::filesystem::path& path) {
    HILTI_DEBUG(logging::debug::Compiler, fmt("reading linker data from %s", path));
    return detail::cxx::Unit::readLinkerMetaData(input);
}
