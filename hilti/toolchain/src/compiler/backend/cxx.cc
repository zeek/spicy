#include <base/logger.h>

#include <hilti/compiler/backend/cxx.h>
#include <hilti/compiler/detail/codegen/codegen.h>

namespace hilti::logging::debug {
inline const DebugStream Compiler("compiler");
} // namespace hilti::logging::debug

namespace hilti {

using util::fmt;

Result<std::shared_ptr<detail::cxx::Unit>> CxxBackend::compile(declaration::Module* mod, const std::shared_ptr<Context>& ctx) {
    // TODO
    HILTI_DEBUG(logging::debug::Compiler, fmt("codegen module %s to C++", mod->uid()));
    logging::DebugPushIndent __(logging::debug::Compiler);
    auto cxx = detail::CodeGen(ctx).compileModule(mod);

    if ( logger().errors() )
        return result::Error("errors encountered during code generation");

    if ( ! cxx )
        logger().internalError(fmt("code generation for module %s failed, but did not log error (%s)",
                                   mod->uid(),
                                   cxx.error().description()));

    HILTI_DEBUG(logging::debug::Compiler, fmt("finalizing module %s", mod->uid()));
    if ( auto x = (*cxx)->finalize(); ! x )
        return x.error();

    return *cxx;
}
} // namespace hilti
