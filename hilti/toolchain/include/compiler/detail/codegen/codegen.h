// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/function.h>
#include <hilti/ast/types/bitfield.h>
#include <hilti/base/cache.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/cxx/elements.h>
#include <hilti/compiler/detail/cxx/unit.h>

namespace hilti {

namespace logging::debug {
inline const DebugStream CodeGen("codegen");
} // namespace logging::debug

class Node;
class Unit;

namespace detail {

namespace codegen {
enum class TypeUsage { Storage, CopyParameter, InParameter, InOutParameter, FunctionResult, Ctor, None };

struct CxxTypes {
    std::optional<cxx::Type> base_type;
    std::optional<cxx::Type> storage;
    std::optional<cxx::Type> result;
    std::optional<cxx::Type> param_copy;
    std::optional<cxx::Type> param_in;
    std::optional<cxx::Type> param_inout;
    std::optional<cxx::Type> ctor;
    std::optional<cxx::Expression> default_;
};

/** Structure capturing runtime type information for a specific type. */
struct CxxTypeInfo {
    bool predefined; /**< True if the type information instances is being predefined statically by the runtime library
                        (vs. generated by the codegen) */
    cxx::Expression reference;                             /**< ID to refer to this type information instance. */
    std::optional<cxx::declaration::Constant> forward;     /**< Forward declaration for type information. */
    std::optional<cxx::declaration::Constant> declaration; /**< Actual declaration for type information.  */
};

} // namespace codegen

/**
 * HILTI's code generator. This is the main internal entry point for
 * generating C++ code from HILTI source code.
 */
class CodeGen {
public:
    CodeGen(const std::shared_ptr<Context>& context);

    /** Entry point for code generation. */
    Result<std::shared_ptr<cxx::Unit>> compileModule(declaration::Module* module);

    /** Entry point for generating additional cross-unit C++ code through HILTI's linker. */
    Result<std::shared_ptr<cxx::Unit>> linkUnits(const std::vector<cxx::linker::MetaData>& mds);

    std::shared_ptr<Context> context() const { return _context.lock(); }
    const Options& options() const { return context()->options(); }
    auto* builder() const { return _builder.get(); }

    // These must be called only while a module is being compiled.
    std::optional<cxx::declaration::Type> typeDeclaration(QualifiedType* t);
    std::list<cxx::declaration::Type> typeDependencies(QualifiedType* t);
    cxx::Type compile(QualifiedType* t, codegen::TypeUsage usage);
    cxx::Expression compile(hilti::Expression* e, bool lhs = false);
    cxx::Expression compile(hilti::Ctor* c, bool lhs = false);
    cxx::Expression compile(hilti::expression::ResolvedOperator* o, bool lhs = false);
    cxx::Block compile(hilti::Statement* s, cxx::Block* b = nullptr);
    cxx::declaration::Function compile(Declaration* decl, type::Function* ft, declaration::Linkage linkage,
                                       function::CallingConvention cc = function::CallingConvention::Standard,
                                       AttributeSet* fattrs = {}, std::optional<cxx::ID> namespace_ = {});
    std::vector<cxx::Expression> compileCallArguments(const hilti::node::Range<Expression>& args,
                                                      const hilti::node::Set<declaration::Parameter>& params);
    std::vector<cxx::Expression> compileCallArguments(const hilti::node::Range<Expression>& args,
                                                      const hilti::node::Range<declaration::Parameter>& params);
    std::optional<cxx::Expression> typeDefaultValue(QualifiedType* t);
    codegen::TypeUsage parameterKindToTypeUsage(parameter::Kind);

    cxx::Expression typeInfo(QualifiedType* t);
    void addTypeInfoDefinition(QualifiedType* t);

    cxx::Expression coerce(const cxx::Expression& e, QualifiedType* src,
                           QualifiedType* dst); // only for supported coercions
    cxx::Expression pack(Expression* data, const Expressions& args);
    cxx::Expression pack(QualifiedType* t, const cxx::Expression& data, const std::vector<cxx::Expression>& args);
    cxx::Expression unpack(QualifiedType* t, QualifiedType* data_type, Expression* data, const Expressions& args,
                           bool throw_on_error);
    cxx::Expression unpack(QualifiedType* t, QualifiedType* data_type, const cxx::Expression& data,
                           const std::vector<cxx::Expression>& args, bool throw_on_error);

    cxx::Expression addTmp(const std::string& prefix, const cxx::Type& t);
    cxx::Expression addTmp(const std::string& prefix, const cxx::Expression& init);

    cxx::Expression startProfiler(const std::string& name, cxx::Block* block = nullptr, bool insert_at_front = false);
    void stopProfiler(const cxx::Expression& profiler, cxx::Block* block = nullptr);

    cxx::Expression unsignedIntegerToBitfield(type::Bitfield* t, const cxx::Expression& value,
                                              const cxx::Expression& bitorder);

    /**
     * Returns an ID that's unique for a given node. The ID is derived from
     * the node's location information, which must be present.
     *
     * @param prefix constant prefix that will be added to ID
     * @param n node to generate the ID for
     *
     */
    cxx::ID uniqueID(const std::string& prefix, Node* n);

    cxx::Expression self() const { return _self.back(); }
    void pushSelf(detail::cxx::Expression e) { _self.push_back(std::move(e)); }
    void popSelf() { _self.pop_back(); }

    cxx::Expression dollardollar() const { return _dd.back(); }
    void pushDollarDollar(cxx::Expression e) { _dd.push_back(std::move(e)); }
    void popDollarDollar() { _dd.pop_back(); }

    auto cxxBlock() const { return ! _cxx_blocks.empty() ? _cxx_blocks.back() : nullptr; }
    void pushCxxBlock(cxx::Block* b) { _cxx_blocks.push_back(b); }
    void popCxxBlock() { _cxx_blocks.pop_back(); }

    cxx::Unit* unit() const;                         // will abort if not compiling a module.
    hilti::declaration::Module* hiltiModule() const; // will abort if not compiling a module.

private:
    const codegen::CxxTypeInfo& _getOrCreateTypeInfo(QualifiedType* t);

    // Adapt expression so that it can be used as a LHS. If expr is already a
    // LHS, it's returned directly. Otherwise it assigns it over into a
    // temporary, which is then returned.
    cxx::Expression _makeLhs(cxx::Expression expr, QualifiedType* type);

    // Add all required C++ declarations to a unit.
    void _addCxxDeclarations(cxx::Unit* unit);

    std::weak_ptr<Context> _context;
    std::unique_ptr<Builder> _builder;

    std::shared_ptr<cxx::Unit> _cxx_unit;
    hilti::declaration::Module* _hilti_module = nullptr;
    std::vector<detail::cxx::Expression> _self = {{"__self", Side::LHS}};
    std::vector<detail::cxx::Expression> _dd = {{"__dd", Side::LHS}};
    std::vector<detail::cxx::Block*> _cxx_blocks;
    std::vector<detail::cxx::declaration::Local> _tmps;
    std::map<std::string, int> _tmp_counters;
    hilti::util::Cache<cxx::ID, codegen::CxxTypes> _cache_types_storage;
    hilti::util::Cache<cxx::ID, codegen::CxxTypeInfo> _cache_type_info;
    hilti::util::Cache<cxx::ID, cxx::declaration::Type> _cache_types_declarations;
};

} // namespace detail
} // namespace hilti
