// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
//
// Provides backwards compatibility for older Zeek versions.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <zeek-spicy/autogen/config.h>

#if SPICY_ZEEK_VERSION_NUMBER >= 30200 // Zeek >= 3.2
#include <zeek/zeek-config.h>
#else
#include "zeek-config.h"
#endif

//// Collect all the Zeek includes here that we need anywhere in the plugin.

#if ZEEK_DEBUG_BUILD
#ifndef DEBUG
#define DEBUG
#endif
#endif

#if ZEEK_VERSION_NUMBER >= 30300 // Zeek >= 3.3 (aka 4.0)
#include <zeek/packet_analysis/Analyzer.h>
#endif

#if ZEEK_VERSION_NUMBER >= 30200 // Zeek >= 3.2
#include <zeek/Conn.h>
#include <zeek/DebugLogger.h>
#include <zeek/Desc.h>
#include <zeek/Event.h>
#include <zeek/EventHandler.h>
#include <zeek/EventRegistry.h>
#include <zeek/Expr.h>
#include <zeek/IPAddr.h>
#include <zeek/Reporter.h>
#include <zeek/Type.h>
#include <zeek/Val.h>
#include <zeek/Var.h>
#include <zeek/analyzer/Analyzer.h>
#include <zeek/analyzer/Manager.h>
#include <zeek/analyzer/protocol/tcp/TCP.h>
#include <zeek/analyzer/protocol/udp/UDP.h>
#include <zeek/file_analysis/Analyzer.h>
#include <zeek/file_analysis/File.h>
#include <zeek/file_analysis/Manager.h>
#include <zeek/module_util.h>
#include <zeek/plugin/Plugin.h>
#else
#include "Conn.h"
#include "DebugLogger.h"
#include "Desc.h"
#include "EventHandler.h"
#include "EventRegistry.h"
#include "Expr.h"
#include "IPAddr.h"
#include "Reporter.h"
#include "Type.h"
#include "Val.h"
#include "Var.h"
#include "analyzer/Analyzer.h"
#include "analyzer/Manager.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/udp/UDP.h"
#include "bro-bif.h" // actually want "Event.h", but that clashes
#include "file_analysis/Analyzer.h"
#include "file_analysis/File.h"
#include "file_analysis/Manager.h"
#if ZEEK_VERSION_NUMBER >= 30100
#include "module_util.h"
#endif
#include "plugin/Plugin.h"
#endif
#undef DEBUG

//// Import types and globals into the new namespaces.

#if ZEEK_VERSION_NUMBER < 30300 // Zeek <= 3.3 (aka 4.0)
namespace zeek {
using ::Connection;
using ::EventHandlerPtr;
using ::IP_Hdr;
using ::IPAddr;
using ::ODesc;

inline auto& analyzer_mgr = ::analyzer_mgr;
inline auto& event_mgr = ::mgr;
inline auto& file_mgr = ::file_mgr;
inline auto& reporter = ::reporter;

namespace analyzer {
using Analyzer = ::analyzer::Analyzer;
using Component = ::analyzer::Component;
using Tag = ::analyzer::Tag;

namespace tcp {
using TCP_ApplicationAnalyzer = ::analyzer::tcp::TCP_ApplicationAnalyzer;
using TCP_Endpoint = ::analyzer::tcp::TCP_Endpoint;
} // namespace tcp
} // namespace analyzer

namespace file_analysis {
using Analyzer = ::file_analysis::Analyzer;
using Component = ::file_analysis::Component;
using File = ::file_analysis::File;
using Tag = ::file_analysis::Tag;
} // namespace file_analysis

namespace util::detail {
inline auto& add_to_zeek_path = ::add_to_bro_path;
}

namespace detail {
inline auto& zeekygen_mgr = ::zeekygen_mgr;
inline auto& GLOBAL_MODULE_NAME = ::GLOBAL_MODULE_NAME;
} // namespace detail

} // namespace zeek

#endif

#if ZEEK_VERSION_NUMBER < 30200
namespace zeek {

namespace plugin {
using ::plugin::Configuration;
using ::plugin::HookType;
using ::plugin::Plugin;
using ::plugin::HookType::HOOK_LOAD_FILE;
} // namespace plugin

namespace id {
inline ::Val* find_const(const char* name) { return ::internal_const_val(name); }
} // namespace id

using Args = val_list*;
using Plugin = ::plugin::Plugin;
using RecordVal = ::RecordVal;
using RecordValPtr = ::RecordVal*;
using TableVal = ::TableVal;
using TableValPtr = ::TableVal*;
using TypePtr = ::BroType*;
using ValPtr = ::Val*;
using VectorVal = ::VectorVal;

using ::TypeTag;
using ::TypeTag::TYPE_ADDR;
using ::TypeTag::TYPE_BOOL;
using ::TypeTag::TYPE_COUNT;
using ::TypeTag::TYPE_DOUBLE;
using ::TypeTag::TYPE_ENUM;
using ::TypeTag::TYPE_INT;
using ::TypeTag::TYPE_INTERVAL;
using ::TypeTag::TYPE_LIST;
using ::TypeTag::TYPE_PORT;
using ::TypeTag::TYPE_RECORD;
using ::TypeTag::TYPE_STRING;
using ::TypeTag::TYPE_TABLE;
using ::TypeTag::TYPE_TIME;
using ::TypeTag::TYPE_VECTOR;

namespace detail {
using Location = ::Location;

using ::attr_tag;
using ::attr_tag::ATTR_DEFAULT;
using ::attr_tag::ATTR_OPTIONAL;
} // namespace detail
} // namespace zeek
#endif

//// Wrapper functions for functionality that differs by version.

#if ZEEK_VERSION_NUMBER >= 30200 // Zeek >= 3.2

namespace spicy::zeek::compat {

inline auto AddrVal_New(const std::string& x) { return ::zeek::make_intrusive<::zeek::AddrVal>(x); }
inline auto DoubleVal_New(double x) { return ::zeek::make_intrusive<::zeek::DoubleVal>(x); }
inline auto IntervalVal_New(double x) { return ::zeek::make_intrusive<::zeek::IntervalVal>(x); }
inline auto StringVal_New(const std::string& x) { return ::zeek::make_intrusive<::zeek::StringVal>(x); }
inline auto TimeVal_New(double x) { return ::zeek::make_intrusive<::zeek::TimeVal>(x); }
inline auto EnumType_New(std::string& x) { return ::zeek::make_intrusive<::zeek::EnumType>(x); }

template<typename T>
inline auto ToValPtr(std::unique_ptr<T> p) {
    return ::zeek::IntrusivePtr{::zeek::AdoptRef{}, p.release()};
}

template<typename T>
inline auto ToValCtorType(T p) {
    return ::zeek::IntrusivePtr{::zeek::NewRef{}, p};
}

template<typename T>
inline auto Unref(const ::zeek::IntrusivePtr<T>& o) {
    // nothing to do
}

inline auto Attribute_Find(::zeek::IntrusivePtr<::zeek::detail::Attributes> a, ::zeek::detail::AttrTag x) {
    return a->Find(x);
}
inline auto Connection_ConnVal(::zeek::Connection* c) { return c->ConnVal(); }
inline auto EnumTypeGetEnumVal(::zeek::EnumType* t, ::bro_int_t i) { return t->GetEnumVal(i); }
inline auto EventHandler_GetType(::zeek::EventHandlerPtr ev, bool check_export = true) {
    return ev->GetType(check_export);
}
inline auto FileAnalysisComponentTag_AsVal(const ::zeek::file_analysis::Tag& t) { return t.AsVal(); }
inline auto File_ToVal(::zeek::file_analysis::File* f) { return f->ToVal(); }
inline auto FuncType_ArgTypes(::zeek::FuncTypePtr f) { return f->ParamList(); }
inline auto RecordType_GetFieldType(::zeek::RecordType* t, int i) { return t->GetFieldType(i); }
inline auto TableType_GetIndexTypes(::zeek::TableType* tt) { return tt->GetIndexTypes(); }
inline auto TableType_GetIndexTypesLength(::zeek::TableType* tt) { return tt->GetIndexTypes().size(); }
inline auto TableType_Yield(::zeek::TableType* t) { return t->Yield(); }
inline auto TypeList_GetTypes(::zeek::TypeListPtr l) { return l->GetTypes(); }
inline auto VectorType_Yield(::zeek::VectorType* t) { return t->Yield(); }
inline auto ZeekArgs_New() { return ::zeek::Args(); }
inline auto ZeekArgs_Append(::zeek::Args& args, ::zeek::ValPtr v) { args.emplace_back(std::move(v)); }
inline auto ZeekArgs_Get(const std::vector<::zeek::TypePtr>& vl, uint64_t idx) { return vl[idx]; }
inline auto event_mgr_Enqueue(const ::zeek::EventHandlerPtr& h, ::zeek::Args vl) {
    return ::zeek::event_mgr.Enqueue(h, std::move(vl));
}
#if ZEEK_VERSION_NUMBER >= 40000 // Zeek >= 4.0
inline auto event_register_Register(const std::string& x) { return ::zeek::event_registry->Register(x); }
#else
inline auto event_register_Register(const std::string& x) { return ::event_registry->Register(x); }
#endif
inline auto val_mgr_Bool(bool b) { return ::zeek::val_mgr->Bool(b); }
inline auto val_mgr_Count(uint64_t i) { return ::zeek::val_mgr->Count(i); }
inline auto val_mgr_Int(int64_t i) { return ::zeek::val_mgr->Int(i); }
inline auto val_mgr_Port(uint32_t p, TransportProto t) { return ::zeek::val_mgr->Port(p, t); }
inline auto TypeList_GetTypesSize(const std::vector<::zeek::TypePtr>& t) { return static_cast<uint64_t>(t.size()); }

} // namespace spicy::zeek::compat
#endif

#if ZEEK_VERSION_NUMBER < 30200 // Zeek < 3.2

namespace zeek {
namespace detail {

inline void set_location(const ::Location loc) { ::set_location(loc); }
inline void set_location(const ::Location start, const Location end) { ::set_location(start, end); }

inline ::ID* lookup_ID(const char* name, const char* module, bool no_global = false, bool same_module_only = false,
                       bool check_export = true) {
    return ::lookup_ID(name, module, no_global, same_module_only, check_export);
}

inline ::ID* install_ID(const char* name, const char* module_name, bool is_global, bool is_export) {
    return ::install_ID(name, module_name, is_global, is_export);
}

} // namespace detail
} // namespace zeek

namespace spicy::zeek::compat {

inline auto AddrVal_New(const std::string& x) { return new ::AddrVal(x); }
inline auto DoubleVal_New(double x) { return new ::Val(x, ::TYPE_DOUBLE); }
inline auto IntervalVal_New(double x) { return new ::Val(x, ::TYPE_INTERVAL); }
inline auto StringVal_New(const std::string& x) { return new ::StringVal(x); }
inline auto TimeVal_New(double x) { return new ::Val(x, ::TYPE_TIME); }
inline auto EnumType_New(std::string& x) { return new ::EnumType(x); }

template<typename T>
inline auto ToValPtr(std::unique_ptr<T> p) {
    return p.release();
}

template<typename T>
inline auto ToValCtorType(T p) {
    return p;
}

inline auto Unref(::BroObj* o) { ::Unref(o); }

inline auto Attribute_Find(Attributes* a, ::attr_tag x) { return a->FindAttr(x); }
inline auto Connection_ConnVal(::zeek::Connection* c) { return c->BuildConnVal(); }
inline auto EnumTypeGetEnumVal(::EnumType* t, ::bro_int_t i) { return t->GetVal(i); }
inline auto EventHandler_GetType(::zeek::EventHandlerPtr ev, bool check_export = true) {
    return ev->FType(check_export);
}
inline auto FileAnalysisComponentTag_AsVal(const ::zeek::file_analysis::Tag& t) { return t.AsEnumVal(); }
inline auto File_ToVal(::zeek::file_analysis::File* f) { return f->GetVal()->Ref(); }
inline auto FuncType_ArgTypes(::FuncType* f) { return f->ArgTypes(); }
inline auto RecordType_GetFieldType(::RecordType* t, int i) { return t->FieldType(i); }
inline auto& TableType_GetIndexTypes(::TableType* tt) { return *tt->IndexTypes(); }
inline auto TableType_GetIndexTypesLength(::TableType* tt) { return tt->IndexTypes()->length(); }
inline auto TableType_Yield(::TableType* t) { return t->YieldType(); }
inline auto TypeList_GetTypes(const ::TypeList* l) { return l->Types(); }
inline auto VectorType_Yield(::VectorType* t) { return t->YieldType(); }
inline auto ZeekArgs_New() { return new ::val_list(); }
inline auto ZeekArgs_Append(::val_list* args, ::Val* v) { args->push_back(std::move(v)); }
inline auto ZeekArgs_Get(const ::type_list* vl, uint64_t idx) { return (*vl)[idx]; }
inline auto event_mgr_Enqueue(const ::zeek::EventHandlerPtr& h, ::val_list* vl) {
    return ::zeek::event_mgr.QueueEvent(h, std::move(vl));
}
inline auto event_register_Register(const std::string& x) { return ::internal_handler(x.c_str()); }
inline auto val_mgr_Bool(bool b) { return ::val_mgr->GetBool(b); }
inline auto val_mgr_Count(uint64_t i) { return ::val_mgr->GetCount(i); }
inline auto val_mgr_Int(int64_t i) { return ::val_mgr->GetInt(i); }
inline auto val_mgr_Port(uint32_t p, TransportProto t) { return ::val_mgr->GetPort(p, t); }
inline auto TypeList_GetTypesSize(const ::type_list* t) { return static_cast<uint64_t>(t->length()); }

} // namespace spicy::zeek::compat
#endif
