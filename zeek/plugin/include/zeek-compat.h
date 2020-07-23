// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.
//
// Provide backwards compability for older Zeek versions.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#if ZEEK_VERSION_NUMBER >= 30200

// Zeek includes
#include "Conn.h"
#include "EventRegistry.h"
#include "Val.h"
#include "bro-bif.h" // TODO: Include "zeek/Event.h" instead once we can
#include "file_analysis/File.h"

namespace spicy::zeek::compat {

inline auto AddrVal_New(const std::string& x) { return ::zeek::make_intrusive<::zeek::AddrVal>(x); }
inline auto DoubleVal_New(double x) { return ::zeek::make_intrusive<::zeek::DoubleVal>(x); }
inline auto IntervalVal_New(double x) { return ::zeek::make_intrusive<::zeek::IntervalVal>(x); }
inline auto StringVal_New(const std::string& x) { return ::zeek::make_intrusive<::zeek::StringVal>(x); }
inline auto TimeVal_New(double x) { return ::zeek::make_intrusive<::zeek::TimeVal>(x); }
inline auto EnumType_New(std::string& x) { return ::zeek::make_intrusive<::zeek::EnumType>(x); }

template<typename T>
inline auto ToValPtr(std::unique_ptr<T> p) {
    return ::zeek::IntrusivePtr{::zeek::NewRef{}, p.release()};
}

inline auto Attribute_Find(::zeek::IntrusivePtr<::zeek::detail::Attributes> a, ::zeek::detail::AttrTag x) {
    return a->Find(x);
}
inline auto Connection_ConnVal(::Connection* c) { return c->ConnVal(); }
inline auto EnumTypeGetEnumVal(::zeek::EnumType* t, ::bro_int_t i) { return t->GetEnumVal(i); }
inline auto EventHandler_GetType(EventHandlerPtr ev, bool check_export = true) { return ev->GetType(check_export); }
inline auto FileAnalysisComponentTag_AsVal(const ::file_analysis::Tag& t) { return t.AsVal(); }
inline auto File_ToVal(::file_analysis::File* f) { return f->ToVal(); }
inline auto FuncType_ArgTypes(::zeek::FuncTypePtr f) { return f->ParamList(); }
inline auto RecordType_GetFieldType(::zeek::RecordType* t, int i) { return t->GetFieldType(i); }
inline auto TableType_GetIndexTypes(::zeek::TableType* tt) { return tt->GetIndexTypes(); }
inline auto TableType_GetIndexTypesLength(::zeek::TableType* tt) { return tt->GetIndexTypes().size(); }
inline auto TableType_Yield(::zeek::TableType* t) { return t->Yield(); }
inline auto TypeList_GetTypes(::zeek::TypeListPtr l) { return l->GetTypes(); }
inline auto VectorType_Yield(::zeek::VectorType* t) { return t->Yield(); }
inline auto ZeekArgs_Append(::zeek::Args& args, ::zeek::ValPtr v) { args.emplace_back(std::move(v)); }
inline auto ZeekArgs_Get(const std::vector<::zeek::TypePtr>& vl, uint64_t idx) { return vl[idx]; }
inline auto event_mgr_Enqueue(const ::EventHandlerPtr& h, ::zeek::Args vl) { return ::mgr.Enqueue(h, std::move(vl)); }
inline auto event_register_Register(const std::string& x) { return ::event_registry->Register(x); }
inline auto val_mgr_Bool(bool b) { return ::zeek::val_mgr->Bool(b); }
inline auto val_mgr_Count(uint64_t i) { return ::zeek::val_mgr->Count(i); }
inline auto val_mgr_Int(int64_t i) { return ::zeek::val_mgr->Int(i); }
inline auto val_mgr_Port(uint32_t p, TransportProto t) { return ::zeek::val_mgr->Port(p, t); }
inline auto TypeList_GetTypesSize(const std::vector<::zeek::TypePtr>& t) { return static_cast<uint64_t>(t.size()); }

} // namespace spicy::zeek::compat

#else

// TODO

namespace zeek {

namespace detail {
using ::zeek::RecordVal = ::zeek::RecordVal;

template<typename T>
inline auto ToValPtr(std::unique_ptr<T> p) {
    return p.release();
}

inline auto File_ToVal(::BroFile* f) { return f->GetVal().Ref(); }

} // namespace detail

} // namespace zeek
#endif
