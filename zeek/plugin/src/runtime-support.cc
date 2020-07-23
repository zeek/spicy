// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/util.h>

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/plugin.h>
#include <zeek-spicy/runtime-support.h>
#include <zeek-spicy/zeek-compat.h>
#include <zeek-spicy/zeek-reporter.h>

// Zeek includes
#if ZEEK_DEBUG_BUILD
#define DEBUG
#endif
#include <Conn.h>
#include <Event.h>
#include <EventHandler.h>
#include <Val.h>
#include <file_analysis/File.h>
#include <file_analysis/Manager.h>
#if ZEEK_VERSION_NUMBER >= 30100
#include <module_util.h>
#endif
#undef DEBUG

using namespace spicy::zeek;
using namespace plugin::Zeek_Spicy;

void rt::register_protocol_analyzer(const std::string& name, hilti::rt::Protocol proto,
                                    const hilti::rt::Vector<hilti::rt::Port>& ports, const std::string& parser_orig,
                                    const std::string& parser_resp, const std::string& replaces) {
    OurPlugin->registerProtocolAnalyzer(name, proto, ports, parser_orig, parser_resp, replaces);
}

void rt::register_file_analyzer(const std::string& name, const hilti::rt::Vector<std::string>& mime_types,
                                const std::string& parser) {
    OurPlugin->registerFileAnalyzer(name, mime_types, parser);
}

void rt::register_enum_type(
    const std::string& ns, const std::string& id,
    const hilti::rt::Vector<std::tuple<std::string, hilti::rt::integer::safe<int64_t>>>& labels) {
    OurPlugin->registerEnumType(ns, id, labels);
}

::EventHandlerPtr rt::internal_handler(const std::string& name) {
    // This always succeeds to return a handler. If there's no such event
    // yet, an empty handler instance is created.
    auto ev = zeek::compat::event_register_Register(name);

    // To support scoped event names, export their IDs implicitly. For the
    // lookup we pretend to be in the right module so that Bro doesn't tell
    // us the ID isn't exported (doh!).
    auto n = ::hilti::rt::split(name, "::");
    std::string mod;

    if ( n.size() > 1 )
        mod = n.front();
    else
        mod = GLOBAL_MODULE_NAME;

    if ( auto id = ::zeek::detail::lookup_ID(name.c_str(), mod.c_str()) )
        id->SetExport();

    return ev;
}

void rt::raise_event(EventHandlerPtr handler, const hilti::rt::Vector<::zeek::ValPtr>& args,
                     std::string_view location) {
    // Caller must have checked already that there's a handler availale.
    assert(handler);

    auto zeek_args =
        zeek::compat::TypeList_GetTypes(zeek::compat::FuncType_ArgTypes(zeek::compat::EventHandler_GetType(handler)));
    if ( args.size() != zeek::compat::TypeList_GetTypesSize(zeek_args) )
        throw TypeMismatch(fmt("expected %" PRIu64 " parameters, but got %zu",
                               zeek::compat::TypeList_GetTypesSize(zeek_args), args.size()),
                           location);

    ::zeek::Args vl = zeek::compat::ZeekArgs_New();
    for ( auto v : args ) {
        if ( v )
            zeek::compat::ZeekArgs_Append(vl, v);
        else
            // Shouldn't happen here, but we have to_vals() that
            // (legitimately) return null in certain contexts.
            throw InvalidValue("null value encountered after conversion", location);
    }

    zeek::compat::event_mgr_Enqueue(handler, vl);
}

::zeek::TypePtr rt::event_arg_type(EventHandlerPtr handler, uint64_t idx, std::string_view location) {
    assert(handler);

    auto zeek_args =
        zeek::compat::TypeList_GetTypes(zeek::compat::FuncType_ArgTypes(zeek::compat::EventHandler_GetType(handler)));
    if ( idx >= static_cast<uint64_t>(zeek::compat::TypeList_GetTypesSize(zeek_args)) )
        throw TypeMismatch(fmt("more parameters given than the %" PRIu64 " that the Zeek event expects",
                               zeek::compat::TypeList_GetTypesSize(zeek_args)),
                           location);

    return zeek::compat::ZeekArgs_Get(zeek_args, idx);
}

::zeek::ValPtr rt::current_conn(std::string_view location) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        return zeek::compat::Connection_ConnVal(x->analyzer->Conn());
    else
        throw ValueUnavailable("$conn not available", location);
}

::zeek::ValPtr rt::current_is_orig(std::string_view location) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        return zeek::compat::val_mgr_Bool(x->is_orig);
    else
        throw ValueUnavailable("$is_orig not available", location);
}

void rt::debug(const std::string_view& msg) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);
    rt::debug(*cookie, msg);
}

void rt::debug(const Cookie& cookie, const std::string_view& msg) {
    std::string name;
    std::string id;

    if ( const auto p = std::get_if<cookie::ProtocolAnalyzer>(&cookie) ) {
        auto name = p->analyzer->GetAnalyzerName();
        ZEEK_DEBUG(
            hilti::rt::fmt("[%s/%" PRIu32 "/%s] %s", name, p->analyzer->GetID(), (p->is_orig ? "orig" : "resp"), msg));
    }
    else if ( const auto f = std::get_if<cookie::FileAnalyzer>(&cookie) ) {
        auto name = ::file_mgr->GetComponentName(f->analyzer->Tag());
        ZEEK_DEBUG(hilti::rt::fmt("[%s/%" PRIu32 "] %s", name, f->analyzer->GetID(), msg));
    }
    else
        throw ValueUnavailable("neither $conn nor $file available for debug logging");
}

::zeek::ValPtr rt::current_file(std::string_view location) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::FileAnalyzer>(cookie) )
        return zeek::compat::File_ToVal(x->analyzer->GetFile());
    else
        throw ValueUnavailable("$file not available", location);
}

bool rt::is_orig() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        return x->is_orig;
    else
        throw ValueUnavailable("is_orig() not available in current context");
}

void rt::flip_roles() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    rt::debug(*cookie, "flipping roles");

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        x->analyzer->Conn()->FlipRoles();
    else
        throw ValueUnavailable("flip_roles() not available in current context");
}

uint64_t rt::number_packets() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) ) {
        return x->num_packets;
    }
    else
        throw ValueUnavailable("number_packets() not available in current context");
}

void rt::confirm_protocol() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) ) {
        auto tag = OurPlugin->tagForProtocolAnalyzer(x->analyzer->GetAnalyzerTag());
        return x->analyzer->ProtocolConfirmation(tag);
    }
    else
        throw ValueUnavailable("no current connection available");
}

void rt::reject_protocol(const std::string& reason) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        return x->analyzer->ProtocolViolation(reason.c_str());
    else
        throw ValueUnavailable("no current connection available");
}

static std::string _file_id(const rt::cookie::ProtocolAnalyzer& c) {
    auto id = hilti::rt::fmt("%" PRIu64 ".%" PRIu64 ".%d", c.analyzer_id, c.file_id, static_cast<int>(c.is_orig));
    return ::file_mgr->HashHandle(id);
}

void rt::file_begin() {
    // Nothing todo.
}

void rt::file_set_size(uint64_t size) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        ::file_mgr->SetSize(size, OurPlugin->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag()), c->analyzer->Conn(),
                            c->is_orig, _file_id(*c));
    else
        throw ValueUnavailable("no current connection available");
}

void rt::file_data_in(const hilti::rt::Bytes& data) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        ::file_mgr->DataIn(reinterpret_cast<const unsigned char*>(data.data()), data.size(),
                           OurPlugin->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag()), c->analyzer->Conn(),
                           c->is_orig, _file_id(*c));
    else
        throw ValueUnavailable("no current connection available");
}

void rt::file_data_in_at_offset(const hilti::rt::Bytes& data, uint64_t offset) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        ::file_mgr->DataIn(reinterpret_cast<const unsigned char*>(data.data()), data.size(), offset,
                           OurPlugin->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag()), c->analyzer->Conn(),
                           c->is_orig, _file_id(*c));
    else
        throw ValueUnavailable("no current connection available");
}

void rt::file_gap(uint64_t offset, uint64_t len) {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie) )
        ::file_mgr->Gap(offset, len, OurPlugin->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag()),
                        c->analyzer->Conn(), c->is_orig, _file_id(*c));
    else
        throw ValueUnavailable("no current connection available");
}

void rt::file_end() {
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = std::get_if<cookie::ProtocolAnalyzer>(cookie) ) {
        ::file_mgr->EndOfFile(_file_id(*c));
        c->file_id += 1;
    }
    else
        throw ValueUnavailable("no current connection available");
}
