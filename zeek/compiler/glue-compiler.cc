// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "glue-compiler.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

#include <hilti/ast/all.h>
#include <hilti/ast/builder/all.h>
#include <hilti/base/preprocessor.h>
#include <hilti/base/util.h>
#include <hilti/compiler/unit.h>

#include <spicy/global.h>

#include "debug.h"
#include "util.h"

using namespace spicy::zeek;

namespace builder = hilti::builder;

// Small parsing helpers.

using ParseError = std::runtime_error;

static void eat_spaces(const std::string& chunk, size_t* i) {
    while ( *i < chunk.size() && isspace(chunk[*i]) )
        ++*i;
}

static std::string::size_type looking_at(const std::string& chunk, std::string::size_type i,
                                         const std::string_view& token) {
    eat_spaces(chunk, &i);

    for ( char j : token ) {
        if ( i >= chunk.size() || chunk[i++] != j )
            return 0;
    }

    return i;
}

static void eat_token(const std::string& chunk, std::string::size_type* i, const std::string_view& token) {
    eat_spaces(chunk, i);

    auto j = looking_at(chunk, *i, token);

    if ( ! j )
        throw ParseError(hilti::util::fmt("expected token '%s'", token));

    *i = j;
}

static bool is_id_char(const std::string& chunk, size_t i) {
    char c = chunk[i];

    if ( isalnum(c) )
        return true;

    if ( strchr("_$%", c) != nullptr )
        return true;

    char prev = (i > 0) ? chunk[i - 1] : '\0';
    char next = (i + 1 < chunk.size()) ? chunk[i + 1] : '\0';

    if ( c == ':' && next == ':' )
        return true;

    if ( c == ':' && prev == ':' )
        return true;

    return false;
}

static bool is_path_char(const std::string& chunk, size_t i) {
    char c = chunk[i];
    return (! isspace(c)) && c != ';';
}

static hilti::ID extract_id(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    size_t j = *i;

    while ( j < chunk.size() && is_id_char(chunk, j) )
        ++j;

    if ( *i == j )
        throw ParseError("expected id");

    auto id = chunk.substr(*i, j - *i);
    *i = j;
    return hilti::ID(hilti::util::replace(id, "%", "0x25_"));
}

static hilti::rt::filesystem::path extract_path(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    size_t j = *i;

    while ( j < chunk.size() && is_path_char(chunk, j) )
        ++j;

    if ( *i == j )
        throw ParseError("expected path");

    auto path = chunk.substr(*i, j - *i);
    *i = j;
    return path;
}

static int extract_int(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    size_t j = *i;

    if ( j < chunk.size() ) {
        if ( chunk[j] == '-' ) {
            ++j;
        }
        if ( chunk[j] == '+' )
            ++j;
    }

    while ( j < chunk.size() && isdigit(chunk[j]) )
        ++j;

    if ( *i == j )
        throw ParseError("expected integer");

    auto x = chunk.substr(*i, j - *i);
    *i = j;

    int integer = 0;
    hilti::util::atoi_n(x.begin(), x.end(), 10, &integer);
    return integer;
}

static std::string extract_expr(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    int level = 0;
    bool done = false;
    size_t j = *i;

    while ( j < chunk.size() ) {
        switch ( chunk[j] ) {
            case '(':
            case '[':
            case '{':
                ++level;
                ++j;
                continue;

            case ')':
                if ( level == 0 ) {
                    done = true;
                    break;
                }

                // fall-through

            case ']':
            case '}':
                if ( level == 0 )
                    throw ParseError("expected Spicy expression");

                --level;
                ++j;
                continue;

            case ',':
                if ( level == 0 ) {
                    done = true;
                    break;
                }

                // fall-through

            default: ++j;
        }

        if ( done )
            break;

        if ( *i == j )
            break;
    }

    auto expr = hilti::util::trim(chunk.substr(*i, j - *i));
    *i = j;
    return expr;
}

static hilti::rt::Port extract_port(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    std::string s;
    size_t j = *i;

    while ( j < chunk.size() && isdigit(chunk[j]) )
        ++j;

    if ( *i == j )
        throw ParseError("cannot parse port specification");

    hilti::rt::Protocol proto;
    uint64_t port = std::numeric_limits<uint64_t>::max();

    s = chunk.substr(*i, j - *i);
    hilti::util::atoi_n(s.begin(), s.end(), 10, &port);

    if ( port > 65535 )
        throw ParseError("port outside of valid range");

    *i = j;

    if ( chunk[*i] != '/' )
        throw ParseError("cannot parse port specification");

    (*i)++;

    if ( looking_at(chunk, *i, "tcp") ) {
        proto = hilti::rt::Protocol::TCP;
        eat_token(chunk, i, "tcp");
    }

    else if ( looking_at(chunk, *i, "udp") ) {
        proto = hilti::rt::Protocol::UDP;
        eat_token(chunk, i, "udp");
    }

    else if ( looking_at(chunk, *i, "icmp") ) {
        proto = hilti::rt::Protocol::ICMP;
        eat_token(chunk, i, "icmp");
    }

    else
        throw ParseError("cannot parse port specification");

    return {static_cast<uint16_t>(port), proto};
}

GlueCompiler::GlueCompiler(Driver* driver, int zeek_version) : _driver(driver), _zeek_version(zeek_version) {}

GlueCompiler::~GlueCompiler() {}

hilti::Result<std::string> GlueCompiler::getNextEvtBlock(std::istream& in, int* lineno) const {
    std::string chunk;

    // Parser need to track whether we are inside a string or a comment.
    enum State { Default, InComment, InString } state = Default;
    char prev = '\0';

    while ( true ) {
        char cur;
        in.get(cur);
        if ( in.eof() ) {
            chunk = hilti::util::trim(std::move(chunk));
            if ( chunk.empty() )
                // Legitimate end of data.
                return std::string();
            else
                // End of input before semicolon.
                return hilti::result::Error("unexpected end of file");
        }

        switch ( state ) {
            case Default:
                if ( cur == '"' && prev != '\\' )
                    state = InString;

                if ( cur == '#' && prev != '\\' ) {
                    state = InComment;
                    continue;
                }

                if ( cur == '\n' )
                    ++*lineno;

                if ( cur == ';' ) {
                    // End of block found.
                    chunk = hilti::util::trim(std::move(chunk));
                    if ( chunk.size() )
                        return chunk + ';';
                    else
                        return hilti::result::Error("empty block");
                }

                break;

            case InString:
                if ( cur == '"' && prev != '\\' )
                    state = Default;

                if ( cur == '\n' )
                    ++*lineno;

                break;

            case InComment:
                if ( cur != '\n' )
                    // skip
                    continue;

                state = Default;
                ++*lineno;
        }

        chunk += cur;
        prev = cur;
    }
}

void GlueCompiler::preprocessEvtFile(hilti::rt::filesystem::path& path, std::istream& in, std::ostream& out) {
    hilti::util::SourceCodePreprocessor pp({{"ZEEK_VERSION", _zeek_version}});
    int lineno = 0;

    while ( true ) {
        lineno++;

        std::string line;
        std::getline(in, line);

        if ( in.eof() )
            break;

        auto trimmed = hilti::util::trim(line);
        _locations.emplace_back(path, lineno);

        if ( hilti::util::startsWith(trimmed, "@") ) {
            // Output empty line to keep line numbers the same
            out << '\n';

            auto m = hilti::util::split1(trimmed);

            if ( auto rc = pp.processLine(m.first, m.second); ! rc )
                throw ParseError(rc.error());
        }

        else {
            switch ( pp.state() ) {
                case hilti::util::SourceCodePreprocessor::State::Include: out << line << '\n'; break;
                case hilti::util::SourceCodePreprocessor::State::Skip:
                    // Output empty line to keep line numbers the same
                    out << '\n';
                    break;
            }
        }
    }

    if ( pp.expectingDirective() )
        throw ParseError("unterminated preprocessor directive");
}

bool GlueCompiler::loadEvtFile(hilti::rt::filesystem::path& path) {
    std::ifstream in(path);

    if ( ! in ) {
        hilti::logger().error(hilti::util::fmt("cannot open %s", path));
        return false;
    }

    ZEEK_DEBUG(hilti::util::fmt("Loading events from %s", path));

    std::vector<glue::Event> new_events;

    try {
        std::stringstream preprocessed;
        preprocessEvtFile(path, in, preprocessed);
        preprocessed.clear();
        preprocessed.seekg(0);

        int lineno = 1;

        while ( true ) {
            _locations.emplace_back(path, lineno);
            auto chunk = getNextEvtBlock(preprocessed, &lineno);
            if ( ! chunk )
                throw ParseError(chunk.error());

            if ( chunk->empty() )
                break; // end of input

            _locations.pop_back();
            _locations.emplace_back(path, lineno);

            if ( looking_at(*chunk, 0, "protocol") ) {
                auto a = parseProtocolAnalyzer(*chunk);
                _protocol_analyzers.push_back(a);
                ZEEK_DEBUG(hilti::util::fmt("  Got protocol analyzer definition for %s", a.name));
            }

            else if ( looking_at(*chunk, 0, "file") ) {
                auto a = parseFileAnalyzer(*chunk);
                _file_analyzers.push_back(a);
                ZEEK_DEBUG(hilti::util::fmt("  Got file analyzer definition for %s", a.name));
            }

            else if ( looking_at(*chunk, 0, "packet") ) {
#ifdef HAVE_PACKET_ANALYZERS
                auto a = parsePacketAnalyzer(*chunk);
                _packet_analyzers.push_back(a);
                ZEEK_DEBUG(hilti::util::fmt("  Got packet analyzer definition for %s", a.name));
#else
                throw ParseError("packet analyzers require Zeek >= 4.0");
#endif
            }

            else if ( looking_at(*chunk, 0, "on") ) {
                auto ev = parseEvent(*chunk);
                ev.file = path;
                new_events.push_back(ev);
                ZEEK_DEBUG(hilti::util::fmt("  Got event definition for %s", ev.name));
            }

            else if ( looking_at(*chunk, 0, "import") ) {
                size_t i = 0;
                eat_token(*chunk, &i, "import");

                hilti::ID module = extract_id(*chunk, &i);
                std::optional<hilti::ID> scope;

                if ( looking_at(*chunk, i, "from") ) {
                    eat_token(*chunk, &i, "from");
                    scope = extract_path(*chunk, &i);
                    ZEEK_DEBUG(hilti::util::fmt("  Got module %s to import from scope %s", module, *scope));
                }
                else
                    ZEEK_DEBUG(hilti::util::fmt("  Got module %s to import", module));

                _imports.emplace_back(hilti::ID(module), std::move(scope));
            }

            else
                throw ParseError("expected 'import', '{file,protocol} analyzer', or 'on'");

            _locations.pop_back();
        }

    } catch ( const ParseError& e ) {
        if ( *e.what() )
            hilti::logger().error(e.what(), _locations.back());

        return false;
    }

    for ( auto&& ev : new_events )
        _events.push_back(ev);

    return true;
}

void GlueCompiler::addSpicyModule(const hilti::ID& id, const hilti::rt::filesystem::path& file) {
    glue::SpicyModule module;
    module.id = id;
    module.file = file;
    _spicy_modules[id] = std::make_shared<glue::SpicyModule>(std::move(module));
}

glue::ProtocolAnalyzer GlueCompiler::parseProtocolAnalyzer(const std::string& chunk) {
    glue::ProtocolAnalyzer a;
    a.location = _locations.back();

    size_t i = 0;

    eat_token(chunk, &i, "protocol");
    eat_token(chunk, &i, "analyzer");
    a.name = hilti::util::replace(extract_id(chunk, &i), "::", "_");

    eat_token(chunk, &i, "over");

    auto proto = hilti::util::tolower(extract_id(chunk, &i).str());

    if ( proto == "tcp" )
        a.protocol = hilti::rt::Protocol::TCP;

    else if ( proto == "udp" )
        a.protocol = hilti::rt::Protocol::UDP;

    else if ( proto == "icmp" )
        a.protocol = hilti::rt::Protocol::ICMP;

    else
        throw ParseError(hilti::util::fmt("unknown transport protocol '%s'", proto));

    eat_token(chunk, &i, ":");

    enum { orig, resp, both } dir;

    while ( true ) {
        if ( looking_at(chunk, i, "parse") ) {
            eat_token(chunk, &i, "parse");

            if ( looking_at(chunk, i, "originator") ) {
                eat_token(chunk, &i, "originator");
                dir = orig;
            }

            else if ( looking_at(chunk, i, "responder") ) {
                eat_token(chunk, &i, "responder");
                dir = resp;
            }

            else if ( looking_at(chunk, i, "with") )
                dir = both;

            else
                throw ParseError("invalid \"parse with ...\" specification");

            eat_token(chunk, &i, "with");
            auto unit = extract_id(chunk, &i);

            switch ( dir ) {
                case orig: a.unit_name_orig = unit; break;

                case resp: a.unit_name_resp = unit; break;

                case both:
                    a.unit_name_orig = unit;
                    a.unit_name_resp = unit;
                    break;
            }
        }

        else if ( looking_at(chunk, i, "ports") ) {
            eat_token(chunk, &i, "ports");
            eat_token(chunk, &i, "{");

            while ( true ) {
                auto p = extract_port(chunk, &i);
                a.ports.push_back(p);

                if ( looking_at(chunk, i, "}") ) {
                    eat_token(chunk, &i, "}");
                    break;
                }

                eat_token(chunk, &i, ",");
            }
        }

        else if ( looking_at(chunk, i, "port") ) {
            eat_token(chunk, &i, "port");
            auto p = extract_port(chunk, &i);
            a.ports.push_back(p);
        }

        else if ( looking_at(chunk, i, "replaces") ) {
            eat_token(chunk, &i, "replaces");
            a.replaces = extract_id(chunk, &i);
        }

        else
            throw ParseError("unexpect token");

        if ( looking_at(chunk, i, ";") )
            break; // All done.

        eat_token(chunk, &i, ",");
    }

    return a;
}

glue::FileAnalyzer GlueCompiler::parseFileAnalyzer(const std::string& chunk) {
    glue::FileAnalyzer a;
    a.location = _locations.back();

    size_t i = 0;

    eat_token(chunk, &i, "file");
    eat_token(chunk, &i, "analyzer");
    a.name = hilti::util::replace(extract_id(chunk, &i).str(), "::", "_");

    eat_token(chunk, &i, ":");

    while ( true ) {
        if ( looking_at(chunk, i, "parse") ) {
            eat_token(chunk, &i, "parse");
            eat_token(chunk, &i, "with");
            a.unit_name = extract_id(chunk, &i);
        }

        else if ( looking_at(chunk, i, "mime-type") ) {
            eat_token(chunk, &i, "mime-type");
            auto mtype = extract_path(chunk, &i);
            a.mime_types.push_back(mtype.string());
        }

        else if ( looking_at(chunk, i, "replaces") ) {
            if ( _zeek_version < 40100 )
                throw ParseError("file analyzer replacement requires Zeek 4.1+");

            eat_token(chunk, &i, "replaces");
            a.replaces = extract_id(chunk, &i);
        }

        else
            throw ParseError("unexpect token");

        if ( looking_at(chunk, i, ";") )
            break; // All done.

        eat_token(chunk, &i, ",");
    }

    return a;
}

#ifdef HAVE_PACKET_ANALYZERS
glue::PacketAnalyzer GlueCompiler::parsePacketAnalyzer(const std::string& chunk) {
    glue::PacketAnalyzer a;
    a.location = _locations.back();

    size_t i = 0;

    eat_token(chunk, &i, "packet");
    eat_token(chunk, &i, "analyzer");

    // We don't normalize the name here so that the user can address
    // it with the expected spelling.
    a.name = extract_id(chunk, &i).str();

    eat_token(chunk, &i, ":");

    while ( true ) {
        if ( looking_at(chunk, i, "parse") ) {
            eat_token(chunk, &i, "parse");
            eat_token(chunk, &i, "with");
            a.unit_name = extract_id(chunk, &i);
        }

        else
            throw ParseError("unexpect token");

        if ( looking_at(chunk, i, ";") )
            break; // All done.

        eat_token(chunk, &i, ",");
    }

    return a;
}
#endif

glue::Event GlueCompiler::parseEvent(const std::string& chunk) {
    glue::Event ev;
    ev.location = _locations.back();

    // We use a quite negative hook priority here to make sure these run last
    // after anything the grammar defines by default.
    ev.priority = -1000;

    size_t i = 0;

    eat_token(chunk, &i, "on");
    ev.path = extract_id(chunk, &i);

    if ( looking_at(chunk, i, "if") ) {
        eat_token(chunk, &i, "if");
        eat_token(chunk, &i, "(");

        ev.condition = extract_expr(chunk, &i);
        eat_token(chunk, &i, ")");
    }

    eat_token(chunk, &i, "->");
    eat_token(chunk, &i, "event");
    ev.name = extract_id(chunk, &i);

    eat_token(chunk, &i, "(");

    bool first = true;
    size_t j = 0;

    while ( true ) {
        j = looking_at(chunk, i, ")");

        if ( j ) {
            i = j;
            break;
        }

        if ( ! first )
            eat_token(chunk, &i, ",");

        auto expr = extract_expr(chunk, &i);
        ev.exprs.push_back(expr);
        first = false;
    }

    if ( looking_at(chunk, i, "&priority") ) {
        eat_token(chunk, &i, "&priority");
        eat_token(chunk, &i, "=");
        ev.priority = extract_int(chunk, &i);
    }

    eat_token(chunk, &i, ";");
    eat_spaces(chunk, &i);

    if ( i < chunk.size() )
        // This shouldn't actually be possible ...
        throw ParseError("unexpected characters at end of line");

    return ev;
}

bool GlueCompiler::compile() {
    auto init_module = hilti::Module(hilti::ID("spicy_init"));

    auto import_ = hilti::declaration::ImportedModule(ID("zeek_rt"), std::string(".hlt"));
    init_module.add(std::move(import_));

    auto preinit_body = hilti::builder::Builder(_driver->context());

    for ( auto&& [id, m] : _spicy_modules )
        m->spicy_module = hilti::Module(hilti::ID(hilti::util::fmt("spicy_hooks_%s", id)));

    if ( ! PopulateEvents() )
        return false;

    for ( auto& a : _protocol_analyzers ) {
        ZEEK_DEBUG(hilti::util::fmt("Adding protocol analyzer '%s'", a.name));

        if ( a.unit_name_orig ) {
            if ( auto ui = _driver->lookupUnit(a.unit_name_orig) )
                a.unit_orig = *ui;
            else {
                hilti::logger().error(
                    hilti::util::fmt("unknown unit type %s with protocol analyzer %s", a.unit_name_orig, a.name));
                return false;
            }
        }

        if ( a.unit_name_resp ) {
            if ( auto ui = _driver->lookupUnit(a.unit_name_resp) )
                a.unit_resp = *ui;
            else {
                hilti::logger().error(
                    hilti::util::fmt("unknown unit type %s with protocol analyzer %s", a.unit_name_resp, a.name));
                return false;
            }
        }

        hilti::ID protocol;

        switch ( a.protocol ) {
            case hilti::rt::Protocol::TCP: protocol = hilti::ID("hilti::Protocol::TCP"); break;
            case hilti::rt::Protocol::UDP: protocol = hilti::ID("hilti::Protocol::UDP"); break;
            default: hilti::logger().internalError("unexpected protocol");
        }

        auto register_ =
            builder::call("zeek_rt::register_protocol_analyzer",
                          {builder::string(a.name), builder::id(protocol),
                           builder::vector(hilti::util::transform(a.ports, [](auto p) { return builder::port(p); })),
                           builder::string(a.unit_name_orig), builder::string(a.unit_name_resp),
                           builder::string(a.replaces)});

        init_module.add(std::move(register_));
    }

    for ( auto& a : _file_analyzers ) {
        ZEEK_DEBUG(hilti::util::fmt("Adding file analyzer '%s'", a.name));

        if ( a.unit_name ) {
            if ( auto ui = _driver->lookupUnit(a.unit_name) )
                a.unit = *ui;
            else {
                hilti::logger().error(
                    hilti::util::fmt("unknown unit type %s with file analyzer %s", a.unit_name, a.name));
                return false;
            }
        }

        auto register_ =
            builder::call("zeek_rt::register_file_analyzer",
                          {builder::string(a.name),
                           builder::vector(
                               hilti::util::transform(a.mime_types, [](auto m) { return builder::string(m); })),
                           builder::string(a.unit_name), builder::string(a.replaces)});

        init_module.add(std::move(register_));
    }

#ifdef HAVE_PACKET_ANALYZERS
    for ( auto& a : _packet_analyzers ) {
        ZEEK_DEBUG(hilti::util::fmt("Adding packet analyzer '%s'", a.name));

        if ( a.unit_name ) {
            if ( auto ui = _driver->lookupUnit(a.unit_name) )
                a.unit = *ui;
            else {
                hilti::logger().error(
                    hilti::util::fmt("unknown unit type %s with packet analyzer %s", a.unit_name, a.name));
                return false;
            }
        }

        auto register_ =
            builder::call("zeek_rt::register_packet_analyzer", {builder::string(a.name), builder::string(a.unit_name)});

        init_module.add(std::move(register_));
    }
#endif

#if 0
    // Check that our events align with what's defined on the Zeek side.
    // TODO: See comment in header for CheckZeekEvent().
    for ( auto&& ev : _events ) {
        if ( ! CheckZeekEvent(ev) )
            return false;
    }
#endif

    // Create the Spicy hooks and accessor functions.
    for ( auto&& ev : _events ) {
        if ( ! CreateSpicyHook(&ev) )
            return false;
    }

    // Create Zeek enum types for exported Spicy enums. We do this here
    // mainly for when compiling C+ code offline. When running live inside
    // Zeek, we also do it earlier through the GlueBuilder itself so that the
    // new types are already available when scripts are parsed. (And
    // registering twice isn't a problem.)
    for ( auto&& e : _driver->publicEnumTypes() ) {
        auto labels = hilti::rt::transform(e.type.as<type::Enum>().labels(), [](const auto& l) {
            return builder::tuple({builder::string(l.id()), builder::integer(l.value())});
        });

        preinit_body.addCall("zeek_rt::register_enum_type", {builder::string(e.id.namespace_()),
                                                             builder::string(e.id.local()), builder::vector(labels)});
    }


    for ( auto&& [id, m] : _spicy_modules ) {
        // Import runtime module.
        auto import_ = hilti::declaration::ImportedModule(ID("zeek_rt"), std::string(".hlt"));
        m->spicy_module->add(std::move(import_));

        // Create a vector of unique parent paths from all EVTs files going into this module.
        auto search_dirs = hilti::util::transform(m->evts, [](auto p) { return p.parent_path(); });
        auto search_dirs_vec = std::vector<hilti::rt::filesystem::path>(search_dirs.begin(), search_dirs.end());

        // Import any dependencies.
        for ( const auto& [module, scope] : _imports ) {
            auto import_ = hilti::declaration::ImportedModule(module, std::string(".spicy"), scope, search_dirs_vec);
            m->spicy_module->add(std::move(import_));
        }

        _driver->addInput(std::move(*m->spicy_module));
    }

    if ( ! preinit_body.empty() ) {
        auto preinit_function =
            hilti::builder::function("zeek_preinit", type::Void(), {}, preinit_body.block(),
                                     hilti::type::function::Flavor::Standard, declaration::Linkage::PreInit);
        init_module.add(std::move(preinit_function));
    }

    _driver->addInput(std::move(init_module));
    return true;
}

bool GlueCompiler::PopulateEvents() {
    for ( auto& ev : _events ) {
        if ( ev.unit_type )
            // Already done.
            continue;

        UnitInfo uinfo;

        // If we find the path itself, it's refering to a unit type directly;
        // then add a "%done" to form the hook name.
        if ( auto ui = _driver->lookupUnit(ev.path) ) {
            uinfo = *ui;
            ev.unit = ev.path;
            ev.hook = ev.unit + hilti::ID("0x25_done");
        }

        else {
            // Strip the last element of the path, the remainder must refer
            // to a unit now.
            ev.unit = ev.path.namespace_();
            if ( ! ev.unit ) {
                hilti::logger().error(hilti::util::fmt("unit type missing in hook '%s'", ev.path));
                return false;
            }

            if ( auto ui = _driver->lookupUnit(ev.unit) ) {
                uinfo = *ui;
                ev.hook = ev.path;
            }
            else {
                hilti::logger().error(hilti::util::fmt("unknown unit type '%s'", ev.unit));
                return false;
            }
        }

        ev.unit_type = std::move(uinfo.type.as<spicy::type::Unit>());
        ev.unit_module_id = uinfo.module_id;
        ev.unit_module_path = uinfo.module_path;

        if ( auto i = _spicy_modules.find(uinfo.module_id); i != _spicy_modules.end() ) {
            ev.spicy_module = i->second;
            i->second->evts.insert(ev.file);
        }
        else
            hilti::logger().internalError(
                hilti::util::fmt("module %s not known in Spicy module list", uinfo.module_id));

        // Create accesor expression for event parameters.
        int nr = 0;

        for ( const auto& e : ev.exprs ) {
            glue::ExpressionAccessor acc;
            acc.nr = ++nr;
            acc.expression = e;
            acc.location = ev.location;
            // acc.dollar_id = util::startsWith(e, "$");
            ev.expression_accessors.push_back(acc);
        }
    }

    return true;
}

#include <hilti/ast/operators/struct.h>

#include <spicy/ast/detail/visitor.h>

// Helper visitor to wrap expressions using the the TryMember operator into a
// "deferred" expression.
class WrapTryMemberVisitor : public hilti::visitor::PostOrder<void, WrapTryMemberVisitor> {
public:
    WrapTryMemberVisitor(bool catch_exception) : _catch_exception(catch_exception) {}

    void operator()(const hilti::expression::UnresolvedOperator& n, position_t p) {
        if ( n.kind() == hilti::operator_::Kind::TryMember )
            p.node = hilti::expression::Deferred(hilti::Expression(n), _catch_exception);
    }

private:
    bool _catch_exception;
};

static hilti::Result<hilti::Expression> _parseArgument(const std::string& expression, bool catch_exception,
                                                       const hilti::Meta& meta) {
    auto expr = spicy::parseExpression(expression, meta);
    if ( ! expr )
        return hilti::result::Error(hilti::util::fmt("error parsing event argument expression '%s'", expression));

    // If the expression uses the ".?" operator, we need to defer evaluation
    // so that we can handle potential exceptions at runtime.
    auto v = WrapTryMemberVisitor(catch_exception);
    auto n = hilti::Node(*expr);
    for ( auto i : v.walk(&n) )
        v.dispatch(i);

    return n.as<hilti::Expression>();
}

bool GlueCompiler::CreateSpicyHook(glue::Event* ev) {
    auto mangled_event_name = hilti::util::fmt("%s_%p", hilti::util::replace(ev->name.str(), "::", "_"), ev);
    auto meta = Meta(ev->location);

    // Find the Spicy module that this event belongs to.
    ZEEK_DEBUG(hilti::util::fmt("Adding Spicy hook '%s' for event %s", ev->hook, ev->name));

    auto import_ = hilti::declaration::ImportedModule(ev->unit_module_id, ev->unit_module_path);
    ev->spicy_module->spicy_module->add(std::move(import_));

    // Define Zeek-side event handler.
    auto handler_id = ID(hilti::util::fmt("__zeek_handler_%s", mangled_event_name));
    auto handler = builder::global(handler_id, builder::call("zeek_rt::internal_handler", {builder::string(ev->name)}),
                                   hilti::declaration::Linkage::Private, meta);
    ev->spicy_module->spicy_module->add(std::move(handler));

    // Create the hook body that raises the event.
    auto body = hilti::builder::Builder(_driver->context());

    // If the event comes with a condition, evaluate that first.
    if ( ev->condition.size() ) {
        auto cond = spicy::parseExpression(ev->condition, meta);
        if ( ! cond ) {
            hilti::logger().error(hilti::util::fmt("error parsing conditional expression '%s'", ev->condition));
            return false;
        }

        auto exit_ = body.addIf(builder::not_(*cond), meta);
        exit_->addReturn(meta);
    }

    // Log event in debug code. Note: We cannot log the Zeek-side version
    // (i.e., Vals with their types) because we wouldn't be able to determine
    // those for events that don't have a handler (or at least a prototype)
    // defined because we use the existing type definition to determine what
    // Zeek type to convert an Spicy type into. However, we wouldn't want
    // limit logging to events with handlers.
    if ( _driver->hiltiOptions().debug ) {
        std::vector<Expression> fmt_args = {builder::string(ev->name)};

        for ( const auto&& [i, e] : hilti::util::enumerate(ev->expression_accessors) ) {
            if ( hilti::util::startsWith(e.expression, "$") ) {
                fmt_args.emplace_back(builder::string(e.expression));
                continue;
            }

            if ( auto expr = _parseArgument(e.expression, true, meta) )
                fmt_args.emplace_back(std::move(*expr));
            else
                // We'll catch and report this below.
                fmt_args.emplace_back(builder::string("<error>"));
        }

        std::vector<std::string> fmt_ctrls(fmt_args.size() - 1, "%s");
        auto fmt_str = hilti::util::fmt("-> event %%s(%s)", hilti::util::join(fmt_ctrls, ", "));
        auto msg = builder::modulo(builder::string(fmt_str), builder::tuple(std::move(fmt_args)));
        auto call = builder::call("zeek_rt::debug", {std::move(msg)});
        body.addExpression(std::move(call));
    }

    // Nothing to do if there's not handler defined.
    auto have_handler = builder::call("zeek_rt::have_handler", {builder::id(handler_id)}, meta);
    auto exit_ = body.addIf(builder::not_(have_handler), meta);
    exit_->addReturn(meta);

    // Build event's argument vector.
    body.addLocal(ID("args"), hilti::type::Vector(builder::typeByID("zeek_rt::Val"), meta), meta);

    int i = 0;
    for ( const auto& e : ev->expression_accessors ) {
        Expression val;

        if ( e.expression == "$conn" )
            val = builder::call("zeek_rt::current_conn", {location(e)}, meta);
        else if ( e.expression == "$file" )
            val = builder::call("zeek_rt::current_file", {location(e)}, meta);
        else if ( e.expression == "$is_orig" )
            val = builder::call("zeek_rt::current_is_orig", {location(e)}, meta);
        else {
            if ( hilti::util::startsWith(e.expression, "$") ) {
                hilti::logger().error(hilti::util::fmt("unknown reserved parameter '%s'", e.expression));
                return false;
            }

            auto expr = _parseArgument(e.expression, false, meta);
            if ( ! expr ) {
                hilti::logger().error(expr.error());
                return false;
            }

            auto ztype = builder::call("zeek_rt::event_arg_type",
                                       {builder::id(handler_id), builder::integer(i), location(e)}, meta);
            val = builder::call("zeek_rt::to_val", {std::move(*expr), ztype, location(e)}, meta);
        }

        body.addMemberCall(builder::id("args"), "push_back", {val}, meta);
        i++;
    }

    body.addCall("zeek_rt::raise_event", {builder::id(handler_id), builder::move(builder::id("args")), location(*ev)},
                 meta);

    auto attrs = hilti::AttributeSet({hilti::Attribute("&priority", builder::integer(ev->priority))});
    auto unit_hook = spicy::Hook({}, body.block(), spicy::Engine::All, {}, meta);
    auto hook = spicy::type::unit::item::UnitHook(ev->hook.local(), std::move(unit_hook), meta);
    auto hook_decl = spicy::declaration::UnitHook(ev->hook, builder::typeByID(ev->unit), std::move(hook), meta);
    ev->spicy_module->spicy_module->add(Declaration(hook_decl));

    return true;
}

hilti::Expression GlueCompiler::location(const glue::Event& ev) { return builder::string(ev.location); }

hilti::Expression GlueCompiler::location(const glue::ExpressionAccessor& e) { return builder::string(e.location); }
