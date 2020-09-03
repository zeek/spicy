#!/usr/bin/env python3

"""Quickly produce Wireshark dissectors from Spicy grammars.

Given a Spicy grammar this script can be produce a Wireshark dissector for that
protocol. We currently faithfully and mechanically try to reproduce the grammar
in the dissector. Since Spicy grammars encode little business logic beyond wire
representations, the produced dissectors will also miss such more tailored
integration (i.e., there is currently no way here to customize domain-specific
value pretty-printing, reorganizing parsed data for representation beyond the
parsed wire format, hiding of uninterresting information, ..).

This script requires:
    - `spicyc` in `PATH`, compiled with JIT support
    - the compiler used to compile Spicy
    - pkg-config
    - a Wireshark installation including headers
        - Wireshark also requires glib-2.0 installation including headers

By default this script will produce a shared library which can be added to
Wireshark by e.g., copying it to the folder
`<prefix>/lib/wireshark/plugins/3-2/epan`."""

import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
from typing import List


def parse_args(argv: List) -> argparse.Namespace:
    """Parse arguments."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--parser", required=True,
        help="Fully qualified name of the parser, e.g, 'Module::Parser'")
    parser.add_argument("sources", nargs='+', type=Path,
                        help='Spicy source files to expose')
    parser.add_argument('--plugin_version', type=str, required=True,
                        help='Version of the generated plugin')
    parser.add_argument('--plugin_want_major', type=int, required=True,
                        help='Major of the Wireshark version to target')
    parser.add_argument('--plugin_want_minor', type=int, required=True,
                        help='Minor of the Wireshark version to target')
    parser.add_argument('--wireshark_include_dir', type=str, required=True,
                        help="Wireshark include directory")
    parser.add_argument('--wireshark_library_dir', type=str, required=True,
                        help="Wireshark library directory")
    parser.add_argument('--output', type=Path, required=True,
                        help="Output file")
    parser.add_argument('--generate_cc', action='store_true',
                        help="Stop after generating C++ code")

    return parser.parse_args(argv)


def gen_plugin(source: Path, opts: argparse.Namespace) -> str:
    """Generate a Wireshark plugin from a Spicy parser."""
    spicy_cc = subprocess.run(['spicyc', '-cQK', source],
                              check=True, capture_output=True)\
        .stdout.decode('utf-8')

    name = opts.parser.replace('::', ' ')
    filter_name = opts.parser.replace(':', '_').lower()
    typeinfo_name = '__hlt::type_info::__ti_' + opts.parser.replace('::', '_')

    epilog = textwrap.dedent("""
        #define SPICY_WIRESHARK_FILTER_NAME "{}"
        #define SPICY_WIRESHARK_NAME "{}"
        #define SPICY_WIRESHARK_SHORT_NAME "{}"
        #define SPICY_TYPEINFO {}
        """.format(filter_name, name, name, typeinfo_name) +
        """
        using SPICY_WIRESHARK_DATA = __hlt::{};
        namespace SPICY_WIRESHARK_PARSER = hlt::{};
        """.format(opts.parser, opts.parser))

    wrapper = textwrap.dedent("""
        #include <config.h>
        #include <epan/packet.h>
        #include <epan/prefs.h>
        #include <epan/proto.h>
        #include <gmodule.h>

        #define WS_BUILD_DLL
        #include "ws_symbol_export.h"

        static int proto = -1;

        struct WiresharkInfo {
            struct HeaderField {
                int hf;
                std::string name;
                std::string abbrev;
                std::string description;
                ftenum type;
                int display;
            };

            struct Subtree {
                gint et;
                std::string name;
                std::vector<WiresharkInfo> children;
            };

            // Only at most one of these is set at a time.
            std::optional<Subtree> et = std::nullopt;
            std::optional<HeaderField> hf = std::nullopt;

            std::function<void(const WiresharkInfo& wi, const hilti::rt::type_info::Value&, proto_tree*, tvbuff_t*, uint64_t,
                               int64_t)>
                draw_fn = [](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree, tvbuff_t* tvb,
                             uint64_t start, int64_t length) {};

            WiresharkInfo() = default;
            WiresharkInfo(const hilti::rt::type_info::Value& v, std::string name);
            WiresharkInfo(WiresharkInfo&&) = default;
            WiresharkInfo& operator=(WiresharkInfo&&) = default;

            // Registers subtree and header field arrays.
            //
            // This function should be called exactly once and be passed a static WiresharkInfo.
            static void register_handles(WiresharkInfo& wi, int protocol_handle) {
                static std::vector<gint*> et;
                static std::vector<hf_register_info> hf;

                std::function<void(WiresharkInfo&)> get_handles = [&get_handles](WiresharkInfo& wi_) {
                    if ( wi_.et ) {
                        et.push_back(&wi_.et->et);

                        for ( auto&& child : wi_.et->children )
                            get_handles(child);
                    }

                    if ( wi_.hf )
                        hf.push_back({&wi_.hf->hf,
                                      {wi_.hf->name.c_str(), wi_.hf->abbrev.c_str(), wi_.hf->type, wi_.hf->display, NULL, 0,
                                       wi_.hf->description.c_str(), HFILL}});
                };
                get_handles(wi);

                if ( ! et.empty() )
                    proto_register_subtree_array(&et[0], et.size());

                if ( ! hf.empty() )
                    proto_register_field_array(protocol_handle, &hf[0], hf.size());
            }

            void draw(const hilti::rt::type_info::Value& v, proto_tree* tree, tvbuff_t* tvb, uint64_t start, int64_t length) {
                // We delegate drawing of fields to the drawing of Struct.
                if ( et ) {
                    draw_fn(*this, v, tree, tvb, start, length);
                }
            }
        };

        template<typename Parser>
        WiresharkInfo make_info(const hilti::rt::TypeInfo& ti, std::string name) {
            spicy::rt::ParsedUnit gunit;
            hilti::rt::ValueReference<Parser> unit = hilti::rt::reference::make_value<Parser>((Parser()));

            spicy::rt::ParsedUnit::initialize(gunit, unit, &ti);

            return WiresharkInfo(gunit.value(), std::move(name));
        }

        WiresharkInfo::WiresharkInfo(const hilti::rt::type_info::Value& v, std::string name) {
            std::visit(
                hilti::rt::type_info::overload{
                    [&](const hilti::rt::type_info::Address& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, hilti::rt::to_string(x.get(v)).c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::Any& x) {
                        // Intentionally left blank.
                    },
                    [&](const hilti::rt::type_info::Bool& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, x.get(v) ? "true" : "false");
                        };
                    },
                    [&](const hilti::rt::type_info::Bytes& x) {
                        hf = HeaderField{-1, name, name, name, FT_BYTES, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            auto& bytes = x.get(v);
                            proto_tree_add_bytes_format_value(tree, wi.hf->hf, tvb, start, length,
                                                              reinterpret_cast<const guint8*>(bytes.data()), "%s",
                                                              to_string_for_print(bytes).c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::BytesIterator& x) {
                        hf = HeaderField{-1, name, name, name, FT_UINT8, BASE_DEC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            try {
                                proto_tree_add_uint(tree, wi.hf->hf, tvb, start, length, *(x.get(v)));
                            } catch ( const hilti::rt::RuntimeError& e ) {
                                REPORT_DISSECTOR_BUG("iterator of field %s is invalid: %s", wi.hf->abbrev.c_str(), e.what());
                            }
                        };
                    },
                    [&](const hilti::rt::type_info::Enum& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, x.get(v).name.c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::Error& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, x.get(v).description().c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::Exception& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, x.get(v).description().c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::Function& x) {
                        // Intentionally left unimplemented.
                    },
                    [&](const hilti::rt::type_info::Interval& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, hilti::rt::to_string(x.get(v)).c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::Library& x) {
                        // Intentionally left unimplemented.
                    },
                    [&](const hilti::rt::type_info::Map& x) {
                        // TODO(bbannier): Figure out a good way to represent maps.
                    },
                    [&](const hilti::rt::type_info::MapIterator& x) {
                        // TODO(bbannier): Figure out a good way to represent maps.
                    },
                    [&](const hilti::rt::type_info::Network& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, hilti::rt::to_string(x.get(v)).c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::Optional& x) {
                        *this = make_info<SPICY_WIRESHARK_DATA>(*x.valueType(), name);
                    },
                    [&](const hilti::rt::type_info::Port& x) {
                        hf = HeaderField{-1, name, name, name, FT_UINT16, BASE_DEC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_uint(tree, wi.hf->hf, tvb, start, length, x.get(v).port());
                        };
                    },
                    [&](const hilti::rt::type_info::Real& x) {
                        hf = HeaderField{-1, name, name, name, FT_DOUBLE, BASE_DEC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start,
                                      int64_t length) { proto_tree_add_double(tree, wi.hf->hf, tvb, start, length, x.get(v)); };
                    },
                    [&](const hilti::rt::type_info::RegExp& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, hilti::rt::fmt("%s", x.get(v)).c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::Result& x) {},
                    [&](const hilti::rt::type_info::Set& x) {
                        *this = make_info<SPICY_WIRESHARK_DATA>(*x.dereferencedType(), name);

                        auto& draw = draw_fn;
                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, uint64_t length) {
                            for ( auto&& element : x.iterate(v) )
                                // TODO(bbannier): Pass offsets to parsed elements once we have access to them.
                                draw(wi, element, tree, tvb, start, length);
                        };
                    },
                    [&](const hilti::rt::type_info::SetIterator& x) {
                        *this = make_info<SPICY_WIRESHARK_DATA>(*x.valueType(), name);

                        auto& draw = draw_fn;
                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            try {
                                draw(wi, x.value(v), tree, tvb, start, length);
                            } catch ( const hilti::rt::RuntimeError& e ) {
                                REPORT_DISSECTOR_BUG("iterator of field %s is invalid: %s", wi.hf->abbrev.c_str(), e.what());
                            }
                        };
                    },
                    [&](const hilti::rt::type_info::SignedInteger<int8_t>& x) {
                        hf = HeaderField{-1, name, name, name, FT_INT8, BASE_DEC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start,
                                      int64_t length) { proto_tree_add_int(tree, wi.hf->hf, tvb, start, length, x.get(v)); };
                    },
                    [&](const hilti::rt::type_info::SignedInteger<int16_t>& x) {
                        hf = HeaderField{-1, name, name, name, FT_INT16, BASE_DEC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start,
                                      int64_t length) { proto_tree_add_int(tree, wi.hf->hf, tvb, start, length, x.get(v)); };
                    },
                    [&](const hilti::rt::type_info::SignedInteger<int32_t>& x) {
                        hf = HeaderField{-1, name, name, name, FT_INT32, BASE_DEC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start,
                                      int64_t length) { proto_tree_add_int(tree, wi.hf->hf, tvb, start, length, x.get(v)); };
                    },
                    [&](const hilti::rt::type_info::SignedInteger<int64_t>& x) {
                        hf = HeaderField{-1, name, name, name, FT_INT64, BASE_DEC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start,
                                      int64_t length) { proto_tree_add_int(tree, wi.hf->hf, tvb, start, length, x.get(v)); };
                    },
                    [&](const hilti::rt::type_info::Stream& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, uint64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, hilti::rt::fmt("%s", x.get(v)).c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::StreamIterator& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, uint64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, hilti::rt::fmt("%s", x.get(v)).c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::StreamView& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, hilti::rt::fmt("%s", x.get(v)).c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::String& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length, hilti::rt::fmt("%s", x.get(v)).c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::StrongReference& x) {
                        *this = make_info<SPICY_WIRESHARK_DATA>(*x.valueType(), name);

                        auto& draw = draw_fn;

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start,
                                      uint64_t length) { draw(wi, x.value(v), tree, tvb, start, length); };
                    },
                    [&](const hilti::rt::type_info::Struct& x) {
                        et = Subtree{-1, std::move(name), {}};

                        for ( auto&& [k, v_] : x.iterate(v) )
                            et->children.emplace_back(v_, k.name);

                        draw_fn = [](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                     tvbuff_t* tvb, uint64_t start, int64_t length) {
                            tree = proto_tree_add_subtree_format(tree, tvb, start, length, wi.et->et, NULL, "%s",
                                                                 wi.et->name.c_str());

                            auto* offsets =
                                spicy::rt::get_offsets_for_unit(std::get<hilti::rt::type_info::Struct>(v.type().aux_type_info),
                                                                v);

                            size_t child_index = 0;
                            auto x = std::get<hilti::rt::type_info::Struct>(v.type().aux_type_info);
                            for ( auto&& [k, v__] : x.iterate(v) ) {
                                if ( v__ ) {
                                    assert(wi.et);
                                    assert(child_index < wi.et->children.size());

                                    // If any offsets are missing claim from start to end (`start` reused here).
                                    int64_t length = -1;
                                    if ( const auto& field_offsets = offsets && child_index < offsets->size() ?
                                                                         offsets->at(child_index) :
                                                                         std::nullopt ) {
                                        start = std::get<0>(*field_offsets);

                                        if ( auto& end = std::get<1>(*field_offsets) )
                                            length = *end - start;
                                    }

                                    const auto& wi_ = wi.et->children[child_index];
                                    wi_.draw_fn(wi_, v__, tree, tvb, start, length);
                                }

                                ++child_index;
                            }
                        };
                    },
                    [&](const hilti::rt::type_info::Time& x) {
                        hf = HeaderField{-1, name, name, name, FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v_, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            auto& t = x.get(v);
                            time_t s = t.nanoseconds() / 1e9;
                            int ns = t.nanoseconds() - s * 1e9;
                            nstime_t nst = {s, ns};
                            proto_tree_add_time(tree, wi.hf->hf, tvb, start, length, &nst);
                        };
                    },
                    [&](const hilti::rt::type_info::Tuple& x) {
                        et = Subtree{-1, std::move(name), {}};

                        size_t n = 1;
                        for ( auto&& e : x.elements() ) {
                            hilti::rt::type_info::Value v_(nullptr, e.type, v);
                            auto name = ! e.name.empty() ? e.name : hilti::rt::fmt("tuple_element-%s", n++);
                            et->children.emplace_back(v_, name);
                        }

                        draw_fn = [](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v_, proto_tree* tree,
                                     tvbuff_t* tvb, uint64_t start, int64_t length) {
                            tree = proto_tree_add_subtree_format(tree, tvb, start, length, wi.et->et, NULL, "%s",
                                                                 wi.et->name.c_str());

                            size_t child_index = 0;
                            auto x = std::get<hilti::rt::type_info::Tuple>(v_.type().aux_type_info);
                            for ( auto&& [k, v__] : x.iterate(v_) ) {
                                if ( v__ ) {
                                    assert(wi.et);
                                    assert(child_index < wi.et->children.size());
                                    const auto& wi_ = wi.et->children[child_index];
                                    // TODO(bbannier): Pass offsets to parsed elements once we have access to them.
                                    wi_.draw_fn(wi_, v__, tree, tvb, start, length);
                                }

                                ++child_index;
                            }
                        };
                    },
                    [&](const hilti::rt::type_info::Union& x) {
                        hf = HeaderField{-1, name, name, name, FT_STRING, BASE_NONE};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v_, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            proto_tree_add_string(tree, wi.hf->hf, tvb, start, length,
                                                  hilti::rt::fmt("%s", x.value(v)).c_str());
                        };
                    },
                    [&](const hilti::rt::type_info::UnsignedInteger<uint8_t>& x) {
                        hf = HeaderField{-1, name, name, name, FT_UINT8, BASE_DEC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start,
                                      int64_t length) { proto_tree_add_uint(tree, wi.hf->hf, tvb, start, length, x.get(v)); };
                    },
                    [&](const hilti::rt::type_info::UnsignedInteger<uint16_t>& x) {
                        hf = HeaderField{-1, name, name, name, FT_UINT16, BASE_DEC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start,
                                      int64_t length) { proto_tree_add_uint(tree, wi.hf->hf, tvb, start, length, x.get(v)); };
                    },
                    [&](const hilti::rt::type_info::UnsignedInteger<uint32_t>& x) {
                        hf = HeaderField{-1, name, name, name, FT_UINT32, BASE_DEC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start,
                                      int64_t length) { proto_tree_add_uint(tree, wi.hf->hf, tvb, start, length, x.get(v)); };
                    },
                    [&](const hilti::rt::type_info::UnsignedInteger<uint64_t>& x) {
                        hf = HeaderField{-1, name, name, name, FT_UINT64, BASE_DEC};

                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start,
                                      int64_t length) { proto_tree_add_uint64(tree, wi.hf->hf, tvb, start, length, x.get(v)); };
                    },
                    [&](const hilti::rt::type_info::ValueReference& x) {
                        auto wi = make_info<SPICY_WIRESHARK_DATA>(*x.valueType(), name);
                        auto draw_fn = wi.draw_fn;
                        wi.draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                         tvbuff_t* tvb, uint64_t start,
                                         int64_t length) { draw_fn(wi, x.value(v), tree, tvb, start, length); };
                        *this = std::move(wi);
                    },
                    [&](const hilti::rt::type_info::Vector& x) {
                        *this = make_info<SPICY_WIRESHARK_DATA>(*x.dereferencedType(), name);

                        auto& draw = draw_fn;
                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            for ( auto&& element : x.iterate(v) )
                                // TODO(bbannier): Pass offsets to parsed elements once we have access to them.
                                draw(wi, element, tree, tvb, start, length);
                        };
                    },
                    [&](const hilti::rt::type_info::VectorIterator& x) {
                        *this = make_info<SPICY_WIRESHARK_DATA>(*x.valueType(), name);

                        auto& draw = draw_fn;
                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start, int64_t length) {
                            try {
                                draw(wi, x.value(v), tree, tvb, start, length);
                            } catch ( const hilti::rt::RuntimeError& e ) {
                                REPORT_DISSECTOR_BUG("iterator of field %s is invalid: %s", wi.hf->abbrev.c_str(), e.what());
                            }
                        };
                    },
                    [&](const hilti::rt::type_info::Void& x) {
                        // Intentionally left unimplemented.
                    },
                    [&](const hilti::rt::type_info::WeakReference& x) {
                        *this = make_info<SPICY_WIRESHARK_DATA>(*x.valueType(), name);

                        auto& draw = draw_fn;
                        draw_fn = [=](const WiresharkInfo& wi, const hilti::rt::type_info::Value& v, proto_tree* tree,
                                      tvbuff_t* tvb, uint64_t start,
                                      int64_t length) { draw(wi, x.value(v), tree, tvb, start, length); };
                    }},
                v.type().aux_type_info);
        }

        static WiresharkInfo wi;

        static int dissect(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
            auto stream = hilti::rt::ValueReference<hilti::rt::Stream>();
            auto cur = stream->view();

            std::string buffer(tvb_reported_length(tvb) + 1, '\\0');
            tvb_get_raw_bytes_as_string(tvb, 0, buffer.data(), buffer.size());
            stream->append(buffer.c_str(), buffer.size() - 1);
            stream->freeze();

            auto gunit = spicy::rt::ParsedUnit();
            auto res = std::optional<hilti::rt::Resumable>();

            size_t consumed_total = 0;

            try {
                if ( ! res )
                    res = SPICY_WIRESHARK_PARSER::parse3(gunit, stream, cur);
                else
                    res->resume();
            } catch ( const spicy::rt::ParseError& e ) {
                return tvb_reported_length(tvb);
            }

            if ( ! *res ) {
                // More data needed.
                // TODO(bbannier): make `stream` stateful so we can make use of Wireshark frame reassembly.
                pinfo->desegment_offset = tvb_captured_length(tvb);
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return tvb_captured_length(tvb);
            }

            const auto ncur = res->get<hilti::rt::stream::View>();
            size_t consumed = ncur.begin() - cur.begin();

            if ( ! consumed )
                return consumed_total;

            col_set_str(pinfo->cinfo, COL_PROTOCOL, SPICY_WIRESHARK_SHORT_NAME);

            col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                         hilti::rt::to_string_for_print(gunit.get<SPICY_WIRESHARK_DATA>()).c_str());

            wi.draw(gunit.value(), tree, tvb, 0, consumed);
            gunit = spicy::rt::ParsedUnit();
            res = {};

            consumed_total += consumed;
            stream->trim(ncur.begin());
            cur = ncur;

            return consumed_total;
        }

        void proto_reg_handoff_spicy() {
            static bool initialized = false;
            static dissector_handle_t handle;

            static std::string current_port;

            if ( ! initialized ) {
                handle = create_dissector_handle(dissect, proto);
                initialized = true;
            }
            else {
                auto port_tcp_pref = prefs_get_range_value(SPICY_WIRESHARK_NAME, "tcp.port");
                dissector_delete_uint_range("tcp.port", port_tcp_pref, handle);

                auto port_udp_pref = prefs_get_range_value(SPICY_WIRESHARK_NAME, "udp.port");
                dissector_delete_uint_range("udp.port", port_udp_pref, handle);
            }

            dissector_add_uint_range_with_preference("tcp.port", "0-65535", handle);
            dissector_add_uint_range_with_preference("udp.port", "0-65535", handle);
        }

        void proto_register_spicy() {
            hilti::rt::init();
            spicy::rt::init();

            // Register the protocol name and description.
            proto = proto_register_protocol(SPICY_WIRESHARK_NAME, SPICY_WIRESHARK_SHORT_NAME, SPICY_WIRESHARK_FILTER_NAME);

            wi = make_info<SPICY_WIRESHARK_DATA>(SPICY_TYPEINFO, SPICY_WIRESHARK_NAME);

            WiresharkInfo::register_handles(wi, proto);
        }
        """)

    plugin_meta = textwrap.dedent("""
        extern "C" {{
        extern WS_DLL_PUBLIC_DEF const gchar plugin_version[] = "{}";
        extern WS_DLL_PUBLIC_DEF const int plugin_want_major = {};
        extern WS_DLL_PUBLIC_DEF const int plugin_want_minor = {};

        WS_DLL_PUBLIC_DEF void plugin_register();

        void plugin_register() {{
            static proto_plugin plug_spicy;
            plug_spicy.register_protoinfo = proto_register_spicy;
            plug_spicy.register_handoff = proto_reg_handoff_spicy;

            proto_register_plugin(&plug_spicy);
        }}
        }}
    """.format(opts.plugin_version,
               opts.plugin_want_major,
               opts.plugin_want_minor))

    output = '{}\n\n{}{}{}'.format(spicy_cc, epilog, wrapper, plugin_meta)

    # Sanitize output, see https://github.com/zeek/spicy/issues/500.
    output = '\n'.join(
        filter(
            lambda line: not re.match(r'\s*using.*= enum class.*$', line),
            output.split('\n')))

    return output


def compile_plugin(source: str, opts: argparse.Namespace) -> None:
    """Compile C++ source code for a Wireshark Spicy plugin."""
    cxx = subprocess.run(['spicy-config', '--cxx'], check=True,
                         capture_output=True).stdout.decode('utf-8').strip()
    flags = subprocess.run(['spicy-config',
                            '--cxxflags',
                            '--ldflags',
                            '--debug'],
                           check=True, capture_output=True) \
        .stdout.decode('utf-8').split()

    wireshark_flags = [
        '-I', opts.wireshark_include_dir,
        '-L', opts.wireshark_library_dir, '-lwireshark',
    ]

    glib_flags = subprocess.run(
        ['pkg-config', 'glib-2.0', '--cflags', '--libs'],
        check=True, capture_output=True).stdout.decode('utf-8').split()

    with tempfile.NamedTemporaryFile('w', suffix='.cc') as f:
        f.write(source)
        subprocess.run([cxx, *flags, f.name, *wireshark_flags, *glib_flags,
                        '--shared', '-o', opts.output], check=True)


if __name__ == "__main__":
    opts = parse_args(sys.argv[1:])

    if len(opts.sources) > 1:
        raise NotImplementedError(
            "Support for multiple source files is not implemented")

    for source in opts.sources:
        plugin = gen_plugin(source, opts)

        if opts.generate_cc:
            if opts.generate_cc:
                with open(opts.output, 'w') as f:
                    f.write(plugin)
        else:
            compile_plugin(plugin, opts)
