// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <spicy/compiler/detail/pir/passes/specialize-regexp.h>

using namespace spicy::detail::pir;
using namespace spicy::detail::pir::ir;

namespace {

// Reads one byte of a pattern: a plain printable ASCII character, or an escape that the matcher expands to one byte.
// `special` are the plain characters that mean something here.
std::optional<uint8_t> readByte(std::string_view& text, std::string_view special) {
    if ( text.empty() )
        return {};

    auto c = static_cast<unsigned char>(text.front());
    if ( c != '\\' ) {
        if ( c < 0x20 || c > 0x7e || special.find(static_cast<char>(c)) != std::string_view::npos )
            return {};

        text.remove_prefix(1);
        return c;
    }

    if ( text.size() < 2 )
        return {};

    auto escaped = text[1];
    text.remove_prefix(2);
    switch ( escaped ) {
        case 'r': return '\r';
        case 'n': return '\n';
        case 't': return '\t';
        case 'x': {
            if ( text.size() < 2 || ! std::isxdigit(static_cast<unsigned char>(text[0])) ||
                 ! std::isxdigit(static_cast<unsigned char>(text[1])) )
                return {};

            auto value = static_cast<uint8_t>(std::stoi(std::string(text.substr(0, 2)), nullptr, 16));
            text.remove_prefix(2);
            return value;
        }
        default:
            // A backslash before punctuation is that character. Letters and digits have meanings of their own.
            if ( std::isalnum(static_cast<unsigned char>(escaped)) || static_cast<unsigned char>(escaped) > 0x7e ||
                 static_cast<unsigned char>(escaped) < 0x20 )
                return {};

            return static_cast<uint8_t>(escaped);
    }
}

void add(ScanBytesPayload& scan, unsigned byte) { scan.set[byte / 64] |= uint64_t{1} << (byte % 64); }

// `[...]` or `[^...]` of single bytes and ranges, to the end of `text`'s class.
bool readClass(std::string_view& text, ScanBytesPayload& scan) {
    text.remove_prefix(1);
    bool negate = ! text.empty() && text.front() == '^';
    if ( negate )
        text.remove_prefix(1);

    bool any = false;
    while ( ! text.empty() && text.front() != ']' ) {
        auto first = readByte(text, "[-");
        if ( ! first )
            return false;

        auto last = *first;
        if ( ! text.empty() && text.front() == '-' ) {
            text.remove_prefix(1);
            auto end = readByte(text, "[-]");
            if ( ! end || *end < *first )
                return false;
            last = *end;
        }

        for ( unsigned byte = *first; byte <= last; ++byte )
            add(scan, byte);
        any = true;
    }

    if ( text.empty() || ! any )
        return false;

    text.remove_prefix(1);
    if ( negate )
        for ( auto& word : scan.set )
            word = ~word;
    return true;
}

} // namespace

std::optional<ScanBytesPayload> passes::recognizeByteScan(const RegExpDecl& regexp) {
    if ( regexp.patterns.size() != 1 || regexp.patterns[0].case_insensitive )
        return {};

    std::string_view text = regexp.patterns[0].value;
    ScanBytesPayload scan;
    if ( text.empty() )
        return {};

    if ( text.front() == '[' ) {
        if ( ! readClass(text, scan) )
            return {};
    }
    else {
        auto byte = readByte(text, "|*+?.()[]{}^$");
        if ( ! byte )
            return {};
        add(scan, *byte);
    }

    if ( text.size() != 1 || (text[0] != '*' && text[0] != '+') )
        return {};

    scan.at_least_one = text[0] == '+';
    return scan;
}

bool passes::specializeRegExps(Package& package, FunctionId function) {
    bool changed = false;
    // Replacing an instruction keeps its ID, so the matches can be collected first.
    std::vector<InstId> matches;
    std::vector<RegionId> pending{package.function(function).root_region};
    while ( ! pending.empty() ) {
        auto region = pending.back();
        pending.pop_back();
        for ( auto block : package.region(region).blocks )
            for ( auto id : package.block(block).insts ) {
                if ( package.inst(id).opcode == Opcode::MatchRegExp )
                    matches.push_back(id);
                pending.insert(pending.end(), package.inst(id).regions.begin(), package.inst(id).regions.end());
            }
    }

    for ( auto id : matches ) {
        const auto& inst = package.inst(id);
        const auto* payload = std::get_if<RegExpPayload>(&inst.payload);
        if ( ! payload || ! package.isValid(payload->regexp) )
            continue;

        if ( auto scan = recognizeByteScan(package.regexp(payload->regexp)) ) {
            package.replaceInst(id, Opcode::ScanBytes, inst.args, InstPayload(*scan));
            changed = true;
        }
    }

    return changed;
}
