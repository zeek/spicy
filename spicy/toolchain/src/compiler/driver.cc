// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <spicy/ast/builder/builder.h>
#include <spicy/compiler/driver.h>

using namespace spicy;

spicy::Options Driver::spicyCompilerOptions() const {
    spicy::Options options;

    const auto& hilti_options = hiltiOptions();
    options.track_offsets = hilti_options.getAuxOption<bool>("spicy.track_offsets", false);
    return options;
}

void Driver::setSpicyCompilerOptions(const spicy::Options& options) {
    auto hilti_options = hiltiOptions();
    hilti_options.setAuxOption("spicy.track_offsets", options.track_offsets);
    setCompilerOptions(std::move(hilti_options));
}

std::unique_ptr<hilti::Builder> Driver::createBuilder(hilti::ASTContext* ctx) const {
    return std::make_unique<Builder>(ctx);
}

std::string Driver::hookAddCommandLineOptions() { return "Q"; }

bool Driver::hookProcessCommandLineOption(int opt, const char* optarg) {
    auto hilti_options = hiltiOptions();

    switch ( opt ) {
        case 'Q': hilti_options.setAuxOption("spicy.track_offsets", true); break;
        default: return false;
    }

    setCompilerOptions(std::move(hilti_options));
    return true;
}

std::string Driver::hookAugmentUsage() {
    return "  -Q | --include-offsets            Include stream offsets of parsed data in output.\n";
}
