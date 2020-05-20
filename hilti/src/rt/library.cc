// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <dlfcn.h>

#include <hilti/rt/exception.h>
#include <hilti/rt/library.h>
#include <hilti/rt/logging.h>

using namespace hilti::rt;

hilti::rt::Library::Library(const std::filesystem::path& path) {
    if ( ! std::filesystem::exists(path) )
        throw EnvironmentError(fmt("no such library: %s", path));

    auto path_ = createTemporaryFile(path.filename());
    if ( ! path_ )
        throw EnvironmentError(fmt("could not add library %s: %s", path, path_.error()));

    std::error_code ec;
    std::filesystem::copy(path, *path_, std::filesystem::copy_options::overwrite_existing, ec);
    if ( ec )
        throw EnvironmentError(fmt("could not store library %s at %s: %s", path, *path_, ec.message()));

    _path = std::filesystem::absolute(std::move(*path_));
}

hilti::rt::Library::~Library() {
    std::error_code ec;
    std::filesystem::remove(_path, ec);

    if ( ec )
        hilti::rt::warning(fmt("could not remove library %s from store: %s", ec.message()));
}

hilti::rt::Result<hilti::rt::Nothing> hilti::rt::Library::open() const {
    constexpr auto mode = RTLD_LAZY | RTLD_GLOBAL;

    if ( ! ::dlopen(_path.c_str(), mode) )
        return result::Error(fmt("failed to load library %s: %s", _path, dlerror()));

    return hilti::rt::Nothing();
}

hilti::rt::Result<hilti::rt::Nothing> hilti::rt::Library::save(const std::filesystem::path& path) const {
    std::error_code ec;
    std::filesystem::copy(_path, path, std::filesystem::copy_options::overwrite_existing, ec);

    if ( ec )
        return result::Error(ec.message());

    return hilti::rt::Nothing();
}
