// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <dlfcn.h>
#include <sys/stat.h>

#include <cassert>
#include <functional>
#include <utility>

#include <hilti/rt/autogen/version.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/json.h>
#include <hilti/rt/library.h>
#include <hilti/rt/logging.h>

using namespace hilti::rt;

std::optional<hilti::rt::filesystem::path> Library::_current_path;

std::string hilti::rt::library::Version::toJSON() const {
    auto version = nlohmann::json{{"magic", magic}, {"hilti_version", hilti_version}, {"debug", debug}};
    std::stringstream json;
    json << version;
    return json.str();
}

hilti::rt::Result<hilti::rt::library::Version> hilti::rt::library::Version::fromJSON(const std::string& json) {
    Version version;

    try {
        auto j = nlohmann::json::parse(json);
        j.at("magic").get_to(version.magic);
        j.at("hilti_version").get_to(version.hilti_version);
        j.at("debug").get_to(version.debug);
    } catch ( const nlohmann::json::exception& e ) {
        return result::Error(e.what());
    }

    return std::move(version);
}

void hilti::rt::library::Version::checkCompatibility() const {
    if ( hilti_version != PROJECT_VERSION_NUMBER )
        warning(fmt("module %s was compiled with HILTI version %d, but using HILTI version %d", path.filename(),
                    hilti_version, PROJECT_VERSION_NUMBER));
}

hilti::rt::Library::Library(const hilti::rt::filesystem::path& path) : _path(hilti::rt::filesystem::canonical(path)) {}

hilti::rt::Library::~Library() {
    if ( _handle ) {
        int error = ::dlclose(_handle);
        if ( error )
            hilti::rt::warning(fmt("failed to unload library %s: %s", _path, dlerror()));
    }
}

hilti::rt::Result<hilti::rt::library::Version> hilti::rt::Library::open() const {
    // Set the current library path while this method is running.
    auto _ = hilti::rt::scope_exit([&]() { hilti::rt::Library::_current_path.reset(); });
    hilti::rt::Library::_current_path = hilti::rt::filesystem::absolute(_path);

    constexpr auto mode = RTLD_NOW | RTLD_GLOBAL;

    if ( ! _handle ) {
        void* handle = ::dlopen(_path.c_str(), mode);

        if ( ! handle )
            return result::Error(fmt("failed to load library %s: %s", _path, dlerror()));

        _handle = handle;
    }

    auto* version_string =
        reinterpret_cast<const char**>(::dlsym(_handle, HILTI_INTERNAL_GLOBAL_ID("hlto_library_version")));
    if ( ! version_string )
        // This could happen if the code was compiled with a custom CXX
        // namespace prefix. But that's not expected for HLTO files; it should
        // be used only when generating C++ code compiled through custom means.
        return result::Error("no version information accessible");

    auto version = library::Version::fromJSON(*version_string);
    if ( ! version )
        return result::Error(fmt("broken version information (%s)", version.error()));

    // Check version. We only warn for now, don't abort.
    if ( version->magic != "v1" )
        result::Error(fmt("unknown HLTO version '%s'", version->magic));

    version->path = hilti::rt::filesystem::relative(_path, hilti::rt::filesystem::current_path());
    version->checkCompatibility();

    return version;
}

hilti::rt::Result<void*> hilti::rt::Library::symbol(const char* name) const {
    if ( ! _handle )
        return result::Error(fmt("library %s has not been opened", _path));

    // Clear any library errors.
    ::dlerror();

    auto* symbol = ::dlsym(_handle, name);

    if ( ::dlerror() )
        return result::Error(fmt("symbol '%s' not found", name));

    return symbol;
}

hilti::rt::Result<Nothing> hilti::rt::Library::remove() const {
    std::error_code ec;
    hilti::rt::filesystem::remove(_path, ec);

    if ( ec )
        return result::Error(fmt("could not remove library %s from store: %s", _path, ec.message()));

    return Nothing();
}

hilti::rt::Result<hilti::rt::Nothing> hilti::rt::Library::save(const hilti::rt::filesystem::path& path) const {
    std::error_code ec;

    // On macOS ARM, there are weird crashes during execution if we don't remove an existing file first. Note that
    // `is_regular_file(`) fails if we cannot access the file due to permissions, but we let it fail during removal.
    if ( hilti::rt::filesystem::is_regular_file(path, ec) ) {
        hilti::rt::filesystem::remove(path, ec);
        if ( ec )
            return result::Error(fmt("could not remove existing library when saving to %s: %s", path, ec.message()));
    }

    hilti::rt::filesystem::copy(_path, path, hilti::rt::filesystem::copy_options::overwrite_existing, ec);

    if ( ec )
        return result::Error(fmt("could not save library to %s: %s", path, ec.message()));

    // Query the current umask. This is safe since we always query and set the umask from a single thread.
    auto default_perms = ::umask(::mode_t());
    ::umask(default_perms);

    // Create the file taking into account the active umask. Since clang creates
    // shared libraries with executable bit we assume default permissions of 777.
    hilti::rt::filesystem::permissions(path, hilti::rt::filesystem::perms(0777 - default_perms),
                                       hilti::rt::filesystem::perm_options::replace, ec);

    if ( ec )
        rt::fatalError(fmt("could not preserve permissions of file %s: %s", path, ec.message()));

    return hilti::rt::Nothing();
}

void hilti::rt::Library::setScope(uint64_t* scope) {
    static uint64_t scope_counter = 0;

    assert(scope);

    // Currently loading a library.
    if ( _current_path )
        *scope = std::hash<std::string>{}(_current_path->native());

    // The passed scope is unset.
    else if ( *scope == 0 )
        *scope = std::hash<uint64_t>{}(++scope_counter);
}
