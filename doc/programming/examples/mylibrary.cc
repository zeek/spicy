
#include <string>

namespace MyLibrary {

// Rotate each letter by 13 characters.
std::string rot13(const std::string& in) {
    std::string out;

    for ( auto c : in ) {
        char b = islower(c) ? 'a' : 'A';
        auto d = c - b + 13;

        if ( d >= 13 && d <= 38 )
            c = static_cast<char>(d % 26 + b);

        out.push_back(c);
    }

    return out;
}

} // namespace MyLibrary
