// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <ostream>
#include <tuple>
#include <type_traits>

#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes;

namespace std {
template<typename X, typename Y>
ostream& operator<<(ostream& stream, const tuple<X, Y>& xs) {
    return stream << '(' << hilti::rt::to_string(get<0>(xs)) << ", " << hilti::rt::to_string(get<1>(xs)) << ')';
}
} // namespace std

TEST_SUITE_BEGIN("Bytes");

TEST_CASE("at") {
    const auto b = "123"_b;
    CHECK_EQ(b.at(0), b.begin());
    CHECK_EQ(*b.at(0), '1');
    CHECK_EQ(*b.at(1), '2');
    CHECK_EQ(*b.at(2), '3');
    CHECK_EQ(b.at(3), b.end());
    CHECK_THROWS_WITH_AS(*b.at(5), "index 5 out of bounds", const IndexError&);
}

TEST_CASE("extract") {
    SUBCASE("sufficient data") {
        unsigned char dst1[3] = {0};
        CHECK_EQ("123456"_b.extract(dst1), "456"_b);
        CHECK_EQ(dst1[0], '1');
        CHECK_EQ(dst1[1], '2');
        CHECK_EQ(dst1[2], '3');

        unsigned char dst2[3] = {0};
        CHECK_EQ("123"_b.extract(dst2), ""_b);
        CHECK_EQ(dst2[0], '1');
        CHECK_EQ(dst2[1], '2');
        CHECK_EQ(dst2[2], '3');
    }

    SUBCASE("insufficient data") {
        unsigned char dst1[3] = {0};
        CHECK_THROWS_WITH_AS(""_b.extract(dst1), "insufficient data in source", const InvalidArgument&);

        unsigned char dst2[1] = {0};
        CHECK_THROWS_WITH_AS(""_b.extract(dst2), "insufficient data in source", const InvalidArgument&);
    }
}

TEST_CASE("find") {
    const auto b = "123"_b;
    const auto empty = ""_b;

    SUBCASE("single byte") {
        SUBCASE("default start") {
            CHECK_EQ(b.find('2'), b.at(1));
            CHECK_EQ(b.find('a'), b.end());
            CHECK_EQ(empty.find('a'), empty.end());
        }

        SUBCASE("start at target") {
            CHECK_EQ(b.find('2', b.at(1)), b.at(1));
            CHECK_EQ(b.find('a', b.at(1)), b.end());
        }

        SUBCASE("start beyond target") {
            CHECK_EQ(b.find('2', b.at(2)), b.end());
            CHECK_EQ(b.find('a', b.at(2)), b.end());
            CHECK_EQ(b.find('a', b.end()), b.end());
        }
    }

    SUBCASE("range of bytes") {
        SUBCASE("default start") {
            CHECK_EQ(b.find("23"_b), std::make_tuple(true, b.at(1)));
            CHECK_EQ(b.find("234"_b), std::make_tuple(false, b.at(1)));
            CHECK_EQ(b.find("22"_b), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find("a"_b), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find(""_b), std::make_tuple(true, b.begin()));
            CHECK_EQ(empty.find("a"_b), std::make_tuple(false, empty.end()));
            CHECK_EQ(empty.find(""_b), std::make_tuple(true, empty.begin()));
        }

        SUBCASE("start at target") {
            CHECK_EQ(b.find("23", b.at(1)), std::make_tuple(true, b.at(1)));
            CHECK_EQ(b.find("ab", b.at(1)), std::make_tuple(false, b.end()));
        }

        SUBCASE("start beyond target") {
            CHECK_EQ(b.find("23", b.at(2)), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find("ab", b.at(2)), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find("ab", b.end()), std::make_tuple(false, b.end()));
        }
    }
}

TEST_CASE("match") {
    const auto b = "123"_b;
    CHECK_EQ(b.match(RegExp("2"), 0), Result("2"_b));
    CHECK_EQ(b.match(RegExp("a"), 0), Result<Bytes>(result::Error("no matches found")));
    CHECK_EQ(b.match(RegExp("2"), 1), Result<Bytes>(result::Error("no matches found")));
}

TEST_CASE("iteration") {
    // Validate that when iterating we yield the `Iterator`'s `reference` type.
    // This is a regression test for #219.
    for ( auto x : Bytes() ) {
        (void)x;
        static_assert(std::is_same_v<decltype(x), uint8_t>);
    }
}

TEST_CASE("split") {
    SUBCASE("separator") {
        CHECK_EQ("12 45"_b.split(" "), Vector({"12"_b, "45"_b}));
        CHECK_EQ("12 45 678"_b.split(" "), Vector({"12"_b, "45"_b, "678"_b}));
        CHECK_EQ("12345"_b.split("34"), Vector({"12"_b, "5"_b}));
        CHECK_EQ(" 2345"_b.split(" "), Vector({""_b, "2345"_b}));
        CHECK_EQ("12345"_b.split(""), Vector({"12345"_b}));
        CHECK_EQ(" "_b.split(" "), Vector({""_b}));
        CHECK_EQ(""_b.split(" "), Vector({""_b}));
        CHECK_EQ(""_b.split(""), Vector({""_b}));
    }

    SUBCASE("whitespace") {
        CHECK_EQ("12 45"_b.split(), Vector({"12"_b, "45"_b}));
        CHECK_EQ("12 45 678"_b.split(), Vector({"12"_b, "45"_b, "678"_b}));

        // TODO(bbannier): This should be symmetric with `split(" ")`.
        CHECK_EQ(" 2345"_b.split(), Vector({"2345"_b}));

        // TODO(bbannier): This should be symmetric with `split(" ")`.
        CHECK_EQ(" "_b.split(), Vector<Bytes>());

        // TODO(bbannier): This should be symmetric with `split(" ")`.
        CHECK_EQ(""_b.split(), Vector<Bytes>());

        CHECK_EQ("1"_b.split(), Vector({"1"_b}));
    }
}

TEST_CASE("split1") {
    SUBCASE("separator") {
        CHECK_EQ("12 45"_b.split1(" "), std::make_tuple("12"_b, "45"_b));
        CHECK_EQ("12 45 678"_b.split1(" "), std::make_tuple("12"_b, "45 678"_b));
        CHECK_EQ("12345"_b.split1("34"), std::make_tuple("12"_b, "5"_b));
        CHECK_EQ(" 2345"_b.split1(" "), std::make_tuple(""_b, "2345"_b));
        CHECK_EQ("12345"_b.split1(""), std::make_tuple(""_b, "12345"_b));
        CHECK_EQ("1"_b.split1(" "), std::make_tuple("1"_b, ""_b));
        CHECK_EQ(""_b.split1("1"), std::make_tuple(""_b, ""_b));
        CHECK_EQ(""_b.split1(""), std::make_tuple(""_b, ""_b));
    }

    SUBCASE("whitespace") {
        CHECK_EQ("12 45"_b.split1(), std::make_tuple("12"_b, "45"_b));
        CHECK_EQ("12 45 678"_b.split1(), std::make_tuple("12"_b, "45 678"_b));

        // TODO(bbannier): This should be symmetric with `split(" ")`.
        CHECK_EQ(" 2345"_b.split1(), std::make_tuple(""_b, "2345"_b));

        CHECK_EQ(" "_b.split1(), std::make_tuple(""_b, ""_b));
        CHECK_EQ(""_b.split1(), std::make_tuple(""_b, ""_b));
        CHECK_EQ("1"_b.split1(), std::make_tuple("1"_b, ""_b));
    }
}

TEST_CASE("startsWith") {
    CHECK("123"_b.startsWith(""_b));
    CHECK("123"_b.startsWith("1"_b));
    CHECK("123"_b.startsWith("12"_b));
    CHECK("123"_b.startsWith("123"_b));

    CHECK_FALSE("123"_b.startsWith("1234"_b));
    CHECK_FALSE("123"_b.startsWith("a"_b));
    CHECK_FALSE(""_b.startsWith("a"_b));
}

TEST_CASE("sub") {
    const auto b = "123456"_b;

    SUBCASE("end offset") {
        CHECK_EQ(b.sub(0), ""_b);
        CHECK_EQ(b.sub(b.size()), b);
        CHECK_EQ(b.sub(99), b);
        CHECK_EQ(b.sub(3), "123"_b);
    }

    SUBCASE("start/end offsets") {
        CHECK_EQ(b.sub(0, 0), ""_b);
        CHECK_EQ(b.sub(b.size(), b.size()), ""_b);
        CHECK_EQ(b.sub(0, b.size()), b);
        CHECK_EQ(b.sub(0, 3), "123"_b);
        CHECK_EQ(b.sub(3, 0), "456"_b);
    }

    SUBCASE("end iterator") {
        CHECK_EQ(b.sub(b.begin()), ""_b);
        CHECK_EQ(b.sub(b.end()), b);
    }

    SUBCASE("start/end iterator") {
        CHECK_EQ(b.sub(b.begin(), b.end()), b);
        CHECK_EQ(b.sub(b.begin(), b.begin()), ""_b);

        const auto bb = "123"_b;
        CHECK_THROWS_WITH_AS(b.sub(b.begin(), bb.begin()),
                             "cannot perform arithmetic with iterators into different bytes", const InvalidArgument&);
    }
}

TEST_CASE("append") {
    auto b = "123"_b;
    auto it = b.begin();

    REQUIRE_EQ(to_string(b), "b\"123\"");
    REQUIRE_EQ(*it, '1');

    SUBCASE("Bytes") {
        b.append("456"_b);

        CHECK_EQ(to_string(b), "b\"123456\"");
        CHECK_EQ(*it, '1');
    }

    SUBCASE("View") {
        auto stream = Stream("456");
        b.append(stream.view());

        CHECK_EQ(to_string(b), "b\"123456\"");
        CHECK_EQ(*it, '1');
    }
}

TEST_CASE("assign") {
    auto b = "123"_b;
    auto it = b.begin();

    REQUIRE_EQ(to_string(b), "b\"123\"");
    REQUIRE_EQ(*it, '1');

    SUBCASE("rvalue") {
        b = "abc"_b;
        CHECK_EQ(to_string(b), "b\"abc\"");
        CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
    }

    SUBCASE("lvalue") {
        const auto bb = "abc"_b;
        b = bb;
        CHECK_EQ(to_string(b), "b\"abc\"");
        CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
    }
}

TEST_CASE("Iterator") {
    const auto b = "123"_b;
    const auto bb = "123"_b;

    SUBCASE("coupled lifetime") {
        CHECK_NOTHROW(*b.begin()); // Iterator valid since container is alife.

        auto it = ""_b.begin();
        CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
    }

    SUBCASE("increment") {
        auto it = b.begin();
        CHECK_EQ(*(it++), '1');
        CHECK_EQ(*it, '2');
        CHECK_EQ(*(++it), '3');
        it += 1;
        CHECK_EQ(it, b.end());

        CHECK_EQ(*(b.begin() + 2), '3');
        CHECK_EQ(*(b.begin() + integer::safe<uint8_t>(2)), '3');

        it = b.begin();
        it += integer::safe<uint64_t>(2);
        CHECK_EQ(*it, '3');
    }

    SUBCASE("bounds check") {
        CHECK_EQ(*b.begin(), '1');
        CHECK_THROWS_WITH_AS(*b.end(), "index 3 out of bounds", const IndexError&);
    }

    SUBCASE("equality") {
        CHECK_EQ(b.begin(), b.begin());
        CHECK_NE(b.begin(), b.end());

        CHECK_THROWS_WITH_AS(operator==(b.begin(), bb.begin()), "cannot compare iterators into different bytes",
                             const InvalidArgument&);
    }

    SUBCASE("distance") {
        CHECK_EQ(b.end() - b.begin(), b.size());
        CHECK_EQ(b.begin() - b.end(), -b.size());
        CHECK_EQ(b.end() - b.end(), 0);
        CHECK_EQ(b.begin() - b.begin(), 0);

        CHECK_THROWS_WITH_AS(operator-(b.begin(), bb.begin()),
                             "cannot perform arithmetic with iterators into different bytes", const InvalidArgument&);
    }

    SUBCASE("ordering") {
        SUBCASE("less") {
            REQUIRE_FALSE(b.isEmpty());

            CHECK_LT(b.begin(), b.end());
            CHECK_FALSE(operator<(b.end(), b.begin()));
            CHECK_THROWS_WITH_AS(operator<(b.begin(), bb.begin()), "cannot compare iterators into different bytes",
                                 const InvalidArgument&);
        }

        SUBCASE("less equal") {
            REQUIRE_FALSE(b.isEmpty());

            CHECK_LE(b.begin(), b.end());
            CHECK_LE(b.begin(), b.begin());
            CHECK_FALSE(operator<=(b.end(), b.begin()));
            CHECK_THROWS_WITH_AS(operator<=(b.begin(), bb.begin()), "cannot compare iterators into different bytes",
                                 const InvalidArgument&);
        }

        SUBCASE("greater") {
            REQUIRE_FALSE(b.isEmpty());

            CHECK_GT(b.end(), b.begin());
            CHECK_FALSE(operator>(b.begin(), b.end()));
            CHECK_THROWS_WITH_AS(operator>(b.begin(), bb.begin()), "cannot compare iterators into different bytes",
                                 const InvalidArgument&);
        }

        SUBCASE("greater equal") {
            REQUIRE_FALSE(b.isEmpty());

            CHECK_GE(b.end(), b.begin());
            CHECK_GE(b.begin(), b.begin());
            CHECK_FALSE(operator>=(b.begin(), b.end()));
            CHECK_THROWS_WITH_AS(operator>=(b.begin(), bb.begin()), "cannot compare iterators into different bytes",
                                 const InvalidArgument&);
        }
    }
}

TEST_SUITE_END();
