// A test harness in one header, for the same reason the NMOS layer is
// hand-rolled: adding Catch2 or GoogleTest would mean adding a package manager
// to a project whose whole deployment story is that it has none. What a test
// runner has to do -- register cases, run them, report which failed and with
// what -- is about eighty lines, and eighty lines is cheaper than a dependency.
//
// Cases register themselves through a static initialiser, so a new test file
// needs only to be added to the build. A failing check throws, which abandons
// that case and moves to the next, so one broken thing does not hide the rest.
//
//   TEST(bitpack, round_trip) {
//       CHECK(x == y);
//       CHECK_EQ(pack(v), expected);
//   }
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace test {

struct Case {
    std::string suite;
    std::string name;
    std::function<void()> fn;
};

// Function-local static, so registration order across translation units cannot
// depend on static initialisation order.
inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

struct Failure : std::exception {
    std::string what_;
    explicit Failure(std::string w) : what_(std::move(w)) {}
    const char* what() const noexcept override { return what_.c_str(); }
};

struct Register {
    Register(const char* suite, const char* name, std::function<void()> fn) {
        registry().push_back({suite, name, std::move(fn)});
    }
};

// Values are printed when a comparison fails, because "CHECK_EQ failed" on its
// own sends you back to the debugger for something the runner already knew.
template <typename T>
std::string show(const T& v) {
    std::ostringstream os;
    os << v;
    return os.str();
}
inline std::string show(bool v) { return v ? "true" : "false"; }
inline std::string show(std::nullptr_t) { return "null"; }
inline std::string show(const std::string& v) { return "\"" + v + "\""; }
inline std::string show(const char* v) { return std::string("\"") + (v ? v : "") + "\""; }
// Chars would otherwise print as text; the numeric value is what a test means.
inline std::string show(std::uint8_t v) { return std::to_string(unsigned(v)); }
inline std::string show(std::int8_t v)  { return std::to_string(int(v)); }

[[noreturn]] inline void fail(const char* file, int line, const std::string& msg) {
    throw Failure(std::string(file) + ":" + std::to_string(line) + "  " + msg);
}

// `only` filters by a substring of "suite.name", so one case can be re-run on
// its own while chasing a failure.
inline int runAll(int argc, char** argv) {
    const char* only = argc > 1 ? argv[1] : nullptr;
    int run = 0, failed = 0;
    std::vector<std::string> failures;

    for (const Case& c : registry()) {
        const std::string full = c.suite + "." + c.name;
        if (only && full.find(only) == std::string::npos) continue;
        ++run;
        try {
            c.fn();
        } catch (const Failure& f) {
            ++failed;
            failures.push_back(full + "\n    " + f.what());
        } catch (const std::exception& e) {
            ++failed;
            failures.push_back(full + "\n    unexpected exception: " + e.what());
        } catch (...) {
            ++failed;
            failures.push_back(full + "\n    unexpected non-standard exception");
        }
    }

    for (const std::string& f : failures) std::printf("FAIL  %s\n", f.c_str());
    std::printf("\n%d case%s run, %d failed\n", run, run == 1 ? "" : "s", failed);
    if (only && run == 0) {
        std::printf("no case matched '%s'\n", only);
        return 2;
    }
    return failed ? 1 : 0;
}

}  // namespace test

#define TEST(suite, name)                                                     \
    static void test_##suite##_##name();                                      \
    static ::test::Register reg_##suite##_##name(#suite, #name,               \
                                                 test_##suite##_##name);      \
    static void test_##suite##_##name()

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) ::test::fail(__FILE__, __LINE__, "CHECK(" #cond ")");     \
    } while (0)

#define CHECK_EQ(a, b)                                                        \
    do {                                                                      \
        const auto& _a = (a);                                                 \
        const auto& _b = (b);                                                 \
        if (!(_a == _b))                                                      \
            ::test::fail(__FILE__, __LINE__,                                  \
                         "CHECK_EQ(" #a ", " #b ")\n      left  = " +         \
                             ::test::show(_a) + "\n      right = " +          \
                             ::test::show(_b));                               \
    } while (0)

#define CHECK_NE(a, b)                                                        \
    do {                                                                      \
        const auto& _a = (a);                                                 \
        const auto& _b = (b);                                                 \
        if (_a == _b)                                                         \
            ::test::fail(__FILE__, __LINE__,                                  \
                         "CHECK_NE(" #a ", " #b ") -- both " +                \
                             ::test::show(_a));                               \
    } while (0)

// Some things genuinely cannot be tested in every environment -- a CI runner
// with no multicast, say. Saying so out loud is better than a test that quietly
// passes because it did nothing.
#define SKIP(why)                                                             \
    do {                                                                      \
        std::printf("SKIP  %s:%d  %s\n", __FILE__, __LINE__, (why));          \
        return;                                                               \
    } while (0)
