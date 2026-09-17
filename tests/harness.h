// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_TESTS_HARNESS_H
#define CRIMSON_TESTS_HARNESS_H

#include <cstdint>
#include <exception>
#include <string>
#include <string_view>
#include <type_traits>

#include "core/net/net_error.h"

// Crimson's test harness.
//
// Small on purpose: ADR 0004 rules out a third-party framework, and a mail
// client's tests need very little beyond registration, assertions and a
// watchdog.
//
// Two design points matter more than the feature list:
//
// ASSERTIONS THROW. A failing CHECK raises AssertionFailure, which the runner
// catches per test. Early-return macros cannot propagate out of a helper
// function, and much of Crimson's test code will live in helpers. Throwing is
// also the only mechanism that guarantees RAII teardown from arbitrary nesting
// depth, which is what stops a failed assertion from leaving a listening socket
// or a live server thread behind.
//
// THERE IS A WATCHDOG. Networking tests can hang rather than fail: a thread
// parked in recv on a connection nobody will ever write to waits forever. A
// thread in that state cannot be safely killed, so the watchdog prints the
// current test, flushes, and terminates the process. Flushing before
// terminating is the part that is easy to forget, and without it CI shows an
// empty log and no clue which test hung.

namespace crimson::test {

class AssertionFailure : public std::exception {
public:
    explicit AssertionFailure(std::string message) : message_(std::move(message)) {}

    [[nodiscard]] const char* what() const noexcept override { return message_.c_str(); }

private:
    std::string message_;
};

using TestFunction = void (*)();

struct TestCase {
    std::string_view suite;
    std::string_view name;
    TestFunction function;
    std::string_view file;
    int line;
};

// Called by the CRIMSON_TEST macro before main runs.
void register_test(const TestCase& test_case);

// Runs the registered tests. Accepts an optional substring filter:
//
//     Crimson.Tests.exe socket        runs tests whose suite.name contains it
//     Crimson.Tests.exe --list        prints the registered tests
//     Crimson.Tests.exe --timeout 30  seconds per test before the watchdog fires
//
// Returns 0 when everything passed.
[[nodiscard]] int run_all(int argc, char** argv);

// Renders a NetError for an assertion message: stage, category, symbolic code
// and the system's own description, so a failure says which call failed and why
// rather than just "expected success".
[[nodiscard]] std::string describe_error(const crimson::net::NetError& error);

// Rendering for assertion messages. Deliberately narrow: enough for the types
// Crimson's tests actually compare, with a readable fallback.
namespace detail {

[[nodiscard]] std::string quote(std::string_view text);

template <typename T>
[[nodiscard]] std::string to_text(const T& value) {
    if constexpr (std::is_same_v<T, bool>) {
        return value ? "true" : "false";
    } else if constexpr (std::is_same_v<T, std::string> ||
                         std::is_same_v<T, std::string_view> ||
                         std::is_same_v<T, const char*>) {
        return quote(value);
    } else if constexpr (std::is_enum_v<T>) {
        // Every enum in the networking layer has a to_string overload found by
        // ordinary lookup; prefer it over the numeric value.
        return std::string{to_string(value)};
    } else if constexpr (std::is_integral_v<T>) {
        if constexpr (std::is_signed_v<T>) {
            return std::to_string(static_cast<long long>(value));
        } else {
            return std::to_string(static_cast<unsigned long long>(value));
        }
    } else if constexpr (std::is_floating_point_v<T>) {
        return std::to_string(value);
    } else if constexpr (std::is_pointer_v<T>) {
        return value == nullptr ? "nullptr" : "<pointer>";
    } else {
        return "<value>";
    }
}

[[noreturn]] void fail(std::string_view file, int line, std::string_view expression,
                       std::string detail);

template <typename A, typename B>
void check_equal(std::string_view file, int line, std::string_view expression,
                 const A& actual, const B& expected) {
    if (!(actual == expected)) {
        fail(file, line, expression,
             "expected " + to_text(expected) + ", got " + to_text(actual));
    }
}

template <typename A, typename B>
void check_not_equal(std::string_view file, int line, std::string_view expression,
                     const A& actual, const B& forbidden) {
    if (actual == forbidden) {
        fail(file, line, expression, "expected anything but " + to_text(forbidden));
    }
}

}  // namespace detail

// Registers a test. Bodies go straight after:
//
//     CRIMSON_TEST(socket_handle, default_is_invalid) {
//         SocketHandle handle;
//         CHECK(!handle.valid());
//     }
#define CRIMSON_TEST(suite_name, test_name)                                        \
    static void crimson_test_##suite_name##_##test_name();                         \
    namespace {                                                                    \
    const struct Register_##suite_name##_##test_name {                             \
        Register_##suite_name##_##test_name() {                                    \
            ::crimson::test::register_test(                                        \
                {#suite_name, #test_name, &crimson_test_##suite_name##_##test_name, \
                 __FILE__, __LINE__});                                             \
        }                                                                          \
    } registrar_##suite_name##_##test_name{};                                      \
    }                                                                              \
    static void crimson_test_##suite_name##_##test_name()

#define CHECK(expression)                                                       \
    do {                                                                        \
        if (!(expression)) {                                                    \
            ::crimson::test::detail::fail(__FILE__, __LINE__, #expression,      \
                                          "expression is false");               \
        }                                                                       \
    } while (false)

#define CHECK_MSG(expression, message)                                          \
    do {                                                                        \
        if (!(expression)) {                                                    \
            ::crimson::test::detail::fail(__FILE__, __LINE__, #expression,      \
                                          (message));                           \
        }                                                                       \
    } while (false)

#define CHECK_EQ(actual, expected)                                              \
    ::crimson::test::detail::check_equal(__FILE__, __LINE__,                    \
                                        #actual " == " #expected, (actual),     \
                                        (expected))

#define CHECK_NE(actual, forbidden)                                             \
    ::crimson::test::detail::check_not_equal(__FILE__, __LINE__,                \
                                            #actual " != " #forbidden,          \
                                            (actual), (forbidden))

// For a std::expected: asserts success and gives a usable message on failure,
// instead of the bare "expression is false" a CHECK would produce.
#define CHECK_OK(outcome)                                                       \
    do {                                                                        \
        const auto& crimson_outcome = (outcome);                                \
        if (!crimson_outcome.has_value()) {                                     \
            ::crimson::test::detail::fail(                                      \
                __FILE__, __LINE__, #outcome,                                   \
                "expected success, got error: " +                               \
                    ::crimson::test::describe_error(crimson_outcome.error()));  \
        }                                                                       \
    } while (false)

#define CHECK_ERR(outcome)                                                      \
    do {                                                                        \
        const auto& crimson_outcome = (outcome);                                \
        if (crimson_outcome.has_value()) {                                      \
            ::crimson::test::detail::fail(__FILE__, __LINE__, #outcome,         \
                                          "expected an error, got success");    \
        }                                                                       \
    } while (false)

}  // namespace crimson::test

#endif  // CRIMSON_TESTS_HARNESS_H
