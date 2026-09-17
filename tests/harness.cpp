// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "harness.h"

#include "platform/windows/net/wsa_error.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

namespace crimson::test {

namespace {

// Registration happens during static initialization, so the registry has to be
// a function-local static: a namespace-scope vector might not be constructed
// yet when the first registrar runs.
std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct Watchdog {
    std::mutex mutex;
    std::condition_variable signal;
    bool finished = false;
    std::string current;
};

[[nodiscard]] std::string_view base_name(std::string_view path) noexcept {
    const std::size_t slash = path.find_last_of("/\\");
    return slash == std::string_view::npos ? path : path.substr(slash + 1);
}

}  // namespace

namespace detail {

std::string quote(std::string_view text) {
    std::string quoted;
    quoted.reserve(text.size() + 2);
    quoted.push_back('"');
    quoted.append(text);
    quoted.push_back('"');
    return quoted;
}

void fail(std::string_view file, int line, std::string_view expression,
          std::string detail_text) {
    std::string message;
    message.append(base_name(file));
    message.push_back(':');
    message.append(std::to_string(line));
    message.append(": ");
    message.append(expression);
    message.append("\n      ");
    message.append(detail_text);
    throw AssertionFailure{std::move(message)};
}

}  // namespace detail

void register_test(const TestCase& test_case) { registry().push_back(test_case); }

std::string describe_error(const crimson::net::NetError& error) {
    std::string text;
    text.append(std::string{crimson::net::to_string(error.op)});
    text.append("/");
    text.append(std::string{crimson::net::to_string(error.cat)});
    text.append(" ");
    text.append(crimson::net::win::symbolic_name(error.native));
    text.append(" (");
    text.append(crimson::net::win::describe(error));
    text.append(")");
    return text;
}

int run_all(int argc, char** argv) {
    std::string filter;
    bool list_only = false;
    int timeout_seconds = 15;

    for (int index = 1; index < argc; ++index) {
        const std::string_view argument = argv[index];
        if (argument == "--list") {
            list_only = true;
        } else if (argument == "--timeout" && index + 1 < argc) {
            const int parsed = std::atoi(argv[++index]);
            if (parsed > 0) {
                timeout_seconds = parsed;
            }
        } else if (!argument.starts_with("--")) {
            filter = argument;
        }
    }

    std::vector<TestCase>& tests = registry();

    if (list_only) {
        for (const TestCase& test_case : tests) {
            std::printf("%.*s.%.*s\n", static_cast<int>(test_case.suite.size()),
                        test_case.suite.data(), static_cast<int>(test_case.name.size()),
                        test_case.name.data());
        }
        return 0;
    }

    // A thread parked in recv cannot be killed safely, so a hung test is
    // terminated at the process level. Printing and flushing first is the whole
    // point: without it the log ends mid-test with no indication of which one.
    Watchdog watchdog;
    std::atomic<bool> stop_watchdog{false};
    std::thread watchdog_thread{[&watchdog, &stop_watchdog, timeout_seconds] {
        std::unique_lock<std::mutex> lock{watchdog.mutex};
        while (!stop_watchdog.load(std::memory_order_acquire)) {
            if (watchdog.current.empty()) {
                watchdog.signal.wait_for(lock, std::chrono::milliseconds{100});
                continue;
            }
            const std::string running = watchdog.current;
            const bool completed = watchdog.signal.wait_for(
                lock, std::chrono::seconds{timeout_seconds},
                [&watchdog, &running] { return watchdog.finished || watchdog.current != running; });
            if (!completed) {
                std::printf("\n  TIMEOUT after %ds in %s\n", timeout_seconds,
                            running.c_str());
                std::printf("\n  A test hung. Terminating: a thread blocked in recv\n"
                            "  cannot be safely interrupted from here.\n");
                std::fflush(stdout);
                std::fflush(stderr);
                ::exit(3);
            }
        }
    }};

    std::size_t passed = 0;
    std::size_t failed = 0;
    std::size_t skipped = 0;
    const auto started = std::chrono::steady_clock::now();

    for (const TestCase& test_case : tests) {
        std::string full_name{test_case.suite};
        full_name.push_back('.');
        full_name.append(test_case.name);

        if (!filter.empty() && full_name.find(filter) == std::string::npos) {
            ++skipped;
            continue;
        }

        {
            const std::lock_guard<std::mutex> guard{watchdog.mutex};
            watchdog.current = full_name;
        }
        watchdog.signal.notify_all();

        std::printf("  %-52s ", full_name.c_str());
        std::fflush(stdout);

        try {
            test_case.function();
            std::printf("ok\n");
            ++passed;
        } catch (const AssertionFailure& failure) {
            std::printf("FAILED\n      %s\n", failure.what());
            ++failed;
        } catch (const std::exception& error) {
            std::printf("FAILED\n      unexpected exception: %s\n", error.what());
            ++failed;
        } catch (...) {
            std::printf("FAILED\n      unexpected non-standard exception\n");
            ++failed;
        }
        std::fflush(stdout);
    }

    {
        const std::lock_guard<std::mutex> guard{watchdog.mutex};
        watchdog.finished = true;
        watchdog.current.clear();
    }
    stop_watchdog.store(true, std::memory_order_release);
    watchdog.signal.notify_all();
    watchdog_thread.join();

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);

    std::printf("\n  %zu passed, %zu failed", passed, failed);
    if (skipped > 0) {
        std::printf(", %zu filtered out", skipped);
    }
    std::printf("  (%lld ms)\n", static_cast<long long>(elapsed.count()));

    return failed == 0 ? 0 : 1;
}

}  // namespace crimson::test
