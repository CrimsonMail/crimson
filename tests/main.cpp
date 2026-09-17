// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <cstdio>

#include "harness.h"
#include "platform/windows/net/net_log.h"
#include "platform/windows/net/winsock_runtime.h"

int main(int argc, char** argv) {
    // One scope for the whole process, destroyed after every test has finished
    // and every server thread has been joined. See winsock_runtime.h on why
    // this is not a function-local static.
    const auto winsock = crimson::net::win::WinsockScope::create();
    if (!winsock) {
        std::printf("Could not initialize Winsock; cannot run networking tests.\n");
        return 2;
    }

    // The networking layer logs to stderr. Tests exercise failure paths
    // deliberately, so keep it quiet unless something is being diagnosed;
    // CRIMSON_NET_LOG=debug turns it back on.
    crimson::net::win::set_log_level(crimson::net::win::LogLevel::off);
    std::size_t length = 0;
    char value[16] = {};
    if (::getenv_s(&length, value, sizeof(value), "CRIMSON_NET_LOG") == 0 && length > 1) {
        const std::string_view level{value, length - 1};
        if (level == "debug") {
            crimson::net::win::set_log_level(crimson::net::win::LogLevel::debug);
        } else if (level == "trace") {
            crimson::net::win::set_log_level(crimson::net::win::LogLevel::trace);
        } else if (level == "info") {
            crimson::net::win::set_log_level(crimson::net::win::LogLevel::info);
        }
    }

    std::printf("Crimson tests\n\n");
    return crimson::test::run_all(argc, argv);
}
