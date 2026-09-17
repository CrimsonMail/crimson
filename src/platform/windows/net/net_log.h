// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_NET_LOG_H
#define CRIMSON_PLATFORM_WINDOWS_NET_NET_LOG_H

#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>

// Structured diagnostics for the networking layer.
//
// Output is one line of key=value pairs:
//
//   component=net level=info event=dns_resolved host=example.com candidates=4
//   component=net level=info event=tcp_connected address=93.184.216.34 family=ipv4 port=80
//
// METADATA ONLY. Never log payload bytes through this, and never add a
// convenience overload that makes it easy to.
//
// Step 1 has no secrets to leak yet, which is exactly why the rule is
// established now. Very shortly this same layer carries IMAP LOGIN commands,
// OAuth bearer tokens, Authorization headers and message bodies. A traffic
// dump added "temporarily" for debugging becomes a credential disclosure the
// moment a user pastes a log into a bug report. Raw protocol tracing, when it
// arrives, is a separate subsystem with explicit redaction, not a flag on this
// one.
//
// Safe to call from any thread and from noexcept code: log_event swallows its
// own failures, and it saves and restores the Win32 last-error value so a log
// line placed between a failed call and its error capture cannot destroy the
// error code. Capturing errors first is still the rule; this is a second line
// of defence.

namespace crimson::net::win {

enum class LogLevel : std::uint8_t {
    error = 0,
    warn = 1,
    info = 2,
    debug = 3,
    trace = 4,
    off = 5,
};

struct LogField {
    std::string_view key;
    std::string value;
};

// Defaults to LogLevel::info. Not synchronized against concurrent readers
// beyond being an atomic load, which is sufficient for a verbosity knob.
void set_log_level(LogLevel level) noexcept;

[[nodiscard]] LogLevel log_level() noexcept;

[[nodiscard]] bool log_enabled(LogLevel level) noexcept;

// Writes one structured line. Values containing spaces, quotes or '=' are
// quoted and escaped so the output stays machine-parseable.
void log_event(LogLevel level, std::string_view event,
               std::initializer_list<LogField> fields) noexcept;

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_NET_LOG_H
