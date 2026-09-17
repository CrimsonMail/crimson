// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "platform/windows/net/net_log.h"

#include "platform/windows/net/win_sockets.h"

#include <atomic>
#include <cstdio>
#include <mutex>

namespace crimson::net::win {

namespace {

std::atomic<LogLevel> g_level{LogLevel::info};

// Serializes writes so concurrent workers cannot interleave half-lines.
std::mutex& output_mutex() {
    static std::mutex mutex;
    return mutex;
}

// Preserves the Win32 last-error value across this scope.
//
// WSAGetLastError() is GetLastError(): one per-thread slot shared with every
// Win32 and CRT call. Without this, a log line between a failed recv and its
// error capture would report the error from fwrite instead.
class LastErrorGuard {
public:
    LastErrorGuard() noexcept : saved_(::GetLastError()) {}
    ~LastErrorGuard() noexcept { ::SetLastError(saved_); }

    LastErrorGuard(const LastErrorGuard&) = delete;
    LastErrorGuard& operator=(const LastErrorGuard&) = delete;

private:
    DWORD saved_;
};

[[nodiscard]] std::string_view level_name(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::error: return "error";
        case LogLevel::warn:  return "warn";
        case LogLevel::info:  return "info";
        case LogLevel::debug: return "debug";
        case LogLevel::trace: return "trace";
        case LogLevel::off:   return "off";
    }
    return "unknown";
}

[[nodiscard]] bool needs_quoting(std::string_view value) noexcept {
    if (value.empty()) {
        return true;
    }
    for (const char character : value) {
        if (character == ' ' || character == '"' || character == '=' ||
            character == '\\' || character == '\r' || character == '\n') {
            return true;
        }
    }
    return false;
}

void append_value(std::string& line, std::string_view value) {
    if (!needs_quoting(value)) {
        line.append(value);
        return;
    }
    line.push_back('"');
    for (const char character : value) {
        switch (character) {
            case '"':  line.append("\\\""); break;
            case '\\': line.append("\\\\"); break;
            case '\r': line.append("\\r");  break;
            case '\n': line.append("\\n");  break;
            default:   line.push_back(character); break;
        }
    }
    line.push_back('"');
}

}  // namespace

void set_log_level(LogLevel level) noexcept {
    g_level.store(level, std::memory_order_relaxed);
}

LogLevel log_level() noexcept {
    return g_level.load(std::memory_order_relaxed);
}

bool log_enabled(LogLevel level) noexcept {
    const LogLevel current = log_level();
    if (current == LogLevel::off) {
        return false;
    }
    return static_cast<std::uint8_t>(level) <= static_cast<std::uint8_t>(current);
}

void log_event(LogLevel level, std::string_view event,
               std::initializer_list<LogField> fields) noexcept {
    const LastErrorGuard error_guard;

    if (!log_enabled(level)) {
        return;
    }

    // Logging must never be the reason a network operation fails, and the
    // callers are noexcept. Formatting allocates, so contain it here.
    try {
        std::string line;
        line.reserve(128);
        line.append("component=net level=");
        line.append(level_name(level));
        line.append(" event=");
        append_value(line, event);

        for (const LogField& field : fields) {
            line.push_back(' ');
            line.append(field.key);
            line.push_back('=');
            append_value(line, field.value);
        }
        line.push_back('\n');

        const std::lock_guard<std::mutex> guard{output_mutex()};
        std::fwrite(line.data(), 1, line.size(), stderr);
        std::fflush(stderr);
    } catch (...) {
        // Dropping a diagnostic is always preferable to disturbing the caller.
    }
}

}  // namespace crimson::net::win
