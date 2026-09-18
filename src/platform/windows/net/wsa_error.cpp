// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "platform/windows/net/wsa_error.h"

#include "platform/windows/net/win_sockets.h"

#include <array>
#include <string_view>

namespace crimson::net::win {

namespace {

struct CodeName {
    int code;
    std::string_view name;
};

// Only the codes Crimson actually reasons about. Anything else falls back to a
// decimal rendering, which is fine for a log line.
constexpr std::array kCodeNames{
    CodeName{WSAEINTR, "WSAEINTR"},
    CodeName{WSAEACCES, "WSAEACCES"},
    CodeName{WSAEFAULT, "WSAEFAULT"},
    CodeName{WSAEINVAL, "WSAEINVAL"},
    CodeName{WSAEMFILE, "WSAEMFILE"},
    CodeName{WSAEWOULDBLOCK, "WSAEWOULDBLOCK"},
    CodeName{WSAEINPROGRESS, "WSAEINPROGRESS"},
    CodeName{WSAEALREADY, "WSAEALREADY"},
    CodeName{WSAENOTSOCK, "WSAENOTSOCK"},
    CodeName{WSAEMSGSIZE, "WSAEMSGSIZE"},
    CodeName{WSAEAFNOSUPPORT, "WSAEAFNOSUPPORT"},
    CodeName{WSAEADDRINUSE, "WSAEADDRINUSE"},
    CodeName{WSAEADDRNOTAVAIL, "WSAEADDRNOTAVAIL"},
    CodeName{WSAENETDOWN, "WSAENETDOWN"},
    CodeName{WSAENETUNREACH, "WSAENETUNREACH"},
    CodeName{WSAENETRESET, "WSAENETRESET"},
    CodeName{WSAECONNABORTED, "WSAECONNABORTED"},
    CodeName{WSAECONNRESET, "WSAECONNRESET"},
    CodeName{WSAENOBUFS, "WSAENOBUFS"},
    CodeName{WSAEISCONN, "WSAEISCONN"},
    CodeName{WSAENOTCONN, "WSAENOTCONN"},
    CodeName{WSAESHUTDOWN, "WSAESHUTDOWN"},
    CodeName{WSAETIMEDOUT, "WSAETIMEDOUT"},
    CodeName{WSAECONNREFUSED, "WSAECONNREFUSED"},
    CodeName{WSAEHOSTDOWN, "WSAEHOSTDOWN"},
    CodeName{WSAEHOSTUNREACH, "WSAEHOSTUNREACH"},
    CodeName{WSAEPROCLIM, "WSAEPROCLIM"},
    CodeName{WSASYSNOTREADY, "WSASYSNOTREADY"},
    CodeName{WSAVERNOTSUPPORTED, "WSAVERNOTSUPPORTED"},
    CodeName{WSANOTINITIALISED, "WSANOTINITIALISED"},
    CodeName{WSAEDISCON, "WSAEDISCON"},
    CodeName{WSATRY_AGAIN, "WSATRY_AGAIN"},
    CodeName{WSANO_RECOVERY, "WSANO_RECOVERY"},
    CodeName{WSANO_DATA, "WSANO_DATA"},
    CodeName{WSAHOST_NOT_FOUND, "WSAHOST_NOT_FOUND"},
    CodeName{WSATYPE_NOT_FOUND, "WSATYPE_NOT_FOUND"},
};

}  // namespace

Retry classify_wsa(int code) noexcept {
    switch (code) {
        // Transient on this very socket: poll and try the same call again.
        case WSAEWOULDBLOCK:
        case WSAEINPROGRESS:
        case WSAEINTR:
            return Retry::same_socket;

        // The connection is gone, but the address is fine. Reconnect.
        case WSAECONNRESET:
        case WSAECONNABORTED:
        case WSAENETRESET:
        case WSAEDISCON:
        case WSAETIMEDOUT:
        // Local resource pressure; likely to pass.
        case WSAENOBUFS:
        case WSAEMFILE:
        case WSAEPROCLIM:
        // Local network is down, which is not this address's fault.
        case WSAENETDOWN:
        // Temporary name-server failure.
        case WSATRY_AGAIN:
            return Retry::new_connection;

        // This particular address is unusable. A different candidate from the
        // same hostname may well work, which is the common IPv6-configured-
        // but-unroutable case.
        case WSAECONNREFUSED:
        case WSAEHOSTUNREACH:
        case WSAENETUNREACH:
        case WSAEHOSTDOWN:
        case WSAEADDRNOTAVAIL:
        case WSAEAFNOSUPPORT:
            return Retry::new_candidate;

        // Permanent: programming errors, permanent DNS answers, and states
        // where retrying is meaningless.
        case WSAENOTCONN:
        case WSAESHUTDOWN:
        case WSAENOTSOCK:
        case WSAEINVAL:
        case WSAEFAULT:
        case WSAEACCES:
        case WSAEISCONN:
        case WSAEALREADY:
        case WSAEMSGSIZE:
        case WSAEADDRINUSE:
        case WSAHOST_NOT_FOUND:
        case WSATYPE_NOT_FOUND:
        case WSANO_DATA:
        case WSANO_RECOVERY:
        case WSANOTINITIALISED:
        case WSASYSNOTREADY:
        case WSAVERNOTSUPPORTED:
            return Retry::no;

        default:
            // Unknown codes are treated as permanent. Retrying an error we do
            // not understand risks a silent hot loop, which is worse than
            // surfacing the failure.
            return Retry::no;
    }
}

NetError from_wsa_code(NetOp op, int code) noexcept {
    return NetError{code, op, NetCat::wsa, classify_wsa(code)};
}

NetError from_wsa(NetOp op) noexcept {
    return from_wsa_code(op, ::WSAGetLastError());
}

NetError from_gai(NetOp op, int code) noexcept {
    // The EAI_* values are WSA codes on Windows, so the same classifier
    // applies. Only the category differs, so a diagnostic can say the failure
    // came from resolution rather than from a socket call.
    return NetError{code, op, NetCat::gai, classify_wsa(code)};
}

std::string symbolic_name(int code) {
    for (const CodeName& entry : kCodeNames) {
        if (entry.code == code) {
            return std::string{entry.name};
        }
    }
    return std::to_string(code);
}

std::string describe(const NetError& error) {
    switch (error.cat) {
        case NetCat::timeout:
            return "operation timed out";
        case NetCat::cancelled:
            return "operation cancelled";
        case NetCat::truncated:
            return "peer closed the connection before all expected data arrived";
        case NetCat::logic:
            return "internal contract violation";
        case NetCat::wsa:
        case NetCat::gai:
        case NetCat::sspi:  // SEC_E_* codes are in the same system message table
            break;
    }

    LPWSTR buffer = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, static_cast<DWORD>(error.native),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    if (length == 0 || buffer == nullptr) {
        if (buffer != nullptr) {
            ::LocalFree(buffer);
        }
        return symbolic_name(error.native);
    }

    // FormatMessageW appends CRLF and sometimes a trailing period.
    std::wstring wide{buffer, length};
    ::LocalFree(buffer);
    while (!wide.empty() &&
           (wide.back() == L'\r' || wide.back() == L'\n' || wide.back() == L' ')) {
        wide.pop_back();
    }
    if (wide.empty()) {
        return symbolic_name(error.native);
    }

    const int needed = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0,
        nullptr, nullptr);
    if (needed <= 0) {
        return symbolic_name(error.native);
    }

    std::string utf8(static_cast<std::size_t>(needed), '\0');
    const int converted = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), utf8.data(),
        needed, nullptr, nullptr);
    if (converted <= 0) {
        return symbolic_name(error.native);
    }
    utf8.resize(static_cast<std::size_t>(converted));
    return utf8;
}

}  // namespace crimson::net::win
