// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <string>

#include "core/net/net_error.h"
#include "harness.h"
#include "platform/windows/net/win_sockets.h"
#include "platform/windows/net/wsa_error.h"

// The classification table is what every retry decision above this layer will
// be built on, so it is pinned down explicitly. No sockets involved.

using crimson::net::NetCat;
using crimson::net::NetError;
using crimson::net::NetOp;
using crimson::net::Retry;
using crimson::net::win::classify_wsa;
using crimson::net::win::describe;
using crimson::net::win::from_gai;
using crimson::net::win::from_wsa_code;
using crimson::net::win::symbolic_name;

CRIMSON_TEST(net_error, refused_and_unreachable_send_us_to_another_address) {
    // The distinction that makes fast IPv6 fallback possible. These say nothing
    // is wrong with the hostname, only with this particular address, so the
    // connector should move on rather than retry the same one.
    CHECK_EQ(classify_wsa(WSAECONNREFUSED), Retry::new_candidate);
    CHECK_EQ(classify_wsa(WSAEHOSTUNREACH), Retry::new_candidate);
    CHECK_EQ(classify_wsa(WSAENETUNREACH), Retry::new_candidate);
    CHECK_EQ(classify_wsa(WSAEHOSTDOWN), Retry::new_candidate);
    CHECK_EQ(classify_wsa(WSAEAFNOSUPPORT), Retry::new_candidate);
}

CRIMSON_TEST(net_error, transient_socket_states_stay_on_the_same_socket) {
    CHECK_EQ(classify_wsa(WSAEWOULDBLOCK), Retry::same_socket);
    CHECK_EQ(classify_wsa(WSAEINPROGRESS), Retry::same_socket);
    CHECK_EQ(classify_wsa(WSAEINTR), Retry::same_socket);
}

CRIMSON_TEST(net_error, lost_connections_warrant_a_reconnect) {
    CHECK_EQ(classify_wsa(WSAECONNRESET), Retry::new_connection);
    CHECK_EQ(classify_wsa(WSAECONNABORTED), Retry::new_connection);
    CHECK_EQ(classify_wsa(WSAETIMEDOUT), Retry::new_connection);
    CHECK_EQ(classify_wsa(WSAENETDOWN), Retry::new_connection);
    // Temporary name-server failure is worth another go; a definitive
    // "no such host" is not.
    CHECK_EQ(classify_wsa(WSATRY_AGAIN), Retry::new_connection);
}

CRIMSON_TEST(net_error, permanent_failures_are_not_retryable) {
    CHECK_EQ(classify_wsa(WSAHOST_NOT_FOUND), Retry::no);
    CHECK_EQ(classify_wsa(WSANO_DATA), Retry::no);
    CHECK_EQ(classify_wsa(WSANO_RECOVERY), Retry::no);
    CHECK_EQ(classify_wsa(WSAENOTCONN), Retry::no);
    CHECK_EQ(classify_wsa(WSAESHUTDOWN), Retry::no);
    CHECK_EQ(classify_wsa(WSAENOTSOCK), Retry::no);
    CHECK_EQ(classify_wsa(WSAEINVAL), Retry::no);
}

CRIMSON_TEST(net_error, unknown_codes_are_treated_as_permanent) {
    // Retrying an error nobody has classified risks a silent hot loop, which is
    // worse than surfacing the failure to the user.
    CHECK_EQ(classify_wsa(424242), Retry::no);
    CHECK_EQ(classify_wsa(0), Retry::no);
}

CRIMSON_TEST(net_error, retryable_reflects_the_retry_axis) {
    CHECK(from_wsa_code(NetOp::connect, WSAECONNREFUSED).retryable());
    CHECK(from_wsa_code(NetOp::recv, WSAECONNRESET).retryable());
    CHECK(!from_wsa_code(NetOp::recv, WSAENOTSOCK).retryable());
    CHECK(!NetError::cancelled(NetOp::recv).retryable());
}

CRIMSON_TEST(net_error, resolution_errors_are_tagged_as_such) {
    // On Windows the EAI_* values are numerically identical to Winsock codes:
    // EAI_NONAME, WSAHOST_NOT_FOUND and 11001 are the same number. The category
    // is the only thing that says which API produced it, which is the
    // difference between reporting "DNS resolution failed for imap.example.com"
    // and the useless "connect failed".
    const NetError resolved = from_gai(NetOp::resolve, WSAHOST_NOT_FOUND);
    const NetError socket_side = from_wsa_code(NetOp::connect, WSAHOST_NOT_FOUND);

    CHECK_EQ(resolved.native, socket_side.native);
    CHECK_EQ(resolved.cat, NetCat::gai);
    CHECK_EQ(socket_side.cat, NetCat::wsa);
    CHECK_EQ(resolved.op, NetOp::resolve);
}

CRIMSON_TEST(net_error, crimson_originated_errors_carry_no_native_code) {
    CHECK_EQ(NetError::timed_out(NetOp::connect).cat, NetCat::timeout);
    CHECK_EQ(NetError::timed_out(NetOp::connect).native, 0);
    CHECK_EQ(NetError::cancelled(NetOp::recv).cat, NetCat::cancelled);
    CHECK_EQ(NetError::truncated(NetOp::recv).cat, NetCat::truncated);
    CHECK_EQ(NetError::logic(NetOp::send).cat, NetCat::logic);
    CHECK_EQ(NetError::logic(NetOp::send).retry, Retry::no);
}

CRIMSON_TEST(net_error, symbolic_names_are_stable_for_known_codes) {
    CHECK_EQ(symbolic_name(WSAECONNREFUSED), std::string{"WSAECONNREFUSED"});
    CHECK_EQ(symbolic_name(WSAEWOULDBLOCK), std::string{"WSAEWOULDBLOCK"});
    CHECK_EQ(symbolic_name(WSAHOST_NOT_FOUND), std::string{"WSAHOST_NOT_FOUND"});
    // Unnamed codes fall back to the number rather than an empty string.
    CHECK_EQ(symbolic_name(424242), std::string{"424242"});
}

CRIMSON_TEST(net_error, descriptions_are_non_empty_for_every_category) {
    // FormatMessageW does render the 10000-range Winsock codes, even though
    // std::system_category does not map them to std::errc.
    CHECK(!describe(from_wsa_code(NetOp::connect, WSAECONNREFUSED)).empty());
    CHECK(!describe(NetError::timed_out(NetOp::connect)).empty());
    CHECK(!describe(NetError::cancelled(NetOp::recv)).empty());
    CHECK(!describe(NetError::truncated(NetOp::recv)).empty());
    CHECK(!describe(NetError::logic(NetOp::send)).empty());
}

CRIMSON_TEST(net_error, enum_names_round_trip_for_diagnostics) {
    CHECK_EQ(crimson::net::to_string(NetOp::connect), std::string_view{"connect"});
    CHECK_EQ(crimson::net::to_string(NetOp::resolve), std::string_view{"resolve"});
    CHECK_EQ(crimson::net::to_string(NetCat::gai), std::string_view{"gai"});
    CHECK_EQ(crimson::net::to_string(Retry::new_candidate),
             std::string_view{"new_candidate"});
}

CRIMSON_TEST(net_error, stays_cheap_enough_to_pass_by_value) {
    // Copied constantly through std::expected's error channel, including on
    // noexcept paths, so it must not grow an allocation.
    CHECK(std::is_trivially_copyable_v<NetError>);
    CHECK(sizeof(NetError) <= 8);
}
