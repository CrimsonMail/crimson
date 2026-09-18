// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <string>

#include "harness.h"
#include "platform/windows/net/sspi_error.h"
#include "platform/windows/net/win_security.h"

// The Schannel classification table. No network: these pin down how each
// status is reported, which is what the interface will build its messages on.

using crimson::net::NetCat;
using crimson::net::NetError;
using crimson::net::NetOp;
using crimson::net::Retry;
using crimson::net::win::classify_sspi;
using crimson::net::win::error_name;
using crimson::net::win::from_sspi;
using crimson::net::win::is_certificate_error;
using crimson::net::win::sspi_symbolic_name;

CRIMSON_TEST(sspi_error, certificate_failures_are_permanent) {
    // An expired or untrusted certificate is exactly as expired and untrusted
    // on the next attempt. These need a person, not a retry loop.
    for (const long status : {SEC_E_CERT_EXPIRED, SEC_E_UNTRUSTED_ROOT, SEC_E_WRONG_PRINCIPAL,
                              SEC_E_CERT_UNKNOWN, CRYPT_E_REVOKED, CERT_E_REVOKED,
                              CERT_E_CN_NO_MATCH}) {
        const NetError error = from_sspi(NetOp::tls_handshake, status);
        CHECK_MSG(error.retry == Retry::no, sspi_symbolic_name(status) + " should not be retried");
        CHECK_MSG(is_certificate_error(error),
                  sspi_symbolic_name(status) + " should be reported as a certificate problem");
    }
}

CRIMSON_TEST(sspi_error, corrupted_records_warrant_a_new_connection) {
    for (const long status : {SEC_E_DECRYPT_FAILURE, SEC_E_MESSAGE_ALTERED, SEC_E_OUT_OF_SEQUENCE,
                              SEC_E_INVALID_TOKEN, SEC_E_ILLEGAL_MESSAGE}) {
        const NetError error = from_sspi(NetOp::tls_decrypt, status);
        CHECK_MSG(error.retry == Retry::new_connection,
                  sspi_symbolic_name(status) + " should suggest reconnecting");
        CHECK(!is_certificate_error(error));
    }
}

CRIMSON_TEST(sspi_error, no_common_protocol_is_permanent_but_not_a_certificate_problem) {
    // What a TLS 1.0-only server produces against Crimson's TLS 1.2 floor,
    // measured against tls-v1-0.badssl.com and tls-v1-1.badssl.com.
    const NetError error = from_sspi(NetOp::tls_handshake, SEC_E_ALGORITHM_MISMATCH);
    CHECK_EQ(error.retry, Retry::no);
    CHECK(!is_certificate_error(error));
}

CRIMSON_TEST(sspi_error, revocation_data_unavailable_is_transient) {
    // With soft-fail revocation these should rarely surface; if they do, the
    // revocation server being unreachable is not a property of the certificate.
    CHECK_EQ(classify_sspi(CRYPT_E_REVOCATION_OFFLINE), Retry::new_connection);
    CHECK(!is_certificate_error(from_sspi(NetOp::tls_handshake, CRYPT_E_REVOCATION_OFFLINE)));
}

CRIMSON_TEST(sspi_error, unknown_statuses_are_permanent) {
    CHECK_EQ(classify_sspi(static_cast<long>(0x80091234)), Retry::no);
}

CRIMSON_TEST(sspi_error, carries_its_category_and_stage) {
    const NetError error = from_sspi(NetOp::tls_handshake, SEC_E_UNTRUSTED_ROOT);
    CHECK_EQ(error.cat, NetCat::sspi);
    CHECK_EQ(error.op, NetOp::tls_handshake);
    CHECK_EQ(error.native, static_cast<int>(SEC_E_UNTRUSTED_ROOT));
}

CRIMSON_TEST(sspi_error, names_are_symbolic_with_a_hex_fallback) {
    CHECK_EQ(sspi_symbolic_name(SEC_E_UNTRUSTED_ROOT), std::string{"SEC_E_UNTRUSTED_ROOT"});
    CHECK_EQ(sspi_symbolic_name(SEC_E_CERT_EXPIRED), std::string{"SEC_E_CERT_EXPIRED"});
    CHECK_EQ(sspi_symbolic_name(CRYPT_E_REVOKED), std::string{"CRYPT_E_REVOKED"});
    // An HRESULT printed as a signed decimal is unreadable; hex is how every
    // Microsoft reference lists them.
    CHECK_EQ(sspi_symbolic_name(static_cast<long>(0x80091234)), std::string{"0x80091234"});
}

CRIMSON_TEST(sspi_error, error_name_dispatches_on_category) {
    CHECK_EQ(error_name(from_sspi(NetOp::tls_handshake, SEC_E_WRONG_PRINCIPAL)),
             std::string{"SEC_E_WRONG_PRINCIPAL"});
    CHECK_EQ(error_name(NetError{WSAECONNREFUSED, NetOp::connect, NetCat::wsa, Retry::new_candidate}),
             std::string{"WSAECONNREFUSED"});
    CHECK_EQ(error_name(NetError::timed_out(NetOp::connect)), std::string{"timeout"});
}

CRIMSON_TEST(sspi_error, certificate_check_ignores_other_categories) {
    // The same number from a different API is not a certificate problem.
    const NetError wsa{static_cast<int>(SEC_E_UNTRUSTED_ROOT), NetOp::recv, NetCat::wsa, Retry::no};
    CHECK(!is_certificate_error(wsa));
}
