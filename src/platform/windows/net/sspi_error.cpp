// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "platform/windows/net/sspi_error.h"

#include "platform/windows/net/win_security.h"
#include "platform/windows/net/wsa_error.h"

#include <array>
#include <cstdio>
#include <string_view>

namespace crimson::net::win {

namespace {

struct StatusName {
    long status;
    std::string_view name;
};

// The statuses Crimson reasons about or is likely to see from a client
// handshake. Anything else is rendered in hex.
constexpr std::array kStatusNames{
    StatusName{SEC_E_INSUFFICIENT_MEMORY, "SEC_E_INSUFFICIENT_MEMORY"},
    StatusName{SEC_E_INVALID_HANDLE, "SEC_E_INVALID_HANDLE"},
    StatusName{SEC_E_UNSUPPORTED_FUNCTION, "SEC_E_UNSUPPORTED_FUNCTION"},
    StatusName{SEC_E_TARGET_UNKNOWN, "SEC_E_TARGET_UNKNOWN"},
    StatusName{SEC_E_INTERNAL_ERROR, "SEC_E_INTERNAL_ERROR"},
    StatusName{SEC_E_SECPKG_NOT_FOUND, "SEC_E_SECPKG_NOT_FOUND"},
    StatusName{SEC_E_INVALID_TOKEN, "SEC_E_INVALID_TOKEN"},
    StatusName{SEC_E_NO_CREDENTIALS, "SEC_E_NO_CREDENTIALS"},
    StatusName{SEC_E_MESSAGE_ALTERED, "SEC_E_MESSAGE_ALTERED"},
    StatusName{SEC_E_OUT_OF_SEQUENCE, "SEC_E_OUT_OF_SEQUENCE"},
    StatusName{SEC_E_NO_AUTHENTICATING_AUTHORITY, "SEC_E_NO_AUTHENTICATING_AUTHORITY"},
    StatusName{SEC_E_CONTEXT_EXPIRED, "SEC_E_CONTEXT_EXPIRED"},
    StatusName{SEC_E_INCOMPLETE_MESSAGE, "SEC_E_INCOMPLETE_MESSAGE"},
    StatusName{SEC_E_WRONG_PRINCIPAL, "SEC_E_WRONG_PRINCIPAL"},
    StatusName{SEC_E_UNTRUSTED_ROOT, "SEC_E_UNTRUSTED_ROOT"},
    StatusName{SEC_E_ILLEGAL_MESSAGE, "SEC_E_ILLEGAL_MESSAGE"},
    StatusName{SEC_E_CERT_UNKNOWN, "SEC_E_CERT_UNKNOWN"},
    StatusName{SEC_E_CERT_EXPIRED, "SEC_E_CERT_EXPIRED"},
    StatusName{SEC_E_ENCRYPT_FAILURE, "SEC_E_ENCRYPT_FAILURE"},
    StatusName{SEC_E_DECRYPT_FAILURE, "SEC_E_DECRYPT_FAILURE"},
    StatusName{SEC_E_ALGORITHM_MISMATCH, "SEC_E_ALGORITHM_MISMATCH"},
    StatusName{SEC_E_UNFINISHED_CONTEXT_DELETED, "SEC_E_UNFINISHED_CONTEXT_DELETED"},
    StatusName{SEC_E_CERT_WRONG_USAGE, "SEC_E_CERT_WRONG_USAGE"},
    StatusName{SEC_E_ISSUING_CA_UNTRUSTED, "SEC_E_ISSUING_CA_UNTRUSTED"},
    StatusName{SEC_E_INVALID_PARAMETER, "SEC_E_INVALID_PARAMETER"},
    StatusName{SEC_E_APPLICATION_PROTOCOL_MISMATCH, "SEC_E_APPLICATION_PROTOCOL_MISMATCH"},
    StatusName{CERT_E_EXPIRED, "CERT_E_EXPIRED"},
    StatusName{CERT_E_UNTRUSTEDROOT, "CERT_E_UNTRUSTEDROOT"},
    StatusName{CERT_E_CHAINING, "CERT_E_CHAINING"},
    StatusName{CERT_E_REVOKED, "CERT_E_REVOKED"},
    StatusName{CERT_E_CN_NO_MATCH, "CERT_E_CN_NO_MATCH"},
    StatusName{CERT_E_WRONG_USAGE, "CERT_E_WRONG_USAGE"},
    StatusName{CRYPT_E_REVOKED, "CRYPT_E_REVOKED"},
    StatusName{CRYPT_E_NO_REVOCATION_CHECK, "CRYPT_E_NO_REVOCATION_CHECK"},
    StatusName{CRYPT_E_REVOCATION_OFFLINE, "CRYPT_E_REVOCATION_OFFLINE"},
    StatusName{TRUST_E_CERT_SIGNATURE, "TRUST_E_CERT_SIGNATURE"},
};

[[nodiscard]] bool is_certificate_status(long status) noexcept {
    switch (status) {
        case SEC_E_WRONG_PRINCIPAL:
        case SEC_E_UNTRUSTED_ROOT:
        case SEC_E_CERT_UNKNOWN:
        case SEC_E_CERT_EXPIRED:
        case SEC_E_CERT_WRONG_USAGE:
        case SEC_E_ISSUING_CA_UNTRUSTED:
        case CERT_E_EXPIRED:
        case CERT_E_UNTRUSTEDROOT:
        case CERT_E_CHAINING:
        case CERT_E_REVOKED:
        case CERT_E_CN_NO_MATCH:
        case CERT_E_WRONG_USAGE:
        case CRYPT_E_REVOKED:
        case TRUST_E_CERT_SIGNATURE:
            return true;
        default:
            return false;
    }
}

}  // namespace

Retry classify_sspi(long status) noexcept {
    if (is_certificate_status(status)) {
        return Retry::no;
    }

    switch (status) {
        // The record stream went wrong in transit, or the session state did.
        // A fresh connection is the only thing that can help.
        //
        // SEC_E_ILLEGAL_MESSAGE is ambiguous: it is also how Schannel reports
        // a fatal alert from a server refusing the handshake outright — a
        // TLS 1.0-only server that shares no cipher suite with this machine,
        // or a CDN given no SNI — and then retrying cannot help. The sync
        // engine's backoff bounds the cost of the misclassification.
        case SEC_E_ILLEGAL_MESSAGE:
        case SEC_E_DECRYPT_FAILURE:
        case SEC_E_ENCRYPT_FAILURE:
        case SEC_E_MESSAGE_ALTERED:
        case SEC_E_INVALID_TOKEN:
        case SEC_E_OUT_OF_SEQUENCE:
        case SEC_E_CONTEXT_EXPIRED:
        case SEC_E_UNFINISHED_CONTEXT_DELETED:
        case SEC_E_INTERNAL_ERROR:
        case SEC_E_INSUFFICIENT_MEMORY:
        case SEC_E_NO_AUTHENTICATING_AUTHORITY:
        // Revocation information could not be fetched. With Crimson's
        // soft-fail revocation policy these should not normally surface, but
        // if they do, the cause is transient.
        case CRYPT_E_REVOCATION_OFFLINE:
        case CRYPT_E_NO_REVOCATION_CHECK:
            return Retry::new_connection;

        // No acceptable protocol or cipher suite in common, or a programming
        // error. Nothing about a retry would change either.
        case SEC_E_ALGORITHM_MISMATCH:
        case SEC_E_UNSUPPORTED_FUNCTION:
        case SEC_E_APPLICATION_PROTOCOL_MISMATCH:
        case SEC_E_TARGET_UNKNOWN:
        case SEC_E_NO_CREDENTIALS:
        case SEC_E_SECPKG_NOT_FOUND:
        case SEC_E_INVALID_HANDLE:
        case SEC_E_INVALID_PARAMETER:
            return Retry::no;

        default:
            // As with Winsock: an unclassified failure is treated as
            // permanent, because retrying what nobody understands risks a
            // silent hot loop.
            return Retry::no;
    }
}

NetError from_sspi(NetOp op, long status) noexcept {
    return NetError{static_cast<int>(status), op, NetCat::sspi, classify_sspi(status)};
}

bool is_certificate_error(const NetError& error) noexcept {
    return error.cat == NetCat::sspi && is_certificate_status(error.native);
}

std::string sspi_symbolic_name(long status) {
    for (const StatusName& entry : kStatusNames) {
        if (entry.status == status) {
            return std::string{entry.name};
        }
    }
    char buffer[16] = {};
    std::snprintf(buffer, sizeof(buffer), "0x%08lX", static_cast<unsigned long>(status));
    return buffer;
}

std::string error_name(const NetError& error) {
    switch (error.cat) {
        case NetCat::sspi:
            return sspi_symbolic_name(error.native);
        case NetCat::wsa:
        case NetCat::gai:
            return symbolic_name(error.native);
        case NetCat::timeout:
        case NetCat::cancelled:
        case NetCat::truncated:
        case NetCat::logic:
            break;
    }
    return std::string{to_string(error.cat)};
}

}  // namespace crimson::net::win
