// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_TLS_CREDENTIALS_H
#define CRIMSON_PLATFORM_WINDOWS_NET_TLS_CREDENTIALS_H

#include <expected>
#include <memory>

#include "core/net/net_error.h"
#include "platform/windows/net/win_security.h"

namespace crimson::net::win {

// Crimson's TLS client policy, as a Schannel credential handle.
//
// Create one and share it. Copies refer to the same handle, which is released
// when the last copy goes, and every TlsStream keeps a copy — so a credential
// can never be freed underneath a connection using it. Sharing is also what
// lets Schannel resume sessions: its session cache is keyed on the credential,
// so a second connection to the same server can skip most of the handshake.
//
// The policy, deliberately fixed rather than configurable:
//
//   Protocols   TLS 1.2 and newer. SSL 3.0, TLS 1.0 and TLS 1.1 are disabled
//               through a disable-list, so TLS 1.3 — and anything later — is
//               used whenever Windows and the server both support it, without
//               Crimson needing a change. RFC 8314 requires 1.2 or better.
//
//   Ciphers     SCH_USE_STRONG_CRYPTO: no weak suites.
//
//   Validation  Schannel validates the server's certificate chain against the
//               Windows trust store and checks the hostname. Crimson does not
//               reimplement any of it (research doc §3, ADR 0011).
//
//   Revocation  Checked for the whole chain except the root, soft-failing when
//               revocation information cannot be fetched. A certificate known
//               to be revoked fails hard; a captive portal or strict network
//               that blocks OCSP does not break every connection. This is the
//               policy browsers use.
//
//   Client      None. Crimson never presents a client certificate, and
//   certs       SCH_CRED_NO_DEFAULT_CREDS stops Schannel choosing one itself.
//
// THREADING. Safe to share between threads and connections.
class TlsCredentials {
public:
    [[nodiscard]] static std::expected<TlsCredentials, NetError> create() noexcept;

    TlsCredentials() noexcept = default;

    [[nodiscard]] bool valid() const noexcept { return state_ != nullptr; }

    // For InitializeSecurityContext. Stays valid for as long as any copy of
    // this object exists.
    [[nodiscard]] CredHandle* handle() const noexcept;

private:
    struct State;
    explicit TlsCredentials(std::shared_ptr<State> state) noexcept
        : state_(std::move(state)) {}

    std::shared_ptr<State> state_;
};

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_TLS_CREDENTIALS_H
