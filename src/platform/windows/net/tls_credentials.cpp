// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "platform/windows/net/tls_credentials.h"

#include "platform/windows/net/sspi_error.h"

#include <new>

namespace crimson::net::win {

struct TlsCredentials::State {
    CredHandle handle{};

    State() noexcept { SecInvalidateHandle(&handle); }
    State(const State&) = delete;
    State& operator=(const State&) = delete;

    ~State() {
        if (SecIsValidHandle(&handle)) {
            ::FreeCredentialsHandle(&handle);
        }
    }
};

std::expected<TlsCredentials, NetError> TlsCredentials::create() noexcept {
    std::shared_ptr<State> state;
    try {
        state = std::make_shared<State>();
    } catch (const std::bad_alloc&) {
        return std::unexpected(NetError::logic(NetOp::credentials));
    }

    // A disable-list rather than an enable-list: whatever is not named here is
    // allowed, so newer protocols need no change to Crimson.
    TLS_PARAMETERS parameters{};
    parameters.grbitDisabledProtocols =
        SP_PROT_SSL2 | SP_PROT_SSL3 | SP_PROT_TLS1_0 | SP_PROT_TLS1_1;

    SCH_CREDENTIALS credentials{};
    credentials.dwVersion = SCH_CREDENTIALS_VERSION;
    credentials.dwFlags =
        SCH_CRED_NO_DEFAULT_CREDS |                   // never pick a client certificate
        SCH_CRED_AUTO_CRED_VALIDATION |               // Schannel validates the chain
        SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |  // ...including revocation,
        SCH_CRED_IGNORE_NO_REVOCATION_CHECK |           // soft-failing when revocation
        SCH_CRED_IGNORE_REVOCATION_OFFLINE |            // data is unreachable
        SCH_USE_STRONG_CRYPTO;                        // no weak cipher suites
    credentials.cTlsParameters = 1;
    credentials.pTlsParameters = &parameters;

    TimeStamp expiry{};
    const SECURITY_STATUS status = ::AcquireCredentialsHandleW(
        nullptr, const_cast<LPWSTR>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND, nullptr,
        &credentials, nullptr, nullptr, &state->handle, &expiry);

    if (status != SEC_E_OK) {
        // Nothing was acquired, so ~State must not free whatever is there.
        SecInvalidateHandle(&state->handle);
        return std::unexpected(from_sspi(NetOp::credentials, status));
    }

    return TlsCredentials{std::move(state)};
}

CredHandle* TlsCredentials::handle() const noexcept {
    return state_ ? &state_->handle : nullptr;
}

}  // namespace crimson::net::win
