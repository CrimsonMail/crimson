// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PLATFORM_WINDOWS_NET_TLS_STREAM_H
#define CRIMSON_PLATFORM_WINDOWS_NET_TLS_STREAM_H

#include <cstddef>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "core/net/byte_stream.h"
#include "core/net/endpoint.h"
#include "platform/windows/net/cancel.h"
#include "platform/windows/net/tcp_stream.h"
#include "platform/windows/net/tls_credentials.h"
#include "platform/windows/net/win_security.h"

namespace crimson::net::win {

struct TlsOptions {
    // The server's DNS name, exactly as configured. It is sent as SNI and the
    // certificate is checked against it, so it must be a name, never an
    // address: a certificate issued for imap.example.com is not valid for
    // 203.0.113.7, and failing that check is correct.
    std::string hostname;
};

// Non-sensitive facts about a negotiated session, for diagnostics.
struct TlsInfo {
    std::string protocol;             // "TLS 1.3"
    std::string cipher_suite;         // "TLS_AES_256_GCM_SHA384"
    std::string certificate_subject;  // the server certificate's display name
    std::string certificate_issuer;

    // The peer ended the TCP connection on a record boundary without sending
    // close_notify. Reported as end of stream, because a great many real
    // servers do exactly this, but recorded because it is also what a
    // truncation attack looks like.
    bool closed_without_notify = false;

    // Post-handshake messages processed. Under TLS 1.3, Schannel surfaces a
    // server's NewSessionTicket as SEC_I_RENEGOTIATE, so this is usually
    // non-zero on TLS 1.3 and does not mean a TLS 1.2 renegotiation happened.
    std::size_t post_handshake_messages = 0;
};

// TLS over any ByteStream, using Schannel.
//
// This is the Step 1 seam being tested: TlsStream IS a ByteStream and HOLDS a
// ByteStream, so protocol code above cannot tell whether it is talking through
// TLS, and TcpStream below does not know it is being wrapped. Nothing in the
// transport layer changed to make this possible.
//
// Holding a unique_ptr<ByteStream> rather than a TcpStream member is what lets
// the record layer be tested against a fragmenting interposer — every read
// delivering one byte — without a TLS server of Crimson's own.
//
// Certificate validation is delegated entirely to Schannel; see TlsCredentials
// and ADR 0011.
//
// THREADING. As TcpStream: one owning thread. A CancelHandle passed to
// connect() interrupts the underlying TCP reads and writes.
class TlsStream final : public ByteStream {
public:
    // Negotiates TLS over an already-connected stream.
    //
    // This is the primitive, and it has to be: IMAP on port 143 and SMTP on
    // 587 begin in plaintext and upgrade the same connection after STARTTLS,
    // so the TLS layer must be able to adopt a stream that already exists.
    [[nodiscard]] static std::expected<TlsStream, NetError> wrap(
        std::unique_ptr<ByteStream> inner, const TlsCredentials& credentials,
        const TlsOptions& options);

    // Resolves, connects over TCP and negotiates TLS, for implicit-TLS ports
    // such as IMAP on 993 and SMTP on 465. The endpoint's host is used as the
    // TLS hostname.
    [[nodiscard]] static std::expected<TlsStream, NetError> connect(
        const Endpoint& endpoint, const TlsCredentials& credentials,
        const ConnectOptions& options = {}, const CancelHandle& cancel = {});

    ~TlsStream() override;

    TlsStream(TlsStream&& other) noexcept;
    TlsStream& operator=(TlsStream&& other) noexcept;

    // ByteStream. read() can return bytes and end of stream together, which is
    // exactly what Schannel produces when the final record and close_notify
    // arrive in one buffer.
    [[nodiscard]] ReadOutcome read(std::span<std::byte> dst) noexcept override;

    // Encrypts at most one record's worth and sends the whole record. A TLS
    // record must reach the wire atomically — a partly written record
    // desynchronises the peer for good — so the record goes out with
    // write_all even though this call itself may accept fewer bytes than
    // offered. Returns the plaintext count consumed.
    [[nodiscard]] WriteOutcome write_some(std::span<const std::byte> src) noexcept override;

    // Sends close_notify, then half-closes the underlying stream.
    [[nodiscard]] VoidOutcome shutdown_send() noexcept override;

    void close() noexcept override;

    [[nodiscard]] const TlsInfo& info() const noexcept { return info_; }

    // Where the TCP connection landed. Filled in by connect(); empty after
    // wrap(), which never sees the socket.
    [[nodiscard]] const PeerAddress& peer() const noexcept { return peer_; }

private:
    TlsStream(std::unique_ptr<ByteStream> inner, TlsCredentials credentials,
              std::wstring target, std::string hostname);

    [[nodiscard]] VoidOutcome negotiate(bool continuing) noexcept;
    [[nodiscard]] VoidOutcome finish_handshake() noexcept;
    [[nodiscard]] VoidOutcome send_token(const SecBuffer& token) noexcept;

    // Reads more ciphertext from the inner stream. Keeps reading until
    // `need_` bytes have arrived, so an inner stream that delivers one byte at
    // a time does not cost one Schannel call per byte.
    [[nodiscard]] VoidOutcome fill_incoming(NetOp op) noexcept;
    [[nodiscard]] bool ensure_incoming_space(std::size_t bytes) noexcept;
    void keep_extra(const SecBuffer* extra) noexcept;

    std::unique_ptr<ByteStream> inner_;
    TlsCredentials credentials_;
    std::wstring target_;
    std::string hostname_;

    CtxtHandle context_{};
    bool has_context_ = false;
    SecPkgContext_StreamSizes sizes_{};

    // Ciphertext received but not yet decrypted: possibly a partial record,
    // possibly several records.
    std::vector<std::byte> incoming_;
    std::size_t incoming_used_ = 0;
    std::size_t need_ = 0;

    // Plaintext decrypted but not yet handed to the caller.
    std::vector<std::byte> plaintext_;
    std::size_t plaintext_used_ = 0;
    std::size_t plaintext_offset_ = 0;

    // One record's worth, allocated once at the end of the handshake so the
    // write path never allocates.
    std::vector<std::byte> outgoing_;

    bool inner_eof_ = false;
    bool peer_closed_ = false;
    bool shutdown_sent_ = false;

    TlsInfo info_;
    PeerAddress peer_;
};

namespace detail {

// The name Schannel should verify and send as SNI: brackets stripped from an
// IPv6 literal, and an internationalised name converted to its ASCII
// ("xn--") form, which is how certificates list such names. Without the
// conversion, "müller.de" would resolve — GetAddrInfoW converts it — and then
// fail certificate validation.
[[nodiscard]] std::expected<std::wstring, NetError> tls_target_name(std::string_view host);

}  // namespace detail

}  // namespace crimson::net::win

#endif  // CRIMSON_PLATFORM_WINDOWS_NET_TLS_STREAM_H
