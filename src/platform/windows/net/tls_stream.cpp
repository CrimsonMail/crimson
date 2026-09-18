// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "platform/windows/net/tls_stream.h"

#include "core/net/stream_helpers.h"
#include "platform/windows/net/net_log.h"
#include "platform/windows/net/sspi_error.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <utility>

namespace crimson::net::win {

namespace {

// Room for one maximum-size TLS record (2^14 bytes of payload plus header,
// padding and authentication tag) with margin. Reads from the inner stream are
// made in chunks of this size.
constexpr std::size_t kReadChunk = 17 * 1024;

// Upper bound on ciphertext held while waiting for a record or handshake
// message to complete. A server certificate chain can span several records,
// so this is generous, but it is finite: a peer that streams an endless
// "incomplete" message must not be able to grow the buffer without limit. Email
// is hostile input, and so is the transport it arrives on.
constexpr std::size_t kMaxIncoming = 256 * 1024;

constexpr ULONG kContextRequest = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                                  ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
                                  ISC_REQ_STREAM;

// Frees output buffers Schannel allocated because of ISC_REQ_ALLOCATE_MEMORY,
// on every path including errors.
class ContextBufferGuard {
public:
    explicit ContextBufferGuard(SecBuffer& buffer) noexcept : buffer_(buffer) {}
    ~ContextBufferGuard() {
        if (buffer_.pvBuffer != nullptr) {
            ::FreeContextBuffer(buffer_.pvBuffer);
            buffer_.pvBuffer = nullptr;
        }
    }
    ContextBufferGuard(const ContextBufferGuard&) = delete;
    ContextBufferGuard& operator=(const ContextBufferGuard&) = delete;

private:
    SecBuffer& buffer_;
};

[[nodiscard]] std::string to_utf8(const wchar_t* wide) {
    if (wide == nullptr || wide[0] == L'\0') {
        return {};
    }
    const int needed = ::WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) {
        return {};
    }
    std::string out(static_cast<std::size_t>(needed - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

[[nodiscard]] std::string protocol_name(DWORD protocol) {
    if (protocol & SP_PROT_TLS1_3_CLIENT) return "TLS 1.3";
    if (protocol & SP_PROT_TLS1_2_CLIENT) return "TLS 1.2";
    if (protocol & SP_PROT_TLS1_1_CLIENT) return "TLS 1.1";
    if (protocol & SP_PROT_TLS1_0_CLIENT) return "TLS 1.0";
    return "unknown";
}

[[nodiscard]] SecBuffer* find_buffer(SecBuffer* buffers, std::size_t count, ULONG type) noexcept {
    for (std::size_t index = 0; index < count; ++index) {
        if (buffers[index].BufferType == type) {
            return &buffers[index];
        }
    }
    return nullptr;
}

}  // namespace

namespace detail {

std::expected<std::wstring, NetError> tls_target_name(std::string_view host) {
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    if (host.empty()) {
        return std::unexpected(NetError::logic(NetOp::tls_handshake));
    }

    const int wide_length = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, host.data(), static_cast<int>(host.size()), nullptr, 0);
    if (wide_length <= 0) {
        return std::unexpected(NetError::logic(NetOp::tls_handshake));
    }
    std::wstring wide(static_cast<std::size_t>(wide_length), L'\0');
    ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host.data(),
                          static_cast<int>(host.size()), wide.data(), wide_length);

    const bool ascii = std::all_of(wide.begin(), wide.end(), [](wchar_t c) { return c < 0x80; });
    if (ascii) {
        return wide;
    }

    // Certificates carry internationalised names in their ASCII-compatible
    // ("xn--") form, so that is the form to verify against and send as SNI.
    const int ascii_length = ::IdnToAscii(0, wide.data(), static_cast<int>(wide.size()), nullptr, 0);
    if (ascii_length <= 0) {
        return std::unexpected(NetError::logic(NetOp::tls_handshake));
    }
    std::wstring converted(static_cast<std::size_t>(ascii_length), L'\0');
    if (::IdnToAscii(0, wide.data(), static_cast<int>(wide.size()), converted.data(),
                     ascii_length) <= 0) {
        return std::unexpected(NetError::logic(NetOp::tls_handshake));
    }
    return converted;
}

}  // namespace detail

TlsStream::TlsStream(std::unique_ptr<ByteStream> inner, TlsCredentials credentials,
                     std::wstring target, std::string hostname)
    : inner_(std::move(inner)),
      credentials_(std::move(credentials)),
      target_(std::move(target)),
      hostname_(std::move(hostname)) {
    SecInvalidateHandle(&context_);
    // Allocated up front so the buffer's data() is never null, which Schannel
    // needs even for an empty input token.
    incoming_.resize(kReadChunk);
}

TlsStream::~TlsStream() { close(); }

TlsStream::TlsStream(TlsStream&& other) noexcept
    : ByteStream(std::move(other)),
      inner_(std::move(other.inner_)),
      credentials_(std::move(other.credentials_)),
      target_(std::move(other.target_)),
      hostname_(std::move(other.hostname_)),
      context_(other.context_),
      has_context_(std::exchange(other.has_context_, false)),
      sizes_(other.sizes_),
      incoming_(std::move(other.incoming_)),
      incoming_used_(std::exchange(other.incoming_used_, 0)),
      need_(std::exchange(other.need_, 0)),
      plaintext_(std::move(other.plaintext_)),
      plaintext_used_(std::exchange(other.plaintext_used_, 0)),
      plaintext_offset_(std::exchange(other.plaintext_offset_, 0)),
      outgoing_(std::move(other.outgoing_)),
      inner_eof_(other.inner_eof_),
      peer_closed_(other.peer_closed_),
      shutdown_sent_(other.shutdown_sent_),
      info_(std::move(other.info_)),
      peer_(std::move(other.peer_)) {
    SecInvalidateHandle(&other.context_);
}

TlsStream& TlsStream::operator=(TlsStream&& other) noexcept {
    if (this != &other) {
        close();  // releasing the current session first is what stops a leak
        ByteStream::operator=(std::move(other));
        inner_ = std::move(other.inner_);
        credentials_ = std::move(other.credentials_);
        target_ = std::move(other.target_);
        hostname_ = std::move(other.hostname_);
        context_ = other.context_;
        has_context_ = std::exchange(other.has_context_, false);
        SecInvalidateHandle(&other.context_);
        sizes_ = other.sizes_;
        incoming_ = std::move(other.incoming_);
        incoming_used_ = std::exchange(other.incoming_used_, 0);
        need_ = std::exchange(other.need_, 0);
        plaintext_ = std::move(other.plaintext_);
        plaintext_used_ = std::exchange(other.plaintext_used_, 0);
        plaintext_offset_ = std::exchange(other.plaintext_offset_, 0);
        outgoing_ = std::move(other.outgoing_);
        inner_eof_ = other.inner_eof_;
        peer_closed_ = other.peer_closed_;
        shutdown_sent_ = other.shutdown_sent_;
        info_ = std::move(other.info_);
        peer_ = std::move(other.peer_);
    }
    return *this;
}

std::expected<TlsStream, NetError> TlsStream::wrap(std::unique_ptr<ByteStream> inner,
                                                   const TlsCredentials& credentials,
                                                   const TlsOptions& options) {
    if (!inner || !credentials.valid() || options.hostname.empty()) {
        return std::unexpected(NetError::logic(NetOp::tls_handshake));
    }

    auto target = detail::tls_target_name(options.hostname);
    if (!target) {
        return std::unexpected(target.error());
    }

    const auto started = std::chrono::steady_clock::now();
    TlsStream stream{std::move(inner), credentials, std::move(*target), options.hostname};

    if (auto negotiated = stream.negotiate(false); !negotiated) {
        log_event(LogLevel::warn, "tls_handshake_failed",
                  {{"host", options.hostname},
                   {"code", error_name(negotiated.error())},
                   {"certificate_problem", is_certificate_error(negotiated.error()) ? "yes" : "no"}});
        return std::unexpected(negotiated.error());
    }
    if (auto finished = stream.finish_handshake(); !finished) {
        return std::unexpected(finished.error());
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    log_event(LogLevel::info, "tls_connected",
              {{"host", options.hostname},
               {"protocol", stream.info_.protocol},
               {"cipher", stream.info_.cipher_suite},
               {"subject", stream.info_.certificate_subject},
               {"elapsed_ms", std::to_string(elapsed.count())}});

    return stream;
}

std::expected<TlsStream, NetError> TlsStream::connect(const Endpoint& endpoint,
                                                      const TlsCredentials& credentials,
                                                      const ConnectOptions& options,
                                                      const CancelHandle& cancel) {
    auto tcp = TcpStream::connect(endpoint, options, cancel);
    if (!tcp) {
        return std::unexpected(tcp.error());
    }
    const PeerAddress peer = tcp->peer();

    auto tls = wrap(std::make_unique<TcpStream>(std::move(*tcp)), credentials,
                    TlsOptions{endpoint.host});
    if (!tls) {
        return std::unexpected(tls.error());
    }
    tls->peer_ = peer;
    return tls;
}

VoidOutcome TlsStream::send_token(const SecBuffer& token) noexcept {
    // SEC_I_CONTINUE_NEEDED can arrive with an empty token. Writing zero
    // bytes is at best pointless and at worst read as a closed connection.
    if (token.pvBuffer == nullptr || token.cbBuffer == 0) {
        return {};
    }
    return write_all(*inner_, std::span{static_cast<const std::byte*>(token.pvBuffer),
                                        static_cast<std::size_t>(token.cbBuffer)});
}

bool TlsStream::ensure_incoming_space(std::size_t bytes) noexcept {
    if (incoming_.size() - incoming_used_ >= bytes) {
        return true;
    }
    const std::size_t wanted = incoming_used_ + bytes;
    if (wanted > kMaxIncoming) {
        return false;
    }
    try {
        incoming_.resize(std::max(wanted, std::min(incoming_.size() * 2, kMaxIncoming)));
    } catch (const std::bad_alloc&) {
        return false;
    }
    return true;
}

VoidOutcome TlsStream::fill_incoming(NetOp op) noexcept {
    std::size_t want = std::max<std::size_t>(need_, 1);
    need_ = 0;

    while (want > 0) {
        if (!ensure_incoming_space(std::min(kReadChunk, kMaxIncoming))) {
            // A record or handshake message larger than any legitimate one.
            return std::unexpected(NetError::logic(op));
        }
        const std::size_t room = incoming_.size() - incoming_used_;
        const ReadOutcome result =
            inner_->read(std::span{incoming_}.subspan(incoming_used_, room));
        if (!result) {
            return std::unexpected(result.error());
        }
        incoming_used_ += result->bytes;
        want -= std::min(want, result->bytes);
        if (result->eof) {
            inner_eof_ = true;
            break;
        }
    }
    return {};
}

void TlsStream::keep_extra(const SecBuffer* extra) noexcept {
    // SECBUFFER_EXTRA is the tail of the input that Schannel did not consume:
    // the start of the next record, or after the final handshake message, the
    // first application data. Discarding it loses data; for IMAP that is the
    // server's greeting, the very first thing it sends.
    if (extra != nullptr && extra->cbBuffer > 0 && extra->cbBuffer <= incoming_used_) {
        std::memmove(incoming_.data(), incoming_.data() + (incoming_used_ - extra->cbBuffer),
                     extra->cbBuffer);
        incoming_used_ = extra->cbBuffer;
    } else {
        incoming_used_ = 0;
    }
}

VoidOutcome TlsStream::negotiate(bool continuing) noexcept {
    ULONG attributes = 0;
    SECURITY_STATUS status = SEC_I_CONTINUE_NEEDED;
    bool need_input = false;

    if (!continuing) {
        // The first call passes no context and no input, and creates the
        // context. Every later call passes &context_. Mixing those up is the
        // classic Schannel mistake and yields a handshake that never ends.
        SecBuffer out{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out};
        const ContextBufferGuard guard{out};

        status = ::InitializeSecurityContextW(
            credentials_.handle(), nullptr, target_.data(), kContextRequest, 0, 0, nullptr, 0,
            &context_, &out_desc, &attributes, nullptr);
        if (status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK) {
            return std::unexpected(from_sspi(NetOp::tls_handshake, status));
        }
        has_context_ = true;

        if (auto sent = send_token(out); !sent) {
            return std::unexpected(sent.error());
        }
        if (status == SEC_E_OK) {
            return {};
        }
        need_input = true;  // the server has to answer before anything else can happen
    }

    for (;;) {
        if (need_input) {
            if (inner_eof_) {
                // The server closed mid-handshake. Often a server rejecting
                // every protocol Crimson offers does exactly this.
                return std::unexpected(NetError::truncated(NetOp::tls_handshake));
            }
            if (auto filled = fill_incoming(NetOp::tls_handshake); !filled) {
                return std::unexpected(filled.error());
            }
            need_input = false;
        }

        SecBuffer in[2] = {
            {static_cast<ULONG>(incoming_used_), SECBUFFER_TOKEN, incoming_.data()},
            {0, SECBUFFER_EMPTY, nullptr},
        };
        SecBufferDesc in_desc{SECBUFFER_VERSION, 2, in};
        SecBuffer out{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out};
        const ContextBufferGuard guard{out};

        status = ::InitializeSecurityContextW(
            credentials_.handle(), &context_, target_.data(), kContextRequest, 0, 0, &in_desc, 0,
            &context_, &out_desc, &attributes, nullptr);

        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            // Keep what has arrived and read more. SECBUFFER_MISSING, when
            // present, says how much more, which avoids re-parsing the same
            // partial message once per byte.
            const SecBuffer* missing = find_buffer(in, 2, SECBUFFER_MISSING);
            need_ = (missing != nullptr && missing->cbBuffer > 0) ? missing->cbBuffer : 1;
            need_input = true;
            continue;
        }

        if (FAILED(status)) {
            return std::unexpected(from_sspi(NetOp::tls_handshake, status));
        }

        if (auto sent = send_token(out); !sent) {
            return std::unexpected(sent.error());
        }
        keep_extra(find_buffer(in, 2, SECBUFFER_EXTRA));

        if (status == SEC_E_OK) {
            return {};
        }
        if (status == SEC_I_CONTINUE_NEEDED || status == SEC_I_INCOMPLETE_CREDENTIALS) {
            // INCOMPLETE_CREDENTIALS means the server asked for a client
            // certificate. Crimson never presents one, so carry on without.
            need_input = incoming_used_ == 0;
            continue;
        }
        return std::unexpected(from_sspi(NetOp::tls_handshake, status));
    }
}

VoidOutcome TlsStream::finish_handshake() noexcept {
    if (::QueryContextAttributesW(&context_, SECPKG_ATTR_STREAM_SIZES, &sizes_) != SEC_E_OK ||
        sizes_.cbMaximumMessage == 0) {
        return std::unexpected(NetError::logic(NetOp::tls_handshake));
    }

    SecPkgContext_ConnectionInfo connection{};
    if (::QueryContextAttributesW(&context_, SECPKG_ATTR_CONNECTION_INFO, &connection) == SEC_E_OK) {
        info_.protocol = protocol_name(connection.dwProtocol);
        // Defence in depth. The credential already disables everything below
        // TLS 1.2, so this can only fire if that policy is ever weakened by
        // mistake.
        if ((connection.dwProtocol & (SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT)) == 0) {
            return std::unexpected(from_sspi(NetOp::tls_handshake, SEC_E_ALGORITHM_MISMATCH));
        }
    }

    SecPkgContext_CipherInfo cipher{};
    cipher.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
    if (::QueryContextAttributesW(&context_, SECPKG_ATTR_CIPHER_INFO, &cipher) == SEC_E_OK) {
        try {
            info_.cipher_suite = to_utf8(cipher.szCipherSuite);
        } catch (const std::bad_alloc&) {
        }
    }

    PCCERT_CONTEXT certificate = nullptr;
    if (::QueryContextAttributesW(&context_, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &certificate) ==
            SEC_E_OK &&
        certificate != nullptr) {
        wchar_t name[256] = {};
        try {
            if (::CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name,
                                     256) > 1) {
                info_.certificate_subject = to_utf8(name);
            }
            if (::CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                     CERT_NAME_ISSUER_FLAG, nullptr, name, 256) > 1) {
                info_.certificate_issuer = to_utf8(name);
            }
        } catch (const std::bad_alloc&) {
        }
        ::CertFreeCertificateContext(certificate);
    }

    try {
        outgoing_.resize(static_cast<std::size_t>(sizes_.cbHeader) + sizes_.cbMaximumMessage +
                         sizes_.cbTrailer);
        plaintext_.resize(sizes_.cbMaximumMessage);
    } catch (const std::bad_alloc&) {
        return std::unexpected(NetError::logic(NetOp::tls_handshake));
    }
    return {};
}

ReadOutcome TlsStream::read(std::span<std::byte> dst) noexcept {
    if (!has_context_ || !inner_) {
        return std::unexpected(NetError::logic(NetOp::tls_decrypt));
    }
    if (dst.empty()) {
        return ReadResult{0, false};
    }

    for (;;) {
        // Hand over whatever is already decrypted first. When close_notify
        // arrived together with the final data, the end of stream is reported
        // alongside the last bytes rather than costing another call.
        if (plaintext_offset_ < plaintext_used_) {
            const std::size_t count = std::min(dst.size(), plaintext_used_ - plaintext_offset_);
            std::memcpy(dst.data(), plaintext_.data() + plaintext_offset_, count);
            plaintext_offset_ += count;
            return ReadResult{count, peer_closed_ && plaintext_offset_ == plaintext_used_};
        }
        if (peer_closed_) {
            return ReadResult{0, true};
        }

        if (incoming_used_ > 0 && need_ == 0) {
            SecBuffer buffers[4] = {
                {static_cast<ULONG>(incoming_used_), SECBUFFER_DATA, incoming_.data()},
                {0, SECBUFFER_EMPTY, nullptr},
                {0, SECBUFFER_EMPTY, nullptr},
                {0, SECBUFFER_EMPTY, nullptr},
            };
            SecBufferDesc desc{SECBUFFER_VERSION, 4, buffers};
            const SECURITY_STATUS status = ::DecryptMessage(&context_, &desc, 0, nullptr);

            if (status == SEC_E_INCOMPLETE_MESSAGE) {
                if (inner_eof_) {
                    // The connection ended part-way through a record: data
                    // was cut off, not finished.
                    return std::unexpected(NetError::truncated(NetOp::tls_decrypt));
                }
                const SecBuffer* missing = find_buffer(buffers, 4, SECBUFFER_MISSING);
                need_ = (missing != nullptr && missing->cbBuffer > 0) ? missing->cbBuffer : 1;
            } else if (status == SEC_E_OK || status == SEC_I_CONTEXT_EXPIRED ||
                       status == SEC_I_RENEGOTIATE) {
                // Decryption is in place, so the plaintext and any extra
                // ciphertext both live inside incoming_. Copy the plaintext out
                // before moving the extra bytes down over it.
                const SecBuffer* data = find_buffer(buffers, 4, SECBUFFER_DATA);
                plaintext_used_ = 0;
                plaintext_offset_ = 0;
                if (data != nullptr && data->cbBuffer > 0) {
                    if (data->cbBuffer > plaintext_.size()) {
                        try {
                            plaintext_.resize(data->cbBuffer);
                        } catch (const std::bad_alloc&) {
                            return std::unexpected(NetError::logic(NetOp::tls_decrypt));
                        }
                    }
                    std::memcpy(plaintext_.data(), data->pvBuffer, data->cbBuffer);
                    plaintext_used_ = data->cbBuffer;
                }
                keep_extra(find_buffer(buffers, 4, SECBUFFER_EXTRA));

                if (status == SEC_I_CONTEXT_EXPIRED) {
                    peer_closed_ = true;  // close_notify
                } else if (status == SEC_I_RENEGOTIATE) {
                    // A post-handshake message. Under TLS 1.3 this is how
                    // Schannel surfaces a NewSessionTicket, so it is routine,
                    // not the TLS 1.2 renegotiation the name suggests. The
                    // handshake machinery consumes it from the extra bytes.
                    ++info_.post_handshake_messages;
                    if (auto renegotiated = negotiate(true); !renegotiated) {
                        return std::unexpected(renegotiated.error());
                    }
                }
                continue;
            } else {
                return std::unexpected(from_sspi(NetOp::tls_decrypt, status));
            }
        }

        if (inner_eof_) {
            if (incoming_used_ == 0) {
                // TCP ended cleanly on a record boundary, but without
                // close_notify. Reported as end of stream — many servers do
                // this — and recorded, since it is also what truncation
                // looks like.
                info_.closed_without_notify = true;
                peer_closed_ = true;
                log_event(LogLevel::warn, "tls_closed_without_notify", {{"host", hostname_}});
                return ReadResult{0, true};
            }
            return std::unexpected(NetError::truncated(NetOp::tls_decrypt));
        }

        if (auto filled = fill_incoming(NetOp::tls_decrypt); !filled) {
            return std::unexpected(filled.error());
        }
    }
}

WriteOutcome TlsStream::write_some(std::span<const std::byte> src) noexcept {
    if (!has_context_ || !inner_ || shutdown_sent_ || outgoing_.empty()) {
        return std::unexpected(NetError::logic(NetOp::tls_encrypt));
    }
    if (src.empty()) {
        return std::size_t{0};
    }

    const std::size_t chunk = std::min<std::size_t>(src.size(), sizes_.cbMaximumMessage);
    std::byte* record = outgoing_.data();
    std::memcpy(record + sizes_.cbHeader, src.data(), chunk);

    SecBuffer buffers[4] = {
        {sizes_.cbHeader, SECBUFFER_STREAM_HEADER, record},
        {static_cast<ULONG>(chunk), SECBUFFER_DATA, record + sizes_.cbHeader},
        {sizes_.cbTrailer, SECBUFFER_STREAM_TRAILER, record + sizes_.cbHeader + chunk},
        {0, SECBUFFER_EMPTY, nullptr},
    };
    SecBufferDesc desc{SECBUFFER_VERSION, 4, buffers};

    const SECURITY_STATUS status = ::EncryptMessage(&context_, 0, &desc, 0);
    if (status != SEC_E_OK) {
        return std::unexpected(from_sspi(NetOp::tls_encrypt, status));
    }

    // The trailer may come back shorter than cbTrailer, so the record's real
    // length is read from the buffers rather than assumed.
    const std::size_t total = static_cast<std::size_t>(buffers[0].cbBuffer) +
                              buffers[1].cbBuffer + buffers[2].cbBuffer;
    if (auto sent = write_all(*inner_, std::span{record, total}); !sent) {
        return std::unexpected(sent.error());
    }
    return chunk;
}

VoidOutcome TlsStream::shutdown_send() noexcept {
    if (!has_context_ || !inner_) {
        return std::unexpected(NetError::logic(NetOp::tls_shutdown));
    }
    if (shutdown_sent_) {
        return {};
    }

    // Ask Schannel for close_notify: apply the shutdown token, then run the
    // context once more to produce the alert record.
    DWORD shutdown_type = SCHANNEL_SHUTDOWN;
    SecBuffer control{sizeof(shutdown_type), SECBUFFER_TOKEN, &shutdown_type};
    SecBufferDesc control_desc{SECBUFFER_VERSION, 1, &control};
    SECURITY_STATUS status = ::ApplyControlToken(&context_, &control_desc);
    if (FAILED(status)) {
        return std::unexpected(from_sspi(NetOp::tls_shutdown, status));
    }

    SecBuffer out{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out};
    const ContextBufferGuard guard{out};
    ULONG attributes = 0;
    status = ::InitializeSecurityContextW(credentials_.handle(), &context_, target_.data(),
                                          kContextRequest, 0, 0, nullptr, 0, &context_,
                                          &out_desc, &attributes, nullptr);
    if (FAILED(status)) {
        return std::unexpected(from_sspi(NetOp::tls_shutdown, status));
    }
    if (auto sent = send_token(out); !sent) {
        return std::unexpected(sent.error());
    }

    shutdown_sent_ = true;
    return inner_->shutdown_send();
}

void TlsStream::close() noexcept {
    if (has_context_) {
        ::DeleteSecurityContext(&context_);
        SecInvalidateHandle(&context_);
        has_context_ = false;
    }
    if (inner_) {
        inner_->close();
    }
}

}  // namespace crimson::net::win
