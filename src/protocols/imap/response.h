// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_PROTOCOLS_IMAP_RESPONSE_H
#define CRIMSON_PROTOCOLS_IMAP_RESPONSE_H

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace crimson::imap {

// IMAP keywords are case-insensitive: "ok", "OK" and "Ok" are one keyword, and
// so are \Seen and \seen.
[[nodiscard]] bool equals_ignore_case(std::string_view left, std::string_view right) noexcept;

// A message's flags. The system flags are named because code asks about them
// constantly; anything else a server invents is a keyword, kept as sent.
struct Flags {
    bool seen = false;
    bool answered = false;
    bool flagged = false;
    bool deleted = false;
    bool draft = false;
    bool recent = false;

    // \* in PERMANENTFLAGS: the server allows keywords it has not seen yet.
    bool accepts_new_keywords = false;

    std::vector<std::string> keywords;

    [[nodiscard]] bool has(std::string_view flag) const noexcept;
};

// One address from an envelope, in the four parts RFC 9051 sends.
//
// A group is expressed as two entries: a start, with a mailbox but no host,
// and an end, with neither. Keeping them means a To: header that said
// "Developers: alice@example.com, bob@example.com;" still says so afterwards.
struct Address {
    std::string name;     // display name, if any
    std::string route;    // the obsolete source route; kept for fidelity
    std::string mailbox;  // the local part
    std::string host;     // the domain

    [[nodiscard]] bool is_group_start() const noexcept { return host.empty() && !mailbox.empty(); }
    [[nodiscard]] bool is_group_end() const noexcept { return host.empty() && mailbox.empty(); }
};

// The envelope: the server's own parse of the message's main headers.
//
// The strings are exactly what the server sent. Crimson does not trust them to
// be well formed, does not decode encoded-words here, and will parse dates and
// addresses itself from the original headers in Step 6 — the envelope is a
// convenience for listing messages, not a replacement for the message.
struct Envelope {
    std::string date;
    std::string subject;
    std::vector<Address> from;
    std::vector<Address> sender;
    std::vector<Address> reply_to;
    std::vector<Address> to;
    std::vector<Address> cc;
    std::vector<Address> bcc;
    std::string in_reply_to;
    std::string message_id;
};

// One BODY[...] or BINARY[...] part of a FETCH response.
struct BodySection {
    std::string specifier;                  // "", "HEADER", "1.2", "HEADER.FIELDS (SUBJECT)"
    std::optional<std::uint32_t> origin;    // the <n> of a partial fetch
    std::uint64_t size = 0;                 // bytes the server sent
    std::string content;                    // empty when streamed
    bool streamed = false;                  // content went to the sink instead
    bool binary = false;                    // arrived as a literal8
};

struct FetchResponse {
    std::uint32_t sequence = 0;
    std::optional<std::uint32_t> uid;
    std::optional<Flags> flags;
    std::optional<std::chrono::sys_seconds> internal_date;
    std::optional<std::uint32_t> size;          // RFC822.SIZE
    std::optional<Envelope> envelope;
    std::optional<std::uint64_t> mod_sequence;  // CONDSTORE
    std::vector<BodySection> sections;

    // Data items Crimson does not know, such as X-GM-LABELS. Named so a
    // future step can see what servers are offering without a code change.
    std::vector<std::string> unknown_items;
};

// One line of a LIST or LSUB response.
struct MailboxListing {
    std::vector<std::string> attributes;   // \HasChildren, \Noselect, \Sent, ...
    std::optional<char> delimiter;         // NIL means a flat namespace
    std::string name;

    [[nodiscard]] bool has_attribute(std::string_view attribute) const noexcept;
};

// A STATUS response.
struct MailboxStatus {
    std::string mailbox;
    std::optional<std::uint32_t> messages;
    std::optional<std::uint32_t> recent;
    std::optional<std::uint32_t> uid_next;
    std::optional<std::uint32_t> uid_validity;
    std::optional<std::uint32_t> unseen;
    std::optional<std::uint64_t> highest_mod_sequence;
    std::optional<std::uint64_t> size;
};

struct SearchResults {
    std::vector<std::uint32_t> numbers;         // sequence numbers, or UIDs after UID SEARCH
    std::optional<std::uint64_t> mod_sequence;  // CONDSTORE's trailing MODSEQ
};

struct Capabilities {
    std::vector<std::string> names;

    [[nodiscard]] bool has(std::string_view capability) const noexcept;
};

// * FLAGS (\Answered \Seen ...): the flags this mailbox can hold.
struct MailboxFlags {
    Flags flags;
};

// * 172 EXISTS, * 1 RECENT, * 44 EXPUNGE — one shape, three meanings.
struct MailboxCount {
    enum class Kind : std::uint8_t { exists, recent, expunge };

    Kind kind = Kind::exists;
    std::uint32_t number = 0;
};

enum class StatusKind : std::uint8_t { ok, no, bad, preauth, bye };

enum class ResponseCodeKind : std::uint8_t {
    none,
    alert,
    badcharset,
    capability,
    parse,
    permanent_flags,
    read_only,
    read_write,
    try_create,
    uid_next,
    uid_validity,
    unseen,
    highest_mod_sequence,
    no_mod_sequence,
    append_uid,
    copy_uid,
    closed,
    other,  // a code Crimson does not know; `name` and `arguments` hold it
};

// The [SQUARE BRACKETED] part of a status response.
struct ResponseCode {
    ResponseCodeKind kind = ResponseCodeKind::none;
    std::string name;                        // as sent
    std::vector<std::string> arguments;      // the raw arguments, whatever the code
    std::optional<std::uint64_t> number;     // UIDNEXT, UIDVALIDITY, UNSEEN, HIGHESTMODSEQ
    std::optional<Flags> flags;              // PERMANENTFLAGS
    std::optional<Capabilities> capabilities;
};

// OK, NO, BAD, PREAUTH or BYE, with its optional code and its human text.
struct StatusResponse {
    StatusKind kind = StatusKind::ok;
    ResponseCode code;
    std::string text;
};

// A response Crimson does not recognise. Never an error: servers send
// extensions all the time, and one unknown line must not end a session.
struct UnknownResponse {
    std::string name;
    std::string text;  // the rest of the line, as sent
};

using UntaggedBody = std::variant<StatusResponse, Capabilities, MailboxListing, MailboxStatus,
                                  SearchResults, FetchResponse, MailboxCount, MailboxFlags,
                                  UnknownResponse>;

struct UntaggedResponse {
    UntaggedBody body;
};

// The end of a command: its tag, and how it went.
struct TaggedResponse {
    std::string tag;
    StatusResponse status;
};

// "+ ...": the server is ready for the rest of a command.
struct ContinuationRequest {
    std::string text;
};

using Response = std::variant<TaggedResponse, UntaggedResponse, ContinuationRequest>;

[[nodiscard]] constexpr std::string_view to_string(StatusKind kind) noexcept {
    switch (kind) {
        case StatusKind::ok:      return "OK";
        case StatusKind::no:      return "NO";
        case StatusKind::bad:     return "BAD";
        case StatusKind::preauth: return "PREAUTH";
        case StatusKind::bye:     return "BYE";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view to_string(ResponseCodeKind kind) noexcept {
    switch (kind) {
        case ResponseCodeKind::none:                 return "none";
        case ResponseCodeKind::alert:                return "ALERT";
        case ResponseCodeKind::badcharset:           return "BADCHARSET";
        case ResponseCodeKind::capability:           return "CAPABILITY";
        case ResponseCodeKind::parse:                return "PARSE";
        case ResponseCodeKind::permanent_flags:      return "PERMANENTFLAGS";
        case ResponseCodeKind::read_only:            return "READ-ONLY";
        case ResponseCodeKind::read_write:           return "READ-WRITE";
        case ResponseCodeKind::try_create:           return "TRYCREATE";
        case ResponseCodeKind::uid_next:             return "UIDNEXT";
        case ResponseCodeKind::uid_validity:         return "UIDVALIDITY";
        case ResponseCodeKind::unseen:               return "UNSEEN";
        case ResponseCodeKind::highest_mod_sequence: return "HIGHESTMODSEQ";
        case ResponseCodeKind::no_mod_sequence:      return "NOMODSEQ";
        case ResponseCodeKind::append_uid:           return "APPENDUID";
        case ResponseCodeKind::copy_uid:             return "COPYUID";
        case ResponseCodeKind::closed:               return "CLOSED";
        case ResponseCodeKind::other:                return "other";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view to_string(MailboxCount::Kind kind) noexcept {
    switch (kind) {
        case MailboxCount::Kind::exists:  return "EXISTS";
        case MailboxCount::Kind::recent:  return "RECENT";
        case MailboxCount::Kind::expunge: return "EXPUNGE";
    }
    return "unknown";
}

}  // namespace crimson::imap

#endif  // CRIMSON_PROTOCOLS_IMAP_RESPONSE_H
