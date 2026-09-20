// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "protocols/imap/response.h"

#include <algorithm>

namespace crimson::imap {

namespace {

[[nodiscard]] constexpr char upper(char c) noexcept {
    return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
}

}  // namespace

bool equals_ignore_case(std::string_view left, std::string_view right) noexcept {
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin(),
                      [](char a, char b) { return upper(a) == upper(b); });
}

bool Flags::has(std::string_view flag) const noexcept {
    if (equals_ignore_case(flag, "\\Seen")) {
        return seen;
    }
    if (equals_ignore_case(flag, "\\Answered")) {
        return answered;
    }
    if (equals_ignore_case(flag, "\\Flagged")) {
        return flagged;
    }
    if (equals_ignore_case(flag, "\\Deleted")) {
        return deleted;
    }
    if (equals_ignore_case(flag, "\\Draft")) {
        return draft;
    }
    if (equals_ignore_case(flag, "\\Recent")) {
        return recent;
    }
    if (flag == "\\*") {
        return accepts_new_keywords;
    }
    return std::any_of(keywords.begin(), keywords.end(),
                       [flag](const std::string& keyword) { return equals_ignore_case(keyword, flag); });
}

bool MailboxListing::has_attribute(std::string_view attribute) const noexcept {
    return std::any_of(attributes.begin(), attributes.end(),
                       [attribute](const std::string& held) { return equals_ignore_case(held, attribute); });
}

bool Capabilities::has(std::string_view capability) const noexcept {
    return std::any_of(names.begin(), names.end(),
                       [capability](const std::string& held) { return equals_ignore_case(held, capability); });
}

}  // namespace crimson::imap
