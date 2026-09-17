// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef CRIMSON_CORE_VERSION_H
#define CRIMSON_CORE_VERSION_H

#include <cstdint>
#include <string_view>

// The integer components come from build/Crimson.Common.props so the build
// system stays the single source of truth. They are defined here as a fallback
// so this header remains usable outside an MSBuild invocation.
#ifndef CRIMSON_VERSION_MAJOR
#define CRIMSON_VERSION_MAJOR 0
#endif
#ifndef CRIMSON_VERSION_MINOR
#define CRIMSON_VERSION_MINOR 1
#endif
#ifndef CRIMSON_VERSION_PATCH
#define CRIMSON_VERSION_PATCH 0
#endif

#define CRIMSON_STRINGIFY_IMPL(x) #x
#define CRIMSON_STRINGIFY(x) CRIMSON_STRINGIFY_IMPL(x)

namespace crimson {

inline constexpr std::uint32_t version_major = CRIMSON_VERSION_MAJOR;
inline constexpr std::uint32_t version_minor = CRIMSON_VERSION_MINOR;
inline constexpr std::uint32_t version_patch = CRIMSON_VERSION_PATCH;

inline constexpr std::string_view version_string =
    CRIMSON_STRINGIFY(CRIMSON_VERSION_MAJOR) "."
    CRIMSON_STRINGIFY(CRIMSON_VERSION_MINOR) "."
    CRIMSON_STRINGIFY(CRIMSON_VERSION_PATCH);

inline constexpr std::string_view product_name = "Crimson";

}  // namespace crimson

#endif  // CRIMSON_CORE_VERSION_H
