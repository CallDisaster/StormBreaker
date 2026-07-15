#pragma once

#define STORMBREAKER_VERSION_MAJOR 1
#define STORMBREAKER_VERSION_MINOR 3
#define STORMBREAKER_VERSION_PATCH 0
#define STORMBREAKER_VERSION_BUILD 0

#define STORMBREAKER_STRINGIFY_INNER(value) #value
#define STORMBREAKER_STRINGIFY(value) STORMBREAKER_STRINGIFY_INNER(value)
#define STORMBREAKER_VERSION_STRING                                         \
  STORMBREAKER_STRINGIFY(STORMBREAKER_VERSION_MAJOR) "."                   \
  STORMBREAKER_STRINGIFY(STORMBREAKER_VERSION_MINOR) "."                   \
  STORMBREAKER_STRINGIFY(STORMBREAKER_VERSION_PATCH)
#define STORMBREAKER_VERSION_FILE_STRING                                    \
  STORMBREAKER_VERSION_STRING "."                                          \
  STORMBREAKER_STRINGIFY(STORMBREAKER_VERSION_BUILD)

namespace StormBreakerVersion {
inline constexpr char kVersion[] = STORMBREAKER_VERSION_STRING;
inline constexpr char kProductName[] = "StormBreaker";
} // namespace StormBreakerVersion
