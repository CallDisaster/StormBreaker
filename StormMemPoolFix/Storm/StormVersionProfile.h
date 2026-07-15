#pragma once

#include "StormApi.h"

#include <cstddef>

namespace StormVersionProfile {

bool ResolveVerified127a(HMODULE stormModule, StormApi::ResolvedApi* output,
                         wchar_t* failureReason,
                         size_t failureReasonCapacity) noexcept;
bool VerifyGame127a(HMODULE gameModule, wchar_t* failureReason,
                    size_t failureReasonCapacity) noexcept;
bool VerifyWorldEdit127a(HMODULE worldEditModule, wchar_t* failureReason,
                         size_t failureReasonCapacity) noexcept;

const char* ExpectedStormSha256() noexcept;
const char* ExpectedGameSha256() noexcept;
const char* ExpectedWorldEditSha256() noexcept;

} // namespace StormVersionProfile
