#include "pch.h"
#include "StormVersionProfile.h"

#include <bcrypt.h>
#include <cstdio>
#include <cstring>

namespace StormVersionProfile {
namespace {

constexpr uint8_t kExpectedStormSha256[32] = {
    0xF8, 0xF5, 0x19, 0xCF, 0xAA, 0x62, 0x75, 0xA5,
    0x17, 0x2A, 0x01, 0x4F, 0x0A, 0xBE, 0xD2, 0x21,
    0x22, 0x84, 0x39, 0x0A, 0x33, 0xF1, 0x19, 0x46,
    0x77, 0x15, 0x5A, 0x7D, 0x40, 0x8E, 0x63, 0xEB,
};

constexpr char kExpectedStormShaText[] =
    "F8F519CFAA6275A5172A014F0ABED2212284390A33F1194677155A7D408E63EB";
constexpr uint8_t kExpectedGameSha256[32] = {
    0xE0, 0x4D, 0x17, 0x16, 0x60, 0x3C, 0x07, 0x5E,
    0xB0, 0xC8, 0xE1, 0xE2, 0x1C, 0xF1, 0x09, 0x3A,
    0x66, 0x4A, 0xDC, 0x52, 0x49, 0xEF, 0xAB, 0x39,
    0x6B, 0xFA, 0x08, 0xD7, 0xB0, 0x9D, 0x0C, 0x3A,
};
constexpr char kExpectedGameShaText[] =
    "E04D1716603C075EB0C8E1E21CF1093A664ADC5249EFAB396BFA08D7B09D0C3A";
constexpr uint8_t kExpectedWorldEditSha256[32] = {
    0x5F, 0x64, 0x5D, 0xB7, 0xC4, 0x36, 0xED, 0x2D,
    0xE0, 0xC5, 0x27, 0x12, 0xD9, 0x8A, 0xCA, 0xF7,
    0x5E, 0x51, 0x88, 0x47, 0xE6, 0x23, 0x4D, 0x4C,
    0xC1, 0xE5, 0xC5, 0xBE, 0xE2, 0xD7, 0x6D, 0xFC,
};
constexpr char kExpectedWorldEditShaText[] =
    "5F645DB7C436ED2DE0C52712D98ACAF75E518847E6234D4CC1E5C5BEE2D76DFC";
constexpr uint32_t kExpectedTimestamp = 0x56BD0E34u;
constexpr uint32_t kExpectedImageSize = 0x00061000u;
constexpr uint64_t kExpectedFileSize = 334312u;
constexpr uint64_t kExpectedGameFileSize = 13187048u;
constexpr uint64_t kExpectedWorldEditFileSize = 4378714u;

struct ExportProfile {
  uint16_t ordinal;
  uint32_t rva;
  uint8_t prologLength;
  uint8_t prolog[8];
};

constexpr ExportProfile kExports[] = {
    {401, 0x2B830, 6, {0x55, 0x8B, 0xEC, 0x51, 0x83, 0x3D, 0x7C, 0x6F}},
    {403, 0x2BE40, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {404, 0x2C000, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {405, 0x2C8B0, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {406, 0x2BF10, 7, {0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x08, 0xA1, 0x8C}},
    {481, 0x2BB20, 8, {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x83, 0x3D}},
    {482, 0x2BD10, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {483, 0x2BF40, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {484, 0x2BF90, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {485, 0x2C0A0, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {486, 0x2C180, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {487, 0x2C300, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {488, 0x2C3A0, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {489, 0x2C5E0, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {490, 0x2C6D0, 5, {0x55, 0x8B, 0xEC, 0x83, 0x3D, 0x7C, 0x6F, 0x05}},
    {496, 0x2C980, 8, {0x55, 0x8B, 0xEC, 0x8B, 0x55, 0x0C, 0x8B, 0x4D}},
};

void SetFailure(wchar_t* output, size_t capacity,
                const wchar_t* message) noexcept {
  if (!output || capacity == 0) {
    return;
  }
  _snwprintf_s(output, capacity, _TRUNCATE, L"%s", message);
}

bool HashFile(HMODULE module, uint8_t output[32], uint64_t* fileSize) noexcept {
  wchar_t path[MAX_PATH]{};
  if (!GetModuleFileNameW(module, path, ARRAYSIZE(path))) {
    return false;
  }

  HANDLE file = CreateFileW(path, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE |
                                FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                            nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }

  LARGE_INTEGER length{};
  if (!GetFileSizeEx(file, &length)) {
    CloseHandle(file);
    return false;
  }
  if (fileSize) {
    *fileSize = static_cast<uint64_t>(length.QuadPart);
  }

  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  PUCHAR hashObject = nullptr;
  PUCHAR buffer = nullptr;
  bool ok = false;
  DWORD objectSize = 0;
  DWORD resultSize = 0;

  if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
          &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) ||
      !BCRYPT_SUCCESS(BCryptGetProperty(
          algorithm, BCRYPT_OBJECT_LENGTH,
          reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize),
          &resultSize, 0))) {
    goto cleanup;
  }

  hashObject = static_cast<PUCHAR>(
      HeapAlloc(GetProcessHeap(), 0, objectSize));
  buffer = static_cast<PUCHAR>(HeapAlloc(GetProcessHeap(), 0, 64u * 1024u));
  if (!hashObject || !buffer ||
      !BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, hashObject,
                                      objectSize, nullptr, 0, 0))) {
    goto cleanup;
  }

  for (;;) {
    DWORD bytesRead = 0;
    if (!ReadFile(file, buffer, 64u * 1024u, &bytesRead, nullptr)) {
      goto cleanup;
    }
    if (bytesRead == 0) {
      break;
    }
    if (!BCRYPT_SUCCESS(BCryptHashData(hash, buffer, bytesRead, 0))) {
      goto cleanup;
    }
  }

  ok = BCRYPT_SUCCESS(BCryptFinishHash(hash, output, 32, 0));

cleanup:
  if (hash) {
    BCryptDestroyHash(hash);
  }
  if (algorithm) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
  }
  if (buffer) {
    HeapFree(GetProcessHeap(), 0, buffer);
  }
  if (hashObject) {
    HeapFree(GetProcessHeap(), 0, hashObject);
  }
  CloseHandle(file);
  return ok;
}

template <typename T>
T ResolveOrdinal(HMODULE module, const ExportProfile& profile,
                 uintptr_t base) noexcept {
  FARPROC address = GetProcAddress(
      module, MAKEINTRESOURCEA(static_cast<WORD>(profile.ordinal)));
  if (!address || reinterpret_cast<uintptr_t>(address) != base + profile.rva ||
      memcmp(address, profile.prolog, profile.prologLength) != 0) {
    return nullptr;
  }
  return reinterpret_cast<T>(address);
}

bool ValidateExportProfiles(HMODULE module, uintptr_t base,
                            wchar_t* failureReason,
                            size_t failureReasonCapacity) noexcept {
  for (const ExportProfile& profile : kExports) {
    FARPROC address = GetProcAddress(
        module, MAKEINTRESOURCEA(static_cast<WORD>(profile.ordinal)));
    if (!address) {
      wchar_t message[96]{};
      _snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
                   L"Storm ordinal %u is missing", profile.ordinal);
      SetFailure(failureReason, failureReasonCapacity, message);
      return false;
    }
    const uintptr_t actualRva =
        reinterpret_cast<uintptr_t>(address) - base;
    if (actualRva != profile.rva) {
      wchar_t message[128]{};
      _snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
                   L"Storm ordinal %u RVA mismatch: 0x%08X != 0x%08X",
                   profile.ordinal, static_cast<uint32_t>(actualRva),
                   profile.rva);
      SetFailure(failureReason, failureReasonCapacity, message);
      return false;
    }
    if (memcmp(address, profile.prolog, profile.prologLength) != 0) {
      wchar_t message[96]{};
      _snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
                   L"Storm ordinal %u prolog mismatch", profile.ordinal);
      SetFailure(failureReason, failureReasonCapacity, message);
      return false;
    }
  }
  return true;
}

} // namespace

bool ResolveVerified127a(HMODULE stormModule, StormApi::ResolvedApi* output,
                         wchar_t* failureReason,
                         size_t failureReasonCapacity) noexcept {
  if (!stormModule || !output) {
    SetFailure(failureReason, failureReasonCapacity,
               L"missing Storm module or output table");
    return false;
  }
  *output = {};

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(stormModule);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    SetFailure(failureReason, failureReasonCapacity, L"invalid DOS header");
    return false;
  }
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
      reinterpret_cast<const uint8_t*>(stormModule) + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
      nt->FileHeader.TimeDateStamp != kExpectedTimestamp ||
      nt->OptionalHeader.SizeOfImage != kExpectedImageSize) {
    SetFailure(failureReason, failureReasonCapacity,
               L"PE identity is not Warcraft III 1.27a Storm.dll");
    return false;
  }

  uint8_t digest[32]{};
  uint64_t fileSize = 0;
  if (!HashFile(stormModule, digest, &fileSize) ||
      fileSize != kExpectedFileSize ||
      memcmp(digest, kExpectedStormSha256, sizeof(digest)) != 0) {
    SetFailure(failureReason, failureReasonCapacity,
               L"Storm.dll SHA-256 or file size mismatch");
    return false;
  }

  const uintptr_t base = reinterpret_cast<uintptr_t>(stormModule);
  if (!ValidateExportProfiles(stormModule, base, failureReason,
                              failureReasonCapacity)) {
    return false;
  }
  StormApi::ResolvedApi resolved{};
  resolved.module = stormModule;
  resolved.base = base;
  resolved.alloc = ResolveOrdinal<StormApi::AllocFn>(stormModule, kExports[0], base);
  resolved.free = ResolveOrdinal<StormApi::FreeFn>(stormModule, kExports[1], base);
  resolved.getSize = ResolveOrdinal<StormApi::GetSizeFn>(stormModule, kExports[2], base);
  resolved.reAlloc = ResolveOrdinal<StormApi::ReAllocFn>(stormModule, kExports[3], base);
  resolved.getAllocated = ResolveOrdinal<StormApi::GetAllocatedFn>(stormModule, kExports[4], base);
  resolved.findNextBlock = ResolveOrdinal<StormApi::FindNextBlockFn>(stormModule, kExports[5], base);
  resolved.findNextHeap = ResolveOrdinal<StormApi::FindNextHeapFn>(stormModule, kExports[6], base);
  resolved.getHeapByCaller = ResolveOrdinal<StormApi::GetHeapByCallerFn>(stormModule, kExports[7], base);
  resolved.getHeapByPtr = ResolveOrdinal<StormApi::GetHeapByPtrFn>(stormModule, kExports[8], base);
  resolved.heapAlloc = ResolveOrdinal<StormApi::HeapAllocFn>(stormModule, kExports[9], base);
  resolved.heapCreate = ResolveOrdinal<StormApi::HeapCreateFn>(stormModule, kExports[10], base);
  resolved.heapDestroy = ResolveOrdinal<StormApi::HeapDestroyFn>(stormModule, kExports[11], base);
  resolved.heapFree = ResolveOrdinal<StormApi::HeapFreeFn>(stormModule, kExports[12], base);
  resolved.heapReAlloc = ResolveOrdinal<StormApi::HeapReAllocFn>(stormModule, kExports[13], base);
  resolved.heapSize = ResolveOrdinal<StormApi::HeapSizeFn>(stormModule, kExports[14], base);
  resolved.setOption = ResolveOrdinal<StormApi::SetOptionFn>(stormModule, kExports[15], base);

  const uint8_t cleanupProlog[8] = {0x55, 0x8B, 0xEC, 0x51,
                                    0x53, 0x56, 0xB9, 0x00};
  auto cleanupAddress = reinterpret_cast<void*>(base + 0x2AB50u);
  if (!resolved.alloc || !resolved.free || !resolved.getSize ||
      !resolved.reAlloc || !resolved.getAllocated ||
      !resolved.findNextBlock || !resolved.findNextHeap ||
      !resolved.getHeapByCaller || !resolved.getHeapByPtr ||
      !resolved.heapAlloc || !resolved.heapCreate || !resolved.heapDestroy ||
      !resolved.heapFree || !resolved.heapReAlloc || !resolved.heapSize ||
      !resolved.setOption ||
      memcmp(cleanupAddress, cleanupProlog, sizeof(cleanupProlog)) != 0) {
    SetFailure(failureReason, failureReasonCapacity,
               L"Storm memory export RVA or prolog mismatch");
    return false;
  }

  resolved.cleanupAll = reinterpret_cast<StormApi::CleanupAllFn>(cleanupAddress);
  resolved.memorySystemInitialized =
      reinterpret_cast<volatile uint8_t*>(base + 0x56F7Cu);
  resolved.debugMemoryEnabled =
      reinterpret_cast<volatile uint32_t*>(base + 0x5536Cu);
  resolved.errorHandlingEnabled =
      reinterpret_cast<volatile uint32_t*>(base + 0x57388u);
  resolved.protectMemoryEnabled =
      reinterpret_cast<volatile uint32_t*>(base + 0x56F74u);
  resolved.fillPatternEnabled =
      reinterpret_cast<volatile uint32_t*>(base + 0x56F70u);
  resolved.reallocShuffleEnabled =
      reinterpret_cast<volatile uint32_t*>(base + 0x56F78u);
  resolved.nativeAllocatedBytes =
      reinterpret_cast<volatile uint32_t*>(base + 0x5738Cu);

  *output = resolved;
  SetFailure(failureReason, failureReasonCapacity, L"");
  return true;
}

bool VerifyGame127a(HMODULE gameModule, wchar_t* failureReason,
                    size_t failureReasonCapacity) noexcept {
  if (!gameModule) {
    SetFailure(failureReason, failureReasonCapacity, L"Game.dll is not loaded");
    return false;
  }

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(gameModule);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    SetFailure(failureReason, failureReasonCapacity,
               L"invalid Game.dll DOS header");
    return false;
  }
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
      reinterpret_cast<const uint8_t*>(gameModule) + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    SetFailure(failureReason, failureReasonCapacity,
               L"Game.dll is not a Win32/x86 PE image");
    return false;
  }

  uint8_t digest[32]{};
  uint64_t fileSize = 0;
  if (!HashFile(gameModule, digest, &fileSize) ||
      fileSize != kExpectedGameFileSize ||
      memcmp(digest, kExpectedGameSha256, sizeof(digest)) != 0) {
    SetFailure(failureReason, failureReasonCapacity,
               L"Game.dll SHA-256 or file size mismatch");
    return false;
  }
  SetFailure(failureReason, failureReasonCapacity, L"");
  return true;
}

bool VerifyWorldEdit127a(HMODULE worldEditModule, wchar_t* failureReason,
                         size_t failureReasonCapacity) noexcept {
  if (!worldEditModule) {
    SetFailure(failureReason, failureReasonCapacity,
               L"WorldEdit.exe module is unavailable");
    return false;
  }
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(worldEditModule);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    SetFailure(failureReason, failureReasonCapacity,
               L"invalid WorldEdit.exe DOS header");
    return false;
  }
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
      reinterpret_cast<const uint8_t*>(worldEditModule) + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    SetFailure(failureReason, failureReasonCapacity,
               L"WorldEdit.exe is not a Win32/x86 PE image");
    return false;
  }
  uint8_t digest[32]{};
  uint64_t fileSize = 0;
  if (!HashFile(worldEditModule, digest, &fileSize) ||
      fileSize != kExpectedWorldEditFileSize ||
      memcmp(digest, kExpectedWorldEditSha256, sizeof(digest)) != 0) {
    SetFailure(failureReason, failureReasonCapacity,
               L"WorldEdit.exe SHA-256 or file size mismatch");
    return false;
  }
  SetFailure(failureReason, failureReasonCapacity, L"");
  return true;
}

const char* ExpectedStormSha256() noexcept { return kExpectedStormShaText; }
const char* ExpectedGameSha256() noexcept { return kExpectedGameShaText; }
const char* ExpectedWorldEditSha256() noexcept {
  return kExpectedWorldEditShaText;
}

} // namespace StormVersionProfile
