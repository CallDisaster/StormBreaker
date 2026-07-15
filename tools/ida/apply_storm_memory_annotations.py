"""Apply verified Warcraft III 1.27a Storm memory annotations in IDA.

The script is intentionally fail-closed: it only changes the two exact binaries
used by the StormBreaker research pass.
"""

import idc
import ida_name
import ida_loader
import ida_nalt


GAME_SHA256 = "e04d1716603c075eb0c8e1e21cf1093a664adc5249efab396bfa08d7b09d0c3a"
STORM_SHA256 = "f8f519cfaa6275a5172a014f0abed2212284390a33f1194677155a7d408e63eb"


def _sha256():
    digest = ida_nalt.retrieve_input_file_sha256()
    return digest.hex() if digest else ""


def _ea(rva):
    return ida_nalt.get_imagebase() + rva


def _apply_types(declarations, functions):
    if declarations:
        errors = idc.parse_decls(declarations, idc.PT_SIL)
        if errors:
            raise RuntimeError("IDA rejected one or more type declarations")
    for rva, signature in functions.items():
        if not idc.SetType(_ea(rva), signature):
            raise RuntimeError("failed to set type at RVA 0x%X" % rva)


def _apply_names(names):
    for rva, name in names.items():
        if not idc.set_name(
            _ea(rva), name, ida_name.SN_FORCE | ida_name.SN_NOCHECK
        ):
            raise RuntimeError("failed to name RVA 0x%X as %s" % (rva, name))


def _apply_comments(comments):
    for rva, comment in comments.items():
        if not idc.set_cmt(_ea(rva), comment, 1):
            raise RuntimeError("failed to comment RVA 0x%X" % rva)


def apply_game():
    declarations = r"""
typedef struct StormHeapInfo482_GameView {
  unsigned int structSize;
  unsigned char unknown_004[272];
  unsigned int displayedCounterAt276;
  unsigned char unknown_118[12];
  unsigned int displayedCounterAt292;
} StormHeapInfo482_GameView;
"""
    names = {
        0x120628: "Storm_SMemAlloc_401",
        0x1205CE: "Storm_SMemFree_403",
        0x12062E: "Storm_SMemReAlloc_405",
        0x81918A: "Storm_SMemGetAllocated_406",
        0x819184: "Storm_SMemHeapInfo_482",
        0x120676: "Storm_SMemSetOption_496",
        0x05E710: "SignalAndDrainMainLoop_05E710",
        0x7039A0: "QueryStormAllocatedBytes",
        0x3B18E0: "UpdateMemoryDebugOverlay",
        0x027660: "GameApp_ShutdownSubsystems",
        0x885910: "Warden_LoadDynamicModule",
    }
    functions = {
        0x120628: "void *__stdcall Storm_SMemAlloc_401(unsigned int size, const char *sourceFile, int sourceLine, unsigned int flags);",
        0x1205CE: "int __stdcall Storm_SMemFree_403(void *pointer, const char *sourceFile, int sourceLine, unsigned int flags);",
        0x12062E: "void *__stdcall Storm_SMemReAlloc_405(void *pointer, unsigned int newSize, const char *sourceFile, int sourceLine, unsigned int flags);",
        0x81918A: "unsigned int __stdcall Storm_SMemGetAllocated_406(unsigned int *outA, unsigned int *outB, unsigned int *outC);",
        0x819184: "int __stdcall Storm_SMemHeapInfo_482(unsigned int currentHeapId, unsigned int *nextHeapId, StormHeapInfo482_GameView *info);",
        0x120676: "int __stdcall Storm_SMemSetOption_496(unsigned int valueBits, unsigned int maskBits);",
        0x05E710: "void __cdecl SignalAndDrainMainLoop_05E710(void);",
        0x7039A0: "unsigned int __cdecl QueryStormAllocatedBytes(void);",
    }
    comments = {
        0x120628: "Storm ordinal 401. Game sees four stdcall stack arguments; Storm's implementation also has two unused fastcall register slots.",
        0x81918A: "Ordinal 406 drives texture/resource memory deltas and also seeds a default texture key.",
        0x819184: "Ordinal 482 consumes a 296-byte record and the HUD sums fields at offsets 276 and 292.",
        0x05E710: "NOT a memory reset: signal engine event, drain/advance main loop, then clear the associated pointer.",
        0x6FE714: "Capture ordinal-406 bytes before texture/resource loading.",
        0x6FE806: "Accumulate the ordinal-406 delta after texture/resource loading.",
        0x885A9C: "Warden resolves dynamic module imports by name or high-bit encoded ordinal.",
    }
    _apply_types(declarations, functions)
    _apply_names(names)
    _apply_comments(comments)


def apply_storm():
    declarations = r"""
typedef struct SMemBlockInfo481 {
  unsigned int structSize;
  void *block;
  int allocated;
  int valid;
  unsigned int requestedBytes;
  unsigned int overheadBytes;
  unsigned int reserved;
} SMemBlockInfo481;
typedef struct SMemHeapInfo482 {
  unsigned int structSize;
  unsigned int heapId;
  char sourceName[260];
  int sourceLine;
  unsigned int reserved272;
  unsigned int committedBytes;
  unsigned int reservedBytes;
  unsigned int maxAllocationSize;
  unsigned int liveAllocationCount;
  unsigned int requestedBytes;
} SMemHeapInfo482;
typedef struct StormSmallBlockHeader {
  unsigned short totalBytes;
  unsigned char alignmentPadding;
  unsigned char flags;
  unsigned short arenaHigh16;
  unsigned short magic6F6D;
} StormSmallBlockHeader;
typedef struct StormHeapArena {
  struct StormHeapArena *next;
  unsigned int heapId;
  unsigned int bucketIndex;
  unsigned int blockSignature;
  unsigned int currentArena;
  unsigned int liveAllocationCount;
  unsigned int requestedLiveBytes;
  unsigned char *dataStart;
  unsigned char *bumpEnd;
  unsigned int adjacentFreeHint;
  unsigned int commitGranularity;
  unsigned int committedBytes;
  unsigned int reservedBytes;
  unsigned int externalRequestedBytes;
  unsigned int allocationCalls;
  unsigned int freeCalls;
  unsigned int reserved64;
  StormSmallBlockHeader *freeBins[9];
  int sourceLine;
  char sourceName[1];
} StormHeapArena;
"""
    names = {
        0x2B830: "SMemAlloc_401", 0x2BE40: "SMemFree_403",
        0x2C000: "SMemGetSize_404", 0x2C8B0: "SMemReAlloc_405",
        0x2BF10: "SMemGetAllocated_406", 0x2BB20: "SMemFindNextBlock_481",
        0x2BD10: "SMemFindNextHeap_482", 0x2BF40: "SMemGetHeapByCaller_483",
        0x2BF90: "SMemGetHeapByPtr_484", 0x2C0A0: "SMemHeapAlloc_485",
        0x2C180: "SMemHeapCreate_486", 0x2C300: "SMemHeapDestroy_487",
        0x2C3A0: "SMemHeapFree_488", 0x2C5E0: "SMemHeapReAlloc_489",
        0x2C6D0: "SMemHeapSize_490", 0x2C980: "SMemSetOption_496",
        0x2A350: "StormHeap_Create", 0x2A510: "StormHeap_AllocPage",
        0x2A920: "StormHeap_RebuildFreeList",
        0x2AA70: "StormHeap_DestroyArenaOrPreservePersistent",
        0x2AB50: "StormHeap_CleanupAll", 0x2ABF0: "StormHeap_InternalFree",
        0x2AD10: "StormHeap_QueryBlockSizeAndOverhead",
        0x2AD60: "StormHeap_ComputeIndex", 0x2ADE0: "StormHeap_CommitPages",
        0x2AE30: "StormHeap_TryGrowInPlace",
        0x2B3B0: "StormHeap_Alloc", 0x2B4F0: "StormHeap_FreeAndAccount",
        0x2B560: "StormHeap_ReallocImpl", 0x2B680: "StormHeap_ShrinkInPlace",
        0x2B790: "StormHeap_SplitFreeBlock",
        0x5536C: "g_DebugMemoryEnabled", 0x56F74: "g_ProtectMemoryEnabled",
        0x49560: "g_NextExplicitHeapId", 0x56F78: "g_ReallocShuffleEnabled",
    }
    functions = {
        0x2B830: "void *__fastcall SMemAlloc_401(int reservedEcx, int reservedEdx, unsigned int size, const char *sourceFile, int sourceLine, unsigned int flags);",
        0x2BE40: "int __stdcall SMemFree_403(void *pointer, const char *sourceFile, int sourceLine, unsigned int flags);",
        0x2C000: "int __stdcall SMemGetSize_404(const void *pointer, const char *sourceFile, int sourceLine);",
        0x2C8B0: "void *__fastcall SMemReAlloc_405(int reservedEcx, int reservedEdx, void *pointer, unsigned int newSize, const char *sourceFile, int sourceLine, unsigned int flags);",
        0x2BF10: "unsigned int __stdcall SMemGetAllocated_406(unsigned int *outA, unsigned int *outB, unsigned int *outC);",
        0x2BB20: "int __stdcall SMemFindNextBlock_481(unsigned int heapId, const void *previousBlock, void **nextBlock, SMemBlockInfo481 *info);",
        0x2BD10: "int __stdcall SMemFindNextHeap_482(unsigned int currentHeapId, unsigned int *nextHeapId, SMemHeapInfo482 *info);",
        0x2BF40: "unsigned int __stdcall SMemGetHeapByCaller_483(const char *sourceFile, int sourceLine);",
        0x2BF90: "unsigned int __stdcall SMemGetHeapByPtr_484(const void *pointer);",
        0x2C0A0: "void *__stdcall SMemHeapAlloc_485(unsigned int heapId, unsigned int flags, unsigned int size);",
        0x2C180: "unsigned int __stdcall SMemHeapCreate_486(void *baseAddress, unsigned int initialSize, unsigned int flags, const char *sourceFile, int sourceLine);",
        0x2C300: "int __stdcall SMemHeapDestroy_487(unsigned int heapId);",
        0x2C3A0: "int __stdcall SMemHeapFree_488(unsigned int heapId, unsigned int flags, void *pointer);",
        0x2C5E0: "void *__stdcall SMemHeapReAlloc_489(unsigned int heapId, unsigned int flags, void *pointer, unsigned int newSize);",
        0x2C6D0: "int __stdcall SMemHeapSize_490(unsigned int heapId, unsigned int flags, const void *pointer);",
        0x2C980: "int __stdcall SMemSetOption_496(unsigned int valueBits, unsigned int maskBits);",
        0x2A350: "StormHeapArena *__fastcall StormHeap_Create(const char *sourceFile, int sourceLine, unsigned int heapId, unsigned int bucketIndex, unsigned int commitGranularity, unsigned int initialCommit, unsigned int reserveBytes);",
        0x2A510: "void *__fastcall StormHeap_AllocPage(StormHeapArena *arena, unsigned int requestedBytes, unsigned int headerFlags);",
        0x2A920: "void __fastcall StormHeap_RebuildFreeList(StormHeapArena *arena);",
        0x2ABF0: "void __fastcall StormHeap_InternalFree(StormHeapArena *arena, StormSmallBlockHeader *block);",
        0x2AD10: "void __fastcall StormHeap_QueryBlockSizeAndOverhead(StormSmallBlockHeader *block, const void *userPointer, unsigned int *requestedBytes, unsigned int *overheadBytes);",
        0x2ADE0: "int __fastcall StormHeap_CommitPages(StormHeapArena *arena, unsigned int requiredEndOffset);",
        0x2AE30: "int __fastcall StormHeap_TryGrowInPlace(StormHeapArena *arena, StormSmallBlockHeader *block, unsigned int oldRequestedBytes, unsigned int newRequestedBytes);",
        0x2B680: "int __fastcall StormHeap_ShrinkInPlace(StormHeapArena *arena, StormSmallBlockHeader *block, unsigned int oldRequestedBytes, unsigned int newRequestedBytes);",
        0x2B790: "void __fastcall StormHeap_SplitFreeBlock(StormHeapArena *arena, StormSmallBlockHeader *freeBlock, unsigned int *allocatedTotalBytes, unsigned char *alignmentPadding);",
    }
    comments = {
        0x2C8B0: "Small realloc(ptr,0) normally returns the same valid zero-request block; large/shuffle realloc returns a new zero-request block. Flag 0x10 forbids moving.",
        0x2BB20: "481 requires heapId, outNext and info size 28; previousBlock may be null. It enumerates allocated and free arena blocks.",
        0x2BD10: "482 record: id@4, name@8, line@268, committed@276, reserved@280, max@284, live count@288, requested@292.",
        0x2C180: "486 requires null baseAddress; explicit IDs begin at 0x80000001 and size rounds to at least 4 KiB.",
        0x2C300: "487 frees ordinary blocks but preserves 0x08000000 persistent blocks and their heap arena.",
        0x2C980: "496 bits: 1 Debug Memory, 2 error handling, 4 Protect Memory, 8 fill pattern. Realloc Shuffle is separate.",
        0x2A350: "Arena layout verified: 112-byte fixed prefix plus source name, rounded to 8. Initial automatic arena reserves 64 KiB and commits 4 KiB.",
        0x2A58F: "Free-list bin is min(totalBytes >> 5, 8): eight 32-byte ranges and one catch-all bin for every block >=256 bytes.",
        0x2A592: "Deferred coalescing runs only when adjacentFreeHint >= 4 and the request's exact bin is empty.",
        0x2A5A5: "Search selects the first nonempty bin at or above the request bin.",
        0x2A5D4: "Only this selected bin is traversed. Approximate best fit stops when remainder is below a growing 16+4n tolerance.",
        0x2A603: "Confirmed fragmentation flaw: if the selected bin contains only undersized blocks, allocation falls through to bump growth without checking higher bins that may fit.",
        0x2A66E: "When bump growth exceeds reserve, the next arena doubles reserve up to 256 MiB and initially commits one eighth.",
        0x2A920: "Rebuild scans dataStart..bumpEnd, coalesces adjacent free blocks while combined total fits uint16, and reconstructs all nine bins.",
        0x2B4F0: "Accounting defect: allocation adds requested bytes, but small free subtracts total block bytes (requested + header + padding). Large free subtracts placeholder bytes.",
        0x2B680: "Shrink inserts a >=16-byte remainder into a free bin. It does not set the following block's previous-free hint, delaying the coalescing heuristic.",
        0x2B790: "This is a split helper, not a coalescer: allocate the front of a selected free block, absorb remainder <16, or enqueue the remainder.",
    }
    _apply_types(declarations, functions)
    _apply_names(names)
    _apply_comments(comments)


digest = _sha256()
if digest == GAME_SHA256:
    apply_game()
elif digest == STORM_SHA256:
    apply_storm()
else:
    raise RuntimeError("unsupported input SHA-256: %s" % (digest or "unavailable"))

ida_loader.save_database(None, 0)
print("StormBreaker memory annotations applied to", ida_nalt.get_input_file_path())
