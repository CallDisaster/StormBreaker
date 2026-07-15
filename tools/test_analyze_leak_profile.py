import struct
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

import analyze_leak_profile as sblp  # noqa: E402


def stream(*records: bytes, mode: int = 2, version: int = 1) -> bytes:
    return sblp.build_file_header(mode=mode, version=version) + b"".join(
        records
    )


class AnalyzeLeakProfileTests(unittest.TestCase):
    def test_complete_flow_and_checkpoint(self) -> None:
        data = stream(
            sblp.build_record(
                sblp.TYPE_ALLOC,
                1,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_ALLOC,
                    pointer=0x1000,
                    size=64,
                    stack=[0xAAA0, 0xAAA1],
                ),
            ),
            sblp.build_record(
                sblp.TYPE_ALLOC,
                2,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_ALLOC,
                    pointer=0x2000,
                    size=32,
                    domain=sblp.DOMAIN_NATIVE,
                    stack=[0xBBB0],
                    flags=sblp.FLAG_NATIVE_SAMPLED,
                ),
            ),
            sblp.build_record(
                sblp.TYPE_FREE,
                3,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_FREE,
                    pointer=0x2000,
                    size=32,
                    domain=sblp.DOMAIN_NATIVE,
                    flags=sblp.FLAG_NATIVE_SAMPLED,
                ),
            ),
            sblp.build_record(
                sblp.TYPE_EPOCH,
                4,
                sblp.encode_epoch(
                    7, reason=sblp.EPOCH_REASON_RESET_HEURISTIC
                ),
            ),
            sblp.build_record(
                sblp.TYPE_CHECKPOINT,
                5,
                sblp.encode_checkpoint(
                    events_enqueued=4, events_written=4
                ),
            ),
        )

        result = sblp.analyze_bytes(data)

        self.assertTrue(result["integrity"]["complete"])
        self.assertEqual(result["summary"]["liveAllocationCount"], 1)
        self.assertEqual(result["summary"]["liveBytes"], 64)
        self.assertEqual(result["survivors"][0]["epoch"], 7)
        self.assertEqual(result["survivors"][0]["caller"], "0x000000000000aaa0")
        self.assertFalse(result["survivors"][0]["leakCandidate"])

    def test_truncated_tail_keeps_complete_prefix(self) -> None:
        first = sblp.build_record(
            sblp.TYPE_ALLOC,
            1,
            sblp.encode_alloc_or_free(
                sblp.TYPE_ALLOC, pointer=0x1110, size=11
            ),
        )
        tail = sblp.build_record(
            sblp.TYPE_ALLOC,
            2,
            sblp.encode_alloc_or_free(
                sblp.TYPE_ALLOC, pointer=0x2220, size=22
            ),
        )

        result = sblp.analyze_bytes(stream(first, tail[:-7]))

        self.assertTrue(result["integrity"]["truncatedTail"])
        self.assertFalse(result["integrity"]["complete"])
        self.assertEqual(result["summary"]["liveAllocationCount"], 1)
        self.assertEqual(result["liveAllocations"][0]["address"], "0x0000000000001110")

    def test_bad_crc_is_skipped_and_later_record_is_recovered(self) -> None:
        bad = bytearray(
            sblp.build_record(
                sblp.TYPE_ALLOC,
                1,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_ALLOC, pointer=0x3330, size=33
                ),
            )
        )
        bad[sblp.RECORD_HEADER.size + 4] ^= 0x80
        epoch = sblp.build_record(
            sblp.TYPE_EPOCH,
            2,
            sblp.encode_epoch(9, reason=sblp.EPOCH_REASON_RESET_HEURISTIC),
        )

        result = sblp.analyze_bytes(stream(bytes(bad), epoch))

        self.assertEqual(result["integrity"]["badCrcRecords"], 1)
        self.assertEqual(result["integrity"]["sequenceGaps"], 1)
        self.assertEqual(result["summary"]["epochCount"], 1)
        self.assertEqual(result["summary"]["liveAllocationCount"], 0)

    def test_realloc_move_and_in_place_preserve_live_state(self) -> None:
        flags = (
            sblp.REALLOC_OLD_FREED
            | sblp.REALLOC_NEW_ALLOCATED
            | sblp.REALLOC_OLD_TRACKED
            | sblp.REALLOC_NEW_TRACKED
        )
        in_place_flags = flags | sblp.REALLOC_IN_PLACE
        data = stream(
            sblp.build_record(
                sblp.TYPE_ALLOC,
                1,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_ALLOC,
                    pointer=0x4000,
                    size=40,
                    stack=[0xA000],
                ),
            ),
            sblp.build_record(
                sblp.TYPE_REALLOC,
                2,
                sblp.encode_realloc(
                    old_pointer=0x4000,
                    new_pointer=0x5000,
                    old_size=40,
                    new_size=50,
                    flags=flags,
                    stack=[0xB000],
                ),
            ),
            sblp.build_record(
                sblp.TYPE_EPOCH,
                3,
                sblp.encode_epoch(1, reason=sblp.EPOCH_REASON_RESET_HEURISTIC),
            ),
            sblp.build_record(
                sblp.TYPE_REALLOC,
                4,
                sblp.encode_realloc(
                    old_pointer=0x5000,
                    new_pointer=0x5000,
                    old_size=50,
                    new_size=80,
                    flags=in_place_flags,
                    stack=[0xC000],
                ),
            ),
            sblp.build_record(
                sblp.TYPE_EPOCH,
                5,
                sblp.encode_epoch(2, reason=sblp.EPOCH_REASON_RESET_HEURISTIC),
            ),
        )

        result = sblp.analyze_bytes(data)

        self.assertEqual(result["summary"]["liveAllocationCount"], 1)
        allocation = result["liveAllocations"][0]
        self.assertEqual(allocation["address"], "0x0000000000005000")
        self.assertEqual(allocation["size"], 80)
        self.assertEqual(allocation["caller"], "0x000000000000b000")
        self.assertEqual(allocation["epochsSurvived"], 2)
        self.assertFalse(allocation["leakCandidate"])

    def test_candidate_requires_growth_in_two_consecutive_reset_epochs(self) -> None:
        data = stream(
            sblp.build_record(
                sblp.TYPE_ALLOC,
                1,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_ALLOC,
                    pointer=0x6000,
                    size=96,
                    stack=[0xD000],
                ),
            ),
            sblp.build_record(
                sblp.TYPE_EPOCH,
                2,
                sblp.encode_epoch(
                    10, reason=sblp.EPOCH_REASON_RESET_HEURISTIC
                ),
            ),
            sblp.build_record(
                sblp.TYPE_ALLOC,
                3,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_ALLOC,
                    pointer=0x6100,
                    size=96,
                    stack=[0xD000],
                ),
            ),
            sblp.build_record(
                sblp.TYPE_EPOCH,
                4,
                sblp.encode_epoch(
                    11, reason=sblp.EPOCH_REASON_RESET_HEURISTIC
                ),
            ),
        )

        result = sblp.analyze_bytes(data)

        self.assertFalse(result["survivors"][0]["leakCandidate"])
        self.assertTrue(result["survivors"][1]["leakCandidate"])
        self.assertEqual(result["survivors"][1]["candidateCount"], 2)
        self.assertEqual(result["summary"]["leakCandidateCount"], 2)
        self.assertEqual(result["summary"]["leakCandidateGroupCount"], 1)

    def test_cleanup_marker_does_not_advance_leak_epoch(self) -> None:
        data = stream(
            sblp.build_record(
                sblp.TYPE_ALLOC,
                1,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_ALLOC, pointer=0x7000, size=128
                ),
            ),
            sblp.build_record(
                sblp.TYPE_EPOCH,
                2,
                sblp.encode_epoch(0, reason=sblp.EPOCH_REASON_CLEANUP),
            ),
            sblp.build_record(
                sblp.TYPE_EPOCH, 3, sblp.encode_epoch(1, reason=1)
            ),
        )

        result = sblp.analyze_bytes(data)

        self.assertEqual(result["summary"]["epochCount"], 1)
        self.assertEqual(result["survivors"][0]["maxEpochsSurvived"], 1)
        self.assertFalse(result["survivors"][0]["leakCandidate"])
        self.assertEqual(result["summary"]["epochMarkerCount"], 2)
        self.assertEqual(result["epochMarkers"][0]["reasonName"], "cleanup")

    def test_module_snapshot_resolves_caller_rva(self) -> None:
        data = stream(
            sblp.build_record(
                sblp.TYPE_MODULE,
                1,
                sblp.encode_module(
                    0x400000, 0x20000, r"E:\War3\StormBreaker.asi"
                ),
            ),
            sblp.build_record(
                sblp.TYPE_ALLOC,
                2,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_ALLOC,
                    pointer=0x9000,
                    size=256,
                    stack=[0x401234],
                ),
            ),
        )

        result = sblp.analyze_bytes(data)

        self.assertEqual(result["modules"][0]["name"], "StormBreaker.asi")
        location = result["liveAllocations"][0]["callerLocation"]
        self.assertEqual(location["module"], "StormBreaker.asi")
        self.assertEqual(location["rva"], "0x00001234")

    def test_v2_event_metadata_and_storm_api_are_preserved(self) -> None:
        version = sblp.CURRENT_FILE_VERSION
        data = stream(
            sblp.build_record(
                sblp.TYPE_MODULE,
                1,
                sblp.encode_module(
                    0x400000, 0x20000, r"E:\War3\StormBreaker.asi"
                ),
            ),
            sblp.build_record(
                sblp.TYPE_ALLOC,
                2,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_ALLOC,
                    pointer=0x1000,
                    size=48,
                    version=version,
                    heap_id=0x80000042,
                    storm_flags=0x18,
                    exported_ordinal=485,
                    route=sblp.ROUTE_MIMALLOC,
                    stack=[0x401234],
                    timestamp_qpc=101,
                    thread_id=7,
                ),
            ),
            sblp.build_record(
                sblp.TYPE_ALLOC,
                3,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_ALLOC,
                    pointer=0x2000,
                    size=96,
                    domain=sblp.DOMAIN_NATIVE,
                    version=version,
                    heap_id=0x1234,
                    exported_ordinal=403,
                    route=sblp.ROUTE_NATIVE_STORM,
                    degraded_reason=sblp.DEGRADED_BELOW_TAKEOVER_THRESHOLD,
                    disposition=sblp.DISPOSITION_DEGRADED,
                ),
            ),
            sblp.build_record(
                sblp.TYPE_FREE,
                4,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_FREE,
                    pointer=0x2000,
                    size=96,
                    domain=sblp.DOMAIN_NATIVE,
                    version=version,
                    heap_id=0x1234,
                    exported_ordinal=404,
                    route=sblp.ROUTE_NATIVE_STORM,
                    disposition=sblp.DISPOSITION_FALLBACK,
                ),
            ),
            sblp.build_record(
                sblp.TYPE_STORM_API,
                5,
                sblp.encode_storm_api(
                    primary_value=123,
                    secondary_value=456,
                    heap_id=0x80000042,
                    storm_flags=0x8000000,
                    exported_ordinal=487,
                    route=sblp.ROUTE_TLSF,
                    degraded_reason=sblp.DEGRADED_BACKEND_OUT_OF_MEMORY,
                    disposition=sblp.DISPOSITION_FALLBACK_DEGRADED,
                ),
            ),
            version=version,
        )

        result = sblp.analyze_bytes(data)

        self.assertEqual(result["format"]["version"], 2)
        self.assertTrue(result["integrity"]["complete"])
        self.assertEqual(result["summary"]["liveAllocationCount"], 1)
        allocation = result["liveAllocations"][0]
        self.assertEqual(allocation["metadata"]["heapId"], 0x80000042)
        self.assertEqual(allocation["metadata"]["stormFlagsHex"], "0x00000018")
        self.assertEqual(allocation["metadata"]["exportedOrdinal"], 485)
        self.assertEqual(allocation["metadata"]["route"], "mimalloc")
        self.assertEqual(
            allocation["callerLocation"]["module"], "StormBreaker.asi"
        )

        self.assertEqual(result["summary"]["eventCounts"]["stormApi"], 1)
        self.assertEqual(result["summary"]["fallbackEventCount"], 2)
        self.assertEqual(result["summary"]["degradedEventCount"], 2)
        self.assertEqual(result["metadataSummary"]["records"], 4)
        self.assertEqual(
            result["metadataSummary"]["byExportedOrdinal"]["487"], 1
        )
        storm_api = result["events"][-1]
        self.assertEqual(storm_api["type"], "stormApi")
        self.assertEqual(storm_api["primaryValue"], 123)
        self.assertEqual(storm_api["secondaryValue"], 456)
        self.assertTrue(storm_api["fallback"])
        self.assertTrue(storm_api["degraded"])
        self.assertEqual(
            storm_api["metadata"]["degradedReason"],
            "backend-out-of-memory",
        )
        self.assertEqual(
            storm_api["metadata"]["disposition"], "fallback-degraded"
        )

    def test_v2_realloc_uses_explicit_new_domain_and_metadata(self) -> None:
        version = sblp.CURRENT_FILE_VERSION
        flags = (
            sblp.REALLOC_OLD_FREED
            | sblp.REALLOC_NEW_ALLOCATED
            | sblp.REALLOC_OLD_TRACKED
            | sblp.REALLOC_NEW_TRACKED
        )
        data = stream(
            sblp.build_record(
                sblp.TYPE_ALLOC,
                1,
                sblp.encode_alloc_or_free(
                    sblp.TYPE_ALLOC,
                    pointer=0x3000,
                    size=128,
                    version=version,
                    heap_id=9,
                    exported_ordinal=403,
                    route=sblp.ROUTE_TLSF,
                ),
            ),
            sblp.build_record(
                sblp.TYPE_REALLOC,
                2,
                sblp.encode_realloc(
                    old_pointer=0x3000,
                    new_pointer=0x4000,
                    old_size=128,
                    new_size=256,
                    flags=flags,
                    domain=sblp.DOMAIN_MANAGED,
                    new_domain=sblp.DOMAIN_NATIVE,
                    version=version,
                    heap_id=9,
                    storm_flags=0x10,
                    exported_ordinal=405,
                    route=sblp.ROUTE_TLSF,
                    new_heap_id=9,
                    new_storm_flags=0x10,
                    new_exported_ordinal=405,
                    new_route=sblp.ROUTE_NATIVE_STORM,
                    new_degraded_reason=sblp.DEGRADED_UNSUPPORTED_FLAGS,
                    new_disposition=sblp.DISPOSITION_FALLBACK_DEGRADED,
                    stack=[0xABC0],
                ),
            ),
            version=version,
        )

        result = sblp.analyze_bytes(data)

        self.assertEqual(result["summary"]["liveAllocationCount"], 1)
        allocation = result["liveAllocations"][0]
        self.assertEqual(allocation["domain"], "native")
        self.assertEqual(allocation["metadata"]["route"], "native-storm")
        self.assertEqual(
            allocation["metadata"]["degradedReason"], "unsupported-flags"
        )
        event = result["events"][1]
        self.assertEqual(event["newDomain"], "native")
        self.assertEqual(event["metadata"]["route"], "tlsf")
        self.assertEqual(event["newMetadata"]["route"], "native-storm")
        self.assertTrue(event["fallback"])
        self.assertTrue(event["degraded"])
        self.assertEqual(result["metadataSummary"]["records"], 3)

    def test_v2_checkpoint_decodes_takeover_and_dropped_state(self) -> None:
        version = sblp.CURRENT_FILE_VERSION
        route_latencies = [
            {"sampleCount": index + 1, "p99Nanoseconds": (index + 1) * 10}
            for index in range(5)
        ]
        checkpoint = sblp.encode_checkpoint(
            version=version,
            timestamp_qpc=999,
            events_enqueued=50,
            events_written=47,
            dropped=3,
            queue_depth=0,
            managed_events=30,
            native_events=20,
            fallback_events=4,
            degraded_events=5,
            takeover={
                "managedApiCalls": 100,
                "nativeApiCalls": 25,
                "managedFallbackCalls": 2,
                "nativeFallbackCalls": 3,
                "degradedCalls": 6,
                "registryInsertFailures": 1,
                "registryCapacity": 16384,
                "registryActive": 12,
                "registryDestroying": 1,
                "registryTombstones": 7,
                "registryNativeDelegated": 2,
                "stormOptionFlags": 0x0F,
                "lastHeapId": 0x80000007,
                "lastStormFlags": 0x10,
                "lastExportedOrdinal": 489,
                "lastRoute": sblp.ROUTE_MIMALLOC,
                "lastDegradedReason": sblp.DEGRADED_PROTECT_MEMORY,
            },
            route_latencies=route_latencies,
        )
        result = sblp.analyze_bytes(
            stream(
                sblp.build_record(sblp.TYPE_CHECKPOINT, 1, checkpoint),
                version=version,
            )
        )

        self.assertFalse(result["integrity"]["complete"])
        self.assertTrue(result["integrity"]["producerIncomplete"])
        parsed = result["checkpoints"][0]
        self.assertEqual(parsed["payloadVersion"], 2)
        self.assertEqual(parsed["managedEvents"], 30)
        self.assertEqual(parsed["fallbackEvents"], 4)
        self.assertEqual(parsed["takeover"]["managedApiCalls"], 100)
        self.assertEqual(parsed["takeover"]["registry"]["capacity"], 16384)
        self.assertEqual(parsed["takeover"]["last"]["heapIdHex"], "0x80000007")
        self.assertEqual(parsed["takeover"]["last"]["route"], "mimalloc")
        self.assertEqual(
            parsed["takeover"]["last"]["degradedReason"], "protect-memory"
        )
        self.assertEqual(parsed["routeLatency"]["tlsf"]["sampleCount"], 3)
        self.assertEqual(parsed["routeLatency"]["tlsf"]["p99Nanoseconds"], 30)

    def test_v2_truncated_tail_keeps_metadata_rich_prefix(self) -> None:
        version = sblp.CURRENT_FILE_VERSION
        first = sblp.build_record(
            sblp.TYPE_ALLOC,
            1,
            sblp.encode_alloc_or_free(
                sblp.TYPE_ALLOC,
                pointer=0x5000,
                size=512,
                version=version,
                heap_id=77,
                exported_ordinal=403,
                route=sblp.ROUTE_TLSF,
            ),
        )
        tail = sblp.build_record(
            sblp.TYPE_STORM_API,
            2,
            sblp.encode_storm_api(
                primary_value=1,
                secondary_value=2,
                exported_ordinal=406,
            ),
        )

        result = sblp.analyze_bytes(
            stream(first, tail[:-9], version=version)
        )

        self.assertTrue(result["integrity"]["truncatedTail"])
        self.assertFalse(result["integrity"]["complete"])
        self.assertEqual(result["summary"]["liveAllocationCount"], 1)
        self.assertEqual(result["liveAllocations"][0]["metadata"]["heapId"], 77)
        self.assertEqual(result["summary"]["eventCounts"]["stormApi"], 0)

    def test_v2_unknown_metadata_values_are_lossless(self) -> None:
        version = sblp.CURRENT_FILE_VERSION
        # Build this payload independently of the fixture encoder so the test
        # also locks the byte order and exact field order used by the C++ writer.
        payload = struct.pack(
            "<QIBBHIIHBBBBHQQ",
            0,
            1,
            sblp.DOMAIN_MANAGED,
            0,
            0,
            0,
            0,
            0,
            99,
            98,
            97,
            0,
            0,
            0x6000,
            1,
        )
        data = stream(
            sblp.build_record(
                sblp.TYPE_ALLOC,
                1,
                payload,
            ),
            version=version,
        )

        metadata = sblp.analyze_bytes(data)["events"][0]["metadata"]

        self.assertEqual(metadata["route"], "unknown:99")
        self.assertEqual(metadata["routeValue"], 99)
        self.assertEqual(metadata["degradedReason"], "unknown:98")
        self.assertEqual(metadata["degradedReasonValue"], 98)
        self.assertEqual(metadata["disposition"], "unknown:97")
        self.assertEqual(metadata["dispositionValue"], 97)


if __name__ == "__main__":
    unittest.main()
