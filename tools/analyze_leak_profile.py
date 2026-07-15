#!/usr/bin/env python3
"""Recover and analyze StormBreaker SBLP v1 and v2 leak profiles.

All integers are little endian. The 32-byte file header is::

    <4s HH BBBB I QQ
    magic, version, header_size, endian, pointer_size, mode, reserved,
    process_id, start_unix_ns, qpc_frequency

Every append-only record is ``header + payload + crc32``. The 24-byte record
header is ``<4s I HH Q I``: magic ``SBLR``, total length, type, header size,
sequence, and payload length. CRC32 covers the record header and payload.

Event payloads use a 16-byte ``<Q I BB H`` prefix (QPC, thread, domain, stack
depth, flags). SBLP v2 follows that prefix with 16 bytes of heap/route/fallback
metadata. ReallocOutcome carries a second metadata block for its destination,
and v2 adds StormApi records plus an extended checkpoint. Event stacks remain
``stack_depth`` 64-bit addresses. EpochMarker and ModuleSnapshot are unchanged.
"""

from __future__ import annotations

import argparse
import json
import ntpath
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


FILE_MAGIC = b"SBLP"
RECORD_MAGIC = b"SBLR"
FILE_VERSION = 1  # Legacy fixture-builder default; the current writer uses v2.
CURRENT_FILE_VERSION = 2
SUPPORTED_FILE_VERSIONS = (FILE_VERSION, CURRENT_FILE_VERSION)
FILE_HEADER = struct.Struct("<4sHHBBBBIQQ")
RECORD_HEADER = struct.Struct("<4sIHHQI")
COMMON_EVENT = struct.Struct("<QIBBH")
EVENT_METADATA = struct.Struct("<IIHBBBBH")
ALLOC_FREE_FIXED = struct.Struct("<QQ")
REALLOC_FIXED = struct.Struct("<QQQQ")
REALLOC_V2_DOMAIN = struct.Struct("<BBH")
STORM_API_FIXED = struct.Struct("<QQ")
EPOCH_PAYLOAD = struct.Struct("<QQII")
CHECKPOINT_PAYLOAD = struct.Struct("<QQQQIBBH")
CHECKPOINT_V2_EVENT_COUNTS = struct.Struct("<QQQQ")
CHECKPOINT_V2_TAKEOVER = struct.Struct("<QQQQQQIIIIIIIIHBBBBH")
ROUTE_LATENCY = struct.Struct("<QQQQQQ")
MODULE_FIXED = struct.Struct("<QQH")
CRC = struct.Struct("<I")
MAX_RECORD_LENGTH = 1024 * 1024
MAX_STACK_DEPTH = 16
CHECKPOINT_V2_PAYLOAD_VERSION = 2

TYPE_ALLOC = 1
TYPE_FREE = 2
TYPE_REALLOC = 3
TYPE_EPOCH = 4
TYPE_CHECKPOINT = 5
TYPE_MODULE = 6
TYPE_STORM_API = 7

DOMAIN_NATIVE = 1
DOMAIN_MANAGED = 2

FLAG_NATIVE_SAMPLED = 0x0001
REALLOC_OLD_FREED = 0x0001
REALLOC_NEW_ALLOCATED = 0x0002
REALLOC_IN_PLACE = 0x0004
REALLOC_OLD_TRACKED = 0x0008
REALLOC_NEW_TRACKED = 0x0010
REALLOC_OLD_SAMPLED = 0x0020
REALLOC_NEW_SAMPLED = 0x0040
REALLOC_NEW_DOMAIN_MANAGED = 0x0080
EPOCH_REASON_RESET_HEURISTIC = 1
EPOCH_REASON_CLEANUP = 2

ROUTE_UNKNOWN = 0
ROUTE_NATIVE_STORM = 1
ROUTE_TLSF = 2
ROUTE_MIMALLOC = 3
ROUTE_TLSF_SHARDED = 4

DEGRADED_NONE = 0
DEGRADED_INTENTIONAL_NATIVE = 1
DEGRADED_HOOK_BYPASS = 2
DEGRADED_UNSAFE_PERIOD = 3
DEGRADED_BELOW_TAKEOVER_THRESHOLD = 4
DEGRADED_UNKNOWN_HEAP = 5
DEGRADED_REGISTRY_CAPACITY = 6
DEGRADED_BACKEND_UNAVAILABLE = 7
DEGRADED_BACKEND_OUT_OF_MEMORY = 8
DEGRADED_REQUESTED_BUDGET_EXCEEDED = 9
DEGRADED_UNSUPPORTED_FLAGS = 10
DEGRADED_PROTECT_MEMORY = 11
DEGRADED_POINTER_REJECTED = 12
DEGRADED_NATIVE_EXCEPTION = 13
DEGRADED_INITIALIZATION_FAILURE = 14
DEGRADED_EXPLICIT_NATIVE_HEAP = 15

DISPOSITION_NORMAL = 0
DISPOSITION_FALLBACK = 1
DISPOSITION_DEGRADED = 2
DISPOSITION_FALLBACK_DEGRADED = 3


class SblpFormatError(ValueError):
    """Raised when the file header is not a supported SBLP stream."""


@dataclass
class _Allocation:
    address: int
    size: int
    domain: int
    caller: int
    stack: list[int]
    sequence: int
    sampled: bool
    metadata: _EventMetadata | None = None
    epochs_survived: int = 0
    first_survivor_epoch: int | None = None
    last_survivor_epoch: int | None = None


@dataclass
class _Integrity:
    records_read: int = 0
    bad_crc_records: int = 0
    malformed_records: int = 0
    malformed_payloads: int = 0
    unknown_record_types: int = 0
    skipped_bytes: int = 0
    sequence_gaps: int = 0
    non_monotonic_sequences: int = 0
    truncated_tail: bool = False
    producer_incomplete: bool = False
    writer_error: bool = False
    checkpoints: int = 0


@dataclass(frozen=True)
class _EventMetadata:
    heap_id: int = 0
    storm_flags: int = 0
    exported_ordinal: int = 0
    route: int = ROUTE_UNKNOWN
    degraded_reason: int = DEGRADED_NONE
    disposition: int = DISPOSITION_NORMAL


@dataclass(frozen=True)
class _Module:
    base: int
    size: int
    path: str


@dataclass
class _GroupHistory:
    last_count: int = 0
    last_bytes: int = 0
    last_epoch_ordinal: int = 0
    growth_streak: int = 0
    candidate: bool = False


def _mode_name(mode: int) -> str:
    return {0: "off", 1: "sampled", 2: "full"}.get(mode, "unknown")


def _domain_name(domain: int) -> str:
    return {
        DOMAIN_NATIVE: "native",
        DOMAIN_MANAGED: "managed",
    }.get(domain, f"unknown:{domain}")


def _route_name(route: int) -> str:
    return {
        ROUTE_UNKNOWN: "unknown",
        ROUTE_NATIVE_STORM: "native-storm",
        ROUTE_TLSF: "tlsf",
        ROUTE_MIMALLOC: "mimalloc",
        ROUTE_TLSF_SHARDED: "tlsf-sharded",
    }.get(route, f"unknown:{route}")


def _degraded_reason_name(reason: int) -> str:
    return {
        DEGRADED_NONE: "none",
        DEGRADED_INTENTIONAL_NATIVE: "intentional-native",
        DEGRADED_HOOK_BYPASS: "hook-bypass",
        DEGRADED_UNSAFE_PERIOD: "unsafe-period",
        DEGRADED_BELOW_TAKEOVER_THRESHOLD: "below-takeover-threshold",
        DEGRADED_UNKNOWN_HEAP: "unknown-heap",
        DEGRADED_REGISTRY_CAPACITY: "registry-capacity",
        DEGRADED_BACKEND_UNAVAILABLE: "backend-unavailable",
        DEGRADED_BACKEND_OUT_OF_MEMORY: "backend-out-of-memory",
        DEGRADED_REQUESTED_BUDGET_EXCEEDED: "requested-budget-exceeded",
        DEGRADED_UNSUPPORTED_FLAGS: "unsupported-flags",
        DEGRADED_PROTECT_MEMORY: "protect-memory",
        DEGRADED_POINTER_REJECTED: "pointer-rejected",
        DEGRADED_NATIVE_EXCEPTION: "native-exception",
        DEGRADED_INITIALIZATION_FAILURE: "initialization-failure",
        DEGRADED_EXPLICIT_NATIVE_HEAP: "explicit-native-heap",
    }.get(reason, f"unknown:{reason}")


def _disposition_name(disposition: int) -> str:
    return {
        DISPOSITION_NORMAL: "normal",
        DISPOSITION_FALLBACK: "fallback",
        DISPOSITION_DEGRADED: "degraded",
        DISPOSITION_FALLBACK_DEGRADED: "fallback-degraded",
    }.get(disposition, f"unknown:{disposition}")


def _is_fallback(metadata: _EventMetadata | None) -> bool:
    return metadata is not None and bool(metadata.disposition & 1)


def _is_degraded(metadata: _EventMetadata | None) -> bool:
    return metadata is not None and (
        bool(metadata.disposition & 2)
        or metadata.degraded_reason != DEGRADED_NONE
    )


def _hex_address(value: int) -> str:
    return f"0x{value:016x}"


def _hex_u32(value: int) -> str:
    return f"0x{value:08x}"


def _metadata_json(metadata: _EventMetadata | None) -> dict[str, Any] | None:
    if metadata is None:
        return None
    return {
        "heapId": metadata.heap_id,
        "heapIdHex": _hex_u32(metadata.heap_id),
        "stormFlags": metadata.storm_flags,
        "stormFlagsHex": _hex_u32(metadata.storm_flags),
        "exportedOrdinal": metadata.exported_ordinal,
        "route": _route_name(metadata.route),
        "routeValue": metadata.route,
        "degradedReason": _degraded_reason_name(metadata.degraded_reason),
        "degradedReasonValue": metadata.degraded_reason,
        "disposition": _disposition_name(metadata.disposition),
        "dispositionValue": metadata.disposition,
        "fallback": _is_fallback(metadata),
        "degraded": _is_degraded(metadata),
    }


def _decode_event_metadata(payload: bytes, offset: int) -> _EventMetadata:
    (
        heap_id,
        storm_flags,
        exported_ordinal,
        route,
        degraded_reason,
        disposition,
        _reserved8,
        _reserved16,
    ) = EVENT_METADATA.unpack_from(payload, offset)
    return _EventMetadata(
        heap_id=heap_id,
        storm_flags=storm_flags,
        exported_ordinal=exported_ordinal,
        route=route,
        degraded_reason=degraded_reason,
        disposition=disposition,
    )


def encode_event_metadata(
    *,
    heap_id: int = 0,
    storm_flags: int = 0,
    exported_ordinal: int = 0,
    route: int = ROUTE_UNKNOWN,
    degraded_reason: int = DEGRADED_NONE,
    disposition: int = DISPOSITION_NORMAL,
) -> bytes:
    """Encode the fixed SBLP v2 event metadata block for test fixtures."""
    return EVENT_METADATA.pack(
        heap_id,
        storm_flags,
        exported_ordinal,
        route,
        degraded_reason,
        disposition,
        0,
        0,
    )


def _resolve_address(value: int, modules: list[_Module]) -> dict[str, Any]:
    location: dict[str, Any] = {"address": _hex_address(value)}
    if value == 0:
        return location
    matches = [
        module
        for module in modules
        if module.base <= value < module.base + module.size
    ]
    if not matches:
        return location
    module = max(matches, key=lambda item: item.base)
    location.update(
        {
            "module": ntpath.basename(module.path),
            "modulePath": module.path,
            "rva": f"0x{value - module.base:08x}",
        }
    )
    return location


def build_file_header(
    *,
    version: int = FILE_VERSION,
    mode: int = 2,
    pointer_size: int = 8,
    process_id: int = 1,
    start_unix_ns: int = 0,
    qpc_frequency: int = 10_000_000,
) -> bytes:
    """Build an SBLP header. Primarily useful for parser test fixtures."""
    if version not in SUPPORTED_FILE_VERSIONS:
        raise ValueError(f"unsupported fixture SBLP version: {version}")
    return FILE_HEADER.pack(
        FILE_MAGIC,
        version,
        FILE_HEADER.size,
        1,
        pointer_size,
        mode,
        0,
        process_id,
        start_unix_ns,
        qpc_frequency,
    )


def build_record(record_type: int, sequence: int, payload: bytes) -> bytes:
    """Build one checksummed SBLP record."""
    total_length = RECORD_HEADER.size + len(payload) + CRC.size
    header = RECORD_HEADER.pack(
        RECORD_MAGIC,
        total_length,
        record_type,
        RECORD_HEADER.size,
        sequence,
        len(payload),
    )
    body = header + payload
    return body + CRC.pack(zlib.crc32(body) & 0xFFFFFFFF)


def encode_alloc_or_free(
    record_type: int,
    *,
    pointer: int,
    size: int,
    domain: int = DOMAIN_MANAGED,
    stack: Iterable[int] = (),
    timestamp_qpc: int = 0,
    thread_id: int = 1,
    flags: int = 0,
    version: int = FILE_VERSION,
    heap_id: int = 0,
    storm_flags: int = 0,
    exported_ordinal: int = 0,
    route: int = ROUTE_UNKNOWN,
    degraded_reason: int = DEGRADED_NONE,
    disposition: int = DISPOSITION_NORMAL,
) -> bytes:
    frames = tuple(stack)
    if len(frames) > MAX_STACK_DEPTH:
        raise ValueError("SBLP stacks are limited to 16 frames")
    if version not in SUPPORTED_FILE_VERSIONS:
        raise ValueError(f"unsupported fixture SBLP version: {version}")
    payload = COMMON_EVENT.pack(
        timestamp_qpc, thread_id, domain, len(frames), flags
    )
    if version >= CURRENT_FILE_VERSION:
        payload += encode_event_metadata(
            heap_id=heap_id,
            storm_flags=storm_flags,
            exported_ordinal=exported_ordinal,
            route=route,
            degraded_reason=degraded_reason,
            disposition=disposition,
        )
    return (
        payload
        + ALLOC_FREE_FIXED.pack(pointer, size)
        + struct.pack(f"<{len(frames)}Q", *frames)
    )


def encode_realloc(
    *,
    old_pointer: int,
    new_pointer: int,
    old_size: int,
    new_size: int,
    flags: int,
    domain: int = DOMAIN_MANAGED,
    new_domain: int | None = None,
    stack: Iterable[int] = (),
    timestamp_qpc: int = 0,
    thread_id: int = 1,
    version: int = FILE_VERSION,
    heap_id: int = 0,
    storm_flags: int = 0,
    exported_ordinal: int = 0,
    route: int = ROUTE_UNKNOWN,
    degraded_reason: int = DEGRADED_NONE,
    disposition: int = DISPOSITION_NORMAL,
    new_heap_id: int = 0,
    new_storm_flags: int = 0,
    new_exported_ordinal: int = 0,
    new_route: int = ROUTE_UNKNOWN,
    new_degraded_reason: int = DEGRADED_NONE,
    new_disposition: int = DISPOSITION_NORMAL,
) -> bytes:
    frames = tuple(stack)
    if len(frames) > MAX_STACK_DEPTH:
        raise ValueError("SBLP stacks are limited to 16 frames")
    if version not in SUPPORTED_FILE_VERSIONS:
        raise ValueError(f"unsupported fixture SBLP version: {version}")
    if new_domain is None:
        new_domain = domain
    if new_domain == DOMAIN_MANAGED:
        flags |= REALLOC_NEW_DOMAIN_MANAGED
    payload = COMMON_EVENT.pack(
        timestamp_qpc, thread_id, domain, len(frames), flags
    )
    if version >= CURRENT_FILE_VERSION:
        payload += encode_event_metadata(
            heap_id=heap_id,
            storm_flags=storm_flags,
            exported_ordinal=exported_ordinal,
            route=route,
            degraded_reason=degraded_reason,
            disposition=disposition,
        )
    payload += REALLOC_FIXED.pack(
        old_pointer, new_pointer, old_size, new_size
    )
    if version >= CURRENT_FILE_VERSION:
        payload += REALLOC_V2_DOMAIN.pack(new_domain, 0, 0)
        payload += encode_event_metadata(
            heap_id=new_heap_id,
            storm_flags=new_storm_flags,
            exported_ordinal=new_exported_ordinal,
            route=new_route,
            degraded_reason=new_degraded_reason,
            disposition=new_disposition,
        )
    return payload + struct.pack(f"<{len(frames)}Q", *frames)


def encode_storm_api(
    *,
    primary_value: int,
    secondary_value: int,
    domain: int = DOMAIN_NATIVE,
    stack: Iterable[int] = (),
    timestamp_qpc: int = 0,
    thread_id: int = 1,
    flags: int = 0,
    heap_id: int = 0,
    storm_flags: int = 0,
    exported_ordinal: int = 0,
    route: int = ROUTE_UNKNOWN,
    degraded_reason: int = DEGRADED_NONE,
    disposition: int = DISPOSITION_NORMAL,
) -> bytes:
    """Encode an SBLP v2 StormApi payload for parser test fixtures."""
    frames = tuple(stack)
    if len(frames) > MAX_STACK_DEPTH:
        raise ValueError("SBLP stacks are limited to 16 frames")
    return (
        COMMON_EVENT.pack(
            timestamp_qpc, thread_id, domain, len(frames), flags
        )
        + encode_event_metadata(
            heap_id=heap_id,
            storm_flags=storm_flags,
            exported_ordinal=exported_ordinal,
            route=route,
            degraded_reason=degraded_reason,
            disposition=disposition,
        )
        + STORM_API_FIXED.pack(primary_value, secondary_value)
        + struct.pack(f"<{len(frames)}Q", *frames)
    )


def encode_epoch(
    epoch: int, *, timestamp_qpc: int = 0, reason: int = 0, thread_id: int = 1
) -> bytes:
    return EPOCH_PAYLOAD.pack(timestamp_qpc, epoch, reason, thread_id)


def encode_checkpoint(
    *,
    timestamp_qpc: int = 0,
    events_enqueued: int = 0,
    events_written: int = 0,
    dropped: int = 0,
    queue_depth: int = 0,
    incomplete: bool = False,
    writer_error: bool = False,
    version: int = FILE_VERSION,
    managed_events: int = 0,
    native_events: int = 0,
    fallback_events: int = 0,
    degraded_events: int = 0,
    takeover: dict[str, int] | None = None,
    route_latencies: Iterable[dict[str, int]] | None = None,
) -> bytes:
    if version not in SUPPORTED_FILE_VERSIONS:
        raise ValueError(f"unsupported fixture SBLP version: {version}")
    payload = CHECKPOINT_PAYLOAD.pack(
        timestamp_qpc,
        events_enqueued,
        events_written,
        dropped,
        queue_depth,
        int(incomplete),
        int(writer_error),
        CHECKPOINT_V2_PAYLOAD_VERSION
        if version >= CURRENT_FILE_VERSION
        else 0,
    )
    if version < CURRENT_FILE_VERSION:
        return payload

    values = takeover or {}
    latencies = list(route_latencies or ({}, {}, {}, {}, {}))
    if len(latencies) > 0xFF:
        raise ValueError("too many route latency entries")
    payload += CHECKPOINT_V2_EVENT_COUNTS.pack(
        managed_events,
        native_events,
        fallback_events,
        degraded_events,
    )
    payload += CHECKPOINT_V2_TAKEOVER.pack(
        values.get("managedApiCalls", 0),
        values.get("nativeApiCalls", 0),
        values.get("managedFallbackCalls", 0),
        values.get("nativeFallbackCalls", 0),
        values.get("degradedCalls", 0),
        values.get("registryInsertFailures", 0),
        values.get("registryCapacity", 0),
        values.get("registryActive", 0),
        values.get("registryDestroying", 0),
        values.get("registryTombstones", 0),
        values.get("registryNativeDelegated", 0),
        values.get("stormOptionFlags", 0),
        values.get("lastHeapId", 0),
        values.get("lastStormFlags", 0),
        values.get("lastExportedOrdinal", 0),
        values.get("lastRoute", ROUTE_UNKNOWN),
        values.get("lastDegradedReason", DEGRADED_NONE),
        len(latencies),
        0,
        0,
    )
    for latency in latencies:
        payload += ROUTE_LATENCY.pack(
            latency.get("sampleCount", 0),
            latency.get("totalNanoseconds", 0),
            latency.get("maxNanoseconds", 0),
            latency.get("p50Nanoseconds", 0),
            latency.get("p95Nanoseconds", 0),
            latency.get("p99Nanoseconds", 0),
        )
    return payload


def encode_module(base: int, size: int, path: str) -> bytes:
    encoded = path.encode("utf-8")
    if len(encoded) > 0xFFFF:
        raise ValueError("module path is too long")
    return MODULE_FIXED.pack(base, size, len(encoded)) + encoded


def _parse_header(data: bytes) -> tuple[dict[str, Any], int]:
    if len(data) < FILE_HEADER.size:
        raise SblpFormatError("truncated SBLP file header")
    (
        magic,
        version,
        header_size,
        endian,
        pointer_size,
        mode,
        _reserved,
        process_id,
        start_unix_ns,
        qpc_frequency,
    ) = FILE_HEADER.unpack_from(data)
    if magic != FILE_MAGIC:
        raise SblpFormatError("not an SBLP file")
    if version not in SUPPORTED_FILE_VERSIONS:
        raise SblpFormatError(f"unsupported SBLP version: {version}")
    if endian != 1:
        raise SblpFormatError("only little-endian SBLP streams are supported")
    if header_size < FILE_HEADER.size or header_size > len(data):
        raise SblpFormatError("invalid or truncated extended file header")
    if pointer_size not in (4, 8):
        raise SblpFormatError(f"invalid pointer size: {pointer_size}")
    return (
        {
            "magic": "SBLP",
            "version": version,
            "headerSize": header_size,
            "endian": "little",
            "pointerSize": pointer_size,
            "mode": _mode_name(mode),
            "modeValue": mode,
            "processId": process_id,
            "startUnixNs": start_unix_ns,
            "qpcFrequency": qpc_frequency,
        },
        header_size,
    )


def _iter_records(
    data: bytes, start: int, integrity: _Integrity
) -> Iterable[tuple[int, int, bytes]]:
    offset = start
    last_sequence = 0

    while offset < len(data):
        marker = data.find(RECORD_MAGIC, offset)
        if marker < 0:
            integrity.skipped_bytes += len(data) - offset
            integrity.truncated_tail = True
            break
        if marker > offset:
            integrity.skipped_bytes += marker - offset
        if len(data) - marker < RECORD_HEADER.size:
            integrity.truncated_tail = True
            break

        (
            magic,
            total_length,
            record_type,
            header_size,
            sequence,
            payload_length,
        ) = RECORD_HEADER.unpack_from(data, marker)
        expected_length = header_size + payload_length + CRC.size
        if (
            magic != RECORD_MAGIC
            or header_size != RECORD_HEADER.size
            or total_length != expected_length
            or total_length < RECORD_HEADER.size + CRC.size
            or total_length > MAX_RECORD_LENGTH
        ):
            integrity.malformed_records += 1
            offset = marker + 1
            continue
        if marker + total_length > len(data):
            next_marker = data.find(RECORD_MAGIC, marker + len(RECORD_MAGIC))
            if next_marker >= 0:
                integrity.malformed_records += 1
                integrity.skipped_bytes += next_marker - marker
                offset = next_marker
                continue
            integrity.truncated_tail = True
            break

        crc_offset = marker + total_length - CRC.size
        expected_crc = CRC.unpack_from(data, crc_offset)[0]
        actual_crc = zlib.crc32(data[marker:crc_offset]) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            integrity.bad_crc_records += 1
            offset = marker + total_length
            continue

        if sequence <= last_sequence:
            integrity.non_monotonic_sequences += 1
        else:
            if sequence > last_sequence + 1:
                integrity.sequence_gaps += sequence - last_sequence - 1
            last_sequence = sequence

        integrity.records_read += 1
        payload_start = marker + header_size
        yield record_type, sequence, data[payload_start:crc_offset]
        offset = marker + total_length


def _decode_stack(
    payload: bytes, fixed_size: int, depth: int
) -> list[int] | None:
    expected = fixed_size + depth * 8
    if depth > MAX_STACK_DEPTH or len(payload) != expected:
        return None
    if depth == 0:
        return []
    return list(struct.unpack_from(f"<{depth}Q", payload, fixed_size))


def _decode_checkpoint(
    payload: bytes, sequence: int, file_version: int
) -> dict[str, Any] | None:
    if len(payload) < CHECKPOINT_PAYLOAD.size:
        return None
    (
        timestamp_qpc,
        events_enqueued,
        events_written,
        dropped,
        queue_depth,
        incomplete,
        writer_error,
        payload_version,
    ) = CHECKPOINT_PAYLOAD.unpack_from(payload)
    checkpoint: dict[str, Any] = {
        "sequence": sequence,
        "timestampQpc": timestamp_qpc,
        "eventsEnqueued": events_enqueued,
        "eventsWritten": events_written,
        "dropped": dropped,
        "queueDepth": queue_depth,
        "incomplete": bool(incomplete),
        "writerError": bool(writer_error),
    }
    if file_version == FILE_VERSION:
        return checkpoint if len(payload) == CHECKPOINT_PAYLOAD.size else None
    if payload_version != CHECKPOINT_V2_PAYLOAD_VERSION:
        return None

    fixed_size = (
        CHECKPOINT_PAYLOAD.size
        + CHECKPOINT_V2_EVENT_COUNTS.size
        + CHECKPOINT_V2_TAKEOVER.size
    )
    if len(payload) < fixed_size:
        return None
    offset = CHECKPOINT_PAYLOAD.size
    (
        managed_events,
        native_events,
        fallback_events,
        degraded_events,
    ) = CHECKPOINT_V2_EVENT_COUNTS.unpack_from(payload, offset)
    offset += CHECKPOINT_V2_EVENT_COUNTS.size
    (
        managed_api_calls,
        native_api_calls,
        managed_fallback_calls,
        native_fallback_calls,
        degraded_calls,
        registry_insert_failures,
        registry_capacity,
        registry_active,
        registry_destroying,
        registry_tombstones,
        registry_native_delegated,
        storm_option_flags,
        last_heap_id,
        last_storm_flags,
        last_exported_ordinal,
        last_route,
        last_degraded_reason,
        route_count,
        _reserved8,
        _reserved16,
    ) = CHECKPOINT_V2_TAKEOVER.unpack_from(payload, offset)
    offset += CHECKPOINT_V2_TAKEOVER.size
    if len(payload) != offset + route_count * ROUTE_LATENCY.size:
        return None

    route_latency: dict[str, dict[str, int]] = {}
    for route in range(route_count):
        (
            sample_count,
            total_nanoseconds,
            max_nanoseconds,
            p50_nanoseconds,
            p95_nanoseconds,
            p99_nanoseconds,
        ) = ROUTE_LATENCY.unpack_from(payload, offset)
        offset += ROUTE_LATENCY.size
        route_latency[_route_name(route)] = {
            "routeValue": route,
            "sampleCount": sample_count,
            "totalNanoseconds": total_nanoseconds,
            "maxNanoseconds": max_nanoseconds,
            "p50Nanoseconds": p50_nanoseconds,
            "p95Nanoseconds": p95_nanoseconds,
            "p99Nanoseconds": p99_nanoseconds,
        }

    checkpoint.update(
        {
            "payloadVersion": payload_version,
            "managedEvents": managed_events,
            "nativeEvents": native_events,
            "fallbackEvents": fallback_events,
            "degradedEvents": degraded_events,
            "takeover": {
                "managedApiCalls": managed_api_calls,
                "nativeApiCalls": native_api_calls,
                "managedFallbackCalls": managed_fallback_calls,
                "nativeFallbackCalls": native_fallback_calls,
                "degradedCalls": degraded_calls,
                "stormOptionFlags": storm_option_flags,
                "stormOptionFlagsHex": _hex_u32(storm_option_flags),
                "last": {
                    "heapId": last_heap_id,
                    "heapIdHex": _hex_u32(last_heap_id),
                    "stormFlags": last_storm_flags,
                    "stormFlagsHex": _hex_u32(last_storm_flags),
                    "exportedOrdinal": last_exported_ordinal,
                    "route": _route_name(last_route),
                    "routeValue": last_route,
                    "degradedReason": _degraded_reason_name(
                        last_degraded_reason
                    ),
                    "degradedReasonValue": last_degraded_reason,
                },
                "registry": {
                    "capacity": registry_capacity,
                    "active": registry_active,
                    "destroying": registry_destroying,
                    "tombstones": registry_tombstones,
                    "nativeDelegated": registry_native_delegated,
                    "insertFailures": registry_insert_failures,
                },
            },
            "routeLatency": route_latency,
        }
    )
    return checkpoint


def _increment_count(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def _note_metadata(
    metadata: _EventMetadata | None,
    counts: dict[str, dict[str, int]],
) -> None:
    if metadata is None:
        return
    _increment_count(counts["byHeapId"], _hex_u32(metadata.heap_id))
    _increment_count(counts["byStormFlags"], _hex_u32(metadata.storm_flags))
    _increment_count(
        counts["byExportedOrdinal"], str(metadata.exported_ordinal)
    )
    _increment_count(counts["byRoute"], _route_name(metadata.route))
    _increment_count(
        counts["byDegradedReason"],
        _degraded_reason_name(metadata.degraded_reason),
    )
    _increment_count(
        counts["byDisposition"], _disposition_name(metadata.disposition)
    )


def _allocation_json(
    allocation: _Allocation,
    modules: list[_Module],
    candidate_groups: set[tuple[int, int, int]],
) -> dict[str, Any]:
    group_key = (allocation.domain, allocation.caller, allocation.size)
    return {
        "address": _hex_address(allocation.address),
        "size": allocation.size,
        "domain": _domain_name(allocation.domain),
        "caller": _hex_address(allocation.caller),
        "callerLocation": _resolve_address(allocation.caller, modules),
        "stack": [_hex_address(frame) for frame in allocation.stack],
        "stackLocations": [
            _resolve_address(frame, modules) for frame in allocation.stack
        ],
        "allocatedSequence": allocation.sequence,
        "sampled": allocation.sampled,
        "metadata": _metadata_json(allocation.metadata),
        "epochsSurvived": allocation.epochs_survived,
        "firstSurvivorEpoch": allocation.first_survivor_epoch,
        "lastSurvivorEpoch": allocation.last_survivor_epoch,
        "leakCandidate": group_key in candidate_groups,
    }


def analyze_bytes(data: bytes, *, source: str = "<memory>") -> dict[str, Any]:
    """Analyze one SBLP byte stream and return a JSON-serializable object."""
    header, records_offset = _parse_header(data)
    integrity = _Integrity()
    live: dict[int, _Allocation] = {}
    survivors: list[dict[str, Any]] = []
    epoch_markers: list[dict[str, Any]] = []
    checkpoints: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    modules: list[_Module] = []
    group_history: dict[tuple[int, int, int], _GroupHistory] = {}
    metadata_counts: dict[str, dict[str, int]] = {
        "byHeapId": {},
        "byStormFlags": {},
        "byExportedOrdinal": {},
        "byRoute": {},
        "byDegradedReason": {},
        "byDisposition": {},
    }

    event_counts = {
        "alloc": 0,
        "free": 0,
        "reallocOutcome": 0,
        "epochMarker": 0,
        "moduleSnapshot": 0,
        "stormApi": 0,
    }
    unknown_frees = 0
    unknown_realloc_olds = 0
    replaced_allocations = 0
    epoch_ordinal = 0
    metadata_records = 0
    fallback_event_count = 0
    degraded_event_count = 0
    file_version = int(header["version"])

    for record_type, sequence, payload in _iter_records(
        data, records_offset, integrity
    ):
        if record_type in (TYPE_ALLOC, TYPE_FREE):
            metadata_size = (
                EVENT_METADATA.size
                if file_version >= CURRENT_FILE_VERSION
                else 0
            )
            fixed_size = (
                COMMON_EVENT.size + metadata_size + ALLOC_FREE_FIXED.size
            )
            if len(payload) < fixed_size:
                integrity.malformed_payloads += 1
                continue
            timestamp_qpc, thread_id, domain, depth, flags = (
                COMMON_EVENT.unpack_from(payload)
            )
            metadata = (
                _decode_event_metadata(payload, COMMON_EVENT.size)
                if metadata_size
                else None
            )
            values_offset = COMMON_EVENT.size + metadata_size
            pointer, size = ALLOC_FREE_FIXED.unpack_from(
                payload, values_offset
            )
            stack = _decode_stack(payload, fixed_size, depth)
            if stack is None:
                integrity.malformed_payloads += 1
                continue
            event_name = "alloc" if record_type == TYPE_ALLOC else "free"
            event = {
                "type": event_name,
                "sequence": sequence,
                "timestampQpc": timestamp_qpc,
                "threadId": thread_id,
                "domain": _domain_name(domain),
                "domainValue": domain,
                "flags": flags,
                "sampled": bool(flags & FLAG_NATIVE_SAMPLED),
                "pointer": _hex_address(pointer),
                "size": size,
                "metadata": _metadata_json(metadata),
                "fallback": _is_fallback(metadata),
                "degraded": _is_degraded(metadata),
                "_stackValues": stack,
            }
            events.append(event)
            if metadata is not None:
                metadata_records += 1
                _note_metadata(metadata, metadata_counts)
                fallback_event_count += int(_is_fallback(metadata))
                degraded_event_count += int(_is_degraded(metadata))
            if record_type == TYPE_ALLOC:
                event_counts["alloc"] += 1
                if pointer in live:
                    replaced_allocations += 1
                live[pointer] = _Allocation(
                    address=pointer,
                    size=size,
                    domain=domain,
                    caller=stack[0] if stack else 0,
                    stack=stack,
                    sequence=sequence,
                    sampled=bool(flags & FLAG_NATIVE_SAMPLED),
                    metadata=metadata,
                )
            else:
                event_counts["free"] += 1
                if live.pop(pointer, None) is None:
                    unknown_frees += 1

        elif record_type == TYPE_REALLOC:
            metadata_size = (
                EVENT_METADATA.size
                if file_version >= CURRENT_FILE_VERSION
                else 0
            )
            fixed_size = COMMON_EVENT.size + metadata_size + REALLOC_FIXED.size
            if file_version >= CURRENT_FILE_VERSION:
                fixed_size += REALLOC_V2_DOMAIN.size + EVENT_METADATA.size
            if len(payload) < fixed_size:
                integrity.malformed_payloads += 1
                continue
            timestamp_qpc, thread_id, domain, depth, flags = (
                COMMON_EVENT.unpack_from(payload)
            )
            metadata = (
                _decode_event_metadata(payload, COMMON_EVENT.size)
                if metadata_size
                else None
            )
            values_offset = COMMON_EVENT.size + metadata_size
            old_pointer, new_pointer, old_size, new_size = (
                REALLOC_FIXED.unpack_from(payload, values_offset)
            )
            new_metadata: _EventMetadata | None = None
            if file_version >= CURRENT_FILE_VERSION:
                domain_offset = values_offset + REALLOC_FIXED.size
                new_domain, _reserved8, _reserved16 = (
                    REALLOC_V2_DOMAIN.unpack_from(payload, domain_offset)
                )
                new_metadata = _decode_event_metadata(
                    payload, domain_offset + REALLOC_V2_DOMAIN.size
                )
            else:
                new_domain = (
                    DOMAIN_MANAGED
                    if flags & REALLOC_NEW_DOMAIN_MANAGED
                    else DOMAIN_NATIVE
                )
            stack = _decode_stack(payload, fixed_size, depth)
            if stack is None:
                integrity.malformed_payloads += 1
                continue
            event_counts["reallocOutcome"] += 1

            previous = live.get(old_pointer)
            old_freed = bool(flags & REALLOC_OLD_FREED)
            new_allocated = bool(flags & REALLOC_NEW_ALLOCATED)
            old_tracked = bool(flags & REALLOC_OLD_TRACKED)
            new_tracked = bool(flags & REALLOC_NEW_TRACKED)
            in_place = bool(flags & REALLOC_IN_PLACE)
            event_fallback = _is_fallback(metadata) or _is_fallback(
                new_metadata
            )
            event_degraded = _is_degraded(metadata) or _is_degraded(
                new_metadata
            )
            events.append(
                {
                    "type": "reallocOutcome",
                    "sequence": sequence,
                    "timestampQpc": timestamp_qpc,
                    "threadId": thread_id,
                    "domain": _domain_name(domain),
                    "domainValue": domain,
                    "newDomain": _domain_name(new_domain),
                    "newDomainValue": new_domain,
                    "flags": flags,
                    "oldPointer": _hex_address(old_pointer),
                    "newPointer": _hex_address(new_pointer),
                    "oldSize": old_size,
                    "newSize": new_size,
                    "oldFreed": old_freed,
                    "newAllocated": new_allocated,
                    "inPlace": in_place,
                    "oldTracked": old_tracked,
                    "newTracked": new_tracked,
                    "oldSampled": bool(flags & REALLOC_OLD_SAMPLED),
                    "newSampled": bool(flags & REALLOC_NEW_SAMPLED),
                    "metadata": _metadata_json(metadata),
                    "newMetadata": _metadata_json(new_metadata),
                    "fallback": event_fallback,
                    "degraded": event_degraded,
                    "_stackValues": stack,
                }
            )
            for item in (metadata, new_metadata):
                if item is not None:
                    metadata_records += 1
                    _note_metadata(item, metadata_counts)
            fallback_event_count += int(event_fallback)
            degraded_event_count += int(event_degraded)

            if old_freed and old_tracked:
                if live.pop(old_pointer, None) is None:
                    unknown_realloc_olds += 1
            if new_allocated and new_tracked:
                if (
                    in_place
                    and old_pointer == new_pointer
                    and previous is not None
                ):
                    previous.size = new_size
                    previous.domain = new_domain
                    previous.sampled = bool(flags & REALLOC_NEW_SAMPLED)
                    previous.metadata = new_metadata
                    live[new_pointer] = previous
                else:
                    if new_pointer in live:
                        replaced_allocations += 1
                    live[new_pointer] = _Allocation(
                        address=new_pointer,
                        size=new_size,
                        domain=new_domain,
                        caller=stack[0] if stack else 0,
                        stack=stack,
                        sequence=sequence,
                        sampled=bool(flags & REALLOC_NEW_SAMPLED),
                        metadata=new_metadata,
                    )

        elif record_type == TYPE_STORM_API:
            if file_version < CURRENT_FILE_VERSION:
                integrity.unknown_record_types += 1
                continue
            fixed_size = (
                COMMON_EVENT.size
                + EVENT_METADATA.size
                + STORM_API_FIXED.size
            )
            if len(payload) < fixed_size:
                integrity.malformed_payloads += 1
                continue
            timestamp_qpc, thread_id, domain, depth, flags = (
                COMMON_EVENT.unpack_from(payload)
            )
            metadata = _decode_event_metadata(payload, COMMON_EVENT.size)
            primary_value, secondary_value = STORM_API_FIXED.unpack_from(
                payload, COMMON_EVENT.size + EVENT_METADATA.size
            )
            stack = _decode_stack(payload, fixed_size, depth)
            if stack is None:
                integrity.malformed_payloads += 1
                continue
            event_counts["stormApi"] += 1
            metadata_records += 1
            _note_metadata(metadata, metadata_counts)
            fallback_event_count += int(_is_fallback(metadata))
            degraded_event_count += int(_is_degraded(metadata))
            events.append(
                {
                    "type": "stormApi",
                    "sequence": sequence,
                    "timestampQpc": timestamp_qpc,
                    "threadId": thread_id,
                    "domain": _domain_name(domain),
                    "domainValue": domain,
                    "flags": flags,
                    "sampled": bool(flags & FLAG_NATIVE_SAMPLED),
                    "primaryValue": primary_value,
                    "primaryValueHex": _hex_address(primary_value),
                    "secondaryValue": secondary_value,
                    "secondaryValueHex": _hex_address(secondary_value),
                    "metadata": _metadata_json(metadata),
                    "fallback": _is_fallback(metadata),
                    "degraded": _is_degraded(metadata),
                    "_stackValues": stack,
                }
            )

        elif record_type == TYPE_EPOCH:
            if len(payload) != EPOCH_PAYLOAD.size:
                integrity.malformed_payloads += 1
                continue
            timestamp_qpc, epoch, reason, thread_id = EPOCH_PAYLOAD.unpack(
                payload
            )
            del timestamp_qpc, thread_id
            event_counts["epochMarker"] += 1
            reason_name = {
                EPOCH_REASON_RESET_HEURISTIC: "reset_heuristic",
                EPOCH_REASON_CLEANUP: "cleanup",
            }.get(reason, f"unknown:{reason}")
            epoch_markers.append(
                {
                    "sequence": sequence,
                    "epoch": epoch,
                    "reason": reason,
                    "reasonName": reason_name,
                }
            )
            # Only Reset is a logical map epoch. Cleanup and unknown markers
            # remain timeline context and never promote leak candidates.
            if reason != EPOCH_REASON_RESET_HEURISTIC:
                continue
            epoch_ordinal += 1
            groups: dict[tuple[int, int, int], dict[str, int]] = {}
            for allocation in live.values():
                allocation.epochs_survived += 1
                if allocation.first_survivor_epoch is None:
                    allocation.first_survivor_epoch = epoch
                allocation.last_survivor_epoch = epoch
                key = (allocation.domain, allocation.caller, allocation.size)
                group = groups.setdefault(
                    key,
                    {
                        "count": 0,
                        "bytes": 0,
                        "candidateCount": 0,
                        "candidateBytes": 0,
                        "maxEpochsSurvived": 0,
                    },
                )
                group["count"] += 1
                group["bytes"] += allocation.size
                group["maxEpochsSurvived"] = max(
                    group["maxEpochsSurvived"],
                    allocation.epochs_survived,
                )
            for key, history in group_history.items():
                if key not in groups:
                    history.last_count = 0
                    history.last_bytes = 0
                    history.last_epoch_ordinal = epoch_ordinal
                    history.growth_streak = 0
                    history.candidate = False

            for (domain, caller, size), group in sorted(groups.items()):
                key = (domain, caller, size)
                history = group_history.setdefault(key, _GroupHistory())
                consecutive = history.last_epoch_ordinal == epoch_ordinal - 1
                grew = group["count"] > history.last_count
                history.growth_streak = (
                    history.growth_streak + 1 if consecutive and grew else 0
                )
                history.candidate |= history.growth_streak >= 2
                history.last_count = group["count"]
                history.last_bytes = group["bytes"]
                history.last_epoch_ordinal = epoch_ordinal
                if history.candidate:
                    group["candidateCount"] = group["count"]
                    group["candidateBytes"] = group["bytes"]
                survivors.append(
                    {
                        "epoch": epoch,
                        "epochOrdinal": epoch_ordinal,
                        "reason": reason,
                        "domain": _domain_name(domain),
                        "caller": _hex_address(caller),
                        "size": size,
                        "growthStreak": history.growth_streak,
                        **group,
                        "leakCandidate": history.candidate,
                    }
                )

        elif record_type == TYPE_CHECKPOINT:
            checkpoint = _decode_checkpoint(payload, sequence, file_version)
            if checkpoint is None:
                integrity.malformed_payloads += 1
                continue
            integrity.checkpoints += 1
            integrity.producer_incomplete |= bool(
                checkpoint["incomplete"] or checkpoint["dropped"]
            )
            integrity.writer_error |= bool(checkpoint["writerError"])
            checkpoints.append(checkpoint)
        elif record_type == TYPE_MODULE:
            if len(payload) < MODULE_FIXED.size:
                integrity.malformed_payloads += 1
                continue
            base, size, path_length = MODULE_FIXED.unpack_from(payload)
            if len(payload) != MODULE_FIXED.size + path_length:
                integrity.malformed_payloads += 1
                continue
            try:
                path = payload[MODULE_FIXED.size :].decode("utf-8")
            except UnicodeDecodeError:
                integrity.malformed_payloads += 1
                continue
            modules.append(_Module(base=base, size=size, path=path))
            event_counts["moduleSnapshot"] += 1
        else:
            integrity.unknown_record_types += 1

    live_allocations = sorted(live.values(), key=lambda item: item.address)
    modules.sort(key=lambda item: item.base)
    for event in events:
        stack_values = event.pop("_stackValues")
        event["stack"] = [_hex_address(frame) for frame in stack_values]
        event["stackLocations"] = [
            _resolve_address(frame, modules) for frame in stack_values
        ]
        caller = stack_values[0] if stack_values else 0
        event["caller"] = _hex_address(caller)
        event["callerLocation"] = _resolve_address(caller, modules)
    for survivor in survivors:
        survivor["callerLocation"] = _resolve_address(
            int(str(survivor["caller"]), 16), modules
        )
    live_group_keys = {
        (allocation.domain, allocation.caller, allocation.size)
        for allocation in live_allocations
    }
    candidate_groups = {
        key
        for key, history in group_history.items()
        if history.candidate and key in live_group_keys
    }
    candidate_allocations = [
        allocation
        for allocation in live_allocations
        if (allocation.domain, allocation.caller, allocation.size)
        in candidate_groups
    ]
    complete = not (
        integrity.truncated_tail
        or integrity.bad_crc_records
        or integrity.malformed_records
        or integrity.malformed_payloads
        or integrity.sequence_gaps
        or integrity.non_monotonic_sequences
        or integrity.skipped_bytes
        or integrity.producer_incomplete
        or integrity.writer_error
    )

    return {
        "format": header,
        "source": source,
        "integrity": {
            "complete": complete,
            "recordsRead": integrity.records_read,
            "badCrcRecords": integrity.bad_crc_records,
            "malformedRecords": integrity.malformed_records,
            "malformedPayloads": integrity.malformed_payloads,
            "unknownRecordTypes": integrity.unknown_record_types,
            "skippedBytes": integrity.skipped_bytes,
            "sequenceGaps": integrity.sequence_gaps,
            "nonMonotonicSequences": integrity.non_monotonic_sequences,
            "truncatedTail": integrity.truncated_tail,
            "producerIncomplete": integrity.producer_incomplete,
            "writerError": integrity.writer_error,
            "checkpoints": integrity.checkpoints,
        },
        "summary": {
            "eventCounts": event_counts,
            "epochCount": epoch_ordinal,
            "epochMarkerCount": len(epoch_markers),
            "liveAllocationCount": len(live_allocations),
            "liveBytes": sum(item.size for item in live_allocations),
            "leakCandidateCount": len(candidate_allocations),
            "leakCandidateBytes": sum(
                item.size for item in candidate_allocations
            ),
            "leakCandidateGroupCount": len(candidate_groups),
            "unknownFrees": unknown_frees,
            "unknownReallocOlds": unknown_realloc_olds,
            "replacedAllocations": replaced_allocations,
            "metadataRecords": metadata_records,
            "fallbackEventCount": fallback_event_count,
            "degradedEventCount": degraded_event_count,
        },
        "metadataSummary": {
            "records": metadata_records,
            "fallbackEvents": fallback_event_count,
            "degradedEvents": degraded_event_count,
            **metadata_counts,
        },
        "survivors": survivors,
        "epochMarkers": epoch_markers,
        "modules": [
            {
                "base": _hex_address(module.base),
                "size": module.size,
                "path": module.path,
                "name": ntpath.basename(module.path),
            }
            for module in modules
        ],
        "liveAllocations": [
            _allocation_json(allocation, modules, candidate_groups)
            for allocation in live_allocations
        ],
        "events": events,
        "checkpoints": checkpoints,
    }


def analyze_file(path: str | Path) -> dict[str, Any]:
    input_path = Path(path)
    return analyze_bytes(input_path.read_bytes(), source=str(input_path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recover an SBLP profile and emit survivor JSON"
    )
    parser.add_argument("input", type=Path, help="input .sblp file")
    parser.add_argument("-o", "--output", type=Path, help="JSON output path")
    parser.add_argument(
        "--compact", action="store_true", help="emit compact JSON"
    )
    args = parser.parse_args(argv)

    try:
        result = analyze_file(args.input)
    except (OSError, SblpFormatError) as error:
        print(f"analyze_leak_profile: {error}", file=sys.stderr)
        return 2

    if args.compact:
        rendered = json.dumps(result, separators=(",", ":"), sort_keys=True)
    else:
        rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
