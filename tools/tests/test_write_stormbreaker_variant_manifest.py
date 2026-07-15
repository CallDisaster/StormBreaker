from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest


TOOLS_DIR = Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import write_stormbreaker_variant_manifest as manifest_writer


def make_pe(*, machine: int = 0x014C, large_address_aware: bool = True) -> bytes:
    data = bytearray(256)
    data[:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<H", data, pe_offset + 4, machine)
    characteristics = 0x2102
    if large_address_aware:
        characteristics |= manifest_writer.IMAGE_FILE_LARGE_ADDRESS_AWARE
    else:
        characteristics &= ~manifest_writer.IMAGE_FILE_LARGE_ADDRESS_AWARE
    struct.pack_into("<H", data, pe_offset + 22, characteristics)
    return bytes(data)


class VariantManifestTests(unittest.TestCase):
    def create_variants(self, build_dir: Path) -> dict[str, bytes]:
        images: dict[str, bytes] = {}
        for index, spec in enumerate(manifest_writer.VARIANTS):
            image = make_pe() + bytes([index])
            (build_dir / spec.file).write_bytes(image)
            images[spec.file] = image
        return images

    def test_manifest_records_validated_release_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build_dir = Path(temporary)
            images = self.create_variants(build_dir)
            result = manifest_writer.build_manifest(
                build_dir,
                built_at="2026-07-14T03:00:00+08:00",
                cpp_tests="2/2 passed",
                python_tests="77/77 passed",
                logic_benchmarks="baseline accepted",
                war3_autotest="not run by request",
            )

            self.assertEqual("stormbreaker.variant-manifest.v2", result["schema"])
            self.assertEqual("x86", result["architecture"])
            self.assertTrue(result["largeAddressAware"])
            self.assertEqual("tlsf", result["defaults"]["backend"])
            self.assertEqual(4, len(result["variants"]))
            for variant in result["variants"]:
                image = images[variant["file"]]
                self.assertEqual(len(image), variant["bytes"])
                self.assertEqual(
                    hashlib.sha256(image).hexdigest().upper(), variant["sha256"]
                )
                self.assertEqual("0x014C", variant["machine"])
                self.assertTrue(variant["largeAddressAware"])

    def test_non_x86_and_non_laa_images_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.asi"
            path.write_bytes(make_pe(machine=0x8664))
            with self.assertRaisesRegex(manifest_writer.ManifestFailure, "not x86"):
                manifest_writer.inspect_release_pe(path)

            path.write_bytes(make_pe(large_address_aware=False))
            with self.assertRaisesRegex(
                manifest_writer.ManifestFailure, "not large-address-aware"
            ):
                manifest_writer.inspect_release_pe(path)

    def test_missing_variant_does_not_replace_existing_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_dir = root / "build"
            build_dir.mkdir()
            self.create_variants(build_dir)
            (build_dir / manifest_writer.VARIANTS[-1].file).unlink()
            output = root / "variants.json"
            output.write_text("old manifest", encoding="utf-8")

            with self.assertRaises(manifest_writer.ManifestFailure):
                manifest_writer.build_manifest(build_dir)
            self.assertEqual("old manifest", output.read_text(encoding="utf-8"))

    def test_atomic_writer_publishes_parseable_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "nested" / "variants.json"
            value = {"schema": "test", "valid": True}
            manifest_writer.write_manifest(output, value)
            self.assertEqual(value, json.loads(output.read_text(encoding="utf-8")))
            self.assertEqual([], list(output.parent.glob("*.tmp")))


if __name__ == "__main__":
    unittest.main()
