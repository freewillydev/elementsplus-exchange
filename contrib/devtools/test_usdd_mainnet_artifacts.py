#!/usr/bin/env python3
"""Adversarial packet admission tests; fixtures contain no real proofs."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from import_usdd_mainnet_artifacts import digest, unique_object, verify_packet


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="usdd-import-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "packet.tar.gz"

    def packet(self, members=None, manifest=None):
        members = members or [("program.elf", b"fixture", tarfile.REGTYPE)]
        if manifest is None:
            manifest = {name: {"bytes": len(data), "sha256": digest(data)}
                        for name, data, _ in members}
        with tarfile.open(self.path, "w:gz") as archive:
            for name, data, kind in members + [
                    ("manifest.json", json.dumps(manifest).encode(), tarfile.REGTYPE)]:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        return digest(self.path.read_bytes())

    def check(self, pin):
        return verify_packet(self.path, pin, "manifest.json")

    def test_valid_packet(self):
        self.assertEqual(self.check(self.packet())["program.elf"], b"fixture")

    def test_substitution(self):
        self.packet()
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            self.check("0" * 64)

    def test_missing_or_corrupt_manifest_entry(self):
        for manifest in ({}, {"program.elf": {"bytes": 7, "sha256": "0" * 64}}):
            pin = self.packet(manifest=manifest)
            with self.assertRaises(ValueError):
                self.check(pin)

    def test_unsafe_members(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("a/../escape", tarfile.REGTYPE), ("a\\escape", tarfile.REGTYPE),
                           ("a//b", tarfile.REGTYPE), ("link", tarfile.SYMTYPE),
                           ("hard", tarfile.LNKTYPE)):
            with self.subTest(name=name):
                pin = self.packet([(name, b"", kind)])
                with self.assertRaises(ValueError):
                    self.check(pin)

    def test_duplicate_member_and_json_key(self):
        pin = self.packet([("program.elf", b"a", tarfile.REGTYPE)] * 2)
        with self.assertRaises(ValueError):
            self.check(pin)
        with self.assertRaises(ValueError):
            json.loads('{"a":1,"a":2}', object_pairs_hook=unique_object)

    def test_packet_symlink(self):
        pin = self.packet()
        link = self.path.with_suffix(".link")
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            verify_packet(link, pin, "manifest.json")


if __name__ == "__main__":
    unittest.main()
