#!/usr/bin/env python3
"""Test archive admission and rebuild gates using non-cryptographic fixtures."""

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "cmake/module/CheckPinnedArchive.cmake"


@unittest.skipUnless(shutil.which("cmake") and shutil.which("c++") and shutil.which("ar"),
                     "CMake, compiler and ar required")
class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="verifier-pin-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.archive = self.root / "fixture.a"
        # This fixture must never be used as a real verifier.
        source = self.root / "fixture.cpp"
        source.write_text('extern "C" bool ecx_sp1_6_3_1_verify_groth16_sha256() { return false; }\n'
                          'extern "C" bool ecx_witness_availability_verify_custody_receipts_v1() { return false; }\n')
        self.run_ok("c++", "-c", str(source), "-o", str(self.root / "fixture.o"))
        self.run_ok("ar", "rcs", str(self.archive), str(self.root / "fixture.o"))
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def run_ok(self, *args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def check(self, path=None, digest=None):
        return subprocess.run(["cmake", f"-DARCHIVE={path or self.archive}",
                               f"-DEXPECTED_SHA256={self.digest if digest is None else digest}",
                               "-P", str(CHECK)], capture_output=True, text=True, timeout=30)

    def test_matching_archive(self):
        self.assertEqual(self.check().returncode, 0)

    def test_missing_malformed_and_wrong_pins(self):
        for value in ("", "0" * 64, "a" * 63, "A" * 64, "g" * 64, self.digest + ";other"):
            with self.subTest(value=value):
                self.assertNotEqual(self.check(digest=value).returncode, 0)

    def test_substitution_and_symlink(self):
        self.archive.write_bytes(self.archive.read_bytes() + b"changed")
        self.assertIn("SHA256 mismatch", self.check().stderr)
        link = self.root / "link.a"
        link.symlink_to(self.archive)
        self.assertIn("non-symlink", self.check(path=link).stderr)

    def test_thin_archive_even_with_matching_hash(self):
        self.archive.write_bytes(b"!<thin>\n")
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.assertIn("thin archives are forbidden", self.check(digest=digest).stderr)

    def test_build_checks_original_and_snapshot(self):
        (self.root / "main.cpp").write_text("int main() { return 0; }\n")
        # Test the platform-independent integrity and link dependency wiring.
        # The separate macOS deployment-target gate has its own tests.
        (self.root / "CMakeLists.txt").write_text(f'''
cmake_minimum_required(VERSION 3.22)
project(pin_fixture CXX)
set(APPLE FALSE)
set(ECX_SP1_VERIFIER_ARCHIVE "{self.archive}" CACHE FILEPATH "")
set(ECX_SP1_VERIFIER_SHA256 "{self.digest}" CACHE STRING "")
set(ECX_SP1_VERIFIER_SYSTEM_LIBS m CACHE STRING "")
include("{ROOT}/cmake/module/DrivechainVerifiers.cmake")
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE drivechain_verifiers)
''')
        build = self.root / "build"
        self.run_ok("cmake", "-S", str(self.root), "-B", str(build))
        self.run_ok("cmake", "--build", str(build), "--target", "consumer")
        original = self.archive.read_bytes()
        snapshot = build / "pinned-verifiers" / f"{self.digest}.a"
        self.assertEqual(snapshot.read_bytes(), original)
        for path in (self.archive, snapshot):
            with self.subTest(path=path):
                path.write_bytes(original + b"substitution")
                result = subprocess.run(["cmake", "--build", str(build), "--target", "consumer"],
                                        capture_output=True, text=True, timeout=90)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("SHA256 mismatch", result.stdout + result.stderr)
                if path == snapshot:
                    result = subprocess.run(["cmake", "--install", str(build), "--prefix", str(self.root / "install")],
                                            capture_output=True, text=True, timeout=30)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("SHA256 mismatch", result.stdout + result.stderr)
                path.write_bytes(original)
        self.run_ok("cmake", "--build", str(build), "--target", "consumer")
        self.run_ok("cmake", "--install", str(build), "--prefix", str(self.root / "install"))


if __name__ == "__main__":
    unittest.main()
