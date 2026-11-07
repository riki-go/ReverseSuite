"""Tests for the artifact cache (AC-13)."""
import os
import tempfile
import unittest
from pathlib import Path

from reversesuite import cache


class CacheTests(unittest.TestCase):
    def test_put_get_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = cache.Cache(Path(tmp) / "cache")
            src = Path(tmp) / "artifact.bin"
            src.write_bytes(b"hello-cache" * 100)
            key = cache.make_key("a" * 64, mode="disasm", slim=False)
            c.put(key, src)
            hit = c.get(key)
            self.assertIsNotNone(hit)
            self.assertEqual(hit.read_bytes(), src.read_bytes())
            self.assertEqual(c.stats()["entries"], 1)

    def test_key_changes_with_schema(self):
        a = cache.make_key("a" * 64, mode="disasm")
        b = cache.make_key("a" * 64, mode="disasm", schema="other")
        self.assertNotEqual(a, b)

    def test_corrupted_artifact_is_miss(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = cache.Cache(Path(tmp) / "cache")
            src = Path(tmp) / "artifact.bin"
            src.write_bytes(b"payload")
            key = cache.make_key("b" * 64, mode="disasm")
            c.put(key, src)
            hit = c.get(key)
            hit.write_bytes(b"tampered")
            self.assertIsNone(c.get(key))

    def test_atomic_write_leaves_no_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cache"
            c = cache.Cache(root)
            src = Path(tmp) / "artifact.bin"
            src.write_bytes(b"x" * 1024)
            c.put(cache.make_key("c" * 64), src)
            leftovers = [p for p in (root / "artifacts").iterdir() if p.suffix == ".tmp"]
            self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
