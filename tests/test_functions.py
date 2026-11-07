"""Tests for heuristic function discovery."""
import unittest
from pathlib import Path

from reversesuite import disasm, functions, loader


def frozen() -> bytes:
    return Path("fixtures/frozen/a.exe").read_bytes()


class FunctionTests(unittest.TestCase):
    def test_exports_are_discovered(self):
        data = frozen()
        text = loader.text_bytes(data)
        exports = loader.export_addresses(data)
        self.assertGreaterEqual(len(exports), 1)
        found = functions.discover(text, exports=exports)
        starts = {f.start for f in found}
        for addr in exports:
            self.assertIn(addr, starts)

    def test_sizes_are_ordered_and_non_negative(self):
        data = frozen()
        found = functions.discover(loader.text_bytes(data)[:65536])
        starts = [f.start for f in found]
        self.assertEqual(starts, sorted(starts))
        for f in found:
            self.assertGreaterEqual(f.size, 0)

    def test_call_targets_detected(self):
        data = frozen()
        found = functions.discover(loader.text_bytes(data))
        with_calls = [f for f in found if "call_target" in f.sources]
        self.assertGreater(len(with_calls), 0)

    def test_deterministic(self):
        blob = loader.text_bytes(frozen())[:32768]
        a = [f.as_dict() for f in functions.discover(blob)]
        b = [f.as_dict() for f in functions.discover(blob)]
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
