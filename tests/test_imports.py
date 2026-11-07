"""Import table tests: IAT slot addresses and names."""
import unittest
from pathlib import Path

from reversesuite import loader


def frozen(name):
    return (Path("fixtures/frozen") / name).read_bytes()


class ImportTests(unittest.TestCase):
    def test_b_exec_import_count(self):
        entries = loader.imports(frozen("b.exe"))
        self.assertEqual(len(entries), 45)
        self.assertEqual(len({e.iat_address for e in entries}), 45)
        self.assertEqual(entries[0].module, "KERNEL32.dll")
        self.assertEqual(entries[0].name, "DeleteCriticalSection")
        self.assertEqual(entries[0].iat_address, 0xB278)

    def test_a_exec_import_count(self):
        entries = loader.imports(frozen("a.exe"))
        self.assertEqual(len(entries), 92)
        self.assertTrue(any(e.name == "QueryPerformanceCounter" for e in entries))

    def test_iat_addresses_are_monotonic_per_thunk(self):
        entries = loader.imports(frozen("b.exe"))
        self.assertEqual([e.iat_address for e in entries], sorted(e.iat_address for e in entries))

    def test_imports_empty_for_garbage(self):
        self.assertEqual(loader.imports(b"MZ" + b"\x00" * 200), [])


if __name__ == "__main__":
    unittest.main()