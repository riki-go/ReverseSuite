"""AC-11 job object sandbox and AC-12 loader caps."""
import os
import struct
import subprocess
import unittest
from pathlib import Path

from reversesuite import loader, sandbox

FIXTURES = Path("fixtures/frozen")


def leftovers():
    out = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True).stdout
    return [line for line in out.splitlines()
            if any(name in line.lower() for name in ("spin.exe", "memhog.exe", "spawner.exe"))]


@unittest.skipUnless(os.name == "nt", "job objects are Windows only")
class SandboxTests(unittest.TestCase):
    def test_memory_cap_stops_allocation(self):
        result = sandbox.run_capped([str(FIXTURES / "memhog.exe")], wallclock_s=8.0,
                                    memory_bytes=64 * 1024 * 1024, active_process_limit=1)
        self.assertFalse(result.timed_out, result.summary())
        self.assertEqual(result.exit_code, 2)
        self.assertIn("alloc_failed_at=", result.stdout)
        self.assertLess(result.wall_seconds, 5.0)
        self.assertLess(result.peak_job_bytes, 32 * 1024 * 1024)

    def test_wallclock_kills_spinning_process(self):
        result = sandbox.run_capped([str(FIXTURES / "spin.exe")], wallclock_s=1.0,
                                    memory_bytes=64 * 1024 * 1024, active_process_limit=1)
        self.assertTrue(result.timed_out, result.summary())
        self.assertTrue(result.killed_tree)
        self.assertLess(result.wall_seconds, 4.0)

    def test_active_process_limit_blocks_child(self):
        result = sandbox.run_capped([str(FIXTURES / "spawner.exe")], wallclock_s=8.0,
                                    memory_bytes=256 * 1024 * 1024, active_process_limit=1)
        self.assertIn("child_spawn_failed=", result.stdout, result.summary())
        self.assertNotIn("child_spawned=", result.stdout)

    def test_no_processes_left_behind(self):
        sandbox.run_capped([str(FIXTURES / "spin.exe")], wallclock_s=0.5,
                           memory_bytes=64 * 1024 * 1024, active_process_limit=1)
        self.assertEqual(leftovers(), [])

    def test_exit_code_is_propagated(self):
        result = sandbox.run_capped(["cmd", "/c", "exit", "7"], wallclock_s=10.0,
                                    memory_bytes=128 * 1024 * 1024, active_process_limit=1)
        self.assertEqual(result.exit_code, 7, result.summary())
        self.assertFalse(result.timed_out)


class LoaderCapTests(unittest.TestCase):
    def _pe_with_sections(self, count: int, size: int = 0x400) -> bytes:
        data = bytearray(size)
        struct.pack_into("<H", data, 0, 0x5A4D)
        struct.pack_into("<I", data, 0x3C, 0x80)
        struct.pack_into("<I", data, 0x80, 0x00004550)
        struct.pack_into("<H", data, 0x84, 0x8664)
        struct.pack_into("<H", data, 0x86, count)
        struct.pack_into("<H", data, 0x94, 240)
        struct.pack_into("<H", data, 0x98, 0x20B)
        return bytes(data)

    def test_excessive_sections_rejected(self):
        result = loader.parse(self._pe_with_sections(loader.MAX_SECTIONS + 1))
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.diagnostics[0].code, "pe.sectab.cap_exceeded")

    def test_section_table_truncation_is_reported(self):
        result = loader.parse(self._pe_with_sections(8, size=0x140))
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.diagnostics[0].code, "pe.sectab.truncated")


if __name__ == "__main__":
    unittest.main()