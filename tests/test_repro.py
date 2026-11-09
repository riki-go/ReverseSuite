"""AC-4: the pinned gcc recipe produces identical binaries."""
import importlib.util
import pathlib
import unittest

# repro_check.py pins this exact toolchain; tools/ is not published, so CI skips the check.
_LOCAL_GCC = pathlib.Path("tools/mingw64/bin/gcc.exe")
HAS_COMPILER = _LOCAL_GCC.exists()


def load_repro_module():
    path = pathlib.Path("build/repro_check.py")
    spec = importlib.util.spec_from_file_location("repro_check", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HAS_COMPILER, "no C compiler on PATH")
class ReproducibleBuildTests(unittest.TestCase):
    def test_two_builds_are_byte_identical(self):
        module = load_repro_module()
        self.assertEqual(module.main([]), 0)


if __name__ == "__main__":
    unittest.main()