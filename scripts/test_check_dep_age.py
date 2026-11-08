import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class DepAgeChecker(unittest.TestCase):
    def script(self):
        return Path(__file__).resolve().parent / "check-dep-age"

    def test_lookup_failure_exits_nonzero(self):
        lock = '[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
        with tempfile.TemporaryDirectory() as temp:
            lock_path = Path(temp) / "Cargo.lock"
            lock_path.write_text(lock)
            stub = Path(temp) / "curl"
            stub.write_text("#!/bin/sh\nexit 22\n")
            stub.chmod(0o755)
            env = os.environ | {"PATH": f"{temp}:{os.environ.get('PATH', '')}", "MIN_DAYS": "14"}
            completed = subprocess.run([self.script(), str(lock_path)], env=env, capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("lookup failed: serde 1.0.0", completed.stderr)


if __name__ == "__main__":
    unittest.main()
