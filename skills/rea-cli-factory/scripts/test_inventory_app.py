"""Bounded regression tests for inventory identity and target confinement."""
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest

import inventory_app as inv


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix=".inventory-test-", dir=Path(__file__).parent)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.app = self.bundle(self.root / "Selected.app")

    def bundle(self, app):
        (app / "Contents/MacOS").mkdir(parents=True)
        (app / "Contents/Resources").mkdir()
        (app / "Contents/MacOS/main").write_bytes(b"not executable, inventory only")
        self.write_info(app, CFBundleExecutable="main", CFBundleIdentifier="local.fixture", CFBundleShortVersionString="1.0")
        return app

    def write_info(self, app, **fields):
        with (app / "Contents/Info.plist").open("wb") as f:
            plistlib.dump(fields, f)

    def test_hashes_and_no_execution_claim(self):
        asar = self.app / "Contents/Resources/app.asar"
        asar.write_bytes(b"fixture archive")
        result = inv.inventory(self.app)
        self.assertEqual(result["artifacts"]["app_asar"]["sha256"], hashlib.sha256(asar.read_bytes()).hexdigest())
        self.assertEqual(result["identity"]["CFBundleIdentifier"], "local.fixture")
        self.assertFalse(result["analysis"]["rea_executed"])
        self.assertFalse(result["analysis"]["runtime_observed"])

    def test_content_change_changes_identity(self):
        before = inv.inventory(self.app)["artifacts"]["executable"]["sha256"]
        (self.app / "Contents/MacOS/main").write_bytes(b"changed")
        after = inv.inventory(self.app)["artifacts"]["executable"]["sha256"]
        self.assertNotEqual(before, after)

    def test_ambiguous_name_has_no_selected_target(self):
        second = self.root / "other"
        self.bundle(second / "Selected.app")
        with self.assertRaises(inv.InventoryError) as caught:
            inv.find_by_name("selected", [self.root, second])
        self.assertEqual(caught.exception.code, "AMBIGUOUS_TARGET")
        self.assertEqual(len(caught.exception.details["candidates"]), 2)

    def test_executable_traversal_rejected(self):
        self.write_info(self.app, CFBundleExecutable="../../outside")
        with self.assertRaises(inv.InventoryError) as caught:
            inv.inventory(self.app)
        self.assertEqual(caught.exception.code, "INVALID_EXECUTABLE")

    def test_bundle_member_symlink_escape_rejected(self):
        outside = self.root / "outside"
        outside.write_text("must not be read")
        exe = self.app / "Contents/MacOS/main"
        exe.unlink()
        exe.symlink_to(outside)
        with self.assertRaises(inv.InventoryError) as caught:
            inv.inventory(self.app)
        self.assertEqual(caught.exception.code, "OUTSIDE_BUNDLE")

    def test_missing_executable_is_not_success(self):
        (self.app / "Contents/MacOS/main").unlink()
        run = subprocess.run([sys.executable, str(Path(inv.__file__)), "--app", str(self.app)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        error = json.loads(run.stdout)
        self.assertFalse(error["ok"])
        self.assertEqual(error["error"]["code"], "MISSING_ARTIFACT")
        self.assertNotIn("Traceback", run.stderr)


if __name__ == "__main__":
    unittest.main()
