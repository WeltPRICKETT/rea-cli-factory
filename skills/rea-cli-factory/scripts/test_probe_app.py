import plistlib
from pathlib import Path
import tempfile
import unittest
from probe_app import probe
from inventory_app import InventoryError


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.app = self.root / 'Fixture.app'
        for rel in ['MacOS', 'Resources', 'Frameworks']:
            (self.app / 'Contents' / rel).mkdir(parents=True)
        self.info = self.app / 'Contents/Info.plist'
        self.info.write_bytes(plistlib.dumps({'CFBundleExecutable': 'main'}))
        (self.app / 'Contents/MacOS/main').write_bytes(b'not executed')

    def test_native_is_not_claimed_callable(self):
        r = probe(self.app)
        self.assertEqual(r['candidates'], [])
        self.assertFalse(r['runtimeObserved'])
        self.assertFalse(r['reaExecuted'])
        self.assertEqual(r['routeOrder'][0], 'documented-api-or-cli')

    def test_electron_and_dictionary_are_candidates(self):
        (self.app / 'Contents/Resources/app.asar').write_bytes(b'fixture')
        (self.app / 'Contents/Resources/App.sdef').write_text('<dictionary/>')
        r = probe(self.app)
        self.assertIn('rea-javascript-if-needed', r['routeOrder'])
        self.assertIn('applescript', r['routeOrder'])
        self.assertEqual(r['candidates'][0]['state'], 'candidate')

    def test_escaping_declaration_rejected(self):
        self.info.write_bytes(plistlib.dumps({'CFBundleExecutable': 'main', 'OSAScriptingDefinition': '../../../outside.sdef'}))
        with self.assertRaises(InventoryError) as e:
            probe(self.app)
        self.assertEqual(e.exception.code, 'OUTSIDE_BUNDLE')

    def test_bounded_coverage_reports_truncation(self):
        for i in range(5):
            (self.app / 'Contents/Resources' / str(i)).touch()
        r = probe(self.app, member_limit=2)
        self.assertTrue(next(c for c in r['coverage'] if c['directory'] == 'Contents/Resources')['truncated'])

    def test_helper_symlink_escape_rejected(self):
        helpers = self.app / 'Contents/Helpers'
        helpers.mkdir()
        (helpers / 'external').symlink_to(self.root)
        with self.assertRaises(InventoryError):
            probe(self.app)


if __name__ == '__main__':
    unittest.main()
