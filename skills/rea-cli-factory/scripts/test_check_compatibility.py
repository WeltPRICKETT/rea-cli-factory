"""Synthetic bundles only; upgrade gates do not launch installed applications."""
import contextlib
import copy
import io
import json
from pathlib import Path
import plistlib
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

import check_compatibility as compat
from inventory_app import inventory


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.app = self.root / 'Fixture.app'
        (self.app / 'Contents/MacOS').mkdir(parents=True)
        (self.app / 'Contents/Resources').mkdir()
        self.exe = self.app / 'Contents/MacOS/main'
        self.exe.write_bytes(b'not executable; synthetic fixture')
        self.asar = self.app / 'Contents/Resources/app.asar'
        self.asar.write_bytes(b'archive version one')
        self.info = self.app / 'Contents/Info.plist'
        self.fields = {'CFBundleIdentifier': 'local.fixture', 'CFBundleName': 'Fixture',
                       'CFBundleShortVersionString': '1.0', 'CFBundleVersion': '1',
                       'CFBundleExecutable': 'main'}
        self.info.write_bytes(plistlib.dumps(self.fields))
        self.baseline = inventory(self.app)
        self.baseline_path = self.root / 'baseline.json'
        self.original_bytes = json.dumps(self.baseline).encode()
        self.baseline_path.write_bytes(self.original_bytes)
        self.addCleanup(self.assert_baseline_untouched)

    def assert_baseline_untouched(self):
        self.assertEqual(self.baseline_path.read_bytes(), self.original_bytes)
        self.assertEqual(self.baseline, json.loads(self.original_bytes))

    def gated_action(self, action):
        # This explicitly tests caller enforcement, not an actual application upgrade.
        result = compat.check(self.app, self.baseline_path)
        if result['ok']:
            action()
        return result

    def assert_changed(self, expected_field):
        action = Mock()
        result = self.gated_action(action)
        action.assert_not_called()
        self.assertEqual(result['error']['code'], 'APP_CHANGED')
        self.assertIn(expected_field, [d['field'] for d in result['differences']])
        self.assertIn('Reanalyze and validate', result['recovery'])
        return result

    def test_match_and_cli_envelope_supported(self):
        for baseline in (self.baseline_path, self.baseline, {'ok': True, 'result': self.baseline}):
            r = compat.check(self.app, baseline)
            self.assertEqual(r['status'], 'compatible')
            self.assertTrue(r['ok'])
            self.assertIn('does not prove interface', r['scope'])
        envelope = self.root / 'envelope.json'
        envelope.write_text(json.dumps({'ok': True, 'result': self.baseline}))
        self.assertTrue(compat.check(self.app, envelope)['ok'])

    def test_version_change_and_restore_allow_action_only_after_match(self):
        before = self.info.read_bytes()
        self.fields['CFBundleShortVersionString'] = '2.0'
        self.info.write_bytes(plistlib.dumps(self.fields))
        self.assert_changed('identity.CFBundleShortVersionString')
        self.info.write_bytes(before)
        action = Mock()
        self.assertTrue(self.gated_action(action)['ok'])
        action.assert_called_once_with()

    def test_all_identity_fields_are_compared(self):
        for field in self.fields:
            with self.subTest(field=field):
                baseline = copy.deepcopy(self.baseline)
                baseline['identity'][field] = 'PreviousValue'
                result = compat.check(self.app, baseline)
                self.assertEqual(result['error']['code'], 'APP_CHANGED')
                self.assertIn('identity.' + field, [d['field'] for d in result['differences']])

    def test_same_version_asar_change_blocks_action(self):
        # Same byte length, distinct hash: catches updates that omit version bumps.
        self.asar.write_bytes(b'archive version two')
        result = self.assert_changed('artifacts.app_asar.sha256')
        self.assertFalse(any(d['field'].startswith('identity.') for d in result['differences']))

    def test_executable_change_blocks_action(self):
        self.exe.write_bytes(b'changed executable with different size')
        result = self.assert_changed('artifacts.executable.sha256')
        self.assertIn('artifacts.executable.size_bytes', [d['field'] for d in result['differences']])

    def test_required_artifact_missing_preserves_error_and_blocks_action(self):
        for path in (self.exe, self.info):
            saved = path.read_bytes()
            path.unlink()
            action = Mock()
            result = self.gated_action(action)
            action.assert_not_called()
            self.assertEqual(result['error']['code'], 'MISSING_ARTIFACT')
            path.write_bytes(saved)

    def test_optional_artifact_removal_and_addition_are_changes(self):
        self.asar.unlink()
        self.assert_changed('artifacts.keys')
        baseline_without_asar = inventory(self.app)
        self.asar.write_bytes(b'new archive')
        result = compat.check(self.app, baseline_without_asar)
        self.assertEqual(result['error']['code'], 'APP_CHANGED')
        self.assertIn('artifacts.keys', [d['field'] for d in result['differences']])

    def test_fixed_app_path_cannot_be_replaced_with_identical_copy(self):
        other = self.root / 'Other.app'
        shutil.copytree(self.app, other)
        result = compat.check(other, self.baseline)
        self.assertEqual(result['error']['code'], 'APP_CHANGED')
        self.assertIn('app_path', [d['field'] for d in result['differences']])

    def test_missing_and_unreadable_app_preserve_error(self):
        self.assertEqual(compat.check(self.root / 'Missing.app', self.baseline)['error']['code'], 'INVALID_APP')
        with patch.object(compat, 'inventory', side_effect=PermissionError('synthetic denied')):
            self.assertEqual(compat.check(self.app, self.baseline)['error']['code'], 'READ_FAILED')

    def test_invalid_baseline_structures_are_rejected_before_inventory(self):
        mutations = [
            lambda d: d.update(schema='other'),
            lambda d: d.update(app_path='relative.app'),
            lambda d: d['identity'].pop('CFBundleName'),
            lambda d: d['identity'].update(CFBundleVersion=4),
            lambda d: d['artifacts'].pop('executable'),
            lambda d: d['artifacts'].update(unexpected={}),
            lambda d: d['artifacts']['executable'].update(sha256='invalid'),
            lambda d: d['artifacts']['executable'].update(size_bytes=True),
            lambda d: d['artifacts']['executable'].update(path='/outside/main'),
            lambda d: d['analysis'].update(runtime_observed=True),
        ]
        for mutate in mutations:
            d = copy.deepcopy(self.baseline)
            mutate(d)
            with patch.object(compat, 'inventory') as scan:
                self.assertEqual(compat.check(self.app, d)['error']['code'], 'INVALID_BASELINE')
                scan.assert_not_called()
        self.assertEqual(compat.check(self.app, {'ok': False, 'result': self.baseline})['error']['code'], 'INVALID_BASELINE')

    def test_bounded_reader_rejects_duplicates_malformed_and_oversize(self):
        path = self.root / 'invalid.json'
        for payload in (b'{bad', b'{"schema":1,"schema":2}', b'{"n":NaN}', b'\xff',
                        b'x' * (compat.MAX_BASELINE_BYTES + 1)):
            path.write_bytes(payload)
            self.assertEqual(compat.check(self.app, path)['error']['code'], 'INVALID_BASELINE')

    def test_cli_return_codes_and_no_traceback(self):
        args = ['--app', str(self.app), '--baseline', str(self.baseline_path)]
        for expected in (0, 3, 2):
            if expected == 3:
                self.asar.write_bytes(b'upgrade')
            if expected == 2:
                self.exe.unlink()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(compat.main(args), expected)
            self.assertIsInstance(json.loads(out.getvalue()), dict)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(compat.main(['--app', str(self.app), '--baseline', str(self.root / 'absent')]), 2)


if __name__ == '__main__':
    unittest.main()
