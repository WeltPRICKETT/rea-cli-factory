"""Synthetic evidence only: no application code or captured data."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import summarize_rea as s


def fixture(labels=('Bridge.Write', 'Bridge.Read')):
    observations = [{'label': label, 'properties': {'private': 'DO_NOT_EMIT'},
                     'evidence': {'location': {'available': True, 'value': {
                         'kind': 'source-range', 'source': 'src/bridge.js',
                         'start': {'line': 2, 'column': 0},
                         'end': {'line': 2, 'column': 12}}}}} for label in labels]
    return {'evidence_id': 'ev_' + 'a' * 64, 'operation': s.OPERATION,
            'raw_result': {'private': 'DO_NOT_EMIT'},
            'limitations': ['private diagnostic DO_NOT_EMIT'],
            'normalized_result': {
                'summary': {**dict.fromkeys(s.COUNTS, 0), 'ipc': dict.fromkeys(s.IPC_COUNTS, 0)},
                'graph': {'coverage': {'status': 'partial', 'truncated': False,
                                       'omitted_count': None},
                          'nodes': [{'kind': 'ipc-channel', 'observations': observations}]}}}


class SummaryTests(unittest.TestCase):
    def test_partial_is_preserved_not_upgraded_by_selection(self):
        r = s.summarize(fixture())
        self.assertEqual(r['coverage']['status'], 'partial')
        self.assertFalse(r['coverage']['truncated'])
        self.assertTrue(any('incomplete' in text for text in r['limitations']))
        self.assertTrue(any('not cryptographically verified' in text for text in r['limitations']))
        self.assertNotIn('DO_NOT_EMIT', json.dumps(r))

    def test_query_limit_and_total_match(self):
        r = s.summarize(fixture(('Bridge.Write', 'Bridge.Read', 'Bridge.WriteAgain')), 'WRITE', 1)
        self.assertEqual(r['totalMatched'], 2)
        self.assertEqual(len(r['findings']), 1)
        self.assertTrue(r['selectionTruncated'])
        self.assertEqual(r['findings'][0]['label'], 'Bridge.Write')
        self.assertEqual(s.summarize(fixture(), 'absent')['totalMatched'], 0)

    def test_absolute_path_and_sensitive_label_are_redacted(self):
        d = fixture(('api_key:syntheticvalue', '/private/account/entry'))
        o = d['normalized_result']['graph']['nodes'][0]['observations']
        o[0]['evidence']['location']['value']['source'] = '/private/account/entry.js'
        r = s.summarize(d)
        self.assertTrue(all(f['label'] == '[redacted]' for f in r['findings']))
        self.assertEqual(r['findings'][0]['sourceRange']['source'], '[redacted]')
        self.assertNotIn('/private/', json.dumps(r))

    def test_artifact_location_and_null_label_have_no_range(self):
        d = fixture((None,))
        d['normalized_result']['graph']['nodes'][0]['observations'][0]['evidence']['location']['value'] = {
            'kind': 'artifact-path', 'path': '/private/artifact'}
        r = s.summarize(d)
        self.assertIsNone(r['findings'][0]['sourceRange'])
        self.assertIsNone(r['findings'][0]['label'])

    def test_invalid_operation_and_shape_fail_closed(self):
        for mutate in (
            lambda d: d.update(operation='other'),
            lambda d: d.update(evidence_id='not-an-evidence-id'),
            lambda d: d['normalized_result']['summary'].update(browser_windows=True),
            lambda d: d['normalized_result']['graph'].update(nodes={}),
            lambda d: d['normalized_result']['graph']['coverage'].update(truncated='no'),
        ):
            d = fixture()
            mutate(d)
            with self.assertRaises(s.SummaryError):
                s.summarize(d)
        for limit in (0, 51, True):
            with self.assertRaises(s.SummaryError):
                s.summarize(fixture(), limit=limit)

    def test_invalid_unselected_observation_also_fails(self):
        d = fixture()
        d['normalized_result']['graph']['nodes'][0]['observations'][1]['evidence'] = None
        with self.assertRaises(s.SummaryError):
            s.summarize(d, query='Write', limit=1)

    def test_reader_rejects_oversize_duplicate_and_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture.json'
            path.write_bytes(b'x' * 33)
            with patch.object(s, 'MAX_BYTES', 32), self.assertRaisesRegex(s.SummaryError, 'INPUT_TOO_LARGE'):
                s.read_evidence(path)
            for payload in (b'{broken', b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff'):
                path.write_bytes(payload)
                with self.assertRaises(s.SummaryError):
                    s.read_evidence(path)

    def test_cli_has_json_error_and_nonzero_exit(self):
        for args in ([], ['--input', '/nonexistent/fixture'], ['--input', 'fixture', '--limit', 'bad']):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = s.main(args)
            self.assertEqual(code, 1)
            self.assertFalse(json.loads(out.getvalue())['ok'])

    def test_cli_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture.json'
            path.write_text(json.dumps(fixture()))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = s.main(['--input', str(path), '--limit', '1'])
            self.assertEqual(code, 0)
            self.assertEqual(len(json.loads(out.getvalue())['findings']), 1)


if __name__ == '__main__':
    unittest.main()
