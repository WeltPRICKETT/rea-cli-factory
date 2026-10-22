import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import prepare_electron as preparation


def archive_bytes(header, payload=b''):
    text = header if isinstance(header, bytes) else json.dumps(header, separators=(',', ':')).encode()
    pad = b'\0' * ((4 - len(text) % 4) % 4)
    encoded = struct.pack('<II', len(text) + len(pad) + 4, len(text)) + text + pad
    return struct.pack('<II', 4, len(encoded)) + encoded + payload


def file_tree(files):
    root = {'files': {}}
    content = b''
    for path, data in files.items():
        node = root
        parts = path.split('/')
        for part in parts[:-1]:
            node = node['files'].setdefault(part, {'files': {}})
        node['files'][parts[-1]] = {'size': len(data), 'offset': str(len(content))}
        content += data
    return root, content


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.asar = self.root / 'app.asar'
        self.out = self.root / 'prepared'
        self.files = {'package.json': b'{"main":"main.js"}',
                      'preload.js': b'throw new Error("must never execute")'}

    def write(self, files=None, header=None, payload=None):
        if header is None:
            header, payload = file_tree(self.files if files is None else files)
        self.asar.write_bytes(archive_bytes(header, payload or b''))

    def rejected(self, code):
        with self.assertRaises(preparation.PreparationError) as error:
            preparation.prepare(self.asar, self.out)
        self.assertEqual(error.exception.code, code)
        self.assertFalse(self.out.exists(), 'Invalid input must not produce a preparation directory')

    def test_deterministic_selection_preserves_bytes_hashes_and_archive_relation(self):
        self.files.update({'dist/preload/index.cjs': b'const a=1;',
                           'other/preload.mjs': b'export const b=2;',
                           'main.js': b'not selected',
                           'preload.js.map': b'not selected',
                           'node_modules/lib/preload.js': b'not selected'})
        self.write()
        original = self.asar.read_bytes()
        result = preparation.prepare(self.asar, self.out)
        second = preparation.prepare(self.asar, self.root / 'repeat')
        self.assertEqual(result, second)
        self.assertEqual([x['path'] for x in result['files']],
                         ['dist/preload/index.cjs', 'other/preload.mjs', 'package.json', 'preload.js'])
        self.assertEqual(result['archive']['sha256'], hashlib.sha256(original).hexdigest())
        self.assertFalse(result['runtimeObserved'])
        self.assertFalse(result['reaExecuted'])
        self.assertEqual(result['status'], 'candidate')
        for item in result['files']:
            actual = (self.out / item['outputPath']).read_bytes()
            self.assertEqual(actual, self.files[item['path']])
            self.assertEqual(actual, original[item['offset']:item['offset'] + item['size']])
            self.assertEqual(item['sha256'], hashlib.sha256(actual).hexdigest())
        self.assertEqual(self.asar.read_bytes(), original)
        self.assertEqual(json.loads((self.out / 'preparation.json').read_text()), result)

    def test_existing_output_never_overwritten(self):
        self.write()
        self.out.mkdir()
        marker = self.out / 'keep.txt'
        marker.write_text('keep')
        with self.assertRaises(preparation.PreparationError) as error:
            preparation.prepare(self.asar, self.out)
        self.assertEqual(error.exception.code, 'OUTPUT_EXISTS')
        self.assertEqual(marker.read_text(), 'keep')
        self.assertEqual(list(self.out.iterdir()), [marker])

    def test_duplicate_json_keys_are_rejected_before_silent_overwrite(self):
        self.write(header=b'{"files":{"preload.js":{},"preload.js":{}}}')
        self.rejected('DUPLICATE_HEADER_KEY')

    def test_traversal_and_portable_collisions_rejected(self):
        for key, code in [('../outside', 'UNSAFE_PATH'), ('..', 'UNSAFE_PATH'),
                          ('a\\b', 'UNSAFE_PATH'), ('a:b', 'UNSAFE_PATH')]:
            with self.subTest(key=key):
                self.write(header={'files': {key: {'size': 0, 'offset': '0'}}})
                self.rejected(code)
        for first, second in [('preload.js', 'PRELOAD.JS'), ('é.js', 'e\u0301.js')]:
            with self.subTest(first=first):
                self.write(files={first: b'', second: b''})
                self.rejected('AMBIGUOUS_PATH')

    def test_selected_links_and_unpacked_rejected_but_unrelated_not_read(self):
        tree, payload = file_tree(self.files)
        tree['files']['external.node'] = {'size': 30, 'unpacked': True}
        tree['files']['external-link'] = {'link': '../../must-not-read'}
        self.write(header=tree, payload=payload)
        preparation.prepare(self.asar, self.out)
        for entry, code in [({'link': '../../outside'}, 'UNSUPPORTED_LINK'),
                            ({'size': 10, 'unpacked': True}, 'UNSUPPORTED_UNPACKED')]:
            with self.subTest(code=code):
                tree['files']['preload.js'] = entry
                self.write(header=tree, payload=payload)
                with self.assertRaises(preparation.PreparationError) as error:
                    preparation.prepare(self.asar, self.root / 'rejected')
                self.assertEqual(error.exception.code, code)
                self.assertFalse((self.root / 'rejected').exists())

    def test_truncated_headers_and_file_ranges_rejected(self):
        for data in [b'', struct.pack('<II', 4, 100), archive_bytes({'files': {}})[:-1]]:
            self.asar.write_bytes(data)
            self.rejected('TRUNCATED_ARCHIVE')
        tree, payload = file_tree(self.files)
        tree['files']['preload.js']['size'] += 1
        self.write(header=tree, payload=payload)
        self.rejected('TRUNCATED_ARCHIVE')

    def test_overlapping_ranges_rejected_even_for_unselected_file(self):
        tree, payload = file_tree(self.files)
        tree['files']['other.js'] = {'offset': '0', 'size': 1}
        self.write(header=tree, payload=payload)
        self.rejected('OVERLAPPING_FILES')

    def test_missing_package_and_no_candidates_are_explicit(self):
        self.write(files={'preload.js': b''})
        self.rejected('PACKAGE_MISSING')
        self.write(files={'package.json': b'{}', 'main.js': b''})
        self.rejected('NO_PRELOAD_CANDIDATES')

    def test_bounds_fail_instead_of_silently_truncating(self):
        self.write()
        for limit, value, code in [('MAX_ARCHIVE_BYTES', 1, 'ARCHIVE_TOO_LARGE'),
                                   ('MAX_HEADER_BYTES', 1, 'HEADER_TOO_LARGE'),
                                   ('MAX_ENTRIES', 1, 'TOO_MANY_ENTRIES'),
                                   ('MAX_SELECTED_FILES', 1, 'TOO_MANY_SOURCES'),
                                   ('MAX_FILE_BYTES', 1, 'SOURCE_TOO_LARGE'),
                                   ('MAX_SELECTED_BYTES', 1, 'SELECTION_TOO_LARGE')]:
            with self.subTest(limit=limit), patch.object(preparation, limit, value):
                self.rejected(code)
        self.write(files={'package.json': b'{}', 'preload/a/b/index.js': b''})
        with patch.object(preparation, 'MAX_DEPTH', 1):
            self.rejected('HEADER_TOO_DEEP')

    def test_invalid_pickle_and_utf8_rejected(self):
        self.write()
        data = bytearray(self.asar.read_bytes())
        data[:4] = struct.pack('<I', 5)
        self.asar.write_bytes(data)
        self.rejected('INVALID_HEADER')
        self.write(files={'package.json': b'{}', 'preload.js': b'\xff'})
        self.rejected('SOURCE_NOT_UTF8')

    def test_source_and_destination_symlinks_not_followed(self):
        self.write()
        linked = self.root / 'linked.asar'
        linked.symlink_to(self.asar)
        with self.assertRaises((OSError, preparation.PreparationError)):
            preparation.prepare(linked, self.out)
        self.assertFalse(self.out.exists())
        self.out.symlink_to(self.root / 'missing')
        with self.assertRaises(preparation.PreparationError) as error:
            preparation.prepare(self.asar, self.out)
        self.assertEqual(error.exception.code, 'OUTPUT_EXISTS')
        self.assertFalse((self.root / 'missing').exists())

    def test_change_during_read_is_rejected(self):
        self.write()
        original_read = preparation.read_exact
        mutated = False

        def racing_read(handle, size):
            nonlocal mutated
            data = original_read(handle, size)
            if not mutated:
                mutated = True
                with self.asar.open('ab') as writer:
                    writer.write(b'changed')
            return data

        with patch.object(preparation, 'read_exact', racing_read):
            self.rejected('ARCHIVE_CHANGED')


if __name__ == '__main__':
    unittest.main()
