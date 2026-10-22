#!/usr/bin/env python3
"""Select bounded Electron preload sources from an ASAR without executing them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import unicodedata

MAX_ARCHIVE_BYTES = 4 * 1024**3
MAX_HEADER_BYTES = 16 * 1024**2
MAX_ENTRIES = 100_000
MAX_DEPTH = 64
MAX_SELECTED_FILES = 64
MAX_FILE_BYTES = 2 * 1024**2
MAX_SELECTED_BYTES = 16 * 1024**2


class PreparationError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def fail(code, message):
    raise PreparationError(code, message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail('DUPLICATE_HEADER_KEY', 'Duplicate JSON key in ASAR header')
        result[key] = value
    return result


def read_exact(handle, size):
    data = handle.read(size)
    if len(data) != size:
        fail('TRUNCATED_ARCHIVE', 'ASAR bytes end before their declared boundary')
    return data


def selected(path):
    parts = path.split('/')
    if 'node_modules' in parts:
        return False
    return path == 'package.json' or (
        Path(parts[-1]).suffix in {'.js', '.cjs', '.mjs'}
        and (Path(parts[-1]).stem == 'preload' or 'preload' in parts[:-1])
    )


def parse_header(handle, archive_size):
    handle.seek(0)
    prefix = read_exact(handle, 8)
    size_payload, header_size = struct.unpack('<II', prefix)
    if size_payload != 4 or header_size < 8 or header_size % 4:
        fail('INVALID_HEADER', 'Invalid ASAR Pickle size header')
    if header_size > MAX_HEADER_BYTES:
        fail('HEADER_TOO_LARGE', f'ASAR header exceeds {MAX_HEADER_BYTES} bytes')
    if 8 + header_size > archive_size:
        fail('TRUNCATED_ARCHIVE', 'ASAR header exceeds archive size')
    raw = read_exact(handle, header_size)
    payload_size, json_size = struct.unpack('<II', raw[:8])
    padding = (4 - json_size % 4) % 4
    if payload_size != header_size - 4 or json_size + 8 + padding != header_size:
        fail('INVALID_HEADER', 'Inconsistent ASAR Pickle string boundaries')
    if any(raw[8 + json_size:]):
        fail('INVALID_HEADER', 'Nonzero ASAR Pickle padding')
    try:
        header = json.loads(raw[8:8 + json_size].decode('utf-8'),
                            object_pairs_hook=unique_object,
                            parse_constant=lambda _: fail('INVALID_HEADER', 'Non-finite JSON value'))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        fail('INVALID_HEADER', f'Invalid ASAR header JSON: {type(exc).__name__}')
    if not isinstance(header, dict) or not isinstance(header.get('files'), dict):
        fail('INVALID_HEADER', 'ASAR root must contain a files object')
    data_offset = 8 + header_size
    files, seen, extents = [], set(), []
    count = 0

    def walk(children, parent='', depth=0):
        nonlocal count
        if depth > MAX_DEPTH:
            fail('HEADER_TOO_DEEP', f'ASAR paths exceed {MAX_DEPTH} levels')
        for name in sorted(children):
            count += 1
            if count > MAX_ENTRIES:
                fail('TOO_MANY_ENTRIES', f'ASAR exceeds {MAX_ENTRIES} entries')
            if (not name or name in {'.', '..'} or any(c in name for c in '/\\:\x00')
                    or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in name)):
                fail('UNSAFE_PATH', 'ASAR contains an unsafe path component')
            path = f'{parent}/{name}' if parent else name
            portable = unicodedata.normalize('NFC', path).casefold()
            if portable in seen:
                fail('AMBIGUOUS_PATH', 'ASAR paths collide under Unicode/case normalization')
            seen.add(portable)
            entry = children[name]
            if not isinstance(entry, dict):
                fail('INVALID_ENTRY', f'ASAR entry is not an object: {path}')
            if 'files' in entry:
                if (not isinstance(entry['files'], dict)
                        or any(k in entry for k in ('size', 'offset', 'link', 'unpacked'))):
                    fail('INVALID_ENTRY', f'Conflicting directory metadata: {path}')
                walk(entry['files'], path, depth + 1)
                continue
            if 'link' in entry:
                if not isinstance(entry['link'], str) or any(k in entry for k in ('size', 'offset', 'unpacked')):
                    fail('INVALID_ENTRY', f'Conflicting link metadata: {path}')
                if selected(path):
                    fail('UNSUPPORTED_LINK', f'Selected source is a link: {path}')
                continue  # Never follow even unrelated links.
            unpacked = entry.get('unpacked', False)
            if not isinstance(unpacked, bool):
                fail('INVALID_ENTRY', f'Invalid unpacked marker: {path}')
            size = entry.get('size')
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                fail('INVALID_ENTRY', f'Invalid file size: {path}')
            if unpacked:
                if selected(path):
                    fail('UNSUPPORTED_UNPACKED', f'Selected source is outside the ASAR: {path}')
                continue  # No app.asar.unpacked reads.
            offset = entry.get('offset')
            if not isinstance(offset, str) or not re.fullmatch(r'0|[1-9][0-9]*', offset) or len(offset) > 20:
                fail('INVALID_ENTRY', f'Invalid packed offset: {path}')
            start = data_offset + int(offset)
            if start + size > archive_size:
                fail('TRUNCATED_ARCHIVE', f'Packed file exceeds archive size: {path}')
            if size:
                extents.append((start, start + size))
            if selected(path):
                files.append({'path': path, 'offset': start, 'size': size})

    walk(header['files'])
    extents.sort()
    if any(previous[1] > current[0] for previous, current in zip(extents, extents[1:])):
        fail('OVERLAPPING_FILES', 'Packed ASAR file byte ranges overlap')
    return sorted(files, key=lambda item: item['path']), count, data_offset


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def prepare(asar, out):
    source, destination = Path(asar).absolute(), Path(out).absolute()
    if destination.exists() or destination.is_symlink():
        fail('OUTPUT_EXISTS', 'Output must be a new directory')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(source, flags), 'rb') as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or source.is_symlink():
            fail('NOT_REGULAR_FILE', 'ASAR input must be a regular file, not a symlink')
        if before.st_size > MAX_ARCHIVE_BYTES:
            fail('ARCHIVE_TOO_LARGE', f'ASAR exceeds {MAX_ARCHIVE_BYTES} bytes')
        files, count, data_offset = parse_header(handle, before.st_size)
        if not any(item['path'] == 'package.json' for item in files):
            fail('PACKAGE_MISSING', 'ASAR root package.json is required')
        if not any(item['path'] != 'package.json' for item in files):
            fail('NO_PRELOAD_CANDIDATES', 'No packed preload .js/.cjs/.mjs candidates; manual selection is required')
        if len(files) > MAX_SELECTED_FILES:
            fail('TOO_MANY_SOURCES', f'Selection exceeds {MAX_SELECTED_FILES} files; narrow the scope manually')
        if any(item['size'] > MAX_FILE_BYTES for item in files):
            fail('SOURCE_TOO_LARGE', f'A selected source exceeds {MAX_FILE_BYTES} bytes')
        if sum(item['size'] for item in files) > MAX_SELECTED_BYTES:
            fail('SELECTION_TOO_LARGE', f'Selection exceeds {MAX_SELECTED_BYTES} bytes')
        contents = []
        for item in files:
            handle.seek(item['offset'])
            data = read_exact(handle, item['size'])
            try:
                data.decode('utf-8')
            except UnicodeDecodeError:
                fail('SOURCE_NOT_UTF8', f'Selected source is not UTF-8: {item["path"]}')
            contents.append(data)
        handle.seek(0)
        archive_hash = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = read_exact(handle, min(1024**2, remaining))
            archive_hash.update(chunk)
            remaining -= len(chunk)
        if (identity(before) != identity(os.fstat(handle.fileno()))
                or identity(before) != identity(source.lstat())):
            fail('ARCHIVE_CHANGED', 'ASAR changed while preparing sources')
    manifest = {
        'schema': 'rea-cli-factory.electron-preparation.v1',
        'status': 'candidate', 'reaExecuted': False, 'runtimeObserved': False,
        'archive': {'path': str(source), 'size': before.st_size,
                    'sha256': archive_hash.hexdigest(), 'dataOffset': data_offset},
        'selection': {'policy': 'root-package-and-preload-v1', 'entriesInspected': count,
                      'selectedFiles': len(files), 'selectedBytes': sum(x['size'] for x in files)},
        'sourcesDirectory': 'sources',
        'files': [{**item, 'outputPath': 'sources/' + item['path'],
                   'sha256': hashlib.sha256(data).hexdigest()} for item, data in zip(files, contents)],
        'limitations': [
            'Filename selection does not establish which preload runs or whether a bridge is reachable.',
            'This is a selected-source input, not complete application analysis; no target code was executed.',
            'No node_modules sources, source maps, unpacked files or linked files were read.',
            'Unrelated links and unpacked entries are skipped; selected links/unpacked entries are rejected.',
            'Manifest paths and source contents are private application evidence, not publication material.',
        ],
    }
    destination.mkdir(mode=0o700)  # Fails rather than merging with existing output.
    for item, data in zip(files, contents):
        target = destination / 'sources' / item['path']
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open('xb') as output:
            os.chmod(target, 0o600)
            output.write(data)
    with (destination / 'preparation.json').open('x', encoding='utf-8') as output:
        os.chmod(destination / 'preparation.json', 0o600)
        json.dump(manifest, output, ensure_ascii=False, indent=2)
        output.write('\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--asar', required=True, help='Original packed app.asar (read only)')
    parser.add_argument('--out', required=True, help='New private preparation directory')
    args = parser.parse_args()
    try:
        manifest = prepare(args.asar, args.out)
        print(json.dumps({'ok': True, 'status': 'candidate', 'out': str(Path(args.out).absolute()),
                          'selectedFiles': manifest['selection']['selectedFiles'],
                          'sourcesDirectory': str(Path(args.out).absolute() / 'sources'),
                          'manifest': str(Path(args.out).absolute() / 'preparation.json')}))
        return 0
    except (PreparationError, OSError, ValueError) as exc:
        print(json.dumps({'ok': False, 'error': {'code': getattr(exc, 'code', 'READ_WRITE_FAILED'),
                                                'message': str(exc)}}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
