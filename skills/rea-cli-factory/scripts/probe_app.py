#!/usr/bin/env python3
"""Discover bounded, static adapter candidates; never launch an application."""
import argparse
import json
from pathlib import Path
import plistlib
import sys
from inventory_app import inventory, within, find_by_name, InventoryError


def probe(app, member_limit=256):
    base = inventory(app)
    root = Path(base['app_path'])
    info_path = within(root, root / 'Contents/Info.plist')
    info = plistlib.loads(info_path.read_bytes())
    candidates, markers, coverage = [], [], []
    # Never walk an entire app, user-data directory, or arbitrary symlink tree.
    for rel in ['Contents/Frameworks', 'Contents/MacOS', 'Contents/Resources',
                'Contents/Resources/bin', 'Contents/Helpers']:
        folder = within(root, root / rel)
        if not folder.is_dir():
            continue
        entries = []
        truncated = False
        for entry in folder.iterdir():
            if len(entries) == member_limit:
                truncated = True
                break
            entries.append(entry)
        coverage.append({'directory': rel, 'entriesInspected': len(entries), 'truncated': truncated})
        for entry in sorted(entries):
            safe = within(root, entry)
            location = str(entry.relative_to(root))
            if entry.name == 'Electron Framework.framework' or entry.name.startswith('Qt') and entry.suffix == '.framework':
                markers.append({'kind': 'framework', 'path': location})
            if entry.suffix == '.sdef' and safe.is_file():
                candidates.append({'kind': 'applescript-dictionary', 'path': location,
                                   'state': 'candidate', 'next': 'Read dictionary; test only an owned document.'})
            if rel in ['Contents/Resources/bin', 'Contents/Helpers'] and safe.is_file() and safe.stat().st_mode & 0o111:
                candidates.append({'kind': 'bundled-executable', 'path': location,
                                   'state': 'candidate', 'next': 'Inspect its purpose before running even --help.'})
    if 'app_asar' in base['artifacts']:
        markers.append({'kind': 'asar', 'path': 'Contents/Resources/app.asar'})
    declaration = info.get('OSAScriptingDefinition')
    if isinstance(declaration, str):
        declared = within(root, root / 'Contents/Resources' / declaration)
        if declared.is_file() and not any(c['path'] == str(declared.relative_to(root)) for c in candidates):
            candidates.append({'kind': 'applescript-dictionary', 'path': str(declared.relative_to(root)),
                               'state': 'candidate', 'next': 'Read dictionary; test only an owned document.'})
    routes = ['documented-api-or-cli']
    if any(c['kind'] == 'applescript-dictionary' for c in candidates):
        routes.append('applescript')
    if any(m['kind'] == 'asar' or 'Electron' in m['path'] for m in markers):
        routes.append('rea-javascript-if-needed')
    else:
        routes.append('rea-native-if-needed')
    return {'schema': 'rea-cli-factory.probe.v1', 'inventory': base, 'markers': markers,
            'candidates': candidates, 'routeOrder': routes, 'coverage': coverage,
            'reaExecuted': False, 'runtimeObserved': False,
            'limitations': ['Static candidates are not verified capabilities.',
                           'No native CLI flags, permissions, runtime session or user data inspected.',
                           'Absence within bounded directories does not establish lack of automation.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--app')
    group.add_argument('--name')
    args = parser.parse_args()
    try:
        print(json.dumps({'ok': True, 'result': probe(args.app or find_by_name(args.name))}, ensure_ascii=False, indent=2))
        return 0
    except (InventoryError, OSError, ValueError, TypeError, plistlib.InvalidFileException) as e:
        print(json.dumps({'ok': False, 'error': {'code': getattr(e, 'code', 'READ_FAILED'), 'message': str(e)}}, ensure_ascii=False))
        return 2


if __name__ == '__main__':
    sys.exit(main())
