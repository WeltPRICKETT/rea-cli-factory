#!/usr/bin/env python3
"""Read-only gate against a previously validated app-inventory.v1 baseline."""
import argparse
import json
from pathlib import Path
import plistlib
import re
import sys

from inventory_app import InventoryError, inventory

MAX_BASELINE_BYTES = 1024 * 1024
SCHEMA = 'rea-cli-factory.app-inventory.v1'
IDENTITY_FIELDS = {'CFBundleIdentifier', 'CFBundleName', 'CFBundleShortVersionString',
                   'CFBundleVersion', 'CFBundleExecutable'}
REQUIRED_ARTIFACTS = {'info_plist', 'executable'}
ARTIFACTS = REQUIRED_ARTIFACTS | {'app_asar'}
SCOPE = ('Only the fixed key files and identity match. This does not prove interface '
         'usability, runtime behavior, a full bundle match, or code-signature validity.')
RECOVERY = 'Reanalyze and validate the changed application before explicitly replacing the baseline.'


class BaselineError(ValueError):
    pass


def require(condition):
    if not condition:
        raise BaselineError('Baseline must be a valid app-inventory.v1 document.')


def absolute_path(value):
    require(isinstance(value, str) and '\x00' not in value)
    path = Path(value)
    require(path.is_absolute() and str(path) == value and '..' not in path.parts)
    return path


def validate_baseline(data):
    require(isinstance(data, dict))
    if 'ok' in data or 'result' in data:
        require(data.get('ok') is True and isinstance(data.get('result'), dict))
        data = data['result']
    require(data.get('schema') == SCHEMA)
    app = absolute_path(data.get('app_path'))
    require(app.suffix.lower() == '.app')
    identity = data.get('identity')
    require(isinstance(identity, dict) and set(identity) == IDENTITY_FIELDS)
    require(all(v is None or (isinstance(v, str) and '\x00' not in v) for v in identity.values()))
    executable = identity['CFBundleExecutable']
    require(isinstance(executable, str) and bool(executable)
            and Path(executable).name == executable and executable not in ('.', '..'))
    artifacts = data.get('artifacts')
    require(isinstance(artifacts, dict) and REQUIRED_ARTIFACTS <= set(artifacts) <= ARTIFACTS)
    for artifact in artifacts.values():
        require(isinstance(artifact, dict) and set(artifact) == {'path', 'sha256', 'size_bytes'})
        path = absolute_path(artifact['path'])
        require(path != app and app in path.parents)
        require(isinstance(artifact['sha256'], str)
                and re.fullmatch(r'[0-9a-f]{64}', artifact['sha256']) is not None)
        require(type(artifact['size_bytes']) is int and 0 <= artifact['size_bytes'] <= 2**63 - 1)
    analysis = data.get('analysis')
    require(isinstance(analysis, dict) and analysis.get('kind') == 'bundle-inventory')
    require(all(analysis.get(key) is False for key in
                ('rea_executed', 'runtime_observed', 'code_signature_verified')))
    require(isinstance(analysis.get('scope'), str))
    return data


def load_baseline(baseline):
    if isinstance(baseline, dict):
        return validate_baseline(baseline)
    try:
        with Path(baseline).open('rb') as stream:
            payload = stream.read(MAX_BASELINE_BYTES + 1)
        if len(payload) > MAX_BASELINE_BYTES:
            raise BaselineError('Baseline exceeds the 1 MiB limit.')

        def unique(pairs):
            obj = {}
            for key, value in pairs:
                require(key not in obj)
                obj[key] = value
            return obj

        def invalid_constant(_):
            raise BaselineError('Non-finite numbers are not valid baseline values.')

        data = json.loads(payload, object_pairs_hook=unique, parse_constant=invalid_constant)
        return validate_baseline(data)
    except BaselineError:
        raise
    except (OSError, ValueError, TypeError, RecursionError):
        raise BaselineError('Baseline cannot be read as valid bounded JSON.') from None


def check(app, baseline):
    """Return a gate result; baseline is an inventory dict/envelope or JSON path.

    Callers must stop before launching or acting when result['ok'] is false.
    A match is a point-in-time comparison, not a lock against subsequent updates.
    No baseline is written and no application process is started.
    """
    try:
        expected = load_baseline(baseline)
    except BaselineError as exc:
        return {'ok': False, 'error': {'code': 'INVALID_BASELINE', 'message': str(exc)}}
    try:
        observed = inventory(app)
    except (InventoryError, OSError, plistlib.InvalidFileException, ValueError, TypeError) as exc:
        return {'ok': False, 'error': {'code': getattr(exc, 'code', 'READ_FAILED'),
                                     'message': str(exc), **getattr(exc, 'details', {})}}
    differences = []

    def compare(field, before, after):
        if before != after:
            differences.append({'field': field, 'expected': before, 'observed': after})

    compare('app_path', expected['app_path'], observed['app_path'])
    for field in sorted(IDENTITY_FIELDS):
        compare('identity.' + field, expected['identity'][field], observed['identity'][field])
    compare('artifacts.keys', sorted(expected['artifacts']), sorted(observed['artifacts']))
    for name in sorted(expected['artifacts'].keys() & observed['artifacts'].keys()):
        for field in ('path', 'sha256', 'size_bytes'):
            compare('artifacts.' + name + '.' + field,
                    expected['artifacts'][name][field], observed['artifacts'][name][field])
    if differences:
        return {'ok': False, 'error': {'code': 'APP_CHANGED',
                                     'message': 'Application differs from the fixed baseline.'},
                'differences': differences, 'recovery': RECOVERY}
    return {'ok': True, 'status': 'compatible', 'scope': SCOPE,
            'limitations': ['Point-in-time check only; does not prevent a subsequent application update.',
                            'An inventory document alone does not prove that prior runtime validation occurred.']}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('Required arguments: --app PATH --baseline JSON')


def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        parser.add_argument('--app', required=True)
        parser.add_argument('--baseline', required=True)
        args = parser.parse_args(argv)
        result = check(args.app, args.baseline)
    except ValueError as exc:
        result = {'ok': False, 'error': {'code': 'INVALID_ARGUMENTS', 'message': str(exc)}}
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    if result['ok']:
        return 0
    return 3 if result['error']['code'] == 'APP_CHANGED' else 2


if __name__ == '__main__':
    sys.exit(main())
