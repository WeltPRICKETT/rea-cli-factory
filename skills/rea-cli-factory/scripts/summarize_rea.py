#!/usr/bin/env python3
"""Bounded developer index of REA JavaScript evidence; never a verifier."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import sys

MAX_BYTES = 64 * 1024 * 1024
OPERATION = 'analyze_javascript_application'
COUNTS = ('browser_windows', 'explicit_web_preferences', 'preload_entrypoints',
          'context_bridge_apis', 'exposed_api_members', 'sender_validation_observations',
          'utility_processes', 'resolved_utility_entrypoints', 'native_addon_bindings',
          'resolved_native_addon_bindings')
IPC_COUNTS = ('operations', 'literal_channels', 'dynamic_channel_operations',
              'renderer_transmissions', 'renderer_listeners', 'main_handlers',
              'paired_renderer_transmissions', 'ambiguous_renderer_transmissions',
              'unpaired_literal_renderer_transmissions')
SECRET = re.compile(r'password|passwd|secret|token|credential|authorization|api.?key|bearer', re.I)


class SummaryError(ValueError):
    pass


def require(condition):
    if not condition:
        raise SummaryError('INVALID_EVIDENCE')


def mapping(value):
    require(isinstance(value, dict))
    return value


def sequence(value):
    require(isinstance(value, list))
    return value


def count(value):
    require(type(value) is int and 0 <= value <= 2**63 - 1)
    return value


def identifier(value):
    require(isinstance(value, str))
    # Only short identifier-like labels are emitted. Free text and credential-like
    # identifiers are deliberately suppressed; this is not a publication scrubber.
    if (not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_.$:\-]{0,159}', value)
            or SECRET.search(value) or re.search(r'[A-Za-z0-9_]{40,}', value)):
        return '[redacted]'
    return value


def source_range(observation):
    evidence = mapping(observation.get('evidence'))
    location = mapping(evidence.get('location'))
    require(type(location.get('available')) is bool)
    if not location['available']:
        return None
    location = mapping(location.get('value'))
    if location.get('kind') == 'artifact-path':
        require(isinstance(location.get('path'), str))
        return None
    require(location.get('kind') == 'source-range')
    source = location.get('source')
    require(isinstance(source, str))
    # Keep relative artifact paths only. Reject rather than truncate dangerous
    # paths, since truncation can change the meaning of a location.
    safe = (len(source) <= 240 and not PurePosixPath(source).is_absolute()
            and all(p not in ('', '.', '..') for p in source.split('/'))
            and re.fullmatch(r'[A-Za-z0-9_./@+ -]+', source)
            and not SECRET.search(source))
    points = {}
    for key in ('start', 'end'):
        point = mapping(location.get(key))
        points[key] = {'line': count(point.get('line')), 'column': count(point.get('column'))}
    require((points['start']['line'], points['start']['column']) <=
            (points['end']['line'], points['end']['column']))
    return {'source': source if safe else '[redacted]', **points}


def summarize(data, query='', limit=10):
    require(isinstance(query, str) and len(query) <= 256)
    require(type(limit) is int and 1 <= limit <= 50)
    data = mapping(data)
    require(data.get('operation') == OPERATION)
    evidence_id = data.get('evidence_id')
    require(isinstance(evidence_id, str) and re.fullmatch(r'ev_[a-f0-9]{64}', evidence_id))
    normalized = mapping(data.get('normalized_result'))
    graph = mapping(normalized.get('graph'))
    coverage = mapping(graph.get('coverage'))
    require(coverage.get('status') in ('complete', 'partial', 'unknown', 'unavailable'))
    require(type(coverage.get('truncated')) is bool)
    omitted = coverage.get('omitted_count')
    if omitted is not None:
        count(omitted)
    summary = mapping(normalized.get('summary'))
    counts = {key: count(summary.get(key)) for key in COUNTS}
    ipc = mapping(summary.get('ipc'))
    counts['ipc'] = {key: count(ipc.get(key)) for key in IPC_COUNTS}
    findings, matched = [], 0
    for node in sequence(graph.get('nodes')):
        node = mapping(node)
        kind = identifier(node.get('kind'))
        for obs in sequence(node.get('observations')):
            obs = mapping(obs)
            require('label' in obs)
            label = identifier(obs['label']) if obs['label'] is not None else None
            location = source_range(obs)
            if query.casefold() in (obs['label'] or '').casefold():
                matched += 1
                if len(findings) < limit:
                    findings.append({'kind': kind, 'label': label, 'sourceRange': location})
    # Never echo arbitrary provider diagnostics: those may contain local paths,
    # source excerpts or credentials. Fixed messages preserve the proof boundary.
    limitation_count = 0
    for owner in (data, normalized, graph):
        values = sequence(owner.get('limitations', []))
        require(all(isinstance(v, str) for v in values))
        limitation_count += len(values)
    limitations = [
        'Developer summary only; evidence IDs are copied, not cryptographically verified.',
        'Static observations do not prove runtime reachability or successful application actions.',
        'Only application-graph observations are indexed; semantic graphs and raw results are excluded.',
        'Source diagnostics are omitted; consult the private original evidence for full limitations.',
        'Labels and relative paths are filtered; this summary is not a publication or secret-scanning guarantee.',
    ]
    if coverage['status'] != 'complete' or coverage['truncated']:
        limitations.append('Analysis coverage is incomplete; missing findings do not establish absence.')
    return {'evidenceId': evidence_id, 'operation': OPERATION,
            'coverage': {'status': coverage['status'], 'truncated': coverage['truncated'],
                         'omittedCount': omitted},
            'summaryCounts': counts, 'totalMatched': matched, 'findings': findings,
            'selectionTruncated': matched > len(findings),
            'sourceLimitationEntries': limitation_count, 'limitations': limitations}


def read_evidence(path):
    try:
        with Path(path).open('rb') as stream:
            payload = stream.read(MAX_BYTES + 1)
        if len(payload) > MAX_BYTES:
            raise SummaryError('INPUT_TOO_LARGE')
        # Duplicate keys and non-finite numbers must not silently change evidence.
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result)
                result[key] = value
            return result
        def invalid_constant(_):
            raise SummaryError('INVALID_JSON')
        return json.loads(payload, object_pairs_hook=unique, parse_constant=invalid_constant)
    except OSError:
        raise SummaryError('INPUT_UNREADABLE') from None
    except SummaryError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise SummaryError('INVALID_JSON') from None


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SummaryError('INVALID_ARGUMENTS')


def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        parser.add_argument('--input', required=True)
        parser.add_argument('--query', default='', help='Case-insensitive substring of observation label')
        parser.add_argument('--limit', type=int, default=10, help='Maximum findings (1-50)')
        args = parser.parse_args(argv)
        result = summarize(read_evidence(args.input), args.query, args.limit)
    except (SummaryError, RecursionError) as exc:
        code = str(exc) if isinstance(exc, SummaryError) else 'INVALID_JSON'
        print(json.dumps({'ok': False, 'error': code}))
        return 1
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
