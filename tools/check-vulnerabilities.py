#!/usr/bin/env python3
"""Apply the reachable-symbol policy to a successful govulncheck JSON scan."""
import datetime
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError(f'invalid JSON constant: {value}')


DECODER = json.JSONDecoder(object_pairs_hook=unique_object, parse_constant=invalid_constant)
ADVISORY_ID = re.compile(r'GO-\d{4}-\d{4,}')


def nonblank(value):
    return isinstance(value, str) and bool(value.strip())


def messages(text):
    while text.strip():
        value, end = DECODER.raw_decode(text.lstrip())
        if not isinstance(value, dict) or len(value) != 1:
            raise ValueError('invalid scanner event')
        yield value
        text = text.lstrip()[end:]


def check(text, exceptions, today=None):
    today = today or datetime.date.today()
    events = list(messages(text))
    if not events or 'config' not in events[0] or sum('config' in event for event in events) != 1:
        raise ValueError('missing scanner configuration')
    config = events[0]['config']
    if (not isinstance(config, dict) or config.get('protocol_version') != 'v1.0.0' or
            config.get('scanner_name') != 'govulncheck' or
            config.get('scanner_version') != 'v1.7.0' or
            config.get('scan_level') != 'symbol' or config.get('scan_mode') != 'source' or
            not nonblank(config.get('db')) or not nonblank(config.get('db_last_modified'))):
        raise ValueError('unexpected scanner version, mode or database metadata')
    timestamp = config['db_last_modified']
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})', timestamp):
        raise ValueError('invalid database timestamp')
    datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    sboms = [event['SBOM'] for event in events if 'SBOM' in event]
    if not sboms:
        raise ValueError('scanner did not report analyzed roots')
    for sbom in sboms:
        roots = sbom.get('roots') if isinstance(sbom, dict) else None
        if not isinstance(roots, list) or not roots or not all(nonblank(root) for root in roots):
            raise ValueError('invalid analyzed roots')
    allowed = {}
    if not isinstance(exceptions, list):
        raise ValueError('exceptions must be a list')
    for item in exceptions:
        if (not isinstance(item, dict) or set(item) != {'id', 'module', 'expires', 'reason', 'review'} or
                not all(nonblank(value) for value in item.values())):
            raise ValueError('exception requires id, module, expiry, reason and review')
        review = urlsplit(item['review'])
        if (not ADVISORY_ID.fullmatch(item['id']) or review.scheme != 'https' or not review.hostname or
                any(char.isspace() for char in item['review'])):
            raise ValueError('exception requires an advisory ID and HTTPS review URL')
        expiry = datetime.date.fromisoformat(item['expires'])
        if expiry < today or expiry > today + datetime.timedelta(days=30):
            raise ValueError('exception expired or exceeds 30 days')
        key = (item['id'], item['module'])
        if key in allowed:
            raise ValueError('duplicate exception')
        allowed[key] = item
    findings = []
    for event in events:
        if next(iter(event)) not in ('config', 'progress', 'SBOM', 'osv', 'finding'):
            raise ValueError('unknown scanner event')
        if 'finding' not in event:
            continue
        finding = event['finding']
        trace = finding.get('trace') if isinstance(finding, dict) else None
        if (not isinstance(trace, list) or not trace or not nonblank(finding.get('osv')) or
                not ADVISORY_ID.fullmatch(finding['osv']) or
                ('fixed_version' in finding and not nonblank(finding['fixed_version']))):
            raise ValueError('malformed scanner finding')
        for frame in trace:
            if (not isinstance(frame, dict) or not nonblank(frame.get('module')) or
                    any(key in frame and not nonblank(frame[key]) for key in ('package', 'function'))):
                raise ValueError('malformed scanner trace')
        if trace[0].get('function'):
            exception = allowed.get((finding['osv'], trace[0]['module']))
            findings.append(dict(finding, exception=exception))
    return config, findings


def main():
    if len(sys.argv) != 3:
        raise ValueError('usage: check-vulnerabilities.py SCAN_JSON EXCEPTIONS_JSON')
    config, findings = check(Path(sys.argv[1]).read_text(), DECODER.decode(Path(sys.argv[2]).read_text()))
    print(f"govulncheck {config['scanner_version']}; database {config['db']} at {config['db_last_modified']}")
    for finding in findings:
        path = ' <- '.join(frame.get('package', frame['module']) + '.' + frame.get('function', '')
                           for frame in finding['trace'])
        print(f"{finding['osv']}: {path}; fixed in {finding.get('fixed_version') or 'not available'}")
        if finding['exception']:
            print(f"Exception expires {finding['exception']['expires']}: {finding['exception']['review']}")
    return int(any(not finding['exception'] for finding in findings))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(f'Vulnerability evidence rejected: {error}', file=sys.stderr)
        sys.exit(2)
