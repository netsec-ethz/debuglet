#!/usr/bin/env python3
"""Apply the reachable-symbol policy to a successful govulncheck JSON scan."""
import datetime
import json
from pathlib import Path
import sys


def messages(text):
    decoder = json.JSONDecoder()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        if not isinstance(value, dict) or len(value) != 1:
            raise ValueError('invalid scanner event')
        yield value
        text = text.lstrip()[end:]


def check(text, exceptions, today=None):
    today = today or datetime.date.today()
    events = list(messages(text))
    if not events or 'config' not in events[0]:
        raise ValueError('missing scanner configuration')
    config = events[0]['config']
    if (config.get('protocol_version') != 'v1.0.0' or
            config.get('scanner_name') != 'govulncheck' or
            config.get('scanner_version') != 'v1.7.0' or
            config.get('scan_level') != 'symbol' or config.get('scan_mode') != 'source' or
            not config.get('db_last_modified')):
        raise ValueError('unexpected scanner version, mode or database metadata')
    if not any(event.get('SBOM', {}).get('roots') for event in events):
        raise ValueError('scanner did not report analyzed roots')
    allowed = {}
    if not isinstance(exceptions, list):
        raise ValueError('exceptions must be a list')
    for item in exceptions:
        if set(item) != {'id', 'module', 'expires', 'reason', 'review'} or not all(item.values()):
            raise ValueError('exception requires id, module, expiry, reason and review')
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
        trace = finding.get('trace')
        if not finding.get('osv') or not isinstance(trace, list) or not trace or not trace[0].get('module'):
            raise ValueError('malformed scanner finding')
        if trace[0].get('function'):
            exception = allowed.get((finding['osv'], trace[0]['module']))
            findings.append(dict(finding, exception=exception))
    return config, findings


def main():
    if len(sys.argv) != 3:
        raise ValueError('usage: check-vulnerabilities.py SCAN_JSON EXCEPTIONS_JSON')
    config, findings = check(Path(sys.argv[1]).read_text(), json.loads(Path(sys.argv[2]).read_text()))
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
