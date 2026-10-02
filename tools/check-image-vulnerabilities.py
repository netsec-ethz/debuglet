#!/usr/bin/env python3
"""Apply the High/Critical policy to a successful, pinned Grype image scan."""
import datetime
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
import tarfile
from urllib.parse import urlsplit

spec = importlib.util.spec_from_file_location('go_policy', Path(__file__).with_name('check-vulnerabilities.py'))
go_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(go_policy)
DECODER, nonblank = go_policy.DECODER, go_policy.nonblank
ROLES = {'full', 'cli', 'dispatcher', 'executor'}
CONTROL = 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'


def read_json(path, limit):
    with open(path, 'rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('report exceeds size bound')
    return DECODER.decode(data.decode())


def archive_identity(path):
    # docker save's config digest identifies the image independently of tags.
    # Read only these bounded members; never extract an image onto the host.
    with tarfile.open(path) as archive:
        def member(name):
            entry = archive.getmember(name)
            if not entry.isfile() or entry.size > 4 << 20:
                raise ValueError('invalid image archive metadata')
            return archive.extractfile(entry).read()
        manifest = DECODER.decode(member('manifest.json').decode())
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError('expected one image in archive')
        return 'sha256:' + hashlib.sha256(member(manifest[0]['Config'])).hexdigest()


def check(report, exceptions, role, identity, today=None):
    today = today or datetime.date.today()
    if role not in ROLES | {'control'} or not isinstance(report, dict):
        raise ValueError('invalid scan target')
    descriptor = report['descriptor']
    if descriptor['name'] != 'grype' or descriptor['version'] != '0.119.0':
        raise ValueError('unexpected scanner version')
    db = descriptor['db']['status']
    if db['valid'] is not True or not all(nonblank(db.get(k)) for k in ('built', 'from', 'schemaVersion')):
        raise ValueError('missing valid vulnerability database identity')
    built = datetime.datetime.fromisoformat(db['built'].replace('Z', '+00:00'))
    if built.tzinfo is None or not today - datetime.timedelta(days=5) <= built.date() <= today:
        raise ValueError('vulnerability database is stale or from the future')
    config = descriptor['configuration']
    if (config.get('only-fixed') is not False or config.get('only-notfixed') is not False or
            config.get('exclude') != [] or config.get('vex-documents') != [] or
            config.get('search', {}).get('scope') != 'squashed' or report.get('ignoredMatches')):
        raise ValueError('filtered scan cannot establish image policy')
    source = report['source']
    if role == 'control':
        if source != {'type': 'purl', 'target': CONTROL}:
            raise ValueError('unexpected scanner control')
    elif (source['type'] != 'image' or source['target']['imageID'] != identity or
            source['target']['os'] != 'linux' or source['target']['architecture'] != 'amd64'):
        raise ValueError('scanner did not analyze the requested image')
    allowed = {}
    if not isinstance(exceptions, list):
        raise ValueError('exceptions must be a list')
    for item in exceptions:
        if (not isinstance(item, dict) or set(item) != {'role', 'id', 'package', 'expires', 'reason', 'review'} or
                not all(nonblank(value) for value in item.values()) or item['role'] not in ROLES or
                not re.fullmatch(r'(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)', item['id']) or
                not item['package'].startswith('pkg:')):
            raise ValueError('exception requires exact role, advisory, package, expiry, reason and review')
        review = urlsplit(item['review'])
        expiry = datetime.date.fromisoformat(item['expires'])
        if review.scheme != 'https' or not review.hostname or any(c.isspace() for c in item['review']):
            raise ValueError('exception requires an HTTPS review URL')
        if not today <= expiry <= today + datetime.timedelta(days=30):
            raise ValueError('exception expired or exceeds 30 days')
        key = (item['role'], item['id'], item['package'])
        if key in allowed:
            raise ValueError('duplicate exception')
        allowed[key] = item
    matches = report['matches']
    if not isinstance(matches, list):
        raise ValueError('missing scanner matches')
    findings = []
    for match in matches:
        vulnerability, artifact = match['vulnerability'], match['artifact']
        severity, fix = vulnerability['severity'], vulnerability['fix']
        if (not all(nonblank(vulnerability.get(k)) for k in ('id', 'dataSource', 'namespace')) or
                not all(nonblank(artifact.get(k)) for k in ('name', 'version', 'type', 'purl')) or
                severity not in ('Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical') or
                fix['state'] not in ('', 'fixed', 'not-fixed', 'unknown', 'wont-fix') or
                not isinstance(fix['versions'], list) or not all(nonblank(v) for v in fix['versions'])):
            raise ValueError('malformed vulnerability match')
        locations = artifact.get('locations', [])
        if role == 'control' and locations is None:
            locations = []
        if not isinstance(locations, list) or any(not nonblank(loc.get('path')) for loc in locations):
            raise ValueError('malformed package location')
        if role != 'control' and not locations:
            raise ValueError('image finding lacks a package location')
        exception = allowed.get((role, vulnerability['id'], artifact['purl']))
        findings.append((vulnerability, artifact, exception))
    return db, findings


def main():
    if len(sys.argv) != 5:
        raise ValueError('usage: check-image-vulnerabilities.py SCAN_JSON EXCEPTIONS_JSON ROLE ARCHIVE')
    scan, exceptions, role, archive = sys.argv[1:]
    identity = archive_identity(archive) if role != 'control' else ''
    db, findings = check(read_json(scan, 32 << 20), read_json(exceptions, 64 << 10), role, identity)
    print(f"grype 0.119.0; {role} {identity}; database {db['schemaVersion']} built {db['built']} from {db['from']}")
    for vuln, package, exception in findings:
        paths = ', '.join(item['path'] for item in package.get('locations') or [])
        print(f"{vuln['severity']} {vuln['id']}: {package['purl']}; paths {paths}; "
              f"{vuln['fix']['state'] or 'unknown'}; fixed in {','.join(vuln['fix']['versions']) or 'not available'}; {vuln['dataSource']}")
        if exception:
            print(f"Exception expires {exception['expires']}: {exception['review']}; {exception['reason']}")
    return int(any(v['severity'] in ('High', 'Critical') and not e for v, _, e in findings))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, KeyError, AttributeError, tarfile.TarError) as error:
        print(f'Image vulnerability evidence rejected: {error}', file=sys.stderr)
        sys.exit(2)
