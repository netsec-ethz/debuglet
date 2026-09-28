#!/usr/bin/env python3
"""Record build inputs offline and bind release inventory to already-built bytes.

The JSON documents are evidence, not authentication. A release verifier must
verify the signature over their digests before trusting this module's checks.
"""
import argparse
import hashlib
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

REPOSITORY = 'https://github.com/netsec-ethz/debuglet'
BUILDER = REPOSITORY + '/.github/workflows/ci.yml'
MANIFEST = 'share/debuglet/manifest.json'
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
GUESTS = {'hello.wasm': 'hello-local', 'demo.wasm': 'demo', 'ping.wasm': 'ping', 'helloworld.wasm': 'helloworld'}
COMPONENTS = {'dbl', 'debuglet-dispatcher', 'debuglet-executor'} | GUESTS.keys()
SOURCE_INPUTS = ('go.mod', 'go.sum', 'LICENSE', 'NOTICE', 'deploy/ci/images.env',
                 'deploy/ci/packages.txt', 'deploy/ci/Dockerfile',
                 'deploy/docker/debuglet.Dockerfile', 'scripts/ci-kernel.sh')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(data):
    require(len(data) <= 4 * 1024 * 1024, 'JSON evidence exceeds 4 MiB')
    def invalid(value):
        raise ValueError('invalid JSON number: ' + value)
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def read_json(path):
    path = Path(path)
    require(path.stat().st_size <= 4 * 1024 * 1024, 'JSON evidence exceeds 4 MiB')
    return decode(regular(path))


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def digest(data):
    return {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def regular(path):
    require(path.is_file() and not path.is_symlink(), 'expected regular file: ' + str(path))
    require(path.stat().st_size <= 512 * 1024 * 1024, 'release file exceeds 512 MiB')
    return path.read_bytes()


def command(args, cwd, **extra_env):
    env = dict(os.environ, GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local', **extra_env)
    return subprocess.check_output(args, cwd=cwd, env=env, text=True, timeout=60)


def build_info(output, expected_go, source, native):
    lines = output.splitlines()
    require(lines and lines[0].endswith(': ' + expected_go), 'binary Go version differs')
    modules, settings = [], {}
    main = None
    for line in lines[1:]:
        fields = line.strip().split('\t')
        if fields[0] == 'dep':
            require(len(fields) == 4 and fields[2].startswith('v') and fields[3].startswith('h1:'),
                    'dependency has no exact module version/checksum')
            modules.append(dict(zip(('path', 'version', 'sum'), fields[1:])))
        elif fields[0] == '=>':
            raise ValueError('replacement modules require an explicit release inventory policy')
        elif fields[0] == 'mod':
            main = fields[1:3]
        elif fields[0] == 'build':
            require(len(fields) == 2 and '=' in fields[1], 'invalid Go build setting')
            key, value = fields[1].split('=', 1)
            require(key not in settings, 'duplicate Go build setting')
            settings[key] = value
    require(main and main[0] == 'github.com/netsec-ethz/debuglet' and
            (main[1] == '(devel)' or main[1].startswith('v')), 'unexpected main module')
    require(len({m['path'] for m in modules}) == len(modules), 'duplicate Go module')
    if native:
        require(settings.get('vcs.revision') == source and settings.get('vcs.modified') == 'false',
                'native binary source identity differs')
    require(settings.get('CGO_ENABLED') == '0', 'release binary must be statically built')
    return {'go_version': expected_go, 'main_module_version': main[1], 'modules': sorted(modules, key=lambda m: m['path']),
            'settings': settings, 'evidence': 'embedded-build-info'}


def collect(source_directory, dist, image_evidence, out, go='go'):
    source_directory, dist = Path(source_directory), Path(dist)
    source = command(['git', 'rev-parse', 'HEAD'], source_directory).strip()
    require(not command(['git', 'status', '--porcelain', '--untracked-files=normal'], source_directory).strip(),
            'inventory requires the clean committed build source')
    record = read_json(dist / 'build-record.json')
    meta = record['metadata']
    require(meta['source_sha'] == source and meta['dirty'] is False, 'build record source differs')
    require(set(record['compiled_files']) == COMPONENTS, 'unexpected compiled component set')
    image = read_json(image_evidence)
    require(image['failures'] == [] and image['go_version'] == meta['go_version'],
            'build image verification failed or Go version differs')
    pipeline = image['pipeline']
    require(pipeline['github_sha'] == source and pipeline['github_job'] == 'build',
            'image evidence is not from this build')
    run_id, attempt = pipeline['github_run_id'], pipeline['github_run_attempt']
    require(str(run_id).isdigit() and str(attempt).isdigit(), 'missing build invocation')
    require(meta['build_pipeline_url'] == REPOSITORY + '/actions/runs/' + str(run_id),
            'build record pipeline differs from image evidence')
    pins = {}
    for line in (source_directory / 'deploy/ci/images.env').read_text().splitlines():
        if line.startswith('DEBUGLET_'):
            key, value = line.split('=', 1)
            pins[key] = value
    build_image = pins['DEBUGLET_CI_BASE_IMAGE'] + '@' + pins['DEBUGLET_CI_BASE_DIGEST']
    require(image['expected_image'] == build_image and image['job_image'] == build_image,
            'observed build image differs from source pin')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', image['image_id'] or ''), 'missing actual image ID')
    sums = set((source_directory / 'go.sum').read_text().splitlines())
    components = []
    for name in sorted(COMPONENTS):
        path = dist / name
        hashed = digest(regular(path))
        require(hashed == record['compiled_files'][name], 'compiled bytes differ: ' + name)
        if name in GUESTS:
            # Go does not expose embedded build info from WASI binaries. Resolve
            # their dependency graph from the same clean source, offline.
            template = '{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Sum}}{{end}}{{end}}'
            output = command([go, 'list', '-mod=readonly', '-deps', '-f', template,
                              './examples/debuglets/go/' + GUESTS[name]], source_directory,
                             GOOS='wasip1', GOARCH='wasm', CGO_ENABLED='0')
            modules = {}
            for line in output.splitlines():
                if line:
                    fields = line.split('\t')
                    require(len(fields) == 3, 'guest module is not pinned')
                    modules[fields[0]] = dict(zip(('path', 'version', 'sum'), fields))
            info = {'go_version': meta['go_version'], 'modules': sorted(modules.values(), key=lambda m: m['path']),
                    'settings': {'CGO_ENABLED': '0', 'GOOS': 'wasip1', 'GOARCH': 'wasm'},
                    'evidence': 'source-dependency-graph'}
        else:
            info = build_info(command([go, 'version', '-m', str(path.resolve())], source_directory),
                              meta['go_version'], source, True)
        for module in info['modules']:
            require('{path} {version} {sum}'.format(**module) in sums,
                    'binary dependency missing from committed go.sum')
        components.append({'name': name, **hashed, **info})
    paths = set(SOURCE_INPUTS)
    for directory in ('ratelimit', 'tagger'):
        for path in (source_directory / 'internal/executor' / directory / 'ebpf').rglob('*'):
            if path.is_file() and path.suffix in ('.c', '.h', '.o', '.go'):
                paths.add(path.relative_to(source_directory).as_posix())
    require(any(name.endswith('.o') for name in paths), 'missing committed BPF objects')
    materials = [{'name': name, **digest(regular(source_directory / name))} for name in sorted(paths)]
    tools = [{'name': 'Go', 'version': meta['go_version'], 'purpose': 'compilation'}]
    for line in (source_directory / 'deploy/ci/packages.txt').read_text().splitlines():
        fields = line.split('#', 1)[0].split()
        if fields:
            require(len(fields) == 2, 'invalid pinned tool package')
            tools.append({'name': fields[0], 'version': fields[1], 'purpose': 'declared-validation-tool'})
    module_text = (source_directory / 'go.mod').read_text()
    version = re.search(r'^\s*github.com/cilium/ebpf (v\S+)', module_text, re.M)
    require(version is not None, 'missing bpf2go module pin')
    tools.append({'name': 'github.com/cilium/ebpf/cmd/bpf2go', 'version': version[1],
                  'purpose': 'declared-BPF-regeneration-tool'})
    images = [{'name': 'build image', 'reference': build_image, 'purpose': 'compilation'},
              {'name': 'runtime base', 'reference': pins['DEBUGLET_CI_RUNTIME_IMAGE'],
               'purpose': 'supported-runtime-base'}]
    for image_pin in images:
        require(re.search(r'@sha256:[0-9a-f]{64}$', image_pin['reference']), 'image is not pinned')
    result = {'schema_version': 1, 'build_record': record, 'build_image': image,
              'components': components, 'materials': materials, 'tools': tools, 'images': images,
              'notices': {name: regular(source_directory / name).decode() for name in ('LICENSE', 'NOTICE')}}
    Path(out).write_bytes(encoded(result))


def properties(**values):
    return [{'name': 'debuglet:' + key, 'value': str(value)} for key, value in sorted(values.items())]


def component(ref, kind, name, version=None, hashed=None, **props):
    value = {'bom-ref': ref, 'type': kind, 'name': name}
    if version:
        value['version'] = version
    if hashed:
        value['hashes'] = [{'alg': 'SHA-256', 'content': hashed['sha256']}]
    if props:
        value['properties'] = properties(**props)
    return value


class BoundedTarReader:
    """Bound the decompressed stream before tarfile reads extension records."""
    def __init__(self, stream):
        self.stream = stream

    def tell(self):
        return self.stream.tell()

    def read(self, size):
        require(0 <= size <= MAX_ARCHIVE_BYTES - self.tell(), 'decompressed archive exceeds limit')
        return self.stream.read(size)

    def seek(self, offset, whence=0):
        require(whence in (0, 1), 'unsupported archive seek')
        position = offset + (self.tell() if whence == 1 else 0)
        require(0 <= position <= MAX_ARCHIVE_BYTES, 'decompressed archive exceeds limit')
        return self.stream.seek(position)


def payloads(directory, version, source, builder, inputs):
    expected = inputs['build_record']['compiled_files']
    archives = sorted(directory.glob('*.tar.gz'))
    require(len(archives) == 4, 'release requires full, CLI, dispatcher and executor archives')
    result = []
    seen = set()
    for path in archives:
        require(path.is_file() and not path.is_symlink(), 'archive must be regular')
        require(path.stat().st_size <= MAX_ARCHIVE_BYTES, 'compressed archive exceeds limit')
        with gzip.open(path, 'rb') as stream, tarfile.open(fileobj=BoundedTarReader(stream), mode='r:') as archive:
            members = []
            for member in archive:
                members.append(member)
                require(len(members) <= 256 and member.size <= 256 * 1024 * 1024
                        and sum(m.size for m in members) <= 512 * 1024 * 1024, 'archive exceeds payload limits')
            names = [m.name for m in members]
            require(len(names) == len(set(names)) and all(m.isfile() for m in members),
                    'archive contains duplicate or non-regular members')
            require(all(PurePosixPath(n).as_posix() == n and not n.startswith('/') and '..' not in PurePosixPath(n).parts
                        for n in names), 'unsafe archive member')
            require(archive.getmember(MANIFEST).size <= 64 * 1024, 'archive manifest exceeds 64 KiB')
            meta = decode(archive.extractfile(MANIFEST).read())
            role = meta.get('component', '')
            require(role in ('', 'cli', 'dispatcher', 'executor') and role not in seen, 'duplicate or unknown archive role')
            seen.add(role)
            require(meta['version'] == version and meta['source_sha'] == source and meta['dirty'] is False
                    and meta['build_pipeline_url'] == builder, 'archive identity differs')
            binaries = {'cli': {'bin/dbl'}, 'dispatcher': {'bin/debuglet-dispatcher'},
                        'executor': {'bin/debuglet-executor'},
                        '': {'bin/dbl', 'bin/debuglet-dispatcher', 'bin/debuglet-executor',
                             'share/debuglet/hello.wasm', 'share/debuglet/demo.wasm'}}[role]
            require(set(meta['files']) == binaries | {'LICENSE', 'README-install.md'}
                    and set(names) == set(meta['files']) | {MANIFEST}, 'archive manifest files differ')
            for name in meta['files']:
                data = archive.extractfile(name).read()
                require(digest(data) == meta['files'][name], 'archive payload checksum differs: ' + name)
                if name.startswith('bin/') or name.endswith('.wasm'):
                    require(digest(data) == expected[PurePosixPath(name).name], 'archive rebuilt or substituted')
                if name == 'LICENSE':
                    require(data == inputs['notices']['LICENSE'].encode(), 'archive inherited LICENSE differs')
            name = 'debuglet-' + (role + '-' if role else '') + version + '-linux-amd64.tar.gz'
            require(path.name == name, 'archive name differs from role/version')
            installer = directory / ('install-' + role + '.sh' if role else 'install.sh')
            installer_bytes = regular(installer)
            require(installer_bytes, 'missing installer')
            checksums = directory / ('SHA256SUMS-' + role if role else 'SHA256SUMS')
            expected_sums = ''.join(digest(data)['sha256'] + '  ' + filename + '\n'
                                    for filename, data in ((path.name, regular(path)), (installer.name, installer_bytes)))
            require(regular(checksums) == expected_sums.encode(), 'archive/installer checksum pair differs')
            result.append((path.name, meta))
    return result


def validate_inputs(inputs, version, source, builder):
    require(inputs['schema_version'] == 1, 'unknown build inputs schema')
    record, image = inputs['build_record'], inputs['build_image']
    meta, pipeline = record['metadata'], image['pipeline']
    require(meta['version'] == version and meta['source_sha'] == source and meta['dirty'] is False
            and meta['build_pipeline_url'] == builder and image['failures'] == [], 'build inputs identity differs')
    require(image['go_version'] == meta['go_version'] and pipeline['github_job'] == 'build'
            and pipeline['github_sha'] == source, 'build image identity differs')
    require(image['job_image'] == image['expected_image']
            and re.fullmatch(r'sha256:[0-9a-f]{64}', image['image_id'] or ''), 'unverified build image')
    require(set(record['compiled_files']) == COMPONENTS, 'incomplete compiled artifact inventory')
    compiled = {c['name']: c for c in inputs['components']}
    require(set(compiled) == COMPONENTS and len(compiled) == len(inputs['components']), 'incomplete component inventory')
    for name, c in compiled.items():
        require({k: c[k] for k in ('sha256', 'bytes')} == record['compiled_files'][name]
                and c['go_version'] == meta['go_version'], 'component identity differs')
        require(c['settings'].get('CGO_ENABLED') == '0', 'missing static build metadata')
        require(c['evidence'] == ('source-dependency-graph' if name in GUESTS else 'embedded-build-info'),
                'missing dependency evidence kind')
        if not name.endswith('.wasm'):
            require(c['settings'].get('vcs.revision') == source
                    and c['settings'].get('vcs.modified') == 'false', 'missing clean native source identity')
        require(len(c['modules']) == len({m['path'] for m in c['modules']}), 'duplicate component module')
        for module in c['modules']:
            require(module['path'] and re.fullmatch(r'v\S+', module['version'])
                    and re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', module['sum']), 'invalid exact module identity')
    materials = {m['name']: m for m in inputs['materials']}
    require(len(materials) == len(inputs['materials']) and set(SOURCE_INPUTS) <= materials.keys()
            and any(n.endswith('.o') for n in materials), 'missing source or BPF inputs')
    for material in materials.values():
        require(re.fullmatch(r'[0-9a-f]{64}', material['sha256']) and type(material['bytes']) is int
                and material['bytes'] > 0, 'invalid source material digest')
    for name in ('LICENSE', 'NOTICE'):
        require(digest(inputs['notices'][name].encode()) == {k: materials[name][k] for k in ('sha256', 'bytes')},
                'inherited notice digest differs')
    tools = {t['name']: t for t in inputs['tools']}
    require(len(tools) == len(inputs['tools']) and {'Go', 'clang', 'llvm', 'libbpf-dev', 'linux-libc-dev',
            'github.com/cilium/ebpf/cmd/bpf2go'} <= tools.keys(), 'missing build or BPF validation tools')
    require(tools['Go']['version'] == meta['go_version'], 'toolchain identity differs')
    require(all(t['version'] and t['purpose'] for t in tools.values()), 'missing tool version or purpose')
    images = {i['purpose']: i for i in inputs['images']}
    require(len(images) == len(inputs['images']) and set(images) == {'compilation', 'supported-runtime-base'}
            and images['compilation']['reference'] == image['expected_image'], 'missing or mismatched image inputs')
    return compiled


def documents(directory, version, source, builder, inputs):
    compiled = validate_inputs(inputs, version, source, builder)
    pipeline = inputs['build_image']['pipeline']
    gates = read_json(directory / 'gates.json')
    require(gates['source_sha'] == source and gates['version'] == version and gates['builder'] == builder,
            'gate identity differs')
    require(pipeline['github_sha'] == source and str(gates['run_id']) == str(pipeline['github_run_id'])
            and str(gates['run_attempt']) == str(pipeline['github_run_attempt']), 'build came from another invocation')
    components, edges, modules = [], [], {}
    for archive_name, manifest in payloads(directory, version, source, builder, inputs):
        ref = 'archive:' + archive_name
        components.append(component(ref, 'application', archive_name, version,
                                    digest(regular(directory / archive_name))))
        children = []
        for path in sorted(manifest['files']):
            name = PurePosixPath(path).name
            if name not in compiled:
                continue
            c = compiled[name]
            child = 'binary:' + name
            children.append(child)
            if any(x['bom-ref'] == child for x in components):
                continue
            components.append(component(child, 'application', name, version, c,
                                        go_version=c['go_version'], evidence=c['evidence'], purpose='runtime'))
            dependencies = []
            for module in c['modules']:
                key = module['path'] + '@' + module['version']
                require(key not in modules or modules[key] == module, 'inconsistent module checksums')
                modules[key] = module
                dependencies.append('module:' + key)
            edges.append({'ref': child, 'dependsOn': dependencies})
        edges.append({'ref': ref, 'dependsOn': children})
    for key, module in sorted(modules.items()):
        components.append(component('module:' + key, 'library', module['path'], module['version'],
                                    module_sum=module['sum'], purpose='runtime'))
    for index, tool in enumerate(inputs['tools']):
        components.append(component('tool:' + str(index), 'application', tool['name'], tool['version'],
                                    purpose=tool['purpose']))
    for index, image_pin in enumerate(inputs['images']):
        reference = image_pin['reference']
        require(re.search(r'@sha256:[0-9a-f]{64}$', reference), 'image is not pinned')
        components.append(component('image:' + str(index), 'container', image_pin['name'], reference,
                                    {'sha256': reference.rsplit(':', 1)[1]}, purpose=image_pin['purpose']))
    for material in inputs['materials']:
        components.append(component('source:' + material['name'], 'file', material['name'], hashed=material,
                                    purpose='committed-build-input'))
    sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': component('debuglet', 'application', 'Debuglet', version),
                         'properties': properties(source_sha=source, builder=builder)},
            'components': components, 'dependencies': edges}
    subject_files = sorted(p for p in directory.iterdir() if p.is_file() and
                           (p.name.endswith(('.tar.gz', '.sh')) or p.name.startswith('SHA256SUMS')))
    subjects = [{'name': p.name, 'digest': {'sha256': digest(regular(p))['sha256']}} for p in subject_files]
    subjects.append({'name': 'sbom.cdx.json', 'digest': {'sha256': digest(encoded(sbom))['sha256']}})
    provenance = {'_type': 'https://in-toto.io/Statement/v1', 'subject': subjects,
                  'predicateType': 'https://slsa.dev/provenance/v1', 'predicate': {
                      'buildDefinition': {'buildType': REPOSITORY + '/blob/' + source + '/docs/development/ci.md',
                          'externalParameters': {'repository': REPOSITORY, 'ref': 'refs/tags/' + version,
                                                 'source_sha': source, 'version': version},
                          'resolvedDependencies': [
                              {'uri': 'git+' + REPOSITORY, 'digest': {'gitCommit': source}},
                              {'name': 'build-inputs.json', 'digest': {'sha256': digest(regular(directory / 'build-inputs.json'))['sha256']}}]},
                      'runDetails': {'builder': {'id': BUILDER}, 'metadata': {'invocationId': builder},
                                     'byproducts': [{'name': 'gates.json', 'digest': {'sha256': digest(regular(directory / 'gates.json'))['sha256']}}]}}}
    return sbom, provenance


def generate(directory, version, source, builder, inputs_path):
    directory = Path(directory)
    input_bytes = regular(Path(inputs_path))
    inputs = decode(input_bytes)
    target = directory / 'build-inputs.json'
    if target.exists():
        require(regular(target) == input_bytes, 'existing build inputs differ')
    else:
        target.write_bytes(input_bytes)
    for name in ('LICENSE', 'NOTICE'):
        data = inputs['notices'][name].encode()
        material = next(m for m in inputs['materials'] if m['name'] == name)
        require(digest(data) == {k: material[k] for k in ('sha256', 'bytes')}, 'inherited notice digest differs')
        if (directory / name).exists():
            require(regular(directory / name) == data, 'existing inherited notice differs')
        else:
            (directory / name).write_bytes(data)
    sbom, provenance = documents(directory, version, source, builder, inputs)
    (directory / 'sbom.cdx.json').write_bytes(encoded(sbom))
    (directory / 'provenance.json').write_bytes(encoded(provenance))


def verify(directory, version, source, builder):
    """Check content bindings; the caller must authenticate release subjects first."""
    directory = Path(directory)
    inputs = read_json(directory / 'build-inputs.json')
    for name in ('LICENSE', 'NOTICE'):
        require(regular(directory / name) == inputs['notices'][name].encode(), 'inherited notice differs')
    sbom, provenance = documents(directory, version, source, builder, inputs)
    require(read_json(directory / 'sbom.cdx.json') == sbom, 'SBOM missing, incomplete or mismatched')
    require(read_json(directory / 'provenance.json') == provenance, 'provenance source, builder, subjects or gates differ')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    collect_args = commands.add_parser('collect')
    collect_args.add_argument('--source-directory', default='.')
    collect_args.add_argument('--dist', required=True)
    collect_args.add_argument('--image-evidence', required=True)
    collect_args.add_argument('--out', required=True)
    collect_args.add_argument('--go', default=os.environ.get('GO', 'go'))
    for name in ('generate', 'verify'):
        command_parser = commands.add_parser(name)
        for option in ('directory', 'version', 'source', 'builder'):
            command_parser.add_argument('--' + option, required=True)
        if name == 'generate':
            command_parser.add_argument('--inputs', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'collect':
            collect(args.source_directory, args.dist, args.image_evidence, args.out, args.go)
        elif args.command == 'generate':
            generate(args.directory, args.version, args.source, args.builder, args.inputs)
        else:
            verify(args.directory, args.version, args.source, args.builder)
            print('Inventory and provenance bindings match; authentication requires signed release subjects.')
    except (OSError, ValueError, KeyError, TypeError, StopIteration, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, 'release inventory: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
