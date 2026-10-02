"""Release identity, inventory completeness and promotion byte preservation."""
import importlib.util
import gzip
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('inventory', Path(__file__).with_name('release_inventory.py'))
inv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inv)
SOURCE = 'a' * 40
VERSION = 'v1.2.3'
BUILDER = inv.REPOSITORY + '/actions/runs/123'


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.compiled = {name: ('compiled:' + name).encode() for name in inv.COMPONENTS}
        self.meta = {'version': VERSION, 'source_sha': SOURCE, 'dirty': False,
                     'build_pipeline_url': BUILDER, 'go_version': 'go1.25.11'}
        self.inputs = {
            'schema_version': 1,
            'build_record': {'metadata': self.meta,
                             'compiled_files': {n: inv.digest(v) for n, v in self.compiled.items()}},
            'build_image': {'failures': [], 'go_version': 'go1.25.11', 'image_id': 'sha256:' + 'b' * 64,
                            'expected_image': 'golang:1.25.11@sha256:' + 'b' * 64,
                            'job_image': 'golang:1.25.11@sha256:' + 'b' * 64,
                            'pipeline': {'github_job': 'build', 'github_sha': SOURCE, 'github_run_id': '123',
                                                       'github_run_attempt': '1'}},
            'components': [{'name': n, **inv.digest(data), 'go_version': 'go1.25.11',
                            'settings': {'CGO_ENABLED': '0', 'vcs.revision': SOURCE, 'vcs.modified': 'false'},
                            'evidence': 'source-dependency-graph' if n in inv.GUESTS else 'embedded-build-info',
                            'modules': [{'path': 'example.org/dependency', 'version': 'v1.0.0',
                                         'sum': 'h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='}]}
                           for n, data in self.compiled.items()],
            'tools': [{'name': n, 'version': 'go1.25.11' if n == 'Go' else '14.0',
                       'purpose': 'compilation' if n == 'Go' else 'declared-validation-tool'}
                      for n in ('Go', 'clang', 'llvm', 'libbpf-dev', 'linux-libc-dev', 'github.com/cilium/ebpf/cmd/bpf2go')],
            'images': [{'name': 'build image', 'reference': 'golang:1.25.11@sha256:' + 'b' * 64,
                        'purpose': 'compilation'},
                       {'name': 'runtime base', 'reference': 'debian:bookworm@sha256:' + 'c' * 64,
                        'purpose': 'supported-runtime-base'}],
            'notices': {'LICENSE': 'inherited license\n', 'NOTICE': 'inherited notice\n'},
            'materials': [{'name': n, **inv.digest(t.encode())}
                          for n, t in {'LICENSE': 'inherited license\n', 'NOTICE': 'inherited notice\n'}.items()]}
        self.inputs['materials'] += [{'name': n, **inv.digest(b'input bytes')}
                                    for n in (*inv.SOURCE_INPUTS, 'bpf/filter.o')
                                    if n not in ('LICENSE', 'NOTICE')]
        compatibility = {'schema_version': 1, 'core_version': VERSION, 'core_source_sha': SOURCE,
                         'core_api_version': '1.12', 'core_openapi_sha256': inv.digest(b'input bytes')['sha256'],
                         'console_repository': 'https://gitlab.inf.ethz.ch/OU-PERRIG/yimin/debuglet/debuglet-dashboard',
                         'console_revision': 'd' * 40}
        compatibility_bytes = inv.encoded(compatibility)
        (self.root / 'compatibility.json').write_bytes(compatibility_bytes)
        (self.root / 'SHA256SUMS-compatibility').write_text(
            inv.digest(compatibility_bytes)['sha256'] + '  compatibility.json\n')
        self.gates = {'source_sha': SOURCE, 'version': VERSION, 'builder': BUILDER,
                      'run_id': 123, 'run_attempt': 1}
        (self.root / 'gates.json').write_bytes(inv.encoded(self.gates))
        self.input_path = self.root / 'build-inputs.json'
        self.input_path.write_bytes(inv.encoded(self.inputs))
        for role, binaries in [('', ['dbl', 'debuglet-dispatcher', 'debuglet-executor', 'hello.wasm', 'demo.wasm']),
                               ('cli', ['dbl']), ('dispatcher', ['debuglet-dispatcher']),
                               ('executor', ['debuglet-executor'])]:
            files = {'LICENSE': self.inputs['notices']['LICENSE'].encode(), 'README-install.md': b'Install\n'}
            for name in binaries:
                files[('share/debuglet/' if name.endswith('.wasm') else 'bin/') + name] = self.compiled[name]
            manifest = dict(self.meta, component=role, files={n: inv.digest(d) for n, d in files.items()})
            files[inv.MANIFEST] = inv.encoded(manifest)
            archive_name = 'debuglet-' + (role + '-' if role else '') + VERSION + '-linux-amd64.tar.gz'
            with tarfile.open(self.root / archive_name, 'w:gz') as archive:
                for name, data in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            installer = 'install-' + role + '.sh' if role else 'install.sh'
            (self.root / installer).write_bytes(b'#!/bin/sh\n')
            checksums = ''.join(inv.digest((self.root / name).read_bytes())['sha256'] + '  ' + name + '\n'
                                for name in (archive_name, installer))
            (self.root / ('SHA256SUMS-' + role if role else 'SHA256SUMS')).write_text(checksums)

    def generate(self):
        inv.generate(self.root, VERSION, SOURCE, BUILDER, self.input_path)

    def verify(self):
        inv.verify(self.root, VERSION, SOURCE, BUILDER)

    def test_complete_inventory_binds_exact_bytes_without_rebuilding(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        self.generate()
        self.verify()
        for name, data in before.items():
            self.assertEqual((self.root / name).read_bytes(), data)
        sbom = inv.read_json(self.root / 'sbom.cdx.json')
        self.assertEqual(sbom['specVersion'], '1.6')
        runtime = [c for c in sbom['components'] if c['type'] == 'library']
        self.assertEqual(len(runtime), 1)
        self.assertEqual(runtime[0]['version'], 'v1.0.0')
        self.assertNotIn('licenses', runtime[0])  # Unknown module licences are not invented.
        self.assertEqual((self.root / 'NOTICE').read_text(), self.inputs['notices']['NOTICE'])
        provenance = inv.read_json(self.root / 'provenance.json')
        self.assertEqual(provenance['predicateType'], 'https://slsa.dev/provenance/v1')
        self.assertEqual(len(provenance['subject']), 15)
        self.assertEqual(provenance['predicate']['runDetails']['builder']['id'], inv.BUILDER)

    def test_compatibility_is_signed_and_must_match_source_and_api(self):
        self.generate()
        provenance = inv.read_json(self.root / 'provenance.json')
        self.assertIn('compatibility.json', {s['name'] for s in provenance['subject']})
        original = (self.root / 'compatibility.json').read_bytes()
        for field, value in [('core_source_sha', 'b' * 40), ('core_version', 'v9.0.0'),
                             ('core_openapi_sha256', 'c' * 64)]:
            with self.subTest(field=field):
                changed = inv.decode(original)
                changed[field] = value
                (self.root / 'compatibility.json').write_bytes(inv.encoded(changed))
                with self.assertRaisesRegex(ValueError, 'compatibility'):
                    self.verify()
        (self.root / 'compatibility.json').write_bytes(original)
        (self.root / 'SHA256SUMS-compatibility').write_text('not the sidecar checksum')
        with self.assertRaisesRegex(ValueError, 'compatibility checksum'):
            self.verify()

    def test_verifier_rejects_changed_identity_inventory_and_evidence(self):
        self.generate()
        mutations = [
            ('sbom.cdx.json', lambda value: value['components'].pop()),
            ('provenance.json', lambda value: value['predicate']['runDetails']['builder'].update(id='https://other.example')),
            ('provenance.json', lambda value: value['subject'][0]['digest'].update(sha256='b' * 64)),
            ('gates.json', lambda value: value.update(run_attempt=2)),
            ('build-inputs.json', lambda value: value['build_record']['metadata'].update(source_sha='b' * 40)),
            ('build-inputs.json', lambda value: value['components'].pop()),
            ('build-inputs.json', lambda value: value['tools'].clear()),
            ('build-inputs.json', lambda value: value['images'].clear()),
            ('build-inputs.json', lambda value: value['materials'].clear()),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                value = inv.decode(original)
                mutate(value)
                path.write_bytes(inv.encoded(value))
                with self.assertRaises(ValueError):
                    self.verify()
                path.write_bytes(original)
        for name in ('sbom.cdx.json', 'provenance.json'):
            path = self.root / name
            original = path.read_bytes()
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                self.verify()
            path.write_bytes(original)

    def test_rejects_other_source_or_pipeline_even_with_intact_documents(self):
        self.generate()
        for source, builder in [('b' * 40, BUILDER), (SOURCE, BUILDER + '4')]:
            with self.subTest(source=source, builder=builder), self.assertRaises(ValueError):
                inv.verify(self.root, VERSION, source, builder)

    def test_rejects_rebuilt_archive_and_modified_notices(self):
        self.generate()
        installer = self.root / 'install.sh'
        installer.write_text('#!/bin/sh\necho changed\n')
        with self.assertRaisesRegex(ValueError, 'checksum pair'):
            self.verify()
        installer.write_bytes(b'#!/bin/sh\n')
        (self.root / 'NOTICE').write_text('new notice')
        with self.assertRaisesRegex(ValueError, 'notice'):
            self.verify()
        (self.root / 'NOTICE').write_text(self.inputs['notices']['NOTICE'])
        value = inv.read_json(self.input_path)
        value['build_record']['compiled_files']['dbl']['sha256'] = 'b' * 64
        value['components'] = [dict(c, sha256='b' * 64) if c['name'] == 'dbl' else c for c in value['components']]
        self.input_path.write_bytes(inv.encoded(value))
        with self.assertRaisesRegex(ValueError, 'rebuilt or substituted'):
            self.verify()

    def test_rejects_missing_stale_wrong_role_and_malformed_checksum_pairs(self):
        sums = self.root / 'SHA256SUMS-cli'
        original = sums.read_bytes()
        alternatives = (original.replace(original[:64], b'0' * 64),
                        (self.root / 'SHA256SUMS-executor').read_bytes(),
                        b'malformed checksums\n', original.splitlines(keepends=True)[0],
                        original + original.splitlines(keepends=True)[0])
        for data in alternatives:
            with self.subTest(data=data):
                sums.write_bytes(data)
                with self.assertRaisesRegex(ValueError, 'checksum pair'):
                    self.generate()
        sums.unlink()
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.generate()

    def test_bounds_compressed_input_and_extension_reads_before_allocation(self):
        with mock.patch.object(inv, 'MAX_ARCHIVE_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'compressed archive exceeds'):
                self.generate()
        archive = sorted(self.root.glob('*.tar.gz'))[0]
        for kind in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
            with self.subTest(extension=kind):
                header = tarfile.TarInfo('extension')
                header.type = kind
                header.size = inv.MAX_ARCHIVE_BYTES + 512
                archive.write_bytes(gzip.compress(header.tobuf(format=tarfile.USTAR_FORMAT)))
                with self.assertRaisesRegex(ValueError, 'decompressed archive exceeds'):
                    self.generate()

    def test_go_metadata_requires_exact_modules_and_native_source(self):
        output = ('binary: go1.25.11\n\tpath\tgithub.com/netsec-ethz/debuglet/cmd/dbl\n'
                  '\tmod\tgithub.com/netsec-ethz/debuglet\t(devel)\t\n'
                  '\tdep\texample.org/dependency\tv1.0.0\th1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n'
                  '\tbuild\tCGO_ENABLED=0\n\tbuild\tvcs.revision=' + SOURCE + '\n\tbuild\tvcs.modified=false\n')
        info = inv.build_info(output.replace('(devel)', 'v0.0.0-20260928072918-aaaaaaaaaaaa'), 'go1.25.11', SOURCE, True)
        self.assertEqual(info['modules'][0]['version'], 'v1.0.0')
        for changed in (output.replace(SOURCE, 'b' * 40), output.replace('vcs.modified=false', 'vcs.modified=true'),
                        output.replace('v1.0.0', '(devel)'), output + '\t=>\t../other\t(devel)\n'):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                inv.build_info(changed, 'go1.25.11', SOURCE, True)

    def test_rejects_duplicate_or_nonfinite_json(self):
        for data in ('{"source_sha": "a", "source_sha": "b"}', '{"bytes": NaN}'):
            with self.assertRaises(ValueError):
                inv.decode(data)


if __name__ == '__main__':
    unittest.main()
