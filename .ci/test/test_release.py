#!/usr/bin/env python3
"""Adversarial release inventory and installer tests; signatures use real Cosign."""
import hashlib
import itertools
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent/'fixtures'
SPEC = importlib.util.spec_from_file_location('release_assets', ROOT/'.ci/release_assets.py')
assets = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assets)
PUBSPEC = importlib.util.spec_from_file_location('release_publish', ROOT/'scripts/release_publish.py')
publisher = importlib.util.module_from_spec(PUBSPEC)
PUBSPEC.loader.exec_module(publisher)


def real_cosign(test):
    binary = os.environ.get('COSIGN_TEST_BIN') or shutil.which('cosign')
    if not binary or not Path(binary).is_file() or not os.access(binary, os.X_OK):
        message = 'real Cosign unavailable: set COSIGN_TEST_BIN to the checksum-pinned binary'
        if 'CI' in os.environ:
            test.fail(message+' (required in CI)')
        test.skipTest(message)
    return Path(binary).resolve()


class PublisherTests(unittest.TestCase):
    def test_key_symlink_rejected_before_resolving(self):
        with tempfile.TemporaryDirectory() as scratch:
            parent = Path(scratch)
            parent.chmod(0o700)
            key = parent/'key'
            key.write_text('throwaway non-key data')
            key.chmod(0o600)
            self.assertEqual(publisher.private_key_path(key), key)
            link = parent/'link'
            link.symlink_to(key)
            with self.assertRaisesRegex(ValueError, 'owned regular 0600 file'):
                publisher.private_key_path(link)
            with patch.object(publisher, 'human_gate'), patch.object(publisher, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'owned regular 0600 file'):
                    publisher.sign(parent, link)
                run.assert_not_called()
            # Exercise argument handling too: main must preserve the supplied
            # path so sign can reject it before any resolution follows links.
            argv = ['release_publish.py', 'v0.5.0', '--baseline', str(parent/'baseline'),
                    '--notes', str(key), '--ci-output', str(parent), '--key', str(link)]
            with patch.object(publisher, 'human_gate'), patch.object(sys, 'argv', argv), \
                 patch.object(publisher, 'publish', side_effect=lambda args: publisher.private_key_path(args.key)):
                with self.assertRaisesRegex(ValueError, 'owned regular 0600 file'):
                    publisher.main()

    def test_ancestor_exit_codes(self):
        for code in (0, 1, 128):
            with self.subTest(code=code), patch.object(publisher.subprocess, 'run', return_value=subprocess.CompletedProcess(['git'], code)):
                if code == 0:
                    publisher.check_ancestor('commit')
                else:
                    with self.assertRaises(ValueError if code == 1 else subprocess.CalledProcessError):
                        publisher.check_ancestor('commit')

    def test_github_copy_retains_original_failure_and_checks_mirror_once(self):
        args = SimpleNamespace(tag='v0.5.0', github_repo='example/repo', forgejo_repo='example/repo', notes=Path('/notes'))
        for cleanup_fails, mirror_fails in itertools.product((False, True), repeat=2):
            original = RuntimeError('original create failure')
            with self.subTest(cleanup=cleanup_fails, mirror=mirror_fails), \
                 patch.object(publisher, 'run', side_effect=[original, RuntimeError('cleanup failure') if cleanup_fails else None]), \
                 patch.object(publisher.subprocess, 'run', return_value=subprocess.CompletedProcess(['gh'], 0, '{"isDraft":true}')), \
                 patch.object(publisher, 'mirror_check', side_effect=RuntimeError('mirror failure') if mirror_fails else None) as mirror, \
                 patch('sys.stderr', new_callable=io.StringIO) as stderr:
                with self.assertRaises(RuntimeError) as raised:
                    publisher.github_copy(args, Path('/payload'), {})
                self.assertIs(raised.exception, original)
                mirror.assert_called_once()
                if cleanup_fails: self.assertIn('cleanup failure', stderr.getvalue())
                if mirror_fails: self.assertIn('mirror failure', stderr.getvalue())
        with patch.object(publisher, 'run'), patch.object(publisher, 'mirror_check') as mirror:
            publisher.github_copy(args, Path('/payload'), {})
            mirror.assert_called_once()

    def test_missing_cosign_is_a_ci_failure(self):
        with patch.dict(os.environ, {'CI': 'false', 'COSIGN_TEST_BIN': '/missing/cosign'}):
            with self.assertRaisesRegex(AssertionError, 'required in CI'):
                real_cosign(self)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'payload'
        shutil.copytree(FIXTURES/'installer', self.path)
        (self.path/'checksums.txt.sigstore.json').unlink()
        (self.path/'no-rekor.sigstore.json').unlink()

    def test_exact_inventory(self):
        self.assertEqual(len(assets.validate(self.path, 'v0.5.0')), 10)
        assets.rebuild_manifest(self.path, 'v0.5.0')
        self.assertEqual((self.path/'checksums.txt').read_bytes(), (FIXTURES/'installer/checksums.txt').read_bytes())

    def reject(self):
        with patch.object(publisher, 'sign') as sign:
            with self.assertRaises((ValueError, OSError)):
                assets.validate(self.path, 'v0.5.0')
            sign.assert_not_called()

    def test_extra_future_archive(self):
        (self.path/'devsecops-attestation_0.6.0_linux_amd64.tar.gz').write_bytes(b'future')
        self.reject()

    def test_renamed_old_version(self):
        name = assets.names('v0.5.0')[0]
        (self.path/name).rename(self.path/name.replace('_0.5.0_', '_0.4.2_'))
        self.reject()

    def test_missing_archive_and_sbom(self):
        for name in assets.names('v0.5.0')[:2]:
            content = (self.path/name).read_bytes()
            (self.path/name).unlink()
            self.reject()
            (self.path/name).write_bytes(content)

    def test_duplicate_and_unsafe_manifest_names(self):
        original = (self.path/'checksums.txt').read_bytes()
        for bad in [original+original.splitlines(keepends=True)[0], original.replace(b'devsecops-', b'../devsecops-', 1), original.replace(b'  devsecops-', b'  /devsecops-', 1), original[:-1], original.replace(b'  ', b' *', 1), original.replace(b'devsecops-', b'dev\x00secops-', 1)]:
            (self.path/'checksums.txt').write_bytes(bad)
            self.reject()
        (self.path/'checksums.txt').write_bytes(original)

    def test_digest_mismatch_and_symlink(self):
        name = assets.names('v0.5.0')[0]
        (self.path/name).write_bytes(b'changed')
        self.reject()
        (self.path/name).unlink()
        (self.path/name).symlink_to(FIXTURES/'installer'/name)
        self.reject()

    def test_current_and_future_manifest_inventory(self):
        path = self.path/'checksums.txt'
        with path.open('ab') as f:
            f.write(b'0'*64+b'  devsecops-attestation_0.6.0_linux_amd64.tar.gz\n')
        self.reject()

    def test_archive_member_types_and_inventory(self):
        for target in assets.TARGETS:
            name = next(n for n in assets.names('v0.5.0') if f'_{target}.' in n and n.endswith(('.tar.gz', '.zip')))
            self.assertEqual(len(assets.archive_contents(self.path/name, target)), 7)
        import io, tarfile
        name = 'devsecops-attestation_0.5.0_linux_amd64.tar.gz'
        for entry in ['../gate', '/gate', 'gate']:
            with tarfile.open(self.path/name, 'w:gz') as tar:
                info = tarfile.TarInfo(entry)
                info.type = tarfile.SYMTYPE
                info.linkname = '/etc/passwd'
                tar.addfile(info)
            with self.assertRaises(ValueError):
                assets.archive_contents(self.path/name, 'linux_amd64')

    def test_baseline_includes_bundle_bytes(self):
        shutil.copyfile(FIXTURES/'installer/checksums.txt.sigstore.json', self.path/'checksums.txt.sigstore.json')
        expected = assets.baseline(self.path, 'v0.5.0')
        self.assertEqual(len(expected), 12)
        bundle = self.path/'checksums.txt.sigstore.json'
        bundle.write_text(json.dumps(json.loads(bundle.read_text()), indent=4))
        with self.assertRaisesRegex(ValueError, 'baseline'):
            assets.check_baseline(self.path, expected, 'v0.5.0')

    def test_complete_remote_inventory(self):
        baseline = {n: {'size': 1} for n in assets.names('v0.5.0')+['checksums.txt', 'checksums.txt.sigstore.json']}
        records = [{'id': i, 'name': n, 'size': 1} for i, n in enumerate(baseline, start=1)]
        api = publisher.API('https://example.invalid')
        for bad in [records[:-1], records+[{'id': 90, 'name': 'extra', 'size': 1}], records+[records[0]], [dict(records[0], size=2)]+records[1:]]:
            with patch.object(api, 'pages', return_value=bad):
                with self.assertRaises(ValueError):
                    publisher.inventories(api, 1, baseline)
        with patch.object(api, 'pages', return_value=records):
            self.assertEqual(len(publisher.inventories(api, 1, baseline)), 12)

    def test_pagination_follows_until_empty_and_rejects_duplicate_pages(self):
        api = publisher.API('https://example.invalid')
        with patch.object(api, 'request', side_effect=[[{'id': 1}], [{'id': 2}], []]) as request:
            self.assertEqual(len(api.pages('/releases/1/assets')), 2)
            self.assertEqual(request.call_count, 3)
        with patch.object(api, 'request', side_effect=[[{'id': 1}], [{'id': 1}]]):
            with self.assertRaises(ValueError):
                api.pages('/releases/1/assets')

    def test_publisher_cannot_run_in_ci_or_without_terminal(self):
        for script in ['scripts/release-publish.sh', 'scripts/release_publish.py']:
            command = ['bash' if script.endswith('.sh') else sys.executable, str(ROOT/script), 'v0.5.0']
            result = subprocess.run(command, env=dict(os.environ, CI='false'), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('forbidden in CI', result.stderr)
            env = {k: v for k, v in os.environ.items() if k not in publisher.CI_NAMES}
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('interactive terminal', result.stderr)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.action = self.path/'action'
        shutil.copytree(ROOT/'actions/setup', self.action)
        shutil.copyfile(FIXTURES/'cosign/test.pub', self.action/'release-keys/release-v1.pub')
        self.fixture = self.path/'fixture'
        shutil.copytree(FIXTURES/'installer', self.fixture)
        self.bin = self.path/'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'], INPUT_VERSION='0.5.0', INPUT_REPOSITORY='ignored/caller',
                        INPUT_DOWNLOAD_BASE_URL='https://fixture.invalid/releases/download', INPUT_INSTALL_DIR=str(self.path/'install'),
                        INPUT_VERIFY_SIGNATURE='false', GITHUB_ACTION_PATH=str(self.action), RUNNER_OS='Linux', RUNNER_ARCH='X64',
                        RUNNER_TEMP=str(self.path), GITHUB_OUTPUT=str(self.path/'outputs'), GITHUB_PATH=str(self.path/'path'),
                        TEST_FIXTURE=str(self.fixture), TEST_URLS=str(self.path/'urls'), TEST_GO=str(self.path/'go-called'))
        (self.bin/'curl').write_text('''#!/usr/bin/env python3
import os,sys,shutil
from pathlib import Path
args=sys.argv[1:]; url=args[-1]
with open(os.environ['TEST_URLS'],'a') as f: f.write(url+'\\n')
source=Path(os.environ['TEST_FIXTURE'])/url.rsplit('/',1)[-1]
if not source.is_file(): sys.exit(22)
shutil.copyfile(source,args[args.index('-o')+1])
''')
        (self.bin/'go').write_text('#!/bin/sh\ntouch "$TEST_GO"\nexit 90\n')
        for path in self.bin.iterdir(): path.chmod(0o755)

    def execute(self):
        return subprocess.run(['bash', str(self.action/'setup.sh')], env=self.env, capture_output=True, text=True)

    def assert_failed_cleanly(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        for name in ['outputs', 'path', 'go-called']:
            self.assertFalse((self.path/name).exists(), name)
        self.assertEqual(list((self.path/'install').iterdir()), [])

    def real_cosign(self):
        (self.bin/'cosign').symlink_to(real_cosign(self))
        self.env['INPUT_VERIFY_SIGNATURE'] = 'true'

    def test_download_and_inventory_without_signature_opt_out_weakening(self):
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(list((self.path/'install').iterdir())), 5)
        self.assertFalse((self.path/'go-called').exists())

    def test_default_url_resolution(self):
        for version, server, base in [
            ('0.4.0', '', 'https://github.com/MemerGamer/devsecops-attestation'),
            ('0.4.1', 'https://other.invalid', 'https://github.com/MemerGamer/devsecops-attestation'),
            ('0.4.2', 'https://github.com', 'https://github.com/MemerGamer/devsecops-attestation'),
            ('0.5.0', 'https://github.com', 'https://github.com/MemerGamer/devsecops-attestation'),
            ('0.5.0', 'https://forgejo.example', 'https://forgejo.remote.kovacsbalinthunor.com/kbalinthunor/devsecops-attestation')]:
            with self.subTest(version=version, server=server):
                self.env.update(INPUT_VERSION=version, INPUT_DOWNLOAD_BASE_URL='', GITHUB_SERVER_URL=server)
                (self.path/'urls').unlink(missing_ok=True)
                self.execute()
                selected = (self.path/'urls').read_text().splitlines()[0]
                self.assertEqual(selected, f'{base}/releases/download/v{version}/devsecops-attestation_{version}_linux_amd64.tar.gz')

    def test_unset_server_and_unsupported_version_fail_closed(self):
        self.env.update(INPUT_DOWNLOAD_BASE_URL='')
        self.env.pop('GITHUB_SERVER_URL', None)
        self.assert_failed_cleanly(self.execute())
        self.env.update(INPUT_VERSION='0.3.2', INPUT_DOWNLOAD_BASE_URL='https://fixture.invalid')
        result = self.execute()
        self.assertIn('unsupported', result.stderr)
        self.assert_failed_cleanly(result)

    def test_legacy_digest_mismatch(self):
        self.env.update(INPUT_VERSION='0.4.2')
        # Supply a selected-archive fixture so this reaches the legacy pin.
        source = next(self.fixture.glob('*linux_amd64.tar.gz'))
        shutil.copyfile(source, self.fixture/source.name.replace('0.5.0', '0.4.2'))
        result = self.execute()
        self.assertIn('legacy checksums.txt digest mismatch', result.stderr)
        self.assert_failed_cleanly(result)

    def test_altered_archive_rejected(self):
        next(self.fixture.glob('*linux_amd64.tar.gz')).write_bytes(b'altered')
        self.assert_failed_cleanly(self.execute())

    def test_extra_future_manifest_rejected(self):
        with (self.fixture/'checksums.txt').open('ab') as output:
            output.write(b'0'*64+b'  devsecops-attestation_0.6.0_linux_amd64.tar.gz\n')
        result = self.execute()
        self.assertIn('manifest', result.stderr)
        self.assert_failed_cleanly(result)

    def test_minimum_cosign_version(self):
        self.env['INPUT_VERIFY_SIGNATURE'] = 'true'
        for version in ['v2.6.1', 'v3.0.1', 'v3.1.0-rc.1', 'v4.0.0', 'garbage']:
            with self.subTest(version=version):
                binary = self.bin/'cosign'
                binary.write_text(f'#!/bin/sh\nif [ "$1" = version ]; then echo "GitVersion: {version}"; else touch "$TEST_GO"; fi\n')
                binary.chmod(0o755)
                result = self.execute()
                self.assertIn('cosign must be', result.stderr)
                self.assert_failed_cleanly(result)

    def test_real_cosign_success_all_targets(self):
        self.real_cosign()
        for target in assets.TARGETS:
            os_name, arch = target.split('_')
            self.env.update(RUNNER_OS={'darwin': 'macOS', 'linux': 'Linux', 'windows': 'Windows'}[os_name], RUNNER_ARCH={'amd64': 'X64', 'arm64': 'ARM64'}[arch])
            result = self.execute()
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_cosign_no_rekor_ambient_bypass_and_root_overrides(self):
        self.real_cosign()
        shutil.copyfile(self.fixture/'no-rekor.sigstore.json', self.fixture/'checksums.txt.sigstore.json')
        poison = str(FIXTURES/'cosign/private-trusted-root.json')
        cases = [{}, {'COSIGN_INSECURE_IGNORE_TLOG': 'true'}, {'COSIGN_PRIVATE_INFRASTRUCTURE': 'true'},
                 {'COSIGN_INSECURE_IGNORE_TLOG': 'true', 'COSIGN_PRIVATE_INFRASTRUCTURE': 'true'},
                 {'COSIGN_TRUSTED_ROOT': poison}, {'SIGSTORE_ROOT_FILE': poison}, {'SIGSTORE_REKOR_PUBLIC_KEY': poison},
                 {'SIGSTORE_CT_LOG_PUBLIC_KEY_FILE': poison}, {'HOME': str(FIXTURES/'cosign'), 'XDG_CACHE_HOME': str(FIXTURES/'cosign'), 'TUF_ROOT': poison}]
        for case in cases:
            with self.subTest(overrides=case):
                base = self.env.copy()
                self.env.update(case)
                result = self.execute()
                self.assertIn('not enough verified log entries', result.stderr)
                self.assert_failed_cleanly(result)
                self.env = base

    def test_unmodified_action_placeholder_fails_closed(self):
        self.real_cosign()
        shutil.copyfile(ROOT/'actions/setup/release-keys/release-v1.pub', self.action/'release-keys/release-v1.pub')
        result = self.execute()
        self.assertIn('release public key contains PLACEHOLDER', result.stderr)
        self.assert_failed_cleanly(result)


class CosignPolicyTests(unittest.TestCase):
    def setUp(self):
        self.binary = real_cosign(self)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.action = self.path/'action'
        shutil.copytree(ROOT/'actions/setup', self.action)
        shutil.copyfile(FIXTURES/'cosign/test.pub', self.action/'release-keys/release-v1.pub')
        (self.path/'cosign').symlink_to(self.binary)
        self.env = dict(os.environ, PATH=str(self.path)+':'+os.environ['PATH'])

    def verify(self, version, manifest, bundle, overrides=None):
        return subprocess.run(['bash', '-euo', 'pipefail', '-c',
                               'source "$1/release-policy.sh"; release_verify "$1" "$2" "$3" "$4"',
                               'policy-test', str(self.action), version, str(manifest), str(bundle)],
                              env=dict(self.env, **(overrides or {})), capture_output=True, text=True, timeout=120)

    def test_private_log_control_and_all_root_bypass_combinations(self):
        fixture = FIXTURES/'cosign'
        # The same accepted key signs this valid private-log fixture. Explicit
        # private trust succeeds, so public-policy rejection tests log trust.
        control = subprocess.run(['bash', '-euo', 'pipefail', '-c',
                                  'source "$1/release-policy.sh"; shift; release_cosign "$@"',
                                  'private-control', str(self.action), 'verify-blob',
                                  '--key', str(self.action/'release-keys/release-v1.pub'),
                                  '--bundle', str(fixture/'private-log.sigstore.json'),
                                  '--new-bundle-format=true', '--insecure-ignore-tlog=false',
                                  '--private-infrastructure=false', '--use-signed-timestamps=false',
                                  '--trusted-root='+str(fixture/'private-trusted-root.json'), str(fixture/'blob.txt')],
                                 env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(control.returncode, 0, control.stderr)
        overrides = {'COSIGN_TRUSTED_ROOT': str(fixture/'private-trusted-root.json'),
                     'SIGSTORE_ROOT_FILE': str(fixture/'private-trusted-root.json'),
                     'COSIGN_INSECURE_IGNORE_TLOG': 'true', 'COSIGN_PRIVATE_INFRASTRUCTURE': 'true'}
        for size in range(len(overrides)+1):
            for names in itertools.combinations(overrides, size):
                case = {name: overrides[name] for name in names}
                with self.subTest(overrides=case):
                    result = self.verify('0.5.0', fixture/'blob.txt', fixture/'private-log.sigstore.json', case)
                    self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
                    self.assertIn('failed to verify log inclusion: not enough verified log entries', result.stderr)
        poisoned = dict(overrides, SIGSTORE_REKOR_PUBLIC_KEY=str(fixture/'private-trusted-root.json'),
                        SIGSTORE_CT_LOG_PUBLIC_KEY_FILE=str(fixture/'private-trusted-root.json'),
                        HOME=str(fixture), USERPROFILE=str(fixture), XDG_CACHE_HOME=str(fixture),
                        TUF_ROOT=str(fixture/'private-trusted-root.json'),
                        HTTPS_PROXY='http://127.0.0.1:1', SSL_CERT_FILE='/missing/roots')
        for case in [{'SIGSTORE_REKOR_PUBLIC_KEY': poisoned['SIGSTORE_REKOR_PUBLIC_KEY']},
                     {'SIGSTORE_CT_LOG_PUBLIC_KEY_FILE': poisoned['SIGSTORE_CT_LOG_PUBLIC_KEY_FILE']}, poisoned]:
            with self.subTest(overrides=case):
                result = self.verify('0.5.0', fixture/'blob.txt', fixture/'private-log.sigstore.json', case)
                self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertIn('failed to verify log inclusion: not enough verified log entries', result.stderr)
        # A legitimate public bundle must still verify in that same environment.
        result = self.verify('0.5.0', fixture/'blob.txt', fixture/'public.sigstore.json', poisoned)
        self.assertEqual(result.returncode, 0, result.stderr)

    def legacy(self, version):
        manifest = FIXTURES/'legacy'/f'{version}-checksums.txt'
        digest = subprocess.check_output(['bash', '-c', 'source "$1/release-policy.sh"; release_legacy_digest "$2"',
                                          'legacy-pin', str(self.action), version], text=True).strip()
        self.assertEqual(hashlib.sha256(manifest.read_bytes()).hexdigest(), digest)
        result = self.verify(version, manifest, manifest.with_suffix('.txt.sigstore.json'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Verified OK', result.stderr)

    def test_legacy_v0_4_0(self):
        self.legacy('0.4.0')

    def test_legacy_v0_4_1(self):
        self.legacy('0.4.1')

    def test_legacy_v0_4_2(self):
        self.legacy('0.4.2')


class ReleaseWorkflowInvariantTests(unittest.TestCase):
    def test_release_workflow_and_config(self):
        workflow = yaml.safe_load((ROOT/'.forgejo/workflows/release.yml').read_text())
        text = (ROOT/'.forgejo/workflows/release.yml').read_text()
        self.assertNotIn('secrets.', text)
        self.assertNotIn('release-publish', text)
        self.assertNotIn('docker-trusted', text)
        self.assertNotIn('environment:', text)
        self.assertNotIn('download-artifact', text)
        self.assertEqual(workflow['permissions'], {})
        self.assertEqual(workflow['jobs']['build']['permissions'], {'contents': 'read'})
        uses = [step['uses'] for job in workflow['jobs'].values() for step in job.get('steps', []) if 'uses' in step]
        self.assertEqual(uses, [
            'https://data.forgejo.org/actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
            'https://data.forgejo.org/forgejo/upload-artifact@cb8afe72b42edc798abfb8fcb556cf660d894245'])
        for job in workflow['jobs'].values():
            self.assertNotIn('environment', job)
        self.assertFalse(workflow['concurrency']['cancel-in-progress'])
        self.assertEqual(workflow['jobs']['build']['runs-on'], 'ubuntu-latest')
        self.assertFalse(workflow['jobs']['build']['steps'][0]['with']['persist-credentials'])
        pins = json.loads((ROOT/'.ci/release-tools.json').read_text())
        for name, pin in pins.items():
            self.assertTrue(pin['url'].startswith('https://github.com/'), name)
            self.assertRegex(pin['sha256'], '^[0-9a-f]{64}$')
        for script in ['.ci/install-release-tools.sh', '.ci/install-go.sh']:
            self.assertIn('=https', (ROOT/script).read_text())
        config = yaml.safe_load((ROOT/'.goreleaser.yaml').read_text())
        for key in ['signs', 'docker_signs', 'dockers_v2']:
            self.assertNotIn(key, config)
        self.assertTrue(config['release']['disable'])
        self.assertEqual(config['sboms'][0]['documents'], ['{{ .ArtifactName }}.sbom.json'])
        for name in ['.github/workflows/release-please.yml', 'release-please-config.json', '.release-please-manifest.json']:
            self.assertFalse((ROOT/name).exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
