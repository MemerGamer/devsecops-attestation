#!/usr/bin/env python3
"""Exercise the human ceremony in a disposable checkout using only fake keys."""
import hashlib
import json
import os
from pathlib import Path
import pty
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PUBLIC = 'FAKE PUBLIC KEY FOR CEREMONY TESTS ONLY\n'
PRIVATE = 'FAKE PRIVATE KEY FOR CEREMONY TESTS ONLY\n'


class CeremonyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ceremony-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base/'repo'
        self.home = self.base/'home'
        self.bin = self.base/'bin'
        self.media = self.base/'media'
        self.log = self.base/'cosign-calls.jsonl'
        self.key_dir = self.home/'.local/share/devsecops-release'
        self.target = self.repo/'actions/setup/release-keys/release-v1.pub'
        for directory in (self.repo/'scripts', self.repo/'.ci', self.home,
                          self.bin, self.media, self.target.parent):
            directory.mkdir(parents=True, exist_ok=True)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        for name in ('scripts/release-key-ceremony.sh', '.ci/install-release-tools.sh',
                     '.ci/release-tools.json', 'actions/setup/release-keys/release-v1.pub'):
            shutil.copyfile(ROOT/name, self.repo/name)
        self.placeholder = self.target.read_bytes()
        self.script = self.repo/'scripts/release-key-ceremony.sh'
        # No production key path, passphrase or real Cosign is ever used.
        self.install_cosign()
        self.env = dict(os.environ, HOME=str(self.home), PATH=f'{self.bin}:/usr/bin:/bin')
        for name in ('COSIGN_PASSWORD', 'COSIGN_KEY', 'BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS'):
            self.env.pop(name, None)
        self.run_uid = 65534 if os.geteuid() == 0 else os.geteuid()

    def install_cosign(self, fail_stage=''):
        stub = self.bin/'cosign'
        stub.write_text(f'''#!/usr/bin/python3
import hashlib, json, os, pathlib, sys
args = sys.argv[1:]
assert not any(k.startswith(('COSIGN_', 'SIGSTORE_', 'TUF_')) for k in os.environ)
with open({str(self.log)!r}, 'a') as log:
    log.write(json.dumps(dict(args=args, cwd=os.getcwd(), home=os.environ['HOME']))+'\\n')
stage = args[0]
if stage == {fail_stage!r}:
    raise SystemExit('simulated cosign failure')
def value(flag):
    return args[args.index(flag)+1]
if stage == 'version':
    print('GitVersion: v3.1.4')
elif stage == 'generate-key-pair':
    assert os.isatty(0)
    assert pathlib.Path.cwd() == pathlib.Path({str(self.key_dir)!r})
    assert pathlib.Path.cwd().stat().st_mode & 0o777 == 0o700
    assert os.umask(0o077) == 0o077
    assert not pathlib.Path('cosign.key').exists()
    pathlib.Path('cosign.key').write_text({PRIVATE!r})
    pathlib.Path('cosign.pub').write_text({PUBLIC!r})
    # Exercise the ceremony's explicit chmod, independently of its umask.
    os.chmod('cosign.key', 0o644)
    os.chmod('cosign.pub', 0o644)
elif stage == 'sign-blob':
    assert os.isatty(0)
    assert '--tlog-upload=false' in args
    assert '--use-signing-config=false' in args
    assert '--timestamp-server-url=' in args
    key = pathlib.Path(value('--key'))
    assert key.read_text() == {PRIVATE!r}
    assert key.stat().st_mode & 0o777 == 0o600
    pathlib.Path(value('--bundle')).write_text(hashlib.sha256(pathlib.Path(args[-1]).read_bytes()).hexdigest())
elif stage == 'verify-blob':
    assert '--offline=true' in args
    assert '--insecure-ignore-tlog=true' in args
    assert '--use-signed-timestamps=false' in args
    assert pathlib.Path(value('--key')).read_text() == {PUBLIC!r}
    assert pathlib.Path(value('--bundle')).read_text() == hashlib.sha256(pathlib.Path(args[-1]).read_bytes()).hexdigest()
else:
    raise SystemExit('unexpected fake cosign command')
''')
        stub.chmod(0o755)
        pins_file = self.repo/'.ci/release-tools.json'
        pins = json.loads(pins_file.read_text())
        pins['cosign-v3.1.4']['sha256'] = hashlib.sha256(stub.read_bytes()).hexdigest()
        pins_file.write_text(json.dumps(pins))

    def invoke(self, *args, answer='SKIP', tty=True, root=False, pass_fds=()):
        command = ['/bin/bash', str(self.script), *args]
        drop_user = None
        if root and os.geteuid() != 0:
            if not shutil.which('unshare') or subprocess.run(
                    ['unshare', '-Ur', 'true'], capture_output=True).returncode:
                self.skipTest('root refusal requires root or an available user namespace')
            command = ['unshare', '-Ur', *command]
        elif not root and os.geteuid() == 0:
            # CI may run as root; the ceremony still has no root bypass.
            for path in (self.base, *self.base.rglob('*')):
                os.chown(path, self.run_uid, self.run_uid, follow_symlinks=False)
            def drop_user():
                os.setgroups([])
                os.setgid(self.run_uid)
                os.setuid(self.run_uid)
        if tty:
            master, slave = pty.openpty()
            self.addCleanup(os.close, master)
            stdin = slave
        else:
            stdin = subprocess.DEVNULL
        try:
            process = subprocess.Popen(command, stdin=stdin, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, env=self.env,
                                       cwd=self.repo, pass_fds=pass_fds, preexec_fn=drop_user)
            if tty and answer is not None:
                os.write(master, (answer+'\n').encode())
            try:
                output, _ = process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                self.fail('ceremony hung waiting for unexpected input')
        finally:
            if tty:
                os.close(slave)
        return process.returncode, output.decode()

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def refused(self, message, **kwargs):
        code, output = self.invoke(**kwargs)
        self.assertNotEqual(code, 0, output)
        self.assertIn(message, output)
        self.assertEqual(self.target.read_bytes(), self.placeholder)
        return output

    def snapshot(self):
        return {str(p.relative_to(self.base)): (p.stat().st_mode, p.read_bytes() if p.is_file() else None)
                for p in self.base.rglob('*')}

    def test_environment_variables_even_empty_are_refused(self):
        for name in ('COSIGN_PASSWORD', 'COSIGN_KEY'):
            with self.subTest(name=name):
                self.env[name] = ''
                self.refused(name+' is set')
                del self.env[name]
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.key_dir.exists())

    def test_root_is_refused(self):
        self.refused('as root', root=True)
        self.assertEqual(self.calls(), [])

    def test_nonterminal_is_refused(self):
        self.refused('stdin must be a TTY', tty=False)
        self.assertEqual(self.calls(), [])

    def test_rotate_never_overwrites(self):
        code, output = self.invoke('--rotate')
        self.assertNotEqual(code, 0)
        self.assertIn('SECURITY.md', output)
        self.assertIn('rotation never overwrites', output)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.key_dir.exists())

    def test_existing_key_or_public_key_is_refused(self):
        self.key_dir.mkdir(parents=True, mode=0o700)
        for name in ('cosign.key', 'cosign.pub'):
            with self.subTest(name=name):
                path = self.key_dir/name
                path.write_text('existing fake key')
                self.refused('release key already exists')
                self.assertEqual(path.read_text(), 'existing fake key')
                path.unlink()
        self.assertEqual(self.calls(), [])

    def test_nonplaceholder_target_is_refused(self):
        self.target.write_text(PUBLIC+'PLACEHOLDER\n')
        code, output = self.invoke()
        self.assertNotEqual(code, 0)
        self.assertIn('not the PLACEHOLDER', output)
        self.assertEqual(self.target.read_text(), PUBLIC+'PLACEHOLDER\n')
        self.assertEqual(self.calls(), [])

    def test_unsafe_key_directory_mode_is_refused(self):
        self.key_dir.mkdir(parents=True, mode=0o755)
        self.key_dir.chmod(0o755)
        self.refused('owned by you with mode 0700')
        self.assertEqual(self.calls(), [])

    def test_symlink_key_directory_is_refused(self):
        self.key_dir.parent.mkdir(parents=True)
        self.key_dir.symlink_to(self.media, target_is_directory=True)
        self.refused('must not be a symlink')
        self.assertEqual(self.calls(), [])

    def test_home_inside_repository_is_refused(self):
        self.env['HOME'] = str(self.repo)
        self.refused('inside a git work tree')
        self.assertEqual(self.calls(), [])

    def test_dry_run_writes_nothing_and_never_executes_cosign(self):
        before = self.snapshot()
        code, output = self.invoke('--dry-run', answer=None)
        self.assertEqual(code, 0, output)
        self.assertIn('5. Recheck the exact PLACEHOLDER', output)
        self.assertIn('v3.1.4', output)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.calls(), [])

    def test_help_needs_no_terminal_and_writes_nothing(self):
        before = self.snapshot()
        code, output = self.invoke('--help', tty=False)
        self.assertEqual(code, 0, output)
        self.assertIn('Usage:', output)
        self.assertEqual(self.snapshot(), before)

    def test_backup_path_inside_git_tree_is_refused(self):
        self.env['GIT_CEILING_DIRECTORIES'] = str(self.repo/'actions')
        self.refused('inside a git work tree', answer=str(self.repo/'actions'))
        self.assertEqual([c['args'][0] for c in self.calls()], ['version', 'generate-key-pair'])
        self.assertEqual(list(self.repo.rglob('cosign.key')), [])

    def test_backup_path_under_tmp_is_refused(self):
        self.refused('must not be under /tmp', answer=str(self.media))

    def test_nonexistent_backup_path_is_refused(self):
        self.refused('must be an existing directory', answer=str(self.base/'missing'))

    def test_backup_symlink_into_git_tree_is_refused(self):
        alias = self.base/'git-alias'
        alias.symlink_to(self.repo/'actions', target_is_directory=True)
        self.refused('inside a git work tree', answer=str(alias))

    def test_backup_gitfile_worktree_is_refused(self):
        tree = self.base/'gitfile-tree'
        subprocess.run(['git', 'init', '-q', '--separate-git-dir',
                        str(self.base/'git-metadata'), str(tree)], check=True)
        self.assertTrue((tree/'.git').is_file())
        self.refused('inside a git work tree', answer=str(tree))

    def assert_completed(self, output):
        self.assertEqual(self.key_dir.stat().st_mode & 0o777, 0o700)
        for name in ('cosign.key', 'cosign.pub'):
            self.assertEqual((self.key_dir/name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.target.read_text(), PUBLIC)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        self.assertIn(hashlib.sha256(PUBLIC.encode()).hexdigest(), output)
        self.assertIn('Update SECURITY.md manually', output)
        self.assertIn('Paste into the PR description and release notes', output)
        self.assertNotIn(PRIVATE.strip(), output)
        self.assertEqual([c['args'][0] for c in self.calls()],
                         ['version', 'generate-key-pair', 'sign-blob', 'verify-blob'])
        for call in self.calls():
            self.assertFalse(Path(call['home']).exists(), 'temporary Cosign home was not cleaned')
        for path in self.repo.rglob('*'):
            if path.is_file():
                self.assertNotIn(PRIVATE.encode(), path.read_bytes(), str(path))

    def test_skip_keeps_merge_checklist_open(self):
        # Ambient config must not reach Cosign even during generation.
        self.env['SIGSTORE_ROOT_FILE'] = '/poisoned/root'
        code, output = self.invoke()
        self.assertEqual(code, 0, output)
        self.assert_completed(output)
        self.assertIn('NO OFFLINE BACKUP', output)
        self.assertIn('merge checklist stays OPEN', output)

    def simulated_media(self):
        # Simulate a removable mount using an inherited directory descriptor.
        # The fixture lives in /tmp; only realpath's media answer is stubbed so
        # real copy/chmod/hash operations need no writes outside the sandbox.
        fd = os.open(self.media, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        media_mount = f'/proc/self/fd/{fd}'
        realpath = self.bin/'realpath'
        realpath.write_text(f'''#!/usr/bin/python3
import os, sys
if sys.argv[-1] == {str(self.media)!r}:
    print({media_mount!r})
else:
    os.execv('/usr/bin/realpath', ['realpath', *sys.argv[1:]])
''')
        realpath.chmod(0o755)
        return fd

    def test_happy_path_with_backup(self):
        fd = self.simulated_media()
        code, output = self.invoke(answer=str(self.media), pass_fds=(fd,))
        self.assertEqual(code, 0, output)
        self.assert_completed(output)
        backups = list(self.media.iterdir())
        self.assertEqual(len(backups), 1)
        backup = backups[0]
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        for name in ('cosign.key', 'cosign.pub'):
            self.assertEqual((backup/name).stat().st_mode & 0o777, 0o600)
            self.assertEqual((backup/name).read_bytes(), (self.key_dir/name).read_bytes())
        self.assertIn('Offline backup: copied with 0700/0600 permissions and SHA-256 verified', output)

    def test_backup_digest_mismatch_is_refused(self):
        fd = self.simulated_media()
        checksum = self.bin/'sha256sum'
        checksum.write_text('''#!/usr/bin/python3
import os, sys
if '/devsecops-release-backup.' in sys.argv[-1]:
    print('0'*64+'  '+sys.argv[-1])
else:
    os.execv('/usr/bin/sha256sum', ['sha256sum', *sys.argv[1:]])
''')
        checksum.chmod(0o755)
        self.refused('backup SHA-256 mismatch', answer=str(self.media), pass_fds=(fd,))
        self.assertEqual([c['args'][0] for c in self.calls()], ['version', 'generate-key-pair'])

    def prepare_installer(self, tamper=False):
        # Isolate PATH from any system Cosign. The existing installer receives
        # fake download bytes via curl, then performs its real SHA-256 check.
        stub = self.base/'downloaded-cosign'
        (self.bin/'cosign').rename(stub)
        if tamper:
            with stub.open('a') as output:
                output.write('# simulated corrupt download\n')
        for name in ('bash', 'python3', 'uname', 'dirname', 'realpath', 'cmp', 'git',
                     'mktemp', 'chmod', 'rm', 'sha256sum', 'cut', 'awk', 'mkdir',
                     'cp', 'dd', 'stat', 'env', 'cat'):
            (self.bin/name).symlink_to(shutil.which(name))
        curl = self.bin/'curl'
        curl.write_text(f'''#!/usr/bin/python3
import shutil, sys
shutil.copyfile({str(stub)!r}, sys.argv[sys.argv.index('-o')+1])
''')
        curl.chmod(0o755)
        self.env['PATH'] = str(self.bin)

    def test_installer_fallback_checks_pinned_download(self):
        self.prepare_installer()
        code, output = self.invoke()
        self.assertEqual(code, 0, output)
        self.assert_completed(output)

    def test_installer_rejects_corrupt_download_before_execution(self):
        self.prepare_installer(tamper=True)
        self.refused('release tool archive digest mismatch')
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.key_dir.exists())

    def test_unverified_cosign_is_never_executed(self):
        with (self.bin/'cosign').open('a') as output:
            output.write('# tampered bytes\n')
        self.refused('PATH cosign SHA-256 does not match')
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.key_dir.exists())

    def test_verification_failure_does_not_copy_public_key(self):
        self.install_cosign(fail_stage='verify-blob')
        self.refused('simulated cosign failure')
        self.assertEqual((self.key_dir/'cosign.key').read_text(), PRIVATE)
        for call in self.calls():
            self.assertFalse(Path(call['home']).exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
