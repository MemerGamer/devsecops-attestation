#!/usr/bin/env python3
"""Hunor's local release publisher. No CI or noninteractive entry point."""
import argparse
import filecmp
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release_assets', ROOT/'.ci/release_assets.py')
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)
FORGE = 'https://forgejo.remote.kovacsbalinthunor.com'
CHECKER = Path('/home/hunor/Documents/GitHub/phd-lab-forgejo-migration/scripts/mirror-check.sh')
PAIRS = {
    'kbalinthunor/devsecops-attestation': 'MemerGamer/devsecops-attestation',
    'kbalinthunor/g7-release-rehearsal': 'MemerGamer/scratch-mirror-test-public',
}
# Release signing uses the same Cosign pin as scripts/release-key-ceremony.sh.
COSIGN_PIN = 'cosign-v3.1.4'
CI_NAMES = ('CI', 'GITHUB_ACTIONS', 'FORGEJO_ACTIONS', 'GITEA_ACTIONS', 'GITHUB_RUN_ID', 'GITEA_RUN_ID', 'FORGEJO_RUN_ID', 'RUNNER_ENVIRONMENT')


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def git(*args, cwd=ROOT):
    return subprocess.check_output(['git', *args], cwd=cwd, text=True).strip()


def human_gate():
    if any(name in os.environ for name in CI_NAMES):
        raise ValueError('release publisher is forbidden in CI')
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('release publisher requires Hunor at an interactive terminal')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('unexpected authenticated API redirect')


class API:
    def __init__(self, base, token=None):
        self.base, self.token = base, token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path, method='GET', data=None, content_type='application/json'):
        if not path.startswith('/') or path.startswith('//'):
            raise ValueError('invalid API path')
        headers = {'Accept': 'application/json', 'User-Agent': 'devsecops-release-publisher'}
        if self.token:
            headers['Authorization'] = 'token '+self.token
        if data is not None:
            headers['Content-Type'] = content_type
        req = urllib.request.Request(self.base+path, data=data, method=method, headers=headers)
        with self.opener.open(req, timeout=120) as response:
            raw = response.read()
            return json.loads(raw) if raw else None

    def pages(self, path):
        result, ids = [], set()
        for page in range(1, 10001):
            data = self.request(path+('&' if '?' in path else '?')+f'limit=100&per_page=100&page={page}')
            if not isinstance(data, list):
                raise ValueError('incomplete or malformed API enumeration')
            if not data:
                return result
            for item in data:
                if not isinstance(item, dict) or 'id' not in item or item['id'] in ids:
                    raise ValueError('duplicate or malformed paginated API result')
                ids.add(item['id'])
                result.append(item)
        raise ValueError('API enumeration did not terminate')

    def release(self, tag):
        return self.request('/releases/tags/'+urllib.parse.quote(tag, safe=''))


def fetch(url, path):
    if urllib.parse.urlparse(url).scheme != 'https':
        raise ValueError('anonymous downloads require HTTPS')
    # No credentials, cookies or caller proxies. Redirects must remain HTTPS.
    class HTTPSOnly(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if urllib.parse.urlparse(newurl).scheme != 'https':
                raise ValueError('download redirected away from HTTPS')
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSOnly())
    with opener.open(url, timeout=300) as response, path.open('xb') as output:
        shutil.copyfileobj(response, output)


def ref_check(url, tag, tag_object, commit):
    lines = git('ls-remote', '--tags', url, f'refs/tags/{tag}', f'refs/tags/{tag}^{{}}').splitlines()
    actual = dict(line.split()[::-1] for line in lines)
    if actual != {f'refs/tags/{tag}': tag_object, f'refs/tags/{tag}^{{}}': commit}:
        raise ValueError('remote annotated tag object or peeled commit differs')


def mirror_check(forge_repo, github_repo):
    if not CHECKER.is_file():
        raise ValueError(f'required external mirror checker missing: {CHECKER}')
    result = run(['bash', str(CHECKER), f'{FORGE}/{forge_repo}.git', f'https://github.com/{github_repo}.git'], capture_output=True, text=True)
    print(result.stdout, end='')
    if 'identical' not in result.stdout.lower():
        raise ValueError('mirror checker did not report identical refs')


def verify(directory, tag):
    run(['bash', '-euo', 'pipefail', '-c',
         'source "$1/release-policy.sh"; release_verify "$1" "$2" "$3/checksums.txt" "$3/checksums.txt.sigstore.json"',
         'release-verify', str(ROOT/'actions/setup'), tag[1:], str(directory)])


def inventories(api, release_id, baseline):
    result = api.pages(f'/releases/{release_id}/assets')
    names = [a.get('name') for a in result]
    if sorted(names) != sorted(baseline):
        raise ValueError('attached-asset inventory differs from twelve-file baseline')
    for item in result:
        if not isinstance(item.get('id'), int) or item.get('size') != baseline[item['name']]['size']:
            raise ValueError('attached-asset ID or size differs')
    return sorted((a['id'], a['name'], a['size']) for a in result)


def install_checks(directory, tag, base, local):
    for target in assets.TARGETS:
        os_name, arch = target.split('_')
        installed = directory/('install-'+target)
        env = dict(os.environ, INPUT_VERSION=tag[1:], INPUT_REPOSITORY='MemerGamer/devsecops-attestation',
                   INPUT_DOWNLOAD_BASE_URL=base, INPUT_INSTALL_DIR=str(installed), INPUT_VERIFY_SIGNATURE='true',
                   GITHUB_ACTION_PATH=str(ROOT/'actions/setup'), RUNNER_TEMP=str(directory),
                   RUNNER_OS={'darwin': 'macOS', 'linux': 'Linux', 'windows': 'Windows'}[os_name],
                   RUNNER_ARCH={'amd64': 'X64', 'arm64': 'ARM64'}[arch],
                   GITHUB_OUTPUT=str(directory/(target+'.outputs')), GITHUB_PATH=str(directory/(target+'.path')))
        run(['bash', str(ROOT/'actions/setup/setup.sh')], env=env)
        name = next(n for n in assets.names(tag) if f'_{target}.' in n and n.endswith(('.tar.gz', '.zip')))
        contents = assets.archive_contents(local/name, target)
        for binary in assets.BINARIES:
            filename = binary+('.exe' if os_name == 'windows' else '')
            if (installed/filename).read_bytes() != contents[filename]:
                raise ValueError('installed binary differs from checked archive')
        if (installed/'deploy.rego').read_bytes() != contents['policies/deploy.rego']:
            raise ValueError('installed policy differs')
        output = (directory/(target+'.outputs')).read_text().splitlines()
        if f'policy-path={installed}/deploy.rego' not in output or f'version={tag[1:]}' not in output:
            raise ValueError('setup install outputs differ')


def distribution(args, local, baseline, record):
    mirror_check(args.forgejo_repo, args.github_repo)
    copies, inventories_before = [], []
    for forge, api, repo_url, base in [
        ('forgejo', API(f'{FORGE}/api/v1/repos/{args.forgejo_repo}'), f'{FORGE}/{args.forgejo_repo}.git', f'{FORGE}/{args.forgejo_repo}/releases/download'),
        ('github', API(f'https://api.github.com/repos/{args.github_repo}'), f'https://github.com/{args.github_repo}.git', f'https://github.com/{args.github_repo}/releases/download')]:
        ref_check(repo_url, args.tag, record['tag_object'], record['commit'])
        release = api.release(args.tag)
        if release.get('tag_name') != args.tag or release.get('draft') is not False or not release.get('published_at'):
            raise ValueError('release is not published for the exact requested tag')
        release_id = release['id']
        before = inventories(api, release_id, baseline)
        inventories_before.append((api, release_id, before))
        with tempfile.TemporaryDirectory(prefix='release-distribution-'+forge+'-') as scratch:
            downloaded = Path(scratch)/'assets'
            downloaded.mkdir(mode=0o700)
            for name in baseline:
                fetch(f'{base}/{args.tag}/{name}', downloaded/name)
            assets.check_baseline(downloaded, baseline, args.tag)
            for name in baseline:
                if not filecmp.cmp(local/name, downloaded/name, shallow=False):
                    raise ValueError('downloaded bytes differ from baseline')
            verify(downloaded, args.tag)
            install_checks(Path(scratch), args.tag, base, local)
            # Keep both downloaded sets until the direct comparison below.
            copy = args.baseline.parent/('download-'+forge)
            shutil.copytree(downloaded, copy)
            copies.append(copy)
    for name in baseline:
        if not filecmp.cmp(copies[0]/name, copies[1]/name, shallow=False):
            raise ValueError('Forgejo and GitHub bytes differ')
    for api, release_id, before in inventories_before:
        if inventories(api, release_id, baseline) != before:
            raise ValueError('attached assets changed during distribution checking')
    for copy in copies:
        shutil.rmtree(copy)
    print('distribution verified: refs, both complete inventories, all twelve files, signatures and ten installs')


def statuses(api, commit):
    data = api.pages(f'/statuses/{commit}')
    # APIs return newest first. Do not let an older success mask a newer failure.
    latest = {}
    for item in data:
        latest.setdefault(item.get('context'), item)
    for context in ['DevSecOps Attested Pipeline / sign (push)', 'DevSecOps Attested Pipeline / publish (push)']:
        if latest.get(context, {}).get('status', latest.get(context, {}).get('state')) != 'success':
            raise ValueError('required tagged-commit status is not success: '+context)


def ci_input(api, run_id, tag, commit, destination):
    run_data = api.request(f'/actions/runs/{run_id}')
    if run_data.get('head_sha') != commit or run_data.get('status') != 'completed' or run_data.get('conclusion') != 'success':
        raise ValueError('CI artifact run is not successful for the tagged SHA')
    listing = api.request(f'/actions/runs/{run_id}/artifacts')
    if not isinstance(listing, dict) or not isinstance(listing.get('artifacts'), list):
        raise ValueError('malformed CI artifact inventory')
    matched = [a for a in listing['artifacts'] if a.get('name') == 'release-input-'+tag and not a.get('expired')]
    if len(matched) != 1:
        raise ValueError('expected exactly one tag-bound CI artifact')
    # Forgejo artifact API capabilities must be proven in rehearsal (V8).
    url = api.base+f'/actions/artifacts/{matched[0]["id"]}/zip'
    req = urllib.request.Request(url, headers={'Authorization': 'token '+api.token})
    with api.opener.open(req, timeout=300) as response:
        raw = response.read()
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if sorted(i.filename for i in archive.infolist()) != sorted(assets.names(tag)+['checksums.txt']):
            raise ValueError('unexpected CI artifact zip inventory')
        for item in archive.infolist():
            kind = stat.S_IFMT(item.external_attr >> 16)
            if item.is_dir() or kind not in (0, stat.S_IFREG):
                raise ValueError('CI artifact contains nonregular files')
            (destination/item.filename).write_bytes(archive.read(item))
    assets.validate(destination, tag)


def private_key_path(key):
    info = key.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('release private key must be an owned regular 0600 file')
    key = key.resolve(strict=True)
    if key.parent.stat().st_uid != os.getuid() or stat.S_IMODE(key.parent.stat().st_mode) != 0o700:
        raise ValueError('release key directory must be owned and 0700')
    if key.is_relative_to(ROOT):
        raise ValueError('release private key must be outside the repository')
    return key


def cosign_pin():
    pin = json.loads((ROOT/'.ci/release-tools.json').read_text())[COSIGN_PIN]
    if not re.fullmatch('[0-9a-f]{64}', pin.get('sha256', '')):
        raise ValueError('invalid cosign SHA-256 pin in .ci/release-tools.json: '+COSIGN_PIN)
    if not re.fullmatch(r'v3\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', pin.get('version', '')):
        raise ValueError('invalid cosign version pin in .ci/release-tools.json: '+COSIGN_PIN)
    return pin['version'], pin['sha256']


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned_cosign(scratch):
    """Resolve Cosign like the key ceremony: a private copy of the PATH binary,
    or the verified installer, accepted only with the pinned SHA-256."""
    version, expected = cosign_pin()
    if os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        raise ValueError('the pinned release-signing Cosign requires linux/amd64')
    found = shutil.which('cosign')
    if found:
        # Verify and execute the same private copy, even if PATH changes later.
        binary = scratch/'cosign'
        shutil.copyfile(found, binary)
        binary.chmod(0o700)
        if sha256(binary) != expected:
            raise ValueError(f'PATH cosign SHA-256 does not match the {COSIGN_PIN} pin in .ci/release-tools.json; '
                             'remove it from PATH to use the verified installer')
    else:
        try:
            run(['bash', str(ROOT/'.ci/install-release-tools.sh'), COSIGN_PIN],
                env=dict(os.environ, RELEASE_TOOLS_DIR=str(scratch/'tools')))
        except subprocess.CalledProcessError as error:
            raise ValueError(f'cosign is not on PATH and the pinned {COSIGN_PIN} install failed') from error
        binary = scratch/'tools'/COSIGN_PIN
        if not binary.is_file() or binary.is_symlink():
            raise ValueError(f'pinned cosign binary is missing after install: {binary}')
        if sha256(binary) != expected:
            raise ValueError('installed cosign SHA-256 does not match the pin in .ci/release-tools.json')
    return binary, version, expected


def sign(directory, key):
    human_gate()
    key = private_key_path(key)
    with tempfile.TemporaryDirectory(prefix='release-cosign-bin-') as scratch:
        binary, version, expected = pinned_cosign(Path(scratch))
        # release_cosign_pinned rechecks the SHA-256 before every execution.
        run(['bash', '-euo', 'pipefail', '-c',
             'source "$1/release-policy.sh"; release_cosign_pinned "$4" "$5" "$6" sign-blob --key "$2" --bundle "$3/checksums.txt.sigstore.json" --new-bundle-format=true --use-signing-config=false --tlog-upload=true --rekor-url=https://rekor.sigstore.dev "$3/checksums.txt"',
             'release-sign', str(ROOT/'actions/setup'), str(key), str(directory), str(binary), expected, version])


def check_ancestor(commit):
    result = subprocess.run(['git', 'merge-base', '--is-ancestor', commit, 'origin/main'], cwd=ROOT, check=False)
    if result.returncode == 1:
        raise ValueError('tagged commit is not an ancestor of origin/main')
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, result.args)


def github_copy(args, payload, baseline):
    # gh uses Hunor's existing login; it may never create a missing tag.
    try:
        run(['gh', 'release', 'create', args.tag, '--repo', args.github_repo, '--verify-tag', '--title', args.tag,
             '--notes-file', str(args.notes), *[str(payload/n) for n in sorted(baseline)]])
    except Exception:
        # Preserve the publication failure even if cleanup or ref checking fails.
        try:
            view = subprocess.run(['gh', 'release', 'view', args.tag, '--repo', args.github_repo, '--json', 'isDraft'], capture_output=True, text=True)
            if view.returncode == 0 and json.loads(view.stdout).get('isDraft') is True:
                run(['gh', 'release', 'delete', args.tag, '--repo', args.github_repo, '--yes'])
        except Exception as cleanup_error:
            print('github draft cleanup also failed: '+str(cleanup_error), file=sys.stderr)
        try:
            mirror_check(args.forgejo_repo, args.github_repo)
        except Exception as mirror_error:
            print('post-write mirror check also failed: '+str(mirror_error), file=sys.stderr)
        raise
    else:
        mirror_check(args.forgejo_repo, args.github_repo)


def publish(args):
    human_gate()
    if not CHECKER.is_file():
        raise ValueError(f'required external mirror checker missing: {CHECKER}')
    if 'PLACEHOLDER' in (ROOT/'actions/setup/release-keys/release-v1.pub').read_text():
        raise ValueError('Hunor must complete and review the release-key ceremony first')
    if args.baseline.exists():
        raise ValueError('baseline already exists; use --check-distribution or a fresh path')
    if args.key is None:
        raise ValueError('--key is required for publication')
    token = os.environ.get('FORGEJO_TOKEN')
    if not token:
        raise ValueError('FORGEJO_TOKEN must be supplied in the local environment')
    forge_api = API(f'{FORGE}/api/v1/repos/{args.forgejo_repo}', token)
    commit = git('rev-parse', args.tag+'^{commit}')
    tag_object = git('rev-parse', 'refs/tags/'+args.tag)
    if git('cat-file', '-t', tag_object) != 'tag':
        raise ValueError('release tag must be annotated')
    check_ancestor(commit)
    for url in [f'{FORGE}/{args.forgejo_repo}.git', f'https://github.com/{args.github_repo}.git']:
        ref_check(url, args.tag, tag_object, commit)
    statuses(forge_api, commit)
    # Existing published releases are never replaced. Drafts require separate
    # Hunor cleanup; the publisher does not reuse potentially stale inputs.
    for api in [forge_api, API(f'https://api.github.com/repos/{args.github_repo}')]:
        try:
            api.release(args.tag)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
        else:
            raise ValueError('release or draft already exists; stop and review rollback')
    args.baseline.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='release-verified-', dir=args.baseline.parent))
    payload = work/'upload'
    if args.ci_output:
        assets.validate(args.ci_output, args.tag)
        shutil.copytree(args.ci_output, payload, symlinks=True)
    else:
        ci_input(forge_api, args.run_id, args.tag, commit, payload)
    assets.validate(payload, args.tag)
    source = work/'source'
    run(['git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', str(ROOT), str(source)])
    run(['git', '-C', str(source), 'checkout', '--quiet', '--detach', commit])
    # Build via the tagged, pinned toolchain and tools, with fresh caches.
    run(['bash', str(source/'scripts/release-build.sh'), '--build-only'], cwd=source)
    assets.compare_build(payload, args.tag, source, source/'dist/artifacts.json')
    sbom_unchecked = False
    for name in assets.names(args.tag):
        if not name.endswith(('.tar.gz', '.zip')):
            continue
        outputs = []
        for iteration in (1, 2):
            output = work/f'{name}.local-{iteration}.json'
            run([str(source/'.release-tools/syft'), str(payload/name), '--output', 'spdx-json='+str(output), '--enrich', 'all'])
            outputs.append(output.read_bytes())
        if outputs[0] != outputs[1]:
            sbom_unchecked = True
        elif outputs[0] != (payload/(name+'.sbom.json')).read_bytes():
            raise ValueError('deterministic SBOM differs from independent regeneration')
    notes = args.notes.read_text()
    if sbom_unchecked and 'SBOMs are signed but not independently checked' not in notes:
        raise ValueError('nondeterministic SBOMs require the exact release-notes disclosure')
    assets.rebuild_manifest(payload, args.tag)
    print(f'checked {args.tag}, tag object {tag_object}, commit {commit}, 20 rebuilt binaries, five archives and ten payload digests')
    print('upload names: '+', '.join(sorted(assets.names(args.tag)+['checksums.txt', 'checksums.txt.sigstore.json'])))
    if input(f'Hunor: type "publish {args.tag}" to sign and publish these bytes: ') != 'publish '+args.tag:
        raise ValueError('publication not confirmed')
    sign(payload, args.key)
    verify(payload, args.tag)
    baseline = assets.baseline(payload, args.tag)
    record = {'tag': args.tag, 'tag_object': tag_object, 'commit': commit, 'forgejo_repo': args.forgejo_repo,
              'github_repo': args.github_repo, 'directory': str(payload), 'assets': baseline}
    with args.baseline.open('x') as output:
        json.dump(record, output, indent=2)
        output.write('\n')
    for name in baseline:
        (payload/name).chmod(0o400)
    payload.chmod(0o500)
    assets.check_baseline(payload, baseline, args.tag)
    release = forge_api.request('/releases', 'POST', json.dumps({'tag_name': args.tag, 'name': args.tag, 'body': notes, 'draft': True}).encode())
    release_id = release['id']
    try:
        for name in baseline:
            assets.check_baseline(payload, baseline, args.tag)
            boundary = 'g7-release-file-boundary'
            body = (f'--{boundary}\r\nContent-Disposition: form-data; name="attachment"; filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
                    +(payload/name).read_bytes()+f'\r\n--{boundary}--\r\n'.encode())
            forge_api.request(f'/releases/{release_id}/assets?name='+urllib.parse.quote(name), 'POST', body, 'multipart/form-data; boundary='+boundary)
        inventories(forge_api, release_id, baseline)
        forge_api.request(f'/releases/{release_id}', 'PATCH', json.dumps({'draft': False}).encode())
    except Exception:
        current = forge_api.request(f'/releases/{release_id}')
        if current.get('draft') is True:
            forge_api.request(f'/releases/{release_id}', 'DELETE')
        raise
    assets.check_baseline(payload, baseline, args.tag)
    github_copy(args, payload, baseline)
    distribution(args, payload, baseline, record)
    print(f'kept verified local baseline at {args.baseline}')


def main():
    human_gate()
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag')
    parser.add_argument('--forgejo-repo', choices=list(PAIRS), default='kbalinthunor/devsecops-attestation')
    parser.add_argument('--baseline', type=Path, required=True, help='new local baseline outside the upload directory')
    parser.add_argument('--check-distribution', action='store_true')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--ci-output', type=Path, help='fresh privately downloaded CI artifact contents')
    source.add_argument('--run-id', type=int, help='successful Forgejo release workflow run ID (V8)')
    parser.add_argument('--key', type=Path, help='private-key path only; passphrase is always interactive')
    parser.add_argument('--notes', type=Path)
    args = parser.parse_args()
    assets.names(args.tag)
    args.github_repo = PAIRS[args.forgejo_repo]
    args.baseline = args.baseline.resolve()
    if args.check_distribution:
        record = json.loads(args.baseline.read_text())
        for key in ('tag', 'forgejo_repo', 'github_repo'):
            if record[key] != getattr(args, key):
                raise ValueError('baseline belongs to another release')
        local = Path(record['directory'])
        assets.check_baseline(local, record['assets'], args.tag)
        distribution(args, local, record['assets'], record)
    else:
        if args.notes is None or (args.ci_output is None and args.run_id is None):
            parser.error('publication requires --notes and --ci-output or --run-id')
        args.notes = args.notes.resolve(strict=True)
        if args.ci_output:
            args.ci_output = args.ci_output.resolve(strict=True)
        publish(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print('error: '+str(error), file=sys.stderr)
        sys.exit(1)
