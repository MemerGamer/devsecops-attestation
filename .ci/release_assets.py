#!/usr/bin/env python3
"""Strict release inventories shared by CI staging and the local publisher."""
import argparse
import hashlib
import json
import re
import stat
import tarfile
import zipfile
from pathlib import Path

TARGETS = ('darwin_amd64', 'darwin_arm64', 'linux_amd64', 'linux_arm64', 'windows_amd64')
BINARIES = ('keygen', 'attest', 'verify', 'gate')
METADATA = ('LICENSE', 'README.md', 'policies/deploy.rego')


def names(tag):
    if not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', tag):
        raise ValueError('invalid stable release tag')
    archives = [f'devsecops-attestation_{tag[1:]}_{t}.' + ('zip' if t.startswith('windows') else 'tar.gz') for t in TARGETS]
    return sorted(archives + [a+'.sbom.json' for a in archives])


def regular(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f'not a regular file: {path.name}')


def digest(path):
    regular(path)
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def manifest(path, tag):
    regular(path)
    data = path.read_bytes()
    entries = {}
    for line in data.splitlines(keepends=True):
        match = re.fullmatch(rb'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)\n', line)
        if not match:
            raise ValueError('malformed checksum entry')
        checksum, name = (x.decode('ascii') for x in match.groups())
        if '..' in name or name in entries:
            raise ValueError('unsafe or duplicate checksum entry')
        entries[name] = checksum
    if sorted(entries) != names(tag):
        raise ValueError('manifest inventory differs from requested tag')
    return entries


def validate(directory, tag, bundle=False):
    expected = names(tag) + ['checksums.txt']
    if bundle:
        expected += ['checksums.txt.sigstore.json']
    if sorted(p.name for p in directory.iterdir()) != sorted(expected):
        raise ValueError('unexpected, missing or duplicate release files')
    for name in expected:
        regular(directory/name)
    entries = manifest(directory/'checksums.txt', tag)
    for name, checksum in entries.items():
        if digest(directory/name) != checksum:
            raise ValueError(f'digest mismatch: {name}')
    return entries


def rebuild_manifest(directory, tag):
    validate(directory, tag)
    data = ''.join(f'{digest(directory/name)}  {name}\n' for name in names(tag))
    (directory/'checksums.txt').write_text(data, encoding='ascii', newline='\n')


def baseline(directory, tag):
    validate(directory, tag, bundle=True)
    return {name: {'size': (directory/name).stat().st_size, 'sha256': digest(directory/name)}
            for name in sorted(names(tag)+['checksums.txt', 'checksums.txt.sigstore.json'])}


def check_baseline(directory, expected, tag):
    if baseline(directory, tag) != expected:
        raise ValueError('release bytes differ from local baseline')


def archive_contents(path, target):
    ext = '.exe' if target.startswith('windows') else ''
    expected = sorted([b+ext for b in BINARIES]+list(METADATA))
    result = {}
    if path.name.endswith('.zip'):
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                kind = stat.S_IFMT(item.external_attr >> 16)
                if item.is_dir() or kind not in (0, stat.S_IFREG) or item.filename in result:
                    raise ValueError('unexpected zip member type or duplicate')
                if item.filename not in expected:
                    raise ValueError('unexpected zip member name')
                result[item.filename] = archive.read(item)
    else:
        with tarfile.open(path, 'r:gz') as archive:
            for item in archive:
                if not item.isfile() or item.name in result or item.name not in expected:
                    raise ValueError('unexpected tar member name, type or duplicate')
                result[item.name] = archive.extractfile(item).read()
    if sorted(result) != expected:
        raise ValueError('archive member inventory differs from expected files')
    return result


def compare_build(directory, tag, source, artifacts):
    local = {}
    for item in json.loads(artifacts.read_text()):
        if item.get('type') != 'Binary':
            continue
        target = item['goos']+'_'+item['goarch']
        binary = item['name'].removesuffix('.exe')
        key = (target, binary)
        path = (source/item['path']).resolve()
        if not path.is_relative_to((source/'dist').resolve()) or key in local:
            raise ValueError('invalid local build artifact path or duplicate')
        regular(path)
        local[key] = path.read_bytes()
    expected = {(t, b) for t in TARGETS for b in BINARIES}
    if set(local) != expected:
        raise ValueError('local build must contain exactly 20 binaries')
    for target in TARGETS:
        archive = next(n for n in names(tag) if n.endswith(('.tar.gz', '.zip')) and f'_{target}.' in n)
        contents = archive_contents(directory/archive, target)
        for name in METADATA:
            if contents[name] != (source/name).read_bytes():
                raise ValueError(f'archive metadata differs from tagged source: {name}')
        for binary in BINARIES:
            name = binary+('.exe' if target.startswith('windows') else '')
            if contents[name] != local[(target, binary)]:
                raise ValueError(f'local rebuild differs: {target}/{binary}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['validate', 'stage'])
    parser.add_argument('tag')
    parser.add_argument('directory', type=Path)
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    if args.command == 'stage':
        import shutil
        if args.destination is None:
            parser.error('stage requires --destination')
        args.destination.mkdir(mode=0o700)
        for name in names(args.tag)+['checksums.txt']:
            regular(args.directory/name)
            shutil.copyfile(args.directory/name, args.destination/name)
        validate(args.destination, args.tag)
    else:
        validate(args.directory, args.tag)


if __name__ == '__main__':
    main()
