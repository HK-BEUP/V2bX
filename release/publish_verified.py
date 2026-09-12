#!/usr/bin/env python3
"""Publish only the explicitly authorized, fixed candidate. Never touches nodes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

REPO = 'HK-BEUP/V2bX'
TAG = 'v25.12.2-beup-observe-rc.1'
SOURCE = '19a661b52103c5c47438330a2a753d1b35be2b58'
SCRIPTS = 'b74ad979a2199e2a733dbfb14cd2881a11d13c40'
TEST_COMMIT = '9c55fddce15ab0ef5d81e08bc215e9b77077015e'
TEST_RUN = 34683953742
SUMS = {
    'V2bX-linux-64.zip': '3b2c6f655458685afeaf0aaa2981f4e2e5ffb42b3c3566ae70061bf90545ae60',
    'V2bX-linux-arm64-v8a.zip': 'c9c1eea26a11e3775623529518690f722396c2797268192bf71d8c4348c4a4b9',
}
BOOTSTRAP_SHA = '3685b956da2c70fafd0d9bb49ee618be8f74f8624d41edcd4bcae7c37bd8bc5c'


def gh(*args, payload=None):
    result = subprocess.run(['gh', *args], input=json.dumps(payload) if payload is not None else None,
                            capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError('GitHub operation failed: ' + ' '.join(args[:4]))
    return json.loads(result.stdout) if args[0] == 'api' and result.stdout.strip() else result.stdout


def api(path, method='GET', payload=None):
    args = ['api', '--method', method, path]
    if payload is not None:
        args += ['--input', '-']
    return gh(*args, payload=payload)


def fetch(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'HK-BEUP-release-verification'}), timeout=60) as response:
        assert response.geturl().startswith('https://')
        data = response.read(140 * 1024 * 1024)
        assert len(data) < 140 * 1024 * 1024
        return data


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['prepare', 'activate'])
    p.add_argument('--artifacts', type=Path, required=True)
    p.add_argument('--notes', type=Path, required=True)
    args = p.parse_args()
    assert os.environ.get('GITHUB_REPOSITORY') == REPO
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('GITHUB_REF') == 'refs/heads/beup/release-20260912'
    test = api(f'repos/{REPO}/actions/runs/{TEST_RUN}')
    assert test['head_sha'] == TEST_COMMIT and test['conclusion'] == 'success'
    jobs = api(f'repos/{REPO}/actions/runs/{TEST_RUN}/jobs')['jobs']
    assert len(jobs) == 2 and all(j['conclusion'] == 'success' for j in jobs)
    assert api(f'repos/{REPO}/git/ref/heads/dev_new')['object']['sha'] == SOURCE
    assets = dict(SUMS)
    for name, checksum in SUMS.items():
        assert hashlib.sha256((args.artifacts / name).read_bytes()).hexdigest() == checksum
    assert set((args.artifacts / 'SHA256SUMS').read_text().splitlines()) == {sha+'  '+name for name, sha in SUMS.items()}
    for name in ['SHA256SUMS', 'package-verification.json']:
        assets[name] = hashlib.sha256((args.artifacts / name).read_bytes()).hexdigest()
    releases = api(f'repos/{REPO}/releases?per_page=100')
    matches = [r for r in releases if r['tag_name'] == TAG]
    assert len(matches) <= 1
    release = matches[0] if matches else None
    if args.mode == 'prepare':
        if release is None:
            # The target equals the verified default: the Actions token never
            # needs workflow-edit permission or an exported personal credential.
            release = api(f'repos/{REPO}/releases', 'POST', {
                'tag_name': TAG, 'target_commitish': SOURCE,
                'name': 'HK-BEUP Xray ' + TAG, 'body': args.notes.read_text(),
                'draft': True, 'prerelease': False, 'make_latest': 'false',
            })
        assert release['target_commitish'] in (SOURCE, 'dev_new')
        existing = {a['name']: a for a in release['assets']}
        assert set(existing) <= set(assets), 'Unexpected release asset'
        for name, checksum in assets.items():
            if name not in existing:
                assert release['draft'], 'Do not mutate published assets'
                gh('release', 'upload', TAG, str(args.artifacts / name), '--repo', REPO)
        release = api(f'repos/{REPO}/releases/{release["id"]}')
        assert {a['name'] for a in release['assets']} == set(assets)
        for a in release['assets']:
            assert a['state'] == 'uploaded' and a['digest'] == 'sha256:' + assets[a['name']]
        if release['draft']:
            release = api(f'repos/{REPO}/releases/{release["id"]}', 'PATCH', {'draft': False, 'make_latest': 'false'})
        for name, checksum in assets.items():
            assert hashlib.sha256(fetch(f'https://github.com/{REPO}/releases/download/{TAG}/{name}')).hexdigest() == checksum
        assert api(f'repos/{REPO}/git/ref/tags/{TAG}')['object']['sha'] == SOURCE
        print('PUBLIC_PACKAGE_VERIFIED_NOT_LATEST', release['html_url'], flush=True)
    else:
        assert release and not release['draft']
        for _ in range(60):
            scripts_ready = api('repos/HK-BEUP/V2bX-script/git/ref/heads/master')['object']['sha'] == SCRIPTS
            if scripts_ready:
                bootstrap = fetch('https://raw.githubusercontent.com/HK-BEUP/V2bX-script/master/install.sh')
                if hashlib.sha256(bootstrap).hexdigest() == BOOTSTRAP_SHA:
                    break
            time.sleep(10)
        else:
            raise RuntimeError('Entry switch not verified; release remains non-latest')
        for a in release['assets']:
            assert a['digest'] == 'sha256:' + assets[a['name']]
        api(f'repos/{REPO}/releases/{release["id"]}', 'PATCH', {'make_latest': 'true'})
        assert api(f'repos/{REPO}/releases/latest')['tag_name'] == TAG
        print('LATEST_AND_BOOTSTRAP_VERIFIED', flush=True)


if __name__ == '__main__':
    main()
