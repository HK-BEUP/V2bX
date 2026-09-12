#!/usr/bin/env python3
"""Destructive fixtures ONLY on an empty, disposable GitHub-hosted Linux runner.

Real systemd, real published-candidate ELF and loopback-only synthetic listeners.
Never run this against an existing installation or a self-hosted runner.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from unittest.mock import patch
import zipfile

VERSION = 'v25.12.2-beup-observe-rc.1'
EXPECTED = {
    'x86_64': ('V2bX-linux-64.zip', '3b2c6f655458685afeaf0aaa2981f4e2e5ffb42b3c3566ae70061bf90545ae60'),
    'aarch64': ('V2bX-linux-arm64-v8a.zip', 'c9c1eea26a11e3775623529518690f722396c2797268192bf71d8c4348c4a4b9'),
}
PROGRAM = Path('/usr/local/V2bX')
CONFIG = Path('/etc/V2bX')
UNIT = Path('/etc/systemd/system/V2bX.service')
TARGETS = [PROGRAM, CONFIG, UNIT, Path('/usr/bin/V2bX'), Path('/usr/bin/v2bx')]


def run(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=180)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.system() == 'Linux'
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert not any(p.exists() or p.is_symlink() for p in TARGETS), 'Existing install: refuse'
    assert not Path('/usr/local/.backups/V2bX').exists(), 'Existing backup: refuse'
    assert run('systemctl', 'show', 'V2bX', '-p', 'LoadState', '--value', check=False).stdout.strip() == 'not-found'
    os.umask(0o077)
    name, checksum = EXPECTED[platform.machine()]
    archive = args.artifacts.resolve() / name
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == checksum
    evidence = {'version': VERSION, 'architecture': platform.machine(), 'cases': [],
                'real_systemd': True, 'real_candidate_binary': True,
                'production_credentials': False, 'panel_requests': False}
    temp = Path(tempfile.mkdtemp(prefix='beup-systemd-acceptance-'))
    helper = temp / 'upgrade.py'
    with zipfile.ZipFile(archive) as z:
        helper.write_bytes(z.read('upgrade.py'))
        binary_sha = hashlib.sha256(z.read('V2bX')).hexdigest()
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == '44e0ece8306bbeb8a757b168ee6742dee2129a2c49fb30e2522659002bc543c7'
    spec = importlib.util.spec_from_file_location('candidate_upgrade', helper)
    u = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(u)

    def cli(expected=0, sha=checksum):
        result = run('python3', str(helper), str(archive), sha, VERSION, check=False)
        assert result.returncode == expected, result.stdout + result.stderr
        return result

    def mark(name):
        evidence['cases'].append(name)
        print('PASS ' + name, flush=True)

    def pid():
        return int(run('systemctl', 'show', 'V2bX', '-p', 'MainPID', '--value').stdout)

    def configure():
        # Nodes empty: no panel, account, or subscription traffic.
        c = {'Log': {'Level': 'error'}, 'Nodes': [], 'Cores': [{
            'Type': 'xray', 'Log': {'Level': 'error'},
            'InboundConfigPath': str(CONFIG / 'fixture-inbound.json'),
            'OutboundConfigPath': str(CONFIG / 'fixture-outbound.json'),
        }]}
        (CONFIG / 'config.json').write_text(json.dumps(c))
        (CONFIG / 'fixture-inbound.json').write_text(json.dumps([{
            'listen': '127.0.0.1', 'port': 29631, 'protocol': 'socks',
            'settings': {'auth': 'noauth', 'udp': False}, 'tag': 'isolated-acceptance',
        }]))
        (CONFIG / 'fixture-outbound.json').write_text('[{"protocol":"blackhole","tag":"no-egress"}]')
        (CONFIG / 'operator-marker').write_text('synthetic retained configuration')
        (PROGRAM / 'operator-marker').write_text('synthetic retained program data')

    def ready():
        for _ in range(30):
            try:
                with socket.create_connection(('127.0.0.1', 29631), timeout=1) as s:
                    s.sendall(b'\x05\x01\x00')
                    assert s.recv(2) == b'\x05\x00'
                assert pid() > 0
                return
            except (OSError, AssertionError):
                time.sleep(1)
        raise AssertionError('Real Xray loopback listener failed')

    def snapshot():
        return {'config': u.tree_hash(CONFIG), 'program': u.tree_hash(PROGRAM),
                'unit': u.digest(UNIT), 'enabled': run('systemctl', 'is-enabled', 'V2bX', check=False).stdout,
                'links': {str(p): os.readlink(p) for p in TARGETS[-2:]}}

    def transaction(service=None):
        return u.transaction(archive, checksum, VERSION, Path('/'), service or u.Systemd(), platform.machine())

    try:
        cli()
        assert not u.Systemd().active() and pid() == 0
        assert json.loads((CONFIG / 'config.json').read_text())['Nodes'] == []
        assert stat.S_IMODE((CONFIG / 'config.json').stat().st_mode) == 0o600
        assert u.digest(PROGRAM / 'V2bX') == binary_sha
        assert VERSION in run(str(PROGRAM / 'V2bX'), 'version').stdout
        mark('fresh-install-no-autostart-real-cli')

        configure()
        before = snapshot()
        cli()
        assert snapshot() == before and not u.Systemd().active() and pid() == 0
        mark('stopped-upgrade-preserves-config-unit-commands-state')

        run('systemctl', 'enable', 'V2bX')
        run('systemctl', 'start', 'V2bX')
        ready()
        before = snapshot()
        original_pid = pid()
        cli()
        ready()
        assert snapshot() == before and pid() != original_pid
        assert run('systemctl', 'show', 'V2bX', '-p', 'NRestarts', '--value').stdout.strip() == '0'
        mark('active-upgrade-restores-listener-config-and-enabled-state')

        original_pid = pid()
        cli(expected=1, sha='0' * 64)
        assert pid() == original_pid and snapshot() == before
        mark('invalid-checksum-does-not-stop-live-fixture')

        # Inject a real crash at the first new start; rollback uses unmodified
        # systemd start and the original binary, config and listener.
        class CrashNewStart(u.Systemd):
            def __init__(self):
                self.starts = 0
            def start(self):
                super().start()
                self.starts += 1
                if self.starts == 1:
                    self.call('kill', '--kill-whom=main', '--signal=SIGKILL', 'V2bX')
                    time.sleep(0.2)
        try:
            transaction(CrashNewStart())
            raise AssertionError('Expected failed startup')
        except RuntimeError as e:
            assert '稳定启动' in str(e), str(e)
        ready()
        assert snapshot() == before
        mark('real-new-process-crash-restores-old-program-and-listener')

        replace = os.replace
        def fail_command(src, dst):
            if str(dst) == '/usr/bin/v2bx':
                raise OSError('synthetic command update failure')
            return replace(src, dst)
        try:
            with patch.object(u.os, 'replace', side_effect=fail_command):
                transaction()
            raise AssertionError('Expected command failure')
        except OSError:
            pass
        ready()
        assert snapshot() == before
        mark('command-update-failure-restores-links-and-service')

        class Interrupted(u.Systemd):
            def stop(self):
                super().stop()
                raise KeyboardInterrupt()
        try:
            transaction(Interrupted())
            raise AssertionError('Expected interruption')
        except KeyboardInterrupt:
            pass
        ready()
        assert snapshot() == before
        mark('interruption-after-stop-restores-service')
        records = [json.loads(p.read_text()) for p in Path('/usr/local/.backups/V2bX').glob('upgrade-*/transaction.json')]
        assert sum(r['status'] == 'rolled-back' for r in records) == 3
        assert all(stat.S_IMODE(p.stat().st_mode) == 0o700 for p in Path('/usr/local/.backups/V2bX').glob('upgrade-*'))
        mark('rollback-records-and-root-only-backup-permissions')
        evidence['status'] = 'passed'
    finally:
        # Only the exact fixtures created above on the preflight-empty runner.
        run('systemctl', 'stop', 'V2bX', check=False)
        run('systemctl', 'disable', 'V2bX', check=False)
        preserved = temp / 'preserved-fixtures'
        preserved.mkdir()
        for i, p in enumerate(TARGETS):
            if p.exists() or p.is_symlink():
                shutil.move(str(p), str(preserved / str(i)))
        run('systemctl', 'daemon-reload')
        evidence['fixture_service_stopped'] = not u.Systemd().active()
        evidence['fixture_backup'] = str(temp)
        args.output.write_text(json.dumps(evidence, indent=2) + '\n')


if __name__ == '__main__':
    main()
