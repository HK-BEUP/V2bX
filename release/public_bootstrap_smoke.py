#!/usr/bin/env python3
"""Verify public one-key download/install on an empty disposable runner only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request

assert os.geteuid() == 0 and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert Path('/proc/1/comm').read_text().strip() == 'systemd'
assert not any(p.exists() or p.is_symlink() for p in [Path('/etc/V2bX'), Path('/usr/local/V2bX'), Path('/etc/systemd/system/V2bX.service'), Path('/usr/bin/V2bX'), Path('/usr/bin/v2bx')])
with urllib.request.urlopen('https://raw.githubusercontent.com/HK-BEUP/V2bX-script/master/install.sh', timeout=60) as r:
    content = r.read(65536)
assert hashlib.sha256(content).hexdigest() == '3685b956da2c70fafd0d9bb49ee618be8f74f8624d41edcd4bcae7c37bd8bc5c'
with tempfile.TemporaryDirectory(prefix='beup-public-bootstrap-') as temp:
    script = Path(temp) / 'install.sh'
    script.write_bytes(content)
    subprocess.run(['bash', str(script)], check=True, timeout=180)
    assert subprocess.run(['systemctl', 'is-active', '--quiet', 'V2bX']).returncode != 0
    config = Path('/etc/V2bX/config.json').read_bytes()
    assert json.loads(config)['Nodes'] == []
    version = subprocess.check_output(['/usr/local/V2bX/V2bX', 'version'], text=True)
    assert 'v25.12.2-beup-observe-rc.1' in version
    # The management update command must follow the verified public latest entry.
    updated = subprocess.run(['bash', '/usr/bin/v2bx', 'update'], check=True, timeout=180, capture_output=True, text=True)
    assert '安装完成；备份：' in updated.stdout, 'Management update did not complete installer'
    print(updated.stdout)
    assert Path('/etc/V2bX/config.json').read_bytes() == config
    assert subprocess.run(['systemctl', 'is-active', '--quiet', 'V2bX']).returncode != 0
print('PASS public master -> latest -> SHA256SUMS -> real install -> management update; stopped configuration preserved')
