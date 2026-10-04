#!/usr/bin/env bash
# Bootstrap only: execute the installer from the same checksum-verified package.
set -euo pipefail
[[ ${EUID} == 0 ]] || { echo '请使用 root 运行'; exit 1; }
command -v python3 >/dev/null || { echo '需要先安装 Python 3（含标准库 SSL）'; exit 1; }
exec python3 - "${1:-latest}" <<'PY'
import hashlib, json, os, platform, re, shutil, stat, subprocess, sys, tempfile, urllib.request, zipfile
version = sys.argv[1]
if platform.system() != 'Linux' or not os.path.isdir('/run/systemd/system'):
    raise SystemExit('仅支持 Linux/systemd；尚未修改系统')
arch = {'x86_64':'64', 'aarch64':'arm64-v8a'}.get(platform.machine())
if not arch: raise SystemExit('不支持此 CPU 架构；尚未修改系统')
def fetch(url, limit):
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'HK-BEUP-installer'}), timeout=45) as r:
        if not r.geturl().startswith('https://'): raise ValueError('HTTPS required')
        data = r.read(limit+1)
        if len(data)>limit: raise ValueError('download too large')
        return data
if version == 'latest':
    version = json.loads(fetch('https://api.github.com/repos/HK-BEUP/V2bX/releases/latest', 1048576))['tag_name']
if not re.fullmatch(r'v[0-9][A-Za-z0-9._-]{0,99}', version): raise SystemExit('版本格式无效')
name = 'V2bX-linux-'+arch+'.zip'
base = 'https://github.com/HK-BEUP/V2bX/releases/download/'+version+'/'
sums = fetch(base+'SHA256SUMS', 65536).decode('ascii')
matches = re.findall(r'^([0-9a-f]{64})  '+re.escape(name)+r'$', sums, re.M)
if len(matches)!=1: raise SystemExit('缺少唯一 SHA256SUMS 校验项；保持原版本')
payload = fetch(base+name, 134217728)
if hashlib.sha256(payload).hexdigest()!=matches[0]: raise SystemExit('安装包校验失败；保持原版本')
os.umask(0o077)
with tempfile.TemporaryDirectory(prefix='beup-v2bx-') as td:
    archive=os.path.join(td,name)
    with open(archive,'wb') as f: f.write(payload)
    # Do not extract arbitrary paths. Only a fixed, regular installer member.
    with zipfile.ZipFile(archive) as z:
        if z.namelist().count('upgrade.py')!=1: raise SystemExit('该版本不含安全升级器；保持原版本')
        i=z.getinfo('upgrade.py')
        if i.file_size>262144 or stat.S_ISLNK(i.external_attr>>16): raise SystemExit('非法升级器成员')
        helper=os.path.join(td,'upgrade.py')
        with open(helper,'wb') as f: f.write(z.read(i))
    # Require the capability marker before running any version's installer.
    with zipfile.ZipFile(archive) as z:
        meta=json.loads(z.read('RELEASE.json'))
        if meta.get('legacy_accounting_v1') is not True:
            raise SystemExit('该包不含旧队列保护；取消安装，保留现有程序和 journal')
    subprocess.run([sys.executable,helper,archive,matches[0],version],check=True)
    sys.path.insert(0, '/usr/local/V2bX')
    from upgrade import load_config
    from pathlib import Path
    if not load_config(Path('/etc/V2bX/config.json'))['Nodes']:
        try: tty=open('/dev/tty','r')
        except OSError:
            print('无交互终端；请运行 python3 /usr/local/V2bX/initconfig.py --start 完成配置')
        else:
            with tty:
                subprocess.run([sys.executable,'/usr/local/V2bX/initconfig.py','--start'],stdin=tty,check=True)
PY
