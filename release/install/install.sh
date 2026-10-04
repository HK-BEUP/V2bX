#!/usr/bin/env bash
# Bootstrap only: execute the installer from the same checksum-verified package.
set -euo pipefail
[[ ${EUID} == 0 ]] || { printf '\033[0;31m错误：\033[0m 必须使用root用户运行此脚本！\n'; exit 1; }
command -v python3 >/dev/null || { echo '需要先安装 Python 3（含标准库 SSL）'; exit 1; }
exec python3 -u - "${1:-latest}" <<'PY'
import hashlib, json, os, platform, re, shutil, stat, subprocess, sys, tempfile, urllib.request, zipfile
from contextlib import contextmanager
import threading, time, urllib.error

@contextmanager
def progress(label, detail=lambda: ''):
    done = threading.Event()
    started = time.monotonic()
    def announce():
        while not done.wait(5):
            text = detail()
            print('  '+label+'：'+(text+'；' if text else '')+'已等待 '+str(int(time.monotonic()-started))+' 秒', flush=True)
    worker = threading.Thread(target=announce, daemon=True)
    worker.start()
    try:
        yield
    finally:
        done.set()
        worker.join()

def fetch(url, limit):
    name = url.rsplit('/', 1)[-1]
    downloaded = 0
    total = 0
    def detail():
        amount = f'{downloaded / 1048576:.1f} MiB'
        if not total:
            return '已接收 '+amount
        percent = min(100, int(downloaded*100/total))
        width = percent//5
        return str(percent)+'% ['+'='*width+' '*(20-width)+'] '+amount+f' / {total / 1048576:.1f} MiB'
    print('  正在下载 '+name+'…', flush=True)
    with progress('下载 '+name, detail):
        with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'HK-BEUP-installer'}), timeout=45) as r:
            if not r.geturl().startswith('https://'): raise ValueError('HTTPS required')
            length = r.headers.get('Content-Length', '')
            total = int(length) if length.isdigit() else 0
            if total > limit: raise ValueError('download too large')
            data = bytearray()
            read = getattr(r, 'read1', r.read)
            while True:
                chunk = read(min(262144, limit+1-len(data)))
                if not chunk: break
                data.extend(chunk)
                downloaded = len(data)
                if downloaded > limit: raise ValueError('download too large')
    print('  '+name+' 100% [====================] '+str(len(data))+' 字节，下载完成', flush=True)
    return bytes(data)


def say(text, color='green'):
    code = {'green':'32', 'yellow':'33', 'red':'31'}[color]
    print(('\033[0;'+code+'m'+text+'\033[0m') if sys.stdout.isatty() else text, flush=True)

def service_flag(kind):
    try:
        return subprocess.run(['systemctl',kind,'--quiet','V2bX'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return None

def finish_message(version, was_active):
    enabled = service_flag('is-enabled')
    suffix = '，已设置开机自启' if enabled else '，开机启动设置保持不变'
    say('V2bX '+version+' 安装完成'+suffix)
    active = service_flag('is-active')
    if active:
        say('V2bX 重启成功' if was_active else 'V2bX 启动成功')
    elif active is False:
        say('V2bX 当前未启动；配置完成后使用 V2bX start 启动', 'yellow')
    else:
        say('暂未确认 V2bX 运行状态，请使用 V2bX status 核对', 'yellow')

USAGE = """
V2bX 管理脚本使用方法 (兼容使用V2bX执行，大小写不敏感):
------------------------------------------
V2bX              - 显示管理菜单 (功能更多)
V2bX start        - 启动 V2bX
V2bX stop         - 停止 V2bX
V2bX restart      - 重启 V2bX
V2bX status       - 查看 V2bX 状态
V2bX enable       - 设置 V2bX 开机自启
V2bX disable      - 取消 V2bX 开机自启
V2bX log          - 查看 V2bX 日志
V2bX x25519       - 生成 x25519 密钥
V2bX generate     - 生成 V2bX 配置文件
V2bX update       - 更新 V2bX
V2bX update x.x.x - 更新 V2bX 指定版本
V2bX install      - 安装 V2bX
V2bX uninstall    - 卸载 V2bX
V2bX version      - 查看 V2bX 版本
------------------------------------------
"""

def main():
    version = sys.argv[1]
    if platform.system() != 'Linux' or not os.path.isdir('/run/systemd/system'):
        raise SystemExit('仅支持 Linux/systemd；尚未修改系统')
    arch = {'x86_64':'64', 'aarch64':'arm64-v8a'}.get(platform.machine())
    if not arch: raise SystemExit('不支持此 CPU 架构；尚未修改系统')
    print('架构: '+arch, flush=True)
    latest = version == 'latest'
    if latest:
        version = json.loads(fetch('https://api.github.com/repos/HK-BEUP/V2bX/releases/latest', 1048576))['tag_name']
    if not re.fullmatch(r'v[0-9][A-Za-z0-9._-]{0,99}', version): raise SystemExit('版本格式无效')
    print(('检测到 V2bX 最新版本：'+version+'，开始安装') if latest else ('开始安装 V2bX '+version), flush=True)
    name = 'V2bX-linux-'+arch+'.zip'
    base = 'https://github.com/HK-BEUP/V2bX/releases/download/'+version+'/'
    sums = fetch(base+'SHA256SUMS', 65536).decode('ascii')
    matches = re.findall(r'^([0-9a-f]{64})  '+re.escape(name)+r'$', sums, re.M)
    if len(matches)!=1: raise SystemExit('缺少唯一 SHA256SUMS 校验项；保持原版本')
    payload = fetch(base+name, 134217728)
    print('正在校验 V2bX 安装包…', flush=True)
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
        was_active = service_flag('is-active')
        print('正在安装 V2bX，已有配置将保留…', flush=True)
        if was_active:
            say('正在等待原 V2bX 结清最后流量并退出，请勿关闭终端…', 'yellow')
        with progress('安装仍在进行，可能正在等待旧节点退出或服务检查；请勿关闭终端'):
            subprocess.run([sys.executable,'-u',helper,archive,matches[0],version],check=True)
        sys.path.insert(0, '/usr/local/V2bX')
        from upgrade import load_config
        from pathlib import Path
        first_install = not load_config(Path('/etc/V2bX/config.json'))['Nodes']
        if first_install:
            print('全新安装，请先配置必要的内容。', flush=True)
            try: tty=open('/dev/tty','r')
            except OSError:
                print('无交互终端；请运行 python3 /usr/local/V2bX/initconfig.py --start 完成配置')
            else:
                with tty:
                    print('检测到你为第一次安装V2bX,是否自动直接生成配置文件？(y/n): ', end='', flush=True)
                    if tty.readline().strip().lower() == 'y':
                        subprocess.run([sys.executable,'-u','/usr/local/V2bX/initconfig.py','--start'],stdin=tty,check=True)
                    else:
                        print('已跳过配置，请使用 V2bX generate 生成配置文件。', flush=True)
        finish_message(version, was_active)
        print(USAGE, flush=True)

if __name__ == '__main__':
    try:
        main()
    except (urllib.error.URLError, TimeoutError) as e:
        say('下载 V2bX 失败，请确保你的服务器能够下载 Github 的文件', 'red')
        print('原因：'+str(e)+'。尚未启动安装。', file=sys.stderr, flush=True)
        raise SystemExit(1)
    except subprocess.CalledProcessError as e:
        print('安装流程未完成（退出码 '+str(e.returncode)+'），请查看上方错误并核对服务状态，勿重复安装。', file=sys.stderr, flush=True)
        raise SystemExit(1)
PY
