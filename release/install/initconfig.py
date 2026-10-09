#!/usr/bin/env python3
"""Conservative installation init; explicit manual reconfiguration via menu 15."""
import copy
import fcntl
import getpass
import hashlib
import sys
import json
import os
import signal
import stat
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit
from upgrade import service_manager, digest, load_config, plain_path, tree_hash

def make_config(host,key,node_ids):
    u=urlsplit(host)
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
        raise ValueError('面板地址必须为 HTTPS，只填域名与可选端口，不含路径或参数')
    if any(c.isspace() for c in u.netloc): raise ValueError('面板域名不能包含空格')
    u.port  # Reject invalid ports before saving.
    if not key or any(ord(c)<32 for c in key): raise ValueError('API Key 无效')
    ids=[int(n.strip()) for n in node_ids.split(',')]
    if not ids or len(set(ids))!=len(ids) or any(i<=0 for i in ids): raise ValueError('NodeID 必须为不重复正整数')
    origin = 'https://' + u.netloc.lower()
    scope = hashlib.sha256(origin.encode()).hexdigest()[:16]
    return {'Log':{'Level':'error','Output':'/dev/null'},'Cores':[{'Type':'xray','Log':{'Level':'none','AccessPath':'/dev/null','ErrorPath':'/dev/null'},'AssetPath':'/etc/V2bX/'}],
            'Nodes':[{'Core':'xray','ApiHost':origin,'ApiKey':key,'NodeID':n,'NodeType':'vless','Timeout':30,
                      'LegacyAccounting':{'Directory':f'/var/lib/beup-legacy/{scope}/vless-{n}'},
                      'ListenIP':'0.0.0.0','SendIP':'0.0.0.0','CertConfig':{'CertMode':'none'}} for n in ids]}

def node_api(node):
    return node.get('ApiConfig', node)

def node_origin(node):
    api = node_api(node)
    return make_config(api['ApiHost'], api['ApiKey'], str(api['NodeID']))['Nodes'][0]['ApiHost']

def replacement_config(current, host, key, ids):
    """Retain globals and matching nodes; only new identities use new-install defaults."""
    fresh = make_config(host, key, ids)
    previous = {}
    for node in current['Nodes']:
        identity = (node_origin(node), node_api(node)['NodeID'])
        if identity in previous:
            raise ValueError('Duplicate node identity')
        previous[identity] = node
    result = copy.deepcopy(current)
    result['Nodes'] = []
    for node in fresh['Nodes']:
        identity = (node['ApiHost'], node['NodeID'])
        if identity in previous:
            retained = copy.deepcopy(previous[identity])
            node_api(retained).update(ApiHost=node['ApiHost'], ApiKey=key)
            result['Nodes'].append(retained)
        else:
            # Do not silently switch an existing transfer-queue installation's mode.
            if any(n.get('Options', n).get('TransferAccounting') for n in current['Nodes']):
                raise ValueError('TransferAccounting node replacement needs a separate configuration plan')
            result['Nodes'].append(node)
    return result

def atomic_config(path, data, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix='.config-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as target:
            os.fchmod(target.fileno(), mode)
            target.write(data); target.flush(); os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

def reconfigure(root, service, read=None, secret=None):
    """Tests inject a private root/service. The CLI always uses / and the real manager."""
    read = read or input
    secret = secret or getpass.getpass
    root = Path(root)
    path = root/'etc/V2bX/config.json'
    backup_root = root/'etc/.backups/V2bX'
    for p in (path, backup_root): plain_path(p)
    baseline = tree_hash(path.parent)
    current = load_config(path) if path.exists() else dict(make_config('https://example.invalid', 'unused', '1'), Nodes=[])
    original = path.read_bytes() if path.exists() else None
    original_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    watched = [root/'usr/local/V2bX/V2bX', root/service.unit_path]
    watched += [root/p for p in getattr(service, 'watch_paths', ())]
    def program_hashes():
        result = {}
        for p in watched:
            plain_path(p)
            result[str(p.relative_to(root))] = (digest(p), stat.S_IMODE(p.stat().st_mode)) if p.exists() else None
        return result
    program_before = program_hashes()
    was_active = service.active()
    if was_active and not current['Nodes']:
        raise RuntimeError('运行中的服务没有可重新配置的节点；未修改配置')
    old_identities = {(node_origin(n), node_api(n)['NodeID']) for n in current['Nodes']}
    hosts = {h for h, _ in old_identities}
    default_host = next(iter(hosts)) if len(hosts) == 1 else ''
    default_ids = ','.join(str(node_api(n)['NodeID']) for n in current['Nodes']) if default_host else ''
    print('手动重新配置：VLESS/Xray。保留全局设置和同面板同编号节点的选项；新增节点使用旧队列默认配置。')
    print('未列出的旧节点将从本机配置中移除；证书、DNS/路由文件和流量 journal 不删除。')
    host = read('HTTPS 面板地址' + (' [回车保留当前面板]' if default_host else '') + '：').strip() or default_host
    # Validate/normalize the origin before considering reuse of an existing secret.
    origin = make_config(host, 'unused', '1')['Nodes'][0]['ApiHost']
    keys = {node_api(n)['ApiKey'] for n in current['Nodes'] if node_origin(n) == origin}
    reusable = next(iter(keys)) if len(keys) == 1 else None
    key = secret('API Key（不回显' + ('，回车保留当前密钥' if reusable else '') + '）：') or reusable
    ids = read('NodeID（多个用逗号分隔' + ('，回车保留当前编号' if default_ids else '') + '）：').strip() or default_ids
    candidate = replacement_config(current, host, key, ids)
    if candidate == current:
        print('配置没有变化；未保存、未停止或重启服务。')
        return {'status': 'unchanged'}
    data = (json.dumps(candidate, ensure_ascii=False, indent=2) + '\n').encode()
    identities = {(node_origin(n), node_api(n)['NodeID']) for n in candidate['Nodes']}
    print('节点：保留 %d / 新增 %d / 移除 %d。API Key 不显示。' %
          (len(identities & old_identities), len(identities - old_identities), len(old_identities - identities)))
    # Both a failed candidate and the original may need a graceful accounting close.
    count = max(sum(bool(n.get('Options', n).get('LegacyAccounting') or n.get('Options', n).get('TransferAccounting')) for n in c['Nodes']) for c in (current, candidate))
    service.stop_budget = max(180, 150 * count + 30)
    service.minimum_stop_seconds = service.stop_budget if count and was_active else 0
    service.validate()
    original_ports = service.required_ports.copy()
    action = '备份并重新配置：会短暂中断本机全部节点，等待流量结清后重启；失败尝试回退' if was_active else '备份并保存新配置，保持停止状态（不会自动启动）'
    if read(action + '。确认输入 YES，其他输入取消：') != 'YES':
        print('已取消，配置和服务保持不变。')
        return {'status': 'cancelled'}
    def check(expected):
        plain_path(path)
        if tree_hash(path.parent) != expected or program_hashes() != program_before:
            raise RuntimeError('配置、程序或服务文件已变化；保留现场，未覆盖其他修改')
    check(baseline)
    if service.active() != was_active:
        raise RuntimeError('服务状态已变化；取消重新配置')
    backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = Path(tempfile.mkdtemp(prefix='reconfigure-', dir=backup_root)); backup.chmod(0o700)
    saved = backup/'etc/V2bX/config.json'
    saved.parent.mkdir(parents=True, mode=0o700)
    if original is not None:
        saved.write_bytes(original); saved.chmod(0o600)
        (backup/'SHA256SUMS').write_text(hashlib.sha256(original).hexdigest() + '  etc/V2bX/config.json\n')
    staged = backup/'candidate.json'; staged.write_bytes(data); staged.chmod(0o600)
    load_config(staged)  # Parse the exact candidate before any interruption.
    record = {'status': 'prepared', 'was_active': was_active, 'original_mode': original_mode,
              'original_sha256': hashlib.sha256(original).hexdigest() if original is not None else None,
              'candidate_sha256': hashlib.sha256(data).hexdigest()}
    def receipt(status):
        record['status'] = status
        (backup/'transaction.json').write_text(json.dumps(record, indent=2) + '\n')
    receipt('prepared')
    print('配置备份：' + str(backup))
    stopped = switched = stop_attempted = False
    applied = dict(baseline); applied['config.json'] = [record['candidate_sha256'], 0o600]
    try:
        check(baseline)
        if service.active() != was_active: raise RuntimeError('服务状态已变化；取消应用')
        if was_active:
            stop_attempted = True
            service.stop(); stopped = True
        check(baseline)
        if service.active(): raise RuntimeError('服务尚未确认停止；未应用新配置')
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_config(path, data); switched = True
        if was_active:
            # Node IDs may change ports: old listeners are required only on rollback.
            service.required_ports = set()
            service.start()
            if not service.healthy(): raise RuntimeError('新配置未通过稳定启动及监听检查')
        check(applied)
        receipt('applied')
    except BaseException as error:
        try:
            check(applied if switched else baseline)
            if stop_attempted and not stopped:
                raise RuntimeError('原进程退出未确认；不强行启动或修改配置')
            if switched:
                if was_active: service.stop()
                check(applied)
                if service.active(): raise RuntimeError('未确认进程退出，保留现场')
                if original is None: path.unlink()
                else: atomic_config(path, original, original_mode)
            if stopped:
                service.required_ports = original_ports
                service.start()
                if not service.healthy(): raise RuntimeError('原服务未恢复稳定监听')
            receipt('rolled-back' if switched else 'cancelled')
        except BaseException:
            receipt('manual-recovery-required')
            raise RuntimeError('自动回退未完成；保留现场，请检查备份：' + str(backup)) from None
        raise RuntimeError('重新配置未完成；配置已恢复，原运行状态已恢复' if stopped else
                           '重新配置未完成；未启动服务，原配置已保留') from error
    print('重新配置完成；进程和 TCP 监听稳定，仍需客户端及面板验证。' if was_active else
          '配置已保存；保持停止状态，可使用 v2bx start 启动。')
    return {'status': 'applied', 'backup': str(backup), 'restarted': was_active}

def main(start=False, manual=False):
    if os.geteuid()!=0: raise SystemExit('需要 root')
    os.umask(0o077)
    path=Path('/etc/V2bX/config.json');plain_path(path)
    service=service_manager()
    Path('/run/lock').mkdir(parents=True,exist_ok=True)
    with open('/run/lock/beup-v2bx-upgrade.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if manual:
            if not sys.stdin.isatty(): raise SystemExit('重新配置需要交互终端；未修改配置或服务')
            return reconfigure(Path('/'), service)
        if service.active():
            raise SystemExit('服务运行中；初始化不会修改正在使用的配置')
        baseline=digest(path) if path.exists() else None
        if path.exists() and load_config(path)['Nodes']: raise SystemExit('已有节点配置，拒绝重写；升级无需重新配置')
        print('新装：VLESS + TCP + REALITY + Vision，旧 Redis/Horizon 可靠上报，节点日志关闭。')
        c=make_config(input('HTTPS 面板地址：').strip(),getpass.getpass('API Key（不回显）：'),input('NodeID（多个用逗号分隔）：'))
        action = '保存配置并启动、设置开机自启' if start else '保存配置（暂不启动）'
        if input(action+'？输入 YES：')!='YES': return
        if (digest(path) if path.exists() else None)!=baseline: raise SystemExit('配置已变化，取消保存')
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        if path.exists():
            backup=Path(tempfile.mkdtemp(prefix='init-',dir=path.parent));backup.chmod(0o700)
            (backup/'config.json').write_bytes(path.read_bytes())
            (backup/'SHA256SUMS').write_text(baseline+'  config.json\n')
        fd,tmp=tempfile.mkstemp(prefix='.config-',dir=path.parent)
        with os.fdopen(fd,'w') as f: json.dump(c,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        if start:
            service.required_ports = set()
            service.start()
            if not service.healthy():
                raise RuntimeError('配置已保留，启动尚未通过监听检查；请核对面板地址、节点参数和连接状态后执行 v2bx status')
            service.enable()
            print('安装及启动完成，已设置开机自启；请在面板确认该节点流量入账。')
        else:
            print('配置已保存。执行 v2bx start 启动、v2bx enable 开机自启。')

if __name__=='__main__':
    try:
        if sys.argv[1:] not in ([], ['--start'], ['--reconfigure']): raise SystemExit('用法: initconfig.py [--start | --reconfigure]')
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        main(start=sys.argv[1:] == ['--start'], manual=sys.argv[1:] == ['--reconfigure'])
    except RuntimeError as error: raise SystemExit(str(error))
    except (EOFError, KeyboardInterrupt): raise SystemExit('已取消配置操作。')
    except (ValueError,OSError,subprocess.SubprocessError): raise SystemExit('配置操作失败；请核对输入、配置格式和文件权限（未输出密钥）。如已显示备份目录，请检查该目录的 transaction.json 状态。')
