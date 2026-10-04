#!/usr/bin/env python3
"""New installations only. Never overwrite populated node configurations."""
import fcntl
import getpass
import hashlib
import sys
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit
from upgrade import Systemd, digest, load_config, plain_path

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

def main(start=False):
    if os.geteuid()!=0: raise SystemExit('需要 root')
    os.umask(0o077)
    path=Path('/etc/V2bX/config.json');plain_path(path)
    with open('/run/lock/beup-v2bx-upgrade.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if subprocess.run(['systemctl','is-active','--quiet','V2bX']).returncode==0:
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
            service = Systemd(); service.required_ports = set()
            service.start()
            if not service.healthy():
                raise RuntimeError('配置已保留，启动尚未通过监听检查；请核对面板地址、节点参数和连接状态后执行 v2bx status')
            service.call('enable', 'V2bX')
            print('安装及启动完成，已设置开机自启；请在面板确认该节点流量入账。')
        else:
            print('配置已保存。执行 v2bx start 启动、v2bx enable 开机自启。')

if __name__=='__main__':
    try:
        if sys.argv[1:] not in ([], ['--start']): raise SystemExit('用法: initconfig.py [--start]')
        main(start=sys.argv[1:] == ['--start'])
    except (ValueError,OSError,RuntimeError,subprocess.SubprocessError): raise SystemExit('初始化失败；请核对输入和文件权限（未输出密钥）')
