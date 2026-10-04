#!/usr/bin/env python3
"""Verified, conservative systemd upgrade. No panel requests or account writes.

The CLI has fixed production paths. Tests inject a private root and fake service
into the transaction function, never via an environment variable or CLI flag.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

MANAGED = ('V2bX','V2bX.sh','install.sh','upgrade.py','initconfig.py','RELEASE.json')
ALLOWED = set(MANAGED) | {'README.md','LICENSE','XRAY_LICENSE','BEUP_OBSERVATION.md','BEUP_LEGACY.md','config.json',
                         'custom_inbound.json','custom_outbound.json','dns.json','route.json','geoip.dat','geosite.dat'}

def digest(path):
    with open(path,'rb') as f:
        h=hashlib.sha256()
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest()

def tree_hash(path):
    """Hash paths/modes/data; do not export content. Reject symlinked configs."""
    if not path.exists(): return {}
    result={}
    for p in [path]+sorted(path.rglob('*')):
        if p.is_symlink(): raise ValueError('配置路径包含符号链接，需要人工核对')
        if p.is_file(): result[str(p.relative_to(path))]=[digest(p),stat.S_IMODE(p.stat().st_mode)]
    return result

def plain_path(path):
    for p in [path]+list(path.parents):
        if p.is_symlink(): raise ValueError('安装路径包含符号链接，需要人工核对')

def load_config(path):
    # Same supported subset as V2bX: JSON with // and /* */ comments. No eval.
    text=path.read_text();out=[];i=0;quoted=False;escaped=False
    while i<len(text):
        ch=text[i]
        if quoted:
            out.append(ch)
            if escaped: escaped=False
            elif ch=='\\': escaped=True
            elif ch=='"': quoted=False
            i+=1;continue
        if ch=='"': quoted=True
        elif text[i:i+2]=='//':
            end=text.find('\n',i);i=len(text) if end<0 else end;continue
        elif text[i:i+2]=='/*':
            end=text.find('*/',i+2)
            if end<0: raise ValueError('配置注释未闭合')
            out.append(' ');i=end+2;continue
        out.append(ch);i+=1
    c=json.loads(''.join(out))
    if not c.get('Cores') or any(x.get('Type')!='xray' for x in c['Cores']):
        raise ValueError('仅允许已有 Xray 配置；不会自动转换其他核心')
    if not isinstance(c.get('Nodes'),list): raise ValueError('缺少 Nodes 列表')
    for n in c['Nodes']:
        if n.get('Include'): raise ValueError('Include 配置需人工核对；不自动跟随外部配置')
        api=n.get('ApiConfig',n); opts=n.get('Options',n)
        if api.get('NodeType')!='vless' or opts.get('Core','xray') not in ('','xray'):
            raise ValueError('仅允许已有 VLESS/Xray 节点')
        if not isinstance(api.get('NodeID'),int) or api['NodeID']<=0 or not api.get('ApiKey'):
            raise ValueError('节点配置缺少必需字段')
    return c

def extract_package(archive,expected,version,machine,dest):
    if not re.fullmatch(r'[0-9a-f]{64}',expected) or digest(archive)!=expected: raise ValueError('安装包 SHA256 不匹配')
    with zipfile.ZipFile(archive) as z:
        entries=z.infolist();names=[i.filename for i in entries]
        if len(set(names))!=len(names) or not (set(MANAGED)|{'config.json'}).issubset(names) or not set(names)<=ALLOWED:
            raise ValueError('安装包成员不符合白名单')
        if sum(i.file_size for i in entries)>268435456: raise ValueError('解压大小超限')
        for i in entries:
            mode=i.external_attr>>16
            if i.is_dir() or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0,stat.S_IFREG)):
                raise ValueError('安装包包含非普通文件')
            target=dest/i.filename
            with z.open(i) as src, open(target,'xb') as dst: shutil.copyfileobj(src,dst)
            target.chmod(0o755 if i.filename in ('V2bX','V2bX.sh','install.sh') else 0o644)
    meta=json.loads((dest/'RELEASE.json').read_text())
    if meta.get('version')!=version or meta.get('cores')!=['xray'] or meta.get('profile')!='VLESS+TCP+REALITY+Vision': raise ValueError('版本或核心声明不符')
    with open(dest/'V2bX','rb') as f: elf=f.read(20)
    if len(elf)!=20 or elf[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(elf[18:20],'little')!={'x86_64':62,'aarch64':183}.get(machine): raise ValueError('ELF 架构不符')
    if meta.get('binary_sha256')!=digest(dest/'V2bX'): raise ValueError('二进制内容不符')
    if load_config(dest/'config.json')['Nodes']: raise ValueError('安装包必须使用无凭据的空 Nodes 示例')

class Systemd:
    @staticmethod
    def listening(pid):
        if pid<=0:return set()
        inodes=set()
        for fd in Path('/proc/'+str(pid)+'/fd').iterdir():
            try:link=os.readlink(fd)
            except FileNotFoundError:continue
            if link.startswith('socket:['):inodes.add(link[8:-1])
        ports=set()
        for family in ('tcp','tcp6'):
            path=Path('/proc/'+str(pid)+'/net/'+family)
            if not path.exists():continue
            for line in path.read_text().splitlines()[1:]:
                fields=line.split()
                if fields[3]=='0A' and fields[9] in inodes:ports.add(family+':'+fields[1])
        return ports
    def call(self,*args,check=True,timeout=90):
        return subprocess.run(['systemctl',*args],check=check,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
    def active(self): return self.call('is-active','--quiet','V2bX',check=False).returncode==0
    def validate(self):
        cmd=self.call('show','V2bX','-p','ExecStart','--value').stdout.strip()
        # Nonstandard commands/config paths require a separate upgrade plan.
        if cmd and not re.search(r'argv\[\]=/usr/local/V2bX/V2bX server\s*;',cmd):
            raise ValueError('自定义 ExecStart 需人工核对；未停止服务')
        if getattr(self,'minimum_stop_seconds',0):
            value=self.call('show','V2bX','-p','TimeoutStopUSec','--value').stdout.strip()
            if value != 'infinity':
                parts=re.findall(r'(\d+(?:\.\d+)?)(us|ms|s|min|h|d)',value)
                factors={'us':0.000001,'ms':0.001,'s':1,'min':60,'h':3600,'d':86400}
                seconds=sum(float(n)*factors[unit] for n,unit in parts)
                if not parts or re.sub(r'(\d+(?:\.\d+)?)(us|ms|s|min|h|d)|\s+', '', value) or seconds < self.minimum_stop_seconds:
                    raise ValueError('已有服务退出超时不足以结清全部节点；未停止服务，请先核对 TimeoutStopSec')
        self.required_ports=set()
        if self.active():
            pid=int(self.call('show','V2bX','-p','MainPID','--value').stdout.strip())
            self.required_ports=self.listening(pid)
            if not self.required_ports:raise ValueError('运行服务没有可核对的 TCP 监听；请先确认节点状态')
    def stop(self):
        self.call('stop','V2bX',timeout=getattr(self,'stop_budget',180)+30)
        result=self.call('show','V2bX','-p','Result','--value').stdout.strip()
        if result in ('timeout','signal','core-dump','watchdog'): raise RuntimeError('服务退出未确认；保留当前程序和流量 journal，请人工检查')
        if self.active(): raise RuntimeError('服务未停止')
    def start(self): self.call('start','V2bX')
    def reload(self): self.call('daemon-reload')
    def healthy(self):
        stable=None;stable_seconds=0
        for _ in range(180):
            time.sleep(1)
            state=self.call('show','V2bX','-p','ActiveState','-p','MainPID','-p','NRestarts','-p','ExecMainStartTimestampMonotonic').stdout
            if 'ActiveState=active' not in state or 'MainPID=0\n' in state: return False
            if stable is None:stable=state
            elif stable!=state:return False
            fields=dict(line.split('=',1) for line in state.splitlines() if '=' in line)
            ports=self.listening(int(fields.get('MainPID','0')))
            if ports and self.required_ports.issubset(ports):
                stable_seconds+=1
                if stable_seconds>=15:return True
            else:stable_seconds=0
        return False

UNIT='''[Unit]
Description=V2bX Service
After=network.target nss-lookup.target
Wants=network.target
[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/usr/local/V2bX/
ExecStart=/usr/local/V2bX/V2bX server
Restart=always
RestartSec=10
# Each accounting scope has a bounded graceful close; never SIGKILL its journal.
TimeoutStopSec=infinity
StandardOutput=null
StandardError=null
LimitNOFILE=999999
[Install]
WantedBy=multi-user.target
'''

def transaction(archive,expected,version,root,service,machine,probe=None):
    root=Path(root);program=root/'usr/local/V2bX';config=root/'etc/V2bX';unit=root/'etc/systemd/system/V2bX.service'
    for p in (program,config,unit,root/'usr/local/.backups',root/'usr/bin/V2bX',root/'usr/bin/v2bx'): plain_path(p.parent)
    for p in (program,config,unit): plain_path(p)
    for p in (root/'usr/bin/V2bX',root/'usr/bin/v2bx'):
        if p.is_symlink() and os.readlink(p) not in ('/usr/bin/V2bX','/usr/local/V2bX/V2bX.sh'): raise ValueError('未知管理命令链接')
    before=tree_hash(config); existed=program.exists();was_active=service.active()
    watched=[program/n for n in MANAGED]+[unit]
    def fingerprints():
        for p in watched: plain_path(p)
        return {str(p.relative_to(root)):digest(p) if p.exists() else None for p in watched}
    original=fingerprints()
    if existed and not (config/'config.json').is_file(): raise ValueError('已有安装缺少配置；需要人工核对')
    if (config/'config.json').exists():
        current_config=load_config(config/'config.json')
        accounting=sum(bool(n.get('Options',n).get('LegacyAccounting') or n.get('Options',n).get('TransferAccounting')) for n in current_config['Nodes'])
        service.stop_budget=max(180,150*accounting+30)
        service.minimum_stop_seconds=service.stop_budget if accounting else 0
    service.validate()
    program.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.beup-stage-',dir=program.parent) as td:
        stage=Path(td);payload=stage/'payload';payload.mkdir()
        extract_package(archive,expected,version,machine,payload)
        if probe: probe(payload/'V2bX',version)
        else:
            r=subprocess.run([str(payload/'V2bX'),'version'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15)
            if r.returncode or version not in r.stdout: raise ValueError('新程序自检失败')
        new=stage/'program'
        if existed: shutil.copytree(program,new,symlinks=True)
        else: new.mkdir()
        for name in MANAGED:
            target=new/name
            if target.is_symlink(): target.unlink()
            shutil.copy2(payload/name,target)
        # Complete all preparation before any service stop.
        backups=program.parent/'.backups'/'V2bX';backups.mkdir(parents=True,exist_ok=True,mode=0o700)
        backup=Path(tempfile.mkdtemp(prefix='upgrade-',dir=backups));backup.chmod(0o700)
        if config.exists(): shutil.copytree(config,backup/'config',symlinks=True)
        if unit.exists(): shutil.copy2(unit,backup/'V2bX.service')
        commands={}
        for name in ('V2bX','v2bx'):
            p=root/'usr/bin'/name
            commands[name]=('link',os.readlink(p)) if p.is_symlink() else ('file',p.read_bytes(),stat.S_IMODE(p.stat().st_mode)) if p.exists() else ('missing',)
            if p.exists() and not p.is_symlink(): shutil.copy2(p,backup/('command-'+name))
        if tree_hash(config)!=before: raise RuntimeError('配置在准备过程中变化；已取消')
        if fingerprints()!=original: raise RuntimeError('程序或服务文件已变化；取消升级')
        record={'version':version,'package_sha256':expected,'was_active':was_active,'config_hashes':before,'original_hashes':original,'status':'prepared'}
        (backup/'transaction.json').write_text(json.dumps(record,indent=2))
        switched=False;moved=False;created_unit=False;created_config=False;stopped=False;commands_changed=False
        try:
            if was_active:
                service.stop();stopped=True
            if tree_hash(config)!=before: raise RuntimeError('配置变化；已取消切换')
            if existed: program.rename(backup/'program');moved=True
            new.rename(program);switched=True
            if not existed and not config.exists():
                config.mkdir(mode=0o700);created_config=True
                shutil.copy2(payload/'config.json',config/'config.json');(config/'config.json').chmod(0o600)
                for name in ('geoip.dat','geosite.dat'):
                    if (payload/name).exists(): shutil.copy2(payload/name,config/name)
            if not existed and not unit.exists():
                unit.parent.mkdir(parents=True,exist_ok=True);unit.write_text(UNIT);created_unit=True;service.reload()
            if was_active:
                service.start()
                if not service.healthy(): raise RuntimeError('新服务未通过稳定启动检查')
            commands_changed=True
            for name in ('V2bX','v2bx'):
                p=root/'usr/bin'/name;p.parent.mkdir(parents=True,exist_ok=True)
                temp=p.parent/('.beup-'+name+'-'+backup.name)
                temp.symlink_to('/usr/local/V2bX/V2bX.sh');os.replace(temp,p)
            record['status']='installed';(backup/'transaction.json').write_text(json.dumps(record,indent=2))
        except BaseException:
            # Never overwrite operator config changes: the upgrade did not edit existing config.
            if switched and was_active: service.stop()
            if switched: program.rename(backup/'failed-program')
            if moved: (backup/'program').rename(program)
            if created_unit: unit.unlink();service.reload()
            if created_config: config.rename(backup/'new-config')
            if commands_changed:
                for name,old in commands.items():
                    p=root/'usr/bin'/name
                    if p.exists() or p.is_symlink(): p.unlink()
                    if old[0]=='link': p.symlink_to(old[1])
                    elif old[0]=='file': p.write_bytes(old[1]);p.chmod(old[2])
            if stopped:
                service.start()
                if not service.healthy(): raise RuntimeError('回退后服务仍异常；请立即检查备份目录 '+str(backup))
            record['status']='rolled-back';(backup/'transaction.json').write_text(json.dumps(record,indent=2))
            raise
        return {'backup':str(backup),'previously_active':was_active,'config_unchanged':not created_config}

def main():
    if os.geteuid()!=0 or platform.system()!='Linux' or not Path('/run/systemd/system').is_dir(): raise SystemExit('需要 Linux/systemd root')
    if len(sys.argv)!=4: raise SystemExit('用法: upgrade.py ZIP SHA256 VERSION')
    os.umask(0o077)
    signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    # Kernel lock shared with config wizard. Released even on abnormal process exit.
    with open('/run/lock/beup-v2bx-upgrade.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        result=transaction(Path(sys.argv[1]),sys.argv[2],sys.argv[3],Path('/'),Systemd(),platform.machine())
    print('安装完成；备份：'+result['backup'])
    if result['previously_active']: print('已恢复原 TCP 监听并通过 15 秒进程稳定检查；仍需客户端业务验收')
    else: print('程序已安装，配置与启动由新装向导继续；已有节点保留原停止状态')

if __name__=='__main__':
    try: main()
    except (Exception,KeyboardInterrupt) as e:
        # Do not print exception details from config parsers/subprocesses: may contain secrets.
        print('安装未完成：'+(str(e) if isinstance(e,(ValueError,RuntimeError)) else type(e).__name__),file=sys.stderr)
        sys.exit(1)
