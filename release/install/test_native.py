"""Only runs inside the disposable local Alpine container; no external panels."""
import json,os,platform,subprocess,time,zipfile,hashlib
from pathlib import Path
import upgrade as u
import initconfig
assert os.environ.get('BEUP_OPENRC_NATIVE_QA')=='1' and Path('/.dockerenv').exists() and Path('/qa/native_fixture.c').exists()
assert not Path('/etc/V2bX').exists() and not Path('/usr/local/V2bX').exists()
VERSION='v25.12.2-beup-alpine-qa'
for i in (1,2):subprocess.run(['gcc','-DBUILD='+str(i),'/qa/native_fixture.c','-o','/qa/fixture'+str(i)],check=True)
net=Path('/etc/init.d/net');net.write_text('#!/sbin/openrc-run\nstart() { return 0; }\nstop() { return 0; }\n');net.chmod(0o755)
subprocess.run(['rc-service','net','start'],check=True)
def pack(i):
 binary=Path('/qa/fixture'+str(i)).read_bytes()
 meta={'version':VERSION,'cores':['xray'],'profile':'VLESS+TCP+REALITY+Vision','binary_sha256':hashlib.sha256(binary).hexdigest(),'legacy_accounting_v1':True,'service_managers':['systemd','openrc']}
 files={n:(Path('/qa')/n).read_bytes() for n in u.MANAGED if n not in ('V2bX','RELEASE.json')}
 files.update({'V2bX':binary,'RELEASE.json':json.dumps(meta).encode(),'config.json':b'{"Cores":[{"Type":"xray"}],"Nodes":[]}'})
 p=Path('/qa/package'+str(i)+'.zip')
 with zipfile.ZipFile(p,'w') as z:
  for n,b in files.items():z.writestr(n,b)
 return p,u.digest(p)
p1,h1=pack(1);p2,h2=pack(2)
service=u.service_manager();assert isinstance(service,u.OpenRC)
fresh=u.transaction(p1,h1,VERSION,Path('/'),service,platform.machine())
unit=Path('/etc/init.d/V2bX');config=Path('/etc/V2bX/config.json')
assert unit.read_text()==u.OPENRC_UNIT and unit.stat().st_mode & 0o111
assert not service.active()
service.start();service.required_ports=set();assert service.healthy()
before=service.identity();assert before
assert os.readlink('/proc/'+str(before[0])+'/fd/1')=='/dev/null'
assert os.readlink('/proc/'+str(before[0])+'/fd/2')=='/dev/null'
service.enable();assert Path('/etc/runlevels/default/V2bX').is_symlink()
print('PASS fresh OpenRC install/start/ports/logs/enabled',flush=True)
# Upgrade a standard upstream init script, exercising a >5 second graceful close.
unit.write_text(u.OPENRC_ORIGINAL)
config.write_text(json.dumps({'Cores':[{'Type':'xray'}],'Nodes':[{'NodeType':'vless','ApiKey':'synthetic-only','NodeID':42,'LegacyAccounting':{'Directory':'/qa/journal'}}]}))
sha_config=u.digest(config);started=time.monotonic()
changed=u.transaction(p2,h2,VERSION,Path('/'),u.OpenRC(),platform.machine())
elapsed=time.monotonic()-started
assert elapsed>=7 and u.digest(config)==sha_config and service.active()
assert u.digest('/usr/local/V2bX/V2bX')==u.digest('/qa/fixture2')
assert unit.read_text()==u.OPENRC_UNIT
assert (Path(changed['backup'])/'V2bX.service').read_text()==u.OPENRC_ORIGINAL
print('PASS running upstream upgrade retained config; graceful close exceeded 5 seconds; new ports stable',round(elapsed,2),flush=True)
# Force failed acceptance, then prove old program/unit/config actually resume.
class FailFirst(u.OpenRC):
 failed=False
 def healthy(self):
  if not self.failed:self.failed=True;return False
  return super().healthy()
unit.write_text(u.OPENRC_ORIGINAL)
try:u.transaction(p1,h1,VERSION,Path('/'),FailFirst(),platform.machine())
except RuntimeError as e:assert '稳定启动' in str(e)
else:raise AssertionError('failure injection was ignored')
assert u.digest('/usr/local/V2bX/V2bX')==u.digest('/qa/fixture2') and service.active()
assert unit.read_text()==u.OPENRC_ORIGINAL and u.digest(config)==sha_config
print('PASS failed upgrade restored old binary/init/config and healthy listener',flush=True)
# Exercise menu-15's transaction using the real OpenRC adapter and a local-only fixture.
# This fixture proves lifecycle/backup behavior, not panel auth or proxy accounting.
config.write_text(json.dumps(initconfig.make_config('https://panel.example','synthetic-only','42')))
prior=config.read_bytes();prior_identity=service.identity()
answers=iter(['','43','YES'])
manual=initconfig.reconfigure(Path('/'),u.OpenRC(),lambda _:next(answers),lambda _: '')
assert service.active() and service.identity()!=prior_identity
assert (Path(manual['backup'])/'etc/V2bX/config.json').read_bytes()==prior
assert u.load_config(config)['Nodes'][0]['NodeID']==43
print('PASS OpenRC manual reconfiguration and private backup',flush=True)
prior=config.read_bytes();answers=iter(['','44','YES'])
try:initconfig.reconfigure(Path('/'),FailFirst(),lambda _:next(answers),lambda _: '')
except RuntimeError as e:assert '原运行状态已恢复' in str(e)
else:raise AssertionError('manual reconfiguration failure injection was ignored')
assert config.read_bytes()==prior and service.active()
print('PASS OpenRC failed reconfiguration restored original config and listener',flush=True)
service.stop()
assert not service.active() and not service.identity()
answers=iter(['','44','YES'])
initconfig.reconfigure(Path('/'),u.OpenRC(),lambda _:next(answers),lambda _: '')
assert not service.active() and not service.identity()
assert u.load_config(config)['Nodes'][0]['NodeID']==44
print(json.dumps({'native_openrc':'pass','fresh_install':True,'upgrade':True,'rollback':True,'logs_off':True,'graceful_wait_seconds':round(elapsed,2),'final_stopped':True}),flush=True)
