#!/usr/bin/env python3
"""Reproducible ZIP packaging; never installs, pushes or publishes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

def sha(b):return hashlib.sha256(b).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--scripts',type=Path,required=True)
    p.add_argument('--version',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not re.fullmatch(r'v[0-9][A-Za-z0-9._-]{0,99}',a.version):p.error('invalid version')
    a.source=a.source.resolve();a.scripts=a.scripts.resolve();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False)
    # Fail closed if the telemetry overlay or real profile acceptance test is missing.
    for name in ['common/beupobserve/observer.go','core/xray/reality_vision_test.go','BEUP_OBSERVATION.md']:
        if not (a.source/name).is_file():raise ValueError('missing observation source/test: '+name)
    results=[];sums=[]
    for arch,friendly,machine in [('amd64','64',62),('arm64','arm64-v8a',183)]:
        with tempfile.TemporaryDirectory(prefix='beup-build-') as td:
            binary=Path(td)/'V2bX'
            env=dict(os.environ,GOTOOLCHAIN='local',GOEXPERIMENT='jsonv2',CGO_ENABLED='0',GOOS='linux',GOARCH=arch)
            subprocess.run(['go','build','-p','2','-mod=readonly','-tags','xray','-trimpath','-ldflags','-X github.com/InazumaV/V2bX/cmd.version='+a.version+' -s -w -buildid=','-o',str(binary),'.'],cwd=a.source,env=env,check=True)
            data=binary.read_bytes()
            if data[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(data[18:20],'little')!=machine:raise ValueError('bad binary architecture')
            meta=subprocess.check_output(['go','version','-m',str(binary)],text=True)
            for marker in ['-tags=xray','GOOS=linux','GOARCH='+arch,'CGO_ENABLED=0']:
                if marker not in meta:raise ValueError('bad build metadata')
            files={'V2bX':data}
            for name in ['V2bX.sh','install.sh','upgrade.py','initconfig.py']:files[name]=(a.scripts/name).read_bytes()
            for name in ['README.md','LICENSE','BEUP_OBSERVATION.md']:files[name]=(a.source/name).read_bytes()
            for name in ['geoip.dat','geosite.dat']:files[name]=(a.source/'example'/name).read_bytes()
            files['config.json']=json.dumps({'Log':{'Level':'info','Output':''},'Cores':[{'Type':'xray','Log':{'Level':'error'},'AssetPath':'/etc/V2bX/'}],'Nodes':[]},indent=2).encode()+b'\n'
            files['RELEASE.json']=json.dumps({'version':a.version,'cores':['xray'],'profile':'VLESS+TCP+REALITY+Vision','binary_sha256':sha(data),'observation_enabled_by_default':False,'acceptance':'local candidate; production pilot required'},indent=2).encode()+b'\n'
            name='V2bX-linux-'+friendly+'.zip';target=a.output/name
            with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
                for n,b in sorted(files.items()):
                    i=zipfile.ZipInfo(n,date_time=(2026,1,1,0,0,0));i.compress_type=zipfile.ZIP_DEFLATED;i.create_system=3
                    i.external_attr=(0o100755 if n in ['V2bX','V2bX.sh','install.sh'] else 0o100644)<<16
                    z.writestr(i,b)
            with zipfile.ZipFile(target) as z:
                if z.testzip() is not None:raise ValueError('ZIP CRC failed')
                for n,b in files.items():
                    if sha(z.read(n))!=sha(b):raise ValueError('ZIP content mismatch')
            checksum=sha(target.read_bytes());sums.append(checksum+'  '+name)
            results.append({'name':name,'sha256':checksum,'binary_sha256':sha(data),'entries':{n:sha(b) for n,b in sorted(files.items())}})
    (a.output/'SHA256SUMS').write_text('\n'.join(sums)+'\n')
    (a.output/'package-verification.json').write_text(json.dumps({'version':a.version,'artifacts':results},indent=2)+'\n')
    print(json.dumps({'version':a.version,'artifacts':[{'name':x['name'],'sha256':x['sha256']} for x in results]}))

if __name__=='__main__':main()
