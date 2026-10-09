"""Real disposable local processes/listeners; synthetic config, no production services."""
import contextlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import initconfig
import upgrade

FIXTURE = r'''
import json,signal,socket,sys,time
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text())
if config['Nodes'][0]['ApiKey'] == 'reject-fixture': sys.exit(23)
port = config['Nodes'][0]['NodeID']
listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
listener.bind(('127.0.0.1',port)); listener.listen(); listener.settimeout(.1)
stopping = False
def stop(*_):
    global stopping
    stopping = True
signal.signal(signal.SIGTERM,stop)
while not stopping:
    try:
        conn,_ = listener.accept(); conn.sendall(b'fixture-ok'); conn.close()
    except socket.timeout: pass
time.sleep(.2)
Path(sys.argv[2]).write_text('graceful-exit-completed')
listener.close()
'''

class LocalProcess:
    unit_path = 'etc/fixture.unit'
    def __init__(self, root, script):
        self.root = root; self.script = script; self.process = None; self.required_ports = set()
    def active(self): return self.process is not None and self.process.poll() is None
    def validate(self):
        self.required_ports = {n['NodeID'] for n in upgrade.load_config(self.root/'etc/V2bX/config.json')['Nodes']}
    def start(self):
        self.process = subprocess.Popen([sys.executable,str(self.script),str(self.root/'etc/V2bX/config.json'),str(self.root/'closed')], stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    def stop(self):
        if self.active(): self.process.terminate()
        if self.process:
            self.process.wait(timeout=5)
            self.process.stderr.close()
    def healthy(self):
        expected = self.required_ports or {n['NodeID'] for n in upgrade.load_config(self.root/'etc/V2bX/config.json')['Nodes']}
        for _ in range(30):
            if not self.active(): return False
            try:
                for port in expected:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1) as c:
                        if c.recv(10) != b'fixture-ok': return False
                return True
            except OSError: time.sleep(.03)
        return False

class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        # Reserve two distinct local ports while choosing IDs; release before starting fixture.
        with socket.socket() as a, socket.socket() as b:
            a.bind(('127.0.0.1',0)); b.bind(('127.0.0.1',0))
            self.old_port = a.getsockname()[1]; self.new_port = b.getsockname()[1]
        self.path = self.root/'etc/V2bX/config.json'; self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps(initconfig.make_config('https://panel.example','synthetic-key',str(self.old_port))))
        self.original = self.path.read_bytes()
        self.script = self.root/'fixture.py'; self.script.write_text(FIXTURE)
        self.service = LocalProcess(self.root,self.script); self.addCleanup(self.service.stop)
        self.service.start(); self.assertTrue(self.service.healthy())
        self.pid = self.service.process.pid
    def configure(self, key='', answer='YES'):
        replies = iter(['',str(self.new_port),answer])
        with contextlib.redirect_stdout(io.StringIO()):
            return initconfig.reconfigure(self.root,self.service,lambda _:next(replies),lambda _:key)
    def test_real_process_graceful_replacement_and_new_listener(self):
        result = self.configure()
        self.assertTrue(result['restarted'])
        self.assertNotEqual(self.pid,self.service.process.pid)
        self.assertTrue(self.service.healthy())
        self.assertEqual((self.root/'closed').read_text(),'graceful-exit-completed')
        self.assertEqual((Path(result['backup'])/'etc/V2bX/config.json').read_bytes(),self.original)
        with self.assertRaises(OSError): socket.create_connection(('127.0.0.1',self.old_port),timeout=.1)
    def test_real_failed_process_rolls_back_to_old_listener(self):
        with self.assertRaisesRegex(RuntimeError,'原运行状态已恢复'): self.configure('reject-fixture')
        self.assertEqual(self.path.read_bytes(),self.original)
        self.assertTrue(self.service.healthy())
        self.assertNotEqual(self.pid,self.service.process.pid)
    def test_cancel_leaves_same_live_pid_and_listener(self):
        self.assertEqual(self.configure(answer='no')['status'],'cancelled')
        self.assertEqual(self.pid,self.service.process.pid)
        self.assertTrue(self.service.healthy())
        self.assertEqual(self.path.read_bytes(),self.original)

if __name__ == '__main__': unittest.main(verbosity=2)
