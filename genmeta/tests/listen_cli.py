#!/usr/bin/env python3
"""Unix CLI acceptance; build genmeta first. Uses only temporary identities."""
import os,pty,select,sqlite3,subprocess,tempfile,time
from pathlib import Path
binary=os.environ.get('GENMETA_TEST_BINARY',str(Path(__file__).resolve().parents[2]/'target/debug/genmeta'))
with tempfile.TemporaryDirectory(prefix='review-cli-') as root:
    profile=Path(root)/'alice.smith'; profile.mkdir()
    env={**os.environ,'DHTTP_HOME':root}
    def run(*args,ok=True):
        p=subprocess.run([binary,*args],env=env,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=15)
        assert (p.returncode==0)==ok,(args,p.returncode,p.stdout,p.stderr)
        return p
    run('listen','--id','alice.smith','internal')
    dbpath=profile/'.volume/sys/setting/.db'
    def kv():
        with sqlite3.connect(dbpath) as db:return db.execute("SELECT value FROM setting WHERE key='listen'").fetchone()
    assert kv()==('internal',)
    run('listen','--id','alice.smith','off',ok=False);assert kv()==('internal',)
    master,slave=pty.openpty()
    p=subprocess.Popen([binary,'listen','--id','alice.smith','off'],env=env,stdin=slave,stdout=slave,stderr=slave)
    os.close(slave);data=b'';limit=time.monotonic()+10
    while b'[y/n]' not in data and time.monotonic()<limit:
        if select.select([master],[],[],1)[0]:data+=os.read(master,4096)
    assert b'[y/n]' in data,data
    os.write(master,b'n\n');assert p.wait(timeout=10)==0;os.close(master);assert kv()==('internal',)
    master,slave=pty.openpty()
    p=subprocess.Popen([binary,'listen','--id','alice.smith','off'],env=env,stdin=slave,stdout=slave,stderr=slave)
    os.close(slave);data=b'';limit=time.monotonic()+10
    while b'[y/n]' not in data and time.monotonic()<limit:
        if select.select([master],[],[],1)[0]:data+=os.read(master,4096)
    assert b'[y/n]' in data,data
    os.write(master,b'y\n');assert p.wait(timeout=10)==0;os.close(master);assert kv() is None
    run('listen','--id','alice.smith','all');assert kv()==('all',)
    with sqlite3.connect(dbpath) as db:db.execute("INSERT INTO proxy_location VALUES('/','http://127.0.0.1:8080')")
    run('listen','--id','alice.smith','off','--yes');assert kv() is None
    with sqlite3.connect(dbpath) as db:assert db.execute('SELECT count(*) FROM proxy_location').fetchone()==(1,)
    run('listen','--id','alice.smith');assert kv() is None
    for mode in ['auto','loopback','list']:
        run('listen','--id','alice.smith',mode,ok=False)
    run('unlisten','--id','alice.smith',ok=False)
    run('forward','--id','alice.smith',ok=False)
    run('mount','--help')
    run('unmount','--help')
    run('unmount','--id','alice.smith','/',ok=False)
    print('CLI verified: isolated KV, interactive cancellation, noninteractive refusal, all/off, mounts preserved, removed aliases.')
