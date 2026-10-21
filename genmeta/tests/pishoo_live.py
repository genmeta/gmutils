#!/usr/bin/env python3
"""Opt-in tests against a running Pishoo. Uses a unique mount/ACL prefix and restores listening.

GENMETA_TEST_BINARY=/path/to/genmeta python3 genmeta/tests/pishoo_live.py \
    --id YOUR_TEST_ID --peer ANOTHER_TEST_ID --output /tmp/pishoo-live.json

No package is published or existing package removed. Store-backed mutations are
attempted only with the currently installed exact version. A store failure is
reported as an external pending check, never counted as a successful installation.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--id', required=True)
parser.add_argument('--peer', required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--allow-store-pending', action='store_true', help='Keep store rollout failures separate from local CLI acceptance')
parser.add_argument('--binary', default=os.environ.get('GENMETA_TEST_BINARY', 'genmeta'))
args = parser.parse_args()
cli = str(Path(args.binary).resolve()) if '/' in args.binary else args.binary
identity = args.id
host = identity if identity.endswith('.dhttp.net') else identity + '.dhttp.net'
peerhost = args.peer if args.peer.endswith('.dhttp.net') else args.peer + '.dhttp.net'
prefix = '/gmutils-qa-' + uuid.uuid4().hex[:12]
results = []
pending_external = []
cleanup_errors = []
env = {**os.environ, 'RUST_LOG': 'error'}

def save():
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'checks': results, 'pending_external': pending_external,
        'cleanup_errors': cleanup_errors, 'prefix': prefix, 'complete': globals().get('complete', False)}, indent=2, ensure_ascii=False) + '\n')

def run(label, argv, ok=True, timeout=35):
    p = subprocess.run([cli, *argv], capture_output=True, text=True, timeout=timeout, env=env,
        stdin=subprocess.DEVNULL)
    record = {'name': label, 'command': argv, 'exit': p.returncode}
    results.append(record)
    record['passed'] = (p.returncode == 0) == ok
    save()
    assert record['passed'], (label, p.returncode, p.stdout[:500], p.stderr[:1000])
    print(label + ': passed', flush=True)
    return p

def curl(label, path, status=200, method='GET', anonymous=False, who=None, data=None, extra=()):
    argv = ['curl', '-sS', '--dns', 'mdns', '--connect-timeout', '3', '-X', method,
        '-w', '\n%{response_code}', *extra]
    argv += ['--anonymous'] if anonymous else ['--id', who or identity]
    if data is not None:
        argv += ['-H', 'Content-Type: application/json', '-d', json.dumps(data)]
    p = run(label, [*argv, 'https://' + host + path], timeout=15)
    body, code = p.stdout.rsplit('\n', 1)
    results[-1]['passed'] = int(code) == status
    assert results[-1]['passed'], (label, code, body[:500])
    results[-1]['status'] = int(code)
    save()
    return body

def forwarded(label, path, expected):
    body = json.loads(curl(label, path))
    assert body['path'] == expected, body
    return body

def policy(path, operation, *rest, ok=True):
    return run('access ' + operation + ' ' + path, ['access', '--id', identity, path, operation, *rest], ok=ok)

def mounts():
    return json.loads(run('mount list', ['mount', '--id', identity]).stdout)

def eventually(label, check, timeout=15):
    end = time.monotonic() + timeout
    while True:
        previous_count = len(results)
        try:
            return check()
        except (AssertionError, OSError, subprocess.TimeoutExpired):
            if time.monotonic() >= end:
                raise
            if len(results) > previous_count:
                results[-1]['readiness_probe'] = True
                results[-1]['passed'] = None
                save()
            time.sleep(0.5)

class Upstream(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'path': self.path}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *unused):
        pass

upstream = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
threading.Thread(target=upstream.serve_forever, daemon=True).start()
target = f'127.0.0.1:{upstream.server_port}'
updated = f'http://127.0.0.1:{upstream.server_port}/updated'
exact = '= ' + prefix + '/a&b'
original_listen = json.loads(run('listen query', ['listen', '--id', identity]).stdout)['listen']
original_mounts = mounts()
original_acl = json.loads(curl('ACL snapshot', '/std/acl/access'))
original_packages = json.loads(run('package list', ['install', '--list', '--id', identity]).stdout)
proxy = None
try:
    # Installed catalogs and query variants use the live host without touching packages.
    for item in original_packages:
        short = json.loads(run('package info short ' + item['name'], ['install', '--info', item['name'], '--id', identity]).stdout)
        full = json.loads(run('package info full ' + item['id'], ['install', '--info', item['id'], '--id', identity]).stdout)
        assert short == full and short['version'] == item['version']
    run('missing package info', ['install', '--info', 'gmutils-qa-missing', '--id', identity], ok=False)
    run('missing uninstall', ['uninstall', 'gmutils-qa-missing', '--id', identity], ok=False)
    installed_names = {item['name'] for item in original_packages}
    dependency = next((d['name'] for item in original_packages for d in item['dependencies'] if d['name'] in installed_names), None)
    if dependency:
        p = run('uninstall dependency protection', ['uninstall', dependency, '--id', identity], ok=False)
        assert '409' in p.stderr or 'depend' in p.stderr.lower(), p.stderr
    if original_packages:
        run('uninstall author mismatch', ['uninstall', 'gmutils-qa.dhttp.net/' + original_packages[0]['name'], '--id', identity], ok=False)
    for command in [['install', './local.pkg'], ['install', 'https://invalid.example/pkg'],
            ['install', 'workspace', '--version', '01.0.0'], ['update', 'gmutils-qa-missing']]:
        run('invalid package input ' + ' '.join(command), [*command, '--id', identity], ok=False)

    # End-to-end mount: real HTTP upstream, asynchronous runtime application and both delete guards.
    run('mount add', ['mount', '--id', identity, prefix, target])
    assert any(m['location'] == prefix for m in mounts())
    eventually('mount serves', lambda: forwarded('mount HTTP forwarding', prefix + '/item?x=a%2Fb', prefix + '/item?x=a%2Fb'))
    run('mount update', ['mount', '--id', identity, prefix, updated])
    eventually('mount update serves', lambda: forwarded('updated HTTP forwarding', prefix + '/item', '/updated/item'))
    run('mount exact', ['mount', '--id', identity, exact, target])
    curl('exact mount encoding', prefix + '/a&b')
    run('unmount rejects changed upstream', ['unmount', '--id', identity, prefix, target, '--yes'], ok=False)
    assert any(m['location'] == prefix and m['proxy_pass'] == updated for m in mounts())
    run('unmount requires noninteractive confirmation', ['unmount', '--id', identity, prefix, updated], ok=False)
    run('unmount exact', ['unmount', '--id', identity, exact, target, '--yes'])
    run('unmount exact idempotent', ['unmount', '--id', identity, exact, target, '--yes'])
    run('reject reserved mount', ['mount', '--id', identity, '/std/gmutils-qa', target], ok=False)
    run('reject nonlocal upstream', ['mount', '--id', identity, prefix + '-invalid', 'http://192.0.2.1:8080'], ok=False)
    for command in [['mount', prefix], ['unmount', prefix], ['unlisten', '--id', identity], ['forward'], ['server']]:
        run('reject obsolete/incomplete ' + command[0], command, ok=False)

    # Exact-prefix ACL operations; no review request is submitted, so no approval record is created.
    policy(prefix, 'allow', '*?', '--method', 'GET')
    curl('anonymous allowed through mount', prefix + '/item', anonymous=True)
    policy(prefix, 'deny', '*?', '--method', 'GET')
    curl('anonymous denied', prefix + '/item', status=403, anonymous=True)
    policy(prefix, 'review', '**', '--method', 'POST')
    output = policy(prefix, 'list').stdout
    assert 'deny' in output and 'review' in output
    run('access method filter', ['access', '--id', identity, '--method', 'POST', 'list', '--wide'])
    policy(prefix, 'allow', 'qa@' + host, '--method', 'PUT')
    policy(prefix, 'remove', 'qa@' + host, '--method', 'PUT')
    policy(prefix, 'remove', '*?', '--method', 'GET')
    policy(prefix, 'remove', '*?', '--method', 'GET')
    policy(prefix, 'clear', '--method', 'POST')
    assert not policy(prefix, 'list').stdout
    policy(prefix, 'allow', '**')
    policy(prefix, 'remove', '--all')
    policy(prefix, 'allow', '?', '--method', 'GET')
    policy(prefix + '/nested%2Fsegment', 'deny', '*?', '--method', 'GET')
    run('access bulk exact paths', ['access', '--id', identity, 'remove', prefix, prefix + '/nested%2Fsegment'])
    assert not policy(prefix, 'list').stdout
    run('access root read', ['access', '--id', identity, '/', 'list'])

    # Local changes can restore an off identity without HTTP. Keep the peer available.
    run('listen noninteractive off refused', ['listen', '--id', identity, 'off'], ok=False)
    for mode in ['internal', 'external', 'all', 'off']:
        run('listen mode ' + mode, ['listen', '--id', identity, mode, '--yes'])
        assert json.loads(run('listen reads ' + mode, ['listen', '--id', identity]).stdout)['listen'] == mode
        if mode in ['internal', 'all']:
            assert any(m['location'] == prefix for m in mounts())
        time.sleep(1.3)
    peerurl = 'https://' + peerhost + '/std/sys/listen'
    run('peer remains reachable while primary off', ['curl', '-sS', '-f', '--dns', 'mdns', '--id', args.peer, '--connect-timeout', '3', peerurl], timeout=15)
    run('listen restore', ['listen', '--id', identity, original_listen, '--yes'])
    eventually('primary restored', lambda: curl('restored host reachable', '/std/sys/listen'))
    assert any(m['location'] == prefix for m in mounts())
    for mode in ['auto', 'loopback', 'list']:
        run('reject obsolete listen ' + mode, ['listen', '--id', identity, mode], ok=False)

    apps = [p for p in original_packages if p['has_app']]
    if apps:
        app = '/app/' + apps[0]['name']
        head = run('curl HEAD verified visitor', ['curl', '-sS', '--dns', 'mdns', '--id', identity,
            '-X', 'HEAD', '-w', '%{response_code}|%{header{Pishoo-Viewer-Name}}|%{header{Cache-Control}}',
            'https://' + host + app + '/'], timeout=15)
        assert head.stdout == '200|' + host + '|no-store', head.stdout
        page = curl('curl GET App', app + '/')
        with tempfile.TemporaryDirectory(prefix='gmutils-curl-') as td:
            out = Path(td) / 'page.html'
            run('curl output file', ['curl', '-sS', '-f', '--dns', 'mdns', '--id', identity, '-o', str(out), 'https://' + host + app + '/'], timeout=15)
            assert out.read_text() == page
        curl('curl redirect follows', app, extra=('-L',))
        # Run the suite's HTTP -> DHTTP proxy against the same real App.
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            proxy_port = sock.getsockname()[1]
        proxy = subprocess.Popen([cli, 'proxy', '--id', identity, '--dns', 'mdns', '--listen', f'127.0.0.1:{proxy_port}'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def proxied():
            conn = http.client.HTTPConnection('127.0.0.1', proxy_port, timeout=8)
            try:
                conn.request('GET', 'http://' + host + app + '/')
                response = conn.getresponse()
                assert response.status == 200, response.status
                assert response.read().decode() == page
            finally:
                conn.close()
        eventually('proxy live App', proxied)
        results.append({'name': 'proxy HTTP to live Pishoo DHTTP', 'passed': True})
        save()
    run('nslookup live identity', ['nslookup', '--id', identity, host, 'mdns'], timeout=20)

    discovery = subprocess.Popen([cli, 'discover'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(4)
    finally:
        discovery.terminate()
        output, _ = discovery.communicate(timeout=10)
    assert any(line.startswith('Name: ' + host.removesuffix('.dhttp.net') + '.') for line in output.splitlines()), output
    results.append({'name': 'discover live Pishoo mDNS advertisement', 'passed': True})
    save()

    # Exact-version install/update reach the pinned store. Do not hide an unavailable registry.
    if apps:
        package = apps[0]
        for operation in ['install', 'update']:
            p = subprocess.run([cli, operation, package['id'], '--id', identity, '--version', package['version']],
                capture_output=True, text=True, timeout=45, env=env, stdin=subprocess.DEVNULL)
            if p.returncode:
                pending_external.append({'command': operation, 'stage': 'store resolution', 'error': p.stderr[-2000:]})
                save()
                print(operation + ': pending store rollout', flush=True)
            else:
                value = json.loads(p.stdout)
                assert value['unchanged'] and value['entry_url'] == 'https://' + host + '/app/' + package['name'] + '/'
                results.append({'name': operation + ' exact installed version', 'passed': True})
                save()
finally:
    if proxy is not None:
        proxy.terminate()
        proxy.wait(timeout=10)
    try:
        run('cleanup restore listening first', ['listen', '--id', identity, original_listen, '--yes'])
        eventually('cleanup host reachable', lambda: curl('cleanup host reachable', '/std/sys/listen'))
        run('cleanup temporary ACL', ['access', '--id', identity, 'remove', prefix, prefix + '/nested%2Fsegment'])
        for mount in mounts():
            if mount['location'].removeprefix('= ').startswith(prefix):
                run('cleanup temporary mount', ['unmount', '--id', identity, mount['location'], mount['proxy_pass'], '--yes'])
    except Exception as error:
        cleanup_errors.append({'error': str(error)})
    upstream.shutdown()
    upstream.server_close()
    save()
assert not cleanup_errors, cleanup_errors
assert mounts() == original_mounts
assert json.loads(curl('ACL restored', '/std/acl/access')) == original_acl
assert json.loads(run('package catalog unchanged', ['install', '--list', '--id', identity]).stdout) == original_packages
assert json.loads(run('listen restored', ['listen', '--id', identity]).stdout)['listen'] == original_listen
complete = True
save()
print(json.dumps({'passed': sum(x.get('passed', False) for x in results), 'pending_external': len(pending_external), 'cleanup': 'restored'}))
raise SystemExit(2 if pending_external and not args.allow_store_pending else 0)
