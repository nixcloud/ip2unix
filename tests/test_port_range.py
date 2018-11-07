import select
import sys
import subprocess
import socket
import time

import helper

TESTPROG = r'''
import sys
import socket

from multiprocessing import Pool

def run_server(arg):
    identifier, addr = arg
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(addr)
        sock.listen(10)
        with sock.accept()[0] as conn:
            assert conn.recv(3) == b'xxx'
            conn.sendall(identifier.encode())
    return True

srvmap = {
    'start': ('1.2.3.4', 1000),
    'end': ('1.2.3.4', 2000),
    'between': ('1.2.3.4', 1444),
    'outside1': ('1.2.3.4', 999),
    'outside2': ('1.2.3.4', 2001),
}

pool = Pool(processes=len(srvmap))
assert all(pool.map(run_server, srvmap.items()))
sys.stdout.write('DONE\n')
sys.stdout.flush()
'''


def assert_client(path, port, identifier):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        while True:
            try:
                client.connect(path.replace('%p', str(port)))
            except FileNotFoundError:
                pass
            else:
                break
            time.sleep(0.1)
        client.sendall(b'xxx')
        assert len(select.select([client], [], [], 5)[0]) > 0
        assert client.recv(len(identifier)) == identifier.encode()


def test_port_range(tmpdir):
    inside_sockfile = str(tmpdir.join('inside-%p.sock'))
    outside_sockfile = str(tmpdir.join('outside-%p.sock'))

    cmd = [helper.IP2UNIX]
    cmd += ['-r', 'port=1000-2000,path=' + inside_sockfile]
    cmd += ['-r', 'path=' + outside_sockfile]
    cmd += [sys.executable, '-c', TESTPROG]

    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as server:
        assert_client(inside_sockfile, 1000, 'start')
        assert_client(inside_sockfile, 1444, 'between')
        assert_client(inside_sockfile, 2000, 'end')
        assert_client(outside_sockfile, 999, 'outside1')
        assert_client(outside_sockfile, 2001, 'outside2')
        stdout = server.communicate(timeout=5)[0]
        assert stdout == b'DONE\n'
