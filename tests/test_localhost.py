import subprocess
import sys

from helper import IP2UNIX

TESTPROG = r'''
import socket
import os

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server1, \
     socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server2:
    server1.bind(('127.0.0.1', 1234))
    server1.listen(10)
    server2.bind(('::1', 1234))
    server2.listen(10)

    childpid = os.fork()
    if childpid == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(('127.0.0.1', 1234))
            pn, sn = sock.getpeername()[0], sock.getsockname()[0]
            assert pn == '127.0.0.1', pn
            assert sn == '127.0.0.1', sn
            sock.sendall(b'foobar\n')
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.connect(('::1', 1234))
            pn, sn = sock.getpeername()[0], sock.getsockname()[0]
            assert pn == '::1', pn
            assert sn == '::1', sn
            sock.sendall(b'foobar\n')
        raise SystemExit
    else:
        with server1.accept()[0] as conn:
            pn, sn = conn.getpeername()[0], conn.getsockname()[0]
            assert pn == '127.0.0.1', pn
            assert sn == '127.0.0.1', sn
            assert conn.recv(7) == b'foobar\n'
        with server2.accept()[0] as conn:
            pn, sn = conn.getpeername()[0], conn.getsockname()[0]
            assert pn == '::1', pn
            assert sn == '::1', sn
            assert conn.recv(7) == b'foobar\n'

status = os.WEXITSTATUS(os.waitpid(childpid, 0)[1])
raise SystemExit(status)
'''


def test_sockserver(tmpdir):
    sockfile = str(tmpdir.join('test-%a.sock'))
    cmd = [IP2UNIX, '-r', 'path=' + sockfile, sys.executable, '-c', TESTPROG]
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    assert result.returncode == 0
