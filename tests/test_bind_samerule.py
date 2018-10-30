import subprocess
import sys

from helper import IP2UNIX

TESTPROG = r'''
import socket
import os

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server1, \
     socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server2, \
     socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server4:
    server1.bind(('127.0.0.1', 444))
    server2.bind(('1.2.3.4', 555))

    # This is to deliberately try to confuse the internal socket registry.
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server3:
        server3.bind(('1234::5', 444))

    server4.bind(('5432::1', 444))

    server1.listen(10)
    server2.listen(10)
    server4.listen(10)

    childpid = os.fork()
    if childpid == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(('127.0.0.1', 444))
            sock.sendall(b'hello')
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.connect(('5432::1', 444))
            sock.sendall(b'world')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(('4.3.2.1', 555))
            sock.sendall(b'unrelated')
        raise SystemExit
    else:
        with server1.accept()[0] as conn:
            assert conn.recv(5) == b'hello'
        # The connection to server4 should get to server1
        with server1.accept()[0] as conn:
            assert conn.recv(5) == b'world'
        with server2.accept()[0] as conn:
            assert conn.recv(9) == b'unrelated'

status = os.WEXITSTATUS(os.waitpid(childpid, 0)[1])
raise SystemExit(status)
'''


def test_sockserver(tmpdir):
    sockfile = str(tmpdir.join('test-%p.sock'))
    cmd = [IP2UNIX, '-r', 'path=' + sockfile, sys.executable, '-c', TESTPROG]
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    assert result.returncode == 0
