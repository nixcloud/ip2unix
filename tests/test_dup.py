import sys
import subprocess

from helper import IP2UNIX

TESTPROG = r'''
import os
import socket

rsync, wsync = os.pipe()

childpid = os.fork()
if childpid == 0:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('127.0.0.1', 9999))
        server.listen(10)
        os.write(wsync, b'X')
        with server.accept()[0] as conn:
            assert conn.recv(10) == b'1234567890'
            assert conn.recv(1) == b''
        with server.accept()[0] as conn:
            assert conn.recv(3) == b'foo'
            assert conn.recv(3) == b'bar'
            conn.sendall(b'yup')
        raise SystemExit

os.read(rsync, 1)

replaceme = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
replaceme.connect(('127.0.0.2', 9999))
replaceme.sendall(b'1234567890')
newfd = replaceme.fileno()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.2', 9999))
os.dup2(sock.fileno(), newfd)
sock.sendall(b'foo')
with sock.dup() as newsock:
    newsock.sendall(b'bar')
    assert newsock.recv(3) == b'yup'
sock.close()
status = os.WEXITSTATUS(os.waitpid(childpid, 0)[1])
raise SystemExit(status)
'''


def test_dup(tmpdir):
    sockfile = str(tmpdir.join('test.sock'))
    cmd = [IP2UNIX, '-r', 'path=' + sockfile, sys.executable, '-c', TESTPROG]
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    assert result.returncode == 0
