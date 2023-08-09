import socket
import subprocess
import sys

from uuid import uuid4
from helper import abstract_sockets_only, IP2UNIX

TESTPROG = r'''
import socket

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.connect('{}')
    sock.sendall(b'hello')
    assert sock.recv(5) == b'world'
'''


def test_from_unix(tmpdir):
    sockfile = str(tmpdir.join('foo.sock'))

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind(sockfile)
        sock.listen(10)

        cmd = [IP2UNIX]
        cmd += ['-r', f'from-unix=/foo/ba[q-s]/xyz,path={sockfile}']
        cmd += [sys.executable, '-c', TESTPROG.format('/foo/bar/xyz')]

        with subprocess.Popen(cmd, stdout=subprocess.PIPE), \
             sock.accept()[0] as conn:
            assert conn.recv(5) == b'hello'
            conn.sendall(b'world')


@abstract_sockets_only
def test_from_abstract(tmpdir):
    name = uuid4().hex

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind('\0' + name)
        sock.listen(10)

        cmd = [IP2UNIX]
        cmd += ['-r', f'from-abstract=foob[a-c]r,abstract={name}']
        cmd += [sys.executable, '-c', TESTPROG.format('\\0foobar')]

        with subprocess.Popen(cmd, stdout=subprocess.PIPE), \
             sock.accept()[0] as conn:
            assert conn.recv(5) == b'hello'
            conn.sendall(b'world')
