import socket
import subprocess
import sys

from uuid import uuid4
from helper import abstract_sockets_only, IP2UNIX

TESTPROG = r'''
import socket

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.connect('{}')
    sock.sendall(b'unrelated')

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.connect('{}')
    sock.sendall(b'hello')
    assert sock.recv(5) == b'world'
'''


def test_from_unix(tmpdir):
    unrelated_sockfile = str(tmpdir.join('unrelated.sock'))
    sockfile = str(tmpdir.join('foo.sock'))

    testprog = TESTPROG.format(unrelated_sockfile, '/foo/bar/xyz')

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unrelated_sock, \
         socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        unrelated_sock.bind(unrelated_sockfile)
        unrelated_sock.listen(10)

        sock.bind(sockfile)
        sock.listen(10)

        cmd = [IP2UNIX]
        cmd += ['-r', f'from-unix=/foo/ba[q-s]/xyz,path={sockfile}']
        cmd += [sys.executable, '-c', testprog]

        with subprocess.Popen(cmd, stdout=subprocess.PIPE) as client:
            with unrelated_sock.accept()[0] as unrelated_conn:
                assert unrelated_conn.recv(9) == b'unrelated'

            with sock.accept()[0] as conn:
                assert conn.recv(5) == b'hello'
                conn.sendall(b'world')

            assert client.wait() == 0


@abstract_sockets_only
def test_from_abstract(tmpdir):
    unrelated_sockfile = str(tmpdir.join('unrelated.sock'))
    name = uuid4().hex

    testprog = TESTPROG.format(unrelated_sockfile, '\\0foobar')

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unrelated_sock, \
         socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        unrelated_sock.bind(unrelated_sockfile)
        unrelated_sock.listen(10)

        sock.bind('\0' + name)
        sock.listen(10)

        cmd = [IP2UNIX]
        cmd += ['-r', f'from-abstract=foob[a-c]r,abstract={name}']
        cmd += [sys.executable, '-c', testprog]

        with subprocess.Popen(cmd, stdout=subprocess.PIPE) as client:
            with unrelated_sock.accept()[0] as unrelated_conn:
                assert unrelated_conn.recv(9) == b'unrelated'

            with sock.accept()[0] as conn:
                assert conn.recv(5) == b'hello'
                conn.sendall(b'world')

            assert client.wait() == 0
