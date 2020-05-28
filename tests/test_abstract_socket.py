import socket
import subprocess
import sys

from helper import abstract_sockets_only, IP2UNIX

TESTPROG = r'''
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect(('4.3.2.1', 4321))
    sock.sendall(b'hello')
    assert sock.recv(5) == b'world'
'''


@abstract_sockets_only
def test_abstcact_socket():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind('\0abstest')
        sock.listen(10)

        cmd = [IP2UNIX]
        cmd += ['-r', 'addr=4.3.2.1,abstract=abstest']
        cmd += [sys.executable, '-c', TESTPROG]

        with subprocess.Popen(cmd, stdout=subprocess.PIPE), \
             sock.accept()[0] as conn:
            assert conn.recv(5) == b'hello'
            conn.sendall(b'world')
