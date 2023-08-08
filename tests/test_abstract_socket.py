import socket
import subprocess
import sys

from uuid import uuid4
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
    name = uuid4().hex

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind('\0' + name)
        sock.listen(10)

        cmd = [IP2UNIX]
        cmd += ['-r', f'addr=4.3.2.1,abstract={name}']
        cmd += [sys.executable, '-c', TESTPROG]

        with subprocess.Popen(cmd, stdout=subprocess.PIPE), \
             sock.accept()[0] as conn:
            assert conn.recv(5) == b'hello'
            conn.sendall(b'world')
