import sys
import socket
import subprocess
import time

from helper import IP2UNIX

TESTPROG = r'''
import os
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind(('127.0.0.1', 9999))
    server.listen(10)

    childpid = os.fork()
    if childpid == 0:
        with server.accept()[0] as conn:
            conn.sendall(bytes(reversed(conn.recv(10))))
    else:
        with server.accept()[0] as conn:
            conn.sendall(conn.recv(10))

        status = os.WEXITSTATUS(os.waitpid(childpid, 0)[1])
        raise SystemExit(status)
'''


def test_double_accept(tmpdir):
    sockfile = str(tmpdir.join('test.sock'))
    cmd = [IP2UNIX, '-r', 'path=' + sockfile, sys.executable, '-c', TESTPROG]
    with subprocess.Popen(cmd) as server:
        replies = set()
        data = b'1234567890'

        for _ in range(2):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                while True:
                    try:
                        client.connect(sockfile)
                    except FileNotFoundError:
                        pass
                    else:
                        break
                    time.sleep(0.1)

                client.sendall(data)
                replies.add(client.recv(10))

        assert replies == {b'1234567890', b'0987654321'}
        server.communicate(timeout=5)
        assert server.returncode == 0
