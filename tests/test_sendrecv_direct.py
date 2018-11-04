import subprocess
import sys

from helper import IP2UNIX

TESTPROG = '''
import os
import socket

with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server:
    server.bind(('12::3', 9999))

    childpid = os.fork()
    if childpid == 0:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
            client.sendto(b'hello recvfrom', ('12::3', 9999))
            client.sendmsg([b'hello recvmsg'], [], 0, ('12::3', 9999))
            client.connect(('12::3', 9999))
            client.sendall(b'hello recv')
            client.recv(1)
        raise SystemExit
    else:
        data, addr = server.recvfrom(14)
        assert data == b'hello recvfrom'
        data, ancdata, flags, addr_msg = server.recvmsg(13)
        assert data == b'hello recvmsg'
        assert addr_msg == addr, '{} != {}'.format(addr_msg, addr)

        server.connect(addr)
        data = server.recv(10)
        assert data == b'hello recv'
        server.send(b'x')

raise SystemExit(os.WEXITSTATUS(os.waitpid(childpid, 0)[1]))
'''


def test_sendrecv_direct(tmpdir):
    sockfile = str(tmpdir.join('test.sock'))
    cmd = [IP2UNIX, '-r', 'path=' + sockfile, sys.executable, '-c', TESTPROG]
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    assert result.returncode == 0
