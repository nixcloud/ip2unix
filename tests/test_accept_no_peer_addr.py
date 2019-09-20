import socket
import subprocess
import time

from helper import IP2UNIX


def test_accept_no_peer_addr(tmpdir, helper_accept_no_peer_addr):
    sockfile = str(tmpdir.join('server.sock'))
    rules = ['-r', 'in,port=1234,path=' + sockfile]
    cmd = [IP2UNIX] + rules + [helper_accept_no_peer_addr]

    with subprocess.Popen(cmd) as server:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            while True:
                try:
                    client.connect(sockfile)
                except FileNotFoundError:
                    pass
                else:
                    break
                time.sleep(0.1)
            client.sendall(b'foo')
            assert client.recv(3) == b'bar'
        server.communicate(timeout=5)
