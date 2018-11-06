import sys
import subprocess
import socket
import time

import helper

TESTPROG = r'''
import os
import sys
import socket

for i in range(3, 1024):
    try:
        os.close(i)
    except OSError:
        pass

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(('9.8.7.6', 1234))
    sock.listen(10)
    with sock.accept()[0] as conn:
        data = conn.recv(10)
        conn.sendall(data.upper())

sys.stdout.write('DONE\n')
sys.stdout.flush()
'''


@helper.systemd_sa_helper_only
def test_closeallfds(tmpdir):
    sockfile = str(tmpdir.join('test.sock'))
    cmd = [
        helper.SYSTEMD_SA_PATH, '-l', sockfile,
        helper.IP2UNIX, '-r', 'systemd',
        sys.executable, '-c', TESTPROG
    ]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as server:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            while True:
                try:
                    client.connect(sockfile)
                except FileNotFoundError:
                    pass
                else:
                    break
                time.sleep(0.1)
            client.sendall(b'abcdefghij')
            assert client.recv(10) == b'ABCDEFGHIJ'
        stdout = server.communicate(timeout=5)[0]
        assert stdout == b'DONE\n'
