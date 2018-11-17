import subprocess
import sys

from helper import IP2UNIX

TESTPROG = '''
import socket
import errno

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    try:
        client.connect(('127.0.0.127', 9999))
    except OSError as e:
        assert e.errno != 9999

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    try:
        server.bind(('127.0.0.127', 9999))
    except OSError as e:
        assert e.errno != 9999

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    try:
        client.connect(('127.0.0.127', 1234))
    except OSError as e:
        assert e.errno == 9999

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    try:
        server.bind(('127.0.0.127', 4321))
    except OSError as e:
        assert e.errno == 9999
'''


def test_reject():
    rules = ['-r', 'port=9999,ignore', '-r', 'reject=9999']
    cmd = [IP2UNIX] + rules + [sys.executable, '-c', TESTPROG]
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    assert result.returncode == 0
