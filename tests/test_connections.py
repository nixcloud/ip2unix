import helper
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from contextlib import contextmanager

CURDIR = os.path.dirname(os.path.abspath(__file__))
CONNECTOR = os.path.join(CURDIR, 'connector.py')


class ConnectionTest(unittest.TestCase):
    def assert_client(self, rules, *args):
        cmd = [sys.executable, CONNECTOR] + list(map(str, args))
        with helper.ip2unix(rules, cmd, stderr=subprocess.STDOUT,
                            stdout=subprocess.PIPE) as process:
            stdout = process.communicate()[0]
            msg = 'Client did not return successful:\n' + stdout.decode()
            self.assertEqual(process.poll(), 0, msg)

    @contextmanager
    def run_server(self, rules, *args):
        cmd = [sys.executable, CONNECTOR, '-l'] + list(map(str, args))
        with helper.ip2unix(rules, cmd, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE) as process:
            assert process.stdout.read(6) == b'READY\n'
            yield process
            process.stdin.write(b'\n')

    def assert_connection(self, crule, srule, cargs, sargs):
        sockpath = os.path.join(self.tmpdir, 'test.sock')
        client_rule = {'direction': 'outgoing', 'socketPath': sockpath}
        client_rule.update(crule)
        server_rule = {'socketPath': sockpath}
        server_rule.update(srule)
        with self.run_server([server_rule], *sargs):
            self.assert_client([client_rule], *cargs)

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_simple(self):
        args = ['1.2.3.4', 123]
        self.assert_connection({}, {}, args, args)

    def test_simple_threaded(self):
        args = ['-m', 'threading', '1.2.3.4', 123]
        self.assert_connection({}, {}, args, args)

    def test_several(self):
        args = ['-p', 10, '-c', 20, '1.2.3.4', 123]
        self.assert_connection({}, {}, args, args)

    def test_several_threaded(self):
        args = ['-m', 'threading', '-p', 10, '-c', 20, '1.2.3.4', 123]
        self.assert_connection({}, {}, args, args)
