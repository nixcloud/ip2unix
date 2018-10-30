import unittest
import subprocess

import helper


class RulesTest(unittest.TestCase):
    def check_rules(self, *rules, bad=False):
        args = [r for rule in rules for r in ('-r', rule)]
        cmd = [helper.IP2UNIX, '-cp'] + args
        with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as proc:
            stdout, stderr = proc.communicate()
            if bad:
                self.assertNotEqual(proc.poll(), 0, stdout)
            else:
                self.assertEqual(proc.poll(), 0, stderr)
            return stdout.decode(), stderr.decode()

    def test_bad_syntax(self):
        syntax_errors = {
            'unknown key': ["=123", "321=", "=", "xxx=", "=="],
            'invalid port': ["port=", "port=-1", "port=65536", "port=1000000"],
            'invalid reject error code': ["reject=", "reject=-1",
                                          "reject=INVALIDERRORCODE"],
            'has to be absolute': ["path=\\", "path=\\a"],
            'unknown flag': [",", "", "/", "path=/a\\\\,xxx"],
        }
        for synerr, rules in syntax_errors.items():
            for rule in rules:
                stdout, stderr = self.check_rules(rule, bad=True)
                self.assertIn(synerr, stderr)

    def test_path_subst(self):
        fixtures = {
            "/%a\\,\\\\": "/%a,\\",
            "/foo\\\\\\,": "/foo\\,",
        }
        for val, expect in fixtures.items():
            stdout, stderr = self.check_rules("path=" + val)
            self.assertIn("Socket path: " + expect + "\n", stdout)

    def test_good(self):
        fixtures = {
            "path=/aaa\\\\,port=0": "Port: 0\n",
            "path=/bbb\\\\,port=65535": "Port: 65535\n",
            "path=/ccc\\\\": "Direction: both\n",
            "path=/ddd\\\\,in": "Direction: incoming\n",
            "path=/eee\\\\,out": "Direction: outgoing\n",
            "path=/fff\\\\,tcp,udp": "IP Type: UDP\n",
            "path=/ggg\\\\,in,out": "Direction: outgoing\n",
            "path=/hhh\\\\": "Socket path: /hhh\\\n",
            "path=/iii\\,,out": "IP Type: TCP and UDP\n",
            "path=/jjj\\,,in": "Socket path: /jjj,\n",
            "reject": "Reject connect() and bind() calls.\n",
            "reject=EPERM": "connect() and bind() calls with errno EPERM.\n",
        }
        for val, expect in fixtures.items():
            stdout, stderr = self.check_rules(val)
            self.assertIn(expect, stdout)
