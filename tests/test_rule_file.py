import json
import subprocess
import sys
import unittest

from helper import IP2UNIX, systemd_only, non_systemd_only


class RuleFileTest(unittest.TestCase):
    def assert_good_rules(self, rules):
        cmd = [IP2UNIX, '-c', '-F', json.dumps(rules)]
        result = subprocess.run(cmd, stderr=subprocess.STDOUT)
        msg = 'Rules {!r} do not validate: {}'.format(rules, result.stdout)
        self.assertEqual(result.returncode, 0, msg)

    def assert_bad_rules(self, rules):
        cmd = [IP2UNIX, '-c', '-F', json.dumps(rules)]
        result = subprocess.run(cmd, stderr=subprocess.STDOUT)
        msg = 'Rules {!r} should not be valid.'.format(rules)
        self.assertNotEqual(result.returncode, 0, msg)

    def test_no_array(self):
        self.assert_bad_rules({'rule1': {'socketPath': '/foo'}})
        self.assert_bad_rules({'rule2': {}})
        self.assert_bad_rules({})

    def test_empty(self):
        self.assert_good_rules([])

    def test_complete_rules(self):
        self.assert_good_rules([
            {'direction': 'outgoing',
             'type': 'udp',
             'socketPath': '/tmp/foo'},
            {'direction': 'incoming',
             'address': '::',
             'socketPath': '/tmp/bar'}
        ])

    def test_unknown_rule_attrs(self):
        self.assert_bad_rules([{'foo': 1}])
        self.assert_bad_rules([{'socketpath': 'xxx'}])

    def test_wrong_rule_types(self):
        self.assert_bad_rules([{'type': 'nope', 'socketPath': '/tmp/foo'}])
        self.assert_bad_rules([{'direction': 'out', 'socketPath': '/tmp/foo'}])
        self.assert_bad_rules([{'socketPath': 1234}])

    def test_no_socket_path(self):
        self.assert_bad_rules([{'address': '1.2.3.4'}])

    def test_relative_socket_path(self):
        self.assert_bad_rules([{'socketPath': 'aaa/bbb'}])
        self.assert_bad_rules([{'socketPath': 'bbb'}])

    def test_absolute_socket_path(self):
        self.assert_good_rules([{'socketPath': '/xxx'}])

    def test_invalid_enums(self):
        self.assert_bad_rules([{'socketPath': '/bbb', 'direction': 111}])
        self.assert_bad_rules([{'socketPath': '/bbb', 'direction': False}])
        self.assert_bad_rules([{'socketPath': '/bbb', 'type': 234}])
        self.assert_bad_rules([{'socketPath': '/bbb', 'type': True}])

    def test_invalid_port_type(self):
        self.assert_bad_rules([{'socketPath': '/aaa', 'port': 'foo'}])
        self.assert_bad_rules([{'socketPath': '/aaa', 'port': True}])
        self.assert_bad_rules([{'socketPath': '/aaa', 'port': -1}])
        self.assert_bad_rules([{'socketPath': '/aaa', 'port': 65536}])

    def test_valid_address(self):
        valid_addrs = [
            '127.0.0.1', '0.0.0.0', '9.8.7.6', '255.255.255.255', '::',
            '::ffff:127.0.0.1', '7:6:5:4:3:2:1::', '::7:6:5:4:3:2:1',
            '7::', '::2:1', '::17', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        ]
        for addr in valid_addrs:
            self.assert_good_rules([{'socketPath': '/foo', 'address': addr}])

    def test_invalid_addrss(self):
        invalid_addrs = [
            '.0.0.1', '123', '123.', '..', '-1.2.3.4', '256.255.255.255', ':::'
            '0.00.0.0', '1.-2.3.4', 'abcde', '::-1', '01000::', 'abcd::efgh'
            '8:7:6:5:4:3:2:1::', '::8:7:6:5:4:3:2:1', 'f:f11::01100:2'
        ]
        for addr in invalid_addrs:
            self.assert_bad_rules([{'socketPath': '/foo', 'address': addr}])

    @systemd_only
    def test_contradicting_socket_options(self):
        self.assert_bad_rules([
            {'socketPath': '/foo', 'socketActivation': True}
        ])

    @systemd_only
    def test_socket_fdname(self):
        self.assert_good_rules([{'socketActivation': True, 'fdName': 'foo'}])

    @non_systemd_only
    def test_no_systemd_options(self):
        self.assert_bad_rules([{'socketActivation': True}])
        self.assert_bad_rules([{'socketActivation': True, 'fdName': 'foo'}])

    def test_print_rules_check_stdout(self):
        rules = [
            {'direction': 'outgoing',
             'type': 'tcp',
             'socketPath': '/foo'},
            {'address': '0.0.0.0',
             'socketPath': '/bar'}
        ]
        cmd = [IP2UNIX, '-cp', '-F', json.dumps(rules)]
        result = subprocess.run(cmd, stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'')
        self.assertNotEqual(result.stdout, b'')
        self.assertGreater(len(result.stdout), 0)
        self.assertIn(b'IP Type', result.stdout)

    def test_print_rules_stderr(self):
        rules = [{'socketPath': '/xxx'}]
        cmd = [IP2UNIX, '-p', '-F', json.dumps(rules),
               sys.executable, '-c', '']
        result = subprocess.run(cmd, stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertNotEqual(result.stderr, b'')
        self.assertGreater(len(result.stderr), 0)
        self.assertIn(b'IP Type', result.stderr)
