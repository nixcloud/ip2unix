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
        self.assert_bad_rules({'rule1': {'path': '/foo'}})
        self.assert_bad_rules({'rule2': {}})
        self.assert_bad_rules({})

    def test_empty(self):
        self.assert_good_rules([])

    def test_complete_rules(self):
        self.assert_good_rules([
            {'direction': 'outgoing',
             'type': 'udp',
             'path': '/tmp/foo'},
            {'direction': 'incoming',
             'address': '::',
             'path': '/tmp/bar'}
        ])

    def test_unknown_rule_attrs(self):
        self.assert_bad_rules([{'foo': 1}])
        self.assert_bad_rules([{'socketpath': 'xxx'}])

    def test_wrong_rule_types(self):
        self.assert_bad_rules([{'type': 'nope', 'path': '/tmp/foo'}])
        self.assert_bad_rules([{'direction': 'out', 'path': '/tmp/foo'}])
        self.assert_bad_rules([{'path': 1234}])

    def test_no_socket_path(self):
        self.assert_bad_rules([{'address': '1.2.3.4'}])

    def test_relative_socket_path(self):
        self.assert_bad_rules([{'path': 'aaa/bbb'}])
        self.assert_bad_rules([{'path': 'bbb'}])

    def test_absolute_socket_path(self):
        self.assert_good_rules([{'path': '/xxx'}])

    def test_invalid_enums(self):
        self.assert_bad_rules([{'path': '/bbb', 'direction': 111}])
        self.assert_bad_rules([{'path': '/bbb', 'direction': False}])
        self.assert_bad_rules([{'path': '/bbb', 'type': 234}])
        self.assert_bad_rules([{'path': '/bbb', 'type': True}])

    def test_invalid_port_type(self):
        self.assert_bad_rules([{'path': '/aaa', 'port': 'foo'}])
        self.assert_bad_rules([{'path': '/aaa', 'port': True}])
        self.assert_bad_rules([{'path': '/aaa', 'port': -1}])
        self.assert_bad_rules([{'path': '/aaa', 'port': 65536}])

    def test_port_range(self):
        self.assert_good_rules([{'path': '/aaa', 'port': 123, 'portEnd': 124}])
        self.assert_good_rules([{'path': '/aaa', 'port': 1000,
                                 'portEnd': 65535}])

    def test_invalid_port_range(self):
        self.assert_bad_rules([{'path': '/aaa', 'port': 123,
                                'portEnd': 10}])
        self.assert_bad_rules([{'path': '/aaa', 'port': 123,
                                'portEnd': 123}])
        self.assert_bad_rules([{'path': '/aaa', 'port': 123,
                                'portEnd': 65536}])

    def test_missing_start_port_in_range(self):
        self.assert_bad_rules([{'path': '/aaa', 'portEnd': 123}])

    def test_valid_address(self):
        valid_addrs = [
            '127.0.0.1', '0.0.0.0', '9.8.7.6', '255.255.255.255', '::',
            '::ffff:127.0.0.1', '7:6:5:4:3:2:1::', '::7:6:5:4:3:2:1',
            '7::', '::2:1', '::17', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        ]
        for addr in valid_addrs:
            self.assert_good_rules([{'path': '/foo', 'address': addr}])

    def test_invalid_addrss(self):
        invalid_addrs = [
            '.0.0.1', '123', '123.', '..', '-1.2.3.4', '256.255.255.255', ':::'
            '0.00.0.0', '1.-2.3.4', 'abcde', '::-1', '01000::', 'abcd::efgh'
            '8:7:6:5:4:3:2:1::', '::8:7:6:5:4:3:2:1', 'f:f11::01100:2'
        ]
        for addr in invalid_addrs:
            self.assert_bad_rules([{'path': '/foo', 'address': addr}])

    def test_valid_reject(self):
        for val in ["EBADF", "EINTR", "enomem", "EnOMeM", 13, 12]:
            self.assert_good_rules([{'reject': True, 'rejectError': val}])

    def test_invalid_reject(self):
        for val in ["EBAAAADF", "", "XXX", "vvv", -10]:
            self.assert_bad_rules([{'reject': True, 'rejectError': val}])

    def test_reject_with_sockpath(self):
        self.assert_bad_rules([{'path': '/foo', 'reject': True}])

    def test_blackhole_with_reject(self):
        self.assert_bad_rules([{'direction': 'incoming', 'reject': True,
                                'blackhole': True}])

    def test_blackhole_outgoing(self):
        self.assert_bad_rules([{'blackhole': True}])
        self.assert_bad_rules([{'direction': 'outgoing', 'blackhole': True}])

    def test_blackhole_with_sockpath(self):
        self.assert_bad_rules([{'direction': 'incoming', 'path': '/foo',
                                'blackhole': True}])

    def test_blackhole_all(self):
        self.assert_good_rules([{'direction': 'incoming', 'blackhole': True}])

    def test_ignore_with_sockpath(self):
        self.assert_bad_rules([{'path': '/foo', 'ignore': True}])

    def test_ignore_with_reject(self):
        self.assert_bad_rules([{'reject': True, 'ignore': True}])

    def test_ignore_with_blackhole(self):
        self.assert_bad_rules([{'blackhole': True, 'ignore': True}])

    @systemd_only
    def test_ignore_with_systemd(self):
        self.assert_bad_rules([{'socketActivation': True, 'ignore': True}])

    @systemd_only
    def test_contradicting_systemd(self):
        self.assert_bad_rules([{'path': '/foo', 'socketActivation': True}])

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
             'path': '/foo'},
            {'address': '0.0.0.0',
             'path': '/bar'}
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
        rules = [{'path': '/xxx'}]
        cmd = [IP2UNIX, '-p', '-F', json.dumps(rules),
               sys.executable, '-c', '']
        result = subprocess.run(cmd, stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertNotEqual(result.stderr, b'')
        self.assertGreater(len(result.stderr), 0)
        self.assertIn(b'IP Type', result.stderr)

    def assert_deprecated_rule(self, rules, rule_name, new_name):
        cmd = [IP2UNIX, '-c', '-F', json.dumps(rules)]
        result = subprocess.run(cmd, capture_output=True)
        expected = '<unknown>:rule #1: The "{}" option is deprecated and' \
                   ' has been renamed to "{}". It will be removed in the' \
                   ' next major version of ip2unix.\n'
        expected_stderr = expected.format(rule_name, new_name).encode()
        self.assertEqual(result.stderr, expected_stderr)
        self.assertEqual(result.stdout, b'')
        msg = "Deprecated options should not fail the validation"
        self.assertEqual(result.returncode, 0, msg)

    def test_deprecated(self):
        rules = [{'socketPath': '/xxx'}]
        self.assert_deprecated_rule(rules, 'socketPath', 'path')
