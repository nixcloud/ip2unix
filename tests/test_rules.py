import unittest

from helper import ip2unix_check, systemd_only, non_systemd_only


class RulesTest(unittest.TestCase):
    def assert_good_rules(self, rules):
        code, output = ip2unix_check(rules)
        msg = 'Rules {!r} do not validate: {}'.format(rules, output.rstrip())
        self.assertTrue(code, msg)

    def assert_bad_rules(self, rules):
        code, output = ip2unix_check(rules)
        msg = 'Rules {!r} should not be valid.'.format(rules)
        self.assertFalse(code, msg)

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
