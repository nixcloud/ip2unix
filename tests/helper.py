import os
import json
import tempfile
import subprocess

from contextlib import contextmanager

import pytest
from conftest import IP2UNIX, SYSTEMD_SUPPORT

__all__ = ['IP2UNIX', 'SYSTEMD_SUPPORT', 'ip2unix', 'ip2unix_check',
           'systemd_only', 'non_systemd_only']


@contextmanager
def ip2unix(rules, childargs, *args, **kwargs):
    cmdargs = kwargs.pop('ip2unix_args', [])
    rulefile = tempfile.NamedTemporaryFile('w', delete=False)
    json.dump(rules, rulefile)
    rulefile.close()
    full_args = [IP2UNIX] + cmdargs + [rulefile.name] + childargs
    try:
        yield subprocess.Popen(full_args, *args, **kwargs)
    finally:
        os.unlink(rulefile.name)


def ip2unix_check(rules):
    with ip2unix(rules, [], stderr=subprocess.STDOUT, stdout=subprocess.PIPE,
                 universal_newlines=True, ip2unix_args=['-c']) as process:
        try:
            stdout = process.communicate()[0]
        except: # NOQA
            process.kill()
            process.wait()
            raise
        return process.poll() == 0, stdout


systemd_only = pytest.mark.skipif(not SYSTEMD_SUPPORT,
                                  reason='no support for systemd compiled in')
non_systemd_only = pytest.mark.skipif(SYSTEMD_SUPPORT,
                                      reason='support for systemd compiled in')
