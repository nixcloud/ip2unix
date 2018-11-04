import os
import sys
import subprocess

cmd = sys.argv[1:] + ['--print-file-name=libc.so.6']
path = subprocess.check_output(cmd).strip()
assert os.path.exists(path)
sys.stdout.buffer.write(path)
