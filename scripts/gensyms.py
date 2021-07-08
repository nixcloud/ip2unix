import re
import sys

from subprocess import Popen, PIPE
from typing import List

RE_IS_INCLUDE = re.compile(rb'^\s*#\s*include\b')
RE_RESULT = re.compile(rb'__RESULT\((.*?)\)RESULT__')

ACTION = sys.argv[1]
SEP_INDEX = sys.argv[2:].index('--')
CC_COMMAND = sys.argv[2:][:SEP_INDEX]
FILES = sys.argv[2:][SEP_INDEX + 1:]


def find_symbols(*wrapper_names: str) -> List[str]:
    args = map(lambda n: f'-D{n}(x)=__RESULT(x)RESULT__', wrapper_names)
    cmd = CC_COMMAND + ['-E'] + list(args) + ['-']
    symbols = []
    for path in FILES:
        with open(path, 'rb') as src:
            process = Popen(cmd, stdin=PIPE, stdout=PIPE)
            for line in src:
                if RE_IS_INCLUDE.match(line):
                    continue
                process.stdin.write(line)
            process.stdin.close()
            data = process.stdout.read()
            process.wait()
            symbols += [m.group(1) for m in RE_RESULT.finditer(data)]
    return [sym.decode() for sym in symbols]


if ACTION == '--map':
    symbols = find_symbols('WRAP_SYM', 'EXPORT_SYM')
    exported = ''.join(map(lambda s: ' "' + s + '";', symbols))
    sys.stdout.write("{\n  global:" + exported + "\n  local: *;\n};\n")
elif ACTION == '--ldscript':
    symbols = find_symbols('WRAP_SYM')
    lines = map(lambda s: f'PROVIDE({s} = ip2unix_wrap_{s});', symbols)
    sys.stdout.write("\n".join(lines) + "\n")
