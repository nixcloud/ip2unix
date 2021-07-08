import re
import sys

from typing import List


def find_symbols(*wrapper_names: str) -> List[str]:
    fun_matches = '|'.join(map(re.escape, wrapper_names))
    wrap_sym_re = re.compile(rf'(?:{fun_matches})\s*\(\s*(\S+?)\s*\)')

    symbols = []
    for path in sys.argv[2:]:
        with open(path, 'r') as src:
            for line in src:
                if line.lstrip().startswith('#'):
                    continue
                for match in wrap_sym_re.finditer(line):
                    symbols.append(match.group(1))
    return symbols


if sys.argv[1] == '--map':
    symbols = find_symbols('WRAP_SYM', 'EXPORT_SYM')
    exported = ''.join(map(lambda s: ' "' + s + '";', symbols))
    sys.stdout.write("{\n  global:" + exported + "\n  local: *;\n};\n")
elif sys.argv[1] == '--ldscript':
    symbols = find_symbols('WRAP_SYM')
    lines = map(lambda s: f'PROVIDE({s} = ip2unix_wrap_{s});', symbols)
    sys.stdout.write("\n".join(lines) + "\n")
