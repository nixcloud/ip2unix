import re
import sys

WRAP_SYM_RE = re.compile(r'WRAP_SYM\s*\(\s*(\S+?)\s*\)')

symbols = []
for path in sys.argv[1:]:
    with open(path, 'r') as src:
        for line in src:
            if line.lstrip().startswith('#'):
                continue
            for match in WRAP_SYM_RE.finditer(line):
                symbols.append(match.group(1))

exported = ''.join(map(lambda s: ' "' + s + '";', symbols))
sys.stdout.write("{\n  global:" + exported + "\n  local: *;\n};\n")
