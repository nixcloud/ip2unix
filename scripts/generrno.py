import subprocess
import sys

errnos = []
cmd = [sys.argv[1], '-E', '-dM', '-include', 'errno.h', '-']
macros = subprocess.check_output(cmd, input=b'')
for line in macros.splitlines():
    chunks = line.decode('ascii').split()
    if len(chunks) != 3:
        continue
    if chunks[0] != '#define':
        continue
    if not chunks[1].startswith('E'):
        continue
    if any(not c.isdigit() and not c.isupper() for c in chunks[1]):
        continue
    if any(not c.isdigit() for c in chunks[2]):
        continue
    errnos.append((int(chunks[2]), chunks[1]))

errnos.sort(key=lambda x: x[0])

out = '#include <optional>\n'
out += '#include <string>\n\n'
out += 'std::optional<int> name2errno(const std::string &str)\n{\n'
out += '    std::string ucstr(str);\n'
out += '    for (auto &c : ucstr) c = toupper(c);\n\n'
for n, (number, name) in enumerate(errnos):
    out += '    else ' if n > 0 else '    '
    out += 'if (ucstr == "' + name + '") return ' + str(number) + ';\n'
out += '    else return std::nullopt;\n'
out += '}\n\n'

out += 'const std::string errno2name(int num)\n{\n'
out += '    switch (num) {\n'
for number, name in dict(errnos).items():
    out += '        case ' + str(number) + ': return "' + name + '";\n'
out += '        default: return "<unknown>";\n'
out += '    }\n'
out += '}\n'

sys.stdout.write(out)
