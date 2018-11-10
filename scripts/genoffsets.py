import sys
from math import sqrt

__all__ = ['offsets']

RANGE = 65536 - 1024

primeset = [True] * (RANGE + 1)
# Only generate values bigger than half of the range, so the assigned
# ports will be further apart.
start = RANGE >> 1 + 1

# See get_random_offset() in dynports.cc for a description of what
# we're doing here.
for p in range(2, int(sqrt(RANGE))):
    if not primeset[p]:
        continue

    for i in range(p * p, RANGE, p):
        primeset[i] = False

offsets = [i for i, p in enumerate(primeset[start:], start)
           if p and RANGE % i != 0]

if __name__ == '__main__':
    if len(sys.argv) == 3:
        chunks = [offsets[i:i + 10] for i in range(0, len(offsets), 10)]
        formatted = [', '.join(['{:>5}'.format(o) for o in chunk])
                     for chunk in chunks]

        sig = 'static constexpr std::array<uint16_t, {}> PORT_OFFSETS'
        header = sig.format(len(offsets)) + ' {{\n    '
        out = header + ',\n    '.join(formatted) + '\n}};\n'

        with open(sys.argv[1], 'r') as fin, open(sys.argv[2], 'w') as fout:
            fout.write(fin.read().replace('@PORT_OFFSETS@', out))
    else:
        print(offsets)
