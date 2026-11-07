from pathlib import Path
import sys

start_index = 2023000
total = 303450  # 6 parts x 50575
parts = 6
per = total // parts
outdir = Path(sys.argv[1])
for p in range(parts):
    name = outdir / f'big_part_{41 + p:02d}.c'
    s = start_index + p * per
    with name.open('w', encoding='utf-8', newline='\n') as f:
        f.write('#include <stdio.h>\n')
        for i in range(s, s + per):
            f.write(f'__declspec(noinline) int fn_{i}(int x) {{ return (x * {i + 1}) ^ {i}; }}\n')
print('extra parts written', parts, 'per', per)