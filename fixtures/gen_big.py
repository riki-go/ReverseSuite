# codegen for d.exe: many real functions (no padding)
import sys

def main(count: int, out_path: str) -> None:
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('#include <stdio.h>' + chr(10))
        for i in range(count):
            f.write(f'__declspec(dllexport) int fn_{i}(int x) {{ return (x * {i + 1}) ^ {i}; }}' + chr(10))
        f.write('int main(void) {' + chr(10))
        f.write('  int acc = 0;' + chr(10))
        f.write('  for (int i = 0; i < ' + str(count) + '; i++) acc += (int)(i & 1);' + chr(10))
        f.write('  printf("%d\n", acc);' + chr(10))
        f.write('  return 0;' + chr(10))
        f.write('}' + chr(10))

if __name__ == '__main__':
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    out = sys.argv[2] if len(sys.argv) > 2 else 'src/big.c'
    main(n, out)
