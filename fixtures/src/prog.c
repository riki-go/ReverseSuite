#include <stdio.h>
int helper_add(int a, int b) { return a + b; }
int helper_mul(int a, int b) { return a * b; }
int helper_clamp(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }
static int internal_step(int x) { return helper_clamp(helper_add(x, 3), 0, 1000); }
__declspec(dllexport) int compute(int x) { int r = internal_step(x); r = helper_mul(r, 2); return r; }
__declspec(dllexport) int compute2(int x) { return compute(x) + helper_add(x, 1); }
int main(void) { printf("%d%c", compute(5), 10); return 0; }
