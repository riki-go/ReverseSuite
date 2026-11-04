#include <stdio.h>
int main(void) { volatile unsigned long long x = 0; for (;;) { x = x + 1; if ((x & 0xFFFFFF) == 0) printf("tick=%llu\n", x); } }
