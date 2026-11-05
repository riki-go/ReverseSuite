/* spin_v2.c - bounded busy loop for R1 spike. Stops by itself at 150 s. */
#include <windows.h>
#include <stdio.h>

#define MAX_MS 150000ULL

int main(void) {
  ULONGLONG start = GetTickCount64();
  volatile unsigned long long x = 0;
  for (;;) {
    x = x + 1;
    if ((x & 0xFFFFFF) == 0) printf("tick=%llu\n", x);
    if (GetTickCount64() - start > MAX_MS) { printf("self_cap_time_150s\n"); return 3; }
  }
}
