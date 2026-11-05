/* memhog_v2.c - bounded memory hog for R1 spike.
 * Self caps: <= 1024 MB total, <= 60 s wall clock.
 * exit 0 = reached cap normally, 2 = allocation failed early, 3 = self cap hit (mem or time).
 * v1 (frozen/memhog.exe) has no caps and is marked do_not_run. */
#include <windows.h>
#include <stdio.h>

#define CHUNK ((size_t)64 * 1024 * 1024)
#define MAX_CHUNKS 16
#define MAX_MS 60000ULL

int main(void) {
  ULONGLONG start = GetTickCount64();
  size_t total = 0;
  for (int i = 0; i < MAX_CHUNKS; i++) {
    void* p = VirtualAlloc(NULL, CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) { printf("alloc_failed at %d MB\n", (int)(total >> 20)); return 2; }
    memset(p, 0x41, CHUNK);
    total += CHUNK;
    printf("allocated_mb=%zu\n", total >> 20);
    if (GetTickCount64() - start > MAX_MS) { printf("self_cap_time\n"); return 3; }
    Sleep(50);
  }
  printf("self_cap_memory=%zu MB\n", total >> 20);
  return 3;
}
