#include <windows.h>
#include <stdio.h>
int main(void) {
  size_t chunk = 64u * 1024u * 1024u; int i = 0;
  for (;;) { void* p = VirtualAlloc(NULL, chunk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) { printf("alloc_failed_at=%d\n", i); return 2; }
    memset(p, 0x41, chunk); i++; if (i % 4 == 0) printf("allocated_mb=%zu\n", (size_t)i * 64);
    Sleep(50); } }
