/* spawner_v2.c - bounded child spawner for R1 spike.
 * Creates at most 3 children sequentially (cmd.exe /c exit 0), waits <= 2 s each.
 * exit 0 = all spawned, 5 = partial, 6 = none. */
#include <windows.h>
#include <stdio.h>

#define MAX_CHILDREN 3

int main(void) {
  int ok = 0;
  ULONGLONG start = GetTickCount64();
  for (int i = 0; i < MAX_CHILDREN; i++) {
    STARTUPINFOA si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    char cmd[] = "C:\\Windows\\System32\\cmd.exe /c exit 0";
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
      printf("child_spawned=%lu\n", pi.dwProcessId);
      WaitForSingleObject(pi.hProcess, 2000);
      CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
      ok++;
    } else {
      printf("child_spawn_failed=%lu\n", GetLastError());
    }
    if (GetTickCount64() - start > 10000) { printf("helper_cap_total_time\n"); break; }
  }
  if (ok == MAX_CHILDREN) return 0;
  if (ok > 0) return 5;
  return 6;
}
