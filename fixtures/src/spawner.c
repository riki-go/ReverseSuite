#include <windows.h>
#include <stdio.h>
int main(void) { STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0}; si.cb = sizeof(si);
  if (CreateProcessA(NULL, (LPSTR)"C:\\Windows\\System32\\cmd.exe /c exit 0", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    printf("child_spawned=%lu\n", pi.dwProcessId); WaitForSingleObject(pi.hProcess, 2000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
  else { printf("child_spawn_failed=%lu\n", GetLastError()); }
  Sleep(3000); return 0; }
