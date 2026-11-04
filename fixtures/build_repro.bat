@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
cl /nologo /Brepro /Zi /Od /Fe:%~dp0out\a_repro1.exe /Fo:%~dp0out\r1\ %~dp0src\prog.c >nul 2>&1
cl /nologo /Brepro /Zi /Od /Fe:%~dp0out\a_repro2.exe /Fo:%~dp0out\r2\ %~dp0src\prog.c >nul 2>&1
exit /b 0
