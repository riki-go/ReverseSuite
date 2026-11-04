@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 1
cl /nologo /Zi /Od /Fe:%~dp0out\a.exe /Fo:%~dp0out\ %~dp0src\prog.c
if errorlevel 1 exit /b 1
cl /nologo /Od /Fe:%~dp0out\b.exe /Fo:%~dp0out\ %~dp0src\prog.c
if errorlevel 1 exit /b 1
cl /nologo /Fe:%~dp0out\memhog.exe /Fo:%~dp0out\ %~dp0src\memhog.c
cl /nologo /Fe:%~dp0out\spin.exe /Fo:%~dp0out\ %~dp0src\spin.c
cl /nologo /Fe:%~dp0out\spawner.exe /Fo:%~dp0out\ %~dp0src\spawner.c
exit /b 0
