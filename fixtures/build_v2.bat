@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
cl /nologo /Fe:%~dp0out\memhog_v2.exe /Fo:%~dp0out\ %~dp0src\memhog_v2.c
cl /nologo /Fe:%~dp0out\spin_v2.exe /Fo:%~dp0out\ %~dp0src\spin_v2.c
cl /nologo /Fe:%~dp0out\spawner_v2.exe /Fo:%~dp0out\ %~dp0src\spawner_v2.c
exit /b 0
