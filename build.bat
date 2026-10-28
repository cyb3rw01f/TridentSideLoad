@echo off
setlocal
cd /d "%~dp0"

where cl >nul 2>&1
if errorlevel 1 (
    if exist "%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
    )
)
where cl >nul 2>&1
if errorlevel 1 (
    echo cl.exe not found. Open an x64 Native Tools prompt for VS 2026 and run build.bat again.
    exit /b 1
)

cl /nologo /LD /O2 /W3 /DUNICODE /D_UNICODE version_canary.cpp /link /DEF:version_canary.def /OUT:version_canary.dll kernel32.lib
if errorlevel 1 exit /b 1
del /q version_canary.obj version_canary.exp version_canary.lib 2>nul
echo Built version_canary.dll
exit /b 0
