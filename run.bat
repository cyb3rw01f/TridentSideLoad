@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

call "%~dp0build.bat"
if errorlevel 1 exit /b 1

for /f %%I in ('powershell -NoProfile -Command "[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')"') do set STAMP=%%I
set CANARY=LAB-TRIDENT-SIDELOAD-%STAMP%
set LAB_TRIDENT_CANARY=%CANARY%

set RUN=%~dp0run\%CANARY%
if exist "%~dp0run" rmdir /s /q "%~dp0run"
mkdir "%RUN%"

rem Stage all three files first. File-create should be cmd.exe, not where.exe.
copy /y "%SystemRoot%\System32\where.exe" "%RUN%\where.exe" >nul
copy /y "%~dp0version_canary.dll" "%RUN%\version.dll" >nul
> "%RUN%\where.dat" echo %CANARY%
>> "%RUN%\where.dat" echo plaintext marker staged before where.exe started

echo.
echo Canary: %CANARY%
echo Host:   %RUN%\where.exe
echo DLL:    %RUN%\version.dll
echo Marker: %RUN%\where.dat
echo UTC:    %STAMP%
echo.
echo Staged where.dat:
type "%RUN%\where.dat"
echo.

pushd "%RUN%"
where.exe
set EXITCODE=!ERRORLEVEL!
popd

echo.
echo where.exe exit code: !EXITCODE!
echo.
echo Hunt this, after ingest. 15-30 minutes is normal. An empty search in the first few minutes is not a miss.
echo.
echo   canary          %CANARY%
echo   Image           ends with \%CANARY%\where.exe
echo   ImageLoaded     ends with \%CANARY%\version.dll
echo   TargetFilename  ends with \%CANARY%\where.dat
echo   file creator    cmd.exe   (the stage, not where.exe)
echo   same directory  %RUN%
echo   same window     %STAMP%
echo.
echo Host signature and DLL signature:
where pwsh >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -File "%~dp0print-sig.ps1" -HostPath "%RUN%\where.exe" -DllPath "%RUN%\version.dll"
) else (
    pwsh -NoProfile -File "%~dp0print-sig.ps1" -HostPath "%RUN%\where.exe" -DllPath "%RUN%\version.dll"
)
echo.
exit /b 0
