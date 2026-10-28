@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

call "%~dp0build.bat"
if errorlevel 1 exit /b 1

for /f %%I in ('powershell -NoProfile -Command "[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')"') do set STAMP=%%I
set CANARY=LAB-TRIDENT-SIDELOAD-%STAMP%
set LAB_TRIDENT_CANARY=%CANARY%

set RUN=%~dp0run
if exist "%RUN%" rmdir /s /q "%RUN%"
mkdir "%RUN%"
copy /y "%SystemRoot%\System32\where.exe" "%RUN%\where.exe" >nul
copy /y "%~dp0version_canary.dll" "%RUN%\version.dll" >nul

echo.
echo Canary: %CANARY%
echo Host:   %RUN%\where.exe
echo DLL:    %RUN%\version.dll
echo Marker: %RUN%\%CANARY%.txt
echo UTC:    %STAMP%
echo.

pushd "%RUN%"
where.exe
set EXITCODE=!ERRORLEVEL!
popd

echo.
echo where.exe exit code: !EXITCODE!
echo Marker file:
type "%RUN%\%CANARY%.txt"
echo.
echo Hunt this, after ingest. 15-30 minutes is normal. An empty search in the first few minutes is not a miss.
echo.
echo   canary          %CANARY%
echo   Image           ends with \run\where.exe
echo   ImageLoaded     ends with \run\version.dll
echo   TargetFilename  ends with \%CANARY%.txt
echo   same directory  %RUN%
echo   same window     %STAMP%
echo.
echo Host signature and DLL signature:
powershell -NoProfile -File "%~dp0print-sig.ps1" -HostPath "%RUN%\where.exe" -DllPath "%RUN%\version.dll"
echo.
exit /b 0
