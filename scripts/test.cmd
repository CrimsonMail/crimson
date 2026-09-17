@echo off
setlocal
rem Run the Crimson test suite.
rem
rem   scripts\test.cmd                   all tests, Debug
rem   scripts\test.cmd Debug tcp_stream  only tests matching a substring
rem   scripts\test.cmd Release
rem
rem Runs inside the MSVC environment on purpose. An AddressSanitizer build links
rem against a runtime DLL that lives in the toolset directory, so without it the
rem tests fail to load with a message about a missing api-ms-win DLL rather than
rem anything resembling a sanitizer report.

set "CONFIGURATION=%~1"
if "%CONFIGURATION%"=="" set "CONFIGURATION=Debug"

set "FILTER=%~2"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Could not find vswhere.exe. Is Visual Studio installed?
  exit /b 1
)

set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"

if "%VSPATH%"=="" (
  echo Visual Studio is installed, but without the C++ toolset.
  exit /b 1
)

call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

set "TESTS=%~dp0..\x64\%CONFIGURATION%\Crimson.Tests.exe"
if not exist "%TESTS%" (
  echo Not built yet: "%TESTS%"
  echo Run scripts\build.cmd %CONFIGURATION% first.
  exit /b 1
)

call "%TESTS%" %FILTER%
exit /b %ERRORLEVEL%
