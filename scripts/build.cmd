@echo off
setlocal
rem Build Crimson without needing the "x64 Native Tools" Start menu shortcut.
rem
rem   scripts\build.cmd                  Debug
rem   scripts\build.cmd Release
rem   scripts\build.cmd Debug asan       Debug with AddressSanitizer
rem
rem Locates Visual Studio with vswhere, which ships with every installation at a
rem fixed path, so no environment setup is assumed and no toolset version is
rem hardcoded.

set "CONFIGURATION=%~1"
if "%CONFIGURATION%"=="" set "CONFIGURATION=Debug"

set "EXTRA="
if /I "%~2"=="asan" set "EXTRA=/p:EnableASAN=true /t:Rebuild"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Could not find vswhere.exe. Is Visual Studio installed?
  echo See README.md for the required workload.
  exit /b 1
)

set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"

if "%VSPATH%"=="" (
  echo Visual Studio is installed, but without the C++ toolset.
  echo Install the "Desktop development with C++" workload; see README.md.
  exit /b 1
)

call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if errorlevel 1 (
  echo Failed to initialise the MSVC environment from "%VSPATH%".
  exit /b 1
)

pushd "%~dp0.."
msbuild Crimson.sln /nologo /m /v:minimal /p:Configuration=%CONFIGURATION% /p:Platform=x64 %EXTRA%
set "RESULT=%ERRORLEVEL%"
popd

exit /b %RESULT%
