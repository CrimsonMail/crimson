@echo off
setlocal
rem Fuzz a Crimson parser with libFuzzer, which ships with MSVC. See ADR 0013.
rem
rem   scripts\fuzz.cmd imap_lexer          run until stopped with Ctrl+C
rem   scripts\fuzz.cmd imap_lexer 600      run for ten minutes
rem
rem Builds the target (Release, with AddressSanitizer and fuzzer coverage) and
rem runs it. New interesting inputs accumulate in obj\fuzz\<target>\corpus,
rem seeded from the committed inputs, so each run starts where the last one
rem stopped. An input that crashes the target is saved to
rem obj\fuzz\<target>\artifacts and the script exits non-zero.

set "TARGET=%~1"
set "SECONDS=%~2"

if /I "%TARGET%"=="imap_lexer" (
  set "PROJECT=tests\fuzz\Crimson.Fuzz.ImapLexer.vcxproj"
  set "EXE=crimson-fuzz-imap-lexer.exe"
  set "SEEDS=tests\fuzz\corpus\imap_lexer tests\imap\fixtures"
) else if /I "%TARGET%"=="imap_parser" (
  set "PROJECT=tests\fuzz\Crimson.Fuzz.ImapParser.vcxproj"
  set "EXE=crimson-fuzz-imap-parser.exe"
  set "SEEDS=tests\fuzz\corpus\imap_parser tests\fuzz\corpus\imap_lexer tests\imap\fixtures"
) else (
  echo Usage: scripts\fuzz.cmd imap_lexer^|imap_parser [seconds]
  exit /b 2
)

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Could not find vswhere.exe. Is Visual Studio installed?
  exit /b 1
)
set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if "%VSPATH%"=="" (
  echo Visual Studio is installed, but without the C++ toolset. See README.md.
  exit /b 1
)

rem The developer environment also puts the AddressSanitizer runtime DLL on
rem PATH, which the fuzzer needs to start at all.
call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if errorlevel 1 (
  echo Failed to initialise the MSVC environment from "%VSPATH%".
  exit /b 1
)

pushd "%~dp0.."
msbuild "%PROJECT%" /nologo /m /v:minimal /p:Configuration=Release /p:Platform=x64
if errorlevel 1 (
  popd
  exit /b 1
)

set "WORK=obj\fuzz\%TARGET%"
if not exist "%WORK%\corpus" mkdir "%WORK%\corpus"
if not exist "%WORK%\artifacts" mkdir "%WORK%\artifacts"

set "TIME_LIMIT="
if not "%SECONDS%"=="" set "TIME_LIMIT=-max_total_time=%SECONDS%"

rem The first directory is the working corpus libFuzzer writes to; the rest
rem are read-only seeds. -timeout catches hangs, -rss_limit_mb runaway memory.
"x64\Release\%EXE%" "%WORK%\corpus" %SEEDS% -artifact_prefix=%WORK%\artifacts\ %TIME_LIMIT% -timeout=10 -rss_limit_mb=2048 -print_final_stats=1
set "RESULT=%ERRORLEVEL%"
popd

exit /b %RESULT%
