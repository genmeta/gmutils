@echo off

REM Check if parameter is -V
if "%~1"=="-V" if "%~2"=="" (
    REM Execute original ssh -V command
    ssh -V
    goto :EOF
)

REM Call genmeta-ssh and pass all arguments
REM If genmeta ssh fails, fall back to traditional ssh for compatibility
genmeta ssh %*
if errorlevel 1 (
    echo genmeta ssh process failed, falling back to regular ssh... >&2
    ssh %*
)
