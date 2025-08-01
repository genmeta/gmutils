@echo off

REM Check if parameter is -V
if "%~1"=="-V" if "%~2"=="" (
    REM Execute original ssh -V command
    ssh -V
    goto :EOF
)

REM Call genmeta-ssh3 and pass all arguments
REM If genmeta ssh3 fails, fall back to traditional ssh for compatibility
genmeta ssh3 %*
if errorlevel 1 (
    echo Custom ssh process failed, falling back to regular ssh... >&2
    ssh %*
)
