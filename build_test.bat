@echo off
echo Building test_timewait...
cl.exe /nologo /std:c++17 /EHsc /O2 test_timewait.cpp /link iphlpapi.lib ws2_32.lib /out:test_timewait.exe
if %errorlevel% equ 0 (
    echo.
    echo Running test_timewait.exe...
    test_timewait.exe
)
