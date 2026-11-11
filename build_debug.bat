@echo off
setlocal

echo ========================================
echo FirewallX - Quick Debug Build
echo ========================================
echo.

where cmake >nul 2>&1
if errorlevel 1 (
    echo [ERROR] CMake not found in PATH
    pause
    exit /b 1
)

if not exist build\CMakeCache.txt (
    echo [1/2] Generating Visual Studio project...
    cmake -S . -B build -G "Visual Studio 18 2026" -A x64
    if errorlevel 1 (
        echo [ERROR] Project generation failed
        pause
        exit /b 1
    )
    echo.
) else (
    echo [1/2] Project already generated, skipping...
    echo.
)

echo [2/2] Building Debug configuration...
cmake --build build --config Debug
if errorlevel 1 (
    echo.
    echo [ERROR] Build failed
    pause
    exit /b 1
)

echo.
echo ========================================
echo [SUCCESS] Debug build completed!
echo ========================================
echo Executable: build\Debug\FirewallX.exe
echo.

if exist build\Debug\FirewallX.exe (
    for %%A in (build\Debug\FirewallX.exe) do echo Size: %%~zA bytes
)

echo.
pause
