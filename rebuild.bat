@echo off
setlocal

echo ========================================
echo FirewallX - Full Rebuild
echo ========================================
echo.
echo This will remove build directory and
echo rebuild the project from scratch.
echo.

set /p config="Choose configuration (1=Release, 2=Debug) [1]: "
if "%config%"=="" set config=1

if "%config%"=="1" (
    set BUILD_CONFIG=Release
) else if "%config%"=="2" (
    set BUILD_CONFIG=Debug
) else (
    echo Invalid choice
    pause
    exit /b 1
)

echo.
echo Configuration: %BUILD_CONFIG%
echo.

if exist build (
    echo [1/3] Cleaning old build...
    rd /s /q build
    if exist build (
        echo [ERROR] Failed to remove build directory
        pause
        exit /b 1
    )
)

echo [2/3] Generating Visual Studio project...
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
if errorlevel 1 (
    echo [ERROR] Project generation failed
    pause
    exit /b 1
)

echo.
echo [3/3] Building %BUILD_CONFIG%...
cmake --build build --config %BUILD_CONFIG%
if errorlevel 1 (
    echo.
    echo [ERROR] Build failed
    pause
    exit /b 1
)

echo.
echo ========================================
echo [SUCCESS] Rebuild completed!
echo ========================================
echo Executable: build\%BUILD_CONFIG%\FirewallX.exe
echo.

if exist build\%BUILD_CONFIG%\FirewallX.exe (
    for %%A in (build\%BUILD_CONFIG%\FirewallX.exe) do echo Size: %%~zA bytes
)

echo.
pause
