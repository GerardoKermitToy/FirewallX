@echo off
setlocal

echo ========================================
echo FirewallX - Clean build directory
echo ========================================
echo.

if not exist build (
    echo Build directory does not exist.
    echo Nothing to clean.
    pause
    exit /b 0
)

echo This will remove the entire build directory.
echo.
set /p confirm="Continue? (y/N): "

if /i not "%confirm%"=="y" (
    echo Cancelled.
    pause
    exit /b 0
)

echo.
echo Removing build...
rd /s /q build

if exist build (
    echo [ERROR] Failed to remove build directory
    pause
    exit /b 1
)

echo [SUCCESS] Build directory cleaned
echo.
pause
