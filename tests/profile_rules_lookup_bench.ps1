param(
    [ValidateRange(5, 300)][int]$Seconds = 30,
    [string]$BuildDirectory = "build-tests",
    [string]$OutputDirectory = "rules-lookup-profile"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$build = [System.IO.Path]::GetFullPath((Join-Path $root $BuildDirectory))
$xperf = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Windows Performance Toolkit\xperf.exe"
$exe = Join-Path $build "Release\rules_lookup_bench.exe"
$directory = Join-Path $build $OutputDirectory
$raw = Join-Path $directory "kernel.etl"
$trace = Join-Path $directory "cpu.etl"

if (-not (Test-Path $xperf)) { throw "Windows Performance Toolkit xperf.exe is required" }
if (-not (Test-Path $exe)) { throw "Build the Release rules_lookup_bench target first" }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "An elevated process is required for ETW CPU sampling"
}

# Не останавливаем чужой сеанс и не перезаписываем результаты предыдущего профиля.
$loggers = & $xperf -loggers 2>&1 | Out-String
if ($loggers -match '(?m)^Logger Name\s*:\s*NT Kernel Logger\s*$') {
    throw "NT Kernel Logger is already in use; leave that recording untouched"
}
if (Test-Path $directory) { throw "Profile output directory already exists: $directory" }
New-Item -ItemType Directory -Path $directory | Out-Null
Copy-Item -Path $exe, (Join-Path $build "Release\rules_lookup_bench.pdb") -Destination $directory

$started = $false
try {
    & $xperf -on PROC_THREAD+LOADER+PROFILE -stackwalk Profile -BufferSize 1024 -MinBuffers 32 -MaxBuffers 128 -f $raw
    if ($LASTEXITCODE -ne 0) { throw "Starting ETW failed with code $LASTEXITCODE" }
    $started = $true
    & $exe --profile-seconds $Seconds 2>&1 | Tee-Object (Join-Path $directory "run.txt")
    if ($LASTEXITCODE -ne 0) { throw "Benchmark failed with code $LASTEXITCODE" }
} finally {
    if ($started) {
        & $xperf -d $trace
        if ($LASTEXITCODE -ne 0) { Write-Warning "Stopping/merging ETW failed with code $LASTEXITCODE" }
    }
}

# Только локальные символы: исходники и адреса не отправляются на внешний сервер.
$env:_NT_SYMBOL_PATH = $directory + ";" + (Join-Path $build "Release") + ";C:\symbols"
$env:_NT_SYMCACHE_PATH = Join-Path $directory "symcache"
$env:_NT_SOURCE_PATH = $root
& $xperf -i $trace -symbols -o (Join-Path $directory "functions.txt") -a profile -detail
if ($LASTEXITCODE -ne 0) { throw "Function report failed with code $LASTEXITCODE" }

$run = Get-Content (Join-Path $directory "run.txt") -Raw
if ($run -notmatch 'PROFILE_BEGIN pid=(\d+) tid=(\d+)') { throw "Profile worker identity is missing" }
$workerId = $Matches[2]
& $xperf -i $trace -symbols -o (Join-Path $directory "stacks.txt") -a stack -butterfly 1 -tid $workerId
if ($LASTEXITCODE -ne 0) { throw "Stack report failed with code $LASTEXITCODE" }
& $xperf -i $trace -o (Join-Path $directory "trace-stats.txt") -a tracestats
Write-Output "Profile reports: $directory"
