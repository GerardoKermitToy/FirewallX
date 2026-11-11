param(
    [Parameter(Mandatory = $true)][string]$BeforeExe,
    [Parameter(Mandatory = $true)][string]$AfterExe,
    [ValidateRange(1, 50)][int]$Rounds = 9,
    [ValidateRange(1, 10)][int]$Pairs = 3,
    [switch]$WithRuleNames,
    [string]$OutputDirectory = "build-tests/rules-lookup-comparison"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$before = [System.IO.Path]::GetFullPath((Join-Path $root $BeforeExe))
$after = [System.IO.Path]::GetFullPath((Join-Path $root $AfterExe))
$directory = [System.IO.Path]::GetFullPath((Join-Path $root $OutputDirectory))
if (-not (Test-Path $before)) { throw "Baseline executable is missing: $before" }
if (-not (Test-Path $after)) { throw "Optimized executable is missing: $after" }
if (Test-Path $directory) { throw "Comparison directory already exists: $directory" }
New-Item -ItemType Directory -Path $directory | Out-Null

# Чередуем A/B и B/A: генератор и проверка остаются одинаковыми в обоих EXE.
$measurements = @()
$referenceData = $null
$culture = [System.Globalization.CultureInfo]::InvariantCulture
$mode = if ($WithRuleNames) { "baseline_names" } else { "baseline" }
$benchmarkArgs = @("--rounds", $Rounds, "--baseline-only")
if ($WithRuleNames) { $benchmarkArgs += "--with-rule-names" }
for ($pair = 1; $pair -le $Pairs; ++$pair) {
    $order = if ($pair % 2) { @("before", "after") } else { @("after", "before") }
    foreach ($label in $order) {
        $exe = if ($label -eq "before") { $before } else { $after }
        $output = & $exe @benchmarkArgs 2>&1
        $exitCode = $LASTEXITCODE
        $output | Set-Content -Path (Join-Path $directory "$pair-$label.txt") -Encoding UTF8
        if ($exitCode -ne 0) { throw "$label benchmark failed with code $exitCode" }
        $data = @($output | Where-Object { "$_" -like "DATA queries=*" })
        if ($data.Count -ne 1) { throw "Missing workload identity in $label output" }
        if ($null -eq $referenceData) { $referenceData = "$($data[0])" }
        if ("$($data[0])" -ne $referenceData) { throw "Before/after workloads differ" }
        if (-not ($output -contains "VALIDATION queries=1000000 errors=0")) {
            throw "$label did not validate all rule IDs"
        }
        if ($WithRuleNames) {
            if ($referenceData -notmatch '(?:^| )name_chars=(\d+)(?: |$)') {
                throw "Missing reference name length in $label output"
            }
            $expectedNameChars = $Matches[1]
            if (-not ($output -contains "VALIDATION_NAMES queries=1000000 errors=0 name_chars=$expectedNameChars")) {
                throw "$label did not validate all returned names"
            }
        }
        if (-not ($output -contains "PASS scm_calls_during_matching=0 driver_calls=0")) {
            throw "$label accessed a runtime data source during matching"
        }
        $count = 0
        foreach ($line in $output) {
            if ("$line" -notlike "RUN mode=$mode *") { continue }
            $fields = @{}
            foreach ($match in [regex]::Matches("$line", '(\w+)=([^ ]+)')) {
                $fields[$match.Groups[1].Value] = $match.Groups[2].Value
            }
            if ($fields.hits -ne "900000" -or $fields.misses -ne "100000" -or
                $fields.checksum -ne "1168320") { throw "Timed result changed in $label" }
            if ($WithRuleNames -and $fields.name_chars -ne $expectedNameChars) {
                throw "Timed rule name length changed in $label"
            }
            $measurements += [pscustomobject]@{
                variant = $label
                mode = $mode
                pair = $pair
                round = [int]$fields.round
                cpu_ms = [double]::Parse($fields.cpu_ms, $culture)
                wall_ms = [double]::Parse($fields.wall_ms, $culture)
                cycles_per_query = [double]::Parse($fields.cycles_per_query, $culture)
            }
            ++$count
        }
        if ($count -ne $Rounds) { throw "Incomplete timed series for $label" }
        $output | Where-Object { "$_" -like "SUMMARY *" } | ForEach-Object {
            Write-Output "PAIR=$pair VARIANT=$label $_"
        }
    }
}

$measurements | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $directory "measurements.json") -Encoding UTF8
$summary = @($referenceData, "Mode: $mode", "Alternating order: A/B, B/A; rounds per variant: $($Rounds * $Pairs)")
foreach ($label in @("before", "after")) {
    $rows = @($measurements | Where-Object { $_.variant -eq $label })
    $fields = @()
    foreach ($metric in @("cpu_ms", "wall_ms", "cycles_per_query")) {
        $values = @($rows | ForEach-Object { $_.$metric } | Sort-Object)
        $middle = [int][Math]::Floor($values.Count / 2)
        $median = $values[$middle]
        if ($values.Count % 2 -eq 0) { $median = ($values[$middle - 1] + $median) / 2 }
        $fields += "$metric median=$($median.ToString('F3', $culture)) min=$($values[0].ToString('F3', $culture)) max=$($values[-1].ToString('F3', $culture))"
    }
    $summary += "$label : $($fields -join '; ')"
}
$summary | Set-Content (Join-Path $directory "summary.txt") -Encoding UTF8
$summary | Write-Output
