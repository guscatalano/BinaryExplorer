<#
.SYNOPSIS
  Capture README screenshots of BinaryExplorer automatically.

.DESCRIPTION
  Writes a request file to the user profile, launches the app, and waits for it
  to finish. In screenshot mode the app loads the sample binary, walks a curated
  set of pages rendering each to a PNG (via RenderTargetBitmap), writes a .done
  file, then exits.

  A file marker is used (not an env var or CLI arg) because packaged-app
  activation inherits neither.

.PARAMETER OutputDir
  Folder for the PNGs. Default: <repo>\screenshots.

.PARAMETER Sample
  Binary to load and inspect. Default: C:\Windows\System32\notepad.exe.

.EXAMPLE
  pwsh ./take-screenshots.ps1
  pwsh ./take-screenshots.ps1 -Sample C:\Windows\System32\shell32.dll
#>
[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path $PSScriptRoot 'screenshots'),
    [string]$Sample = 'C:\Windows\System32\notepad.exe'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Sample)) { throw "Sample binary not found: $Sample" }

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Get-ChildItem $OutputDir -Filter *.png -ErrorAction SilentlyContinue | Remove-Item -Force
Remove-Item (Join-Path $OutputDir 'error.txt') -ErrorAction SilentlyContinue

$request = Join-Path $env:USERPROFILE '.binexp-screenshots.json'
$done    = Join-Path $env:USERPROFILE '.binexp-screenshots.done'
Remove-Item $request, $done -ErrorAction SilentlyContinue

# Close any running instance so a clean screenshot-mode window starts.
Get-Process BinaryExplorer -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

$req = [ordered]@{ outputDir = $OutputDir; sample = $Sample }

# The MSI page needs a real installer database — pass our own built MSI if present.
$msi = Get-ChildItem (Join-Path $PSScriptRoot 'artifacts') -Filter *.msi -ErrorAction SilentlyContinue |
       Sort-Object Length -Descending | Select-Object -First 1
if ($msi) { $req['msiSample'] = $msi.FullName }

[pscustomobject]$req | ConvertTo-Json | Set-Content -Path $request -Encoding UTF8

Write-Host "Launching BinaryExplorer in screenshot mode..." -ForegroundColor Cyan
Write-Host "  output: $OutputDir"
Write-Host "  sample: $Sample"
if ($msi) { Write-Host "  msi:    $($msi.FullName)" }
dotnet build (Join-Path $PSScriptRoot 'BinaryExplorer.csproj') -c Debug -p:Platform=x64 --nologo -v quiet
dotnet run --project (Join-Path $PSScriptRoot 'BinaryExplorer.csproj') -p:Platform=x64 --no-build

# The app detaches; wait for the .done file it writes when finished.
$deadline = (Get-Date).AddMinutes(4)
while (-not (Test-Path $done) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }

if (-not (Test-Path $done)) {
    Remove-Item $request -ErrorAction SilentlyContinue
    throw "Timed out waiting for screenshot run to finish."
}

$status = (Get-Content $done -Raw).Trim()
Remove-Item $request, $done -ErrorAction SilentlyContinue

if ($status -ne 'ok') {
    Write-Host "Screenshot run failed:" -ForegroundColor Red
    Write-Host $status
    exit 1
}

$shots = Get-ChildItem $OutputDir -Filter *.png | Sort-Object Name
Write-Host "Done - $($shots.Count) screenshot(s):" -ForegroundColor Green
$shots | ForEach-Object { Write-Host ("  {0}  ({1:N0} KB)" -f $_.Name, ($_.Length / 1KB)) }
