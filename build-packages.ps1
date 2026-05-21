<#
.SYNOPSIS
  Build the BinaryExplorer MSIX and MSI installers locally.

.DESCRIPTION
  Mirrors the .github/workflows/release.yml steps so packages can be produced
  and tested on a developer machine.

  - MSIX: built via the single-project MSIX tooling, signed with a self-signed
    test certificate whose subject matches the package Publisher. The matching
    .cer is exported so the
    package can be trusted before install.
  - MSI:  built from an unpackaged, self-contained publish folder using WiX v5.

.PARAMETER Platform
  x64 (default) or ARM64.

.PARAMETER Version
  4-part product version. Default 1.0.0.0.

.PARAMETER SkipMsix
  Skip the MSIX build.

.PARAMETER SkipMsi
  Skip the MSI build.

.EXAMPLE
  pwsh ./build-packages.ps1 -Platform x64 -Version 1.0.0.0
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'ARM64')]
    [string]$Platform = 'x64',

    [string]$Version = '1.0.0.0',

    [switch]$SkipMsix,
    [switch]$SkipMsi
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$artifacts = Join-Path $root 'artifacts'
$rid = if ($Platform -eq 'ARM64') { 'win-arm64' } else { 'win-x64' }
$arch = if ($Platform -eq 'ARM64') { 'arm64' } else { 'x64' }

New-Item -ItemType Directory -Force -Path $artifacts | Out-Null

function Find-SignTool {
    $kits = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (-not (Test-Path $kits)) { return $null }
    Get-ChildItem $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Sort-Object FullName | Select-Object -Last 1 -ExpandProperty FullName
}

if (-not $SkipMsix) {
    Write-Host "==> Building MSIX ($Platform)" -ForegroundColor Cyan

    $pfx = Join-Path $artifacts 'BinaryExplorer-test.pfx'
    $cer = Join-Path $artifacts "BinaryExplorer-$Platform.cer"
    $cert = Get-ChildItem 'Cert:\CurrentUser\My' |
        Where-Object { $_.Subject -eq 'CN=119E0257-3B74-437C-A728-AC7C50256853' } | Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Type Custom -Subject 'CN=119E0257-3B74-437C-A728-AC7C50256853' `
            -KeyUsage DigitalSignature -FriendlyName 'BinaryExplorer test' `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
    }
    $pwd = ConvertTo-SecureString -String 'BinExpl0rer!' -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pwd | Out-Null
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null

    # Build the package unsigned, then sign explicitly with signtool — the in-build
    # PackageCertificateKeyFile import is unreliable with password-protected PFX files.
    dotnet build (Join-Path $root 'BinaryExplorer.csproj') `
        -c Release `
        -p:Platform=$Platform `
        -p:GenerateAppxPackageOnBuild=true `
        -p:AppxPackageDir="$artifacts\msix\" `
        -p:UapAppxPackageBuildMode=SideloadOnly `
        -p:AppxBundle=Never `
        -p:AppxPackageSigningEnabled=false
    if ($LASTEXITCODE -ne 0) { throw "MSIX build failed." }

    $msix = Get-ChildItem "$artifacts\msix" -Recurse -Filter 'BinaryExplorer*.msix' |
        Select-Object -First 1
    if (-not $msix) { throw "No MSIX package was produced." }

    $signtool = Find-SignTool
    if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK)." }
    & $signtool sign /fd SHA256 /f $pfx /p 'BinExpl0rer!' $msix.FullName
    if ($LASTEXITCODE -ne 0) { throw "MSIX signing failed." }

    # The MSIX needs its dependency runtimes + Install.ps1 — zip the whole sideload folder.
    $zip = Join-Path $artifacts "BinaryExplorer-$Platform-msix.zip"
    Compress-Archive -Path (Join-Path $msix.Directory.FullName '*') -DestinationPath $zip -Force

    Write-Host "MSIX signed: $($msix.FullName)" -ForegroundColor Green
    Write-Host "MSIX bundle zipped: $zip" -ForegroundColor Green
}

if (-not $SkipMsi) {
    Write-Host "==> Publishing unpackaged build ($Platform)" -ForegroundColor Cyan
    $publishDir = Join-Path $artifacts "publish-$Platform"

    dotnet publish (Join-Path $root 'BinaryExplorer.csproj') `
        -c Release `
        -p:Platform=$Platform `
        -r $rid `
        --self-contained `
        -p:WindowsPackageType=None `
        -p:WindowsAppSDKSelfContained=true `
        -p:GenerateAppxPackageOnBuild=false `
        -o $publishDir
    if ($LASTEXITCODE -ne 0) { throw "Publish failed." }

    if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
        Write-Host "==> Installing WiX 5" -ForegroundColor Cyan
        dotnet tool install --global wix --version 5.0.2
        $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
    }

    Write-Host "==> Building MSI ($Platform)" -ForegroundColor Cyan
    $msi = Join-Path $artifacts "BinaryExplorer-$Platform.msi"
    wix build (Join-Path $root 'installer\BinaryExplorer.wxs') `
        -d PublishDir=$publishDir `
        -d Version=$Version `
        -arch $arch `
        -o $msi
    if ($LASTEXITCODE -ne 0) { throw "MSI build failed." }
    Write-Host "MSI written to $msi" -ForegroundColor Green
}

Write-Host "Done." -ForegroundColor Green
