[CmdletBinding()]
param(
    [string]$IsccPath,
    [string]$Publisher = 'LANORA',
    [string]$CertificateThumbprint,
    [string]$SignToolPath,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'Run this script on Windows.' }
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'src\Lanora\Lanora.csproj'
[xml]$projectXml = Get-Content -LiteralPath $project
$version = [string](@($projectXml.Project.PropertyGroup | Where-Object { $_.SelectSingleNode('Version') })[0].Version)
if ($version -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') { throw "Invalid installer version: $version" }
if ($Publisher -match '[\r\n"]') { throw 'Publisher must not contain quotes or newlines.' }
$publish = Join-Path $root "dist\Lanora-$version-win-x64"
$output = Join-Path $root 'dist\installer'
if (-not $IsccPath) {
    $compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($compiler) { $IsccPath = $compiler.Source }
    else {
        foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
            if (-not $base) { continue }
            foreach ($major in @(7, 6)) {
                $candidate = Join-Path $base "Inno Setup $major\ISCC.exe"
                if (Test-Path -LiteralPath $candidate) { $IsccPath = $candidate; break }
            }
            if ($IsccPath) { break }
        }
    }
}
if (-not $IsccPath -or -not (Test-Path -LiteralPath $IsccPath)) {
    throw 'Install Inno Setup (with its preprocessor), or pass -IsccPath.'
}
if ($CertificateThumbprint -and -not $SignToolPath) {
    $tool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($tool) { $SignToolPath = $tool.Source }
    else { throw 'Pass -SignToolPath from the Windows SDK for a signed build.' }
}
if (Test-Path -LiteralPath $publish) { Remove-Item -LiteralPath $publish -Recurse -Force }
New-Item -ItemType Directory -Force -Path $publish, $output | Out-Null
& dotnet publish $project -c Release -r win-x64 --self-contained true -o $publish --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed: $LASTEXITCODE" }

# Console launcher for the "lanora" command (NativeAOT, needs the Visual Studio C++ build tools). It is published to its
# own folder first: as "lanora.exe" it would overwrite Lanora.exe (file names are case-insensitive on Windows).
$launcherProject = Join-Path $root 'src\Lanora.Launcher\Lanora.Launcher.csproj'
[xml]$launcherXml = Get-Content -LiteralPath $launcherProject
$launcherVersion = [string](@($launcherXml.Project.PropertyGroup | Where-Object { $_.SelectSingleNode('Version') })[0].Version)
if ($launcherVersion -ne $version) { throw "Launcher version $launcherVersion does not match LANORA $version." }
$launcherOut = Join-Path $root 'dist\launcher'
if (Test-Path -LiteralPath $launcherOut) { Remove-Item -LiteralPath $launcherOut -Recurse -Force }
$vsInstaller = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
if ((Test-Path -LiteralPath $vsInstaller) -and -not (Get-Command vswhere.exe -ErrorAction SilentlyContinue)) { $env:PATH = "$vsInstaller;$env:PATH" }
& dotnet publish $launcherProject -c Release -r win-x64 -o $launcherOut --nologo
if ($LASTEXITCODE -ne 0) { throw "launcher publish failed: $LASTEXITCODE" }
Copy-Item -LiteralPath (Join-Path $launcherOut 'lanora.exe') -Destination (Join-Path $publish 'lanora.com') -Force
Copy-Item -LiteralPath (Join-Path $root 'README.md'), (Join-Path $root 'THIRD-PARTY-NOTICES.md') -Destination $publish
$license = Join-Path $root 'LICENSE'
if (Test-Path -LiteralPath $license) { Copy-Item -LiteralPath $license -Destination $publish }
$argsList = @("/DMyAppVersion=$version", "/DPublishDir=$publish", "/DInstallerDir=$output", "/DMyAppPublisher=$Publisher")
$oldCert = $env:LANORA_CERT_THUMBPRINT
$oldTimestamp = $env:LANORA_TIMESTAMP_URL
$oldTool = $env:LANORA_SIGNTOOL
try {
    if ($CertificateThumbprint) {
        $env:LANORA_CERT_THUMBPRINT = $CertificateThumbprint
        $env:LANORA_TIMESTAMP_URL = $TimestampUrl
        $env:LANORA_SIGNTOOL = $SignToolPath
        & (Join-Path $PSScriptRoot 'Sign-File.ps1') -FilePath (Join-Path $publish 'Lanora.exe')
        # The launcher is signed under its .exe name (signtool picks the signature format by file type) and copied again.
        & (Join-Path $PSScriptRoot 'Sign-File.ps1') -FilePath (Join-Path $launcherOut 'lanora.exe')
        Copy-Item -LiteralPath (Join-Path $launcherOut 'lanora.exe') -Destination (Join-Path $publish 'lanora.com') -Force
        $signScript = Join-Path $PSScriptRoot 'Sign-File.ps1'
        # $f and $q are expanded by Inno Setup, not by PowerShell.
        $signCommand = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File $q' + $signScript + '$q -FilePath $f'
        $argsList += '/DEnableSigning'
        $argsList += '/Slanora=' + $signCommand
    }
    $argsList += Join-Path $PSScriptRoot 'Lanora.iss'
    & $IsccPath @argsList
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed: $LASTEXITCODE" }
    $installer = Join-Path $output "Lanora-$version-Setup-x64.exe"
    if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Installer output is missing.' }
    if ($CertificateThumbprint) { & $SignToolPath verify /pa /all /v $installer; if ($LASTEXITCODE -ne 0) { throw 'Installer signature verification failed.' } }
    else { Write-Warning 'Unsigned build: Windows may show Unknown publisher or SmartScreen warnings.' }
    $portable = Join-Path $output "Lanora-$version-Portable-x64.zip"
    Compress-Archive -Path (Join-Path $publish '*') -DestinationPath $portable -Force
    $hashLines = foreach ($file in @($installer, $portable)) {
        $hash = Get-FileHash -LiteralPath $file -Algorithm SHA256
        '{0}  {1}' -f $hash.Hash.ToLowerInvariant(), (Split-Path -Leaf $file)
    }
    $hashLines | Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS.txt') -Encoding ascii
    Write-Host "Installer: $installer"
    Write-Host "Portable:  $portable"
}
finally {
    $env:LANORA_CERT_THUMBPRINT = $oldCert
    $env:LANORA_TIMESTAMP_URL = $oldTimestamp
    $env:LANORA_SIGNTOOL = $oldTool
}
