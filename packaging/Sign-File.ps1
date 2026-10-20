[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [string]$CertificateThumbprint = $env:LANORA_CERT_THUMBPRINT,
    [string]$TimestampUrl = $env:LANORA_TIMESTAMP_URL,
    [string]$SignToolPath = $env:LANORA_SIGNTOOL
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $CertificateThumbprint -or -not $TimestampUrl -or -not $SignToolPath) {
    throw 'Signing requires CertificateThumbprint, TimestampUrl and SignToolPath.'
}
if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { throw "Missing file: $FilePath" }
# The private key stays in its certificate provider (for example a token/HSM).
& $SignToolPath sign /sha1 $CertificateThumbprint /s My /fd SHA256 /tr $TimestampUrl /td SHA256 /d 'LANORA' $FilePath
if ($LASTEXITCODE -ne 0) { throw "SignTool signing failed: $LASTEXITCODE" }
& $SignToolPath verify /pa /all /v $FilePath
if ($LASTEXITCODE -ne 0) { throw "Signature verification failed: $LASTEXITCODE" }
