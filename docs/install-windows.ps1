<#
.SYNOPSIS
    Installs bw-agent for the current user on Windows: the binaries, the
    browser native-messaging host, and a logon entry that starts the agent
    in the background. Nothing here needs administrator rights.

.EXAMPLE
    cargo build --release -p bw-agent
    powershell -ExecutionPolicy Bypass -File docs\install-windows.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File docs\install-windows.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    # Directory holding bw-agent.exe, bw-agentw.exe and bw-proxy.exe.
    [string]$Source = (Join-Path $PSScriptRoot '..\target\release'),
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\bw-agent'),
    [string]$ChromeId = 'nngceckbapebfimnlniiiahkandclblb',
    [string]$EdgeId = 'jbkfoedolllekgbhcbcoahefnbanhhlh',
    [string]$FirefoxId = '{446900e4-71c2-419f-a6a7-df9c091e268b}',
    [switch]$NoAutostart,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

$HostName = 'com.8bit.bitwarden'
$Binaries = @('bw-agent.exe', 'bw-agentw.exe', 'bw-proxy.exe')
$ChromiumManifest = Join-Path $Prefix "$HostName.chromium.json"
$FirefoxManifest = Join-Path $Prefix "$HostName.firefox.json"
$HostKeys = [ordered]@{
    'HKCU:\Software\Google\Chrome\NativeMessagingHosts'                 = $ChromiumManifest
    'HKCU:\Software\Chromium\NativeMessagingHosts'                      = $ChromiumManifest
    'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts'                = $ChromiumManifest
    'HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts'   = $ChromiumManifest
    'HKCU:\Software\Mozilla\NativeMessagingHosts'                       = $FirefoxManifest
}
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunName = 'bw-agent'

function Stop-Agent {
    Get-Process -Name 'bw-agentw', 'bw-agent' -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase) } |
        Stop-Process -Force
}

function Get-HostTarget([string]$Key) {
    $path = Join-Path $Key $HostName
    if (Test-Path $path) { return (Get-Item $path).GetValue('') }
    return $null
}

function Write-Json([string]$Path, $Object) {
    # .NET writes UTF-8 without a BOM, which browsers require.
    [IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth 4))
}

if ($Uninstall) {
    Stop-Agent
    foreach ($key in $HostKeys.Keys) {
        $target = Get-HostTarget $key
        if ($target -and $target.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item (Join-Path $key $HostName) -Recurse
            Write-Host "  removed $key\$HostName"
        }
    }
    Remove-ItemProperty -Path $RunKey -Name $RunName -ErrorAction SilentlyContinue
    if (Test-Path $Prefix) { Remove-Item $Prefix -Recurse -Force }
    Write-Host "uninstalled. Enrollment state is kept in $env:LOCALAPPDATA\bw-agent;"
    Write-Host "run 'bw-agent remove' before uninstalling to delete it."
    return
}

foreach ($bin in $Binaries) {
    if (-not (Test-Path (Join-Path $Source $bin))) {
        throw "$bin not found in $Source; build with 'cargo build --release -p bw-agent' or pass -Source"
    }
}

Stop-Agent
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
foreach ($bin in $Binaries) {
    Copy-Item (Join-Path $Source $bin) (Join-Path $Prefix $bin) -Force
}
Write-Host "installed binaries to $Prefix"

$proxy = Join-Path $Prefix 'bw-proxy.exe'
$description = 'Bitwarden browser <-> bw-agent bridge'
Write-Json $ChromiumManifest ([ordered]@{
    name            = $HostName
    description     = $description
    path            = $proxy
    type            = 'stdio'
    allowed_origins = @("chrome-extension://$ChromeId/", "chrome-extension://$EdgeId/")
})
Write-Json $FirefoxManifest ([ordered]@{
    name               = $HostName
    description        = $description
    path               = $proxy
    type               = 'stdio'
    allowed_extensions = @($FirefoxId)
})

foreach ($key in $HostKeys.Keys) {
    $manifest = $HostKeys[$key]
    $previous = Get-HostTarget $key
    if ($previous -and $previous -ne $manifest) {
        Write-Warning "$key\$HostName pointed at $previous (Bitwarden Desktop?); replacing it"
    }
    New-Item -Path (Join-Path $key $HostName) -Value $manifest -Force | Out-Null
    Write-Host "  $key\$HostName -> $manifest"
}

$agentw = Join-Path $Prefix 'bw-agentw.exe'
if (-not $NoAutostart) {
    Set-ItemProperty -Path $RunKey -Name $RunName -Value "`"$agentw`""
    Write-Host "bw-agent will start at logon"
}

$enrolled = Test-Path (Join-Path $env:LOCALAPPDATA 'bw-agent\blob')
if ($enrolled) {
    Start-Process $agentw
    Write-Host "bw-agent started; restart the browser to pick up the native-messaging host"
} else {
    Write-Host ''
    Write-Host 'next, enroll this device:'
    Write-Host "  & '$(Join-Path $Prefix 'bw-agent.exe')' enroll --email <email> --server <host:port> --token <token>"
    Write-Host "then start it with: Start-Process '$agentw' (or log off and on)"
}
