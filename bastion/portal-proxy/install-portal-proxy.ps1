#Requires -Version 5.1
<#
.SYNOPSIS
  Installs PortalProxy on the bastion: the portal ports (8080 ACI Web UI, 8081 ONTAP Restore) are passed to nginx in WSL
  with the real client address (PROXY protocol) instead of through "netsh interface portproxy".

.DESCRIPTION
  Run in PowerShell as Administrator (Remote Desktop to the bastion), from the folder of this script:
      powershell -ExecutionPolicy Bypass -File .\install-portal-proxy.ps1
  Back to netsh portproxy (removes the service):
      powershell -ExecutionPolicy Bypass -File .\install-portal-proxy.ps1 -Uninstall

  Steps: checks (nginx in WSL already has the PROXY protocol ports) -> build PortalProxy.exe with the .NET Framework
  compiler of Windows -> test run on other ports (the portal ports are not touched) -> install the service -> remove the
  netsh portproxy entries of the portal ports and start the service -> check both portals. When a step after the switch
  fails, the service is removed again and the netsh portproxy entries are put back.
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [string]$ListenAddress = '172.26.0.100',
    [int[]]$Ports = @(8080, 8081),
    [int]$Offset = 20000,       # nginx in WSL listens for PortalProxy on 127.0.0.1:<port + Offset>
    [int]$TestOffset = 30000    # test run before the switch: <ListenAddress>:<port + TestOffset>
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$ServiceName = 'PortalProxy'
$InstallDir = Join-Path $env:ProgramFiles 'PortalProxy'
$DataDir = Join-Path $env:ProgramData 'PortalProxy'
$LogDir = Join-Path $DataDir 'logs'
$Exe = Join-Path $InstallDir 'PortalProxy.exe'
$Conf = Join-Path $InstallDir 'portalproxy.conf'
$Csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$PortProxyKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'

function Step([string]$Text) { Write-Host ''; Write-Host "== $Text" -ForegroundColor Cyan }
function Ok([string]$Text) { Write-Host "   $Text" -ForegroundColor Green }
function Info([string]$Text) { Write-Host "   $Text" }
function Warn([string]$Text) { Write-Host "   $Text" -ForegroundColor Yellow }

# The portals use self-signed certificates; the checks below only read /healthz and /api/session.
if (-not ('PortalProxyTrustAll' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class PortalProxyTrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
'@
}
[Net.ServicePointManager]::CertificatePolicy = New-Object PortalProxyTrustAll
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.WebRequest]::DefaultWebProxy = New-Object Net.WebProxy   # straight to the bastion, not through the Squid proxy

function Test-Port([string]$Address, [int]$Port, [int]$TimeoutMs = 2000) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($Address, $Port)
        return ($task.Wait($TimeoutMs) -and $client.Connected)
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Get-HttpStatus([string]$Url) {
    try {
        return [int](Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 15).StatusCode
    } catch {
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}

# The client address the portal sees for this PowerShell (field "client" of /api/session).
function Get-ClientAddress([string]$BaseUrl) {
    $json = (Invoke-WebRequest -Uri "$BaseUrl/api/session" -UseBasicParsing -TimeoutSec 15).Content | ConvertFrom-Json
    if (-not $json.PSObject.Properties['client']) {
        throw "$BaseUrl/api/session has no client address: the portal in WSL is not updated yet (run the WSL update first)."
    }
    return [string]$json.client
}

# netsh portproxy entries as @{ '172.26.0.100/8080' = '127.0.0.1/8080' } (read from the registry, as netsh keeps them).
function Get-PortProxy {
    $entries = @{}
    if (Test-Path $PortProxyKey) {
        $item = Get-ItemProperty -Path $PortProxyKey
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -notlike 'PS*') { $entries[$p.Name] = [string]$p.Value }
        }
    }
    return $entries
}

function Add-PortProxy([string]$Listen, [string]$Connect) {
    $l = $Listen.Split('/'); $c = $Connect.Split('/')
    & netsh interface portproxy add v4tov4 "listenaddress=$($l[0])" "listenport=$($l[1])" "connectaddress=$($c[0])" "connectport=$($c[1])" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "netsh could not add the portproxy entry $Listen -> $Connect" }
}

function Remove-PortProxy([string]$Listen) {
    $l = $Listen.Split('/')
    & netsh interface portproxy delete v4tov4 "listenaddress=$($l[0])" "listenport=$($l[1])" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "netsh could not remove the portproxy entry $Listen" }
}

function Remove-ProxyService {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force; $service.WaitForStatus('Stopped', '00:00:20') }
        & sc.exe delete $ServiceName | Out-Null
        for ($i = 0; $i -lt 20 -and (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
    }
}

function Test-Portals([string]$Address, [int[]]$PortList, [string]$What) {
    foreach ($port in $PortList) {
        $base = "https://$($Address):$port"
        $status = Get-HttpStatus "$base/healthz"
        if ($status -ne 200) { throw "$What $base/healthz answered $status (expected 200)" }
        $client = Get-ClientAddress $base
        if ($client -like '127.0.0.1*') { throw "$What the portal on $base still sees 127.0.0.1: the PROXY protocol is not used" }
        Ok "$base healthz 200, client address seen by the portal: $client"
    }
}

# Runs a native program and returns its output; stderr lines do not stop the script (PowerShell 5.1 would with Stop).
function Invoke-Native([string]$Program, [string[]]$Arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { return @(& $Program @Arguments 2>&1 | ForEach-Object { "$_" }) } finally { $ErrorActionPreference = $previous }
}

function Assert-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script in PowerShell as Administrator.'
    }
}

function Install-PortalProxy {
    Step 'Checks'
    Assert-Administrator
    if (-not (Test-Path $Csc)) { throw "The .NET Framework compiler was not found: $Csc" }
    $source = Join-Path $Here 'PortalProxy.cs'
    if (-not (Test-Path $source)) { throw "PortalProxy.cs is not next to this script ($Here)." }
    foreach ($port in $Ports) {
        if (-not (Test-Port '127.0.0.1' ($port + $Offset))) {
            throw "Nothing answers on 127.0.0.1:$($port + $Offset). Update the portals in WSL first (install.sh adds this nginx port)."
        }
        Ok "nginx in WSL answers on 127.0.0.1:$($port + $Offset) (PROXY protocol port for $port)"
    }
    $current = Get-PortProxy
    foreach ($key in ($current.Keys | Sort-Object)) { Info "netsh portproxy now: $key -> $($current[$key])" }

    Step 'Build PortalProxy.exe'
    $build = Join-Path $env:TEMP ('PortalProxy-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $build | Out-Null
    Copy-Item $source (Join-Path $build 'PortalProxy.cs')
    $output = Invoke-Native $Csc @('/nologo', '/optimize+', '/target:exe', "/out:$build\PortalProxy.exe",
                                  '/reference:System.ServiceProcess.dll', '/reference:System.Core.dll', "$build\PortalProxy.cs")
    if ($LASTEXITCODE -ne 0) {
        $output | ForEach-Object { Warn "$_" }
        throw 'The build failed; nothing was changed.'
    }
    Ok "Built with $Csc"

    Step "Test run on other ports ($(($Ports | ForEach-Object { $_ + $TestOffset }) -join ', ')); the portal ports are not touched"
    $testConf = Join-Path $build 'test.conf'
    $lines = @($Ports | ForEach-Object { "listen $($ListenAddress):$($_ + $TestOffset) 127.0.0.1:$($_ + $Offset)" })
    $lines += 'rdp on'
    $lines += "log $build\logs"
    Set-Content -Path $testConf -Value $lines -Encoding ASCII
    $proc = Start-Process -FilePath "$build\PortalProxy.exe" -ArgumentList @('--console', "`"$testConf`"", '60') -PassThru -WindowStyle Hidden
    try {
        for ($i = 0; $i -lt 20 -and -not (Test-Port $ListenAddress ($Ports[0] + $TestOffset)); $i++) { Start-Sleep -Milliseconds 500 }
        Test-Portals $ListenAddress @($Ports | ForEach-Object { $_ + $TestOffset }) 'Test run:'
    } finally {
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
        $log = Join-Path $build 'logs\portalproxy.log'
        if (Test-Path $log) { Get-Content $log -Tail 4 | ForEach-Object { Info "log: $_" } }
    }

    Step 'Install the service and switch the portal ports to it'
    # What to put back when a step fails or on -Uninstall: the current netsh portproxy entry, or the usual one (same
    # port on 127.0.0.1) when PortalProxy already has the port (an update of PortalProxy).
    $restore = @{}
    $toRemove = @()
    foreach ($port in $Ports) {
        $key = "$ListenAddress/$port"
        if ($current.ContainsKey($key)) { $restore[$key] = $current[$key]; $toRemove += $key } else { $restore[$key] = "127.0.0.1/$port" }
    }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    # The log names Windows accounts and RDP client addresses: administrators and SYSTEM only.
    & icacls $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    $backup = Join-Path $DataDir ('portproxy-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
    ConvertTo-Json -InputObject @($restore.Keys | ForEach-Object { @{ listen = $_; connect = $restore[$_] } }) |
        Set-Content -Path $backup -Encoding ASCII
    Info "Backup of the portproxy entries: $backup"
    try {
        # An installed PortalProxy (update): stop it, replace the program and the configuration, start it again.
        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existing -and $existing.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force
            $existing.WaitForStatus('Stopped', '00:00:20')
            Info "Service $ServiceName stopped for the update"
        }
        for ($i = 0; ; $i++) {   # the program file can stay locked for a moment after the service stopped
            try { Copy-Item "$build\PortalProxy.exe" $Exe -Force; break } catch { if ($i -ge 20) { throw }; Start-Sleep -Milliseconds 500 }
        }
        Copy-Item $source (Join-Path $InstallDir 'PortalProxy.cs') -Force
        # (PowerShell names are case-insensitive: $confLines, not $conf, which would hide the path in $Conf.)
        $confLines = @('# PortalProxy (install-portal-proxy.ps1): address:port on Windows -> nginx PROXY protocol port in WSL')
        $confLines += @($Ports | ForEach-Object { "listen $($ListenAddress):$_ 127.0.0.1:$($_ + $Offset)" })
        $confLines += 'rdp on'
        $confLines += "log $LogDir"
        Set-Content -Path $Conf -Value $confLines -Encoding ASCII
        Invoke-Native $Exe @('--check', $Conf) | ForEach-Object { Info $_ }
        if ($LASTEXITCODE -ne 0) { throw "The configuration $Conf was refused." }
        if ($existing) {
            Ok "Service $ServiceName updated"
        } else {
            New-Service -Name $ServiceName -BinaryPathName "`"$Exe`"" -DisplayName 'PortalProxy (ACI Web UI and ONTAP Restore ports)' `
                -Description 'Passes the portal ports to nginx in WSL with the real client address (PROXY protocol); replaces netsh portproxy for these ports. Source: PortalProxy.cs in this folder.' `
                -StartupType Automatic | Out-Null
            & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
            Ok "Service $ServiceName installed (LocalSystem, automatic start, restarts after a failure)"
        }
        foreach ($key in $toRemove) { Remove-PortProxy $key; Info "netsh portproxy removed: $key -> $($restore[$key])" }
        Start-Service -Name $ServiceName
        foreach ($port in $Ports) {
            for ($i = 0; $i -lt 40 -and -not (Test-Port $ListenAddress $port); $i++) { Start-Sleep -Milliseconds 500 }
        }
        Test-Portals $ListenAddress $Ports 'After the switch:'
    } catch {
        Warn "Failed: $($_.Exception.Message)"
        Warn 'Removing PortalProxy and putting netsh portproxy back ...'
        Remove-ProxyService
        $now = Get-PortProxy
        foreach ($key in $restore.Keys) { if (-not $now.ContainsKey($key)) { Add-PortProxy $key $restore[$key] } }
        foreach ($port in $Ports) {
            $status = Get-HttpStatus "https://$($ListenAddress):$port/healthz"
            Info "https://$($ListenAddress):$port/healthz with netsh portproxy: $status"
        }
        throw 'PortalProxy is not running; the portal ports go through netsh portproxy again (client address 127.0.0.1).'
    }
    Remove-Item -Recurse -Force $build -ErrorAction SilentlyContinue

    Step 'Done'
    Ok "The portal ports $($Ports -join ', ') on $ListenAddress now pass the real client address to the portals."
    Info "Log: $LogDir\portalproxy.log (one line per connection)"
    Info "Back to netsh portproxy: powershell -ExecutionPolicy Bypass -File `"$($MyInvocation.ScriptName)`" -Uninstall"
}

function Uninstall-PortalProxy {
    Step 'Back to netsh portproxy'
    Assert-Administrator
    Remove-ProxyService
    Ok "Service $ServiceName removed (if it was there)"
    $latest = Get-ChildItem -Path $DataDir -Filter 'portproxy-backup-*.json' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    $entries = @{}
    if ($latest) {
        $saved = Get-Content $latest.FullName -Raw | ConvertFrom-Json
        foreach ($e in $saved) { if ($e) { $entries[[string]$e.listen] = [string]$e.connect } }
        Info "From the backup $($latest.FullName)"
    }
    foreach ($port in $Ports) {
        $key = "$ListenAddress/$port"
        if (-not $entries.ContainsKey($key)) { $entries[$key] = "127.0.0.1/$port" }
    }
    $current = Get-PortProxy
    foreach ($key in ($entries.Keys | Sort-Object)) {
        if (-not $current.ContainsKey($key)) { Add-PortProxy $key $entries[$key] }
        Ok "netsh portproxy: $key -> $($entries[$key])"
    }
    foreach ($port in $Ports) {
        $status = Get-HttpStatus "https://$($ListenAddress):$port/healthz"
        Info "https://$($ListenAddress):$port/healthz: $status"
    }
    Info 'The portals see 127.0.0.1 again as the client address.'
}

if ($Uninstall) { Uninstall-PortalProxy } else { Install-PortalProxy }
