# Bootstrap v2 locale initialization worker.
# The caller supplies a short-lived, destination-restricted SSH credential.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RelayMaterialPath,
    [Parameter(Mandatory = $true)]
    [string]$TargetLocale,
    [switch]$EmbeddedMode
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RelayHost = $null
$RelayPort = 0
$RelayUser = $null
$RelayExpires = $null
$PrivateKeyBase64 = $null
$PinnedHostKey = $null
$WaitSeconds = 120
$ProxyHosts = @(
    "ab.chatgpt.com",
    "api.statsigcdn.com",
    "featureassets.org",
    "prodregistryv2.org",
    "statsigapi.net"
)

Add-Type -AssemblyName System.Windows.Forms

function Read-RelayMaterial {
    if (-not (Test-Path -LiteralPath $RelayMaterialPath -PathType Leaf)) {
        throw "短时语言初始化材料不存在。"
    }
    try {
        $material = Get-Content -LiteralPath $RelayMaterialPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
    }
    finally {
        Remove-Item -LiteralPath $RelayMaterialPath -Force -ErrorAction SilentlyContinue
    }

    if ([int]$material.schema_version -ne 1) {
        throw "短时语言初始化材料版本无效。"
    }
    $script:RelayHost = [string]$material.relay_host
    $script:RelayPort = [int]$material.relay_port
    $script:RelayUser = [string]$material.relay_user
    $script:RelayExpires = [string]$material.expires_at
    $script:PrivateKeyBase64 = [string]$material.private_key_base64
    $script:PinnedHostKey = [string]$material.known_hosts_line

    if ($RelayHost -notmatch '^[A-Za-z0-9.-]{1,253}$' -or
        $RelayHost.StartsWith(".") -or $RelayHost.EndsWith(".")) {
        throw "短时语言中继主机格式无效。"
    }
    if ($RelayPort -lt 1 -or $RelayPort -gt 65535) {
        throw "短时语言中继端口无效。"
    }
    if ($RelayUser -notmatch '^[A-Za-z_][A-Za-z0-9_-]{0,31}$') {
        throw "短时语言中继用户格式无效。"
    }
    if ($TargetLocale -notmatch '^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$') {
        throw "目标系统语言格式无效。"
    }
    $expiresAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
            $RelayExpires,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal,
            [ref]$expiresAt
        ) -or $expiresAt -le [DateTimeOffset]::UtcNow -or
        $expiresAt -gt [DateTimeOffset]::UtcNow.AddHours(6)) {
        throw "短时语言中继凭据已经失效或有效期异常。"
    }
    try {
        $privateKeyBytes = [Convert]::FromBase64String($PrivateKeyBase64)
    }
    catch {
        throw "短时语言中继私钥编码无效。"
    }
    if ($privateKeyBytes.Length -lt 64 -or $privateKeyBytes.Length -gt 16384) {
        throw "短时语言中继私钥长度无效。"
    }
    if ($PinnedHostKey.Contains("`r") -or $PinnedHostKey.Contains("`n") -or
        $PinnedHostKey -notmatch '^\S+\s+(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-\S+)\s+\S+$') {
        throw "短时语言中继主机密钥格式无效。"
    }
}

Read-RelayMaterial

function Show-Result {
    param(
        [string]$Text,
        [string]$Title,
        [System.Windows.Forms.MessageBoxIcon]$Icon
    )
    if ($EmbeddedMode) {
        return
    }
    [void][System.Windows.Forms.MessageBox]::Show(
        $Text,
        $Title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        $Icon
    )
}

$RunId = [Guid]::NewGuid().ToString("N")
$CurrentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$StateRoot = Join-Path $env:LOCALAPPDATA "2466335\CodexI18nRelay\state\$RunId"
$LogRoot = Join-Path $env:LOCALAPPDATA "2466335\CodexI18nRelay\logs"
$KeyFile = Join-Path $StateRoot "relay_key"
$KnownHostsFile = Join-Path $StateRoot "known_hosts"
$SshErrorFile = Join-Path $StateRoot "ssh.stderr.log"
$SshPidFile = Join-Path $StateRoot "ssh.pid"
$PacServerScript = Join-Path $StateRoot "pac-server.ps1"
$PacServerErrorFile = Join-Path $StateRoot "pac-server.stderr.log"
$PacPidFile = Join-Path $StateRoot "pac.pid"
$PacFile = Join-Path $StateRoot "proxy.pac"
$ProxySnapshotFile = Join-Path $StateRoot "proxy-settings.json"
$CleanupScript = Join-Path $StateRoot "cleanup.ps1"
$WatchdogScript = Join-Path $StateRoot "watchdog.ps1"
$WatchdogPidFile = Join-Path $StateRoot "watchdog.pid"
$RunOncePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$RunOnceName = "2466335-CodexI18nCleanup-$RunId"
$LogFile = Join-Path $LogRoot "i18n-relay-$RunId.log"
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$SshProcess = $null
$PacProcess = $null
$WatchdogProcess = $null
$SelectedRelayBindAddress = $null
$CleanupArmed = $false
$ProxyChanged = $false

New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null

function Write-Log {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    try {
        [IO.File]::AppendAllText(
            $LogFile,
            ($line + [Environment]::NewLine),
            (New-Object Text.UTF8Encoding($true))
        )
    }
    catch {
        # Logging must never block cleanup or recovery.
    }
    Write-Host $Message
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        [int]$Attempts = 20
    )
    $lastError = $null
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            & $Action
            return
        }
        catch {
            $lastError = $_
            if ($attempt -lt $Attempts) {
                Start-Sleep -Milliseconds ([Math]::Min(2000, 150 + (150 * $attempt)))
            }
        }
    }
    throw ("{0}失败：{1}" -f $Operation, $lastError.Exception.Message)
}

function Save-ProxySettings {
    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        throw "无法访问当前登录用户的 Windows 网络设置。"
    }
    $key = Get-Item -LiteralPath $RegistryPath
    $snapshot = [ordered]@{}
    foreach ($name in @("AutoConfigURL", "ProxyEnable", "ProxyServer", "ProxyOverride")) {
        if ($key.GetValueNames() -contains $name) {
            $snapshot[$name] = [ordered]@{
                Exists = $true
                Value = $key.GetValue($name, $null, "DoNotExpandEnvironmentNames")
                Kind = $key.GetValueKind($name).ToString()
            }
        }
        else {
            $snapshot[$name] = [ordered]@{
                Exists = $false
                Value = $null
                Kind = "String"
            }
        }
    }
    [IO.File]::WriteAllText(
        $ProxySnapshotFile,
        ($snapshot | ConvertTo-Json -Depth 5),
        (New-Object Text.UTF8Encoding($false))
    )
}

function Restore-ProxySettings {
    if (-not (Test-Path -LiteralPath $ProxySnapshotFile)) {
        return
    }
    $snapshot = Get-Content -LiteralPath $ProxySnapshotFile -Raw |
        ConvertFrom-Json
    foreach ($name in @("AutoConfigURL", "ProxyEnable", "ProxyServer", "ProxyOverride")) {
        $entry = $snapshot.$name
        if ($entry.Exists) {
            New-ItemProperty `
                -Path $RegistryPath `
                -Name $name `
                -Value $entry.Value `
                -PropertyType $entry.Kind `
                -Force | Out-Null
        }
        else {
            Remove-ItemProperty `
                -Path $RegistryPath `
                -Name $name `
                -ErrorAction SilentlyContinue
        }
    }
    $script:ProxyChanged = $false
}

function Refresh-WindowsProxy {
    if (-not ("Native.WinInet" -as [type])) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
namespace Native {
    public static class WinInet {
        [DllImport("wininet.dll", SetLastError = true)]
        public static extern bool InternetSetOption(
            IntPtr hInternet,
            int dwOption,
            IntPtr lpBuffer,
            int dwBufferLength
        );
    }
}
"@
    }
    [void][Native.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    [void][Native.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
}

function Get-FreeTcpPort {
    $listener = New-Object Net.Sockets.TcpListener(
        [Net.IPAddress]::Loopback,
        0
    )
    $listener.Start()
    try {
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Test-BoundTcpConnection {
    param(
        [string]$SourceAddress,
        [string]$Destination,
        [int]$Port,
        [int]$TimeoutMilliseconds = 4000
    )
    $client = New-Object Net.Sockets.TcpClient
    try {
        if ($SourceAddress) {
            $local = New-Object Net.IPEndPoint(
                [Net.IPAddress]::Parse($SourceAddress),
                0
            )
            $client.Client.Bind($local)
        }
        $result = $client.BeginConnect($Destination, $Port, $null, $null)
        if (-not $result.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            return $false
        }
        $client.EndConnect($result)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Read-ExactBytes {
    param(
        [Parameter(Mandatory = $true)]
        [IO.Stream]$Stream,
        [Parameter(Mandatory = $true)]
        [int]$Count
    )
    $buffer = New-Object byte[] $Count
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -le 0) {
            throw "连接在读取完整响应前关闭。"
        }
        $offset += $read
    }
    return ,$buffer
}

function Test-SocksTlsEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [string]$HostName = "ab.chatgpt.com",
        [int]$TimeoutMilliseconds = 5000
    )
    $client = New-Object Net.Sockets.TcpClient
    $stream = $null
    $tls = $null
    try {
        $connect = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            return $false
        }
        $client.EndConnect($connect)
        $client.ReceiveTimeout = $TimeoutMilliseconds
        $client.SendTimeout = $TimeoutMilliseconds
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMilliseconds
        $stream.WriteTimeout = $TimeoutMilliseconds

        $greeting = [byte[]]@(5, 1, 0)
        $stream.Write($greeting, 0, $greeting.Length)
        $greetingReply = Read-ExactBytes -Stream $stream -Count 2
        if ($greetingReply[0] -ne 5 -or $greetingReply[1] -ne 0) {
            return $false
        }

        $hostBytes = [Text.Encoding]::ASCII.GetBytes($HostName)
        if ($hostBytes.Length -gt 255) {
            return $false
        }
        $request = New-Object byte[] ($hostBytes.Length + 7)
        $request[0] = 5
        $request[1] = 1
        $request[2] = 0
        $request[3] = 3
        $request[4] = [byte]$hostBytes.Length
        [Array]::Copy($hostBytes, 0, $request, 5, $hostBytes.Length)
        $request[$hostBytes.Length + 5] = 1
        $request[$hostBytes.Length + 6] = 187
        $stream.Write($request, 0, $request.Length)

        $reply = Read-ExactBytes -Stream $stream -Count 4
        if ($reply[0] -ne 5 -or $reply[1] -ne 0) {
            return $false
        }
        switch ($reply[3]) {
            1 {
                [void](Read-ExactBytes -Stream $stream -Count 6)
            }
            3 {
                $domainLength = Read-ExactBytes -Stream $stream -Count 1
                [void](Read-ExactBytes -Stream $stream -Count ($domainLength[0] + 2))
            }
            4 {
                [void](Read-ExactBytes -Stream $stream -Count 18)
            }
            default {
                return $false
            }
        }

        $tls = New-Object Net.Security.SslStream -ArgumentList $stream, $false
        $tls.ReadTimeout = $TimeoutMilliseconds
        $tls.WriteTimeout = $TimeoutMilliseconds
        $tls.AuthenticateAsClient($HostName)
        return $tls.IsAuthenticated
    }
    catch {
        return $false
    }
    finally {
        if ($tls) {
            $tls.Dispose()
        }
        elseif ($stream) {
            $stream.Dispose()
        }
        $client.Dispose()
    }
}

function Test-PacEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [int]$TimeoutMilliseconds = 2000
    )
    $client = New-Object Net.Sockets.TcpClient
    $stream = $null
    $memory = New-Object IO.MemoryStream
    try {
        $connect = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            return $false
        }
        $client.EndConnect($connect)
        $client.ReceiveTimeout = $TimeoutMilliseconds
        $client.SendTimeout = $TimeoutMilliseconds
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMilliseconds
        $stream.WriteTimeout = $TimeoutMilliseconds
        $request = [Text.Encoding]::ASCII.GetBytes(
            "GET /proxy.pac HTTP/1.1`r`nHost: 127.0.0.1`r`nConnection: close`r`n`r`n"
        )
        $stream.Write($request, 0, $request.Length)
        $buffer = New-Object byte[] 4096
        while ($memory.Length -lt 65536) {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) {
                break
            }
            $memory.Write($buffer, 0, $read)
        }
        $response = [Text.Encoding]::ASCII.GetString($memory.ToArray())
        return (
            $response.StartsWith("HTTP/1.1 200 OK") -and
            $response.Contains("FindProxyForURL") -and
            $response.Contains("SOCKS5")
        )
    }
    catch {
        return $false
    }
    finally {
        $memory.Dispose()
        if ($stream) {
            $stream.Dispose()
        }
        $client.Dispose()
    }
}

function Get-RelayBindAddresses {
    $candidates = @(
        Get-NetIPConfiguration -ErrorAction SilentlyContinue |
            Where-Object {
                $_.NetAdapter.Status -eq "Up" -and
                $_.NetAdapter.HardwareInterface -and
                $_.IPv4Address -and
                $_.IPv4DefaultGateway
            } |
            ForEach-Object { $_.IPv4Address.IPAddress }
    )
    $reachable = @()
    foreach ($candidate in $candidates) {
        if (Test-BoundTcpConnection `
            -SourceAddress $candidate `
            -Destination $RelayHost `
            -Port $RelayPort) {
            $reachable += $candidate
        }
    }
    if ($reachable.Count -gt 0) {
        return $reachable
    }
    if (-not (Test-BoundTcpConnection -Destination $RelayHost -Port $RelayPort)) {
        throw "无法从任何可用网络接口连接临时中继。"
    }
    return @()
}

function New-PacServerScript {
    param([int]$Port)
    $body = @'
$ErrorActionPreference = "SilentlyContinue"
$Port = __PORT__
$PacPath = '__PAC_PATH__'
$StopPath = '__STOP_PATH__'
$Deadline = (Get-Date).AddMinutes(20)
$Listener = New-Object Net.Sockets.TcpListener(
    [Net.IPAddress]::Loopback,
    $Port
)
$Listener.Start()
try {
    while ((Get-Date) -lt $Deadline -and -not (Test-Path -LiteralPath $StopPath)) {
        if (-not $Listener.Pending()) {
            Start-Sleep -Milliseconds 100
            continue
        }
        $Client = $Listener.AcceptTcpClient()
        $Stream = $null
        try {
            $Client.ReceiveTimeout = 3000
            $Client.SendTimeout = 3000
            $Stream = $Client.GetStream()
            if (-not $Stream.CanRead -or -not $Stream.CanWrite) {
                continue
            }
            $Buffer = New-Object byte[] 4096
            [void]$Stream.Read($Buffer, 0, $Buffer.Length)
            $Content = [IO.File]::ReadAllBytes($PacPath)
            $Header = [Text.Encoding]::ASCII.GetBytes(
                "HTTP/1.1 200 OK`r`n" +
                "Content-Type: application/x-ns-proxy-autoconfig`r`n" +
                "Cache-Control: no-store`r`n" +
                "Connection: close`r`n" +
                "Content-Length: $($Content.Length)`r`n`r`n"
            )
            $Stream.Write($Header, 0, $Header.Length)
            $Stream.Write($Content, 0, $Content.Length)
            $Stream.Flush()
        }
        catch {
            # A cancelled probe must not stop the local PAC service.
        }
        finally {
            if ($Stream) {
                $Stream.Dispose()
            }
            $Client.Dispose()
        }
    }
}
finally {
    $Listener.Stop()
}
'@
    $body = $body.Replace("__PORT__", [string]$Port)
    $body = $body.Replace("__PAC_PATH__", $PacFile.Replace("'", "''"))
    $body = $body.Replace(
        "__STOP_PATH__",
        (Join-Path $StateRoot "stop").Replace("'", "''")
    )
    [IO.File]::WriteAllText(
        $PacServerScript,
        $body,
        (New-Object Text.UTF8Encoding($false))
    )
}

function Start-PacServer {
    param([int]$Port)
    New-PacServerScript -Port $Port
    $script:PacProcess = Start-Process `
        -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", ('"{0}"' -f $PacServerScript)
        ) `
        -WindowStyle Hidden `
        -RedirectStandardError $PacServerErrorFile `
        -PassThru
    [IO.File]::WriteAllText(
        $PacPidFile,
        [string]$PacProcess.Id,
        [Text.Encoding]::ASCII
    )
}

function Wait-PacServer {
    param([int]$Port)
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        if ($PacProcess.HasExited) {
            $detail = Get-Content `
                -LiteralPath $PacServerErrorFile `
                -Raw `
                -ErrorAction SilentlyContinue
            throw "本机 PAC 服务提前退出：$detail"
        }
        if (Test-PacEndpoint -Port $Port) {
            return
        }
        Start-Sleep -Milliseconds 300
    }
    throw "本机 PAC 服务未在规定时间内就绪。"
}

function Arm-SafetyCleanup {
    $body = @'
$ErrorActionPreference = "Stop"
$StateRoot = '__STATE_ROOT__'
$RegistryPath = '__REGISTRY_PATH__'
$SnapshotFile = '__SNAPSHOT_FILE__'
$RunOncePath = '__RUN_ONCE_PATH__'
$RunOnceName = '__RUN_ONCE_NAME__'

try {
    [IO.File]::WriteAllText(
        (Join-Path $StateRoot "stop"),
        "stop",
        [Text.Encoding]::ASCII
    )
    foreach ($PidFile in @("ssh.pid", "pac.pid", "watchdog.pid")) {
        $Path = Join-Path $StateRoot $PidFile
        if (Test-Path -LiteralPath $Path) {
            $ProcessId = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue
            if ($ProcessId -and ([int]$ProcessId -ne $PID)) {
                Stop-Process -Id ([int]$ProcessId) -Force -ErrorAction SilentlyContinue
            }
        }
    }

    if (Test-Path -LiteralPath $SnapshotFile) {
        $Snapshot = Get-Content -LiteralPath $SnapshotFile -Raw |
            ConvertFrom-Json
        foreach ($Name in @("AutoConfigURL", "ProxyEnable", "ProxyServer", "ProxyOverride")) {
            $Entry = $Snapshot.$Name
            if ($Entry.Exists) {
                New-ItemProperty `
                    -Path $RegistryPath `
                    -Name $Name `
                    -Value $Entry.Value `
                    -PropertyType $Entry.Kind `
                    -Force | Out-Null
            }
            else {
                Remove-ItemProperty `
                    -Path $RegistryPath `
                    -Name $Name `
                    -ErrorAction SilentlyContinue
            }
        }
    }

    Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class RelayWinInet {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(
        IntPtr hInternet,
        int dwOption,
        IntPtr lpBuffer,
        int dwBufferLength
    );
}
"@
    [void][RelayWinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    [void][RelayWinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
    Remove-ItemProperty `
        -Path $RunOncePath `
        -Name $RunOnceName `
        -ErrorAction SilentlyContinue
}
catch {
    [IO.File]::WriteAllText(
        (Join-Path $StateRoot "RESTORE_REQUIRED.txt"),
        $_.Exception.Message,
        (New-Object Text.UTF8Encoding($false))
    )
    exit 51
}

Start-Sleep -Milliseconds 500
Remove-Item -LiteralPath $StateRoot -Recurse -Force -ErrorAction SilentlyContinue
exit 0
'@
    $body = $body.Replace("__STATE_ROOT__", $StateRoot.Replace("'", "''"))
    $body = $body.Replace("__REGISTRY_PATH__", $RegistryPath.Replace("'", "''"))
    $body = $body.Replace(
        "__SNAPSHOT_FILE__",
        $ProxySnapshotFile.Replace("'", "''")
    )
    $body = $body.Replace("__RUN_ONCE_PATH__", $RunOncePath.Replace("'", "''"))
    $body = $body.Replace("__RUN_ONCE_NAME__", $RunOnceName.Replace("'", "''"))
    [IO.File]::WriteAllText(
        $CleanupScript,
        $body,
        (New-Object Text.UTF8Encoding($false))
    )

    $watchdogBody = @'
$ErrorActionPreference = "SilentlyContinue"
Start-Sleep -Seconds 900
$CleanupScript = '__CLEANUP_SCRIPT__'
if (Test-Path -LiteralPath $CleanupScript) {
    Start-Process `
        -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", ('"{0}"' -f $CleanupScript)
        ) `
        -WindowStyle Hidden
}
'@
    $watchdogBody = $watchdogBody.Replace(
        "__CLEANUP_SCRIPT__",
        $CleanupScript.Replace("'", "''")
    )
    [IO.File]::WriteAllText(
        $WatchdogScript,
        $watchdogBody,
        (New-Object Text.UTF8Encoding($false))
    )

    New-Item -ItemType Directory -Path $RunOncePath -Force | Out-Null
    $powerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $cleanupCommand = '"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}"' -f `
        $powerShellExe,
        $CleanupScript
    New-ItemProperty `
        -Path $RunOncePath `
        -Name $RunOnceName `
        -Value $cleanupCommand `
        -PropertyType String `
        -Force | Out-Null

    $script:WatchdogProcess = Start-Process `
        -FilePath $powerShellExe `
        -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", ('"{0}"' -f $WatchdogScript)
        ) `
        -WindowStyle Hidden `
        -PassThru
    [IO.File]::WriteAllText(
        $WatchdogPidFile,
        [string]$WatchdogProcess.Id,
        [Text.Encoding]::ASCII
    )
    $script:CleanupArmed = $true
}

function Invoke-SafetyCleanup {
    if (-not (Test-Path -LiteralPath $StateRoot)) {
        return
    }
    if (Test-Path -LiteralPath $CleanupScript) {
        try {
            $cleanupProcess = Start-Process `
                -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
                -ArgumentList @(
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-File", ('"{0}"' -f $CleanupScript)
                ) `
                -WindowStyle Hidden `
                -Wait `
                -PassThru
            if (($cleanupProcess.ExitCode -eq 0) -and
                (-not (Test-Path -LiteralPath $StateRoot))) {
                return
            }
        }
        catch {
            Write-Log ("清理子进程未能启动：{0}" -f $_.Exception.Message)
        }
        Write-Log "自动清理未完成，主程序正在执行第二次恢复。"
    }

    if (-not (Test-Path -LiteralPath $StateRoot)) {
        return
    }
    [IO.File]::WriteAllText(
        (Join-Path $StateRoot "stop"),
        "stop",
        [Text.Encoding]::ASCII
    )
    foreach ($process in @($SshProcess, $PacProcess, $WatchdogProcess)) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    if ($ProxyChanged -or (Test-Path -LiteralPath $ProxySnapshotFile)) {
        Invoke-WithRetry `
            -Operation "恢复原 Windows 网络设置" `
            -Action { Restore-ProxySettings }
        Refresh-WindowsProxy
    }
    if ($CleanupArmed) {
        Remove-ItemProperty `
            -Path $RunOncePath `
            -Name $RunOnceName `
            -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $StateRoot -Recurse -Force -ErrorAction SilentlyContinue
}

function Stop-CodexProcesses {
    Get-Process -Name "ChatGPT", "codex" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

function Get-CodexPackage {
    $package = Get-AppxPackage -Name "OpenAI.Codex" |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if (-not $package) {
        throw "没有检测到已安装的 OpenAI Codex 桌面应用。"
    }
    return $package
}

function Get-CodexApplication {
    param($Package)
    $manifest = Get-AppxPackageManifest -Package $Package.PackageFullName
    $application = @($manifest.Package.Applications.Application)[0]
    if (-not $application -or -not $application.Id) {
        throw "无法读取 Codex 应用启动标识。"
    }
    return $application
}

function Start-CodexNormal {
    $package = Get-CodexPackage
    $application = Get-CodexApplication -Package $package
    $aumid = "{0}!{1}" -f $package.PackageFamilyName, $application.Id
    Start-Process -FilePath "explorer.exe" -ArgumentList "shell:AppsFolder\$aumid"
    Write-Log ("Codex normal launch: version {0}" -f $package.Version)
}

function Start-CodexWithPac {
    param([string]$PacUrl)
    $package = Get-CodexPackage
    $application = Get-CodexApplication -Package $package
    $executable = $application.Executable
    if ($executable) {
        $executablePath = Join-Path $package.InstallLocation $executable
        if (Test-Path -LiteralPath $executablePath) {
            try {
                Start-Process `
                    -FilePath $executablePath `
                    -ArgumentList @(
                        "--proxy-pac-url=$PacUrl",
                        "--disable-quic"
                    )
                Write-Log "Codex 已使用进程级 PAC 启动。"
                return
            }
            catch {
                Write-Log "进程级 PAC 启动不可用，改用 Windows PAC 兜底。"
            }
        }
    }
    $aumid = "{0}!{1}" -f $package.PackageFamilyName, $application.Id
    Start-Process -FilePath "explorer.exe" -ArgumentList "shell:AppsFolder\$aumid"
    Write-Log "Codex 已使用 Windows PAC 启动。"
}

function Test-SocksRelay {
    param(
        [int]$Port,
        [int]$Attempts = 20
    )
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        if ($SshProcess.HasExited) {
            $detail = Get-Content `
                -LiteralPath $SshErrorFile `
                -Raw `
                -ErrorAction SilentlyContinue
            throw "临时中继提前退出：$detail"
        }
        if (Test-SocksTlsEndpoint -Port $Port) {
            Write-Log "受限 SOCKS/TLS 验证通过。"
            return
        }
        Start-Sleep -Milliseconds 500
    }
    $detail = Get-Content `
        -LiteralPath $SshErrorFile `
        -Raw `
        -ErrorAction SilentlyContinue
    throw "受限 SOCKS 中继未在规定时间内就绪：$detail"
}

function Start-VerifiedSocksRelay {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SshExecutable,
        [string[]]$BindAddresses = @()
    )
    $lastError = $null
    $routes = @("") + @(
        $BindAddresses |
            Where-Object { $_ } |
            Select-Object -Unique
    )
    foreach ($route in $routes) {
        $routeLabel = if ($route) {
            "物理接口 $route"
        }
        else {
            "Windows 默认网络路径"
        }
        for ($portAttempt = 1; $portAttempt -le 3; $portAttempt++) {
            $port = Get-FreeTcpPort
            Remove-Item -LiteralPath $SshErrorFile -Force -ErrorAction SilentlyContinue
            $sshArguments = @(
                "-N",
                "-T",
                "-F", "NUL",
                "-i", ('"{0}"' -f $KeyFile),
                "-o", "BatchMode=yes",
                "-o", "IdentitiesOnly=yes",
                "-o", "ExitOnForwardFailure=yes",
                "-o", "ConnectTimeout=10",
                "-o", "ServerAliveInterval=15",
                "-o", "ServerAliveCountMax=3",
                "-o", "StrictHostKeyChecking=yes",
                "-o", ('UserKnownHostsFile="{0}"' -f $KnownHostsFile),
                "-o", "GlobalKnownHostsFile=NUL"
            )
            if ($RelayPort -ne 22) {
                $sshArguments += @("-p", [string]$RelayPort)
            }
            if ($route) {
                $sshArguments += @("-b", $route)
            }
            $sshArguments += @(
                "-D", "127.0.0.1:${port}",
                ("{0}@{1}" -f $RelayUser, $RelayHost)
            )
            try {
                $script:SshProcess = Start-Process `
                    -FilePath $SshExecutable `
                    -ArgumentList $sshArguments `
                    -WindowStyle Hidden `
                    -RedirectStandardError $SshErrorFile `
                    -PassThru
                [IO.File]::WriteAllText(
                    $SshPidFile,
                    [string]$SshProcess.Id,
                    [Text.Encoding]::ASCII
                )
                Test-SocksRelay -Port $port
                $script:SelectedRelayBindAddress = $route
                Write-Log ("中继已通过{0}建立。" -f $routeLabel)
                return $port
            }
            catch {
                $lastError = $_
                if ($SshProcess -and -not $SshProcess.HasExited) {
                    Stop-Process -Id $SshProcess.Id -Force -ErrorAction SilentlyContinue
                }
                $detail = $_.Exception.Message
                $isPortConflict = (
                    $detail -match "cannot listen to port" -or
                    $detail -match "Address already in use"
                )
                if ($isPortConflict -and $portAttempt -lt 3) {
                    Write-Log (
                        "{0}的本机端口被占用，正在更换端口重试。" -f
                        $routeLabel
                    )
                    Start-Sleep -Milliseconds (300 * $portAttempt)
                    continue
                }
                Write-Log (
                    "{0}不可用，正在切换下一条网络路径：{1}" -f
                    $routeLabel,
                    $detail
                )
                break
            }
        }
    }
    throw (
        "默认路径及全部物理接口均无法建立经过 TLS 验证的临时中继：{0}" -f
        $lastError.Exception.Message
    )
}

function Write-PacFile {
    param(
        [Parameter(Mandatory = $true)]
        [int]$SocksPort
    )
    $checks = ($ProxyHosts | ForEach-Object { 'host === "{0}"' -f $_ }) -join " || "
    $pacContent = @"
function FindProxyForURL(url, host) {
    if ($checks) {
        return "SOCKS5 127.0.0.1:$SocksPort";
    }
    return "DIRECT";
}
"@
    [IO.File]::WriteAllText(
        $PacFile,
        $pacContent,
        [Text.Encoding]::ASCII
    )
}

function Start-VerifiedPacServer {
    param(
        [Parameter(Mandatory = $true)]
        [int]$SocksPort
    )
    $lastError = $null
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $port = Get-FreeTcpPort
        Remove-Item -LiteralPath $PacServerErrorFile -Force -ErrorAction SilentlyContinue
        Write-PacFile -SocksPort $SocksPort
        try {
            Start-PacServer -Port $port
            Wait-PacServer -Port $port
            return $port
        }
        catch {
            $lastError = $_
            if ($PacProcess -and -not $PacProcess.HasExited) {
                Stop-Process -Id $PacProcess.Id -Force -ErrorAction SilentlyContinue
            }
            Write-Log (
                "PAC 服务第 {0} 次未通过，正在更换端口重试：{1}" -f
                $attempt,
                $_.Exception.Message
            )
            if ($attempt -lt 5) {
                Start-Sleep -Milliseconds (300 * $attempt)
            }
        }
    }
    throw ("无法启动经过内容验证的本机 PAC 服务：{0}" -f $lastError.Exception.Message)
}

$BootstrapSucceeded = $false
$ExitCode = 1

try {
    Write-Log ("开始 Codex 系统语言短时初始化：{0}。" -f $TargetLocale)
    Write-Log ("中继凭据将在 {0} 自动失效。" -f $RelayExpires)
    $package = Get-CodexPackage
    $sshCommand = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if (-not $sshCommand) {
        throw "系统缺少 Windows OpenSSH 客户端，无法建立安全中继。"
    }

    $bindAddresses = @(Get-RelayBindAddresses)
    Write-Log "将先尝试 Windows 默认网络路径；失败时再逐个尝试可用物理接口。"

    [IO.File]::WriteAllBytes(
        $KeyFile,
        [Convert]::FromBase64String($PrivateKeyBase64)
    )
    [IO.File]::WriteAllText(
        $KnownHostsFile,
        ($PinnedHostKey + [Environment]::NewLine),
        [Text.Encoding]::ASCII
    )
    & "$env:SystemRoot\System32\icacls.exe" `
        $KeyFile `
        "/inheritance:r" `
        "/grant:r" `
        "*${CurrentUserSid}:(R)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "无法保护临时中继密钥文件。"
    }

    Save-ProxySettings
    Arm-SafetyCleanup
    $socksPort = Start-VerifiedSocksRelay `
        -SshExecutable $sshCommand.Source `
        -BindAddresses $bindAddresses
    $pacPort = Start-VerifiedPacServer -SocksPort $socksPort
    $pacUrl = "http://127.0.0.1:${pacPort}/proxy.pac"

    New-ItemProperty `
        -Path $RegistryPath `
        -Name "AutoConfigURL" `
        -Value $pacUrl `
        -PropertyType String `
        -Force | Out-Null
    New-ItemProperty `
        -Path $RegistryPath `
        -Name "ProxyEnable" `
        -Value 0 `
        -PropertyType DWord `
        -Force | Out-Null
    $ProxyChanged = $true
    Refresh-WindowsProxy
    Write-Log "短时 PAC 已启用；只有五个语言配置域名经香港中继。"

    Stop-CodexProcesses
    Start-Sleep -Seconds 2
    Start-CodexWithPac -PacUrl $pacUrl
    Show-Result `
        ("临时中继已经开启。Codex 正在按系统语言 {0} 完成远程初始化。" -f $TargetLocale) `
        "正在初始化系统语言" `
        ([System.Windows.Forms.MessageBoxIcon]::Information)

    for ($remaining = $WaitSeconds; $remaining -gt 0; $remaining -= 10) {
        Write-Log ("等待远程语言初始化，剩余约 {0} 秒。" -f $remaining)
        Start-Sleep -Seconds ([Math]::Min(10, $remaining))
        if ($SshProcess.HasExited) {
            throw "等待期间临时中继意外退出。"
        }
        if ($PacProcess.HasExited) {
            throw "等待期间本机 PAC 服务意外退出。"
        }
    }

    Stop-CodexProcesses
    Start-Sleep -Seconds 2
    $BootstrapSucceeded = $true
    $ExitCode = 0
}
catch {
    $message = $_.Exception.Message
    $errorType = $_.Exception.GetType().FullName
    $errorId = $_.FullyQualifiedErrorId
    $errorLine = $_.InvocationInfo.ScriptLineNumber
    Write-Log (
        "失败：{0} | 类型={1} | ErrorId={2} | 行={3}" -f
        $message,
        $errorType,
        $errorId,
        $errorLine
    )
    Show-Result `
        ("临时中继验证失败：`r`n{0}`r`n`r`n诊断日志：{1}" -f $message, $LogFile) `
        "验证失败" `
        ([System.Windows.Forms.MessageBoxIcon]::Error)
}
finally {
    Write-Log "正在关闭临时中继并恢复原 Windows 网络设置。"
    Invoke-SafetyCleanup
}

if ($BootstrapSucceeded) {
    if ($EmbeddedMode) {
        exit $ExitCode
    }
    try {
        Start-CodexNormal
        Show-Result `
            "临时中继已关闭，原网络设置已恢复，Codex 已正常重启。请观察界面是否仍为简体中文。" `
            "验证完成" `
            ([System.Windows.Forms.MessageBoxIcon]::Information)
    }
    catch {
        Write-Log ("恢复后启动 Codex 失败：{0}" -f $_.Exception.Message)
        Show-Result `
            ("网络已恢复，但重新启动 Codex 失败。请手动打开 Codex。`r`n日志：{0}" -f $LogFile) `
            "需要手动启动" `
            ([System.Windows.Forms.MessageBoxIcon]::Warning)
        $ExitCode = 2
    }
}

exit $ExitCode
