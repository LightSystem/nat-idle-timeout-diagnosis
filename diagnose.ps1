<#
.SYNOPSIS
    Native Windows PowerShell ISP / NAT TCP idle-timeout diagnostic tool (no Python required).

.DESCRIPTION
    Diagnoses silent NAT / CGNAT TCP session eviction (violation of RFC 5382 REQ-5, which
    requires established TCP mappings to survive at least 2 hours 4 minutes of inactivity).

    Pins AF_INET (IPv4), disables OS TCP keepalive on probe sockets, runs parallel idle
    probes against an IMAP endpoint (or custom host/port) alongside an active 20-second
    control connection, tests a fresh connection at the end, and prints a full diagnosis.

.EXAMPLE
    .\diagnose.ps1
    Runs the full parallel bracket (30, 45, 60, 75, 90, 120s + control + fresh check).

.EXAMPLE
    .\diagnose.ps1 -Quick
    Runs a single 90s idle probe vs 20s control connection (~2 minutes).

.EXAMPLE
    .\diagnose.ps1 -WanIp 100.64.1.25
    Includes an automated CGNAT (100.64.0.0/10) check against your router's WAN IP.

.EXAMPLE
    .\diagnose.ps1 -FindEndpoint
    Tests candidate IPv4 endpoints to see which hold idle TCP connections past 240s.
#>
[CmdletBinding()]
param(
    [switch]$Quick,
    [switch]$Bracket,
    [switch]$FindEndpoint,
    [switch]$Passive,
    [string]$HostName = "imap.gmx.com",
    [int]$Port = 143,
    [string]$Idles = "30,45,60,75,90,120",
    [int]$PokeTimeout = 40,
    [string]$WanIp = "",
    [int]$HoldSeconds = 240,
    [int]$Samples = 15,
    [int]$Interval = 20,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs = @()
)

$ErrorActionPreference = "Stop"
for ($i = 0; $i -lt $ExtraArgs.Count; $i++) {
    switch ($ExtraArgs[$i].ToLowerInvariant()) {
        "--quick"         { $Quick = $true }
        "--bracket"       { $Bracket = $true }
        "--find-endpoint" { $FindEndpoint = $true }
        "--passive"       { $Passive = $true }
        "--host"          { if ($i + 1 -lt $ExtraArgs.Count) { $HostName = $ExtraArgs[++$i] } }
        "--port"          { if ($i + 1 -lt $ExtraArgs.Count) { $Port = [int]$ExtraArgs[++$i] } }
        "--idles"         { if ($i + 1 -lt $ExtraArgs.Count) { $Idles = $ExtraArgs[++$i] } }
        "--poke-timeout"  { if ($i + 1 -lt $ExtraArgs.Count) { $PokeTimeout = [int]$ExtraArgs[++$i] } }
        "--wan-ip"        { if ($i + 1 -lt $ExtraArgs.Count) { $WanIp = $ExtraArgs[++$i] } }
        "--hold-seconds"  { if ($i + 1 -lt $ExtraArgs.Count) { $HoldSeconds = [int]$ExtraArgs[++$i] } }
        "--samples"       { if ($i + 1 -lt $ExtraArgs.Count) { $Samples = [int]$ExtraArgs[++$i] } }
        "--interval"      { if ($i + 1 -lt $ExtraArgs.Count) { $Interval = [int]$ExtraArgs[++$i] } }
    }
}
$ControlInterval = 20
$Rfc5382MinSeconds = 7440

function Get-TimeStr {
    return (Get-Date).ToString("HH:mm:ss")
}

function Get-LocalIPv4 {
    try {
        $u = New-Object System.Net.Sockets.UdpClient([System.Net.Sockets.AddressFamily]::InterNetwork)
        $u.Connect("1.1.1.1", 80)
        $ip = ([System.Net.IPEndPoint]$u.Client.LocalEndPoint).Address.ToString()
        $u.Close()
        return $ip
    } catch {
        return $null
    }
}

function Get-LocalIPv6 {
    try {
        $u = New-Object System.Net.Sockets.UdpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        $u.Connect("2606:4700:4700::1111", 80)
        $ip = ([System.Net.IPEndPoint]$u.Client.LocalEndPoint).Address.ToString()
        $u.Close()
        return $ip
    } catch {
        return $null
    }
}

function Get-PublicIPv4 {
    $urls = @("https://api4.ipify.org", "https://ipv4.icanhazip.com", "https://v4.ident.me")
    foreach ($url in $urls) {
        try {
            $resp = Invoke-RestMethod -Uri $url -TimeoutSec 5 -Method Get
            $text = ($resp | Out-String).Trim()
            $parsed = $null
            if ([System.Net.IPAddress]::TryParse($text, [ref]$parsed) -and
                $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                return $text
            }
        } catch {
            continue
        }
    }
    return $null
}

function Test-WanIpAddress {
    param([string]$WanIpStr, [string]$PublicIpStr)
    if ([string]::IsNullOrWhiteSpace($WanIpStr)) { return $null }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($WanIpStr.Trim(), [ref]$parsed) -or
        $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return @{ Status = "INVALID"; Detail = "'$WanIpStr' is not a valid IPv4 address." }
    }
    $bytes = $parsed.GetAddressBytes()
    $b0 = $bytes[0]
    $b1 = $bytes[1]

    # 100.64.0.0/10 -> first octet 100, second octet 64..127
    if ($b0 -eq 100 -and $b1 -ge 64 -and $b1 -le 127) {
        return @{
            Status = "CGNAT_RFC6598"
            Detail = "Router WAN IP ($parsed) is inside 100.64.0.0/10 (RFC 6598 Carrier-Grade NAT). Your ISP is applying CGNAT upstream of your router."
        }
    }
    $isRfc1918 = ($b0 -eq 10) -or ($b0 -eq 172 -and $b1 -ge 16 -and $b1 -le 31) -or ($b0 -eq 192 -and $b1 -eq 168)
    if ($isRfc1918) {
        return @{
            Status = "DOUBLE_NAT_RFC1918"
            Detail = "Router WAN IP ($parsed) is in RFC 1918 private space. There is another NAT layer upstream of this router (double NAT or ISP private WAN)."
        }
    }
    if ($PublicIpStr -and ($parsed.ToString() -ne $PublicIpStr)) {
        return @{
            Status = "NAT_MISMATCH"
            Detail = "Router WAN IP ($parsed) differs from external public IP ($PublicIpStr). Your traffic crosses an upstream carrier NAT."
        }
    }
    if ($PublicIpStr -and ($parsed.ToString() -eq $PublicIpStr)) {
        return @{
            Status = "PUBLIC_MATCH"
            Detail = "Router WAN IP ($parsed) matches external public IP ($PublicIpStr). No CGNAT detected on the line; only your local router performs NAT."
        }
    }
    return @{
        Status = "PUBLIC_UNVERIFIED"
        Detail = "Router WAN IP ($parsed) is a public address outside 100.64.0.0/10."
    }
}

function Get-TcpCounterSnapshot {
    try {
        $props = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $s4 = $props.GetTcpIPv4Statistics()
        return [ordered]@{
            "Tcp4.RetransmittedSegments" = [int64]$s4.SegmentsRetransmitted
            "Tcp4.ResetConnections"      = [int64]$s4.ResetConnections
            "Tcp4.ErrorsReceived"        = [int64]$s4.ErrorsReceived
        }
    } catch {
        return [ordered]@{}
    }
}

function Write-CounterSnapshot {
    param([string]$Label, $Current, $Before = $null)
    if (-not $Current -or $Current.Count -eq 0) { return }
    Write-Host "${Label}:"
    foreach ($k in $Current.Keys) {
        $v = $Current[$k]
        if ($null -ne $Before -and $Before.Contains($k)) {
            $delta = $v - $Before[$k]
            $sign = if ($delta -gt 0) { "+$delta" } else { "$delta" }
            Write-Host ("  {0,-28} {1,-10} (delta: {2})" -f $k, $v, $sign)
        } else {
            Write-Host ("  {0,-28} {1}" -f $k, $v)
        }
    }
}

$ProbeScriptBlock = {
    param(
        [string]$Mode,
        [string]$TargetHost,
        [int]$TargetPort,
        [int]$IdleSec,
        [int]$PokeTimeoutSec,
        [int]$ControlIntervalSec
    )

    function Open-IPv4Socket([string]$h, [int]$p, [int]$timeoutMs) {
        $addrs = [System.Net.Dns]::GetHostAddresses($h) | Where-Object {
            $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
        }
        if (-not $addrs -or $addrs.Count -eq 0) {
            throw "No IPv4 (A) record found for $h"
        }
        $sock = New-Object System.Net.Sockets.Socket(
            [System.Net.Sockets.AddressFamily]::InterNetwork,
            [System.Net.Sockets.SocketType]::Stream,
            [System.Net.Sockets.ProtocolType]::Tcp
        )
        $sock.ReceiveTimeout = $timeoutMs
        $sock.SendTimeout = $timeoutMs
        $sock.NoDelay = $true
        $sock.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::KeepAlive, $false)
        $sock.Connect($addrs[0], $p)
        $buf = New-Object byte[] 512
        $read = $sock.Receive($buf)
        if ($read -le 0) {
            $sock.Close()
            throw "Server sent empty greeting (EOF)"
        }
        return $sock
    }

    $tag = if ($Mode -eq "control") { "control" } else { "idle-${IdleSec}s" }
    $sock = $null
    try {
        $sock = Open-IPv4Socket $TargetHost $TargetPort 20000
        if ($Mode -eq "idle") {
            Start-Sleep -Seconds $IdleSec
            while ($sock.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead)) {
                $preBuf = New-Object byte[] 512
                $preRead = $sock.Receive($preBuf)
                if ($preRead -le 0) {
                    return @{ Tag = $tag; Verdict = "SERVER"; Detail = "Server sent FIN during ${IdleSec}s idle window (discarded)"; Time = (Get-Date).ToString("HH:mm:ss") }
                }
            }
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $payload = [System.Text.Encoding]::ASCII.GetBytes("a1 NOOP`r`n")
            [void]$sock.Send($payload)
            $sock.ReceiveTimeout = $PokeTimeoutSec * 1000
            $replyBuf = New-Object byte[] 512
            $r = $sock.Receive($replyBuf)
            $sw.Stop()
            $el = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            if ($r -gt 0) {
                return @{ Tag = $tag; Verdict = "ECHO"; Detail = "Replied in ${el}s after ${IdleSec}s idle"; Time = (Get-Date).ToString("HH:mm:ss") }
            } else {
                return @{ Tag = $tag; Verdict = "SERVER"; Detail = "EOF after poke (${el}s)"; Time = (Get-Date).ToString("HH:mm:ss") }
            }
        } else {
            $totalWindow = $IdleSec + $ControlIntervalSec
            $endTime = (Get-Date).AddSeconds($totalWindow)
            $tick = 0
            while ((Get-Date) -lt $endTime) {
                Start-Sleep -Seconds $ControlIntervalSec
                $tick++
                $payload = [System.Text.Encoding]::ASCII.GetBytes("c${tick} NOOP`r`n")
                [void]$sock.Send($payload)
                $sock.ReceiveTimeout = 30000
                $replyBuf = New-Object byte[] 512
                $r = $sock.Receive($replyBuf)
                if ($r -le 0) {
                    return @{ Tag = "control"; Verdict = "SERVER"; Detail = "Server closed control connection at tick $tick"; Time = (Get-Date).ToString("HH:mm:ss") }
                }
            }
            return @{ Tag = "control"; Verdict = "ECHO"; Detail = "Survived ${totalWindow}s with traffic every ${ControlIntervalSec}s (never idle >${ControlIntervalSec}s)"; Time = (Get-Date).ToString("HH:mm:ss") }
        }
    } catch [System.Net.Sockets.SocketException] {
        $errCode = $_.Exception.SocketErrorCode
        if ($errCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
            if ($Mode -eq "idle") {
                return @{ Tag = $tag; Verdict = "SILENT"; Detail = "No reply for ${PokeTimeoutSec}s after ${IdleSec}s idle, no RST/FIN -> mapping evicted"; Time = (Get-Date).ToString("HH:mm:ss") }
            } else {
                return @{ Tag = "control"; Verdict = "SILENT"; Detail = "Died despite traffic every ${ControlIntervalSec}s (general line loss)"; Time = (Get-Date).ToString("HH:mm:ss") }
            }
        } elseif ($errCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) {
            return @{ Tag = $tag; Verdict = "RST"; Detail = "Connection actively reset (RST)"; Time = (Get-Date).ToString("HH:mm:ss") }
        } else {
            return @{ Tag = $tag; Verdict = "ERROR"; Detail = "SocketError ($errCode): $($_.Exception.Message)"; Time = (Get-Date).ToString("HH:mm:ss") }
        }
    } catch {
        return @{ Tag = $tag; Verdict = "ERROR"; Detail = "$($_.Exception.GetType().Name): $($_.Exception.Message)"; Time = (Get-Date).ToString("HH:mm:ss") }
    } finally {
        if ($null -ne $sock) {
            try { $sock.Close() } catch {}
        }
    }
}

Write-Host ("=" * 76)
Write-Host ("NAT / ISP TCP IDLE-TIMEOUT DIAGNOSTIC (Windows PowerShell {0})" -f $PSVersionTable.PSVersion)
Write-Host ("Started at: {0}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
Write-Host ("=" * 76)

if ($FindEndpoint) {
    $candidates = @(
        @{ Host = "imap.gmx.com"; Port = 143 },
        @{ Host = "imap.web.de"; Port = 143 },
        @{ Host = "smtp.gmx.com"; Port = 25 }
    )
    Write-Host ("[{0}] Probing {1} IPv4 endpoints to see which hold idle TCP >= {2}s...`n" -f (Get-TimeStr), $candidates.Count, $HoldSeconds)
    $pool = [runspacefactory]::CreateRunspacePool(1, $candidates.Count)
    $pool.Open()
    $jobs = @()
    foreach ($c in $candidates) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript({
            param($h, $p, $holdSec)
            $tag = "${h}:${p}"
            $sock = $null
            try {
                $addrs = [System.Net.Dns]::GetHostAddresses($h) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
                $sock = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                $sock.ReceiveTimeout = 15000
                $sock.SendTimeout = 15000
                $sock.NoDelay = $true
                $sock.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::KeepAlive, $false)
                $sock.Connect($addrs[0], $p)
                $buf = New-Object byte[] 512
                if ($sock.Receive($buf) -le 0) {
                    return @{ Tag = $tag; Usable = $false; Line = ("  {0,-28} CLOSED (empty greeting)" -f $tag); Host = $h; Port = $p }
                }
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                while ($sw.Elapsed.TotalSeconds -lt $holdSec) {
                    if ($sock.Poll(5000000, [System.Net.Sockets.SelectMode]::SelectRead)) {
                        $r = $sock.Receive($buf)
                        if ($r -le 0) {
                            $el = [math]::Round($sw.Elapsed.TotalSeconds, 1)
                            return @{ Tag = $tag; Usable = $false; Line = ("  {0,-28} CLOSED (FIN) at {1,5}s" -f $tag, $el); Host = $h; Port = $p }
                        }
                    }
                }
                $payload = [System.Text.Encoding]::ASCII.GetBytes("a1 NOOP`r`n")
                [void]$sock.Send($payload)
                if ($sock.Receive($buf) -le 0) {
                    return @{ Tag = $tag; Usable = $false; Line = ("  {0,-28} CLOSED (EOF after poke)" -f $tag); Host = $h; Port = $p }
                }
                return @{ Tag = $tag; Usable = $true; Line = ("  {0,-28} HELD past {1}s  [USABLE]" -f $tag, $holdSec); Host = $h; Port = $p }
            } catch {
                return @{ Tag = $tag; Usable = $false; Line = ("  {0,-28} ERROR ({1})" -f $tag, $_.Exception.Message); Host = $h; Port = $p }
            } finally {
                if ($null -ne $sock) { try { $sock.Close() } catch {} }
            }
        }).AddArgument($c.Host).AddArgument($c.Port).AddArgument($HoldSeconds)
        $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke() }
    }
    $usable = @()
    foreach ($j in $jobs) {
        $res = $j.PS.EndInvoke($j.Handle)[0]
        $j.PS.Dispose()
        Write-Host $res.Line
        if ($res.Usable) { $usable += $res }
    }
    $pool.Close()
    Write-Host ("`n" + ("=" * 76))
    if ($usable.Count -gt 0) {
        $best = $usable[0]
        Write-Host ("RECOMMENDATION: {0} endpoint(s) held past {1}s." -f $usable.Count, $HoldSeconds)
        Write-Host ("  Use: .\diagnose.ps1 -HostName {0} -Port {1}" -f $best.Host, $best.Port)
        Write-Host ("=" * 76)
        exit 0
    } else {
        Write-Host ("WARNING: None of the candidate endpoints held past {0}s." -f $HoldSeconds)
        Write-Host ("=" * 76)
        exit 1
    }
}

if ($Passive) {
    $totalSec = $Samples * $Interval
    Write-Host ("[{0}] Passive workload sampler started: {1} samples every {2}s (~{3}s total)." -f (Get-TimeStr), $Samples, $Interval, $totalSec)
    $startCounters = Get-TcpCounterSnapshot
    for ($i = 1; $i -le $Samples; $i++) {
        $cur = Get-TcpCounterSnapshot
        $retransDelta = $cur["Tcp4.RetransmittedSegments"] - $startCounters["Tcp4.RetransmittedSegments"]
        $rstDelta = $cur["Tcp4.ResetConnections"] - $startCounters["Tcp4.ResetConnections"]
        Write-Host ("  [{0}] Sample {1}/{2}: Tcp4.RetransmittedSegments delta=+{3}, ResetConnections delta=+{4}" -f (Get-TimeStr), $i, $Samples, $retransDelta, $rstDelta)
        if ($i -lt $Samples) { Start-Sleep -Seconds $Interval }
    }
    $endCounters = Get-TcpCounterSnapshot
    Write-Host ("`n" + ("=" * 76))
    Write-Host "PASSIVE SAMPLER DIAGNOSIS"
    Write-Host ("=" * 76)
    Write-CounterSnapshot "OS TCP Counters (End vs Start)" $endCounters $startCounters
    Write-Host ("=" * 76)
    exit 0
}

if ($Quick) {
    $idleList = @(90)
} else {
    $idleList = @(
        $Idles.Split(",") |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne "" } |
        ForEach-Object { [int]$_ } |
        Sort-Object -Unique
    )
}

$localIPv4 = Get-LocalIPv4
$localIPv6 = Get-LocalIPv6
$publicIPv4 = Get-PublicIPv4
$wanInfo = Test-WanIpAddress -WanIpStr $WanIp -PublicIpStr $publicIPv4

Write-Host "`n[1/4] Addressing & Path Context:"
Write-Host ("  Local IPv4 address:     {0}" -f $(if ($localIPv4) { $localIPv4 } else { "not detected" }))
Write-Host ("  External Public IPv4:   {0}" -f $(if ($publicIPv4) { $publicIPv4 } else { "could not query" }))
Write-Host ("  Routed IPv6 available:  {0}" -f $(if ($localIPv6) { "yes ($localIPv6)" } else { "no" }))
if ($null -ne $wanInfo) {
    Write-Host ("  Router WAN IP check:    {0}" -f $wanInfo.Detail)
} else {
    Write-Host "  Router WAN IP check:    Tip: pass -WanIp <ROUTER_WAN_IP> (from http://192.168.1.1/)"
    Write-Host "                          to check whether your ISP places you behind CGNAT (100.64.0.0/10)."
}

$countersBefore = Get-TcpCounterSnapshot
Write-Host ""
Write-CounterSnapshot "[2/4] OS TCP Counters (Before Test)" $countersBefore

$maxIdle = ($idleList | Measure-Object -Maximum).Maximum
$estSeconds = $maxIdle + [math]::Max($PokeTimeout, $ControlInterval) + 5
Write-Host ("`n[3/4] Running IPv4 TCP Idle Probes against {0}:{1}" -f $HostName, $Port)
Write-Host ("      Idle windows: [{0}]s + active control (every {1}s)" -f ($idleList -join ", "), $ControlInterval)
Write-Host ("      Estimated wait: ~{0} seconds (~{1:N1} minutes)...`n" -f $estSeconds, ($estSeconds / 60.0))

$pool = [runspacefactory]::CreateRunspacePool(1, $idleList.Count + 1)
$pool.Open()
$jobs = @()

foreach ($idleSec in $idleList) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($ProbeScriptBlock).AddArgument("idle").AddArgument($HostName).AddArgument($Port).AddArgument($idleSec).AddArgument($PokeTimeout).AddArgument($ControlInterval)
    $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke() }
}

$psCtrl = [powershell]::Create()
$psCtrl.RunspacePool = $pool
[void]$psCtrl.AddScript($ProbeScriptBlock).AddArgument("control").AddArgument($HostName).AddArgument($Port).AddArgument($maxIdle).AddArgument($PokeTimeout).AddArgument($ControlInterval)
$jobs += @{ PS = $psCtrl; Handle = $psCtrl.BeginInvoke() }

$verdicts = @{}
$pending = [System.Collections.ArrayList]@($jobs)
while ($pending.Count -gt 0) {
    for ($idx = $pending.Count - 1; $idx -ge 0; $idx--) {
        $item = $pending[$idx]
        if ($item.Handle.IsCompleted) {
            $res = $item.PS.EndInvoke($item.Handle)[0]
            $item.PS.Dispose()
            $verdicts[$res.Tag] = $res.Verdict
            Write-Host ("  [{0}] {1,-11} {2,-8} {3}" -f $res.Time, $res.Tag, $res.Verdict, $res.Detail)
            $pending.RemoveAt($idx)
        }
    }
    if ($pending.Count -gt 0) {
        Start-Sleep -Milliseconds 250
    }
}
$pool.Close()

# Fresh connection test right after probes complete
$swFresh = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $addrs = [System.Net.Dns]::GetHostAddresses($HostName) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
    $sFresh = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
    $sFresh.ReceiveTimeout = 15000
    $sFresh.Connect($addrs[0], $Port)
    $buf = New-Object byte[] 512
    [void]$sFresh.Receive($buf)
    $sFresh.Close()
    $swFresh.Stop()
    $elFresh = [math]::Round($swFresh.Elapsed.TotalSeconds, 1)
    $verdicts["fresh"] = "ECHO"
    Write-Host ("  [{0}] {1,-11} {2,-8} {3}" -f (Get-TimeStr), "fresh", "ECHO", "Brand-new connection opened and greeted in ${elFresh}s")
} catch {
    $verdicts["fresh"] = "ERROR"
    Write-Host ("  [{0}] {1,-11} {2,-8} {3}" -f (Get-TimeStr), "fresh", "ERROR", $_.Exception.Message)
}

$countersAfter = Get-TcpCounterSnapshot
Write-Host ""
Write-CounterSnapshot "[4/4] OS TCP Counters (After Test)" $countersAfter $countersBefore

$survived = @($idleList | Where-Object { $verdicts["idle-${_}s"] -eq "ECHO" })
$evicted  = @($idleList | Where-Object { $verdicts["idle-${_}s"] -eq "SILENT" })
$reset    = @($idleList | Where-Object { $verdicts["idle-${_}s"] -eq "RST" })
$srvFin   = @($idleList | Where-Object { $verdicts["idle-${_}s"] -eq "SERVER" })
$ctrl     = $verdicts["control"]
$fresh    = $verdicts["fresh"]

Write-Host ("`n" + ("=" * 76))
Write-Host "DIAGNOSIS SUMMARY"
Write-Host ("=" * 76)
Write-Host ("  Survived (ECHO):        {0}" -f $(if ($survived.Count -gt 0) { "[" + ($survived -join ", ") + "]" } else { "none" }))
Write-Host ("  Silent Drop (SILENT):   {0}" -f $(if ($evicted.Count -gt 0) { "[" + ($evicted -join ", ") + "]" } else { "none" }))
if ($reset.Count -gt 0)  { Write-Host ("  Active Reset (RST):     [{0}]" -f ($reset -join ", ")) }
if ($srvFin.Count -gt 0) { Write-Host ("  Server FIN (discarded): [{0}]" -f ($srvFin -join ", ")) }
Write-Host ("  Active Control (20s):   {0}" -f $ctrl)
Write-Host ("  Fresh Connection Now:   {0}" -f $fresh)
Write-Host ("-" * 76)
if ($null -ne $wanInfo) {
    Write-Host ("  Addressing Check:       {0}" -f $wanInfo.Detail)
    Write-Host ("-" * 76)
}

if ($evicted.Count -gt 0 -and $ctrl -eq "ECHO" -and $fresh -eq "ECHO") {
    $minEv = ($evicted | Measure-Object -Minimum).Minimum
    $okBelow = @($survived | Where-Object { $_ -lt $minEv })
    if ($okBelow.Count -gt 0) {
        $maxOk = ($okBelow | Measure-Object -Maximum).Maximum
        $thresholdDesc = "between ${maxOk}s and ${minEv}s"
    } else {
        $thresholdDesc = "at or below ${minEv}s"
    }
    $approxFactor = [math]::Floor($Rfc5382MinSeconds / [math]::Max($minEv, 1))

    Write-Host "VERDICT: [FAULT CONFIRMED] SILENT NAT TCP IDLE EVICTION DETECTED`n"
    Write-Host "  1. Measured Idle Threshold: $thresholdDesc of inactivity."
    Write-Host "     RFC 5382 REQ-5 requires NAT timers for established TCP sessions to be at least"
    Write-Host "     2 hours 4 minutes (${Rfc5382MinSeconds}s). Your path drops mappings ~${approxFactor}x below the standard.`n"
    Write-Host "  2. Why This Is Definitely Idle Eviction (and Not Line Loss or Server Downtime):"
    Write-Host "     - The control connection to the same server survived by sending traffic every ${ControlInterval}s."
    Write-Host "     - A brand-new connection opened immediately afterwards succeeded right away."
    Write-Host "     - The idle connection received no FIN and no RST — its NAT translation entry was"
    Write-Host "       silently deleted, forcing your OS to retransmit into a black hole (~15 minutes).`n"
    Write-Host "  3. Determining Whether It Is ISP CGNAT or Your Home Router (ONT):"
    Write-Host ("     - Your external public IPv4 is: {0}" -f $(if ($publicIPv4) { $publicIPv4 } else { "unknown" }))
    Write-Host "     - Log into your router status page (typically http://192.168.1.1/) and check the"
    Write-Host "       WAN IPv4 address:"
    Write-Host "         * If the WAN IP is in 100.64.0.0/10 (RFC 6598) or differs from your external"
    Write-Host "           public IP, you are behind ISP CGNAT. Bridge mode or replacing your router"
    Write-Host "           will NOT fix CGNAT; ask your ISP to remove CGNAT (assign a public IPv4) or"
    Write-Host "           fix their CGNAT TCP established idle timer per RFC 5382 REQ-5."
    Write-Host "         * If the WAN IP equals your external public IP, only your router's own NAT is"
    Write-Host "           in the path (reconfigure its NAT TCP timeout, update firmware, or use bridge mode)."
    if ($localIPv6) {
        Write-Host "`n  4. IPv6 Note (Local IPv6 detected: $localIPv6):"
        Write-Host "     IPv6 is routed rather than NAT-translated, so IPv6 connections escape this fault"
        Write-Host "     while IPv4 connections stall. This makes failures look random across applications."
    }
    Write-Host ("=" * 76)
    exit 2
}

if ($reset.Count -gt 0 -and $ctrl -eq "ECHO") {
    $minRst = ($reset | Measure-Object -Minimum).Minimum
    $okBelow = @($survived | Where-Object { $_ -lt $minRst })
    if ($okBelow.Count -gt 0) {
        $maxOk = ($okBelow | Measure-Object -Maximum).Maximum
        $thresholdDesc = "between ${maxOk}s and ${minRst}s"
    } else {
        $thresholdDesc = "at or below ${minRst}s"
    }
    Write-Host "VERDICT: [FAULT CONFIRMED] ACTIVE TCP RESET (RST) ON IDLE CONNECTIONS`n"
    Write-Host "  A middlebox or firewall on your path actively resets idle TCP connections $thresholdDesc."
    Write-Host "  RFC 5382 REQ-5 requires established TCP sessions to survive >= ${Rfc5382MinSeconds}s (2h 04m)."
    Write-Host ("=" * 76)
    exit 2
}

if ($survived.Count -gt 0 -and $evicted.Count -eq 0 -and $reset.Count -eq 0 -and $ctrl -eq "ECHO") {
    $maxOk = ($survived | Measure-Object -Maximum).Maximum
    Write-Host "VERDICT: [HEALTHY] NO NAT IDLE EVICTION DETECTED UP TO ${maxOk}s`n"
    Write-Host "  All tested idle durations up to ${maxOk}s survived without silent drops, and the"
    Write-Host "  control connection remained healthy."
    if ($maxOk -lt $Rfc5382MinSeconds) {
        Write-Host "`n  Note: RFC 5382 REQ-5 demands >= ${Rfc5382MinSeconds}s (2h 04m). This run proves your network"
        Write-Host "  does not suffer from short ${maxOk}s eviction, not full 2h 04m RFC compliance."
        Write-Host "  To test longer windows, re-run with e.g. .\diagnose.ps1 -Idles '60,300,600,1800'"
    }
    Write-Host ("=" * 76)
    exit 0
}

Write-Host "VERDICT: [INCONCLUSIVE] COULD NOT ISOLATE IDLE EVICTION`n"
if ($ctrl -ne "ECHO") {
    Write-Host "  - The active control connection (poked every ${ControlInterval}s) did not survive ($ctrl)."
    Write-Host "    This points to general connectivity loss, firewall blocking, or server instability."
}
if ($srvFin.Count -gt 0 -and $evicted.Count -eq 0) {
    Write-Host "  - The test server closed connections early with FIN."
    Write-Host "    Run .\diagnose.ps1 -FindEndpoint to pick an endpoint that holds idle connections longer."
}
Write-Host ("=" * 76)
exit 1
