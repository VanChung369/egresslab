# Soak run on Windows with a WSL runtime: one approved hold served by serve-endpoint with automatic
# recovery, polite load, one optional injected fault, a sample every minute, and a teardown at the
# end. Start it detached (Start-Process) so that it outlives the shell that started it. A file named
# "stop" in OutDir ends it early, with the same teardown.
#
# It never prints or records an egress address, a key or the SOCKS password: addresses are only
# compared. The SOCKS credentials sit in OutDir while the run lasts and are deleted at teardown.
param(
    [Parameter(Mandatory)][string]$ControllerDir,   # egresslab-controller-lab.exe and egresslab-controller.exe
    [Parameter(Mandatory)][string]$ProfileId,
    [Parameter(Mandatory)][string]$OutDir,
    [string]$Distro = 'Ubuntu-22.04',
    [double]$Hours = 1,
    [int]$FaultAfterMinutes = 30,                    # 0: no injected fault
    [int]$RecoverAttempts = 3,
    [int]$Port = 1080,
    [int]$RequestEvery = 15,
    [string[]]$Hosts = @('api4.ipify.org', 'ifconfig.co'),
    [string]$DownloadUrl = 'https://proof.ovh.net/files/100Mb.dat',
    [string]$DownloadRate = '2k'
)

# Not Stop: in Windows PowerShell 5.1, 2>&1 on a native command turns its stderr into terminating errors.
$ErrorActionPreference = 'Continue'
$lab = Join-Path $ControllerDir 'egresslab-controller-lab.exe'
$api = Join-Path $ControllerDir 'egresslab-controller.exe'
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
New-Item -ItemType Directory -Force $OutDir | Out-Null

$events = Join-Path $OutDir 'events.log'
function Write-Event([string]$text) {
    "$((Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')) $text" | Add-Content -Path $events -Encoding utf8
}

# Keep the machine awake while this process runs (ES_CONTINUOUS | ES_SYSTEM_REQUIRED).
Add-Type -Namespace Soak -Name Power -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint flags);
'@
[void][Soak.Power]::SetThreadExecutionState(0x80000001)

function ConvertTo-WslPath([string]$path) { (wsl.exe -d $Distro -- wslpath -a ($path -replace '\\', '/')).Trim() }
$rootScript = ConvertTo-WslPath (Join-Path $PSScriptRoot 'wsl-root.sh')
function Invoke-Root([string[]]$RootArgs) {
    $out = wsl.exe -d $Distro -u root -- bash $rootScript @RootArgs 2>&1
    return @{ code = $LASTEXITCODE; out = ($out | Out-String).Trim() }
}

function Invoke-Lab([string[]]$LabArgs, [switch]$Local) {
    if ($Local) { $out = & $lab @LabArgs 2>&1 } else { $out = & $lab -runtime wsl -wsl-distro $Distro @LabArgs 2>&1 }
    $text = ($out | ForEach-Object { "$_" }) -join "`n"
    $json = $null
    if ($LASTEXITCODE -eq 0) { try { $json = $text | ConvertFrom-Json } catch { } }
    # Codes only: a helper error names no address, but keep the line short anyway.
    $code = if ($LASTEXITCODE -eq 0) { 'ok' } elseif ($text -match '([A-Z_]{6,})') { $Matches[1] } else { 'error' }
    return @{ ok = ($LASTEXITCODE -eq 0); json = $json; code = $code }
}

$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$helperLog = "/root/egresslab-soak-$stamp.log"
$journal = Join-Path $env:APPDATA 'EgressLab\egress-reservations.journal'
$summary = [ordered]@{ started = (Get-Date).ToString('o'); hours = $Hours; fault_after_minutes = $FaultAfterMinutes;
    recover_attempts = $RecoverAttempts; journal_bytes_start = (Get-Item $journal).Length }
$helper = $null; $serve = $null; $download = $null; $clock = $null; $endpointId = $null
$exitReason = 'completed'

try {
    $check = Invoke-Root @('precheck')
    if ($check.code -ne 0) { throw "precheck: $($check.out)" }

    $uid = (wsl.exe -d $Distro -- id -u).Trim(); $gid = (wsl.exe -d $Distro -- id -g).Trim()
    $helper = Start-Process wsl.exe -ArgumentList "-d $Distro -u root -- bash $rootScript start-helper $helperLog $uid $gid" -WindowStyle Hidden -PassThru
    if ((Invoke-Root @('wait-helper')).code -ne 0) { throw 'helper did not start' }
    $logStart = [int](Invoke-Root @('loglines', $helperLog)).out
    Write-Event 'helper started'

    $created = Invoke-Lab @('-approve', 'create-lab', $ProfileId)
    if (-not $created.ok) { throw "create-lab: $($created.code)" }
    $ns = $created.json.namespace
    $stage = Invoke-Lab @('stage-info', $ProfileId)
    if (-not $stage.ok) { throw "stage-info: $($stage.code)" }
    $tunnel = Invoke-Lab @('-approve', 'connect-tunnel', $ProfileId, $ns, $stage.json.stage_id)
    if (-not $tunnel.ok) { throw "connect-tunnel: $($tunnel.code)" }

    $probe = $null
    for ($i = 0; $i -lt 4; $i++) {
        Start-Sleep -Seconds 3
        $probe = Invoke-Lab @('-approve', 'probe-egress-multi', $ProfileId, $ns)
        if ($probe.ok -or $probe.code -ne 'EVIDENCE_UNAVAILABLE') { break }
    }
    if (-not $probe.ok) { throw "probe-egress-multi: $($probe.code)" }

    $reserved = Invoke-Lab @('-approve', 'reserve-egress', $ProfileId, $ns)
    if (-not $reserved.ok) { throw "reserve-egress: $($reserved.code)" }
    $reservedIP = $reserved.json.reservation.ipv4
    Write-Event 'hold prepared'

    # The endpoint through the HTTP controller, which then stops: serve-endpoint reads state.json.
    $apiProc = Start-Process $api -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 2
    $endpoint = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8787/api/v1/endpoints -ContentType 'application/json' `
        -Body (@{ name = "Soak $stamp"; protocol = 'socks5'; profile_id = $ProfileId; port = $Port } | ConvertTo-Json) -ErrorAction Stop
    $endpointId = $endpoint.id
    Stop-Process -Id $apiProc.Id

    $serveOut = Join-Path $OutDir 'endpoint-out.json'; $serveErr = Join-Path $OutDir 'endpoint-err.log'
    $serve = Start-Process $lab -ArgumentList "-approve -recover -recover-ip same -recover-attempts $RecoverAttempts serve-endpoint $endpointId" `
        -RedirectStandardOutput $serveOut -RedirectStandardError $serveErr -WindowStyle Hidden -PassThru
    for ($i = 0; $i -lt 100 -and -not ((Test-Path $serveOut) -and (Get-Content $serveOut -Raw) -match 'password'); $i++) { Start-Sleep -Milliseconds 200 }
    $listener = Get-Content $serveOut -Raw -ErrorAction Stop | ConvertFrom-Json
    if (-not $listener.password) { throw 'serve-endpoint did not start' }
    $proxy = "socks5h://$($listener.username):$($listener.password)@$($listener.listen)"
    Write-Event 'endpoint serving with automatic recovery'

    $clock = Start-Process wsl.exe -ArgumentList "-d $Distro -- bash $rootScript clocksteps $([int]($Hours * 3600))" `
        -RedirectStandardOutput (Join-Path $OutDir 'clocksteps.log') -WindowStyle Hidden -PassThru

    $requests = Join-Path $OutDir 'requests.csv'; 'time,host,result,http,seconds,curl_exit' | Set-Content $requests
    $downloads = Join-Path $OutDir 'downloads.csv'; 'started,ended,curl_exit,http,bytes,seconds' | Set-Content $downloads
    $samples = Join-Path $OutDir 'samples.csv'
    'time,elapsed_min,helper_alive,helper_rss_kb,helper_fds,helper_threads,namespaces,proxy_processes,lab_ws_mb,lab_handles,lab_threads,wsl_processes,journal_bytes,recoveries,req_ok,req_mismatch,req_fail,download_restarts,log' |
        Set-Content $samples

    $start = Get-Date; $end = $start.AddHours($Hours)
    $nextRequest = $start; $nextSample = $start; $faulted = $FaultAfterMinutes -le 0
    $ok = 0; $mismatch = 0; $fail = 0; $restarts = 0; $hostIndex = 0; $downloadStarted = $null; $downloadOut = $null

    while ((Get-Date) -lt $end) {
        if ($serve.HasExited) { $exitReason = "endpoint exited with code $($serve.ExitCode)"; Write-Event $exitReason; break }
        if (Test-Path (Join-Path $OutDir 'stop')) { $exitReason = 'stopped by request'; Write-Event $exitReason; break }

        $now = Get-Date

        if ($null -eq $download -or $download.HasExited) {
            if ($null -ne $download) {
                $fields = ((Get-Content $downloadOut -Raw) + '').Trim() -split ' '
                "$($downloadStarted.ToString('o')),$($now.ToString('o')),$($download.ExitCode),$($fields[0]),$($fields[1]),$($fields[2])" | Add-Content $downloads
                $restarts++
            }
            $downloadOut = Join-Path $OutDir 'download-current.out'
            $downloadStarted = $now
            $download = Start-Process $curl -ArgumentList @('-4', '-s', '-o', 'NUL', '--limit-rate', $DownloadRate, '--max-time', '86400',
                '-x', $proxy, '-w', '"%{http_code} %{size_download} %{time_total}"', $DownloadUrl) -RedirectStandardOutput $downloadOut -WindowStyle Hidden -PassThru
            [void]$download.Handle   # keeps the handle, without which ExitCode reads empty
        }

        if ($now -ge $nextRequest) {
            $target = $Hosts[$hostIndex % $Hosts.Count]; $hostIndex++
            $lines = & $curl -4 -s --max-time 60 -x $proxy -w '\n%{http_code} %{time_total}' "https://$target" 2>$null
            $exit = $LASTEXITCODE
            $meta = ("$($lines | Select-Object -Last 1)").Trim() -split ' '
            $body = ("$($lines | Select-Object -First 1)").Trim()
            $result = if ($exit -ne 0) { 'fail' } elseif ($body -eq $reservedIP) { 'match' } else { 'mismatch' }
            switch ($result) { 'match' { $ok++ } 'mismatch' { $mismatch++ } default { $fail++ } }
            "$($now.ToString('o')),$target,$result,$($meta[0]),$($meta[1]),$exit" | Add-Content $requests
            $nextRequest = $now.AddSeconds($RequestEvery)
        }

        if (-not $faulted -and $now -ge $start.AddMinutes($FaultAfterMinutes)) {
            $labs = Invoke-Lab @('list-labs')
            $current = @($labs.json.labs | Where-Object { $_.profile_id -eq $ProfileId })[0]
            $down = Invoke-Root @('linkdown', $current.namespace)
            Write-Event "fault injected: wg0 down (exit $($down.code))"
            $faulted = $true
        }

        if ($now -ge $nextSample) {
            $s = (Invoke-Root @('sample')).out
            $logs = (Invoke-Root @('logcounts', $helperLog, "$logStart")).out
            $serve.Refresh()
            $recoveries = @(Select-String -Path $serveErr -Pattern 'route replaced' -SimpleMatch -ErrorAction SilentlyContinue).Count
            $wsl = @(Get-Process wsl -ErrorAction SilentlyContinue).Count
            "$($now.ToString('o')),$([math]::Round(($now - $start).TotalMinutes, 1)),$s,$([math]::Round($serve.WorkingSet64 / 1MB, 1)),$($serve.HandleCount),$($serve.Threads.Count),$wsl,$((Get-Item $journal).Length),$recoveries,$ok,$mismatch,$fail,$restarts,$logs" |
                Add-Content $samples
            $nextSample = $now.AddSeconds(60)
        }

        Start-Sleep -Seconds 1
    }
} catch {
    $exitReason = "error: $($_.Exception.Message)"
    Write-Event $exitReason
} finally {
    Write-Event "teardown ($exitReason)"
    foreach ($p in @($download, $serve, $clock)) { if ($null -ne $p -and -not $p.HasExited) { Stop-Process -Id $p.Id -ErrorAction SilentlyContinue } }

    $holds = Invoke-Lab @('list-reservations') -Local
    foreach ($hold in @($holds.json.reservations | Where-Object { $_.owner.profile_id -eq $ProfileId })) {
        $released = Invoke-Lab @('-approve', 'release-egress', $hold.id)
        Write-Event "release: $($released.code), generation retired: $($released.json.revoked_lease.generation_retired)"
    }

    $labs = Invoke-Lab @('list-labs')
    foreach ($item in @($labs.json.labs | Where-Object { $_.profile_id -eq $ProfileId })) {
        $deleted = Invoke-Lab @('-approve', 'delete-lab', $ProfileId, $item.namespace)
        Write-Event "delete-lab: $($deleted.code)"
    }

    if ($endpointId) {
        $apiProc = Start-Process $api -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 2
        try { Invoke-RestMethod -Method Delete -Uri "http://127.0.0.1:8787/api/v1/endpoints/$endpointId" -ErrorAction Stop | Out-Null; Write-Event 'endpoint deleted' }
        catch { Write-Event "endpoint delete failed: $($_.Exception.Message)" }
        Stop-Process -Id $apiProc.Id -ErrorAction SilentlyContinue
    }

    if ($null -ne $helper) {
        Write-Event "helper stop: $((Invoke-Root @('stop-helper')).code)"
        $helper.WaitForExit(30000) | Out-Null
    }

    $summary.ended = (Get-Date).ToString('o')
    $summary.exit_reason = $exitReason
    $summary.journal_bytes_end = (Get-Item $journal).Length
    $summary.leftovers = (Invoke-Root @('leftovers')).out
    if (Test-Path (Join-Path $OutDir 'endpoint-err.log')) {
        $summary.recoveries = @(Select-String -Path (Join-Path $OutDir 'endpoint-err.log') -Pattern 'route replaced' -SimpleMatch).Count
    }
    $summary | ConvertTo-Json | Set-Content (Join-Path $OutDir 'summary.json') -Encoding utf8

    Remove-Item (Join-Path $OutDir 'endpoint-out.json') -ErrorAction SilentlyContinue
    Write-Event 'done'
    [void][Soak.Power]::SetThreadExecutionState(0x80000000)
}
