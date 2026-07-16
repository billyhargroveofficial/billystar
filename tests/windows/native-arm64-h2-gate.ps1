param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Prepare", "Run", "Cleanup")]
    [string]$Phase,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[a-z0-9-]{8,96}$")]
    [string]$RunId,

    [Parameter(Mandatory = $true)]
    [string]$SharedRoot,

    [string]$Server = "",
    [string]$ServerFingerprint = "",
    [string]$Nonce = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$LocalRoot = Join-Path $env:TEMP ("shadowpipe-win-" + $RunId)
$SharedInput = Join-Path $SharedRoot "input"
$SharedEvidence = Join-Path $SharedRoot "evidence"
$SharedClient = Join-Path $SharedInput "shadowpipe-client.exe"
$LocalClient = Join-Path $LocalRoot "shadowpipe-client.exe"
$ClientCredential = Join-Path $LocalRoot "client-credential.json"
$ClientEnrollment = Join-Path $LocalRoot "client-enrollment.json"
$UnauthorizedCredential = Join-Path $LocalRoot "unauthorized-credential.json"
$UnauthorizedEnrollment = Join-Path $LocalRoot "unauthorized-enrollment.json"
$SharedEnrollment = Join-Path $SharedInput "client-enrollment.json"

function Write-LinesNoBom {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Lines
    )
    foreach ($line in $Lines) {
        if ($line.Contains("`r") -or $line.Contains("`n")) {
            throw "line-oriented evidence contains an embedded newline"
        }
    }
    $text = if ($Lines.Count -eq 0) {
        ""
    } else {
        [string]::Join("`n", $Lines) + "`n"
    }
    [System.IO.File]::WriteAllText($Path, $text, $Utf8NoBom)
}

function Write-TextNoBom {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )
    [System.IO.File]::WriteAllText($Path, $Text, $Utf8NoBom)
}

function Remove-Ansi {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )
    $pattern = ([string][char]27) + "\[[0-?]*[ -/]*[@-~]"
    return [regex]::Replace($Text, $pattern, "")
}

function Get-CanonicalRouteLines {
    $items = @(Get-NetRoute -ErrorAction Stop | Sort-Object `
        @{Expression = { $_.AddressFamily.ToString() }}, `
        InterfaceIndex, DestinationPrefix, NextHop, RouteMetric, Protocol)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($item in $items) {
        $lines.Add((
            "{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f `
                $item.AddressFamily.ToString(),
                [int]$item.InterfaceIndex,
                [string]$item.DestinationPrefix,
                [string]$item.NextHop,
                [int]$item.RouteMetric,
                [int]$item.InterfaceMetric,
                $item.Protocol.ToString()
        ))
    }
    return $lines.ToArray()
}

function Get-CanonicalDnsLines {
    $items = @(Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object `
        InterfaceIndex, @{Expression = { $_.AddressFamily.ToString() }})
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($item in $items) {
        $addresses = @($item.ServerAddresses | ForEach-Object { [string]$_ })
        $lines.Add((
            "{0}|{1}|{2}|{3}" -f `
                [int]$item.InterfaceIndex,
                [string]$item.InterfaceAlias,
                $item.AddressFamily.ToString(),
                [string]::Join(",", $addresses)
        ))
    }
    return $lines.ToArray()
}

function Write-NetworkSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("before", "after")]
        [string]$Label
    )
    $routePath = Join-Path $SharedEvidence ("windows-routes-" + $Label + ".txt")
    $dnsPath = Join-Path $SharedEvidence ("windows-dns-" + $Label + ".txt")
    $rawRoutePath = Join-Path $SharedEvidence ("windows-routes-" + $Label + ".raw.txt")
    $rawDnsPath = Join-Path $SharedEvidence ("windows-dns-" + $Label + ".raw.txt")
    Write-LinesNoBom -Path $routePath -Lines @(Get-CanonicalRouteLines)
    Write-LinesNoBom -Path $dnsPath -Lines @(Get-CanonicalDnsLines)
    Write-TextNoBom -Path $rawRoutePath -Text (
        (Get-NetRoute -ErrorAction Stop | Sort-Object `
            @{Expression = { $_.AddressFamily.ToString() }}, `
            InterfaceIndex, DestinationPrefix, NextHop |
            Format-Table -AutoSize | Out-String -Width 4096)
    )
    Write-TextNoBom -Path $rawDnsPath -Text (
        (Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object `
            InterfaceIndex, @{Expression = { $_.AddressFamily.ToString() }} |
            Format-Table -AutoSize | Out-String -Width 4096)
    )
    $routeHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $routePath).Hash.ToLowerInvariant()
    $dnsHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $dnsPath).Hash.ToLowerInvariant()
    Write-LinesNoBom -Path (Join-Path $SharedEvidence ("windows-network-" + $Label + ".env")) -Lines @(
        "schema_version=1",
        ("route_sha256=" + $routeHash),
        ("dns_sha256=" + $dnsHash)
    )
}

function Invoke-Captured {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 180)]
        [int]$TimeoutSeconds
    )
    $stdout = Join-Path $LocalRoot ($Name + ".stdout")
    $stderr = Join-Path $LocalRoot ($Name + ".stderr")
    Remove-Item -Force -LiteralPath $stdout, $stderr -ErrorAction SilentlyContinue
    foreach ($argument in $Arguments) {
        if ($argument -match "[\s`"]") {
            throw "generated native argument contains unsupported whitespace or quotes"
        }
    }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $LocalClient
    $startInfo.Arguments = [string]::Join(" ", $Arguments)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "native process did not start"
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 100
        $process.Refresh()
    }
    $timedOut = $false
    if (-not $process.HasExited) {
        $timedOut = $true
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
    $process.WaitForExit()
    $process.Refresh()
    $exitCode = if ($timedOut) { 124 } else { [int]$process.ExitCode }
    $stdoutText = $process.StandardOutput.ReadToEnd()
    $stderrText = $process.StandardError.ReadToEnd()
    $stdoutPlain = Remove-Ansi -Text $stdoutText
    $stderrPlain = Remove-Ansi -Text $stderrText
    Write-TextNoBom -Path $stdout -Text $stdoutText
    Write-TextNoBom -Path $stderr -Text $stderrText
    Write-TextNoBom -Path (Join-Path $SharedEvidence ($Name + ".stdout.txt")) -Text $stdoutText
    Write-TextNoBom -Path (Join-Path $SharedEvidence ($Name + ".stderr.txt")) -Text $stderrText
    Write-TextNoBom -Path (Join-Path $SharedEvidence ($Name + ".stdout.normalized.txt")) `
        -Text $stdoutPlain
    Write-TextNoBom -Path (Join-Path $SharedEvidence ($Name + ".stderr.normalized.txt")) `
        -Text $stderrPlain
    Write-LinesNoBom -Path (Join-Path $SharedEvidence ($Name + ".status.env")) -Lines @(
        "schema_version=1",
        ("exit_code=" + $exitCode),
        ("timed_out=" + $timedOut.ToString().ToLowerInvariant())
    )
    return [PSCustomObject]@{
        ExitCode = $exitCode
        TimedOut = $timedOut
        Stdout = $stdoutText
        Stderr = $stderrText
        Combined = ($stdoutText + "`n" + $stderrText)
        CombinedPlain = ($stdoutPlain + "`n" + $stderrPlain)
    }
}

function Assert-Arm64Windows {
    $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    if ($architecture -ne "Arm64") {
        throw ("native gate requires Windows ARM64, observed " + $architecture)
    }
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Write-LinesNoBom -Path (Join-Path $SharedEvidence "windows-platform.env") -Lines @(
        "schema_version=1",
        ("os_architecture=" + $architecture),
        ("os_caption=" + ([string]$os.Caption -replace "[`r`n=]", " ")),
        ("os_version=" + ([string]$os.Version -replace "[`r`n=]", " ")),
        ("powershell_version=" + $PSVersionTable.PSVersion.ToString())
    )
}

function Invoke-Prepare {
    if (Test-Path -LiteralPath $LocalRoot) {
        throw ("generated local root already exists: " + $LocalRoot)
    }
    New-Item -ItemType Directory -Path $LocalRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $SharedEvidence | Out-Null
    Assert-Arm64Windows
    if (-not (Test-Path -LiteralPath $SharedClient -PathType Leaf)) {
        throw ("missing shared PE: " + $SharedClient)
    }
    Copy-Item -LiteralPath $SharedClient -Destination $LocalClient
    $sharedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $SharedClient).Hash.ToLowerInvariant()
    $localHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $LocalClient).Hash.ToLowerInvariant()
    if ($sharedHash -ne $localHash) {
        throw "shared-to-local PE hash mismatch"
    }
    Write-LinesNoBom -Path (Join-Path $SharedEvidence "windows-artifact.env") -Lines @(
        "schema_version=1",
        ("sha256=" + $localHash),
        ("size_bytes=" + (Get-Item -LiteralPath $LocalClient).Length),
        "transfer_hash_match=true"
    )

    Write-NetworkSnapshot -Label "before"
    $env:RUST_LOG = "info"

    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback,
        0
    )
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $acceptTask = $listener.AcceptTcpClientAsync()
    $missingPin = Invoke-Captured -Name "missing-pin" -TimeoutSeconds 20 -Arguments @(
        "--development-user-credential",
        "--client-credential", $ClientCredential,
        "--server", ("127.0.0.1:" + $port),
        "--camouflage", "h2",
        "--message", "must-not-connect"
    )
    Start-Sleep -Milliseconds 500
    $connectionCount = if ($acceptTask.IsCompleted) { 1 } else { 0 }
    if ($acceptTask.IsCompleted -and -not $acceptTask.IsFaulted) {
        $accepted = $acceptTask.Result
        $accepted.Dispose()
    }
    $listener.Stop()
    if ($missingPin.ExitCode -eq 0 -or $missingPin.TimedOut) {
        throw "missing-pin process did not fail promptly"
    }
    if ($missingPin.Combined -notmatch "missing required --server-fp") {
        throw "missing-pin error did not identify the mandatory pin gate"
    }
    if ($connectionCount -ne 0) {
        throw "missing-pin validation opened a loopback TCP connection"
    }

    $directListener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback,
        0
    )
    $directListener.Start()
    $directPort = ([System.Net.IPEndPoint]$directListener.LocalEndpoint).Port
    $directAcceptTask = $directListener.AcceptTcpClientAsync()
    $directArguments = @(
        "--development-user-credential",
        "--client-credential", $ClientCredential,
        "--server", ("127.0.0.1:" + $directPort),
        "--camouflage", "h2",
        "--message", "direct-must-not-connect"
    )
    $savedErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $directOutput = (
            & $LocalClient @directArguments 2>&1 |
                ForEach-Object { $_.ToString() } |
                Out-String
        )
        $directExitCode = [int]$LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorAction
    }
    Start-Sleep -Milliseconds 500
    $directConnectionCount = if ($directAcceptTask.IsCompleted) { 1 } else { 0 }
    if ($directAcceptTask.IsCompleted -and -not $directAcceptTask.IsFaulted) {
        $directAccepted = $directAcceptTask.Result
        $directAccepted.Dispose()
    }
    $directListener.Stop()
    Write-TextNoBom -Path (Join-Path $SharedEvidence "missing-pin-direct-output.txt") `
        -Text $directOutput
    Write-LinesNoBom -Path (Join-Path $SharedEvidence "missing-pin-direct-status.env") -Lines @(
        "schema_version=1",
        ("exit_code=" + $directExitCode),
        ("tcp_connection_count=" + $directConnectionCount)
    )
    if ($directExitCode -eq 0) {
        throw "direct native missing-pin invocation returned a success exit code"
    }
    if ($directOutput -notmatch "missing required --server-fp") {
        throw "direct native missing-pin invocation omitted the mandatory pin error"
    }
    if ($directConnectionCount -ne 0) {
        throw "direct native missing-pin invocation opened a loopback TCP connection"
    }

    Write-LinesNoBom -Path (Join-Path $SharedEvidence "missing-pin-proof.env") -Lines @(
        "schema_version=1",
        "expected_failure=true",
        ("process_api_exit_code=" + $missingPin.ExitCode),
        "process_api_tcp_connection_count=0",
        ("direct_native_exit_code=" + $directExitCode),
        "direct_native_tcp_connection_count=0",
        "pin_validation_before_network_io=true"
    )

    $provision = Invoke-Captured -Name "credential-provision" -TimeoutSeconds 30 -Arguments @(
        "--development-user-credential",
        "--generate-client-credential",
        "--client-credential", $ClientCredential,
        "--write-client-enrollment", $ClientEnrollment
    )
    if ($provision.ExitCode -ne 0 -or $provision.TimedOut) {
        throw "enrolled Windows credential provisioning failed"
    }
    $unauthorizedProvision = Invoke-Captured `
        -Name "unauthorized-credential-provision" -TimeoutSeconds 30 -Arguments @(
        "--development-user-credential",
        "--generate-client-credential",
        "--client-credential", $UnauthorizedCredential,
        "--write-client-enrollment", $UnauthorizedEnrollment
    )
    if ($unauthorizedProvision.ExitCode -ne 0 -or $unauthorizedProvision.TimedOut) {
        throw "unauthorized Windows credential provisioning failed"
    }
    foreach ($path in @(
        $ClientCredential,
        $ClientEnrollment,
        $UnauthorizedCredential,
        $UnauthorizedEnrollment
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw ("credential provisioning omitted " + $path)
        }
    }
    Copy-Item -LiteralPath $ClientEnrollment -Destination $SharedEnrollment
    $enrollmentHash = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $SharedEnrollment
    ).Hash.ToLowerInvariant()
    Write-LinesNoBom -Path (Join-Path $SharedEvidence "prepare-status.env") -Lines @(
        "schema_version=1",
        "prepare_status=valid",
        "credential_scope=windows_local_temp_only",
        "development_user_credential=true",
        "tunnel=false",
        ("enrollment_sha256=" + $enrollmentHash)
    )
}

function Invoke-Run {
    Assert-Arm64Windows
    foreach ($path in @($LocalClient, $ClientCredential, $UnauthorizedCredential)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw ("missing prepared local artifact: " + $path)
        }
    }
    if ($Server -notmatch "^(?<ip>(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})):(?<port>[1-9][0-9]{0,4})$") {
        throw "server must be one exact RFC1918 IPv4 socket"
    }
    if ($ServerFingerprint -notmatch "^[0-9a-f]{64}$") {
        throw "server fingerprint must be 64 lowercase hex characters"
    }
    if ($Nonce -notmatch "^[0-9a-f]{32}$") {
        throw "nonce must be 128-bit lowercase hex"
    }
    $env:RUST_LOG = "info"
    $common = @(
        "--development-user-credential",
        "--server", $Server,
        "--server-fp", $ServerFingerprint,
        "--camouflage", "h2",
        "--connect-timeout-secs", "10",
        "--outer-handshake-timeout-secs", "10",
        "--inner-handshake-timeout-secs", "10",
        "--carrier-idle-timeout-secs", "10",
        "--carrier-probe-timeout-secs", "5",
        "--carrier-write-timeout-secs", "5"
    )

    $echo = Invoke-Captured -Name "authenticated-h2-echo" -TimeoutSeconds 45 -Arguments (
        $common + @(
            "--client-credential", $ClientCredential,
            "--message", $Nonce
        )
    )
    if ($echo.ExitCode -ne 0 -or $echo.TimedOut) {
        throw "authenticated H2 nonce echo failed"
    }
    if ($echo.Combined -notmatch ([regex]::Escape("echo: " + $Nonce))) {
        throw "authenticated H2 output omitted the exact nonce echo"
    }

    $unauthorized = Invoke-Captured -Name "unauthorized-h2" -TimeoutSeconds 45 -Arguments (
        $common + @(
            "--client-credential", $UnauthorizedCredential,
            "--message", "unauthorized-must-not-echo"
        )
    )
    if ($unauthorized.ExitCode -eq 0 -or $unauthorized.TimedOut) {
        throw "unenrolled credential was not rejected promptly"
    }
    if ($unauthorized.Combined -match "echo: unauthorized-must-not-echo") {
        throw "unenrolled credential received an authenticated echo"
    }

    $load = Invoke-Captured -Name "authenticated-h2-load-1mib" `
        -TimeoutSeconds 90 -Arguments (
        $common + @(
            "--client-credential", $ClientCredential,
            "--loadtest", "1"
        )
    )
    if ($load.ExitCode -ne 0 -or $load.TimedOut) {
        throw "authenticated H2 1 MiB workload failed"
    }
    if ($load.CombinedPlain -notmatch "LOADTEST: OK") {
        throw "1 MiB workload did not publish a clean terminal outcome"
    }
    if (
        $load.CombinedPlain -notmatch "\bsent_kb=1024\b" -or
        $load.CombinedPlain -notmatch "\bechoed_kb=1024\b"
    ) {
        throw "1 MiB workload did not account for exactly 1024 KiB in both directions"
    }

    Write-NetworkSnapshot -Label "after"
    $beforeRoutes = Join-Path $SharedEvidence "windows-routes-before.txt"
    $afterRoutes = Join-Path $SharedEvidence "windows-routes-after.txt"
    $beforeDns = Join-Path $SharedEvidence "windows-dns-before.txt"
    $afterDns = Join-Path $SharedEvidence "windows-dns-after.txt"
    $routeMatch = (
        (Get-FileHash -Algorithm SHA256 -LiteralPath $beforeRoutes).Hash -eq
        (Get-FileHash -Algorithm SHA256 -LiteralPath $afterRoutes).Hash
    )
    $dnsMatch = (
        (Get-FileHash -Algorithm SHA256 -LiteralPath $beforeDns).Hash -eq
        (Get-FileHash -Algorithm SHA256 -LiteralPath $afterDns).Hash
    )
    if (-not $routeMatch -or -not $dnsMatch) {
        throw "Windows route or DNS state changed during the no-TUN socket gate"
    }
    Write-LinesNoBom -Path (Join-Path $SharedEvidence "run-status.env") -Lines @(
        "schema_version=1",
        "run_status=valid",
        "carrier=h2_chunk_tcp",
        "protocol_auth=v3_hybrid_mandatory",
        "development_user_credential=true",
        "tunnel=false",
        "authenticated_nonce_echo=valid",
        "unenrolled_credential_rejection=valid",
        "load_payload_bytes=1048576",
        "load_echoed_bytes=1048576",
        ("windows_route_digest_match=" + $routeMatch.ToString().ToLowerInvariant()),
        ("windows_dns_digest_match=" + $dnsMatch.ToString().ToLowerInvariant())
    )
}

function Invoke-Cleanup {
    $cleanupErrors = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $LocalRoot) {
        try {
            Remove-Item -Recurse -Force -LiteralPath $LocalRoot
        } catch {
            $cleanupErrors.Add($_.Exception.Message)
        }
    }
    if (Test-Path -LiteralPath $SharedEnrollment) {
        try {
            Remove-Item -Force -LiteralPath $SharedEnrollment
        } catch {
            $cleanupErrors.Add($_.Exception.Message)
        }
    }
    New-Item -ItemType Directory -Force -Path $SharedEvidence | Out-Null
    $status = if ($cleanupErrors.Count -eq 0) { "valid" } else { "failed" }
    Write-LinesNoBom -Path (Join-Path $SharedEvidence "windows-cleanup.env") -Lines @(
        "schema_version=1",
        ("windows_cleanup_status=" + $status),
        ("local_root_absent=" + (-not (Test-Path -LiteralPath $LocalRoot)).ToString().ToLowerInvariant()),
        ("shared_enrollment_absent=" + (-not (Test-Path -LiteralPath $SharedEnrollment)).ToString().ToLowerInvariant())
    )
    if ($cleanupErrors.Count -ne 0) {
        Write-LinesNoBom -Path (Join-Path $SharedEvidence "windows-cleanup-errors.txt") `
            -Lines $cleanupErrors.ToArray()
        throw "Windows private-artifact cleanup failed"
    }
}

switch ($Phase) {
    "Prepare" { Invoke-Prepare }
    "Run" { Invoke-Run }
    "Cleanup" { Invoke-Cleanup }
}
