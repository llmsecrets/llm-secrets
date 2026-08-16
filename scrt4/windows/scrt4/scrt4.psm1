# scrt4.psm1 -- native Windows PowerShell client for the scrt4 daemon.
#
# Faithful port of the core command surface of daemon/bin/scrt4-core
# (v0.2), with the localhost WebAuthn flows restored from the v0.1.0
# monolith (daemon/bin/scrt4) so Windows Hello is the primary unlock.
# The daemon owns all vault/session state; this client is thin: it
# authenticates the user and shapes JSON-RPC requests over a named pipe.
#
# Windows PowerShell 5.1 compatible (also runs on PowerShell 7+).

#  Constants / init 

$script:Version = '0.3.3'


$script:DevMode = $false
if ($env:SCRT4_DEV_MODE -eq '1' -or $env:SCRT4_DEV_MODE -eq 'true') {
    $script:DevMode = $true
}

# CONFIG_DIR follows the daemon's keystore::config_dir(): hardened uses
# ~/.scrt4, dev uses ~/.scrt4-dev. Must stay in sync with daemon/src/keystore.rs.
if ($script:DevMode) {
    $script:ConfigDir = Join-Path $env:USERPROFILE '.scrt4-dev'
} else {
    $script:ConfigDir = Join-Path $env:USERPROFILE '.scrt4'
}

$script:RelayBase = 'https://auth.llmsecrets.com'
$script:RelayPoll = 'https://llmsecrets-auth.vercel.app'  # CLI polling host (bypasses corporate filters)

# Pipe name must match daemon/src/winpipe.rs::pipe_name().
# NamedPipeClientStream takes the bare name (no \\.\pipe\ prefix).
$script:PipeName = 'scrt4-' + $env:USERNAME
if ($env:SCRT4_PIPE_NAME) {
    $script:PipeName = $env:SCRT4_PIPE_NAME -replace '^\\\\\.\\pipe\\', ''
}

# Global flags (set per invocation by the dispatcher)
$script:ForceCli = $false
$script:ForceAuth = $false

# QR codes use Unicode half-blocks; make sure the console can show them.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

#  Output helpers (bash color parity) 

function Write-Info  { param([string]$Text) Write-Host $Text -ForegroundColor Cyan }
function Write-Ok    { param([string]$Text) Write-Host $Text -ForegroundColor Green }
function Write-Warn2 { param([string]$Text) Write-Host $Text -ForegroundColor Yellow }
function Write-Err   { param([string]$Text) Write-Host $Text -ForegroundColor Red }

#  GUI detection (mirrors _has_gui in scrt4-core) 

function Test-Scrt4Gui {
    if ($script:DevMode) { return $false }
    if ($env:SCRT4_NO_GUI -eq '1') { return $false }
    if ($script:ForceCli) { return $false }
    return [Environment]::UserInteractive
}

#  Daemon I/O 

# Send-Scrt4Request REQUEST -- sends a single newline-terminated JSON
# message to the daemon pipe and returns the parsed response object.
# This is the only path through which CLI code reaches the daemon.
#
# Framing: the daemon replies with exactly one \n-terminated JSON line
# per request (handlers.rs::handle_connection), so we read bytes until
# the first LF and then close; the daemon's read loop exits when we
# disconnect. Long operations (unlock_local_complete) simply block here,
# matching the bash client's untimed socket read.
function Send-Scrt4Request {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Request,
        [int]$ConnectTimeoutMs = 3000,
        [switch]$NoAutoStart
    )

    $json = ConvertTo-Json -InputObject $Request -Depth 10 -Compress

    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', $script:PipeName, [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None)
    try {
        try {
            $pipe.Connect($ConnectTimeoutMs)
        } catch {
            $started = $false
            if (-not $NoAutoStart) { $started = Start-Scrt4Daemon }
            if (-not $started) {
                throw "Cannot connect to daemon (pipe: $($script:PipeName)). Start with: scrt4 daemon"
            }
            $pipe.Connect($ConnectTimeoutMs)
        }

        $utf8 = New-Object System.Text.UTF8Encoding($false)
        $bytes = $utf8.GetBytes($json + "`n")
        $pipe.Write($bytes, 0, $bytes.Length)
        $pipe.Flush()

        $ms = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 4096
        while ($true) {
            $n = $pipe.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $ms.Write($buf, 0, $n)
            if ([Array]::IndexOf($buf, [byte]10, 0, $n) -ge 0) { break }
        }
        $text = $utf8.GetString($ms.ToArray()).TrimEnd("`r", "`n")
        if (-not $text) { throw 'Empty response from daemon' }
        return ($text | ConvertFrom-Json)
    } finally {
        $pipe.Dispose()
    }
}

# Resolve the daemon binary: alongside the module, the standard install
# dir, the repo build output, then PATH (mirrors cmd_daemon's search).
function Find-Scrt4DaemonExe {
    $candidates = @(
        (Join-Path $PSScriptRoot 'scrt4-daemon.exe'),
        (Join-Path (Split-Path $PSScriptRoot -Parent) 'scrt4-daemon.exe'),
        (Join-Path $env:LOCALAPPDATA 'scrt4\scrt4-daemon.exe'),
        (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'daemon\target\release\scrt4-daemon.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    $cmd = Get-Command 'scrt4-daemon.exe' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# Start the daemon hidden and wait for the pipe to come up. Returns
# $true on success. SCRT4_NO_AUTOSTART=1 opts out (then the caller
# reports the connect error like the bash client does).
function Start-Scrt4Daemon {
    if ($env:SCRT4_NO_AUTOSTART -eq '1') { return $false }

    $exe = Find-Scrt4DaemonExe
    if (-not $exe) { return $false }

    Write-Warn2 "Daemon not running -- starting $exe"
    Start-Process -FilePath $exe -WindowStyle Hidden | Out-Null

    for ($i = 0; $i -lt 25; $i++) {
        Start-Sleep -Milliseconds 200
        $probe = New-Object System.IO.Pipes.NamedPipeClientStream(
            '.', $script:PipeName, [System.IO.Pipes.PipeDirection]::InOut,
            [System.IO.Pipes.PipeOptions]::None)
        try {
            $probe.Connect(100)
            $probe.Dispose()
            return $true
        } catch {
            $probe.Dispose()
        }
    }
    return $false
}

#  TCB: auth gates (mirror scrt4-core ensure_unlocked / _wa_gate) 

function Test-Scrt4Unlocked {
    if ($script:DevMode -and -not $script:ForceAuth) { return $true }

    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'status' } } catch { }
    if ($resp -and $resp.success -and $resp.data.active) { return $true }

    Write-Warn2 'Session not active. Run: scrt4 unlock'
    return $false
}

# WebAuthn step-up gate: localhost browser flow first (Windows Hello),
# remote QR flow as fallback -- the v0.1.0 monolith behavior.
#
function Invoke-Scrt4WaGate {
    if ($script:DevMode -and -not $script:ForceAuth) { return $true }

    Write-Info 'WebAuthn verification required...'

    $params = @{ ttl = 7200 }
    $start = $null
    try { $start = Send-Scrt4Request @{ method = 'unlock_local'; params = $params } } catch { }
    if ($start -and $start.success) {
        $url = $start.data.url
        Write-Info 'Opening browser for authentication...'
        Start-Process $url | Out-Null
        Write-Host "  URL: $url"
        Write-Host '  Authenticate in the browser window.'
        Write-Host ''
        Write-Info '  Waiting for authentication...'
        $done = $null
        try { $done = Send-Scrt4Request @{ method = 'unlock_local_complete'; params = @{ ttl = 7200 } } } catch { }
        if ($done -and $done.success) {
            Write-Ok 'WebAuthn verified.'
            return $true
        }
    }

    Write-Warn2 'Trying remote authentication...'
    if (Invoke-Scrt4RelayUnlock -Ttl 7200) { return $true }
    Write-Err 'WebAuthn verification failed.'
    return $false
}

#  WebAuthn flows 

# Ask the relay for a 4-digit AuthCode so users can type a code at
# auth.llmsecrets.com instead of scanning the QR (shorten_qr_url).
function Get-Scrt4AuthCode {
    param([string]$SessionId)
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "$($script:RelayPoll)/api/relay/shorten" `
            -ContentType 'application/json' `
            -Body (ConvertTo-Json @{ session_id = $SessionId } -Compress) -TimeoutSec 10
        if ($resp.code) { return [string]$resp.code }
    } catch { }
    return ''
}

# Poll the relay until the encrypted payload appears (poll_relay).
# Blocks indefinitely; Ctrl+C cancels.
function Wait-Scrt4RelayPayload {
    param([string]$SessionId)
    $url = "$($script:RelayPoll)/api/relay/$SessionId"
    while ($true) {
        try {
            $body = Invoke-RestMethod -Uri $url -TimeoutSec 10
            if ($body.payload) { return [string]$body.payload }
        } catch { }
        Start-Sleep -Milliseconds 1500
    }
}

# Print the QR challenge + AuthCode block shared by unlock/setup relay flows.
function Show-Scrt4RelayChallenge {
    param($Data, [string]$Url, [string]$AuthCode, [string]$TapHint)

    Write-Host ''
    Write-Info "  Auth URL: $Url"
    if ($AuthCode) {
        Write-Host ''
        Write-Host '  AuthCode:  ' -NoNewline -ForegroundColor Cyan
        Write-Host $AuthCode -ForegroundColor Green
        Write-Info '  Enter at auth.llmsecrets.com'
        Write-Host ''
    }
    if ($Data.qr) {
        Write-Host $Data.qr
    }
    # Native Windows: also open the auth page locally so a desktop
    # passkey (Windows Hello) can complete the ceremony without a phone.
    try {
        Start-Process $Url | Out-Null
        Write-Host '  (opened in your browser -- you can use Windows Hello there,'
        Write-Host '   or scan the QR with your phone)'
    } catch {
        Write-Host '  Scan the QR code with your phone camera.'
    }
    Write-Host $TapHint
    Write-Host ''
    Write-Info '  Waiting for authentication...'
}

# run_unlock_flow -- remote QR/phone unlock via the relay.
function Invoke-Scrt4RelayUnlock {
    param([long]$Ttl = 72000)

    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'unlock_webauthn'; params = @{ ttl = $Ttl } } } catch {
        Write-Err "Unlock failed: $($_.Exception.Message)"
        return $false
    }
    if (-not $resp.success) {
        Write-Err "Unlock failed: $($resp.error)"
        return $false
    }

    # No URL -> the unlock already succeeded (e.g. cached session).
    if (-not $resp.data.url) {
        if ($null -ne $resp.data.count) {
            Write-Ok "Unlocked ($($resp.data.count) secrets)"
        } else {
            Write-Ok 'OK'
        }
        return $true
    }

    $url = $resp.data.url
    $authCode = Get-Scrt4AuthCode -SessionId $resp.data.session_id
    Show-Scrt4RelayChallenge -Data $resp.data -Url $url -AuthCode $authCode `
        -TapHint "  Then tap 'Unlock with Passkey' on the page."

    $payload = Wait-Scrt4RelayPayload -SessionId $resp.data.session_id
    Write-Ok '  received!'

    Write-Info 'Decrypting vault...'
    $done = $null
    try {
        $done = Send-Scrt4Request @{
            method = 'unlock_webauthn_complete'
            params = @{
                encrypted_payload = $payload
                wrapping_key      = $resp.data.wrapping_key
                ttl               = $Ttl
            }
        }
    } catch {
        Write-Err "Unlock failed: $($_.Exception.Message)"
        return $false
    }
    if ($done.success) {
        $count = 0
        if ($null -ne $done.data.count) { $count = $done.data.count }
        Write-Ok "Unlocked $count secret(s)."
        return $true
    }
    Write-Err "Unlock failed: $($done.error)"
    return $false
}

# run_unlock_local_flow -- localhost browser unlock (Windows Hello).
function Invoke-Scrt4LocalUnlock {
    param([long]$Ttl = 72000)

    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'unlock_local'; params = @{ ttl = $Ttl } } } catch {
        Write-Err "Unlock failed: $($_.Exception.Message)"
        return $false
    }
    if (-not $resp.success) {
        $err = [string]$resp.error
        # Credential registered for the relay rpId only -> remote fallback.
        if ($err -match 'rpId') {
            Write-Warn2 $err
            Write-Warn2 'Falling back to remote QR flow...'
            return (Invoke-Scrt4RelayUnlock -Ttl $Ttl)
        }
        Write-Err "Unlock failed: $err"
        return $false
    }

    $url = $resp.data.url
    Write-Info 'Opening browser for authentication...'
    Start-Process $url | Out-Null
    Write-Host "  URL: $url"
    Write-Host '  Authenticate in the browser window (Windows Hello).'
    Write-Host ''
    Write-Info '  Waiting for authentication...'

    $done = $null
    try { $done = Send-Scrt4Request @{ method = 'unlock_local_complete'; params = @{ ttl = $Ttl } } } catch {
        Write-Err "Unlock failed: $($_.Exception.Message)"
        return $false
    }
    if ($done.success) {
        $count = 0
        if ($null -ne $done.data.count) { $count = $done.data.count }
        Write-Ok "Unlocked $count secret(s)."
        return $true
    }
    Write-Err "Unlock failed: $($done.error)"
    return $false
}

# run_setup_flow -- remote passkey enrollment via the relay. On native
# Windows the auth page is also opened locally, so the passkey can be
# created with Windows Hello in the desktop browser (no phone needed).
function Invoke-Scrt4RelaySetup {
    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'setup_webauthn' } } catch {
        Write-Err "Setup failed: $($_.Exception.Message)"
        return $false
    }
    if (-not $resp.success) {
        Write-Err "Setup failed: $($resp.error)"
        return $false
    }

    $url = $resp.data.url
    $authCode = Get-Scrt4AuthCode -SessionId $resp.data.session_id
    Show-Scrt4RelayChallenge -Data $resp.data -Url $url -AuthCode $authCode `
        -TapHint "  Then tap 'Register Passkey' on the page."

    $payload = Wait-Scrt4RelayPayload -SessionId $resp.data.session_id
    Write-Ok '  received!'

    Write-Info 'Completing registration...'
    $done = $null
    try {
        $done = Send-Scrt4Request @{
            method = 'setup_webauthn_complete'
            params = @{
                encrypted_payload = $payload
                wrapping_key      = $resp.data.wrapping_key
                prf_salt_b64      = $resp.data.prf_salt_b64
            }
        }
    } catch {
        Write-Err "Registration failed: $($_.Exception.Message)"
        return $false
    }
    if ($done.success) {
        Write-Ok 'Credential registered successfully!'
        Write-Ok 'Empty secret store created.'
        Write-Info 'Add secrets with: scrt4 add KEY=value'
        Write-Host ''
        Write-Info 'Next: run  scrt4 unlock  then  scrt4 setup --local'
        Write-Info 'to add a Windows Hello (localhost) passkey for phone-free unlocks.'
        return $true
    }
    Write-Err "Registration failed: $($done.error)"
    return $false
}

# run_setup_local_flow -- add a localhost-rpId credential (Windows Hello)
# that wraps the EXISTING master key. Requires an active session.
function Invoke-Scrt4LocalSetup {
    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'setup_local' } } catch {
        Write-Err "Setup failed: $($_.Exception.Message)"
        return $false
    }
    if (-not $resp.success) {
        Write-Err "Setup failed: $($resp.error)"
        return $false
    }

    $url = $resp.data.url
    Write-Info 'Adding localhost passkey (wraps existing master key)...'
    Start-Process $url | Out-Null
    Write-Host "  URL: $url"
    Write-Host '  Register a passkey in the browser window (Windows Hello).'
    Write-Host ''
    Write-Info '  Waiting for registration...'

    $done = $null
    try { $done = Send-Scrt4Request @{ method = 'setup_local_complete' } } catch {
        Write-Err "Setup failed: $($_.Exception.Message)"
        return $false
    }
    if ($done.success) {
        Write-Ok 'Localhost credential added!'
        Write-Ok "You can now unlock with 'scrt4 unlock' (Windows Hello, no internet needed)."
        return $true
    }
    Write-Err "Setup failed: $($done.error)"
    return $false
}

#  WinForms dialogs (zenity replacement) 

# Copy text to the clipboard and clear it after 30 seconds (parity with
# _clipboard_copy in scrt4-core). The clearer is a detached hidden
# process so it survives the dialog and the CLI exiting.
function Set-Scrt4ClipboardAutoClear {
    param([string]$Text)
    Set-Clipboard -Value $Text
    Start-Process -WindowStyle Hidden powershell -ArgumentList `
        '-NoProfile', '-Command', 'Start-Sleep 30; Set-Clipboard -Value ([string][char]0x200B)' | Out-Null
}

# Modal monospace multi-line editor. Returns the edited text, or $null
# on cancel. Secret values shown here never touch stdout/scrollback.
function Show-Scrt4TextDialog {
    param(
        [string]$Title,
        [string]$Text,
        [string]$OkLabel = 'OK',
        [int]$Width = 700,
        [int]$Height = 500,
        [switch]$ShowCopyAll
    )

    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    Add-Type -AssemblyName System.Drawing | Out-Null

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size($Width, $Height)
    $form.StartPosition = 'CenterScreen'

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Multiline = $true
    $textBox.ScrollBars = 'Both'
    $textBox.WordWrap = $false
    $textBox.AcceptsReturn = $true
    $textBox.Font = New-Object System.Drawing.Font('Consolas', 10)
    $textBox.Dock = 'Fill'
    $textBox.Text = $Text -replace "(?<!`r)`n", "`r`n"

    $panel = New-Object System.Windows.Forms.FlowLayoutPanel
    $panel.FlowDirection = 'RightToLeft'
    $panel.Dock = 'Bottom'
    $panel.Height = 40

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = $OkLabel
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $panel.Controls.Add($okButton)
    $panel.Controls.Add($cancelButton)
    if ($ShowCopyAll) {
        # Parity with the bash view's zenity --extra-button="Copy All":
        # copies the current text, auto-clears the clipboard in 30s.
        $copyButton = New-Object System.Windows.Forms.Button
        $copyButton.Text = 'Copy All'
        $copyButton.Width = 80
        $copyButton.Add_Click({
            Set-Scrt4ClipboardAutoClear -Text $textBox.Text
        }.GetNewClosure())
        $panel.Controls.Add($copyButton)
    }
    $form.Controls.Add($textBox)
    $form.Controls.Add($panel)
    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $form.TopMost = $true

    $result = $form.ShowDialog()
    $edited = $textBox.Text
    $form.Dispose()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return ($edited -replace "`r`n", "`n")
    }
    return $null
}

#  Secret text parsing (ports the embedded Python parsers) 

# Parse a KEY=value block. AllowColon also accepts `KEY: value` when the
# key matches ^[A-Za-z_][A-Za-z0-9_]*$ (the add parser); the view parser
# accepts '=' only. Returns @{ Secrets = <hashtable>; Skipped = <list> }.
function ConvertFrom-Scrt4SecretText {
    param([string]$Text, [switch]$AllowColon)

    $secrets = @{}
    $skipped = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($Text -split "`r?`n")) {
        $stripped = $line.Trim()
        if (-not $stripped -or $stripped.StartsWith('#')) { continue }

        if ($stripped.Contains('=')) {
            $parts = $stripped.Split('=', 2)
            $key = $parts[0].Trim()
            if ($key) {
                $secrets[$key] = $parts[1]
                continue
            }
        }
        if ($AllowColon -and $stripped.Contains(':')) {
            $parts = $stripped.Split(':', 2)
            $key = $parts[0].Trim()
            $value = $parts[1].Trim()
            if ($key -and $key -cmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
                $secrets[$key] = $value
                continue
            }
        }
        $skipped.Add($stripped)
    }
    return @{ Secrets = $secrets; Skipped = $skipped }
}

# Read a password without echo. Returns plain text (needed for PBKDF2).
function Read-Scrt4Password {
    param([string]$Prompt)
    $secure = Read-Host -Prompt $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

#  Core commands 

function Invoke-CmdStatus {
    if ($script:DevMode) {
        Write-Warn2 'DEV MODE -- auth gates disabled. Session reporting is informational only.'
    }
    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'status' } } catch {
        Write-Warn2 'Daemon not reachable. Start with: scrt4 daemon'
        return 1
    }
    # Parity with scrt4-core cmd_status: pretty-print the raw response.
    Write-Host (ConvertTo-Json -InputObject $resp -Depth 10)
    return 0
}

function Invoke-CmdUnlock {
    param([string[]]$Rest)

    if ($script:DevMode -and -not $script:ForceAuth) {
        Write-Warn2 'DEV MODE -- session is already active, no unlock needed.'
        Write-Warn2 'To test the auth path itself, pass --auth to a command.'
        return 0
    }

    $ttl = 72000
    $forceMode = ''
    foreach ($arg in $Rest) {
        switch ($arg) {
            '--remote' { $forceMode = 'remote' }
            '--local'  { $forceMode = 'local' }
            default {
                $parsed = 0
                if ([long]::TryParse($arg, [ref]$parsed)) { $ttl = $parsed }
            }
        }
    }

    switch ($forceMode) {
        'remote' { if (Invoke-Scrt4RelayUnlock -Ttl $ttl) { return 0 } else { return 1 } }
        'local'  { if (Invoke-Scrt4LocalUnlock -Ttl $ttl) { return 0 } else { return 1 } }
        default {
            # Default: localhost (Windows Hello) if a localhost credential
            # exists, otherwise the remote QR flow -- v0.1 monolith behavior.
            $check = $null
            try { $check = Send-Scrt4Request @{ method = 'unlock_local'; params = @{ ttl = $ttl } } } catch {
                Write-Err "Unlock failed: $($_.Exception.Message)"
                return 1
            }
            if ($check.success) {
                $url = $check.data.url
                Write-Info 'Opening browser for authentication...'
                Start-Process $url | Out-Null
                Write-Host "  URL: $url"
                Write-Host '  Authenticate in the browser window (Windows Hello).'
                Write-Host ''
                Write-Info '  Waiting for authentication...'
                $done = $null
                try { $done = Send-Scrt4Request @{ method = 'unlock_local_complete'; params = @{ ttl = $ttl } } } catch {
                    Write-Err "Unlock failed: $($_.Exception.Message)"
                    return 1
                }
                if ($done.success) {
                    $count = 0
                    if ($null -ne $done.data.count) { $count = $done.data.count }
                    Write-Ok "Unlocked $count secret(s)."
                    return 0
                }
                Write-Err "Unlock failed: $($done.error)"
                return 1
            }
            if (Invoke-Scrt4RelayUnlock -Ttl $ttl) { return 0 }
            return 1
        }
    }
}

function Invoke-CmdSetup {
    param([string[]]$Rest)

    if ($script:DevMode -and -not $script:ForceAuth) {
        Write-Warn2 'DEV MODE -- no passkey to register.'
        Write-Warn2 'The dev daemon bootstraps with a fixed key at startup.'
        return 0
    }

    $useLocal = $false
    foreach ($arg in $Rest) {
        if ($arg -eq '--local') { $useLocal = $true }
    }

    if ($useLocal) {
        if (Invoke-Scrt4LocalSetup) { return 0 } else { return 1 }
    }

    # Warn if existing secrets would be wiped: registration generates a
    # new master key and the old vault becomes unrecoverable.
    $existing = 0
    try {
        $listResp = Send-Scrt4Request @{ method = 'list' }
        if ($listResp.success -and $listResp.data.names) {
            $existing = @($listResp.data.names).Count
        }
    } catch { }

    if ($existing -gt 0) {
        Write-Host ''
        Write-Err '=============================================================='
        Write-Err '  WARNING: You have existing secrets in your vault!'
        Write-Err '--------------------------------------------------------------'
        Write-Err '  Setting up WebAuthn generates new encryption keys.'
        Write-Err '  ALL existing secrets will be permanently deleted.'
        Write-Err '--------------------------------------------------------------'
        Write-Err '  Before proceeding, you should:'
        Write-Err "    1. Run 'scrt4 backup-key --save $env:USERPROFILE\Desktop'"
        Write-Err '       (saves encrypted master key backup)'
        Write-Err "    2. Run 'scrt4 view' and copy your secret values"
        Write-Err "    3. After setup, re-add with 'scrt4 add KEY=value'"
        Write-Err '=============================================================='
        Write-Host ''
        $confirm = Read-Host 'Type YES to proceed, or anything else to abort'
        if ($confirm -cne 'YES') {
            Write-Warn2 'Aborted. Your secrets are safe.'
            return 0
        }
        Write-Host ''
    }

    if (Invoke-Scrt4RelaySetup) { return 0 }
    return 1
}

function Invoke-CmdExtend {
    param([string[]]$Rest)

    if (-not (Test-Scrt4Unlocked)) { return 1 }

    # Always include params -- the Rust enum needs the params object even
    # when ttl is null (see the serde note in scrt4-core cmd_extend).
    $ttl = $null
    if ($Rest.Count -gt 0) {
        $parsed = 0
        if ([long]::TryParse($Rest[0], [ref]$parsed)) { $ttl = $parsed }
    }
    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'extend'; params = @{ ttl = $ttl } } } catch {
        Write-Err "extend failed: $($_.Exception.Message)"
        return 1
    }
    if (-not $resp.success) {
        Write-Err "extend failed: $($resp.error)"
        return 1
    }
    $remaining = 0
    if ($null -ne $resp.data.remaining) { $remaining = [long]$resp.data.remaining }
    $hours = [math]::Floor($remaining / 3600)
    $mins = [math]::Floor(($remaining % 3600) / 60)
    Write-Ok "Session extended. ${hours}h ${mins}m remaining."
    return 0
}

function Invoke-CmdLogout {
    if ($script:DevMode) {
        Write-Warn2 'DEV MODE -- nothing to lock.'
        return 0
    }
    # v0.2 core sends {"method":"logout"}, which the daemon protocol does
    # not define; "clear" is the actual wire method (protocol.rs).
    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'clear' } } catch {
        Write-Err "logout failed: $($_.Exception.Message)"
        return 1
    }
    if ($resp.success) {
        Write-Ok 'Session cleared.'
        return 0
    }
    Write-Err "logout failed: $($resp.error)"
    return 1
}

function Invoke-CmdList {
    param([string[]]$Rest)

    if (-not (Test-Scrt4Unlocked)) { return 1 }

    $filterTag = ''
    $showTags = $false
    for ($i = 0; $i -lt $Rest.Count; $i++) {
        switch ($Rest[$i]) {
            '--tag'  { if ($i + 1 -lt $Rest.Count) { $filterTag = $Rest[$i + 1]; $i++ } }
            '--tags' { $showTags = $true }
        }
    }

    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'list' } } catch {
        Write-Err "list failed: $($_.Exception.Message)"
        return 1
    }
    if (-not $resp.success) {
        Write-Err "list failed: $($resp.error)"
        return 1
    }

    $names = @()
    if ($resp.data.names) { $names = @($resp.data.names) }
    if ($names.Count -eq 0) {
        Write-Warn2 'No secrets stored. Add with: scrt4 add KEY=value'
        return 0
    }

    # Fast path: no flags -- historical script-parseable one-name-per-line.
    if (-not $filterTag -and -not $showTags) {
        foreach ($n in $names) { Write-Host $n }
        return 0
    }

    # Tags come from $ConfigDir\tags.json (same file the tags module writes).
    $tags = $null
    $tagsFile = Join-Path $script:ConfigDir 'tags.json'
    if (Test-Path $tagsFile) {
        try { $tags = Get-Content -Raw $tagsFile | ConvertFrom-Json } catch { }
    }

    function Get-TagsFor([string]$name) {
        if ($null -eq $tags) { return @() }
        $prop = $tags.PSObject.Properties[$name]
        if ($prop -and $prop.Value) { return @($prop.Value) }
        return @()
    }

    if ($filterTag) {
        $names = @($names | Where-Object {
            $t = Get-TagsFor $_
            ($t | ForEach-Object { $_.ToLowerInvariant() }) -contains $filterTag.ToLowerInvariant()
        })
        if ($names.Count -eq 0) {
            Write-Warn2 "No secrets with tag '$filterTag'."
            return 0
        }
        Write-Info "$($names.Count) secret(s) tagged '$filterTag':"
    } else {
        Write-Info "$($names.Count) secret(s):"
    }

    foreach ($n in $names) {
        $t = Get-TagsFor $n
        if ($t.Count -gt 0) {
            Write-Host "  $n  [$($t -join ', ')]"
        } else {
            Write-Host "  $n"
        }
    }
    return 0
}

function Invoke-CmdAdd {
    param([string[]]$Rest)

    if (-not (Test-Scrt4Unlocked)) { return 1 }

    $secrets = @{}

    if ($Rest.Count -eq 0) {
        # GUI mode: notepad dialog (zenity --text-info equivalent).
        if (-not (Test-Scrt4Gui)) {
            Write-Err 'Usage: scrt4 add KEY=value [KEY=value ...]'
            Write-Warn2 'GUI mode is unavailable here; pass KEY=value arguments on the command line.'
            return 1
        }

        $placeholder = @"
# Paste your secrets below, one per line
# Format: KEY=value
# Lines starting with # are ignored
# Example:
# API_KEY=sk-abc123
# DB_PASSWORD=mysecretpassword
"@
        $input2 = Show-Scrt4TextDialog -Title 'scrt4 -- Add Secrets' -Text $placeholder -OkLabel 'Add'
        if ($null -eq $input2 -or -not $input2.Trim()) {
            Write-Warn2 'Cancelled.'
            return 0
        }

        $parsed = ConvertFrom-Scrt4SecretText -Text $input2 -AllowColon
        foreach ($s in $parsed.Skipped) { Write-Warn2 "Skipping: $s" }
        $secrets = $parsed.Secrets
        if ($secrets.Count -eq 0) {
            Write-Warn2 'No valid KEY=value lines found.'
            return 0
        }
    } else {
        # CLI mode: KEY=value arguments.
        foreach ($arg in $Rest) {
            if ($arg -notmatch '=') {
                Write-Err "Invalid entry: $arg (expected KEY=value)"
                return 1
            }
            $parts = $arg.Split('=', 2)
            $secrets[$parts[0]] = $parts[1]
        }
    }

    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'add_secrets'; params = @{ secrets = $secrets } } } catch {
        Write-Err $_.Exception.Message
        return 1
    }
    if ($resp.success) {
        $count = 0
        if ($null -ne $resp.data.count) { $count = $resp.data.count }
        Write-Ok "Added $count secret(s)."
        return 0
    }
    Write-Err "$($resp.error)"
    return 1
}

function Invoke-CmdRun {
    param([string[]]$Rest)

    if (-not (Test-Scrt4Unlocked)) { return 1 }
    if ($Rest.Count -eq 0) {
        Write-Err 'Usage: scrt4 run ''cmd $env[KEY]'''
        return 1
    }
    $cmd = $Rest -join ' '

    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'run'; params = @{ command = $cmd } } } catch {
        Write-Err "scrt4 run failed: $($_.Exception.Message)"
        return 1
    }
    if (-not $resp.success) {
        Write-Err "scrt4 run failed: $($resp.error)"
        return 1
    }

    $output = ''
    if ($null -ne $resp.data.output) { $output = [string]$resp.data.output }
    if ($output) { [Console]::Out.Write($output) }
    if ($output -and -not $output.EndsWith("`n")) { [Console]::Out.WriteLine() }

    $exitCode = 0
    if ($null -ne $resp.data.exit_code) { $exitCode = [int]$resp.data.exit_code }
    return $exitCode
}

function Invoke-CmdView {
    param([string[]]$Rest)

    if (-not (Test-Scrt4Unlocked)) { return 1 }

    $cliMode = $false
    if ($Rest -contains '--cli' -or $script:ForceCli) { $cliMode = $true }
    if (-not $cliMode -and -not (Test-Scrt4Gui)) { $cliMode = $true }

    if (-not (Invoke-Scrt4WaGate)) { return 1 }

    $resp1 = $null
    try { $resp1 = Send-Scrt4Request @{ method = 'reveal_all' } } catch {
        Write-Err "view failed: $($_.Exception.Message)"
        return 1
    }
    if (-not $resp1.success) {
        Write-Err "view failed: $($resp1.error)"
        return 1
    }

    $resp2 = $null
    try {
        $resp2 = Send-Scrt4Request @{
            method = 'reveal_all_confirm'
            params = @{ challenge = $resp1.data.challenge; code = $resp1.data.code }
        }
    } catch {
        Write-Err "view confirm failed: $($_.Exception.Message)"
        return 1
    }
    if (-not $resp2.success) {
        Write-Err "view confirm failed: $($resp2.error)"
        return 1
    }

    $props = @($resp2.data.secrets.PSObject.Properties | Sort-Object Name)
    if ($props.Count -eq 0) {
        Write-Warn2 'No secrets stored. Add with: scrt4 add KEY=value'
        return 0
    }

    $lines = foreach ($p in $props) { "$($p.Name)=$($p.Value)" }
    $secretText = $lines -join "`n"

    if ($cliMode) {
        Write-Host ''
        foreach ($l in $lines) { Write-Host $l }
        Write-Host ''
        $secretText = '[CLEARED]'; $lines = '[CLEARED]'; $resp2 = '[CLEARED]'
        return 0
    }

    # GUI mode -- editable dialog; on Save, parse KEY=value lines and
    # round-trip through add_secrets so edits persist.
    $edited = Show-Scrt4TextDialog -Title 'scrt4 -- View All' -Text $secretText `
        -OkLabel 'Save' -Width 800 -Height 600 -ShowCopyAll
    $secretText = '[CLEARED]'; $lines = '[CLEARED]'; $resp2 = '[CLEARED]'

    if ($null -eq $edited) { return 0 }
    if ($edited.Trim()) {
        $parsed = ConvertFrom-Scrt4SecretText -Text $edited
        if ($parsed.Secrets.Count -gt 0) {
            $saveResp = $null
            try {
                $saveResp = Send-Scrt4Request @{ method = 'add_secrets'; params = @{ secrets = $parsed.Secrets } }
            } catch { }
            if ($saveResp -and $saveResp.success) {
                Write-Ok "Saved $($parsed.Secrets.Count) secret(s)."
            } else {
                $serr = 'unknown'
                if ($saveResp) { $serr = $saveResp.error }
                Write-Err "Save failed: $serr"
            }
        }
    }
    $edited = '[CLEARED]'
    return 0
}

# Encrypt TO a public address, not to a transport: the sealed blob is
# safe at rest (Drive, email, USB) and only the named recipient's vault
# opens it. See issues #86 / #87.

function Invoke-CmdBackupVault {
    param([string[]]$Rest)

    $dest = '.'
    for ($i = 0; $i -lt $Rest.Count; $i++) {
        switch ($Rest[$i]) {
            '--local' {
                if ($i + 1 -ge $Rest.Count) {
                    Write-Err 'Usage: scrt4 backup-vault --local <directory>'
                    return 1
                }
                $dest = $Rest[$i + 1]; $i++
            }
            default {
                Write-Err "Unknown option: $($Rest[$i])"
                Write-Host 'Usage: scrt4 backup-vault [--local <directory>]'
                return 1
            }
        }
    }

    if (-not (Test-Path $script:ConfigDir)) {
        Write-Err "Config directory not found: $($script:ConfigDir)"
        return 1
    }
    if (-not (Test-Path $dest)) {
        Write-Err "Destination directory not found: $dest"
        return 1
    }

    $files = @(Get-ChildItem -Path $script:ConfigDir -Recurse -File -Force -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) {
        Write-Err "No files in $($script:ConfigDir)"
        return 1
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd'
    $archive = Join-Path (Resolve-Path $dest) "scrt4-backup-$timestamp.tar.gz"

    Write-Info "Backing up $($script:ConfigDir) ($($files.Count) files)..."
    # tar.exe (bsdtar) ships with Windows 10 1803+; archives cross-restore
    # with the WSL bash CLI's tar output.
    $parent = Split-Path $script:ConfigDir -Parent
    $basename = Split-Path $script:ConfigDir -Leaf
    & tar.exe -czf $archive -C $parent $basename
    if ($LASTEXITCODE -ne 0) {
        Write-Err 'tar failed'
        return 1
    }

    $size = (Get-Item $archive).Length
    Write-Ok "Wrote $archive ($size bytes)"
    Write-Host ''
    Write-Warn2 'Note: the vault file inside the archive is still encrypted.'
    Write-Warn2 'You also need the master key to recover. Run: scrt4 backup-key'
    return 0
}

# Encrypted master-key backup writer/reader. MUST stay byte-compatible
# with the bash implementation (scrt4-core cmd_backup_key / cmd_recover):
# PBKDF2-HMAC-SHA256 100k iters dklen 32; AES-256-CBC PKCS7 with no
# OpenSSL "Salted__" header (bash uses `openssl enc -K -iv -nosalt`);
# plaintext = the master-key string bytes with no trailing newline.
function Invoke-CmdBackupKey {
    param([string[]]$Rest)

    $saveDir = ''
    if ($Rest.Count -gt 0 -and $Rest[0] -eq '--save') {
        $saveDir = '.'
        if ($Rest.Count -gt 1) { $saveDir = $Rest[1] }
        if (-not (Test-Path $saveDir)) {
            Write-Err "Directory not found: $saveDir"
            return 1
        }
    }

    if (-not (Test-Scrt4Unlocked)) { return 1 }
    if (-not (Invoke-Scrt4WaGate)) { return 1 }

    Write-Info 'Retrieving master key from daemon...'
    $resp = $null
    try { $resp = Send-Scrt4Request @{ method = 'backup_key' } } catch {
        Write-Err "Failed to retrieve master key: $($_.Exception.Message)"
        return 1
    }
    if (-not $resp.success) {
        Write-Err "Failed to retrieve master key: $($resp.error)"
        return 1
    }
    $key = [string]$resp.data.key

    if (-not $saveDir) {
        Write-Ok "Master key ($($key.Length) characters):"
        Write-Host ''
        Write-Host $key
        Write-Host ''
        Write-Warn2 'Store this somewhere safe and offline.'
        Write-Warn2 'Never paste it into Claude Code or any AI agent.'
        return 0
    }

    $outFile = Join-Path (Resolve-Path $saveDir) 'encrypted-master-key-instructions.json'
    Write-Host ''
    Write-Info 'Creating encrypted master key backup at:'
    Write-Host "  $outFile"
    Write-Host ''

    if ($env:SCRT4_TEST_PASSWORD) {
        $password = $env:SCRT4_TEST_PASSWORD
        $password2 = $env:SCRT4_TEST_PASSWORD
        Write-Warn2 '(using SCRT4_TEST_PASSWORD from environment)'
    } else {
        $password = Read-Scrt4Password 'Recovery password (min 8 chars)'
        $password2 = Read-Scrt4Password 'Confirm password'
    }

    if ($password -cne $password2) {
        Write-Err 'Passwords do not match. No file written.'
        return 1
    }
    if ($password.Length -lt 8) {
        Write-Err 'Password must be at least 8 characters. No file written.'
        return 1
    }

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $salt = New-Object byte[] 16
    $iv = New-Object byte[] 16
    $rng.GetBytes($salt)
    $rng.GetBytes($iv)

    $pwBytes = [System.Text.Encoding]::UTF8.GetBytes($password)
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $pwBytes, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $derivedKey = $kdf.GetBytes(32)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $derivedKey
    $aes.IV = $iv
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)
    $encryptor = $aes.CreateEncryptor()
    $ciphertext = $encryptor.TransformFinalBlock($keyBytes, 0, $keyBytes.Length)
    $encryptor.Dispose()
    $aes.Dispose()
    $kdf.Dispose()

    $backup = [ordered]@{
        Type               = 'MasterKeyBackup'
        Version            = '2.0'
        CreatedAt          = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.ffffffzzz')
        SecurityMode       = 'webauthn-prf'
        Salt               = [Convert]::ToBase64String($salt)
        IV                 = [Convert]::ToBase64String($iv)
        EncryptedMasterKey = [Convert]::ToBase64String($ciphertext)
        DecryptionInstructions = [ordered]@{
            Algorithm     = 'AES-256-CBC'
            KeyDerivation = 'PBKDF2-SHA256'
            Iterations    = 100000
            KeyLength     = 32
        }
    }

    # BOM-less UTF-8: the bash recover path pre-checks the file with
    # `jq -e`, which rejects a UTF-8 BOM.
    $jsonOut = ConvertTo-Json -InputObject $backup -Depth 5
    [System.IO.File]::WriteAllText($outFile, $jsonOut, (New-Object System.Text.UTF8Encoding($false)))

    Write-Ok "Wrote $outFile"
    Write-Host ''
    Write-Warn2 "Recover with: scrt4 recover $outFile"
    Write-Warn2 'You will need the password you just set.'
    return 0
}

function Invoke-CmdRecover {
    param([string[]]$Rest)

    if ($Rest.Count -eq 0) {
        Write-Err 'Usage: scrt4 recover <encrypted-master-key-instructions.json>'
        return 1
    }
    $backupFile = $Rest[0]
    if (-not (Test-Path $backupFile)) {
        Write-Err "File not found: $backupFile"
        return 1
    }

    $backup = $null
    try { $backup = Get-Content -Raw $backupFile | ConvertFrom-Json } catch { }
    if (-not ($backup -and $backup.EncryptedMasterKey)) {
        Write-Err 'Not a scrt4 master-key backup (missing EncryptedMasterKey field)'
        return 1
    }

    Write-Info '=== scrt4 master key recovery ==='
    $created = 'unknown'
    if ($backup.CreatedAt) { $created = $backup.CreatedAt }
    $version = '1.0'
    if ($backup.Version) { $version = $backup.Version }
    Write-Host "  Backup created: $created"
    Write-Host "  Format version: $version"
    Write-Host ''

    if ($env:SCRT4_TEST_PASSWORD) {
        $password = $env:SCRT4_TEST_PASSWORD
        Write-Warn2 '(using SCRT4_TEST_PASSWORD from environment)'
    } else {
        $password = Read-Scrt4Password 'Recovery password'
    }

    $salt = [Convert]::FromBase64String($backup.Salt)
    $iv = [Convert]::FromBase64String($backup.IV)
    $encrypted = [Convert]::FromBase64String($backup.EncryptedMasterKey)
    $iters = 100000
    if ($backup.DecryptionInstructions -and $backup.DecryptionInstructions.Iterations) {
        $iters = [int]$backup.DecryptionInstructions.Iterations
    }

    $recoveredKey = $null
    try {
        $pwBytes = [System.Text.Encoding]::UTF8.GetBytes($password)
        $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $pwBytes, $salt, $iters, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $derivedKey = $kdf.GetBytes(32)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $derivedKey
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $plainBytes = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
        $decryptor.Dispose()
        $aes.Dispose()
        $kdf.Dispose()
        # Mirrors the bash recover's rstrip(chr(0)) for legacy padding.
        $recoveredKey = [System.Text.Encoding]::UTF8.GetString($plainBytes).TrimEnd([char]0)
    } catch { }

    if (-not $recoveredKey) {
        Write-Err 'Decryption failed. Check your recovery password.'
        return 1
    }

    Write-Host ''
    Write-Ok 'SUCCESS -- your master key:'
    Write-Host ''
    Write-Host "  $recoveredKey"
    Write-Host ''
    Write-Host "  Length: $($recoveredKey.Length) characters"
    Write-Host ''
    Write-Info 'Next steps:'
    Write-Host "  1. Place this key in $env:USERPROFILE\.scrt4\master.key (or let setup do it)"
    Write-Host '  2. Run: scrt4 setup   -- register a new FIDO2 authenticator'
    Write-Host '  3. Run: scrt4 unlock  -- authenticate and start a session'
    Write-Host ''
    Write-Host '  Your vault (secrets.enc) is still encrypted with this key.'
    Write-Host '  Once setup + unlock completes, all your secrets are accessible.'
    return 0
}

# ── Update checks ────────────────────────────────────────────────────
#
# Design constraints, in priority order:
#
#   1. It must never break the CLI. Offline, DNS down, server gone -- every
#      failure path is swallowed and scrt4 carries on.
#   2. It must never pollute stdout. `scrt4 run` output gets piped into files
#      and consumed by scripts, so the notice goes to STDERR. An update banner
#      on stdout would silently corrupt a redirect.
#   3. It must not phone home on every command. The result is cached for 24h,
#      and the check only runs on interactive commands (never `run`/`view`),
#      so scripted use makes no network calls at all.
#   4. It must be refusable: SCRT4_NO_UPDATE_CHECK=1 turns it off entirely.
#
# The request is a plain GET of a static file. No identifiers are sent -- no
# machine id, no vault contents, not even a version string.

function Invoke-CmdDaemon {
    param([string[]]$Rest)

    $exe = Find-Scrt4DaemonExe
    if (-not $exe) {
        Write-Err 'scrt4-daemon.exe not found on PATH or in the usual install locations.'
        Write-Host 'Install it or run the daemon directly from its build output.'
        return 1
    }
    Write-Info 'Starting scrt4-daemon...'
    & $exe @Rest
    return $LASTEXITCODE
}

function Invoke-CmdHelp {
    Write-Host @'
scrt4 -- secure secret manager (v0.2 architecture, native Windows client)

USAGE:
    scrt4 <command> [options]

CORE COMMANDS:
    help                Show this help
    daemon              Start scrt4-daemon in the foreground
    status              Check session status
    setup [--local]     Register a WebAuthn passkey (--local adds a Windows
                        Hello passkey for phone-free unlocks; needs a session)
    unlock [--remote|--local] [ttl]  Authenticate and start a session
    extend [ttl]        Reset session timer (optionally update TTL)
    logout              Lock the session (aliases: lock, clear)
    list [--tags] [--tag T]  List secret names (optionally with tags / filtered)
    add [KEY=value ...] Add secrets (GUI notepad if no args)
    run 'cmd $env[K]'   Run a command with secret injection (cmd.exe syntax)
    view [--cli]        View secrets (GUI default, --cli for terminal)
    backup-vault [--local DIR]   Archive the vault directory (tar.gz)
    backup-key [--save DIR]      Show or save the master key
    recover FILE                 Recover a master key from an encrypted backup
    backup-guide        Show backup & recovery guide

GLOBAL FLAGS:
    --cli               Force terminal mode (skip GUI dialogs)

FIRST-TIME WINDOWS HELLO SETUP:
    scrt4 setup          # register passkey (browser; Windows Hello works here)
    scrt4 unlock         # first unlock via the relay page
    scrt4 setup --local  # add a localhost passkey -> future unlocks are
                         # a pure Windows Hello prompt, no internet needed
'@
    Write-Host ''
    Write-Host "Version: $($script:Version)"
    if ($script:DevMode) {
        Write-Host ''
        Write-Host 'DEV MODE FLAG:'
        Write-Host '    --auth              Force the auth gate ON for this command'
    }
    return 0
}

function Invoke-CmdBackupGuide {
    Write-Host @'

=====================================================================
              SCRT4 -- BACKUP & RECOVERY GUIDE
=====================================================================

Full guide: https://github.com/VestedJosh/scrt4/blob/main/docs/ONBOARDING-HARDENED.md

HOW SCRT4 AUTHENTICATION WORKS:

  scrt4 uses FIDO2/WebAuthn -- your hardware authenticator (Windows
  Hello, YubiKey, phone passkey) IS the key. There are no passwords
  or TOTP codes. The master key is derived from the FIDO2 hmac-secret
  extension every time you authenticate.

PRIMARY RECOVERY (you still have your authenticator):

  Just re-authenticate. Your authenticator derives the same master
  key every time -- no backup files or passwords needed.

    scrt4 unlock            # authenticate -> session active
    scrt4 backup-key        # prints the master key (if you need it)

DISASTER RECOVERY (authenticator lost or broken):

  You need TWO things:

    1. The encrypted vault file
       scrt4 backup-vault                    # writes scrt4-backup-DATE.tar.gz
       scrt4 backup-vault --local D:\USB

    2. The master key (one of these):
       - Paper printout from `scrt4 backup-key`
       - Password-encrypted file from `scrt4 backup-key --save DIR`

  WITHOUT BOTH, RECOVERY IS IMPOSSIBLE BY DESIGN.

  To recover:
    scrt4 recover <encrypted-master-key-instructions.json>
    # You'll need the recovery password you set during --save

BACKUP BEST PRACTICES:

  - Run `scrt4 backup-vault` regularly (automated or weekly)
  - Run `scrt4 backup-key --save D:\USB` at least once
  - Store the USB/paper key offline (safe, lockbox)
  - Never paste the master key into a chat, email, or repo
  - After recovery, re-register a new authenticator with `scrt4 setup`

'@
    return 0
}

function Show-Scrt4DevBanner {
    if (-not $script:DevMode) { return }
    Write-Host ''
    Write-Host '========================================================' -ForegroundColor Yellow
    Write-Host '  scrt4-dev -- DEV MODE -- ZERO AUTH' -ForegroundColor Yellow
    Write-Host '  Do NOT store real secrets in this distribution.' -ForegroundColor Yellow
    Write-Host '  See: https://github.com/VestedJosh/scrt4/issues/59' -ForegroundColor Yellow
    Write-Host '========================================================' -ForegroundColor Yellow
    Write-Host ''
}

#  Optional client modules
#
$script:ModuleCommands = @{}
$script:PostUnlockHooks = @()
$script:ClientModulesDir = Join-Path $PSScriptRoot 'modules'
if (Test-Path $script:ClientModulesDir) {
    Get-ChildItem -Path $script:ClientModulesDir -Filter '*.ps1' -ErrorAction SilentlyContinue |
        Sort-Object Name | ForEach-Object { . $_.FullName }
}

#  Dispatch

function Invoke-Scrt4 {
    [CmdletBinding()]
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    $script:ForceCli = $false
    $script:ForceAuth = $false

    Show-Scrt4DevBanner

    if (-not $Arguments -or $Arguments.Count -eq 0) {
        return (Invoke-CmdHelp)
    }

    $rawCmd = $Arguments[0]
    $rest = New-Object System.Collections.Generic.List[string]
    for ($i = 1; $i -lt $Arguments.Count; $i++) {
        switch ($Arguments[$i]) {
            '--cli'  { $script:ForceCli = $true }
            '--auth' { $script:ForceAuth = $true }
            default  { $rest.Add($Arguments[$i]) }
        }
    }
    $restArr = $rest.ToArray()

    # Commands where an update nudge is welcome. Deliberately excludes `run`
    # and `view`: those are used by scripts and agents, where the check would
    # add latency to every call and the notice would be noise. `upgrade`
    # excludes itself because it reports the version anyway.
    $nudgeable = @('help', '--help', '-h', 'status', 'list', 'unlock', 'setup', '--version', '-v')

    try {
        switch ($rawCmd) {
            'help'         { return (Invoke-CmdHelp) }
            '--help'       { return (Invoke-CmdHelp) }
            '-h'           { return (Invoke-CmdHelp) }
            '--version'    { Write-Host "scrt4 v$($script:Version)"; return 0 }
            '-v'           { Write-Host "scrt4 v$($script:Version)"; return 0 }
            'daemon'       { return (Invoke-CmdDaemon -Rest $restArr) }
            'status'       { return (Invoke-CmdStatus) }
            'setup'        { return (Invoke-CmdSetup -Rest $restArr) }
            'unlock'       {
                $rc = Invoke-CmdUnlock -Rest $restArr
                if ($rc -eq 0) {
                    foreach ($hook in $script:PostUnlockHooks) {
                        try { & $hook } catch { }
                    }
                }
                return $rc
            }
            'extend'       { return (Invoke-CmdExtend -Rest $restArr) }
            'logout'       { return (Invoke-CmdLogout) }
            'lock'         { return (Invoke-CmdLogout) }
            'clear'        { return (Invoke-CmdLogout) }
            'list'         { return (Invoke-CmdList -Rest $restArr) }
            'add'          { return (Invoke-CmdAdd -Rest $restArr) }
            'run'          { return (Invoke-CmdRun -Rest $restArr) }
            'view'         { return (Invoke-CmdView -Rest $restArr) }
            'backup-vault' { return (Invoke-CmdBackupVault -Rest $restArr) }
            'backup-key'   { return (Invoke-CmdBackupKey -Rest $restArr) }
            'recover'      { return (Invoke-CmdRecover -Rest $restArr) }
            'backup-guide' { return (Invoke-CmdBackupGuide) }
            default {
                if ($script:ModuleCommands.ContainsKey($rawCmd)) {
                    return (& $script:ModuleCommands[$rawCmd] $restArr)
                }
                Write-Err "Unknown command: $rawCmd"
                Write-Host 'Run: scrt4 help'
                return 1
            }
        }
    } finally {
        # `finally` still runs on the `return`s above, so the nudge lands after
        # the command's own output without disturbing its exit code.
        if ($nudgeable -contains $rawCmd) {
        }
    }
}

# Send-Scrt4Request is exported so the manual Hello test can pre-flight the
# vault (checking for existing secrets) before running a destructive setup.
Export-ModuleMember -Function Invoke-Scrt4, Send-Scrt4Request
