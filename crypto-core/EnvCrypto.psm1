# EnvCrypto.psm1
# Windows Hello-Protected Environment Variable Encryption System
# Features: AES-256 encryption, Real Windows Hello biometric auth, KeePass master key storage, time-based sessions

using namespace System.Security.Cryptography
using namespace System.Text

#region Dependency Management

function Install-RequiredModules {
    <#
    .SYNOPSIS
    Checks for and installs required PowerShell modules.
    #>

    # Check if PoShKeePass is available
    $module = Get-Module -ListAvailable -Name PoShKeePass

    if (-not $module) {
        Write-Host "[INFO] PoShKeePass module not found. Installing..." -ForegroundColor Yellow

        # Try to install from PSGallery
        try {
            # Check if running as admin for AllUsers scope, otherwise use CurrentUser
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

            if ($isAdmin) {
                Install-Module -Name PoShKeePass -Force -Scope AllUsers -AllowClobber
            } else {
                Install-Module -Name PoShKeePass -Force -Scope CurrentUser -AllowClobber
            }

            Write-Host "[OK] PoShKeePass module installed successfully" -ForegroundColor Green
            return $true
        } catch {
            Write-Error "Failed to install PoShKeePass module: $_"
            Write-Host ""
            Write-Host "Please install manually:" -ForegroundColor Yellow
            Write-Host "  Install-Module -Name PoShKeePass -Scope CurrentUser" -ForegroundColor Cyan
            return $false
        }
    }

    return $true
}

# Ensure required modules are installed
$moduleInstalled = Install-RequiredModules
if (-not $moduleInstalled) {
    throw "Required module PoShKeePass is not installed. Run: Install-Module -Name PoShKeePass -Scope CurrentUser"
}

#endregion

# Load PoShKeePass module (now guaranteed to be available)
Import-Module PoShKeePass -ErrorAction Stop

# Module configuration
$script:SessionDuration = 2 * 60 * 60 # 2 hours in seconds
$script:RefreshThreshold = 60 * 60    # 1 hour in seconds
$script:CredentialTarget = "EnvCrypto_SessionKey"
$script:KeePassDbPath = Join-Path $PSScriptRoot "EnvCrypto.kdbx"
$script:KeePassEntryTitle = "EnvCrypto_MasterKey"

# Simple Secret settings
$script:SettingsPath = Join-Path $PSScriptRoot "settings.json"
$script:DpapiMasterKeyTarget = "EnvCrypto_DpapiMasterKey"
$script:DefaultSettings = @{
    securityMode = "simple"
    masterKeyStorage = "dpapi"
    sessionDuration = 7200
    showSuccessDialog = $true
    advancedSecurity = @{
        enabled = $false
        keepassPath = "EnvCrypto.kdbx"
    }
    backup = @{
        enabled = $true
        frequency = "monthly"  # daily, weekly, monthly, never
        destination = "google-drive"
        lastBackup = $null
        recoveryPasswordSet = $false
    }
}

#region Helper Functions

function Get-RandomBytes {
    param([int]$Length = 32)
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    return $bytes
}

function ConvertTo-Base64 {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes)
}

function ConvertFrom-Base64 {
    param([string]$Base64String)
    return [Convert]::FromBase64String($Base64String)
}

function Get-SHA256Hash {
    param([string]$Text)
    $sha256 = [SHA256]::Create()
    $bytes = [Encoding]::UTF8.GetBytes($Text)
    $hash = $sha256.ComputeHash($bytes)
    return $hash
}

function Show-PasswordDialog {
    param([string]$Title = "Password Required", [string]$Message = "Enter password:")

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size(400, 180)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10, 20)
    $label.Size = New-Object System.Drawing.Size(360, 20)
    $label.Text = $Message
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10, 50)
    $textBox.Size = New-Object System.Drawing.Size(360, 20)
    $textBox.UseSystemPasswordChar = $true
    $textBox.TabIndex = 0  # First in tab order
    $form.Controls.Add($textBox)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(210, 90)
    $okButton.Size = New-Object System.Drawing.Size(75, 23)
    $okButton.Text = "OK"
    $okButton.TabIndex = 1
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(295, 90)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 23)
    $cancelButton.Text = "Cancel"
    $cancelButton.TabIndex = 2
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($cancelButton)

    # Set active control and focus on textbox when form loads
    $form.Add_Shown({
        $form.Activate()
        $textBox.Select()
        $textBox.Focus()
    })

    $form.ActiveControl = $textBox
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $secureString = ConvertTo-SecureString -String $textBox.Text -AsPlainText -Force
        $textBox.Text = ""
        return $secureString
    }

    return $null
}

#endregion

#region Settings Management

function Get-Settings {
    <#
    .SYNOPSIS
    Reads the settings from settings.json or returns defaults.

    .OUTPUTS
    Returns a hashtable of settings
    #>

    if (-not (Test-Path $script:SettingsPath)) {
        return $script:DefaultSettings.Clone()
    }

    try {
        $settings = Get-Content $script:SettingsPath -Raw | ConvertFrom-Json

        # Convert PSCustomObject to hashtable for easier manipulation
        $settingsHash = @{
            securityMode = $settings.securityMode
            masterKeyStorage = $settings.masterKeyStorage
            sessionDuration = $settings.sessionDuration
            showSuccessDialog = $settings.showSuccessDialog
            advancedSecurity = @{
                enabled = $settings.advancedSecurity.enabled
                keepassPath = $settings.advancedSecurity.keepassPath
            }
            backup = @{
                enabled = if ($null -ne $settings.backup.enabled) { $settings.backup.enabled } else { $true }
                frequency = if ($settings.backup.frequency) { $settings.backup.frequency } else { "monthly" }
                destination = if ($settings.backup.destination) { $settings.backup.destination } else { "google-drive" }
                lastBackup = $settings.backup.lastBackup
                recoveryPasswordSet = if ($null -ne $settings.backup.recoveryPasswordSet) { $settings.backup.recoveryPasswordSet } else { $false }
            }
        }

        return $settingsHash
    } catch {
        Write-Warning "Failed to read settings, using defaults: $_"
        return $script:DefaultSettings.Clone()
    }
}

function Set-Settings {
    <#
    .SYNOPSIS
    Saves settings to settings.json

    .PARAMETER Settings
    Hashtable of settings to save

    .OUTPUTS
    Returns $true if successful
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Settings
    )

    try {
        $Settings | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:SettingsPath -Encoding UTF8
        return $true
    } catch {
        Write-Error "Failed to save settings: $_"
        return $false
    }
}

#endregion

#region DPAPI Master Key Storage

function Save-DpapiMasterKey {
    <#
    .SYNOPSIS
    Stores the master key encrypted with DPAPI (Windows user credentials).

    .PARAMETER MasterKey
    The master key to store (base64 string)

    .DESCRIPTION
    Uses DPAPI to encrypt the master key. The key can only be decrypted
    by the same Windows user on the same machine.

    .OUTPUTS
    Returns $true if successful
    #>
    param(
        [Parameter(Mandatory)]
        [string]$MasterKey
    )

    try {
        # Convert to secure string and encrypt with DPAPI
        $secureKey = ConvertTo-SecureString -String $MasterKey -AsPlainText -Force
        $encryptedKey = ConvertFrom-SecureString -SecureString $secureKey

        # Store in credentials folder
        $credPath = Join-Path $PSScriptRoot "credentials"
        if (-not (Test-Path $credPath)) {
            New-Item -ItemType Directory -Path $credPath -Force | Out-Null
        }

        $keyFile = Join-Path $credPath "$($script:DpapiMasterKeyTarget).dat"

        $keyData = @{
            Target = $script:DpapiMasterKeyTarget
            EncryptedKey = $encryptedKey
            CreatedAt = (Get-Date).ToString("o")
            Storage = "DPAPI"
        }

        $keyData | ConvertTo-Json -Depth 10 | Out-File -FilePath $keyFile -Encoding UTF8

        Write-Host "[OK] Master key stored with DPAPI encryption" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Failed to store master key with DPAPI: $_"
        return $false
    }
}

function New-SimpleVault {
    <#
    .SYNOPSIS
    Creates a new Simple mode vault with DPAPI-protected master key.

    .DESCRIPTION
    Generates a new 256-bit master key, stores it with DPAPI encryption,
    and saves default Simple mode settings. Returns the master key for backup.

    .OUTPUTS
    Returns the master key (base64 string) for backup, or $null if failed
    #>

    try {
        # Generate 256-bit master key
        $keyBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($keyBytes)
        $masterKey = [Convert]::ToBase64String($keyBytes)

        # Store with DPAPI
        $result = Save-DpapiMasterKey -MasterKey $masterKey
        if (-not $result) {
            Write-Error "Failed to store master key with DPAPI"
            return $null
        }

        # Save default Simple mode settings
        $settings = @{
            securityMode = "simple"
            masterKeyStorage = "dpapi"
            sessionDuration = 7200
            showSuccessDialog = $true
            advancedSecurity = @{
                enabled = $false
                keepassPath = "EnvCrypto.kdbx"
            }
            backup = @{
                enabled = $true
                frequency = "monthly"
                destination = "google-drive"
                lastBackup = $null
                recoveryPasswordSet = $false
            }
        }
        $settings | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:SettingsPath -Encoding UTF8

        Write-Host "[OK] Simple vault created successfully" -ForegroundColor Green
        return $masterKey
    } catch {
        Write-Error "Failed to create simple vault: $_"
        return $null
    }
}

function Get-DpapiMasterKey {
    <#
    .SYNOPSIS
    Retrieves the DPAPI-encrypted master key.

    .DESCRIPTION
    Decrypts the master key using DPAPI. Only works for the same
    Windows user on the same machine that encrypted it.

    .OUTPUTS
    Returns the master key string or $null if not found/failed
    #>

    $credPath = Join-Path $PSScriptRoot "credentials"
    $keyFile = Join-Path $credPath "$($script:DpapiMasterKeyTarget).dat"

    if (-not (Test-Path $keyFile)) {
        return $null
    }

    try {
        $keyData = Get-Content $keyFile -Raw | ConvertFrom-Json

        # Decrypt with DPAPI
        $secureKey = ConvertTo-SecureString -String $keyData.EncryptedKey
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
        $masterKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        return $masterKey
    } catch {
        Write-Error "Failed to retrieve DPAPI master key: $_"
        return $null
    }
}

function Remove-DpapiMasterKey {
    <#
    .SYNOPSIS
    Removes the DPAPI-stored master key.
    #>

    $credPath = Join-Path $PSScriptRoot "credentials"
    $keyFile = Join-Path $credPath "$($script:DpapiMasterKeyTarget).dat"

    if (Test-Path $keyFile) {
        Remove-Item $keyFile -Force
        Write-Host "[OK] DPAPI master key removed" -ForegroundColor Yellow
    }
}

function Test-DpapiMasterKey {
    <#
    .SYNOPSIS
    Checks if a DPAPI-stored master key exists.

    .OUTPUTS
    Returns $true if DPAPI master key exists
    #>

    $credPath = Join-Path $PSScriptRoot "credentials"
    $keyFile = Join-Path $credPath "$($script:DpapiMasterKeyTarget).dat"

    return (Test-Path $keyFile)
}

#endregion

#region Windows Hello Authentication

function Invoke-WindowsHelloAuth {
    <#
    .SYNOPSIS
    Invokes Windows Hello authentication.

    .DESCRIPTION
    Calls the WindowsHelloAuth.exe to perform biometric/PIN authentication.

    .OUTPUTS
    Returns $true if authentication successful, $false otherwise
    #>

    $authExePath = Join-Path $PSScriptRoot "WindowsHelloAuth.exe"

    if (-not (Test-Path $authExePath)) {
        Write-Error "WindowsHelloAuth.exe not found at: $authExePath"
        return $false
    }

    Write-Host "[AUTH] Windows Hello Authentication Required" -ForegroundColor Cyan
    Write-Host "Please authenticate using your biometric or PIN..." -ForegroundColor Yellow

    $process = Start-Process -FilePath $authExePath -NoNewWindow -Wait -PassThru
    $exitCode = $process.ExitCode

    # Check result based on exit code
    # 0 = Success, 1 = Failed/Cancelled, 2 = Not Available, 3 = Exception
    if ($exitCode -ne 0) {
        switch ($exitCode) {
            1 { Write-Error "Windows Hello authentication failed or was cancelled" }
            2 { Write-Error "Windows Hello is not available on this device" }
            3 { Write-Error "An error occurred during Windows Hello authentication" }
            default { Write-Error "Unknown error during Windows Hello authentication (Exit code: $exitCode)" }
        }
        return $false
    }

    Write-Host "[OK] Windows Hello authentication successful" -ForegroundColor Green
    return $true
}

#endregion

#region KeePass Helper Functions

function Test-KeePassDatabase {
    <#
    .SYNOPSIS
    Checks if the KeePass database exists.
    #>
    return (Test-Path $script:KeePassDbPath)
}

function New-KeePassDatabaseWithMasterKey {
    <#
    .SYNOPSIS
    Creates a new KeePass database and stores the master encryption key.

    .PARAMETER DatabasePassword
    The password to encrypt the KeePass database (SecureString)

    .PARAMETER ExportKey
    If specified, returns the master key for backup

    .PARAMETER ExistingMasterKey
    If specified, stores this master key instead of generating a new one.
    Used when migrating from DPAPI to KeePass storage.

    .OUTPUTS
    Returns the master key if -ExportKey is specified
    #>
    param(
        [Parameter(Mandatory)]
        [SecureString]$DatabasePassword,

        [switch]$ExportKey,

        [string]$ExistingMasterKey = ""
    )

    if (Test-KeePassDatabase) {
        Write-Error "KeePass database already exists at: $script:KeePassDbPath"
        return $false
    }

    # Use existing master key or generate a new one
    if ($ExistingMasterKey -ne "") {
        $masterKey = $ExistingMasterKey
        Write-Host "[INFO] Using existing master key for KeePass database" -ForegroundColor Cyan
    } else {
        # Generate master encryption key
        $masterKeyBytes = Get-RandomBytes -Length 32
        $masterKey = ConvertTo-Base64 -Bytes $masterKeyBytes
    }

    # Create KeePass database using KeePassLib directly
    try {
        # Load KeePassLib (comes with PoShKeePass)
        $keePassLibPath = (Get-Module PoShKeePass).ModuleBase
        Add-Type -Path "$keePassLibPath\bin\KeePassLib_2.39.1.dll"

        # Create composite key (password only)
        $compositeKey = New-Object KeePassLib.Keys.CompositeKey

        # Convert SecureString to plain text for KeePassLib
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($DatabasePassword)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        $kcpPassword = New-Object KeePassLib.Keys.KcpPassword($plainPassword)
        $compositeKey.AddUserKey($kcpPassword)

        # Create new database
        $ioConnection = New-Object KeePassLib.Serialization.IOConnectionInfo
        $ioConnection.Path = $script:KeePassDbPath

        $pwDatabase = New-Object KeePassLib.PwDatabase
        $pwDatabase.New($ioConnection, $compositeKey)

        # Create entry for master key in root group
        $rootGroup = $pwDatabase.RootGroup
        $entry = New-Object KeePassLib.PwEntry($true, $true)
        $entry.Strings.Set("Title", (New-Object KeePassLib.Security.ProtectedString($false, $script:KeePassEntryTitle)))
        $entry.Strings.Set("UserName", (New-Object KeePassLib.Security.ProtectedString($false, "EnvCrypto")))
        $entry.Strings.Set("Password", (New-Object KeePassLib.Security.ProtectedString($true, $masterKey)))
        $entry.Strings.Set("Notes", (New-Object KeePassLib.Security.ProtectedString($false, "Master encryption key for .env files. Created: $((Get-Date).ToString('o'))")))

        $rootGroup.AddEntry($entry, $true)

        # Save database
        $pwDatabase.Save($null)
        $pwDatabase.Close()

        Write-Host "[OK] KeePass database created: $script:KeePassDbPath" -ForegroundColor Green
        Write-Host "Database is protected with YOUR password (not stored anywhere)" -ForegroundColor Gray

        if ($ExportKey) {
            Write-Host ""
            Write-Host "BACKUP YOUR MASTER KEY (store in password manager):" -ForegroundColor Yellow
            return $masterKey
        } else {
            Write-Host ""
            Write-Host "Master key stored securely in KeePass database." -ForegroundColor Cyan
            return $true
        }

    } catch {
        Write-Error "Failed to create KeePass database: $_"
        if (Test-Path $script:KeePassDbPath) {
            Remove-Item $script:KeePassDbPath -Force
        }
        return $false
    }
}

function Get-MasterKeyFromKeePass {
    <#
    .SYNOPSIS
    Retrieves the master key from KeePass database.

    .PARAMETER DatabasePassword
    The KeePass database password (SecureString)

    .OUTPUTS
    Returns the master key string or $null if failed
    #>
    param(
        [Parameter(Mandatory)]
        [SecureString]$DatabasePassword
    )

    if (-not (Test-KeePassDatabase)) {
        Write-Error "KeePass database not found. Create one first with New-MasterKey."
        return $null
    }

    try {
        # Load KeePassLib
        $keePassLibPath = (Get-Module PoShKeePass).ModuleBase
        Add-Type -Path "$keePassLibPath\bin\KeePassLib_2.39.1.dll"

        # Create composite key
        $compositeKey = New-Object KeePassLib.Keys.CompositeKey

        # Convert SecureString to plain text
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($DatabasePassword)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        $kcpPassword = New-Object KeePassLib.Keys.KcpPassword($plainPassword)
        $compositeKey.AddUserKey($kcpPassword)

        # Open database
        $ioConnection = New-Object KeePassLib.Serialization.IOConnectionInfo
        $ioConnection.Path = $script:KeePassDbPath

        $pwDatabase = New-Object KeePassLib.PwDatabase
        $pwDatabase.Open($ioConnection, $compositeKey, $null)

        # Find master key entry
        $rootGroup = $pwDatabase.RootGroup
        $entry = $null

        foreach ($e in $rootGroup.GetEntries($true)) {
            $title = $e.Strings.ReadSafe("Title")
            if ($title -eq $script:KeePassEntryTitle) {
                $entry = $e
                break
            }
        }

        if (-not $entry) {
            $pwDatabase.Close()
            Write-Error "Master key entry not found in KeePass database."
            return $null
        }

        # Extract master key
        $masterKey = $entry.Strings.ReadSafe("Password")

        $pwDatabase.Close()

        return $masterKey

    } catch {
        Write-Error "Failed to retrieve master key from KeePass: $_"
        return $null
    }
}

#endregion

#region Windows Credential Manager Integration

function Save-SecureCredential {
    param(
        [string]$Target,
        [string]$Value,
        [hashtable]$Metadata = @{}
    )

    # Create credential object
    $cred = New-Object -TypeName PSCredential -ArgumentList $Target, (ConvertTo-SecureString -String $Value -AsPlainText -Force)

    # Store in Windows Credential Manager (requires CredentialManager module or native API)
    # For now, we'll use a simple file-based approach for testing
    # In production, this would use Windows Credential Manager API

    $credPath = Join-Path $PSScriptRoot "credentials"
    if (-not (Test-Path $credPath)) {
        New-Item -ItemType Directory -Path $credPath -Force | Out-Null
    }

    $credFile = Join-Path $credPath "$Target.json"

    $credData = @{
        Target = $Target
        Value = $Value
        Metadata = $Metadata
        CreatedAt = (Get-Date).ToString("o")
    }

    $credData | ConvertTo-Json -Depth 10 | Out-File -FilePath $credFile -Encoding UTF8
}

function Get-SecureCredential {
    param([string]$Target)

    $credPath = Join-Path $PSScriptRoot "credentials"
    $credFile = Join-Path $credPath "$Target.json"

    if (-not (Test-Path $credFile)) {
        return $null
    }

    $credData = Get-Content $credFile -Raw | ConvertFrom-Json
    return $credData
}

function Remove-SecureCredential {
    param([string]$Target)

    $credPath = Join-Path $PSScriptRoot "credentials"
    $credFile = Join-Path $credPath "$Target.json"

    if (Test-Path $credFile) {
        Remove-Item $credFile -Force
    }
}

#endregion

#region Master Key Management

function New-MasterKey {
    <#
    .SYNOPSIS
    Creates a new KeePass database with master encryption key.

    .DESCRIPTION
    Creates a KeePass database protected by YOUR password (stored only in your head).
    Generates a 256-bit master encryption key and stores it in the database.

    This provides exfiltration protection: stolen .kdbx file is useless without your password.

    .PARAMETER ExportKey
    If specified, also returns the master key for backup purposes.
    STORE THIS IN A SECURE LOCATION (password manager, safe, etc.)

    .OUTPUTS
    Returns success status, or the master key if -ExportKey is specified
    #>
    param(
        [switch]$ExportKey
    )

    if (Test-KeePassDatabase) {
        Write-Warning "KeePass database already exists. Delete EnvCrypto.kdbx to regenerate."
        return $false
    }

    Write-Host "=== Create KeePass Database ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Choose a STRONG password for your KeePass database." -ForegroundColor Yellow
    Write-Host "This password will:" -ForegroundColor Gray
    Write-Host "  - Protect your master encryption key" -ForegroundColor Gray
    Write-Host "  - NOT be stored anywhere (must remember it!)" -ForegroundColor Gray
    Write-Host "  - Be required to decrypt .env files" -ForegroundColor Gray
    Write-Host ""

    $password1 = Show-PasswordDialog -Title "EnvCrypto Setup" -Message "Enter KeePass password:"
    if (-not $password1) {
        Write-Host "[ERROR] Password entry cancelled" -ForegroundColor Red
        return $null
    }

    $password2 = Show-PasswordDialog -Title "EnvCrypto Setup" -Message "Confirm KeePass password:"
    if (-not $password2) {
        Write-Host "[ERROR] Password confirmation cancelled" -ForegroundColor Red
        return $null
    }

    # Compare passwords
    $bstr1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password1)
    $bstr2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password2)
    $plain1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr1)
    $plain2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr2)
    $match = ($plain1 -eq $plain2)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)

    if (-not $match) {
        Write-Error "Passwords do not match. Please try again."
        return $false
    }

    Write-Host ""
    Write-Host "Creating KeePass database..." -ForegroundColor Cyan

    return New-KeePassDatabaseWithMasterKey -DatabasePassword $password1 -ExportKey:$ExportKey
}

function Get-MasterKey {
    <#
    .SYNOPSIS
    Retrieves the master key based on current security mode.

    .DESCRIPTION
    Simple mode: Retrieves DPAPI-encrypted master key (requires Windows Hello session)
    Advanced mode: Retrieves from KeePass using cached password (requires Windows Hello session)

    .OUTPUTS
    Returns the master key string if authorized, $null otherwise
    #>

    # Check for valid session
    $sessionData = Get-SessionKey
    if (-not $sessionData) {
        Write-Error "No valid Windows Hello session. Please authenticate first with New-SessionKey."
        return $null
    }

    # Get settings to determine security mode
    $settings = Get-Settings

    if ($settings.securityMode -eq "simple") {
        # Simple mode: Get DPAPI-encrypted master key
        $masterKey = Get-DpapiMasterKey
        if (-not $masterKey) {
            Write-Error "DPAPI master key not found. Run Initialize-SimpleSecret.ps1 to set up."
            return $null
        }
        return $masterKey
    } else {
        # Advanced mode: Get from KeePass using cached password
        $keepassPasswordSecure = ConvertTo-SecureString -String $sessionData
        return Get-MasterKeyFromKeePass -DatabasePassword $keepassPasswordSecure
    }
}

#endregion

#region Session Key Management

function New-SessionKey {
    <#
    .SYNOPSIS
    Authenticates with Windows Hello and creates a session.

    .DESCRIPTION
    Simple mode (default):
    1. Prompts for Windows Hello biometric or PIN authentication
    2. Creates a session marker for 2 hours

    Advanced mode:
    1. Prompts for Windows Hello biometric or PIN authentication
    2. Asks for your KeePass database password
    3. Verifies the password by accessing the master key
    4. Caches the KeePass password (encrypted) for 2 hours

    .OUTPUTS
    Returns $true if authentication successful
    #>

    # Get settings to determine security mode
    $settings = Get-Settings

    if ($settings.securityMode -eq "simple") {
        # Simple mode: Windows Hello only
        return New-SessionKeySimple
    } else {
        # Advanced mode: Windows Hello + KeePass
        return New-SessionKeyAdvanced
    }
}

function New-SessionKeySimple {
    <#
    .SYNOPSIS
    Creates a session using Simple mode (Windows Hello only).
    #>

    # Check if DPAPI master key exists
    if (-not (Test-DpapiMasterKey)) {
        Write-Error "DPAPI master key not found. Run Initialize-SimpleSecret.ps1 to set up."
        return $false
    }

    # Windows Hello authentication
    if (-not (Invoke-WindowsHelloAuth)) {
        return $false
    }

    Write-Host ""

    # Verify DPAPI master key is accessible
    $masterKey = Get-DpapiMasterKey
    if (-not $masterKey) {
        Write-Error "Failed to access DPAPI master key."
        return $false
    }

    # Create session marker (simple mode doesn't cache a password, just marks session as active)
    $sessionMarker = "SIMPLE_MODE_SESSION_" + [guid]::NewGuid().ToString()
    $metadata = @{
        CreatedAt = (Get-Date).ToString("o")
        ExpiresAt = (Get-Date).AddSeconds($script:SessionDuration).ToString("o")
        Type = "SimpleSession"
        Mode = "simple"
    }

    Save-SecureCredential -Target $script:CredentialTarget -Value $sessionMarker -Metadata $metadata

    $settings = Get-Settings
    if ($settings.showSuccessDialog) {
        Write-Host "[OK] Session created (Simple mode). Valid for 2 hours." -ForegroundColor Green
    }

    return $true
}

function New-SessionKeyAdvanced {
    <#
    .SYNOPSIS
    Creates a session using Advanced mode (Windows Hello + KeePass).
    #>

    # Check if KeePass database exists
    if (-not (Test-KeePassDatabase)) {
        Write-Error "KeePass database not found. Create one first with New-MasterKey or switch to Simple mode."
        return $false
    }

    # Windows Hello authentication
    if (-not (Invoke-WindowsHelloAuth)) {
        return $false
    }

    Write-Host ""

    # Prompt for KeePass password with GUI dialog
    Write-Host "Prompting for KeePass password..." -ForegroundColor Cyan
    $keepassPassword = Show-PasswordDialog -Title "EnvCrypto Authentication" -Message "Enter your KeePass database password:"

    if (-not $keepassPassword) {
        Write-Host "[ERROR] Password entry cancelled" -ForegroundColor Red
        return $null
    }

    # Verify password by trying to get master key
    Write-Host "Verifying KeePass password..." -ForegroundColor Gray
    $masterKey = Get-MasterKeyFromKeePass -DatabasePassword $keepassPassword

    if (-not $masterKey) {
        Write-Error "Invalid KeePass password or failed to access database."
        return $false
    }

    Write-Host "[OK] KeePass database unlocked" -ForegroundColor Green

    # Cache the KeePass password (DPAPI-encrypted) for the session
    $encryptedPassword = ConvertFrom-SecureString -SecureString $keepassPassword

    # Store encrypted password with expiry metadata
    $metadata = @{
        CreatedAt = (Get-Date).ToString("o")
        ExpiresAt = (Get-Date).AddSeconds($script:SessionDuration).ToString("o")
        Type = "KeePassSession"
        Mode = "advanced"
    }

    Save-SecureCredential -Target $script:CredentialTarget -Value $encryptedPassword -Metadata $metadata

    Write-Host "[OK] Session created (Advanced mode). KeePass password cached for 2 hours." -ForegroundColor Green
    return $true
}

function Get-SessionKey {
    <#
    .SYNOPSIS
    Retrieves the current session key if valid.

    .OUTPUTS
    Returns session key string if valid, $null if expired or not found
    #>

    $cred = Get-SecureCredential -Target $script:CredentialTarget

    if (-not $cred) {
        return $null
    }

    # Check if expired
    $expiresAt = [DateTime]::Parse($cred.Metadata.ExpiresAt)
    $now = Get-Date

    if ($now -gt $expiresAt) {
        Write-Warning "Session key expired. Please re-authenticate."
        Remove-SecureCredential -Target $script:CredentialTarget
        return $null
    }

    # Check if needs refresh soon
    $timeRemaining = ($expiresAt - $now).TotalSeconds
    if ($timeRemaining -lt $script:RefreshThreshold) {
        $minutesRemaining = [Math]::Round($timeRemaining / 60)
        Write-Warning "Session key expires in $minutesRemaining minutes. Consider refreshing."
    }

    return $cred.Value
}

function Update-SessionKey {
    <#
    .SYNOPSIS
    Refreshes the session key with Windows Hello authentication.

    .OUTPUTS
    Returns $true if session key refreshed successfully
    #>

    Write-Host "[REFRESH] Refreshing session key..." -ForegroundColor Cyan
    return New-SessionKey
}

function Remove-SessionKey {
    <#
    .SYNOPSIS
    Removes the current session key (logout).
    #>

    Remove-SecureCredential -Target $script:CredentialTarget
    Write-Host "[LOGOUT] Session key removed. You have been logged out." -ForegroundColor Yellow
}

#endregion

#region Encryption/Decryption

function Protect-EnvFile {
    <#
    .SYNOPSIS
    Encrypts a .env file using AES-256 with the master key.

    .PARAMETER InputPath
    Path to the plaintext .env file

    .PARAMETER OutputPath
    Path for the encrypted output file (default: InputPath + ".encrypted")

    .PARAMETER MasterKey
    Optional: Provide master key directly (for recovery/backup scenarios).
    If not provided, retrieves master key from KeePass (requires Windows Hello session).

    .DESCRIPTION
    Encrypts the file with the master key from KeePass.
    Requires an active Windows Hello session UNLESS you provide -MasterKey directly.

    .OUTPUTS
    Returns $true if encryption successful
    #>
    param(
        [Parameter(Mandatory)]
        [string]$InputPath,

        [string]$OutputPath = "",

        [string]$MasterKey = ""
    )

    if (-not (Test-Path $InputPath)) {
        Write-Error "Input file not found: $InputPath"
        return $false
    }

    if ($OutputPath -eq "") {
        $OutputPath = "$InputPath.encrypted"
    }

    # Determine encryption key source
    if ($MasterKey -ne "") {
        # Using provided master key (recovery mode)
        if ($MasterKey.Length -ne 44) {
            Write-Error "Invalid master key format. Expected 44-character base64 string."
            return $false
        }
        Write-Host "[INFO] Using provided master key" -ForegroundColor Cyan
        $encryptionKey = $MasterKey
    } else {
        # Get master key from KeePass (requires valid Windows Hello session)
        $encryptionKey = Get-MasterKey
        if (-not $encryptionKey) {
            Write-Error "Cannot access master key. Please authenticate with New-SessionKey first, or provide -MasterKey parameter."
            return $false
        }
    }

    $encryptionKeyBytes = ConvertFrom-Base64 -Base64String $encryptionKey

    # Read plaintext content
    $plaintext = Get-Content -Path $InputPath -Raw -Encoding UTF8
    $plaintextBytes = [Encoding]::UTF8.GetBytes($plaintext)

    # Create AES encryptor
    $aes = [Aes]::Create()
    $aes.KeySize = 256
    $aes.Key = $encryptionKeyBytes
    $aes.GenerateIV()

    # Encrypt
    $encryptor = $aes.CreateEncryptor()
    $encryptedBytes = $encryptor.TransformFinalBlock($plaintextBytes, 0, $plaintextBytes.Length)

    # Create output structure: IV (16 bytes) + Encrypted Data
    $outputBytes = $aes.IV + $encryptedBytes
    $outputBase64 = ConvertTo-Base64 -Bytes $outputBytes

    # Add metadata
    $metadata = @{
        Version = "1.0"
        Algorithm = "AES-256-CBC"
        EncryptedAt = (Get-Date).ToString("o")
        OriginalFile = (Split-Path -Leaf $InputPath)
    }

    $output = @{
        Metadata = $metadata
        Data = $outputBase64
    }

    # Save encrypted file
    $output | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8

    Write-Host "[OK] File encrypted successfully: $OutputPath" -ForegroundColor Green
    return $true
}

function Unprotect-EnvFile {
    <#
    .SYNOPSIS
    Decrypts an encrypted .env file.

    .PARAMETER InputPath
    Path to the encrypted .env file

    .PARAMETER OutputPath
    Path for the decrypted output file (default: removes ".encrypted" suffix)

    .PARAMETER InMemory
    If specified, returns the decrypted content as a string instead of writing to file

    .PARAMETER MasterKey
    Optional: Provide master key directly (for recovery/backup scenarios).
    If not provided, retrieves master key from KeePass (requires Windows Hello session).

    .DESCRIPTION
    Decrypts the file using the master key from KeePass.
    Requires an active Windows Hello session UNLESS you provide -MasterKey directly.

    .OUTPUTS
    Returns $true if decryption successful, or decrypted content if -InMemory
    #>
    param(
        [Parameter(Mandatory)]
        [string]$InputPath,

        [string]$OutputPath = "",

        [switch]$InMemory,

        [string]$MasterKey = ""
    )

    if (-not (Test-Path $InputPath)) {
        Write-Error "Input file not found: $InputPath"
        return $false
    }

    if ($OutputPath -eq "" -and -not $InMemory) {
        $OutputPath = $InputPath -replace '\.encrypted$', ''
    }

    # Determine decryption key source
    if ($MasterKey -ne "") {
        # Using provided master key (recovery mode)
        if ($MasterKey.Length -ne 44) {
            Write-Error "Invalid master key format. Expected 44-character base64 string."
            return $false
        }
        Write-Host "[INFO] Using provided master key" -ForegroundColor Cyan
        $decryptionKey = $MasterKey
    } else {
        # Get master key from KeePass (requires valid Windows Hello session)
        $decryptionKey = Get-MasterKey
        if (-not $decryptionKey) {
            Write-Error "Cannot access master key. Please authenticate with New-SessionKey first, or provide -MasterKey parameter."
            return $false
        }
    }

    $decryptionKeyBytes = ConvertFrom-Base64 -Base64String $decryptionKey

    # Read encrypted file
    $encryptedData = Get-Content -Path $InputPath -Raw | ConvertFrom-Json
    $encryptedBytes = ConvertFrom-Base64 -Base64String $encryptedData.Data

    # Extract IV and encrypted data
    $iv = $encryptedBytes[0..15]
    $ciphertext = $encryptedBytes[16..($encryptedBytes.Length - 1)]

    # Create AES decryptor
    $aes = [Aes]::Create()
    $aes.KeySize = 256
    $aes.Key = $decryptionKeyBytes
    $aes.IV = $iv

    # Decrypt
    try {
        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        $plaintext = [Encoding]::UTF8.GetString($decryptedBytes)
    } catch {
        Write-Error "Decryption failed. Invalid key or corrupted file."
        return $false
    }

    # Return or save
    if ($InMemory) {
        return $plaintext
    } else {
        $plaintext | Out-File -FilePath $OutputPath -Encoding UTF8 -NoNewline
        Write-Host "[OK] File decrypted successfully: $OutputPath" -ForegroundColor Green
        return $true
    }
}

#endregion

#region Utility Functions

function Get-SessionStatus {
    <#
    .SYNOPSIS
    Displays the current session key status.
    #>

    $cred = Get-SecureCredential -Target $script:CredentialTarget

    if (-not $cred) {
        Write-Host "[ERROR] No active session" -ForegroundColor Red
        Write-Host "Run New-SessionKey to authenticate" -ForegroundColor Yellow
        return
    }

    $createdAt = [DateTime]::Parse($cred.Metadata.CreatedAt)
    $expiresAt = [DateTime]::Parse($cred.Metadata.ExpiresAt)
    $now = Get-Date

    if ($now -gt $expiresAt) {
        Write-Host "[ERROR] Session expired" -ForegroundColor Red
        Write-Host "Expired at: $($expiresAt.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
        Remove-SecureCredential -Target $script:CredentialTarget
        return
    }

    $timeRemaining = $expiresAt - $now
    $hoursRemaining = [Math]::Floor($timeRemaining.TotalHours)
    $minutesRemaining = [Math]::Floor($timeRemaining.TotalMinutes % 60)

    Write-Host "[OK] Active session" -ForegroundColor Green
    Write-Host "Created:  $($createdAt.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    Write-Host "Expires:  $($expiresAt.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    Write-Host "Remaining: ${hoursRemaining}h ${minutesRemaining}m" -ForegroundColor Cyan

    if ($timeRemaining.TotalSeconds -lt $script:RefreshThreshold) {
        Write-Host "WARNING: Session expiring soon. Run Update-SessionKey to refresh." -ForegroundColor Yellow
    }
}

#endregion

#region Backup Functions

function Set-BackupRecoveryPassword {
    <#
    .SYNOPSIS
    Sets the recovery password and creates an encrypted backup of the master key.

    .PARAMETER RecoveryPassword
    The password to encrypt the master key backup (SecureString)

    .DESCRIPTION
    Encrypts the master key with a user-provided recovery password using AES-256.
    This encrypted backup can be uploaded to cloud storage for disaster recovery.

    .OUTPUTS
    Returns $true if successful
    #>
    param(
        [Parameter(Mandatory)]
        [SecureString]$RecoveryPassword
    )

    # Get the current master key
    $settings = Get-Settings

    if ($settings.securityMode -eq "simple") {
        $masterKey = Get-DpapiMasterKey
    } else {
        # For advanced mode, we need a valid session
        $masterKey = Get-MasterKey
    }

    if (-not $masterKey) {
        Write-Error "Cannot access master key. Ensure you have set up Simple Secret first."
        return $false
    }

    try {
        # Convert recovery password to encryption key using PBKDF2
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($RecoveryPassword)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        # Generate salt for PBKDF2
        $salt = Get-RandomBytes -Length 16

        # Derive key using PBKDF2
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($plainPassword, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $derivedKey = $pbkdf2.GetBytes(32)

        # Encrypt master key with AES-256
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.Key = $derivedKey
        $aes.GenerateIV()

        $masterKeyBytes = [System.Text.Encoding]::UTF8.GetBytes($masterKey)
        $encryptor = $aes.CreateEncryptor()
        $encryptedMasterKey = $encryptor.TransformFinalBlock($masterKeyBytes, 0, $masterKeyBytes.Length)

        # Create backup file structure
        $backupData = @{
            Version = "1.0"
            Type = "MasterKeyBackup"
            CreatedAt = (Get-Date).ToString("o")
            Salt = [Convert]::ToBase64String($salt)
            IV = [Convert]::ToBase64String($aes.IV)
            EncryptedMasterKey = [Convert]::ToBase64String($encryptedMasterKey)
            SecurityMode = $settings.securityMode
        }

        # Save to backup folder
        $backupPath = Join-Path $PSScriptRoot "backup"
        if (-not (Test-Path $backupPath)) {
            New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        }

        $backupFile = Join-Path $backupPath "master-key.backup"
        $backupData | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupFile -Encoding UTF8

        # Update settings
        $settings.backup.recoveryPasswordSet = $true
        Set-Settings -Settings $settings | Out-Null

        Write-Host "[OK] Recovery password set and master key backup created" -ForegroundColor Green
        return $true

    } catch {
        Write-Error "Failed to set recovery password: $_"
        return $false
    }
}

function Restore-FromRecoveryPassword {
    <#
    .SYNOPSIS
    Restores the master key from a backup using the recovery password.

    .PARAMETER RecoveryPassword
    The recovery password (SecureString)

    .PARAMETER BackupFile
    Path to the backup file (optional, defaults to local backup)

    .OUTPUTS
    Returns the master key string if successful, $null otherwise
    #>
    param(
        [Parameter(Mandatory)]
        [SecureString]$RecoveryPassword,

        [string]$BackupFile = ""
    )

    # Find backup file
    if ($BackupFile -eq "") {
        $backupPath = Join-Path $PSScriptRoot "backup"
        $BackupFile = Join-Path $backupPath "master-key.backup"
    }

    if (-not (Test-Path $BackupFile)) {
        Write-Error "Backup file not found: $BackupFile"
        return $null
    }

    try {
        # Read backup
        $backupData = Get-Content $BackupFile -Raw | ConvertFrom-Json

        # Convert recovery password to decryption key
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($RecoveryPassword)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        # Get salt and derive key
        $salt = [Convert]::FromBase64String($backupData.Salt)
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($plainPassword, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $derivedKey = $pbkdf2.GetBytes(32)

        # Decrypt master key
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.Key = $derivedKey
        $aes.IV = [Convert]::FromBase64String($backupData.IV)

        $encryptedMasterKey = [Convert]::FromBase64String($backupData.EncryptedMasterKey)
        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedMasterKey, 0, $encryptedMasterKey.Length)
        $masterKey = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

        Write-Host "[OK] Master key restored from backup" -ForegroundColor Green
        return $masterKey

    } catch {
        Write-Error "Failed to restore from backup. Check your recovery password."
        return $null
    }
}

function Test-BackupNeeded {
    <#
    .SYNOPSIS
    Checks if a backup is due based on the configured frequency.

    .OUTPUTS
    Returns $true if backup is needed, $false otherwise
    #>

    $settings = Get-Settings

    if (-not $settings.backup.enabled -or $settings.backup.frequency -eq "never") {
        return $false
    }

    if (-not $settings.backup.lastBackup) {
        return $true
    }

    $lastBackup = [DateTime]::Parse($settings.backup.lastBackup)
    $now = Get-Date

    switch ($settings.backup.frequency) {
        "daily" { return ($now - $lastBackup).TotalDays -ge 1 }
        "weekly" { return ($now - $lastBackup).TotalDays -ge 7 }
        "monthly" { return ($now - $lastBackup).TotalDays -ge 30 }
        default { return $false }
    }
}

function New-CloudBackup {
    <#
    .SYNOPSIS
    Creates a backup and opens Google Drive for easy drag-and-drop upload.

    .DESCRIPTION
    1. Ensures backup file exists
    2. Opens Google Drive in browser
    3. Opens File Explorer to backup location
    4. User drags and drops the file

    .PARAMETER OpenDrive
    If specified, opens Google Drive and File Explorer for manual upload

    .OUTPUTS
    Returns $true if successful
    #>
    param(
        [switch]$OpenDrive
    )

    $settings = Get-Settings

    if (-not $settings.backup.recoveryPasswordSet) {
        Write-Error "Recovery password not set. Run Set-BackupRecoveryPassword first."
        return $false
    }

    # Get the backup file path
    $backupPath = Join-Path $PSScriptRoot "backup"
    $backupFile = Join-Path $backupPath "master-key.backup"

    if (-not (Test-Path $backupFile)) {
        Write-Error "Backup file not found. Run Set-BackupRecoveryPassword first."
        return $false
    }

    # Update last backup time
    $settings.backup.lastBackup = (Get-Date).ToString("o")
    Set-Settings -Settings $settings | Out-Null

    Write-Host "[OK] Local backup ready: $backupFile" -ForegroundColor Green

    # Open Google Drive and File Explorer for drag-and-drop
    if ($OpenDrive) {
        Open-BackupForUpload
    }

    return $true
}

function Open-BackupForUpload {
    <#
    .SYNOPSIS
    Opens Google Drive website and File Explorer for easy drag-and-drop backup upload.

    .DESCRIPTION
    1. Opens https://drive.google.com/drive/u/0/recent in default browser
    2. Opens File Explorer to the backup folder with the file selected
    3. User simply drags the file to the browser

    .EXAMPLE
    Open-BackupForUpload
    #>

    $backupPath = Join-Path $PSScriptRoot "backup"
    $backupFile = Join-Path $backupPath "master-key.backup"

    if (-not (Test-Path $backupFile)) {
        Write-Error "Backup file not found. Run Set-BackupRecoveryPassword first."
        return $false
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Upload Backup to Google Drive" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Opening:" -ForegroundColor Gray
    Write-Host "  1. Google Drive (in browser)" -ForegroundColor White
    Write-Host "  2. File Explorer (backup folder)" -ForegroundColor White
    Write-Host ""
    Write-Host "Just drag and drop the backup file to Google Drive!" -ForegroundColor Yellow
    Write-Host ""

    # Open Google Drive in default browser
    Start-Process "https://drive.google.com/drive/u/0/recent"

    # Small delay to let browser open first
    Start-Sleep -Milliseconds 500

    # Open File Explorer with the backup file selected
    if (Test-Path $backupFile) {
        # Use explorer with /select to highlight the file
        Start-Process explorer.exe -ArgumentList "/select,`"$backupFile`""
    } else {
        # Just open the backup folder
        Start-Process explorer.exe -ArgumentList "`"$backupPath`""
    }

    Write-Host "[OK] Windows opened. Drag the file to Google Drive." -ForegroundColor Green
    Write-Host ""

    return $true
}

function Get-BackupStatus {
    <#
    .SYNOPSIS
    Shows the current backup status and configuration.
    #>

    $settings = Get-Settings

    Write-Host ""
    Write-Host "=== Backup Configuration ===" -ForegroundColor Cyan
    Write-Host "Enabled:            $($settings.backup.enabled)" -ForegroundColor Gray
    Write-Host "Frequency:          $($settings.backup.frequency)" -ForegroundColor Gray
    Write-Host "Destination:        $($settings.backup.destination)" -ForegroundColor Gray
    Write-Host "Recovery Password:  $(if ($settings.backup.recoveryPasswordSet) { 'Set' } else { 'Not Set' })" -ForegroundColor $(if ($settings.backup.recoveryPasswordSet) { 'Green' } else { 'Yellow' })

    if ($settings.backup.lastBackup) {
        $lastBackup = [DateTime]::Parse($settings.backup.lastBackup)
        Write-Host "Last Backup:        $($lastBackup.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    } else {
        Write-Host "Last Backup:        Never" -ForegroundColor Yellow
    }

    if (Test-BackupNeeded) {
        Write-Host ""
        Write-Host "[!] Backup is due" -ForegroundColor Yellow
    }

    Write-Host ""
}

#endregion

# Export module functions
Export-ModuleMember -Function @(
    # Settings Management
    'Get-Settings',
    'Set-Settings',
    # DPAPI Master Key Storage
    'Save-DpapiMasterKey',
    'Get-DpapiMasterKey',
    'Remove-DpapiMasterKey',
    'Test-DpapiMasterKey',
    # Windows Hello Authentication
    'Invoke-WindowsHelloAuth',
    # Master Key Management
    'New-MasterKey',
    'Get-MasterKey',
    'Get-MasterKeyFromKeePass',
    'New-KeePassDatabaseWithMasterKey',
    # Session Key Management
    'New-SessionKey',
    'New-SessionKeySimple',
    'New-SessionKeyAdvanced',
    'Get-SessionKey',
    'Update-SessionKey',
    'Remove-SessionKey',
    # Encryption/Decryption
    'Protect-EnvFile',
    'Unprotect-EnvFile',
    # Backup Functions
    'Set-BackupRecoveryPassword',
    'Restore-FromRecoveryPassword',
    'Test-BackupNeeded',
    'New-CloudBackup',
    'Open-BackupForUpload',
    'Get-BackupStatus',
    # Utility Functions
    'Get-SessionStatus',
    'Save-SecureCredential',
    'Get-SecureCredential',
    'Remove-SecureCredential',
    'Show-PasswordDialog',
    # KeePass Functions
    'Test-KeePassDatabase'
)
