@{
    RootModule        = 'scrt4.psm1'
    ModuleVersion     = '0.2.0'
    GUID              = '7a2c1f5e-9d3b-4c8a-b6e1-40feb2026aa1'
    Author            = 'VestedJosh'
    Description       = 'Native Windows client for the scrt4 hardware-bound secret manager (FIDO2/WebAuthn PRF).'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-Scrt4', 'Send-Scrt4Request')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
