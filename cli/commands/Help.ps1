# Help.ps1
# scrt help command

function Invoke-ScrtHelp {
    <#
    .SYNOPSIS
    Displays help information for scrt commands.
    #>
    param(
        [string]$Command = ""
    )

    Write-ScrtLog -Message "Help requested for: $(if ($Command) { $Command } else { 'all' })"

    if ($Command -eq "") {
        Show-GeneralHelp
    } else {
        Show-CommandHelp -Command $Command
    }
}

function Show-GeneralHelp {
    Write-Host ""
    Write-Host "scrt - EnvCrypto Secrets Management CLI" -ForegroundColor Cyan
    Write-Host "Version 1.0.0" -ForegroundColor Gray
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  scrt <command> [options] [arguments]"
    Write-Host ""
    Write-Host "GETTING STARTED:" -ForegroundColor Yellow
    Write-Host "  setup [path-to-.env]" -NoNewline -ForegroundColor White
    Write-Host "          Encrypt existing .env (recommended)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "CORE COMMANDS:" -ForegroundColor Yellow
    Write-Host "  auth" -NoNewline -ForegroundColor White
    Write-Host "                            Start session (Windows Hello)" -ForegroundColor Gray
    Write-Host "  status" -NoNewline -ForegroundColor White
    Write-Host "                          Show session status" -ForegroundColor Gray
    Write-Host "  logout" -NoNewline -ForegroundColor White
    Write-Host "                          End session" -ForegroundColor Gray
    Write-Host ""
    Write-Host "FILE OPERATIONS:" -ForegroundColor Yellow
    Write-Host "  encrypt [--force]" -NoNewline -ForegroundColor White
    Write-Host "               Encrypt .env to .env.encrypted" -ForegroundColor Gray
    Write-Host "  decrypt [--master-key]" -NoNewline -ForegroundColor White
    Write-Host "          Decrypt .env.encrypted to .env" -ForegroundColor Gray
    Write-Host "  decrypt --preview" -NoNewline -ForegroundColor White
    Write-Host "               Show first 5 lines only" -ForegroundColor Gray
    Write-Host ""
    Write-Host "SECRET ACCESS:" -ForegroundColor Yellow
    Write-Host "  view [secret-name]" -NoNewline -ForegroundColor White
    Write-Host "            Auth + view secrets (all-in-one)" -ForegroundColor Gray
    Write-Host "  list [--verbose]" -NoNewline -ForegroundColor White
    Write-Host "                List secret names (never values)" -ForegroundColor Gray
    Write-Host "  run -- <command>" -NoNewline -ForegroundColor White
    Write-Host "              Run command with secrets injected" -ForegroundColor Gray
    Write-Host ""
    Write-Host "UTILITIES:" -ForegroundColor Yellow
    Write-Host "  help [command]" -NoNewline -ForegroundColor White
    Write-Host "                  Show help" -ForegroundColor Gray
    Write-Host "  version" -NoNewline -ForegroundColor White
    Write-Host "                         Show version" -ForegroundColor Gray
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  scrt setup                   # Encrypt .env in current directory"
    Write-Host "  scrt setup C:\project\.env   # Encrypt .env from specific path"
    Write-Host "  scrt view                    # Auth + show all secrets"
    Write-Host "  scrt view STRIPE_SECRET_KEY  # Auth + show specific secret"
    Write-Host "  scrt run -- npm start        # Run with secrets"
    Write-Host ""
    Write-Host "For command-specific help: scrt help <command>" -ForegroundColor Gray
    Write-Host ""
}

function Show-CommandHelp {
    param([string]$Command)

    switch ($Command.ToLower()) {
        "setup" {
            Write-Host ""
            Write-Host "scrt setup - First Time Setup" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor Yellow
            Write-Host "  scrt setup [path-to-.env]"
            Write-Host ""
            Write-Host "DESCRIPTION:" -ForegroundColor Yellow
            Write-Host "  Encrypts your existing .env file with Windows Hello protection."
            Write-Host ""
            Write-Host "  This command will:"
            Write-Host "    1. Set up Windows Hello authentication"
            Write-Host "    2. Generate and securely store an encryption key"
            Write-Host "    3. Create .env.backup (preserves your original)"
            Write-Host "    4. Create .env.encrypted"
            Write-Host ""
            Write-Host "  Your original .env is NEVER deleted or overwritten."
            Write-Host ""
            Write-Host "EXAMPLES:" -ForegroundColor Yellow
            Write-Host "  scrt setup                    # Use .env in current directory"
            Write-Host "  scrt setup C:\myproject\.env  # Specify path to .env"
            Write-Host "  scrt setup ..\.env            # Relative path"
            Write-Host ""
        }

        "init" {
            Write-Host ""
            Write-Host "scrt init - Setup Wizard" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor Yellow
            Write-Host "  scrt init [--mode simple|advanced] [--force]"
            Write-Host ""
            Write-Host "OPTIONS:" -ForegroundColor Yellow
            Write-Host "  --mode simple     Use Simple mode (Windows Hello only)"
            Write-Host "  --mode advanced   Use Advanced mode (Windows Hello + KeePass)"
            Write-Host "  --force           Re-initialize even if already set up"
            Write-Host ""
            Write-Host "DESCRIPTION:" -ForegroundColor Yellow
            Write-Host "  Sets up the secret encryption system. Guides you through"
            Write-Host "  choosing a security mode and creating your master key."
            Write-Host ""
        }

        "auth" {
            Write-Host ""
            Write-Host "scrt auth - Start Session" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor Yellow
            Write-Host "  scrt auth"
            Write-Host ""
            Write-Host "DESCRIPTION:" -ForegroundColor Yellow
            Write-Host "  Authenticates with Windows Hello (and KeePass in Advanced mode)"
            Write-Host "  and creates a 2-hour session for encrypt/decrypt operations."
            Write-Host ""
        }

        "status" {
            Write-Host ""
            Write-Host "scrt status - Show Session Status" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor Yellow
            Write-Host "  scrt status"
            Write-Host ""
            Write-Host "DESCRIPTION:" -ForegroundColor Yellow
            Write-Host "  Shows whether you have an active session, when it expires,"
            Write-Host "  and which security mode is configured."
            Write-Host ""
        }

        "logout" {
            Write-Host ""
            Write-Host "scrt logout - End Session" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor Yellow
            Write-Host "  scrt logout"
            Write-Host ""
            Write-Host "DESCRIPTION:" -ForegroundColor Yellow
            Write-Host "  Removes the current session, requiring re-authentication"
            Write-Host "  for subsequent encrypt/decrypt operations."
            Write-Host ""
        }

        "encrypt" {
            Write-Host ""
            Write-Host "scrt encrypt - Encrypt .env File" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor Yellow
            Write-Host "  scrt encrypt [--force] [--keep]"
            Write-Host ""
            Write-Host "OPTIONS:" -ForegroundColor Yellow
            Write-Host "  --force   Overwrite existing .env.encrypted"
            Write-Host "  --keep    Keep plaintext .env after encryption"
            Write-Host ""
            Write-Host "DESCRIPTION:" -ForegroundColor Yellow
            Write-Host "  Encrypts .env to .env.encrypted using AES-256."
            Write-Host "  Requires active session (run 'scrt auth' first)."
            Write-Host "  By default, deletes plaintext .env after encryption."
            Write-Host ""
        }

        "decrypt" {
            Write-Host ""
            Write-Host "scrt decrypt - Decrypt .env.encrypted" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor Yellow
            Write-Host "  scrt decrypt [--preview] [--master-key]"
            Write-Host ""
            Write-Host "OPTIONS:" -ForegroundColor Yellow
            Write-Host "  --preview      Show first 5 lines only (no file created)"
            Write-Host "  --master-key   Prompt for master key (recovery mode)"
            Write-Host ""
            Write-Host "DESCRIPTION:" -ForegroundColor Yellow
            Write-Host "  Decrypts .env.encrypted to .env for editing."
            Write-Host "  Requires active session unless --master-key is used."
            Write-Host ""
        }

        "list" {
            Write-Host ""
            Write-Host "scrt list - List Secret Names" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor Yellow
            Write-Host "  scrt list [--verbose]"
            Write-Host ""
            Write-Host "OPTIONS:" -ForegroundColor Yellow
            Write-Host "  --verbose   Show secret names with their lengths"
            Write-Host ""
            Write-Host "DESCRIPTION:" -ForegroundColor Yellow
            Write-Host "  Lists secret names from .env.encrypted."
            Write-Host "  NEVER shows secret values."
            Write-Host "  Requires active session."
            Write-Host ""
        }

        "run" {
            Write-Host ""
            Write-Host "scrt run - Run Command with Secrets" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor Yellow
            Write-Host "  scrt run -- <command> [args...]"
            Write-Host ""
            Write-Host "DESCRIPTION:" -ForegroundColor Yellow
            Write-Host "  Decrypts secrets in-memory and injects them as environment"
            Write-Host "  variables for the specified command."
            Write-Host "  Requires active session."
            Write-Host ""
            Write-Host "EXAMPLES:" -ForegroundColor Yellow
            Write-Host "  scrt run -- npm start"
            Write-Host "  scrt run -- python deploy.py"
            Write-Host "  scrt run -- cmd /c echo %PRIVATE_KEY%"
            Write-Host ""
        }

        "view" {
            Write-Host ""
            Write-Host "scrt view - Authenticate and View Secrets" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor Yellow
            Write-Host "  scrt view [secret-name]"
            Write-Host ""
            Write-Host "OPTIONS:" -ForegroundColor Yellow
            Write-Host "  secret-name   Optional: view only a specific secret"
            Write-Host ""
            Write-Host "DESCRIPTION:" -ForegroundColor Yellow
            Write-Host "  Combines auth + decrypt in one command:"
            Write-Host "  1. Authenticates with Windows Hello (if needed)"
            Write-Host "  2. Decrypts .env.encrypted in memory"
            Write-Host "  3. Displays secret values"
            Write-Host ""
            Write-Host "  Secrets are NEVER written to disk."
            Write-Host ""
            Write-Host "EXAMPLES:" -ForegroundColor Yellow
            Write-Host "  scrt view                    # Show all secrets"
            Write-Host "  scrt view STRIPE_SECRET_KEY  # Show specific secret"
            Write-Host ""
        }

        "version" {
            Write-Host ""
            Write-Host "scrt version - Show Version" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor Yellow
            Write-Host "  scrt version"
            Write-Host ""
        }

        default {
            Write-ScrtError "Unknown command: $Command"
            Write-Host "Run 'scrt help' for available commands." -ForegroundColor Gray
        }
    }
}
