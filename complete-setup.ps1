<#
.SYNOPSIS
    Completes the scriptable SecureOTA setup tasks: commits outstanding work,
    generates firmware signing keys, and configures GitHub Actions secrets.

.DESCRIPTION
    Runs in three independent phases. Each can be run on its own and each is
    safe to re-run — nothing here rewrites history, force-pushes, or deletes.

        1  commit    Commit (and push where permitted) outstanding work
        2  keys      Generate the RSA-2048 signing keypair
        3  secrets   Set the GitHub Actions secrets

    NOT covered, because they are not shell work:
      - the rollback fix and the other verified defects (code changes)
      - patent prior-disclosure / inventorship / institutional IP (decisions)
      - scrubbing the leaked key from git history (destructive; do it
        deliberately, not from a convenience script)

.PARAMETER Phase
    all (default), commit, keys, or secrets.

.PARAMETER KeyDir
    Where the signing keypair is written. Default: .\signing-keys
    This directory must never be committed.

.EXAMPLE
    .\complete-setup.ps1 -Phase commit
    .\complete-setup.ps1 -Phase keys
    .\complete-setup.ps1 -Phase secrets

.NOTES
    Administrator privileges are NOT required for anything in this script.
#>

[CmdletBinding()]
param(
    [ValidateSet('all', 'commit', 'keys', 'secrets')]
    [string]$Phase = 'all',

    [string]$KeyDir = (Join-Path $PSScriptRoot 'signing-keys')
)

$ErrorActionPreference = 'Stop'

$Root       = $PSScriptRoot
$BackendDir = $Root
$IdeDir     = Join-Path $Root 'CODE\SecureOTA-IDE'
$Repo       = 'Rithik-sharma12/Secure_OTA_Update_Security_Mechanism'

function Write-Step  { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok    { param($m) Write-Host "  [ok]   $m" -ForegroundColor Green }
function Write-Warn2 { param($m) Write-Host "  [warn] $m" -ForegroundColor Yellow }
function Write-Info  { param($m) Write-Host "  [info] $m" -ForegroundColor Gray }

function Assert-Tool {
    param($Name, $Hint)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { throw "$Name not found on PATH. $Hint" }
    Write-Ok "$Name found"
}

# ---------------------------------------------------------------------------
# Phase 1 — commit outstanding work
# ---------------------------------------------------------------------------
function Invoke-CommitPhase {
    Write-Step 'Phase 1 of 3 - commit outstanding work'
    Assert-Tool git 'Install Git for Windows.'

    # -- backend repo -------------------------------------------------------
    Push-Location $BackendDir
    try {
        $dirty = git status --porcelain
        if ([string]::IsNullOrWhiteSpace($dirty)) {
            Write-Info 'Backend repo already clean, nothing to commit.'
        }
        else {
            Write-Info "Backend repo has $(($dirty -split "`n").Count) changed path(s)."
            git add -A
            if ($LASTEXITCODE -ne 0) { throw 'git add failed in backend repo.' }

            # Refuse to proceed if a known-sensitive path got staged.
            $staged = git diff --cached --name-only
            $forbidden = $staged | Where-Object {
                $_ -match '\.env\.docker$' -or
                $_ -match 'credentials\.json$' -or
                $_ -match '\.pem$' -or
                $_ -match 'gateway_firmware_cache/'
            }
            if ($forbidden) {
                git reset | Out-Null
                throw "Refusing to commit - sensitive path(s) staged:`n  $($forbidden -join "`n  ")"
            }

            git commit -q -m @'
feat: WiFi provisioning at serial flash, CI activation, architecture docs

Serial flash now bakes WiFi credentials into ota_config.h at compile
time. The sketch is copied to a temp workspace and the copy is patched,
so the tracked placeholder header is never written to and concurrent
flashes cannot clobber each other. The workspace is removed in a
finally block, success or failure.

Activates the firmware release workflow by moving it into
.github/workflows/, and fixes three bugs that would each have stopped
it running:
  - the ota_config.h heredoc wrote to the project root, which the
    compiler never sees; PlatformIO uses src_dir = esp32_ota_main
  - `if: secrets.X != ''` is invalid; the secrets context is not
    available to step-level if, so the workflow failed to parse
  - the generated header omitted OTA_NTP_SERVER_PRIMARY/SECONDARY and
    OTA_ROOT_CA, which the sketch uses and which have no fallbacks

Adds docs/architecture: the OTA lifecycle study and the verified gap
analysis.
'@
            if ($LASTEXITCODE -ne 0) { throw 'git commit failed in backend repo.' }
            Write-Ok 'Backend repo committed.'
        }

        Write-Info 'Pushing backend repo...'
        git push origin main
        if ($LASTEXITCODE -ne 0) { Write-Warn2 'Backend push failed - commit is safe locally.' }
        else { Write-Ok 'Backend repo pushed.' }
    }
    finally { Pop-Location }

    # -- IDE repo -----------------------------------------------------------
    if (-not (Test-Path $IdeDir)) {
        Write-Warn2 'SecureOTA-IDE directory not found, skipping.'
        return
    }

    Push-Location $IdeDir
    try {
        $dirty = git status --porcelain
        if ([string]::IsNullOrWhiteSpace($dirty)) {
            Write-Info 'IDE repo already clean, nothing to commit.'
        }
        else {
            git add -A
            if ($LASTEXITCODE -ne 0) { throw 'git add failed in IDE repo.' }

            git commit -q -m @'
feat: implement GitHub release pipeline, packet security, device panel

Replaces the scaffold stubs with working modules. triggerRelease()
previously only incremented a counter in a local JSON file and made no
API call; simulateUpload() was a no-op.

  - real GitHub REST client: repo create/check, source and binary
    commit, release creation, asset upload, with rate-limit and 5xx
    retry and a durable offline queue
  - AES-256-CBC + HMAC-SHA256 packet codec, device registry with
    per-device keys, and a UDP listener running all four verification
    layers
  - update relevance checker
  - ESP32 tracking agent (device/TrackingAgent.{h,cpp})
  - 42 tests, all passing

Three corrections to the sketched design:
  - the IV was never transmitted; a CBC ciphertext cannot be decrypted
    without it, so the wire format is now IV || ciphertext
  - HMAC compared with !== leaks via timing; now timingSafeEqual
  - layer 3 accepted any registered MAC, letting one device impersonate
    another; the keys that decrypt must now match the claimed MAC

Also fixes the root scripts, which used Yarn 2 syntax under a Yarn 1
packageManager pin, so `yarn build` had never worked.
'@
            if ($LASTEXITCODE -ne 0) { throw 'git commit failed in IDE repo.' }
            Write-Ok 'IDE repo committed.'
        }

        Write-Info 'Pushing IDE repo...'
        git push origin master
        if ($LASTEXITCODE -ne 0) {
            Write-Warn2 'IDE push failed. This repo belongs to riteshvijaykumar -'
            Write-Warn2 'you may not have write access. The commit is safe locally;'
            Write-Warn2 'open a pull request or ask for collaborator access.'
        }
        else { Write-Ok 'IDE repo pushed.' }
    }
    finally { Pop-Location }
}

# ---------------------------------------------------------------------------
# Phase 2 — generate signing keys
# ---------------------------------------------------------------------------
function Invoke-KeysPhase {
    Write-Step 'Phase 2 of 3 - generate the RSA-2048 signing keypair'
    Assert-Tool openssl 'Install OpenSSL, or use the one bundled with Git for Windows.'

    if (-not (Test-Path $KeyDir)) {
        New-Item -ItemType Directory -Path $KeyDir -Force | Out-Null
    }

    $priv = Join-Path $KeyDir 'firmware_priv.pem'
    $pub  = Join-Path $KeyDir 'firmware_pub.pem'

    if (Test-Path $priv) {
        Write-Warn2 "Private key already exists at $priv"
        Write-Warn2 'Not regenerating - a new key would invalidate every device'
        Write-Warn2 'already carrying the old public key.'
    }
    else {
        openssl genrsa -out $priv 2048 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'RSA private key generation failed.' }
        openssl rsa -in $priv -pubout -out $pub 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'Public key extraction failed.' }
        Write-Ok "Keypair written to $KeyDir"
    }

    # Keep the keys out of git no matter which repo they land beside.
    $ignore = Join-Path $KeyDir '.gitignore'
    if (-not (Test-Path $ignore)) {
        Set-Content -Path $ignore -Value "*`n!.gitignore`n" -Encoding utf8
    }

    # 32 chars exactly - the workflow hard-fails on any other length.
    $aesFile = Join-Path $KeyDir 'aes_key.txt'
    if (Test-Path $aesFile) {
        Write-Warn2 'AES key already exists, leaving it alone.'
    }
    else {
        $bytes = New-Object 'System.Byte[]' 24
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $aes = ([Convert]::ToBase64String($bytes) -replace '[^A-Za-z0-9]', '').Substring(0, 32)
        Set-Content -Path $aesFile -Value $aes -NoNewline -Encoding ascii
        Write-Ok "AES-256 key (32 chars) written to $aesFile"
    }

    Write-Warn2 'These files are secrets. Never commit them, never email them.'
}

# ---------------------------------------------------------------------------
# Phase 3 — set GitHub Actions secrets
# ---------------------------------------------------------------------------
function Invoke-SecretsPhase {
    Write-Step 'Phase 3 of 3 - set GitHub Actions secrets'
    Assert-Tool gh 'Install the GitHub CLI: https://cli.github.com'

    gh auth status 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Not authenticated. Run: gh auth login' }
    Write-Ok 'GitHub CLI authenticated'

    $priv    = Join-Path $KeyDir 'firmware_priv.pem'
    $pub     = Join-Path $KeyDir 'firmware_pub.pem'
    $aesFile = Join-Path $KeyDir 'aes_key.txt'

    if (-not (Test-Path $priv)) { throw "Signing keys missing. Run: .\complete-setup.ps1 -Phase keys" }

    # -- key material -------------------------------------------------------
    # PowerShell has no '<' input redirection, so the PEMs are piped. A
    # trailing newline is normal in a PEM and harmless.
    Write-Info 'Setting key material from files...'
    Get-Content $priv -Raw | gh secret set FIRMWARE_PRIV_KEY --repo $Repo
    if ($LASTEXITCODE -ne 0) { throw 'Failed to set FIRMWARE_PRIV_KEY.' }
    Get-Content $pub -Raw | gh secret set FIRMWARE_PUB_KEY --repo $Repo
    if ($LASTEXITCODE -ne 0) { throw 'Failed to set FIRMWARE_PUB_KEY.' }

    # The AES key is passed with --body rather than piped: piping through
    # PowerShell appends a newline, which would make it 33 characters and
    # trip the workflow's "must be exactly 32" check.
    $aes = (Get-Content $aesFile -Raw).Trim()
    if ($aes.Length -ne 32) {
        throw "AES key must be exactly 32 characters, found $($aes.Length). Delete $aesFile and re-run -Phase keys."
    }
    gh secret set FIRMWARE_ENC_KEY --repo $Repo --body $aes
    if ($LASTEXITCODE -ne 0) { throw 'Failed to set FIRMWARE_ENC_KEY.' }
    Write-Ok 'Key material set (3 secrets)'

    # -- interactive secrets ------------------------------------------------
    # gh prompts and reads these itself, so no credential is ever held in a
    # PowerShell variable or written to the console history.
    Write-Info 'You will now be prompted for each remaining value.'
    Write-Info 'Input is hidden and is read directly by gh, not by this script.'

    $prompts = [ordered]@{
        'WIFI_SSID'       = 'WiFi network name the CI-built firmware should join'
        'WIFI_PASSWORD'   = 'WiFi password (blank is allowed for an open network)'
        'OTA_PASSWORD'    = 'ArduinoOTA push password'
        'BACKEND_URL'     = 'Gateway URL reachable BY THE DEVICE (never localhost)'
        'BACKEND_API_KEY' = 'Gateway API key (OTA_GATEWAY_API_KEY from .env.docker)'
        'DEVICE_ID'       = 'Device identity for telemetry, e.g. ESP32_DEVICE_001'
    }

    foreach ($name in $prompts.Keys) {
        Write-Host ''
        Write-Host "  $name" -ForegroundColor White
        Write-Host "    $($prompts[$name])" -ForegroundColor Gray
        gh secret set $name --repo $Repo
        if ($LASTEXITCODE -ne 0) { Write-Warn2 "Skipped or failed: $name" }
        else { Write-Ok "$name set" }
    }

    Write-Host ''
    Write-Info 'OTA_ROOT_CA is optional - only needed when BACKEND_URL is https.'
    Write-Info 'Set it later with: gh secret set OTA_ROOT_CA --repo <repo> < ca.pem'

    Write-Step 'Secrets now configured'
    gh secret list --repo $Repo
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host 'SecureOTA - scriptable setup tasks' -ForegroundColor White
Write-Host 'No administrator privileges required.' -ForegroundColor Gray

try {
    if ($Phase -eq 'all' -or $Phase -eq 'commit')  { Invoke-CommitPhase }
    if ($Phase -eq 'all' -or $Phase -eq 'keys')    { Invoke-KeysPhase }
    if ($Phase -eq 'all' -or $Phase -eq 'secrets') { Invoke-SecretsPhase }

    Write-Step 'Done'
    Write-Host @'
  Still outstanding, and NOT scriptable:

    - Stage 0 + 1: pin the Arduino core, then the rollback + health gate.
      Until that ships, a failed OTA bricks the device (USB reflash only).
    - The other verified defects in docs/architecture/GAP_ANALYSIS.md
    - Patent: prior-disclosure check, inventorship, institutional IP policy
    - The Ed25519 key and old admin password still in git history
      (commit 367720b). Removing them rewrites shared history - do it
      deliberately, not from this script.

  Do NOT push a version tag until the rollback fix is in: a tag triggers a
  real GitHub Release, and any device that takes that update has no way back.
'@ -ForegroundColor Gray
}
catch {
    Write-Host ''
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
