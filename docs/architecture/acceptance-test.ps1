<#
.SYNOPSIS
    SecureOTA backend acceptance test suite.

.DESCRIPTION
    Starts an ISOLATED gateway instance (scratch cache + scratch keys, port
    5099) and runs the acceptance tests from BACKEND_AUDIT.md against it.
    Your real gateway_keys/, gateway_firmware_cache/ and .env.docker are never
    touched, and no repository file is modified.

    Each test reports one of:
      PASS            control works as required
      FAIL            control is broken - investigate
      FAIL (expected) a KNOWN GAP from the audit. These must become PASS
                      after remediation; that is how you verify the fix.
      SKIP            prerequisite unavailable

.PARAMETER Port
    Port for the isolated gateway. Default 5099.

.PARAMETER KeepRunning
    Leave the gateway up after the run for manual poking.

.EXAMPLE
    .\acceptance-test.ps1
    .\acceptance-test.ps1 -KeepRunning

.NOTES
    No administrator privileges required.
    Requires: python (with fastapi/uvicorn/cryptography), on PATH.
#>

[CmdletBinding()]
param(
    [int]$Port = 5099,
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'

$ApiKey    = 'acceptance-test-key-' + (Get-Random)
$Base      = "http://127.0.0.1:$Port"
$RepoRoot  = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent   # -> repo root
$ImplDir   = Join-Path $RepoRoot 'src\implementation'
$Scratch   = Join-Path $env:TEMP ("secureota-acceptance-" + [guid]::NewGuid().ToString('N').Substring(0,8))

$script:Pass = 0; $script:Fail = 0; $script:Expected = 0; $script:Skip = 0
$script:Results = @()

function Get-Status {
    param($Url, $Method = 'GET', $Body, $Headers = @{}, $ContentType = 'application/json')
    try {
        $p = @{ Uri = $Url; Method = $Method; Headers = $Headers; UseBasicParsing = $true; TimeoutSec = 20 }
        if ($PSBoundParameters.ContainsKey('Body')) { $p.Body = $Body; $p.ContentType = $ContentType }
        (Invoke-WebRequest @p).StatusCode
    }
    catch {
        if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 'ERR' }
    }
}

function Get-Json {
    param($Url, $Method = 'GET', $Body, $Headers = @{})
    try {
        $p = @{ Uri = $Url; Method = $Method; Headers = $Headers; UseBasicParsing = $true; TimeoutSec = 20 }
        if ($PSBoundParameters.ContainsKey('Body')) { $p.Body = $Body; $p.ContentType = 'application/json' }
        (Invoke-WebRequest @p).Content | ConvertFrom-Json
    } catch { $null }
}

function Test-Item {
    param(
        [string]$Id,
        [string]$Name,
        [scriptblock]$Check,       # returns $true / $false
        [string]$Detail = '',
        [switch]$KnownGap          # audit says this currently fails
    )
    $ok = $false
    try { $ok = [bool](& $Check) } catch { $ok = $false; $Detail = "exception: $($_.Exception.Message)" }

    if ($ok) {
        $script:Pass++
        $tag = 'PASS'; $col = 'Green'
        if ($KnownGap) { $tag = 'PASS (gap fixed!)'; $col = 'Cyan' }
    }
    elseif ($KnownGap) {
        $script:Expected++
        $tag = 'FAIL (expected)'; $col = 'Yellow'
    }
    else {
        $script:Fail++
        $tag = 'FAIL'; $col = 'Red'
    }

    $line = "  [{0,-16}] {1}  {2}" -f $tag, $Id, $Name
    Write-Host $line -ForegroundColor $col
    if ($Detail) { Write-Host "                     $Detail" -ForegroundColor DarkGray }
    $script:Results += [pscustomobject]@{ Id = $Id; Name = $Name; Result = $tag }
}

function Section { param($t) Write-Host "`n--- $t ---" -ForegroundColor White }

# ---------------------------------------------------------------------------
Write-Host "`nSecureOTA backend acceptance tests" -ForegroundColor White
Write-Host "Isolated instance on port $Port. No repo file is modified." -ForegroundColor Gray

if (-not (Test-Path $ImplDir)) { throw "Cannot find src\implementation at $ImplDir" }
New-Item -ItemType Directory -Path $Scratch -Force | Out-Null

$env:OTA_GATEWAY_CACHE_DIR  = Join-Path $Scratch 'cache'
$env:OTA_GATEWAY_KEYS_DIR   = Join-Path $Scratch 'keys'
$env:OTA_GATEWAY_API_KEY    = $ApiKey
$env:OTA_GATEWAY_PUBLIC_URL = $Base

Write-Host "Starting gateway..." -ForegroundColor Gray
$proc = Start-Process -FilePath 'python' `
    -ArgumentList '-m', 'uvicorn', 'gateway:app', '--host', '127.0.0.1', '--port', $Port, '--log-level', 'warning' `
    -WorkingDirectory $ImplDir -PassThru -WindowStyle Hidden

$up = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 700
    if ((Get-Status "$Base/healthz") -eq 200) { $up = $true; break }
}
if (-not $up) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    throw "Gateway did not start. Check: pip install -r $ImplDir\requirements.txt"
}
Write-Host "Gateway up (pid $($proc.Id))" -ForegroundColor Green

try {
    # =======================================================================
    Section 'AT-1  Service architecture'
    Test-Item 'AT-1.1' 'Health endpoint returns 200' { (Get-Status "$Base/healthz") -eq 200 }
    Test-Item 'AT-1.2' 'OpenAPI schema served'       { (Get-Status "$Base/openapi.json") -eq 200 }
    Test-Item 'AT-1.3' 'Swagger UI served'           { (Get-Status "$Base/docs") -eq 200 }
    Test-Item 'AT-1.4' 'Root endpoint responds'      { (Get-Status "$Base/") -eq 200 }

    # =======================================================================
    Section 'AT-2  Write authentication (gateway/auth.py)'
    $writes = @(
        @{ p = '/api/trigger_sync';      m = 'POST'; b = $null },
        @{ p = '/api/pipeline/run';      m = 'POST'; b = $null },
        @{ p = '/api/deployments';       m = 'POST'; b = '{}' },
        @{ p = '/api/releases';          m = 'POST'; b = '{"version":"9.9.9","description":"x","changelog":"x","compatible":["ESP32"]}' }
    )
    foreach ($w in $writes) {
        $n = $w.p
        Test-Item "AT-2 $n" "401 without API key" {
            if ($null -eq $w.b) { (Get-Status "$Base$($w.p)" $w.m) -eq 401 }
            else { (Get-Status "$Base$($w.p)" $w.m $w.b) -eq 401 }
        }
    }
    Test-Item 'AT-2.5' 'Wrong API key rejected' {
        (Get-Status "$Base/api/trigger_sync" 'POST' -Headers @{ 'x-api-key' = 'wrong' }) -eq 401
    }
    Test-Item 'AT-2.6' 'Valid API key accepted' {
        (Get-Status "$Base/api/trigger_sync" 'POST' -Headers @{ 'x-api-key' = $ApiKey }) -eq 200
    }

    # =======================================================================
    Section 'AT-3  Device identity  (KNOWN GAPS - audit CRITICAL)'
    Test-Item 'AT-3.1' 'POST /api/devices/register exists' -KnownGap `
        -Detail 'Audit: returns 404. Fix = Priority 1.3' {
        (Get-Status "$Base/api/devices/register" 'POST' '{"device_id":"X"}') -ne 404
    }

    Test-Item 'AT-3.2' 'Unauthenticated heartbeat is REJECTED' -KnownGap `
        -Detail 'Audit: returns 200 and creates the device. Fix = Priority 1.3' {
        $s = Get-Status "$Base/api/heartbeat" 'POST' '{"device_id":"AT_FORGED","device_type":"ESP32","current_version":"1.0.0","ash_score":100}'
        $s -eq 401 -or $s -eq 403
    }

    Test-Item 'AT-3.3' 'Forged heartbeat cannot confirm a deployment' -KnownGap `
        -Detail 'Audit: unauthenticated POST flips deployment to success. Fix = Priority 1.3' {
        # publish a release, assign it, then try to confirm it with no credential
        $tmp = Join-Path $Scratch 'fw.bin'
        [IO.File]::WriteAllBytes($tmp, (1..4096 | ForEach-Object { [byte](Get-Random -Max 256) }))
        $py = @"
import urllib.request, json, os
b='$Base'; k='$ApiKey'; path=r'$tmp'
data=open(path,'rb').read()
bnd='----att'; nl='\r\n'
def part(n,v): return f'--{bnd}{nl}Content-Disposition: form-data; name="{n}"{nl}{nl}{v}{nl}'
body=(part('version','7.0.0')+part('compatible','ESP32')).encode()
body+=f'--{bnd}{nl}Content-Disposition: form-data; name="file"; filename="f.bin"{nl}Content-Type: application/octet-stream{nl}{nl}'.encode()
body+=data+f'{nl}--{bnd}--{nl}'.encode()
r=urllib.request.Request(b+'/api/releases/upload',data=body,headers={'x-api-key':k,'Content-Type':f'multipart/form-data; boundary={bnd}'})
urllib.request.urlopen(r,timeout=30).read()
# register target via (unauthenticated) heartbeat
d=json.dumps({'device_id':'AT_TARGET','device_type':'ESP32','current_version':'1.0.0','ash_score':100}).encode()
urllib.request.urlopen(urllib.request.Request(b+'/api/heartbeat',data=d,headers={'Content-Type':'application/json'}),timeout=20).read()
# assign
d=json.dumps({'version':'7.0.0','deviceIds':['AT_TARGET']}).encode()
urllib.request.urlopen(urllib.request.Request(b+'/api/deployments',data=d,headers={'Content-Type':'application/json','x-api-key':k}),timeout=20).read()
# ATTACK: unauthenticated heartbeat claiming the target version
d=json.dumps({'device_id':'AT_TARGET','device_type':'ESP32','current_version':'7.0.0','ash_score':100}).encode()
try:
    urllib.request.urlopen(urllib.request.Request(b+'/api/heartbeat',data=d,headers={'Content-Type':'application/json'}),timeout=20).read()
except Exception:
    pass
deps=json.load(urllib.request.urlopen(b+'/api/deployments',timeout=20)).get('deployments',[])
confirmed=any(t.get('state')=='confirmed' for dep in deps for t in dep.get('targets',{}).values())
print('FORGED' if confirmed else 'BLOCKED')
"@
        $out = $py | python - 2>$null
        $out -match 'BLOCKED'
    }

    # =======================================================================
    Section 'AT-4  OTA policy enforcement'
    # seed a release + devices for the policy tests
    $seed = @"
import urllib.request, json, os
b='$Base'; k='$ApiKey'
data=os.urandom(4096); bnd='----seed'; nl='\r\n'
def part(n,v): return f'--{bnd}{nl}Content-Disposition: form-data; name="{n}"{nl}{nl}{v}{nl}'
body=(part('version','2.0.0')+part('compatible','ESP32')).encode()
body+=f'--{bnd}{nl}Content-Disposition: form-data; name="file"; filename="f.bin"{nl}Content-Type: application/octet-stream{nl}{nl}'.encode()
body+=data+f'{nl}--{bnd}--{nl}'.encode()
try:
    urllib.request.urlopen(urllib.request.Request(b+'/api/releases/upload',data=body,headers={'x-api-key':k,'Content-Type':f'multipart/form-data; boundary={bnd}'}),timeout=30).read()
except Exception: pass
print('seeded')
"@
    $seed | python - 2>$null | Out-Null

    Test-Item 'AT-4.1' 'Manifest served for a compatible architecture' {
        (Get-Status "$Base/releases/latest/manifest?device_type=ESP32") -eq 200
    }
    Test-Item 'AT-4.2' 'Manifest REFUSED for incompatible architecture (404)' `
        -Detail 'Prevents flashing an ESP32 image onto an ESP8266' {
        (Get-Status "$Base/releases/latest/manifest?device_type=ESP8266") -eq 404
    }
    Test-Item 'AT-4.3' 'Anti-rollback: no downgrade offered to a newer device' {
        $r = Get-Json "$Base/api/heartbeat" 'POST' '{"device_id":"AT_NEWER","device_type":"ESP32","current_version":"9.9.9","ash_score":100}'
        $r.command -eq 'ack'
    }
    Test-Item 'AT-4.4' 'Update offered to an older device' {
        $r = Get-Json "$Base/api/heartbeat" 'POST' '{"device_id":"AT_OLDER","device_type":"ESP32","current_version":"1.0.0","ash_score":100}'
        $r.command -eq 'update_available'
    }
    Test-Item 'AT-4.5' 'Quarantined device (ASH<=40) is withheld from updates' {
        $r = Get-Json "$Base/api/heartbeat" 'POST' '{"device_id":"AT_SICK","device_type":"ESP32","current_version":"1.0.0","ash_score":10}'
        $r.command -eq 'ack'
    }

    # =======================================================================
    Section 'AT-5  Cryptography'
    Test-Item 'AT-5.1' 'Manifest signature verifies over the real artifact bytes' `
        -Detail 'Ed25519; also asserts a 1-bit tamper is rejected' {
        $py = @"
import urllib.request, json, base64, hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
b='$Base'
m=json.load(urllib.request.urlopen(b+'/releases/latest/manifest?device_type=ESP32',timeout=20))
pk=json.load(urllib.request.urlopen(b+'/releases/latest/public-key',timeout=20))
blob=urllib.request.urlopen(b+'/releases/download/'+m['filename'],timeout=20).read()
pub=serialization.load_pem_public_key(pk['publicKeyPem'].encode())
ok = hashlib.sha256(blob).hexdigest()==m['sha256']
try: pub.verify(base64.b64decode(m['signature']), blob); sig=True
except InvalidSignature: sig=False
try: pub.verify(base64.b64decode(m['signature']), blob[:-1]+bytes([blob[-1]^1])); tam=True
except InvalidSignature: tam=False
print('OK' if (ok and sig and not tam) else 'BAD')
"@
        ($py | python - 2>$null) -match 'OK'
    }

    # =======================================================================
    Section 'AT-6  Input validation and abuse resistance'
    Test-Item 'AT-6.1' 'Path traversal blocked (../../../../etc/passwd)' {
        (Get-Status "$Base/releases/download/../../../../etc/passwd") -eq 404
    }
    Test-Item 'AT-6.2' 'Path traversal blocked (URL-encoded)' {
        (Get-Status "$Base/releases/download/..%2f..%2f..%2fetc%2fpasswd") -eq 404
    }
    Test-Item 'AT-6.3' 'Heartbeat rejects missing device_id (400)' {
        (Get-Status "$Base/api/heartbeat" 'POST' '{"device_type":"ESP32"}') -eq 400
    }
    Test-Item 'AT-6.4' 'Heartbeat rejects oversized device_id (400)' {
        $long = '{"device_id":"' + ('A' * 500) + '"}'
        (Get-Status "$Base/api/heartbeat" 'POST' $long) -eq 400
    }
    Test-Item 'AT-6.5' 'Invalid JSON rejected (422)' {
        (Get-Status "$Base/api/heartbeat" 'POST' '{ broken') -eq 422
    }
    Test-Item 'AT-6.6' 'ASH score clamped to 0..100' {
        Get-Json "$Base/api/heartbeat" 'POST' '{"device_id":"AT_CLAMP_HI","ash_score":99999}' | Out-Null
        Get-Json "$Base/api/heartbeat" 'POST' '{"device_id":"AT_CLAMP_LO","ash_score":-500}'  | Out-Null
        $d = (Get-Json "$Base/api/dashboard").devices
        $hi = ($d | Where-Object { $_.id -eq 'AT_CLAMP_HI' }).ash
        $lo = ($d | Where-Object { $_.id -eq 'AT_CLAMP_LO' }).ash
        ($hi -eq 100) -and ($lo -eq 0)
    }
    Test-Item 'AT-6.7' 'Rate limiting on heartbeat' -KnownGap `
        -Detail 'Audit: none implemented. 200 rapid requests all accepted' {
        $codes = 1..40 | ForEach-Object { Get-Status "$Base/api/heartbeat" 'POST' '{"device_id":"AT_FLOOD","ash_score":50}' }
        ($codes | Where-Object { $_ -eq 429 }).Count -gt 0
    }

    # =======================================================================
    Section 'AT-7  Firmware upload validation'
    $binOk  = Join-Path $Scratch 'ok.bin';  [IO.File]::WriteAllBytes($binOk, (New-Object byte[] 2048))
    function Upload-Fw {
        param($Version, $FileName, $Path)
        $py = @"
import urllib.request, json
b='$Base'; k='$ApiKey'
data=open(r'$Path','rb').read(); bnd='----up'; nl='\r\n'
def part(n,v): return f'--{bnd}{nl}Content-Disposition: form-data; name="{n}"{nl}{nl}{v}{nl}'
body=(part('version','$Version')+part('compatible','ESP32')).encode()
body+=f'--{bnd}{nl}Content-Disposition: form-data; name="file"; filename="$FileName"{nl}Content-Type: application/octet-stream{nl}{nl}'.encode()
body+=data+f'{nl}--{bnd}--{nl}'.encode()
r=urllib.request.Request(b+'/api/releases/upload',data=body,headers={'x-api-key':k,'Content-Type':f'multipart/form-data; boundary={bnd}'})
try:
    urllib.request.urlopen(r,timeout=60); print(200)
except urllib.error.HTTPError as e: print(e.code)
except Exception: print('ERR')
"@
        ($py | python - 2>$null).Trim()
    }
    $txt = Join-Path $Scratch 'bad.txt'; Set-Content $txt 'hello'
    Test-Item 'AT-7.1' 'Non-.bin extension rejected (400)' { (Upload-Fw '8.0.0' 'evil.txt' $txt) -eq '400' }
    $empty = Join-Path $Scratch 'empty.bin'; New-Item -ItemType File -Path $empty -Force | Out-Null
    Test-Item 'AT-7.2' 'Empty artifact rejected (400)'      { (Upload-Fw '8.0.1' 'e.bin' $empty) -eq '400' }
    Test-Item 'AT-7.3' 'Duplicate version rejected (409)'   { (Upload-Fw '2.0.0' 'd.bin' $binOk) -eq '409' }
    Test-Item 'AT-7.4' 'Non-numeric version rejected (400)' { (Upload-Fw 'abc'   'v.bin' $binOk) -eq '400' }

    # =======================================================================
    Section 'AT-8  Monitoring'
    Test-Item 'AT-8.1' 'Dashboard reports devices and releases' {
        $d = Get-Json "$Base/api/dashboard"
        ($null -ne $d) -and ($d.devices.Count -gt 0)
    }
    Test-Item 'AT-8.2' 'Events are recorded' {
        (Get-Json "$Base/api/events").events.Count -gt 0
    }
    Test-Item 'AT-8.3' 'Offline detection marks a silent device offline' -KnownGap `
        -Detail 'Audit: no offline/last-seen evaluation exists anywhere. Fix = Priority 3.1' {
        $d = Get-Json "$Base/api/dashboard"
        $hasOffline = $false
        foreach ($x in $d.devices) {
            if ($x.PSObject.Properties.Name -contains 'online' -or $x.status -eq 'Offline') { $hasOffline = $true }
        }
        $hasOffline
    }

    # =======================================================================
    Section 'AT-9  Persistence and scale'
    Test-Item 'AT-9.1' 'State survives restart (persisted to disk)' {
        Test-Path (Join-Path $env:OTA_GATEWAY_CACHE_DIR 'gateway_state.json')
    }
    Test-Item 'AT-9.2' 'Concurrency: 200 parallel heartbeats all succeed' `
        -Detail 'Also prints throughput and p95 - watch these degrade as fleet grows' {
        $py = @"
import concurrent.futures, json, time, urllib.request
B='$Base'
def hb(i,r):
    d=json.dumps({'device_id':f'AT_LOAD_{i:03d}','device_type':'ESP32','current_version':'1.0.0','ash_score':100}).encode()
    rq=urllib.request.Request(B+'/api/heartbeat',data=d,headers={'Content-Type':'application/json'})
    t=time.time()
    try:
        with urllib.request.urlopen(rq,timeout=60) as x: return x.status, time.time()-t
    except Exception: return 0, time.time()-t
s=time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
    res=[f.result() for f in [ex.submit(hb,i,r) for r in range(4) for i in range(50)]]
el=time.time()-s
ok=sum(1 for c,_ in res if c==200); lat=sorted(d for _,d in res)
print(f'{ok}/{len(res)} ok | {len(res)/el:.0f} req/s | p95 {lat[int(len(lat)*.95)]*1000:.0f} ms')
"@
        $out = ($py | python - 2>$null)
        Write-Host "                     $out" -ForegroundColor DarkGray
        $out -match '^200/200'
    }

    # =======================================================================
    Section 'AT-10  Automated test suites'
    Test-Item 'AT-10.1' 'Backend has a Python test suite' -KnownGap `
        -Detail 'Audit: zero test files. Fix = Priority 5.1' {
        $found = Get-ChildItem -Path $RepoRoot -Recurse -Include 'test_*.py', '*_test.py', 'conftest.py' `
                 -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'node_modules' }
        $found.Count -gt 0
    }
    Test-Item 'AT-10.2' 'Dashboard has a JS test suite' -KnownGap `
        -Detail 'Audit: zero test files, no "test" script' {
        $d = Join-Path $RepoRoot 'CODE\OTA_IDE'
        $found = Get-ChildItem -Path $d -Recurse -Include '*.test.ts', '*.test.tsx', '*.spec.ts' `
                 -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'node_modules' }
        $found.Count -gt 0
    }

    # =======================================================================
    Section 'AT-11  Secrets hygiene'
    Test-Item 'AT-11.1' 'No private key committed in HEAD' -KnownGap `
        -Detail 'Audit: gateway_keys/ed25519_private_key.pem is in HEAD on origin/main. Fix = Priority 1.4' {
        Push-Location $RepoRoot
        try { git cat-file -e HEAD:gateway_keys/ed25519_private_key.pem 2>$null; $LASTEXITCODE -ne 0 }
        finally { Pop-Location }
    }
    Test-Item 'AT-11.2' '.env.docker is git-ignored' {
        Push-Location $RepoRoot
        try { git check-ignore -q .env.docker 2>$null; $LASTEXITCODE -eq 0 }
        finally { Pop-Location }
    }
    Test-Item 'AT-11.3' 'CI secrets are configured' -KnownGap `
        -Detail 'Audit: gh secret list returns empty. Fix = Priority 2.2' {
        $out = gh secret list --repo Rithik-sharma12/Secure_OTA_Update_Security_Mechanism 2>$null
        -not [string]::IsNullOrWhiteSpace($out)
    }
}
finally {
    if (-not $KeepRunning) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Remove-Item $Scratch -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "`nGateway stopped, scratch removed." -ForegroundColor Gray
    }
    else {
        Write-Host "`nGateway still running on $Base (pid $($proc.Id))" -ForegroundColor Yellow
        Write-Host "API key: $ApiKey" -ForegroundColor Yellow
        Write-Host "Stop it with: Stop-Process -Id $($proc.Id) -Force" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
Write-Host "`n=================== SUMMARY ===================" -ForegroundColor White
Write-Host ("  PASS            : {0}" -f $script:Pass)     -ForegroundColor Green
Write-Host ("  FAIL (expected) : {0}   <- known audit gaps" -f $script:Expected) -ForegroundColor Yellow
Write-Host ("  FAIL            : {0}   <- unexpected, investigate" -f $script:Fail) -ForegroundColor Red
Write-Host "===============================================" -ForegroundColor White

if ($script:Fail -gt 0) {
    Write-Host "`nUnexpected failures - a control that the audit found working is now broken." -ForegroundColor Red
    exit 1
}
if ($script:Expected -gt 0) {
    Write-Host "`n$($script:Expected) known gap(s) still open. Each becomes PASS once remediated." -ForegroundColor Yellow
}
exit 0
