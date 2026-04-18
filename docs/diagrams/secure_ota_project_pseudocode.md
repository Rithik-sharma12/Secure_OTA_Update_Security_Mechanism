# Secure_OTA Project Pseudocode

This pseudocode models the implemented project workflow across:
- Control Plane (OTA_IDE)
- Gateway Plane (FastAPI)
- Device Plane (Firmware OTA runtime)

It includes the main control flow, yes/no branches, state updates, and operation side effects.

## 1. Shared Constants and Models

```text
CONSTANT ASH_THRESHOLD_QUARANTINE = 40
CONSTANT ASH_MAX = 100
CONSTANT SESSION_TTL_HOURS = ENV.OTA_SESSION_TTL_HOURS OR 24
CONSTANT CHECK_INTERVAL_MS = 15 minutes
CONSTANT HEARTBEAT_INTERVAL_MS = 15 seconds

TYPE User:
  id, username, role, isActive, passwordHash, lastLoginAt

TYPE Session:
  tokenHash, userId, expiresAt, revoked

TYPE Release:
  id, version, description, changelog, assets[], compatible[], status, downloadCount

TYPE Manifest:
  version, filename, sha256, size, signature, signatureAlgorithm, signatureKeyId, generated_at, url

TYPE DeviceState:
  id, arch, fw, ash, status, last_seen, logs[], cpuUsage, memoryUsage, uptime, signalStrength

TYPE Deployment:
  id, releaseId, deviceIds[], status, successCount, failureCount, logs
```

## 2. Control Plane Pseudocode (OTA_IDE)

```text
FUNCTION LOGIN(username, password):
  ENSURE_DEFAULT_ADMIN_USER_EXISTS()

  IF username is empty OR password is empty:
    RETURN HTTP 401

  user = DB.users.findOne(username)

  IF user does not exist OR user.isActive == false:
    RETURN HTTP 401

  IF VERIFY_SCRYPT_PASSWORD(password, user.passwordHash) == false:
    RETURN HTTP 401

  sessionToken = RANDOM_HEX(32 bytes)
  tokenHash = SHA256(sessionToken)
  expiresAt = NOW + SESSION_TTL_HOURS

  DB.sessions.insert(tokenHash, user.id, expiresAt, revoked=false)
  DB.users.update(user.id, lastLoginAt=NOW)

  SET_HTTPONLY_COOKIE(name="ota_session_token", value=sessionToken, expires=expiresAt)
  RETURN HTTP 200 with sanitized user


FUNCTION AUTHENTICATE_REQUEST(request):
  token = READ_COOKIE("ota_session_token")

  IF token is empty:
    token = READ_BEARER_TOKEN(request)

  IF token is empty:
    RETURN null

  tokenHash = SHA256(token)
  session = DB.sessions.findOne(tokenHash, revoked=false)

  IF session is null:
    RETURN null

  IF session.expiresAt <= NOW:
    DB.sessions.update(session.id, revoked=true)
    RETURN null

  user = DB.users.findOne(session.userId, isActive=true)

  IF user is null:
    RETURN null

  RETURN AuthContext(user, session, tokenHash)


FUNCTION WITH_SECURE_API(request, routeName, handler, requireAuth):
  START_TIMER()
  statusCode = 500
  userId = null
  errorMessage = null

  TRY:
    INIT_LOCAL_DB()
    ENSURE_DEFAULT_ADMIN_USER_EXISTS()

    auth = null
    IF requireAuth == true:
      auth = AUTHENTICATE_REQUEST(request)
      IF auth is null:
        statusCode = 401
        RETURN HTTP 401
      userId = auth.user.id

    response = handler(auth)
    statusCode = response.status
    RETURN response

  CATCH error:
    errorMessage = error.message
    statusCode = 500
    RETURN HTTP 500

  FINALLY:
    durationMs = STOP_TIMER()
    DB.apiLogs.insert(routeName, request.method, statusCode, durationMs, userId, errorMessage)


FUNCTION OTA_IDE_RUNTIME_SNAPSHOT(request):
  auth = AUTHENTICATE_REQUEST(request)
  IF auth is null:
    RETURN HTTP 401

  dashboard = TRY_FETCH_JSON(GATEWAY_URL + "/api/dashboard")
  manifest = TRY_FETCH_JSON(GATEWAY_URL + "/releases/latest/manifest")

  devices = NORMALIZE_DEVICES(dashboard.devices)
  events = NORMALIZE_EVENTS(dashboard.events, dashboard.alerts, devices)
  releases = NORMALIZE_RELEASES(dashboard.releases, manifest)
  pipeline = NORMALIZE_PIPELINE(dashboard.pipeline)
  deployments = NORMALIZE_DEPLOYMENTS(dashboard.deployments)

  reachable = (dashboard != null OR manifest != null)
  ok = (dashboard != null AND manifest != null)

  RETURN HTTP 200 with {ok, reachable, devices, events, releases, manifest, pipeline, deployments}


FUNCTION OTA_IDE_CREATE_RELEASE(requestPayload):
  // Triggered from release UI/runtime actions
  // Gateway validates version/artifact and signs payload
  response = HTTP_POST(GATEWAY_URL + "/api/releases", requestPayload, apiKeyIfConfigured)
  RETURN response


FUNCTION OTA_IDE_START_SERIAL_UPLOAD(payload, authUserId):
  VALIDATE payload.filePath, payload.boardType, payload.comPort, payload.baudRate

  IF file extension != ".ino":
    RETURN HTTP 400

  IF COM port format invalid:
    RETURN HTTP 400

  jobId = NEW_UUID()
  INSERT_UPLOAD_JOB(jobId, payload, authUserId, status="queued", progress=0)

  ASYNC RUN:
    SET job.status = "compiling"
    RUN "arduino-cli compile --fqbn <fqbn> <sketchDir>"

    IF compile failed:
      SET job.status = "failed"
      APPEND_UPLOAD_LOG(error)
      EXIT

    SET job.status = "uploading"
    RUN "arduino-cli upload --fqbn <fqbn> --port <COMx> <sketchDir>"

    IF upload failed:
      SET job.status = "failed"
      APPEND_UPLOAD_LOG(error)
      EXIT

    SET job.status = "success"
    SET job.progress = 100

  RETURN HTTP 200 with {jobId, status, progress}
```

## 3. Gateway Plane Pseudocode (FastAPI)

```text
FUNCTION REQUIRE_WRITE_AUTH(request):
  IF ENV.OTA_GATEWAY_API_KEY is empty:
    RETURN allow

  provided = request.query.api_key OR request.header.x-api-key OR request.bearerToken

  IF provided != ENV.OTA_GATEWAY_API_KEY:
    RETURN HTTP 401

  RETURN allow


FUNCTION NORMALIZE_VERSION(versionText):
  candidate = TRIM(versionText).removePrefix("v")

  IF candidate empty:
    RAISE ValueError("Version cannot be empty")

  IF candidate is not dot-separated numeric:
    RAISE ValueError("Version format invalid")

  RETURN candidate


FUNCTION CREATE_RELEASE(payload):
  REQUIRE_WRITE_AUTH()

  version = NORMALIZE_VERSION(payload.version)

  IF version already exists in STATE.releases:
    RETURN HTTP 409

  artifactPath = RESOLVE_ARTIFACT_PATH(payload.sourceFilePath OR ENV.OTA_GATEWAY_RELEASE_ARTIFACT)

  IF artifactPath not found OR extension != ".bin":
    RETURN HTTP 400

  artifactBytes = READ_BYTES(artifactPath)

  IF artifactBytes length == 0:
    RETURN HTTP 400

  filename = "firmware_v" + version + ".bin"
  cachePath = GATEWAY_CACHE_DIR / filename
  WRITE_BYTES(cachePath, artifactBytes)

  checksum = SHA256(artifactBytes)
  signature = ED25519_SIGN(artifactBytes, privateKey)

  release = BUILD_RELEASE_RECORD(version, payload, filename, checksum)
  manifest = BUILD_MANIFEST_RECORD(version, filename, checksum, signature)
  pipeline = BUILD_PIPELINE(release.id)

  STATE.releases.prepend(release)
  STATE.manifest = manifest
  STATE.pipeline = pipeline
  PUSH_EVENT("deployment", "success", "Release Published", ...)

  WRITE_JSON(MANIFEST_FILE, manifest)
  WRITE_JSON(STATE_FILE, STATE)

  RETURN HTTP 200 with {release, manifest, pipeline}


FUNCTION GET_MANIFEST():
  IF MANIFEST_FILE exists:
    RETURN FILE_RESPONSE(MANIFEST_FILE)

  IF STATE.manifest exists:
    WRITE_JSON(MANIFEST_FILE, STATE.manifest)
    RETURN HTTP 200 with STATE.manifest

  RETURN HTTP 404


FUNCTION DOWNLOAD_FIRMWARE(filename):
  safePath = SAFE_CACHE_PATH(filename)

  IF safePath invalid:
    RETURN HTTP 400

  IF safePath does not exist:
    RETURN HTTP 404

  INCREMENT release.downloadCount for matching asset
  WRITE_JSON(STATE_FILE, STATE)

  RETURN FILE_RESPONSE(safePath)


FUNCTION RECEIVE_HEARTBEAT(payload):
  IF payload.device_id missing OR too long:
    RETURN HTTP 400

  ash = CLAMP(payload.ash_score, 0, 100)
  deviceType = NORMALIZE_DEVICE_TYPE(payload.device_type)

  previous = STATE.devices[payload.device_id]
  previousAsh = previous.ash OR 100

  IF previous does not exist:
    PUSH_EVENT("info", "success", "New Device Registered", ...)

  IF previousAsh > 40 AND ash <= 40:
    PUSH_ALERT("CRITICAL: device entered quarantine")
    PUSH_EVENT("security", "error", "Device Quarantine Triggered", ...)

  STATE.devices[payload.device_id] = NORMALIZED_DEVICE_RECORD(payload, deviceType, ash)
  WRITE_JSON(STATE_FILE, STATE)

  latestVersion = STATE.manifest.version OR "0.0.0"

  IF latestVersion != payload.current_version AND ash > 40:
    command = "update_available"
  ELSE:
    command = "ack"

  RETURN HTTP 200 with {command, latest_version=latestVersion}


FUNCTION CREATE_DEPLOYMENT(payload):
  REQUIRE_WRITE_AUTH()

  IF STATE.releases is empty:
    RETURN HTTP 404

  selectedRelease = payload.releaseId ? FIND_RELEASE(payload.releaseId) : STATE.releases[0]

  IF selectedRelease not found:
    RETURN HTTP 404

  targetDeviceIds = payload.deviceIds OR ALL_DEVICE_IDS()

  IF targetDeviceIds is empty:
    RETURN HTTP 400

  successCount = 0
  failureCount = 0
  logs = []

  FOR each deviceId in targetDeviceIds:
    device = STATE.devices[deviceId]

    IF device missing:
      failureCount += 1
      logs.add("device not found")
      CONTINUE

    IF device.ash <= ASH_THRESHOLD_QUARANTINE:
      failureCount += 1
      device.status = "Quarantined"
      PUSH_EVENT("security", "error", "Deployment Blocked by ASH Policy", deviceId)
      logs.add("blocked by ASH policy")
      CONTINUE

    successCount += 1
    device.fw = selectedRelease.version
    device.status = "Healthy"
    logs.add("updated successfully")
    PUSH_EVENT("firmware_update", "success", "Device Updated", deviceId)

  deploymentStatus = COMPUTE_DEPLOYMENT_STATUS(successCount, failureCount)
  deployment = BUILD_DEPLOYMENT_RECORD(selectedRelease.id, targetDeviceIds, deploymentStatus, logs)

  STATE.deployments.prepend(deployment)
  WRITE_JSON(STATE_FILE, STATE)

  RETURN HTTP 200 with deployment
```

## 4. Firmware Plane Pseudocode (Device Runtime)

```text
GLOBAL state:
  healthScore = 100
  inQuarantine = false
  failedAttempts24h = 0
  lastBackendCheck = 0
  lastHeartbeat = 0


FUNCTION SETUP():
  INIT_SERIAL()
  LOAD_HEALTH_FROM_NVS()
  CONNECT_WIFI()
  SETUP_ARDUINO_OTA()

  IF inQuarantine == true:
    LOG("Device in quarantine; recovery mode")


FUNCTION LOOP():
  HANDLE_ARDUINO_OTA()

  IF BUTTON_HELD(3000ms) == true:
    CHECK_BACKEND_OTA()

  now = MILLIS()

  IF now - lastBackendCheck >= CHECK_INTERVAL_MS:
    lastBackendCheck = now

    IF inQuarantine == true:
      LOG("Skip backend check: quarantined")
    ELSE:
      CHECK_BACKEND_OTA()

  IF now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS:
    lastHeartbeat = now
    ADJUST_HEALTH(+1, "poll success")
    SEND_HEARTBEAT()


FUNCTION CHECK_BACKEND_OTA():
  manifest = FETCH_LATEST_RELEASE()

  IF manifest fetch failed:
    ADJUST_HEALTH(-1, "network error")
    RETURN

  remoteVerN = PARSE_VERSION(manifest.version)
  currentVerN = PARSE_VERSION(FIRMWARE_VERSION)

  IF remoteVerN == currentVerN:
    ADJUST_HEALTH(+1, "poll success")
    RETURN

  IF remoteVerN < currentVerN:
    LOG("Anti-rollback blocked")
    RETURN

  success = PERFORM_HTTP_UPDATE(manifest.downloadUrl)

  IF success == true:
    ADJUST_HEALTH(+10, "update success")
    REBOOT_DEVICE()
  ELSE:
    failedAttempts24h += 1
    ADJUST_HEALTH(-25, "update failed")


FUNCTION PERFORM_HTTP_UPDATE(url):
  IF IS_SECURE_OTA_CONFIGURED() == true:
    success = PERFORM_SECURE_PACKAGE_UPDATE(url)

    IF success == true:
      RETURN true

    LOG("Secure path failed; trying plain fallback")

  RETURN PERFORM_PLAIN_PACKAGE_UPDATE(url)


FUNCTION PERFORM_SECURE_PACKAGE_UPDATE(url):
  response = HTTP_GET(url)

  IF response status != 200:
    RETURN false

  IF contentLength <= (IV_BYTES + SIGNATURE_BYTES):
    RETURN false

  READ header: IV(16 bytes), SIGNATURE(256 bytes)

  INIT AES-256-CBC decrypt context with FIRMWARE_ENC_KEY
  INIT SHA-256 hash context
  INIT public key context with FIRMWARE_PUB_KEY

  BEGIN Update.begin(encryptedPayloadSize)

  FOR each encrypted block:
    decryptedBlock = AES_CBC_DECRYPT(block)

    IF last block:
      VALIDATE_PKCS7_PADDING(decryptedBlock)
      bytesToWrite = blockSize - padding
    ELSE:
      bytesToWrite = blockSize

    UPDATE_SHA256(decryptedBlock[0:bytesToWrite])
    WRITE_FLASH(decryptedBlock[0:bytesToWrite])

    IF write failed:
      Update.abort()
      RETURN false

  digest = FINALIZE_SHA256()

  IF VERIFY_SIGNATURE(publicKey, digest, SIGNATURE) == false:
    Update.abort()
    RETURN false

  IF Update.end(true) == false:
    Update.abort()
    RETURN false

  RETURN true


FUNCTION PERFORM_PLAIN_PACKAGE_UPDATE(url):
  response = HTTP_GET(url)

  IF response status != 200:
    RETURN false

  IF content length known:
    BEGIN Update.begin(contentLength)
  ELSE:
    BEGIN Update.begin(UPDATE_SIZE_UNKNOWN)

  bytesWritten = Update.writeStream(response.stream)

  IF bytesWritten == 0:
    Update.abort()
    RETURN false

  IF content length known AND bytesWritten != contentLength:
    Update.abort()
    RETURN false

  IF Update.end(true) == false:
    Update.abort()
    RETURN false

  RETURN true


FUNCTION ADJUST_HEALTH(delta, reason):
  previous = healthScore
  healthScore = CLAMP(healthScore + delta, 0, ASH_MAX)
  SAVE_HEALTH_TO_NVS(healthScore, inQuarantine, failedAttempts24h)

  IF healthScore < ASH_THRESHOLD_QUARANTINE AND inQuarantine == false:
    inQuarantine = true
    SAVE_HEALTH_TO_NVS(...)
    LOG("Quarantine enabled")

  IF inQuarantine == true AND healthScore >= ASH_MAX:
    inQuarantine = false
    SAVE_HEALTH_TO_NVS(...)
    LOG("Quarantine lifted")
    SETUP_ARDUINO_OTA()


FUNCTION SEND_HEARTBEAT():
  IF WIFI_CONNECTED() == false:
    RETURN

  payload = {
    device_id,
    device_type,
    current_version,
    ash_score = healthScore,
    status = inQuarantine ? "Quarantined" : "Healthy",
    memoryUsage,
    uptime,
    location,
    signalStrength,
    logs[]
  }

  HTTP_POST(GATEWAY_URL + "/api/heartbeat", payload)
```

## 5. End-to-End Scenario Pseudocode

```text
PROCEDURE SECURE_OTA_RELEASE_TO_RUNTIME_FLOW(operatorInput):
  // Step 1: Authenticate
  loginResult = LOGIN(operatorInput.username, operatorInput.password)
  IF loginResult.status != 200:
    STOP("Authentication failed")

  // Step 2: Create release at gateway
  releaseResult = OTA_IDE_CREATE_RELEASE(operatorInput.releasePayload)

  IF releaseResult.status == 401:
    STOP("Gateway API key invalid or missing")
  IF releaseResult.status == 400:
    STOP("Release payload invalid")
  IF releaseResult.status == 409:
    STOP("Release version already exists")
  IF releaseResult.status != 200:
    STOP("Unknown release error")

  // Step 3: Device periodic cycle
  LOOP forever:
    CHECK_BACKEND_OTA()
    SEND_HEARTBEAT()

    // Runtime monitoring snapshot for UI
    snapshot = OTA_IDE_RUNTIME_SNAPSHOT(currentRequest)

    IF snapshot.reachable == false:
      LOG("Gateway currently unreachable")
    ELSE IF snapshot.ok == false:
      LOG("Partial gateway data; degraded mode")
    ELSE:
      LOG("Fleet telemetry healthy")
```

## 6. Path Coverage Checklist (Pseudocode Validation)

```text
[ ] Login success path
[ ] Login failure path
[ ] Session success path
[ ] Session expired/revoked path
[ ] Release create success path
[ ] Release duplicate path
[ ] Release invalid artifact path
[ ] Gateway auth required + invalid key path
[ ] Manifest available path
[ ] Manifest unavailable path
[ ] Device up-to-date path
[ ] Anti-rollback block path
[ ] Quarantine block path
[ ] Secure update success path
[ ] Secure update fail -> plain fallback success path
[ ] Secure update fail -> plain fallback fail path
[ ] Heartbeat valid payload path
[ ] Heartbeat invalid payload path
[ ] Deployment policy allow path
[ ] Deployment policy block path
[ ] Snapshot full-ok path
[ ] Snapshot partial/degraded path
```

This pseudocode can be used as the baseline for implementation review, test-case generation, and viva/presentation walkthroughs.
