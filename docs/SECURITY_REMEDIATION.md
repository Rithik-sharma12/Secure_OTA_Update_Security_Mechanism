# Security Remediation — credential material in git history

This file records secrets that reached this repository's history and what has
to be done about each one. Removing a file from the working tree does not
remove it from history: every one of the items below is still recoverable by
anyone who can clone the repository, including from forks and from clones taken
before the cleanup.

> **The short version:** untracking is not rotation. Every credential listed
> here must be replaced, not just deleted.

## 1. Gateway Ed25519 firmware signing key — CRITICAL

- **File:** `gateway_keys/ed25519_private_key.pem`
- **Added in:** `367720b` (2026-04-09)
- **Untracked in:** `ef14b2b` ("security: untrack Ed25519 signing keypair and rotate")
- **Still recoverable:** yes

`git show 367720b:gateway_keys/ed25519_private_key.pem` prints the private key
today. `ef14b2b` removed it from the working tree but the blob is still in
history, so the rotation that commit message describes is not complete.

This key signs release manifests. Anyone holding it can produce a manifest the
dashboard presents as authentically signed.

**Required:**

1. Generate a new keypair. The gateway does this automatically when
   `gateway_keys/` is empty on boot, so deleting the volume contents and
   restarting is enough.
2. Confirm the new fingerprint in the key vault page differs from
   `sha256(old public key)`.
3. Purge the blob from history (see §5), then force-push and have every
   collaborator re-clone.

## 2. Gateway API key — CRITICAL

- **Value:** `sentinel_ota_secure_gateway_key_2026`
- **Where:** `docker-compose.yml` (both services) as a `:-` default, and
  `docs/guides/WEB_OTA_UPDATE_GUIDE.md` as a copy-paste example

Every deployment that did not set `OTA_GATEWAY_API_KEY` used this exact key. It
guards all gateway write endpoints — including firmware publishing.

**Required:**

1. Generate a replacement: `openssl rand -hex 32`.
2. Set `OTA_GATEWAY_API_KEY` in `.env`. Compose now fails to start without it.
3. Reflash every device's `BACKEND_API_KEY`, since devices present this key on
   heartbeat and download. Devices cannot be updated over the air to a new key
   without first authenticating with the old one, so plan the rollout before
   rotating.

## 3. Dashboard admin password — HIGH

- **Value:** `SentinelSecure_2026!#`
- **Where:** `CODE/OTA_IDE/lib/auth.ts`, as the `OTA_ADMIN_PASSWORD` fallback

Any dashboard started without `OTA_ADMIN_PASSWORD` bootstrapped its admin
account with this password. The fallback is gone and the value is now on the
rejected-passwords list, so it cannot be re-used even deliberately.

**Required:** set `OTA_ADMIN_PASSWORD` (12+ characters), and change the
password on any already-bootstrapped instance — the existing account keeps the
old hash, because bootstrap only runs once.

## 4. Local NeDB stores — MEDIUM

- **Files:** `.data/*.db`, `CODE/OTA_IDE/.data/*.db`,
  `CODE/OTA_IDE/.local-db-smoke*/`, `CODE/OTA_IDE/.local-db-temp-session/`
- **Added in:** `367720b`, `c463990`

`users.db` holds scrypt password hashes; `sessions.db` holds live session token
hashes. These appear to be development fixtures rather than production data,
but they are real hashes and should be treated as compromised.

Session tokens are stored hashed and each record carries an `expiresAt` well in
the past, so the practical exposure is offline cracking of the password hashes
rather than session replay. scrypt with a per-user salt makes that expensive
against a strong password and cheap against a weak one.

**Required:** rotate any password that was ever used on a real instance. These
paths are now in `.gitignore`.

## 5. Purging history

Rotation above is what actually restores security; purging is cleanup so the
old values stop being handed out with every clone. Do it after rotating, never
instead.

```bash
# git-filter-repo is the supported tool; git filter-branch is deprecated.
pip install git-filter-repo

# Work on a fresh mirror, never on a clone with local work in it.
git clone --mirror https://github.com/<owner>/Secure_OTA_Update_Security_Mechanism.git
cd Secure_OTA_Update_Security_Mechanism.git

git filter-repo \
  --path gateway_keys/ed25519_private_key.pem \
  --path-glob '*.db' \
  --invert-paths

git push --force --mirror
```

Then:

- Every collaborator re-clones. Old clones still contain the secrets, and
  pushing from one can reintroduce the blobs.
- Forks keep their own history. GitHub does not rewrite forks, so a fork made
  before the purge still exposes everything. Ask GitHub Support to expire the
  cached views if the repository is public.
- Rotate first regardless. A published key is compromised from the moment it
  was pushed, not from the moment someone is seen using it.

## 6. What is now enforced in code

| Control | Where |
| --- | --- |
| Gateway refuses to start with no API key unless `OTA_GATEWAY_ALLOW_OPEN_WRITES` | `gateway/config.py` |
| API key compared with `hmac.compare_digest` | `gateway/auth.py` |
| CORS origins explicit; credentials off when wildcard | `gateway/config.py`, `gateway/__init__.py` |
| Compose fails fast without `OTA_GATEWAY_API_KEY` | `docker-compose*.yml` |
| Admin password has no default and rejects the leaked one | `CODE/OTA_IDE/lib/auth.ts` |
| Local DB stores ignored | `.gitignore` |
| Firmware never falls back to unverified flashing | `esp32_ota_main.ino` |
| Firmware refuses https:// without a pinned root | `esp32_ota_main.ino` |
| Firmware binds each flash to the manifest `sha256` | `esp32_ota_main.ino` |
