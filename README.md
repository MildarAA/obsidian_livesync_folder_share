This code is extremly vibecoded. use at own risk!

# obsidian_livesync_folder_share

This project synchronises one subtree between two CouchDB databases used by Obsidian LiveSync.

Default target:
- subtree: `/share`
- database A: from `DB_MAIN` (default: `main_db`)
- database B: from `DB_CLIENT` (default: `client_db`)

The sync is bidirectional and supports:
- single-run mode
- continuous mode with checkpoints
- dry-run mode
- Docker secrets for credentials and passphrase

## Important behaviour notes

1. LiveSync data model is metadata + chunks. This script copies selected metadata documents and their referenced chunks.
2. Metadata deletions are propagated as soft deletes (`deleted: true`) first.
3. Metadata conflict policy is bidirectional with an exception: in `DB_MAIN -> DB_CLIENT`, main metadata state is authoritative.
4. Chunk GC uses two phases: soft-delete tombstones first, then hard-delete unreferenced soft-deleted chunks.

## Encryption support

When LiveSync E2EE is enabled with property encryption, metadata paths are encrypted and stored as `/\:` + encrypted data. 

To enable automatic decryption of encrypted paths for proper subtree filtering:

1. Provide your LiveSync passphrase via `LIVESYNC_PASSPHRASE` env var or secret file.
2. The syncer will:
   - Fetch the PBKDF2 salt from both CouchDB databases
   - Decrypt encrypted paths using HKDF-SHA256
   - Match decrypted paths against the configured `SUBTREE_PREFIX`

If `LIVESYNC_PASSPHRASE` is not provided, encrypted paths will be skipped (no syncing of documents with encrypted metadata paths).

### ⚠️ Important: Different Obsidian Instances

If your databases are used by **different Obsidian instances** (different users or installations):
- Each instance has its own encryption key (different PBKDF2 salt)
- The sync tool **automatically re-encrypts encrypted metadata** using the target database's key
- This ensures the target Obsidian instance can decrypt synced paths with its own encryption key

**How re-encryption works:**
1. Detects encrypted paths when source and target databases have different PBKDF2 salts
2. Decrypts path with **source database's key** (using source PBKDF2 salt)
3. Re-encrypts path with **target database's key** (using target PBKDF2 salt)
4. Syncs the re-encrypted document to target database
5. Target Obsidian instance can now decrypt the path normally

**Configuration:**
- Ensure `LIVESYNC_PASSPHRASE` matches both databases' passphrase (same user passphrase)
- Both databases must have been initialized with encryption enabled
- If salts are different, re-encryption happens automatically

**Logs:**
- Look for `"Re-encrypted metadata"` log entries to confirm re-encryption is working
- Any re-encryption errors are logged with `"Failed to re-encrypt"` prefix

Note: Path obfuscation (`f:...` format) is a simpler obfuscation that does not require decryption, but is no longer actively used in current LiveSync versions.

## Quick start on Linux or WSL

1. Copy env template:
   - `cp .env.example .env`
2. Create secret files:
   - `cp ./secrets/couchdb_user.txt.example ./secrets/couchdb_user.txt`
   - `cp ./secrets/couchdb_password.txt.example ./secrets/couchdb_password.txt`
   - `cp ./secrets/livesync_passphrase.txt.example ./secrets/livesync_passphrase.txt`
3. Edit `.env` and secret files.
4. Dry-run first:
   - `docker compose up --build`
5. After verifying logs, set `DRY_RUN=false` in `.env`.

## Local run without Docker

1. Create virtual environment and install dependencies:
   - `python -m venv .venv`
   - `source .venv/bin/activate`
   - `pip install -r requirements.txt`
2. Set env vars or secret file env vars.
3. Run:
   - `python sync.py`

## Linux Docker deployment

Use the same files on Linux with Docker Compose:
- `docker compose up -d --build`

## Synology NAS deployment

Use `docker-compose.synology.yml` for Synology Container Manager and Docker Compose environments where top-level `secrets` support may vary.

1. Build and push the image from your CI or Linux host:
   - `docker build -t ghcr.io/mildaraa/obsidian_livesync_folder_share:<tag> .`
   - `docker push ghcr.io/mildaraa/obsidian_livesync_folder_share:<tag>`
2. On Synology, copy this project directory, including `.env` and `secrets/*.txt`.
3. Set `SYNC_IMAGE` in `.env` to your pushed tag.
4. Run:
   - `docker compose -f docker-compose.synology.yml up -d`

The Synology compose file mounts secret files directly into `/run/secrets` and keeps the same environment contract as `sync.py`.

## Health check

Container health check runs:
- `python /app/sync.py --healthcheck`

## Proposed image creation plan

1. Build pipeline
   - Build image from `python:3.12-slim`.
   - Install pinned dependencies from `requirements.txt`.
   - Copy only runtime script and dependencies.
   - Run as non-root user.

2. Security controls
   - Keep credentials outside image layers.
   - Use Docker secrets in production.
   - Keep writable state in mounted volumes only (`/data`, `/logs`).

3. Release strategy
   - Build immutable image tags per commit SHA.
   - Promote selected tags to stable aliases.

4. Validation gate
   - Run `python -m py_compile sync.py`.
   - Run healthcheck in CI with test credentials.
   - Run dry-run smoke sync before write-enabled release.

## Configuration

See `.env.example` for all supported variables.

## GitHub upload checklist

Safe to commit:
- `sync.py`, `Dockerfile`, `requirements.txt`
- `docker-compose.yml`, `docker-compose.synology.yml`
- `.env.example`, `README.md`, `.gitignore`
- `secrets/*.example`, `secrets/.gitkeep`, `data/.gitkeep`, `logs/.gitkeep`

Never commit:
- `.env`
- `secrets/*.txt` (real credentials/passphrase)
- `data/state.json`
- `logs/sync.log`

If this folder is not yet a Git repository, initialize and push:

```bash
git init
git add .
git commit -m "Initial commit: obsidian_livesync_folder_share"
git branch -M main
git remote add origin https://github.com/MildarAA/obsidian_livesync_folder_share.git
git push -u origin main
```
