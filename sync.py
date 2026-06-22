#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# ============================================================================
# Constants & Enums for Encryption, Document Types, and State Management
# ============================================================================


@dataclass
class EncryptionFormat:
    """LiveSync encryption format constants."""
    HKDF_WITH_EMBEDDED_SALT = "%="
    HKDF_WITH_PBKDF2_SALT = "%$"
    ENCRYPTED_PATH_PREFIX = "/\\:"


class DocumentType(Enum):
    """Classification of documents in CouchDB."""
    METADATA = "metadata"
    CHUNK = "chunk"
    SYSTEM = "system"  # Design docs, local docs
    UNKNOWN = "unknown"


@dataclass
class StateStoreKeys:
    """Keys for StateStore.data dictionary."""
    CHECKPOINTS = "checkpoints"
    IN_SCOPE_DOC_IDS = "in_scope_doc_ids"
    LAST_SYNCED_REVS = "last_synced_revs"


def parse_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def read_secret(env_name: str, file_env_name: str, required: bool = True) -> Optional[str]:
    file_path = os.getenv(file_env_name, "").strip()
    if file_path:
        path_obj = Path(file_path)
        if not path_obj.exists():
            raise RuntimeError(f"Secret file not found for {file_env_name}: {file_path}")
        value = path_obj.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = os.getenv(env_name, "").strip()
    if value:
        return value
    if required:
        raise RuntimeError(
            f"Missing required secret. Set {env_name} or {file_env_name}."
        )
    return None


@dataclass
class Config:
    couchdb_url: str
    couchdb_user: str
    couchdb_password: str
    db_main: str
    db_client: str
    subtree_prefix: str
    subtree_case_insensitive: bool
    mode: str
    poll_interval_seconds: int
    dry_run: bool
    verify_tls: bool
    ca_cert_path: str
    request_timeout_seconds: int
    changes_limit: int
    state_file: Path
    log_file: Path
    log_level: str
    livesync_passphrase: Optional[str]
    gc_interval: int  # Run GC every N sync cycles (default 5)

    @staticmethod
    def from_env() -> "Config":
        couchdb_url = os.getenv("COUCHDB_URL", "").strip().rstrip("/")
        if not couchdb_url.startswith("https://") and not couchdb_url.startswith("http://"):
            raise RuntimeError("COUCHDB_URL must start with http:// or https://")

        mode = os.getenv("MODE", "continuous").strip().lower()
        if mode not in {"single", "continuous"}:
            raise RuntimeError("MODE must be either 'single' or 'continuous'")

        db_main = os.getenv("DB_MAIN", "main_db").strip()
        db_client = os.getenv("DB_CLIENT", "client_db").strip()
        if not db_main or not db_client:
            raise RuntimeError("DB_MAIN and DB_CLIENT must be non-empty")
        if db_main == db_client:
            raise RuntimeError("DB_MAIN and DB_CLIENT must be different")

        subtree_prefix = os.getenv("SUBTREE_PREFIX", "/share").strip()
        if not subtree_prefix:
            raise RuntimeError("SUBTREE_PREFIX must be non-empty")

        if not subtree_prefix.startswith("/"):
            subtree_prefix = f"/{subtree_prefix}"

        ca_cert_path = os.getenv("CA_CERT_PATH", "").strip()

        return Config(
            couchdb_url=couchdb_url,
            couchdb_user=read_secret("COUCHDB_USER", "COUCHDB_USER_FILE", required=True) or "",
            couchdb_password=read_secret("COUCHDB_PASSWORD", "COUCHDB_PASSWORD_FILE", required=True) or "",
            db_main=db_main,
            db_client=db_client,
            subtree_prefix=subtree_prefix,
            subtree_case_insensitive=parse_bool(
                os.getenv("SUBTREE_CASE_INSENSITIVE", "true"), default=True
            ),
            mode=mode,
            poll_interval_seconds=int(os.getenv("POLL_INTERVAL_SECONDS", "30")),
            dry_run=parse_bool(os.getenv("DRY_RUN", "true"), default=True),
            verify_tls=parse_bool(os.getenv("VERIFY_TLS", "true"), default=True),
            ca_cert_path=ca_cert_path,
            request_timeout_seconds=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30")),
            changes_limit=int(os.getenv("CHANGES_LIMIT", "200")),
            state_file=Path(os.getenv("STATE_FILE", "/data/state.json")),
            log_file=Path(os.getenv("LOG_FILE", "/logs/sync.log")),
            log_level=os.getenv("LOG_LEVEL", "INFO").strip().upper(),
            livesync_passphrase=read_secret("LIVESYNC_PASSPHRASE", "LIVESYNC_PASSPHRASE_FILE", required=False),
            gc_interval=int(os.getenv("GC_INTERVAL", "5")),
        )


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: Dict[str, Any] = {
            StateStoreKeys.CHECKPOINTS: {},
            StateStoreKeys.IN_SCOPE_DOC_IDS: {},
            StateStoreKeys.LAST_SYNCED_REVS: {},
        }

    def load(self) -> None:
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as f:
                self.data = json.load(f)

        self.data.setdefault(StateStoreKeys.CHECKPOINTS, {})
        self.data.setdefault(StateStoreKeys.IN_SCOPE_DOC_IDS, {})
        self.data.setdefault(StateStoreKeys.LAST_SYNCED_REVS, {})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def checkpoint(self, db_name: str) -> str:
        return str(self.data[StateStoreKeys.CHECKPOINTS].get(db_name, "0"))

    def update_checkpoint(self, db_name: str, seq: str) -> None:
        self.data[StateStoreKeys.CHECKPOINTS][db_name] = str(seq)

    def is_in_scope(self, doc_id: str) -> bool:
        return bool(self.data[StateStoreKeys.IN_SCOPE_DOC_IDS].get(doc_id, False))

    def set_in_scope(self, doc_id: str, is_in_scope: bool) -> None:
        self.data[StateStoreKeys.IN_SCOPE_DOC_IDS][doc_id] = bool(is_in_scope)

    @staticmethod
    def _sync_rev_key(source_db: str, target_db: str, doc_id: str) -> str:
        return f"{source_db}->{target_db}:{doc_id}"

    def get_last_synced_revs(
        self,
        source_db: str,
        target_db: str,
        doc_id: str,
    ) -> Optional[Dict[str, str]]:
        key = self._sync_rev_key(source_db, target_db, doc_id)
        value = self.data[StateStoreKeys.LAST_SYNCED_REVS].get(key)
        if isinstance(value, dict):
            source_rev = value.get("source_rev")
            target_rev = value.get("target_rev")
            if isinstance(source_rev, str) and isinstance(target_rev, str):
                return {"source_rev": source_rev, "target_rev": target_rev}
        return None

    def set_last_synced_revs(
        self,
        source_db: str,
        target_db: str,
        doc_id: str,
        source_rev: str,
        target_rev: str,
    ) -> None:
        key = self._sync_rev_key(source_db, target_db, doc_id)
        self.data[StateStoreKeys.LAST_SYNCED_REVS][key] = {
            "source_rev": source_rev,
            "target_rev": target_rev,
        }

    def clear_last_synced_revs(self, source_db: str, target_db: str, doc_id: str) -> None:
        key = self._sync_rev_key(source_db, target_db, doc_id)
        self.data[StateStoreKeys.LAST_SYNCED_REVS].pop(key, None)


def decode_base64(data: str) -> bytes:
    """Decode base64 string to bytes."""
    # Base64 can have padding issues; this ensures proper handling
    try:
        return base64.b64decode(data, validate=True)
    except Exception:
        # Fallback: add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data = data + ("=" * padding)
        return base64.b64decode(data)


def encode_base64(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode("ascii")


def decrypt_hkdf(encrypted_data: str, passphrase: str, pbkdf2_salt: Optional[bytes]) -> str:
    """
    Decrypt HKDF-encrypted data using passphrase.
    Supported formats:
    - %= + base64(iv[12] + hkdfSalt[32] + ciphertext+tag)
    - %$ + base64(pbkdf2Salt[32] + iv[12] + hkdfSalt[32] + ciphertext+tag)
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    payload = encrypted_data
    format_prefix = ""
    if payload.startswith(EncryptionFormat.HKDF_WITH_EMBEDDED_SALT):
        format_prefix = EncryptionFormat.HKDF_WITH_EMBEDDED_SALT
        payload = payload[2:]
    elif payload.startswith(EncryptionFormat.HKDF_WITH_PBKDF2_SALT):
        format_prefix = EncryptionFormat.HKDF_WITH_PBKDF2_SALT
        payload = payload[2:]

    # Decode base64 encrypted payload
    encrypted_bytes = decode_base64(payload)

    # %$ includes an extra leading PBKDF2 salt field (32 bytes).
    offset = 32 if format_prefix == EncryptionFormat.HKDF_WITH_PBKDF2_SALT else 0

    # Extract IV (first 12 bytes), HKDF salt (12-44), and ciphertext+tag (44+)
    if len(encrypted_bytes) < offset + 44:  # 12 (IV) + 32 (salt) + 16 (tag) minimum
        raise ValueError(f"Encrypted data too short: {len(encrypted_bytes)} bytes")

    # Select pbkdf2 salt source depending on format.
    local_pbkdf2_salt = pbkdf2_salt
    if format_prefix == EncryptionFormat.HKDF_WITH_PBKDF2_SALT:
        local_pbkdf2_salt = encrypted_bytes[:32]

    if not local_pbkdf2_salt:
        raise ValueError("Missing PBKDF2 salt for HKDF decryption")

    iv = encrypted_bytes[offset : offset + 12]
    hkdf_salt = encrypted_bytes[offset + 12 : offset + 44]
    ciphertext_and_tag = encrypted_bytes[offset + 44 :]

    # LiveSync key schedule:
    # 1) PBKDF2(passphrase, pbkdf2salt, 310000, 32) -> master key bytes
    # 2) HKDF(master key bytes, hkdfSalt, empty info, SHA-256, 32) -> AES key
    master_key = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        local_pbkdf2_salt,
        310000,
        dklen=32,
    )
    hkdf_obj = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=b"",  # LiveSync uses empty info parameter
        backend=default_backend(),
    )
    key = hkdf_obj.derive(master_key)

    # Decrypt using AES-256-GCM
    cipher = AESGCM(key)
    try:
        plaintext = cipher.decrypt(iv, ciphertext_and_tag, None)
        return plaintext.decode("utf-8")
    except Exception as ex:
        raise ValueError(f"Failed to decrypt data: {ex}")


def encrypt_hkdf(plaintext: str, passphrase: str, pbkdf2_salt: bytes) -> str:
    """
    Encrypt plaintext using HKDF-based AES-256-GCM encryption.
    Returns: %= + base64(iv[12] + hkdfSalt[32] + ciphertext+tag[16])
    
    Args:
        plaintext: Text to encrypt (typically JSON)
        passphrase: User's passphrase
        pbkdf2_salt: PBKDF2 salt bytes from target database
    
    Returns:
        Encrypted data in %= format ready to store in database
    """
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Generate random IV (12 bytes) and HKDF salt (32 bytes)
    iv = os.urandom(12)
    hkdf_salt = os.urandom(32)

    # LiveSync key schedule:
    # 1) PBKDF2(passphrase, pbkdf2salt, 310000, 32) -> master key bytes
    # 2) HKDF(master key bytes, hkdfSalt, empty info, SHA-256, 32) -> AES key
    master_key = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        pbkdf2_salt,
        310000,
        dklen=32,
    )
    hkdf_obj = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=b"",
        backend=default_backend(),
    )
    key = hkdf_obj.derive(master_key)

    # Encrypt using AES-256-GCM
    cipher = AESGCM(key)
    ciphertext_and_tag = cipher.encrypt(iv, plaintext.encode("utf-8"), None)

    # Format: %= + base64(iv + hkdfSalt + ciphertext+tag)
    encrypted_bytes = iv + hkdf_salt + ciphertext_and_tag
    payload_b64 = encode_base64(encrypted_bytes)
    return f"{EncryptionFormat.HKDF_WITH_EMBEDDED_SALT}{payload_b64}"


class CouchClient:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.auth = (config.couchdb_user, config.couchdb_password)
        if config.verify_tls:
            self.verify = config.ca_cert_path if config.ca_cert_path else True
        else:
            self.verify = False

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = f"{self.config.couchdb_url}/{path.lstrip('/')}"
        kwargs.setdefault("timeout", self.config.request_timeout_seconds)
        kwargs.setdefault("verify", self.verify)
        response = self.session.request(method=method, url=url, **kwargs)
        return response

    def ensure_db_reachable(self, db_name: str) -> None:
        resp = self._request("GET", db_name)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Cannot access database {db_name}. Status={resp.status_code}, body={resp.text[:300]}"
            )

    def get_changes(self, db_name: str, since: str) -> Dict[str, Any]:
        params = {
            "since": since,
            "include_docs": "true",
            "style": "all_docs",
            "limit": str(self.config.changes_limit),
        }
        resp = self._request("GET", f"{db_name}/_changes", params=params)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Failed to fetch _changes for {db_name}. Status={resp.status_code}, body={resp.text[:300]}"
            )
        return resp.json()

    def get_doc(self, db_name: str, doc_id: str) -> Optional[Dict[str, Any]]:
        resp = self._request("GET", f"{db_name}/{requests.utils.quote(doc_id, safe='')}" )
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise RuntimeError(
                f"Failed to get document {doc_id} from {db_name}. Status={resp.status_code}, body={resp.text[:300]}"
            )
        return resp.json()

    def put_doc(self, db_name: str, doc_id: str, doc: Dict[str, Any]) -> Tuple[bool, str]:
        resp = self._request(
            "PUT",
            f"{db_name}/{requests.utils.quote(doc_id, safe='')}",
            headers={"content-type": "application/json"},
            data=json.dumps(doc),
        )
        if resp.status_code in (200, 201, 202):
            return True, "ok"
        if resp.status_code == 409:
            return False, "conflict"
        return False, f"status={resp.status_code} body={resp.text[:300]}"

    def delete_doc(self, db_name: str, doc_id: str, rev: str) -> Tuple[bool, str]:
        """Hard-delete a document from CouchDB (leaves a tombstone)."""
        resp = self._request(
            "DELETE",
            f"{db_name}/{requests.utils.quote(doc_id, safe='')}",
            params={"rev": rev},
        )
        if resp.status_code in (200, 202):
            return True, "ok"
        if resp.status_code == 409:
            return False, "conflict"
        return False, f"status={resp.status_code} body={resp.text[:300]}"

    def get_pbkdf2_salt(self, db_name: str) -> Optional[bytes]:
        doc = self.get_doc(db_name, "_local/obsidian_livesync_sync_parameters")
        if not doc:
            return None
        salt_base64 = doc.get("pbkdf2salt")
        if not isinstance(salt_base64, str) or not salt_base64:
            return None
        try:
            return decode_base64(salt_base64)
        except Exception:
            return None

    def put_doc_with_retry(
        self,
        db_name: str,
        doc_id: str,
        doc: Dict[str, Any],
        max_retries: int = 3,
        get_doc_callback=None,
    ) -> Tuple[bool, str]:
        """PUT a document with automatic retry on conflict.
        
        On conflict (409), fetches the current revision and retries up to max_retries times.
        
        Args:
            db_name: Target database name
            doc_id: Document ID
            doc: Document to write (should have _rev if updating existing)
            max_retries: Maximum retry attempts
            get_doc_callback: Optional callback to refresh _rev on conflict; 
                            if None, uses self.get_doc
        
        Returns:
            (success, reason) tuple
        """
        get_doc_fn = get_doc_callback or self.get_doc
        
        for attempt in range(max_retries):
            ok, reason = self.put_doc(db_name, doc_id, doc)
            if ok:
                return True, "ok"
            if reason != "conflict":
                return False, reason
            
            # Conflict: refresh revision and retry
            if attempt < max_retries - 1:
                refreshed = get_doc_fn(db_name, doc_id)
                if refreshed is None:
                    doc.pop("_rev", None)
                else:
                    doc["_rev"] = refreshed.get("_rev", "")
        
        return False, f"too_many_conflicts (max_retries={max_retries})"

    def delete_doc_with_retry(
        self,
        db_name: str,
        doc_id: str,
        rev: str,
        max_retries: int = 3,
        get_doc_callback=None,
    ) -> Tuple[bool, str]:
        """DELETE a document with automatic retry on conflict.
        
        On conflict (409), fetches the current revision and retries up to max_retries times.
        
        Args:
            db_name: Target database name
            doc_id: Document ID
            rev: Current revision string
            max_retries: Maximum retry attempts
            get_doc_callback: Optional callback to refresh _rev on conflict
        
        Returns:
            (success, reason) tuple
        """
        get_doc_fn = get_doc_callback or self.get_doc
        current_rev = rev
        
        for attempt in range(max_retries):
            ok, reason = self.delete_doc(db_name, doc_id, current_rev)
            if ok:
                return True, "ok"
            if reason != "conflict":
                return False, reason
            
            # Conflict: refresh revision and retry
            if attempt < max_retries - 1:
                refreshed = get_doc_fn(db_name, doc_id)
                if refreshed is None:
                    return False, "deleted_by_concurrent_operation"
                current_rev = refreshed.get("_rev", "")
        
        return False, f"too_many_conflicts (max_retries={max_retries})"


class SubtreeSync:
    def __init__(self, config: Config, state: StateStore, client: CouchClient) -> None:
        self.config = config
        self.state = state
        self.client = client
        self.log = logging.getLogger("subtree-sync")
        self.encrypted_path_prefix = EncryptionFormat.ENCRYPTED_PATH_PREFIX
        self._pbkdf2_salts: Dict[str, bytes] = {}
        self.gc_cycle_count = 0  # Track cycles for periodic GC trigger

    def classify_document(self, doc: Dict[str, Any]) -> DocumentType:
        """Unified document classifier: returns DocumentType for any CouchDB document.
        
        Classification hierarchy:
        1. System docs (_design/*, _local/*) -> SYSTEM
        2. Chunks (type in {CHUNK, leaf} or _id starts with h:) -> CHUNK
        3. Metadata (children array or type starts with NOTE) -> METADATA
        4. Everything else -> UNKNOWN
        """
        if not isinstance(doc, dict):
            return DocumentType.UNKNOWN
        
        doc_id = str(doc.get("_id", ""))
        if doc_id.startswith("_design/") or doc_id.startswith("_local/"):
            return DocumentType.SYSTEM
        
        doc_type = doc.get("type")
        if doc_type in {"CHUNK", "leaf"} or doc_id.startswith("h:"):
            return DocumentType.CHUNK
        
        if isinstance(doc.get("children"), list):
            return DocumentType.METADATA
        if isinstance(doc_type, str) and doc_type.startswith("NOTE"):
            return DocumentType.METADATA
        
        return DocumentType.UNKNOWN

    def initialize_crypto_state(self) -> None:
        if not self.config.livesync_passphrase:
            return

        for db_name in (self.config.db_main, self.config.db_client):
            salt = self.client.get_pbkdf2_salt(db_name)
            if salt:
                self._pbkdf2_salts[db_name] = salt
                self.log.info("Loaded pbkdf2salt from %s", db_name)
            else:
                self.log.warning(
                    "Could not load pbkdf2salt from %s; encrypted paths from this DB cannot be decrypted",
                    db_name,
                )

    def _has_salts_match(self, db_a: str, db_b: str) -> bool:
        """Check if two databases have matching PBKDF2 salts for safe encrypted metadata sync."""
        salt_a = self._pbkdf2_salts.get(db_a)
        salt_b = self._pbkdf2_salts.get(db_b)
        if not salt_a or not salt_b:
            return False  # Can't verify match if either salt is missing
        return salt_a == salt_b

    def _has_encrypted_metadata(self, doc: Dict[str, Any]) -> bool:
        """Check if metadata has encrypted path."""
        if not self._is_metadata(doc):
            return False
        path = doc.get("path", "")
        return isinstance(path, str) and path.startswith(self.encrypted_path_prefix)

    @staticmethod
    def _is_deleted(doc: Dict[str, Any]) -> bool:
        return bool(doc.get("_deleted") is True or doc.get("deleted") is True)

    def _is_metadata(self, doc: Dict[str, Any]) -> bool:
        """Check if document is metadata (uses unified classifier)."""
        return self.classify_document(doc) == DocumentType.METADATA

    def _is_chunk(self, doc: Dict[str, Any]) -> bool:
        """Check if document is a chunk (uses unified classifier)."""
        return self.classify_document(doc) == DocumentType.CHUNK

    @staticmethod
    def _clean_doc_for_write(doc: Dict[str, Any]) -> Dict[str, Any]:
        remove_keys = {
            "_conflicts",
            "_deleted_conflicts",
            "_local_seq",
            "_revs_info",
            "_revisions",
        }
        return {k: v for k, v in doc.items() if k not in remove_keys}

    def _prepare_doc_for_target(self, source_db: str, target_db: str, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare document for writing to target database.
        
        If source/target databases have different keys, re-encrypt LiveSync HKDF
        payload fields (metadata path and chunk data) with the target key.
        """
        if not self.config.livesync_passphrase:
            return doc  # No encryption; return as-is

        # If both DBs use the same salt, no re-encryption is needed.
        if self._has_salts_match(source_db, target_db):
            return doc

        source_salt = self._pbkdf2_salts.get(source_db)
        target_salt = self._pbkdf2_salts.get(target_db)
        if not source_salt or not target_salt:
            self.log.warning(
                "Cannot re-encrypt doc '%s': missing PBKDF2 salt for source or target",
                doc.get("_id"),
            )
            return doc

        result = doc.copy()

        if self._is_metadata(doc):
            path = doc.get("path")
            if isinstance(path, str) and path.startswith(self.encrypted_path_prefix):
                try:
                    encrypted_payload = path[len(self.encrypted_path_prefix) :]
                    decrypted_path = decrypt_hkdf(
                        encrypted_payload,
                        self.config.livesync_passphrase,
                        source_salt,
                    )
                    re_encrypted = encrypt_hkdf(
                        decrypted_path,
                        self.config.livesync_passphrase,
                        target_salt,
                    )
                    result["path"] = f"{self.encrypted_path_prefix}{re_encrypted}"
                    self.log.debug(
                        "Re-encrypted metadata '%s' for %s->%s",
                        doc.get("_id"),
                        source_db,
                        target_db,
                    )
                except Exception as ex:
                    self.log.error(
                        "Failed to re-encrypt metadata path for doc '%s': %s",
                        doc.get("_id"),
                        ex,
                    )

        if self._is_chunk(doc):
            encrypted_data = doc.get("data")
            if isinstance(encrypted_data, str) and (
                encrypted_data.startswith(EncryptionFormat.HKDF_WITH_EMBEDDED_SALT) or encrypted_data.startswith(EncryptionFormat.HKDF_WITH_PBKDF2_SALT)
            ):
                try:
                    plaintext = decrypt_hkdf(
                        encrypted_data,
                        self.config.livesync_passphrase,
                        source_salt,
                    )
                    result["data"] = encrypt_hkdf(
                        plaintext,
                        self.config.livesync_passphrase,
                        target_salt,
                    )
                    self.log.debug(
                        "Re-encrypted chunk '%s' for %s->%s",
                        doc.get("_id"),
                        source_db,
                        target_db,
                    )
                except Exception as ex:
                    self.log.error(
                        "Failed to re-encrypt chunk data for doc '%s': %s",
                        doc.get("_id"),
                        ex,
                    )

        return result

    def _normalise_plain_path(self, path: str) -> str:
        normalized = path.replace("\\", "/").strip()
        if normalized.startswith("./"):
            normalized = normalized[2:]
        normalized = normalized.lstrip("/")
        if self.config.subtree_case_insensitive:
            normalized = normalized.lower()
        return normalized

    def _decrypt_encrypted_path(self, encrypted_path: str, source_db: str) -> Optional[str]:
        r"""
        Decrypt HKDF-encrypted data using passphrase.
        Format: base64(iv[12] + hkdfSalt[32] + ciphertext+tag)
        The HKDF salt is embedded in the encrypted data (at bytes 12-44).
        Encrypted content is JSON: {path, mtime, ctime, size, children?}
        Returns the decrypted path, or None if decryption fails.
        """
        props = self._decrypt_encrypted_metadata_props(encrypted_path, source_db)
        if isinstance(props, dict):
            path_value = props.get("path")
            if isinstance(path_value, str):
                return path_value
        return None

    def _decrypt_encrypted_metadata_props(self, encrypted_path: str, source_db: str) -> Optional[Dict[str, Any]]:
        """Decrypt encrypted metadata path and return decoded metadata JSON object."""
        if not self.config.livesync_passphrase:
            return None

        if not encrypted_path.startswith(self.encrypted_path_prefix):
            return None

        try:
            encrypted_data = encrypted_path[len(self.encrypted_path_prefix) :]
            decrypted_json = decrypt_hkdf(
                encrypted_data,
                self.config.livesync_passphrase,
                self._pbkdf2_salts.get(source_db),
            )
            props = json.loads(decrypted_json)
            if isinstance(props, dict):
                return props
            return None
        except Exception as ex:
            self.log.warning("Failed to decrypt path: %s", ex)
            return None

    def _get_metadata_children(self, metadata_doc: Dict[str, Any], source_db: str) -> list[str]:
        """Return chunk IDs from metadata, including encrypted metadata payload."""
        children = metadata_doc.get("children", [])
        if isinstance(children, list) and children:
            return [child for child in children if isinstance(child, str) and child]

        path_value = metadata_doc.get("path")
        if isinstance(path_value, str) and path_value.startswith(self.encrypted_path_prefix):
            props = self._decrypt_encrypted_metadata_props(path_value, source_db)
            if isinstance(props, dict):
                embedded_children = props.get("children", [])
                if isinstance(embedded_children, list) and embedded_children:
                    extracted = [child for child in embedded_children if isinstance(child, str) and child]
                    if extracted:
                        self.log.debug(
                            "Metadata '%s' using %d children from encrypted payload",
                            metadata_doc.get("_id"),
                            len(extracted),
                        )
                    return extracted

        return []

    def _is_path_in_subtree(self, raw_path: str, source_db: str) -> bool:
        """Check if a path (possibly encrypted) is within the configured subtree."""
        # Try to decrypt encrypted paths
        if raw_path.startswith(self.encrypted_path_prefix):
            decrypted = self._decrypt_encrypted_path(raw_path, source_db)
            if decrypted:
                raw_path = decrypted
                self.log.debug("Successfully decrypted path: %s", raw_path)
            else:
                # Cannot decrypt; skip this document to be safe
                self.log.debug("Could not decrypt encrypted path; skipping document")
                return False

        path_value = self._normalise_plain_path(raw_path)
        subtree_value = self._normalise_plain_path(self.config.subtree_prefix)
        if subtree_value == "":
            # Explicit root subtree '/' means all paths.
            return True
        if path_value == subtree_value:
            return True
        return path_value.startswith(f"{subtree_value}/")

    def _is_metadata_in_scope(self, doc: Dict[str, Any], source_db: str) -> bool:
        doc_id = str(doc.get("_id", ""))
        path_value = doc.get("path")

        if isinstance(path_value, str):
            in_scope = self._is_path_in_subtree(path_value, source_db)
            self.state.set_in_scope(doc_id, in_scope)
            if not in_scope:
                self.log.debug(
                    "Document '%s' path='%s' is out of scope (subtree=%s)",
                    doc_id,
                    path_value,
                    self.config.subtree_prefix,
                )
            return in_scope

        # For tombstones or malformed metadata, rely on historical scope memory.
        result = self.state.is_in_scope(doc_id)
        self.log.debug(
            "Document '%s' has no path field; using historical scope=%s",
            doc_id,
            result,
        )
        return result

    def _doc_mtime(self, doc: Dict[str, Any]) -> float:
        value = doc.get("mtime", 0)
        if isinstance(value, (int, float)):
            return float(value)
        return 0.0

    @staticmethod
    def _doc_rev_generation(doc: Dict[str, Any]) -> int:
        rev = str(doc.get("_rev", ""))
        if "-" not in rev:
            return 0
        head = rev.split("-", 1)[0]
        if head.isdigit():
            return int(head)
        return 0

    def _is_target_newer(self, source_doc: Dict[str, Any], target_doc: Dict[str, Any]) -> bool:
        """Return True if target should win based on recency metadata.

        Priority:
        1) mtime when present on either side
        2) _rev generation as fallback (best-effort for docs without mtime)
        """
        source_mtime = self._doc_mtime(source_doc)
        target_mtime = self._doc_mtime(target_doc)
        if source_mtime > 0 or target_mtime > 0:
            return target_mtime > source_mtime

        source_gen = self._doc_rev_generation(source_doc)
        target_gen = self._doc_rev_generation(target_doc)
        return target_gen > source_gen

    def _canonical_doc_for_compare(self, doc: Dict[str, Any], db_name: str) -> Dict[str, Any]:
        """Build a comparable representation independent of ciphertext randomness."""
        canonical = self._clean_doc_for_write(doc.copy())
        canonical.pop("_rev", None)

        if self._is_metadata(canonical):
            path_value = canonical.get("path")
            if isinstance(path_value, str) and path_value.startswith(self.encrypted_path_prefix):
                props = self._decrypt_encrypted_metadata_props(path_value, db_name)
                if isinstance(props, dict):
                    canonical["path"] = "__ENCRYPTED_PATH__"
                    canonical["__path_props"] = props

        if self._is_chunk(canonical):
            encrypted_data = canonical.get("data")
            if isinstance(encrypted_data, str) and (
                encrypted_data.startswith(EncryptionFormat.HKDF_WITH_EMBEDDED_SALT) or encrypted_data.startswith(EncryptionFormat.HKDF_WITH_PBKDF2_SALT)
            ):
                try:
                    plaintext = decrypt_hkdf(
                        encrypted_data,
                        self.config.livesync_passphrase or "",
                        self._pbkdf2_salts.get(db_name),
                    )
                    canonical["data"] = "__ENCRYPTED_DATA__"
                    canonical["__data_plain"] = plaintext
                except Exception:
                    # If decryption fails, keep raw data for conservative comparison.
                    pass

        return canonical

    def _docs_semantically_equal(
        self,
        source_db: str,
        target_db: str,
        source_doc: Dict[str, Any],
        target_doc: Dict[str, Any],
    ) -> bool:
        source_canonical = self._canonical_doc_for_compare(source_doc, source_db)
        target_canonical = self._canonical_doc_for_compare(target_doc, target_db)
        return source_canonical == target_canonical

    def _resolve_deletion_conflict(
        self,
        source_db: str,
        target_db: str,
        source_deleted: bool,
        source_mtime: float,
        target_deleted: bool,
        target_mtime: float,
    ) -> str:
        """Resolve deletion conflict with mainDB-authoritative policy.
        
        Returns conflict resolution action:
        - "apply" - proceed with the operation
        - "kept_target_newer" - target is newer, keep target state
        - "both_deleted" - both deleted, skip
        """
        # Both deleted: skip
        if source_deleted and target_deleted:
            return "both_deleted"
        
        # Main DB is authoritative for metadata state.
        if source_db == self.config.db_main and target_db == self.config.db_client:
            return "apply"

        # Source deleted, target live: check if target is newer (edit resurrection)
        if source_deleted and not target_deleted:
            # If target was edited after source was deleted, target wins (resurrection)
            if target_mtime > source_mtime:
                return "kept_target_newer"
            return "apply"
        
        # Source live, target deleted: check if source is newer (resurrect from older delete)
        if not source_deleted and target_deleted:
            # If source was edited after target was deleted, source wins (resurrect)
            if source_mtime > target_mtime:
                return "apply"
            return "kept_target_deleted"
        
        return "apply"

    def _apply_document(
        self,
        source_db: str,
        target_db: str,
        source_doc: Dict[str, Any],
        metadata_conflict_policy: bool,
    ) -> str:
        """Apply document from source to target with conflict resolution.
        
        Implements bidirectional authority:
        - Deletion always propagates unless target is newer live version
        - Edit conflicts resolved by mtime, no role-based veto
        - Two-phase deletion: soft-delete metadata, then GC chunks later
        """
        doc_id = str(source_doc["_id"])
        source_rev = str(source_doc.get("_rev", ""))
        source_deleted = self._is_deleted(source_doc)

        target_doc = self.client.get_doc(target_db, doc_id)

        # Fast path: if source/target revisions match the last successful sync pair,
        # skip any decrypt/re-encrypt and avoid unnecessary writes.
        if target_doc is not None and source_rev:
            last_revs = self.state.get_last_synced_revs(source_db, target_db, doc_id)
            target_rev_now = str(target_doc.get("_rev", ""))
            if (
                last_revs
                and last_revs["source_rev"] == source_rev
                and last_revs["target_rev"] == target_rev_now
            ):
                return "skipped_seen_rev"

        # CASE 1: Source is DELETED metadata/chunk (soft-delete propagation)
        if source_deleted:
            if target_doc is None:
                return "skipped_delete_missing"
            
            # Only apply soft-delete conflict check for metadata (not chunks)
            if metadata_conflict_policy:
                target_deleted = self._is_deleted(target_doc)
                source_mtime = self._doc_mtime(source_doc)
                target_mtime = self._doc_mtime(target_doc)
                conflict_action = self._resolve_deletion_conflict(
                    source_db=source_db,
                    target_db=target_db,
                    source_deleted=True,
                    source_mtime=source_mtime,
                    target_deleted=target_deleted,
                    target_mtime=target_mtime,
                )
                if conflict_action == "both_deleted":
                    return "skipped_both_deleted"
                elif conflict_action == "kept_target_newer":
                    self.log.debug(
                        "Conflict: source deleted, target live (source_mtime=%s target_mtime=%s): keeping target",
                        source_mtime,
                        target_mtime,
                    )
                    return "kept_target_newer"
            
            # Build soft-delete document with preserved metadata for GC
            soft_delete_doc = {"_id": doc_id, "_rev": target_doc["_rev"], "deleted": True}
            if isinstance(target_doc, dict):
                # Preserve metadata fields already encrypted with target vault key
                if "path" in target_doc:
                    soft_delete_doc["path"] = target_doc["path"]
                if "type" in target_doc:
                    soft_delete_doc["type"] = target_doc["type"]
                if "children" in target_doc and isinstance(target_doc.get("children"), list):
                    soft_delete_doc["children"] = target_doc["children"]  # FOR GC
                if "mtime" in target_doc:
                    soft_delete_doc["mtime"] = target_doc["mtime"]
                if "ctime" in target_doc:
                    soft_delete_doc["ctime"] = target_doc["ctime"]
            
            if self.config.dry_run:
                return "dryrun_delete"

            ok, reason = self.client.put_doc_with_retry(
                target_db,
                doc_id,
                soft_delete_doc,
                max_retries=3,
            )
            if ok:
                self.state.clear_last_synced_revs(source_db, target_db, doc_id)
                return "deleted"
            if "too_many" in reason or "conflict" in reason:
                raise RuntimeError(f"Too many delete conflicts for {doc_id} in {target_db}")
            if "deleted_by_concurrent" in reason:
                return "skipped_delete_missing"
            raise RuntimeError(f"Failed deleting {doc_id} in {target_db}: {reason}")

        # CASE 2: Source is LIVE metadata/chunk (create or update)
        prepared_doc = self._prepare_doc_for_target(source_db, target_db, source_doc)
        write_doc = self._clean_doc_for_write(prepared_doc)

        # Subcase: Target does not exist (CREATE)
        if target_doc is None:
            write_doc.pop("_rev", None)
            if self.config.dry_run:
                return "dryrun_create"
            ok, reason = self.client.put_doc(target_db, doc_id, write_doc)
            if not ok:
                raise RuntimeError(f"Failed creating {doc_id} in {target_db}: {reason}")
            latest_target_doc = self.client.get_doc(target_db, doc_id)
            if latest_target_doc is not None and source_rev:
                self.state.set_last_synced_revs(
                    source_db,
                    target_db,
                    doc_id,
                    source_rev,
                    str(latest_target_doc.get("_rev", "")),
                )
            return "created"

        # Subcase: Target exists, check if already synchronized or if conflict
        if self._docs_semantically_equal(source_db, target_db, source_doc, target_doc):
            if source_rev:
                self.state.set_last_synced_revs(
                    source_db,
                    target_db,
                    doc_id,
                    source_rev,
                    str(target_doc.get("_rev", "")),
                )
            return "skipped_unchanged"

        # Subcase: Target exists and differs, check for edit conflict
        target_deleted = self._is_deleted(target_doc)
        if target_deleted:
            # Target is deleted but source is live: may be resurrection
            main_to_client = source_db == self.config.db_main and target_db == self.config.db_client
            if metadata_conflict_policy and (not main_to_client) and self._is_target_newer(source_doc, target_doc):
                source_mtime = self._doc_mtime(source_doc)
                target_mtime = self._doc_mtime(target_doc)
                source_gen = self._doc_rev_generation(source_doc)
                target_gen = self._doc_rev_generation(target_doc)
                self.log.debug(
                    "Conflict: source live, target deleted (source_mtime=%s target_mtime=%s source_gen=%s target_gen=%s): keeping target deleted",
                    source_mtime,
                    target_mtime,
                    source_gen,
                    target_gen,
                )
                return "kept_target_deleted"
        else:
            # Both live: mtime-based conflict resolution
            main_to_client = source_db == self.config.db_main and target_db == self.config.db_client
            if metadata_conflict_policy and (not main_to_client) and self._is_target_newer(source_doc, target_doc):
                self.log.debug(
                    "Conflict: edit on both sides, target newer: keeping target",
                )
                return "kept_target_newer"

        # Apply the update (retry on conflict up to 3 times)
        write_doc["_rev"] = target_doc["_rev"]
        if self.config.dry_run:
            return "dryrun_update"

        ok, reason = self.client.put_doc_with_retry(
            target_db,
            doc_id,
            write_doc,
            max_retries=3,
        )
        if ok:
            latest_target_doc = self.client.get_doc(target_db, doc_id)
            if latest_target_doc is not None and source_rev:
                self.state.set_last_synced_revs(
                    source_db,
                    target_db,
                    doc_id,
                    source_rev,
                    str(latest_target_doc.get("_rev", "")),
                )
            return "updated"
        if "too_many" in reason or "conflict" in reason:
            raise RuntimeError(f"Too many update conflicts for {doc_id} in {target_db}")
        raise RuntimeError(f"Failed updating {doc_id} in {target_db}: {reason}")

    def _sync_metadata_and_children(self, source_db: str, target_db: str, metadata_doc: Dict[str, Any]) -> Dict[str, int]:
        result = {
            "metadata_applied": 0,
            "metadata_skipped": 0,
            "chunks_applied": 0,
            "chunks_skipped": 0,
        }

        if self._is_deleted(metadata_doc):
            metadata_status = self._apply_document(
                source_db=source_db,
                target_db=target_db,
                source_doc=metadata_doc,
                metadata_conflict_policy=True,
            )
            if metadata_status.startswith("kept_target") or metadata_status.startswith("skipped"):
                result["metadata_skipped"] += 1
            else:
                result["metadata_applied"] += 1
            return result

        children = self._get_metadata_children(metadata_doc, source_db)
        missing_children = 0

        if not children:
            self.log.debug("Metadata '%s' has empty children array", metadata_doc.get("_id"))

        if children:
            self.log.debug("Syncing %d chunks for metadata '%s'", len(children), metadata_doc.get("_id"))

            for child_id in children:
                if not isinstance(child_id, str) or not child_id:
                    self.log.warning("Invalid child ID in metadata '%s': %r", metadata_doc.get("_id"), child_id)
                    continue

                child_doc = self.client.get_doc(source_db, child_id)
                if child_doc is None:
                    missing_children += 1
                    self.log.warning("Missing chunk '%s' referenced by '%s'", child_id, metadata_doc.get("_id"))
                    continue

                if not self._is_chunk(child_doc):
                    self.log.warning(
                        "Document '%s' referenced by metadata '%s' is not a chunk (type=%s)",
                        child_id,
                        metadata_doc.get("_id"),
                        child_doc.get("type"),
                    )
                    continue

                chunk_status = self._apply_document(
                    source_db=source_db,
                    target_db=target_db,
                    source_doc=child_doc,
                    metadata_conflict_policy=True,
                )
                if chunk_status.startswith("skipped") or chunk_status.startswith("kept_target"):
                    result["chunks_skipped"] += 1
                    self.log.debug("Chunk '%s' skipped: %s", child_id, chunk_status)
                else:
                    result["chunks_applied"] += 1
                    self.log.info("Chunk '%s' synced: %s", child_id, chunk_status)

        if missing_children > 0:
            self.log.warning(
                "Skipping metadata '%s' update because %d referenced chunks are missing in source DB",
                metadata_doc.get("_id"),
                missing_children,
            )
            result["metadata_skipped"] += 1
            return result

        metadata_status = self._apply_document(
            source_db=source_db,
            target_db=target_db,
            source_doc=metadata_doc,
            metadata_conflict_policy=True,
        )

        if metadata_status.startswith("kept_target") or metadata_status.startswith("skipped"):
            result["metadata_skipped"] += 1
        else:
            result["metadata_applied"] += 1

        return result

    def _collect_referenced_chunks(self, db_name: str, deleted: bool = False) -> set:
        """Collect all chunk IDs referenced by live metadata in the given database.
        
        Args:
            db_name: Database name to scan
            deleted: If False, scan only live metadata (deleted=false). If True, scan deleted metadata.
        
        Returns:
            Set of chunk IDs (_id values) referenced in metadata.children arrays
        """
        chunk_ids: set = set()
        
        # Query all documents; filter by metadata type and deleted status
        all_docs_payload = self.client._request("GET", f"{db_name}/_all_docs", params={"include_docs": "true"})
        all_docs_payload.raise_for_status()
        all_docs = all_docs_payload.json()
        
        for row in all_docs.get("rows", []):
            doc = row.get("doc")
            if not isinstance(doc, dict):
                continue
            
            # Filter by metadata type
            if not self._is_metadata(doc):
                continue
            
            # Filter by deleted status
            is_doc_deleted = self._is_deleted(doc)
            if is_doc_deleted != deleted:
                continue
            
            # Filter by scope
            if not self._is_metadata_in_scope(doc, db_name):
                continue
            
            # Collect referenced chunks using the same logic as normal metadata sync.
            # This handles encrypted metadata payloads where children may not be present
            # as plain top-level fields.
            children = self._get_metadata_children(doc, db_name)
            if isinstance(children, list):
                for chunk_id in children:
                    if isinstance(chunk_id, str) and chunk_id:
                        chunk_ids.add(chunk_id)
        
        return chunk_ids

    def _all_chunks_in_db(self, db_name: str) -> list:
        """Retrieve all chunk documents from the database.
        
        Returns:
            List of chunk documents
        """
        chunks = []
        
        all_docs_payload = self.client._request("GET", f"{db_name}/_all_docs", params={"include_docs": "true"})
        all_docs_payload.raise_for_status()
        all_docs = all_docs_payload.json()
        
        for row in all_docs.get("rows", []):
            doc = row.get("doc")
            if isinstance(doc, dict) and self._is_chunk(doc):
                chunks.append(doc)
        
        return chunks

    def _mark_chunk_soft_deleted(self, db_name: str, chunk_id: str) -> bool:
        """Mark a chunk as soft-deleted (set deleted=true) without hard-deleting."""
        chunk_doc = self.client.get_doc(db_name, chunk_id)
        if chunk_doc is None:
            self.log.warning("Chunk %s not found in %s for GC", chunk_id, db_name)
            return False

        if self._is_deleted(chunk_doc):
            self.log.debug("Chunk %s already soft-deleted in %s", chunk_id, db_name)
            return True

        soft_deleted_chunk = {
            "_id": chunk_id,
            "_rev": chunk_doc.get("_rev", ""),
            "deleted": True,
        }

        if self.config.dry_run:
            self.log.info("[DRY-RUN] Would soft-delete chunk %s in %s", chunk_id, db_name)
            return True

        ok, reason = self.client.put_doc(db_name, chunk_id, soft_deleted_chunk)
        if not ok:
            self.log.error("Failed to soft-delete chunk %s in %s: %s", chunk_id, db_name, reason)
            return False

        self.log.debug("Soft-deleted chunk %s in %s", chunk_id, db_name)
        return True

    def _hard_delete_chunk(self, db_name: str, chunk_id: str) -> bool:
        """Hard-delete a soft-deleted chunk from a database.

        Safe to call only after confirming the chunk is already soft-deleted
        (deleted=True) in that database, ensuring any peer has already observed
        the soft-delete tombstone via normal sync before we remove it.
        """
        chunk_doc = self.client.get_doc(db_name, chunk_id)
        if chunk_doc is None:
            # Already gone
            return True

        if not self._is_deleted(chunk_doc):
            self.log.warning(
                "Refusing to hard-delete chunk %s in %s: not yet soft-deleted",
                chunk_id,
                db_name,
            )
            return False

        rev = chunk_doc.get("_rev", "")
        if not rev:
            self.log.error("Chunk %s in %s has no _rev; cannot hard-delete", chunk_id, db_name)
            return False

        if self.config.dry_run:
            self.log.info("[DRY-RUN] Would hard-delete chunk %s in %s", chunk_id, db_name)
            return True

        ok, reason = self.client.delete_doc(db_name, chunk_id, rev)
        if not ok:
            self.log.error("Failed to hard-delete chunk %s in %s: %s", chunk_id, db_name, reason)
            return False

        self.log.debug("Hard-deleted chunk %s from %s", chunk_id, db_name)
        return True

    def _gc_phase_1_collect_live_references(self) -> set:
        """Phase 1: Collect all chunk IDs referenced by live metadata in both databases.
        
        Returns:
            Set of chunk IDs that are actively referenced
        """
        live_refs_main = self._collect_referenced_chunks(self.config.db_main, deleted=False)
        live_refs_client = self._collect_referenced_chunks(self.config.db_client, deleted=False)
        live_chunks = live_refs_main | live_refs_client  # Union: still needed by either side
        
        self.log.info(
            "GC Phase 1: Found %d live chunks in %s, %d in %s (union=%d)",
            len(live_refs_main),
            self.config.db_main,
            len(live_refs_client),
            self.config.db_client,
            len(live_chunks),
        )
        return live_chunks

    def _gc_phase_2_process_main_db(self, live_chunks: set) -> Dict[str, int]:
        """Phase 2: Process chunks in main DB for soft-delete and hard-delete.
        
        For each unreferenced chunk:
          - If already soft-deleted in BOTH DBs -> hard-delete from both
          - If not yet soft-deleted -> soft-delete in main (sync will propagate to client)
          - If soft-deleted in main only -> defer until next cycle
        
        Returns:
            Dict with soft_deleted and hard_deleted counts
        """
        stats = {"soft_deleted": 0, "hard_deleted": 0, "total": 0}
        all_chunks_main = self._all_chunks_in_db(self.config.db_main)
        stats["total"] = len(all_chunks_main)
        
        for chunk_doc in all_chunks_main:
            chunk_id = chunk_doc.get("_id")
            if not isinstance(chunk_id, str):
                continue
            
            # Skip if still referenced by any live metadata
            if chunk_id in live_chunks:
                continue
            
            soft_deleted_main = self._is_deleted(chunk_doc)
            
            # Check client DB state
            chunk_doc_client = self.client.get_doc(self.config.db_client, chunk_id)
            soft_deleted_client = chunk_doc_client is None or self._is_deleted(chunk_doc_client)
            
            if soft_deleted_main and soft_deleted_client:
                # Safe to hard-delete from both: tombstone visible to both peers already
                if self._hard_delete_chunk(self.config.db_main, chunk_id):
                    stats["hard_deleted"] += 1
                if chunk_doc_client is not None:
                    if self._hard_delete_chunk(self.config.db_client, chunk_id):
                        stats["hard_deleted"] += 1
            elif not soft_deleted_main:
                # Soft-delete in main; sync will propagate tombstone to client
                if self._mark_chunk_soft_deleted(self.config.db_main, chunk_id):
                    stats["soft_deleted"] += 1
            else:
                # Soft-deleted in main but not yet in client: wait for sync to propagate
                self.log.debug(
                    "GC Phase 2: chunk %s soft-deleted in %s but not yet in %s; deferring hard-delete",
                    chunk_id,
                    self.config.db_main,
                    self.config.db_client,
                )
        
        return stats

    def _gc_phase_3_cleanup_client_tombstones(self, live_chunks: set) -> Dict[str, int]:
        """Phase 3: Clean up soft-deleted tombstones in client DB.
        
        Catches residual soft-deleted chunks that were hard-deleted from main
        on a prior cycle but still have a tombstone in client.
        
        Returns:
            Dict with soft_deleted and hard_deleted counts
        """
        stats = {"soft_deleted": 0, "hard_deleted": 0}
        all_chunks_client = self._all_chunks_in_db(self.config.db_client)
        
        for chunk_doc in all_chunks_client:
            chunk_id = chunk_doc.get("_id")
            if not isinstance(chunk_id, str):
                continue
            if chunk_id in live_chunks:
                continue
            
            if not self._is_deleted(chunk_doc):
                # Live in client but unreferenced: soft-delete here too so the
                # next main-DB scan can promote to hard-delete on the next cycle.
                if self._mark_chunk_soft_deleted(self.config.db_client, chunk_id):
                    stats["soft_deleted"] += 1
                continue
            
            # Already soft-deleted in client and not live -> hard-delete
            if self._hard_delete_chunk(self.config.db_client, chunk_id):
                stats["hard_deleted"] += 1
        
        return stats

    def garbage_collect_unused_chunks(self) -> Dict[str, int]:
        """Chunk garbage collection: soft-delete then hard-delete unreferenced chunks.

        Orchestrates three phases:
        - Phase 1: Collect live chunk references from both DBs
        - Phase 2: Process main DB (soft/hard-delete unreferenced chunks)
        - Phase 3: Clean up client DB tombstones
        """
        self.log.info("Starting garbage collection for unused chunks")

        # Phase 1: Collect live references
        live_chunks = self._gc_phase_1_collect_live_references()
        
        # Phase 2: Process main DB
        phase2_stats = self._gc_phase_2_process_main_db(live_chunks)
        
        # Phase 3: Cleanup client tombstones
        phase3_stats = self._gc_phase_3_cleanup_client_tombstones(live_chunks)
        
        # Aggregate stats
        stats = {
            "soft_deleted": phase2_stats["soft_deleted"] + phase3_stats["soft_deleted"],
            "hard_deleted": phase2_stats["hard_deleted"] + phase3_stats["hard_deleted"],
            "chunks_total": phase2_stats["total"],
        }
        
        self.log.info(
            "GC complete: soft_deleted=%d, hard_deleted=%d, total_chunks=%d",
            stats["soft_deleted"],
            stats["hard_deleted"],
            stats["chunks_total"],
        )
        return stats

    def sync_direction(self, source_db: str, target_db: str) -> Dict[str, int]:
        stats = {
            "rows": 0,
            "metadata_in_scope": 0,
            "metadata_applied": 0,
            "metadata_skipped": 0,
            "chunks_applied": 0,
            "chunks_skipped": 0,
            "errors": 0,
        }
        since = self.state.checkpoint(source_db)
        self.log.info("Sync direction %s -> %s starting from seq=%s", source_db, target_db, since)

        while True:
            payload = self.client.get_changes(source_db, since=since)
            results = payload.get("results", [])
            if not isinstance(results, list):
                break

            if not results:
                break

            for row in results:
                stats["rows"] += 1
                seq = str(row.get("seq", since))
                doc = row.get("doc")
                if not isinstance(doc, dict):
                    since = seq
                    self.state.update_checkpoint(source_db, since)
                    continue

                try:
                    if self._is_metadata(doc) and self._is_metadata_in_scope(doc, source_db):
                        stats["metadata_in_scope"] += 1
                        # Note: if databases have different encryption keys, _prepare_doc_for_target
                        # will re-encrypt encrypted metadata with the target database's key.
                        r = self._sync_metadata_and_children(source_db, target_db, doc)
                        stats["metadata_applied"] += r["metadata_applied"]
                        stats["metadata_skipped"] += r["metadata_skipped"]
                        stats["chunks_applied"] += r["chunks_applied"]
                        stats["chunks_skipped"] += r["chunks_skipped"]
                    elif self._is_deleted(doc):
                        doc_id = str(doc.get("_id", ""))
                        in_scope_tombstone = self.state.is_in_scope(doc_id)

                        # If state was reset, infer scope from target-side metadata when available.
                        if not in_scope_tombstone:
                            target_doc = self.client.get_doc(target_db, doc_id)
                            if isinstance(target_doc, dict) and self._is_metadata(target_doc):
                                in_scope_tombstone = self._is_metadata_in_scope(target_doc, target_db)

                        if in_scope_tombstone:
                            self.state.set_in_scope(doc_id, True)
                            stats["metadata_in_scope"] += 1
                            r = self._sync_metadata_and_children(source_db, target_db, doc)
                            stats["metadata_applied"] += r["metadata_applied"]
                            stats["metadata_skipped"] += r["metadata_skipped"]
                            stats["chunks_applied"] += r["chunks_applied"]
                            stats["chunks_skipped"] += r["chunks_skipped"]
                except Exception as exc:  # pylint: disable=broad-except
                    stats["errors"] += 1
                    self.log.exception("Failed processing row id=%s: %s", row.get("id"), exc)

                since = seq
                self.state.update_checkpoint(source_db, since)

            last_seq = payload.get("last_seq")
            if last_seq is not None:
                since = str(last_seq)
                self.state.update_checkpoint(source_db, since)

            self.state.save()

        self.log.info(
            "Sync direction %s -> %s done. rows=%s metadata_in_scope=%s metadata_applied=%s chunks_applied=%s errors=%s",
            source_db,
            target_db,
            stats["rows"],
            stats["metadata_in_scope"],
            stats["metadata_applied"],
            stats["chunks_applied"],
            stats["errors"],
        )
        return stats


def setup_logging(config: Config) -> None:
    config.log_file.parent.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, config.log_level, logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(config.log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)

    root.handlers = [stream_handler, file_handler]


def run_healthcheck(config: Config) -> int:
    client = CouchClient(config)
    client.ensure_db_reachable(config.db_main)
    client.ensure_db_reachable(config.db_client)
    return 0


def run_sync(config: Config) -> int:
    setup_logging(config)
    log = logging.getLogger("main")

    state = StateStore(config.state_file)
    state.load()

    client = CouchClient(config)
    client.ensure_db_reachable(config.db_main)
    client.ensure_db_reachable(config.db_client)

    syncer = SubtreeSync(config=config, state=state, client=client)
    syncer.initialize_crypto_state()

    log.info(
        "Starting subtree sync. db_main=%s db_client=%s subtree=%s mode=%s dry_run=%s gc_interval=%d",
        config.db_main,
        config.db_client,
        config.subtree_prefix,
        config.mode,
        config.dry_run,
        config.gc_interval,
    )

    while True:
        syncer.sync_direction(config.db_main, config.db_client)
        syncer.sync_direction(config.db_client, config.db_main)
        state.save()

        # Increment cycle counter and trigger GC if needed
        syncer.gc_cycle_count += 1
        if syncer.gc_cycle_count >= config.gc_interval:
            syncer.gc_cycle_count = 0
            try:
                gc_stats = syncer.garbage_collect_unused_chunks()
                log.info(
                    "Garbage collection completed: soft_deleted=%d hard_deleted=%d total_chunks=%d",
                    gc_stats.get("soft_deleted", 0),
                    gc_stats.get("hard_deleted", 0),
                    gc_stats.get("chunks_total", 0),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.error("Garbage collection failed: %s", exc)

        if config.mode == "single":
            break

        time.sleep(config.poll_interval_seconds)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync a subtree between two CouchDB databases.")
    parser.add_argument(
        "--healthcheck",
        action="store_true",
        help="Only verify connectivity and credentials.",
    )
    args = parser.parse_args()

    try:
        config = Config.from_env()
        if args.healthcheck:
            return run_healthcheck(config)
        return run_sync(config)
    except Exception as exc:  # pylint: disable=broad-except
        logging.basicConfig(level=logging.ERROR)
        logging.error("Fatal error: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
