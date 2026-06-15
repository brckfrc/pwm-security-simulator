"""
Vault module.

Implements two vault modes to contrast their security properties:

  - Insecure mode: AES-CTR encryption with no integrity protection.
    KDF parameters are stored in plaintext and not bound to the ciphertext.
    Tampering goes undetected.

  - Secure mode: AES-GCM (AEAD) encryption.
    KDF parameters + vault version are passed as associated data (AAD),
    so they are authenticated even though they are not encrypted.
    Any modification to the ciphertext, tag, or KDF parameters is detected.

Tamper helpers modify vault files in controlled ways for the demo.
"""

import base64
import copy
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from kdf import derive_pbkdf2

KDF_ITERATIONS_DEFAULT = 600_000


class IntegrityError(Exception):
    """Raised when authenticated decryption detects tampering."""


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def _aad_for_vault(meta: dict) -> bytes:
    """
    Build the AAD string that is fed into AES-GCM as associated data.

    The AAD covers every field an attacker might want to modify without
    touching the ciphertext: vault version, KDF type, salt, and iteration count.
    Argon2id params are included when relevant.
    """
    parts = [
        f"version={meta['version']}",
        f"kdf={meta['kdf']['type']}",
        f"salt={meta['kdf']['salt']}",
    ]
    if meta["kdf"]["type"] == "pbkdf2":
        parts.append(f"iterations={meta['kdf']['iterations']}")
    else:
        parts.append(f"time_cost={meta['kdf']['time_cost']}")
        parts.append(f"memory_cost={meta['kdf']['memory_cost']}")
        parts.append(f"parallelism={meta['kdf']['parallelism']}")
    return "|".join(parts).encode()


# ---------------------------------------------------------------------------
# Insecure vault  (AES-CTR, no MAC)
# ---------------------------------------------------------------------------

def encrypt_insecure(plaintext_dict: dict, password: str, path: str | Path) -> dict:
    """
    Encrypt *plaintext_dict* with AES-CTR.

    No integrity mechanism is applied. The KDF parameters are stored in
    plaintext and are NOT cryptographically bound to the ciphertext.
    """
    salt = os.urandom(16)
    key = derive_pbkdf2(password, salt, KDF_ITERATIONS_DEFAULT)
    iv = os.urandom(16)  # AES block size = 16 bytes; used as CTR nonce+counter

    plaintext = json.dumps(plaintext_dict).encode()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    vault: dict[str, Any] = {
        "mode": "insecure-aes-ctr",
        "version": 1,
        "kdf": {
            "type": "pbkdf2",
            "salt": _b64(salt),
            "iterations": KDF_ITERATIONS_DEFAULT,
        },
        "iv": _b64(iv),
        "ciphertext": _b64(ciphertext),
    }
    Path(path).write_text(json.dumps(vault, indent=2))
    return vault


def decrypt_insecure(password: str, path: str | Path) -> dict:
    """
    Decrypt an insecure (AES-CTR) vault.

    Returns the plaintext dict.  If ciphertext bytes were flipped, the
    plaintext bytes are equally flipped (AES-CTR is malleable) and JSON
    parsing may fail.  This is intentional: we return a special dict with
    key ``"_corrupted"`` holding the raw bytes, so the UI can show the
    damage without raising an IntegrityError — because there is no integrity
    check in this mode.
    """
    vault = json.loads(Path(path).read_text())
    salt = _unb64(vault["kdf"]["salt"])
    iterations = vault["kdf"]["iterations"]
    key = derive_pbkdf2(password, salt, iterations)
    iv = _unb64(vault["iv"])
    ciphertext = _unb64(vault["ciphertext"])

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        return json.loads(plaintext)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Tampering corrupted the plaintext; the system does NOT raise an
        # integrity error — it simply yields garbled data, which is the lesson.
        return {"_corrupted": True, "_raw": plaintext.hex()}


# ---------------------------------------------------------------------------
# Secure vault  (AES-GCM / AEAD)
# ---------------------------------------------------------------------------

def encrypt_secure(plaintext_dict: dict, password: str, path: str | Path, version: int = 1) -> dict:
    """
    Encrypt *plaintext_dict* with AES-GCM.

    The vault version and KDF parameters are passed as associated data (AAD)
    so that they are authenticated alongside the ciphertext.  Any modification
    to these fields will cause decryption to fail.
    """
    salt = os.urandom(16)
    key = derive_pbkdf2(password, salt, KDF_ITERATIONS_DEFAULT)
    nonce = os.urandom(12)  # 96-bit nonce recommended for AES-GCM

    meta: dict[str, Any] = {
        "mode": "secure-aes-gcm",
        "version": version,
        "kdf": {
            "type": "pbkdf2",
            "salt": _b64(salt),
            "iterations": KDF_ITERATIONS_DEFAULT,
        },
        "nonce": _b64(nonce),
    }

    aad = _aad_for_vault(meta)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt appends the 16-byte GCM tag to the ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, json.dumps(plaintext_dict).encode(), aad)
    meta["ciphertext"] = _b64(ct_with_tag)

    Path(path).write_text(json.dumps(meta, indent=2))
    return meta


def decrypt_secure(password: str, path: str | Path) -> dict:
    """
    Decrypt a secure (AES-GCM) vault.

    Raises IntegrityError if anything in the vault file (ciphertext, tag, or
    any KDF/version metadata field) has been modified.
    """
    vault = json.loads(Path(path).read_text())
    salt = _unb64(vault["kdf"]["salt"])
    iterations = vault["kdf"]["iterations"]
    key = derive_pbkdf2(password, salt, iterations)
    nonce = _unb64(vault["nonce"])
    ct_with_tag = _unb64(vault["ciphertext"])

    aad = _aad_for_vault(vault)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, aad)
    except InvalidTag as exc:
        raise IntegrityError("Vault integrity check failed.") from exc

    return json.loads(plaintext)


# ---------------------------------------------------------------------------
# Tamper helpers
# ---------------------------------------------------------------------------

def tamper_bitflip(path: str | Path, byte_offset: int = 8) -> str:
    """
    Flip a single bit in the ciphertext.

    In insecure (AES-CTR) mode: because CTR mode is stream-cipher-like,
    flipping bit N in the ciphertext flips the same bit in the plaintext —
    allowing predictable, targeted plaintext modification without the key.

    In secure (AES-GCM) mode: this invalidates the GCM authentication tag,
    so decryption will raise IntegrityError.

    Returns a description of the modification made.
    """
    vault = json.loads(Path(path).read_text())
    raw = bytearray(_unb64(vault["ciphertext"]))
    idx = byte_offset % len(raw)
    original = raw[idx]
    raw[idx] ^= 0xFF  # flip all bits in that byte
    vault["ciphertext"] = _b64(bytes(raw))
    Path(path).write_text(json.dumps(vault, indent=2))
    return f"Flipped byte {idx}: 0x{original:02x} → 0x{raw[idx]:02x}"


def tamper_downgrade_kdf(path: str | Path, low_iterations: int = 1_000) -> str:
    """
    Lower the stored KDF iteration count.

    In insecure mode: the iteration count is used as-is during decryption,
    which weakens the key derivation and makes the vault vulnerable to
    brute-force attacks. The vault still decrypts "successfully" — but with a
    different (wrong) key, producing garbage (or raising a JSON parse error).
    The system does not alert the user that parameters were tampered.

    In secure mode: the KDF parameters are bound via AAD, so the GCM tag
    will not match and decryption raises IntegrityError.

    Returns a description of the modification made.
    """
    vault = json.loads(Path(path).read_text())
    original = vault["kdf"]["iterations"]
    vault["kdf"]["iterations"] = low_iterations
    Path(path).write_text(json.dumps(vault, indent=2))
    return f"KDF iterations: {original:,} → {low_iterations:,}"


def tamper_version_field(path: str | Path, new_version: int = 1) -> str:
    """
    Downgrade the version field in the vault JSON (without touching the ciphertext).

    This simulates a targeted rollback metadata attack: an attacker wants the
    system to treat the current ciphertext as if it were an older version, e.g.
    to bypass version-gated features or confuse the integrity model.

    In insecure mode: the field changes silently; the vault decrypts with the
    altered version.

    In secure mode: the version field is part of AAD.  Changing it makes the
    AAD diverge from what was used at encryption time, so the GCM tag is
    invalid and decryption raises IntegrityError.

    Returns a description of the modification made.
    """
    vault = json.loads(Path(path).read_text())
    original = vault.get("version", "?")
    vault["version"] = new_version
    Path(path).write_text(json.dumps(vault, indent=2))
    return f"version field: {original} → {new_version}"


def tamper_replay(old_vault_json: str, path: str | Path) -> str:
    """
    Replace the current vault with an older saved snapshot (full file swap).

    In insecure mode: the old vault decrypts without complaint — a rollback
    attack succeeds silently.

    In secure mode: because every field in the old snapshot was validly
    authenticated at the time it was written, decryption of the old vault
    also succeeds at the crypto layer.  Full-vault replay protection requires
    an *external* monotonic counter (e.g. a server-side version tracker) to
    compare against.  The version-in-AAD approach defends against *in-place*
    version-field tampering (see tamper_version_field), not against replacing
    the entire vault file with an intact older copy.

    *old_vault_json* is the raw JSON string of the snapshot to restore.

    Returns a description of the modification made.
    """
    current = json.loads(Path(path).read_text())
    old = json.loads(old_vault_json)
    Path(path).write_text(json.dumps(old, indent=2))
    return f"Vault file replaced with snapshot v{old.get('version', '?')} (was v{current.get('version', '?')})"


def tamper_metadata(path: str | Path) -> str:
    """
    Modify an unencrypted metadata field (e.g. the mode label string).

    This illustrates that even non-sensitive metadata can be changed silently
    in the insecure design, while in the secure design it is caught if it is
    part of AAD.  The mode label itself is NOT in AAD, so this succeeds in
    both modes — demonstrating that only fields explicitly covered by AAD are
    protected.

    Returns a description of the modification made.
    """
    vault = json.loads(Path(path).read_text())
    original = vault.get("mode", "")
    vault["mode"] = original + " (tampered)"
    Path(path).write_text(json.dumps(vault, indent=2))
    return f"mode field: '{original}' → '{vault['mode']}'"


def load_vault_json(path: str | Path) -> str:
    """Return the raw vault JSON string (for display or snapshotting)."""
    return Path(path).read_text()


def save_vault_snapshot(path: str | Path) -> str:
    """Return the raw JSON of the current vault file (to be passed to tamper_replay later)."""
    return Path(path).read_text()
