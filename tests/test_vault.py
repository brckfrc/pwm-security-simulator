"""
Tests for the vault module.

Each test runs against a fresh temp vault file (tmp_path) so nothing in
vault_samples/ is touched. The secure-mode tests assert that tampering is
detected (IntegrityError); the insecure-mode tests assert that the same
tampering goes *undetected* — which is the security lesson of the project.
"""

import pytest

import vault as v

DATA = {
    "website": "example.com",
    "username": "alice@example.com",
    "password": "SuperSecret!42",
    "notes": "Main account",
}
PW = "correct-horse-battery-staple"


@pytest.fixture(params=["pbkdf2", "argon2id"])
def kdf_type(request):
    """Run KDF-agnostic tests against both supported key derivation functions."""
    return request.param


# --- Round-trips --------------------------------------------------------------

def test_insecure_roundtrip(tmp_path, kdf_type):
    p = tmp_path / "insecure.json"
    v.encrypt_insecure(DATA, PW, p, kdf_type=kdf_type)
    assert v.decrypt_insecure(PW, p) == DATA


def test_secure_roundtrip(tmp_path, kdf_type):
    p = tmp_path / "secure.json"
    v.encrypt_secure(DATA, PW, p, version=1, kdf_type=kdf_type)
    assert v.decrypt_secure(PW, p) == DATA


# --- Secure mode: tampering must be detected ----------------------------------

def test_secure_bitflip_detected(tmp_path, kdf_type):
    p = tmp_path / "secure.json"
    v.encrypt_secure(DATA, PW, p, kdf_type=kdf_type)
    v.tamper_bitflip(p)
    with pytest.raises(v.IntegrityError):
        v.decrypt_secure(PW, p)


def test_secure_kdf_downgrade_detected(tmp_path, kdf_type):
    p = tmp_path / "secure.json"
    v.encrypt_secure(DATA, PW, p, kdf_type=kdf_type)
    v.tamper_downgrade_kdf(p)
    with pytest.raises(v.IntegrityError):
        v.decrypt_secure(PW, p)


def test_secure_version_field_detected(tmp_path, kdf_type):
    p = tmp_path / "secure.json"
    v.encrypt_secure(DATA, PW, p, version=1, kdf_type=kdf_type)
    v.tamper_version_field(p, new_version=0)
    with pytest.raises(v.IntegrityError):
        v.decrypt_secure(PW, p)


# --- Insecure mode: same tampering goes undetected ----------------------------

def test_insecure_bitflip_undetected(tmp_path):
    p = tmp_path / "insecure.json"
    v.encrypt_insecure(DATA, PW, p)
    v.tamper_bitflip(p)  # default 0xFF mask garbles the JSON, but no error is raised
    result = v.decrypt_insecure(PW, p)
    assert result != DATA  # corrupted/changed, yet no IntegrityError


def test_insecure_targeted_bitflip_is_predictable(tmp_path):
    p = tmp_path / "insecure.json"
    v.encrypt_insecure(DATA, PW, p)
    offset = v.field_value_letter_offset(DATA, "password")
    v.tamper_bitflip(p, byte_offset=offset, mask=0x20)
    result = v.decrypt_insecure(PW, p)
    # AES-CTR malleability: only the first letter's case flips, rest untouched.
    assert result["password"] == "s" + DATA["password"][1:]


def test_insecure_kdf_downgrade_undetected(tmp_path):
    p = tmp_path / "insecure.json"
    v.encrypt_insecure(DATA, PW, p)
    v.tamper_downgrade_kdf(p)
    result = v.decrypt_insecure(PW, p)  # wrong key -> garbage, but no error
    assert result != DATA


# --- Limits of AAD ------------------------------------------------------------

def test_metadata_not_in_aad_passes_secure(tmp_path):
    # The 'mode' label is intentionally NOT in AAD, so secure decrypt still works.
    p = tmp_path / "secure.json"
    v.encrypt_secure(DATA, PW, p)
    v.tamper_metadata(p)
    assert v.decrypt_secure(PW, p) == DATA


def test_full_file_replay_undetected_in_secure(tmp_path):
    # Known limitation documented in the report: AAD cannot stop a full-file
    # rollback to an intact, validly-encrypted older snapshot.
    p = tmp_path / "secure.json"
    v.encrypt_secure(DATA, PW, p, version=2)
    old_snapshot = v.save_vault_snapshot(p)
    v.encrypt_secure(DATA, PW, p, version=3)  # newer state on disk
    v.tamper_replay(old_snapshot, p)          # roll back to v2
    assert v.decrypt_secure(PW, p) == DATA     # decrypts -> replay NOT detected


def test_unknown_kdf_rejected(tmp_path):
    with pytest.raises(ValueError):
        v.encrypt_secure(DATA, PW, tmp_path / "x.json", kdf_type="bogus")
