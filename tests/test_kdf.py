"""Tests for the KDF module: determinism, parameter sensitivity, benchmark shape."""

import kdf


def test_pbkdf2_deterministic_and_length():
    salt = b"x" * 16
    k1 = kdf.derive_pbkdf2("pw", salt, 1000)
    k2 = kdf.derive_pbkdf2("pw", salt, 1000)
    assert k1 == k2
    assert len(k1) == kdf.KEY_LENGTH == 32


def test_pbkdf2_iterations_change_key():
    salt = b"x" * 16
    assert kdf.derive_pbkdf2("pw", salt, 1000) != kdf.derive_pbkdf2("pw", salt, 2000)


def test_argon2id_deterministic_and_length():
    salt = b"y" * 16
    k1 = kdf.derive_argon2id("pw", salt)
    k2 = kdf.derive_argon2id("pw", salt)
    assert k1 == k2
    assert len(k1) == 32


def test_argon2id_memory_cost_changes_key():
    salt = b"y" * 16
    assert kdf.derive_argon2id("pw", salt, memory_cost=8) != kdf.derive_argon2id(
        "pw", salt, memory_cost=16
    )


def test_benchmark_shape():
    results = kdf.benchmark("pw")
    labels = [r.label for r in results]
    assert sum("PBKDF2" in label for label in labels) == 3
    assert any("Argon2id" in label for label in labels)
    assert all(r.elapsed_ms >= 0 for r in results)
