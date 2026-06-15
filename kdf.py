"""
KDF (Key Derivation Function) module.

Provides PBKDF2-HMAC-SHA256 and Argon2id key derivation, plus a benchmark
that compares their performance for the Streamlit UI.
"""

import os
import time
from typing import NamedTuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import argon2.low_level as argon2_ll

KEY_LENGTH = 32  # 256-bit key


def derive_pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    """Derive a 256-bit key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())


def derive_argon2id(
    password: str,
    salt: bytes,
    time_cost: int = 3,
    memory_cost: int = 65536,  # 64 MiB
    parallelism: int = 1,
) -> bytes:
    """Derive a 256-bit key using Argon2id (memory-hard KDF)."""
    return argon2_ll.hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_LENGTH,
        type=argon2_ll.Type.ID,
    )


class BenchmarkResult(NamedTuple):
    label: str
    iterations_or_params: str
    elapsed_ms: float
    key_hex: str


def benchmark(password: str) -> list[BenchmarkResult]:
    """
    Run key derivation for several PBKDF2 configurations and one Argon2id
    configuration. Returns timing results for UI display.
    """
    salt = os.urandom(16)
    results: list[BenchmarkResult] = []

    pbkdf2_configs = [
        (1_000, "PBKDF2 (1,000 iter)"),
        (100_000, "PBKDF2 (100,000 iter)"),
        (600_000, "PBKDF2 (600,000 iter)"),
    ]
    for iterations, label in pbkdf2_configs:
        t0 = time.perf_counter()
        key = derive_pbkdf2(password, salt, iterations)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        results.append(
            BenchmarkResult(
                label=label,
                iterations_or_params=f"{iterations:,} iterations",
                elapsed_ms=round(elapsed_ms, 2),
                key_hex=key.hex()[:16] + "…",
            )
        )

    argon2_time_cost = 3
    argon2_memory_cost = 65536  # 64 MiB
    argon2_parallelism = 1
    t0 = time.perf_counter()
    key = derive_argon2id(password, salt, argon2_time_cost, argon2_memory_cost, argon2_parallelism)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    results.append(
        BenchmarkResult(
            label="Argon2id",
            iterations_or_params=f"t={argon2_time_cost}, m={argon2_memory_cost} KiB, p={argon2_parallelism}",
            elapsed_ms=round(elapsed_ms, 2),
            key_hex=key.hex()[:16] + "…",
        )
    )

    return results
