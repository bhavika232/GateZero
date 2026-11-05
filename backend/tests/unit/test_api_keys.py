"""Unit tests for key generation, parsing and verification. No database needed."""

import pytest

from app.core.api_keys import (
    fingerprint_prefix,
    generate_key,
    hash_key,
    parse_key,
    verify_key,
)

PEPPER = "unit-test-pepper-not-a-real-secret-000000"


def test_generated_key_round_trips():
    key = generate_key(PEPPER)
    parsed = parse_key(key.plaintext)
    assert parsed is not None
    assert parsed.prefix == key.prefix
    assert verify_key(parsed.full_key, key.key_hash, PEPPER)


def test_keys_are_unique():
    assert len({generate_key(PEPPER).plaintext for _ in range(200)}) == 200


def test_stored_hash_does_not_contain_key_material():
    key = generate_key(PEPPER)
    secret_part = key.plaintext.split("_", 2)[2]
    assert secret_part not in key.key_hash
    assert len(key.key_hash) == 64


def test_wrong_secret_fails():
    key = generate_key(PEPPER)
    tampered = key.plaintext[:-1] + ("A" if key.plaintext[-1] != "A" else "B")
    assert not verify_key(tampered, key.key_hash, PEPPER)


def test_wrong_pepper_fails():
    """A DB dump alone (without the pepper) can't verify keys."""
    key = generate_key(PEPPER)
    assert not verify_key(key.plaintext, key.key_hash, "some-other-pepper-value-1234567890")


def test_hash_is_deterministic():
    assert hash_key("gz_x", PEPPER) == hash_key("gz_x", PEPPER)


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "gz_",
        "Bearer gz_0123456789ab_" + "a" * 43,  # scheme included by mistake
        "xx_0123456789ab_" + "a" * 43,  # wrong scheme
        "gz_0123456789AB_" + "a" * 43,  # uppercase hex prefix
        "gz_0123456789a_" + "a" * 43,  # prefix too short
        "gz_0123456789ab_" + "a" * 42,  # secret too short
        "gz_0123456789ab_" + "a" * 44,  # secret too long
        "gz_0123456789ab_" + "a" * 42 + "!",  # character outside the alphabet
        "gz_0123456789ab_" + "a" * 43 + "\n",  # trailing newline
        " gz_0123456789ab_" + "a" * 43,  # leading space
        "gz_0123456789ab_" + "a" * 10_000,  # huge input
    ],
)
def test_parse_rejects_malformed_keys(candidate):
    assert parse_key(candidate) is None


def test_fingerprint_hides_prefix():
    fp = fingerprint_prefix("0123456789ab")
    assert fp == fingerprint_prefix("0123456789ab")
    assert "0123456789ab" not in fp
    assert len(fp) == 16
