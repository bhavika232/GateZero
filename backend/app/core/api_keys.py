"""API-key generation, parsing and verification. Pure functions, no I/O.

Key format:   gz_<prefix>_<secret>
  prefix: 12 hex chars (48 random bits). Not secret. Used to find the DB row in O(1).
  secret: 43 URL-safe chars from secrets.token_urlsafe(32), i.e. 256 random bits.

Storage: we store only HMAC-SHA256(pepper, full_key) as hex.

Why HMAC-SHA256 and not bcrypt/Argon2?
  Slow password hashes exist to protect *low-entropy* human passwords against offline guessing.
  Our keys carry 256 bits of randomness, so guessing is infeasible no matter how fast the hash
  is. A slow hash would only add ~100 ms to every single tool call. The pepper (a server-side
  secret kept outside the DB) adds a second layer: a leaked DB dump alone can't be used to test
  candidate keys.

Why compare with hmac.compare_digest?
  A normal `==` can return as soon as the first differing character is found, which leaks
  timing information about how much of the hash matched. compare_digest takes the same time
  regardless of where the strings differ.
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

KEY_SCHEME = "gz"
PREFIX_HEX_CHARS = 12
SECRET_BYTES = 32

# Anchored, exact-length pattern: rejects anything unexpected before we touch the DB.
_KEY_PATTERN = re.compile(r"^gz_(?P<prefix>[0-9a-f]{12})_(?P<secret>[A-Za-z0-9_-]{43})$")
MAX_KEY_LENGTH = 64  # cheap length check before running the regex on attacker input


@dataclass(frozen=True)
class GeneratedKey:
    plaintext: str  # shown to the operator exactly once, never stored
    prefix: str
    key_hash: str


@dataclass(frozen=True)
class ParsedKey:
    full_key: str
    prefix: str


def hash_key(full_key: str, pepper: str) -> str:
    return hmac.new(pepper.encode(), full_key.encode(), hashlib.sha256).hexdigest()


def generate_key(pepper: str) -> GeneratedKey:
    prefix = secrets.token_hex(PREFIX_HEX_CHARS // 2)
    secret = secrets.token_urlsafe(SECRET_BYTES)
    plaintext = f"{KEY_SCHEME}_{prefix}_{secret}"
    return GeneratedKey(plaintext=plaintext, prefix=prefix, key_hash=hash_key(plaintext, pepper))


def parse_key(candidate: str) -> ParsedKey | None:
    """Return the parsed key, or None if it isn't syntactically a GateZero key."""
    if len(candidate) > MAX_KEY_LENGTH:
        return None
    match = _KEY_PATTERN.fullmatch(candidate)
    if match is None:
        return None
    return ParsedKey(full_key=candidate, prefix=match.group("prefix"))


def verify_key(full_key: str, stored_hash: str, pepper: str) -> bool:
    return hmac.compare_digest(hash_key(full_key, pepper), stored_hash)


# Used when the prefix matches no row: we still compute and compare a hash so that "unknown
# prefix" and "known prefix, wrong secret" take roughly the same time.
DUMMY_HASH = "0" * 64


def fingerprint_prefix(prefix: str) -> str:
    """Short, non-reversible tag for a key prefix, safe to put in audit findings.

    Lets an operator notice "the same revoked key keeps being tried" without storing any part
    of the credential itself.
    """
    return hashlib.sha256(prefix.encode()).hexdigest()[:16]
