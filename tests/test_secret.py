"""Secrets at rest: DPAPI on Windows, the system keyring elsewhere, and a clean refusal with neither.

The behaviour under test is the contract callers rely on: `available()` tells the truth about
whether a store exists; when it does, protect/unprotect round-trip and the token never carries
the plaintext; when it does not, both raise SecretUnavailable rather than returning something
that looks like a token.
"""
import sys

import pytest

from netmap import secret

PLAIN = "s3cret-community-éè"  # non-ASCII on purpose: the token path is UTF-8 both ways


def test_available_is_a_string():
    where = secret.available()
    assert isinstance(where, str)
    if sys.platform == "win32":
        assert "DPAPI" in where


@pytest.mark.parametrize("bad", ["", "plain-text", "nope:abc", "dpapi:", "keyring:"])
def test_unprotect_rejects_tokens_it_did_not_issue(bad):
    """Whatever store exists, a token without a payload it issued is refused, never decoded to junk."""
    with pytest.raises(secret.SecretUnavailable):
        secret.unprotect(bad)


def test_round_trip_or_unavailable():
    where = secret.available()
    if not where:
        with pytest.raises(secret.SecretUnavailable):
            secret.protect(PLAIN)
        with pytest.raises(secret.SecretUnavailable):
            secret.unprotect("keyring:0123456789abcdef")
        return
    try:
        token = secret.protect(PLAIN)
    except secret.SecretUnavailable as e:
        # a keyring backend is installed but locked/headless (typical on a CI box): that is the
        # documented "session only" outcome, not a bug
        pytest.skip(f"secret store present but unusable here: {e}")
    assert token.startswith(("dpapi:", "keyring:"))
    assert PLAIN not in token and PLAIN.encode("utf-8").hex() not in token.lower()
    assert secret.unprotect(token) == PLAIN
    # each token is self-describing: the wrong prefix is refused even when a store exists
    with pytest.raises(secret.SecretUnavailable):
        secret.unprotect("nope:" + token.split(":", 1)[1])
