"""The curated factory-default SNMP community list and its helpers."""
from subnetsleuth.communities import (
    DEFAULT_COMMUNITIES,
    default_community_creds,
    default_label,
    is_default_community,
)


def test_list_is_curated_and_documented():
    values = [c for c, _, _ in DEFAULT_COMMUNITIES]
    # the two universal defaults are present and come first
    assert values[0] == "public" and values[1] == "private"
    # curated, not a spraying word-list
    assert 2 <= len(DEFAULT_COMMUNITIES) <= 30
    assert len(values) == len(set(values)), "no duplicate communities"
    # every entry is (community, access, note), all non-empty, access is read/write
    for community, access, note in DEFAULT_COMMUNITIES:
        assert community and note
        assert access in ("read", "write")


def test_default_community_creds_are_v2c_and_labelled():
    creds = default_community_creds()
    assert len(creds) == len(DEFAULT_COMMUNITIES)
    assert all(c.kind == "v2c" for c in creds)
    # public/private tried first, in list order
    assert creds[0].community == "public" and creds[1].community == "private"
    # the label records which default answered, without exposing a secret of the user's
    assert all(c.label == default_label(c.community) for c in creds)
    assert is_default_community(creds[0].label)


def test_default_community_creds_can_add_v1():
    creds = default_community_creds(kinds=("v2c", "v1"))
    assert len(creds) == 2 * len(DEFAULT_COMMUNITIES)
    assert {c.kind for c in creds} == {"v1", "v2c"}


def test_is_default_community_matches_labels_and_legacy_values():
    # auto-added default credential
    assert is_default_community("default community 'public'")
    assert is_default_community(default_label("ilmi"))
    # legacy / bare-value labels (old projects stored the community as the label)
    assert is_default_community("public")
    assert is_default_community("PRIVATE")  # case-insensitive
    # a credential the user named themselves is not a default
    assert not is_default_community("corp-monitoring")
    assert not is_default_community("v3: readonly")
    assert not is_default_community("")
    assert not is_default_community(None)
