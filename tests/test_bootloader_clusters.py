"""Cluster registry tests — the cluster-membership substrate (2026-08-06).

Registry-level tests (no HTTP server): register/heartbeat/lease-expiry/
orphan-reap/recovery/projection hygiene. The server wiring is exercised
by the config-presence gate the whole server already uses; the substrate
behaviors are what need proving here.
"""

from __future__ import annotations

import json

import pytest

from recto.bootloader.clusters import (
    ClusterRegistry,
    ClusterRegistryError,
)


@pytest.fixture()
def registry(tmp_path):
    return ClusterRegistry(
        tmp_path / "clusters.json",
        projection_path=tmp_path / "clusters-projection.json",
        default_lease_ttl_seconds=60,
    )


def test_register_returns_token_once_and_persists_only_hash(registry, tmp_path):
    rec, token = registry.register(region="ncus", ordinal="01", color="blue")
    assert rec.cluster_id == "ncus-01-blue"
    assert rec.status == "active"
    assert token  # returned exactly once...
    raw = json.loads((tmp_path / "clusters.json").read_text())
    (stored,) = raw["clusters"]
    assert token not in json.dumps(raw)  # ...and never at rest (law #3)
    assert stored["heartbeat_token_sha256"] != token
    assert len(stored["heartbeat_token_sha256"]) == 64


def test_projection_never_contains_token_material(registry, tmp_path):
    _, token = registry.register(region="ncus", ordinal="01", color="blue")
    proj = json.loads((tmp_path / "clusters-projection.json").read_text())
    dumped = json.dumps(proj)
    assert token not in dumped
    assert "heartbeat_token_sha256" not in dumped  # law #1: pointers only
    assert proj["clusters"][0]["cluster_id"] == "ncus-01-blue"


def test_heartbeat_renews_lease_and_bad_token_rejected(registry):
    rec, token = registry.register(region="ncus", ordinal="01", color="blue")
    before = rec.last_heartbeat_unix
    renewed = registry.heartbeat("ncus-01-blue", token)
    assert renewed.last_heartbeat_unix >= before
    with pytest.raises(ClusterRegistryError):
        registry.heartbeat("ncus-01-blue", "wrong-token")


def test_lapsed_lease_reads_orphaned_and_reap_persists(registry, tmp_path):
    rec, _token = registry.register(region="ncus", ordinal="01", color="blue")
    lapsed = rec.last_heartbeat_unix + rec.lease_ttl_seconds + 1
    # Lazy detection: effective status flips before any write (law #2).
    assert rec.effective_status(lapsed) == "orphaned"
    newly = registry.reap(now_unix=lapsed)
    assert newly == ["ncus-01-blue"]
    raw = json.loads((tmp_path / "clusters.json").read_text())
    assert raw["clusters"][0]["status"] == "orphaned"
    # Idempotent.
    assert registry.reap(now_unix=lapsed) == []


def test_orphan_recovers_on_heartbeat_but_retired_stays_dead(registry):
    rec, token = registry.register(region="ncus", ordinal="01", color="blue")
    lapsed = rec.last_heartbeat_unix + rec.lease_ttl_seconds + 1
    registry.reap(now_unix=lapsed)
    recovered = registry.heartbeat("ncus-01-blue", token)
    assert recovered.status == "active"  # presumed dead, not sentenced
    registry.retire("ncus-01-blue", token, reason="drained")
    with pytest.raises(ClusterRegistryError):
        registry.heartbeat("ncus-01-blue", token)  # retirement is final


def test_duplicate_active_id_refused_but_retired_id_respawnable(registry):
    _, token = registry.register(region="ncus", ordinal="01", color="blue")
    with pytest.raises(ClusterRegistryError):
        registry.register(region="ncus", ordinal="01", color="blue")
    registry.retire("ncus-01-blue", token, reason="replaced")
    rec2, token2 = registry.register(region="ncus", ordinal="01", color="blue")
    assert rec2.status == "active"
    assert token2 != token


def test_registry_survives_reload(registry, tmp_path):
    _, token = registry.register(
        region="ncus", ordinal="01", color="blue",
        endpoints={"web": "https://ncus-01-blue.internal"},
    )
    reloaded = ClusterRegistry(tmp_path / "clusters.json")
    assert reloaded.list_clusters()[0]["endpoints"]["web"].endswith("internal")
    # Token authenticates against the reloaded store too.
    reloaded.heartbeat("ncus-01-blue", token)
