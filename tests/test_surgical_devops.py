# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Pinned real-API measurement for Surgical DevOps G7."""

import copy
import os

import pytest

from agmi.adapters.surgical_devops import (
    EXPECTED_NODE_VERSION,
    EXPECTED_SDO_COMMIT,
    EXPECTED_SDO_VERSION,
    SurgicalDevOpsAdapter,
)
from agmi.attacks.at_rest import (
    ALL_AT_REST_ATTACKS,
    AT_REST_ATTACKS_WITH_SNAPSHOT,
    CrossContextReplayAttack,
    SnapshotRollbackAttack,
)
from agmi.attacks.guard import snapshot

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGMI_SDO_REPO"),
    reason="AGMI_SDO_REPO is required for the optional Surgical DevOps row",
)

MEASURED_ON = (
    "surgical-dev-ops 2.6.0-rc.6 at f267cf3, Node 24.18.0"
)


def test_sdo_and_node_are_exactly_pinned():
    adapter = SurgicalDevOpsAdapter()
    assert adapter.pin == {
        "commit": EXPECTED_SDO_COMMIT,
        "node": EXPECTED_NODE_VERSION,
        "packageVersion": EXPECTED_SDO_VERSION,
    }
    assert adapter.measured_on() == MEASURED_ON


def test_clean_g7_is_seeded_and_verified_by_real_sdo_apis():
    adapter = SurgicalDevOpsAdapter()
    adapter.setup()
    try:
        adapter.seed(5)
        assert adapter.verify() is True
        adapter.reload()
        assert adapter.verify() is True
        records = adapter.read_all_raw()
        assert len(records) == 5
        assert all(adapter.owner_of(record) == adapter._primary_identity for record in records)
        assert all(record.fields["envelope"]["payload"]["state"] == "CLAIMED"
                   for record in records)
    finally:
        adapter.teardown()


@pytest.mark.parametrize("attack_cls", ALL_AT_REST_ATTACKS,
                         ids=lambda cls: cls().name)
def test_t1_through_t8_edit_only_g7_and_are_rejected_on_read(attack_cls):
    adapter = SurgicalDevOpsAdapter()
    attack = attack_cls()
    adapter.setup()
    try:
        adapter.seed(attack.seed_count)
        support_before = adapter.artifact_fingerprints()
        before = snapshot(adapter, adapter.read_all_raw())
        attack._ctx = {}
        attack.tamper(adapter)
        after = snapshot(adapter, adapter.read_all_raw())
        attack.check_landed(adapter, before, after)
        support_after = adapter.artifact_fingerprints()

        assert support_after["g7"] != support_before["g7"]
        assert support_after["context"] == support_before["context"]
        assert support_after["identity"] == support_before["identity"]
        assert support_after["witness"] == support_before["witness"]

        adapter.reload()
        assert adapter.verify() is False, f"{attack.name}: served as genuine on {MEASURED_ON}"
        assert adapter.verify_detail
    finally:
        adapter.teardown()


def test_t6_replays_the_genuine_donor_envelope_byte_for_byte():
    adapter = SurgicalDevOpsAdapter()
    attack = CrossContextReplayAttack()
    adapter.setup()
    try:
        adapter.seed(attack.seed_count)
        donor = adapter.read_other_raw()[-1]
        victim = adapter.read_all_raw()[-1]
        donor_bytes = donor.fields["envelopeBytes"]
        donor_envelope = copy.deepcopy(donor.fields["envelope"])
        donor_identity = adapter.identity_of(donor)
        victim_identity = adapter.identity_of(victim)
        before = snapshot(adapter, adapter.read_all_raw())

        attack._ctx = {}
        attack.tamper(adapter)
        after_records = adapter.read_all_raw()
        after = snapshot(adapter, after_records)
        attack.check_landed(adapter, before, after)

        replayed = after_records[-1]
        donor_after = adapter.read_other_raw()[-1]
        assert replayed.fields["envelopeBytes"] == donor_bytes
        assert replayed.fields["envelope"] == donor_envelope
        assert donor_after.fields["envelopeBytes"] == donor_bytes
        assert adapter.identity_of(replayed) == victim_identity
        assert adapter.identity_of(donor_after) == donor_identity
        assert adapter.owner_of(replayed) == adapter._primary_identity
        assert adapter.owner_of(donor_after) == adapter._other_identity
        assert adapter.read_meta(replayed.seq)["physicalWorkspaceIdentity"] == adapter._other_identity

        adapter.reload()
        assert adapter.verify() is False
        assert adapter.verify_detail
    finally:
        adapter.teardown()


def test_all_nine_have_guarded_real_measurements_and_are_rejected():
    for attack_cls in AT_REST_ATTACKS_WITH_SNAPSHOT:
        adapter = SurgicalDevOpsAdapter()
        result = attack_cls().run(adapter)
        assert result.error is None, f"{result.attack} errored: {result.error}"
        assert result.guard is None, f"{result.attack} did not land: {result.guard}"
        assert result.detected, f"{result.attack}: served as genuine on {MEASURED_ON}"
        assert adapter.verify_detail


def test_t9_restores_only_g7_and_leaves_the_witness_advanced():
    adapter = SurgicalDevOpsAdapter()
    adapter.setup()
    try:
        adapter.seed(5)
        before = adapter.artifact_fingerprints()
        token = adapter.snapshot_store()
        adapter.append_genuine()
        advanced = adapter.artifact_fingerprints()
        assert advanced["g7"] != before["g7"]
        assert advanced["witness"] != before["witness"]
        assert advanced["context"] == before["context"]
        assert advanced["identity"] == before["identity"]

        adapter.restore_store(token)
        restored = adapter.artifact_fingerprints()
        assert restored["g7"] == before["g7"]
        assert restored["witness"] == advanced["witness"]
        assert restored["context"] == advanced["context"]
        assert restored["identity"] == advanced["identity"]
        assert adapter.verify() is False
        assert "witness" in (adapter.verify_detail or "").lower()
    finally:
        adapter.teardown()


def test_t9_attack_contract_runs_without_adapter_shortcuts():
    adapter = SurgicalDevOpsAdapter()
    result = SnapshotRollbackAttack().run(adapter)
    assert result.error is None and result.guard is None, (result.error, result.guard)
    assert result.detected
