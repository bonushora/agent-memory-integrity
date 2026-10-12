# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for OpenClaw's MEMORY.md.

Runs only when AGMI_OPENCLAW_DIR names a directory with openclaw installed
by npm (`npm install openclaw@2026.10.1`) and Node 24.16 or later is on PATH
or named by AGMI_NODE. The read path is OpenClaw's own memory_get function,
run in a fresh Node process for every read."""

import os

import pytest

if not os.environ.get("AGMI_OPENCLAW_DIR"):
    pytest.skip("AGMI_OPENCLAW_DIR not set", allow_module_level=True)

from agmi.adapters.openclaw_memory import PIN, OpenClawMemoryAdapter, package_dir  # noqa: E402
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_SNAPSHOT  # noqa: E402


def test_installed_version_is_the_pinned_one():
    import json
    meta = json.loads((package_dir() / "package.json").read_text(encoding="utf-8"))
    assert meta["version"] == PIN == "2026.10.1"


def test_clean_store_is_served_whole():
    a = OpenClawMemoryAdapter()
    a.setup()
    try:
        a.seed(5)
        assert a.verify() is True
        served = a.read_served().split("\n")
        assert served == a._lines("a") and len(served) == 5
    finally:
        a.teardown()


def test_each_agent_reads_only_its_own_workspace():
    a = OpenClawMemoryAdapter()
    a.setup()
    try:
        a.seed(5)
        a.seed_other(5)
        assert "agmi-b-" not in a.read_served("a")
        assert "agmi-a-" not in a.read_served("b")
    finally:
        a.teardown()


def test_all_nine_edits_are_served_as_genuine():
    seen = set()
    for cls in AT_REST_ATTACKS_WITH_SNAPSHOT:
        r = cls().run(OpenClawMemoryAdapter())
        seen.add(r.attack)
        assert r.error is None, f"{r.attack}: {r.error}"
        assert r.detected is False, f"{r.attack} moved at openclaw {PIN}; re-measure"
    assert len(seen) == 9


def test_tampered_entry_reaches_the_model_unchanged():
    a = OpenClawMemoryAdapter()
    a.setup()
    try:
        a.seed(5)
        a.seed_other(5)
        rec = a.read_all_raw()[2]
        a.write_raw(a.mutate_payload(rec))
        a.replay_onto(3, a.read_other_raw()[1])
        a.write_meta(4, {"agmi_meta_tampered": True})
        served = a.read_served()
        assert "agmi-a-2: the limit is 42 [TAMPERED]" in served
        assert "agmi-b-1: the limit is 41" in served
        assert "agmi-a-4: the limit is 44 <!-- importance: 10 -->" in served
    finally:
        a.teardown()
