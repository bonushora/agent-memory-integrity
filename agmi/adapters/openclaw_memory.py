# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""OpenClaw: an agent's curated long-term memory, MEMORY.md in its workspace.

OpenClaw (npm `openclaw`, MIT) keeps an agent's memory as plain Markdown in
the agent's workspace. MEMORY.md is the curated long-term layer: durable
facts and decisions, one entry per list item, each entry optionally carrying
annotations OpenClaw itself parses (`<!-- importance: N -->`,
`<!-- trigger: ... -->`, `<!-- project: key -->`). The file is injected
into the model's context at the start of a session, and the `memory_get`
tool reads it back on demand. OpenClaw makes no integrity claim for these
files: its security policy describes OpenClaw as local-first infrastructure
for trusted operators, and its memory documentation says the model only
remembers what is saved to disk. This row is in the group that makes no
claim, like the LangGraph checkpointers.

Write path: OpenClaw has no memory-write API. The agent writes MEMORY.md
with its own file tools, so the seed writes the entries the same way, in the
format OpenClaw documents.

Read path: `readAgentMemoryFile` from OpenClaw's public plugin SDK
(`openclaw/plugin-sdk/memory-core-host-runtime-files`), the function behind
the `memory_get` tool, called from a fresh Node process on every read, with
the agent's workspace taken from an OpenClaw config that lists two agents.
A fresh process is a restart: nothing is cached between reads. A read that
throws or returns a status other than "ok" is "rejected"; a read that serves
the file is "accepted", with the served entry count in the detail.

Second context for T6: a second agent with its own workspace. T6 copies one
of that agent's genuine entries over an entry in the first agent's
MEMORY.md. T8 changes an entry's `importance` annotation and leaves its text
alone. T9 restores the first agent's whole workspace from a copy taken before
one more genuine entry was written.

The package is installed with npm into a directory named by
AGMI_OPENCLAW_DIR (`npm install openclaw@2026.10.1`); the adapter refuses any
other version. OpenClaw needs Node 24.16 or later, found on PATH or named by
AGMI_NODE.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

PIN = "2026.10.1"
NODE_ENGINE = (24, 16, 0)
MEASURED_ON = f"openclaw {PIN} (npm)"
SDK_MODULE = "./plugin-sdk/memory-core-host-runtime-files"
CTX, OTHER = "a", "b"
MEMORY_FILE = "MEMORY.md"
ANNOTATION = " <!-- importance: "

HELPER = r"""
import fs from 'node:fs';
const [, , sdkPath] = process.argv;
const sdk = await import(sdkPath);
const ops = JSON.parse(fs.readFileSync(0, 'utf8'));
const out = [];
for (const op of ops) {
  try {
    const r = await sdk.readAgentMemoryFile({ cfg: op.cfg, agentId: op.agentId, relPath: op.relPath });
    out.push({ ok: true, result: r });
  } catch (e) {
    out.push({ ok: false, error: `${e && e.constructor ? e.constructor.name : 'Error'}: ${e && e.message}` });
  }
}
process.stdout.write(JSON.stringify(out));
"""


def openclaw_dir() -> str | None:
    path = os.environ.get("AGMI_OPENCLAW_DIR")
    return os.path.realpath(os.path.expanduser(path)) if path else None


def package_dir() -> Path:
    root = openclaw_dir()
    if not root:
        raise RuntimeError("AGMI_OPENCLAW_DIR is not set (a directory with openclaw installed by npm)")
    pkg = Path(root) / "node_modules" / "openclaw"
    meta = json.loads((pkg / "package.json").read_text(encoding="utf-8"))
    if meta.get("version") != PIN:
        raise RuntimeError(f"openclaw {meta.get('version')} installed, pinned {PIN}; re-measure before re-pinning")
    return pkg


def sdk_entry(pkg: Path) -> Path:
    meta = json.loads((pkg / "package.json").read_text(encoding="utf-8"))
    target = meta["exports"][SDK_MODULE]
    if isinstance(target, dict):
        target = target.get("import") or target.get("default")
    return (pkg / target).resolve()


def node_binary() -> str:
    node = os.environ.get("AGMI_NODE") or shutil.which("node")
    if not node:
        raise RuntimeError("node not found; set AGMI_NODE")
    v = subprocess.run([node, "--version"], capture_output=True, text=True,
                       check=True).stdout.strip().lstrip("v")
    if tuple(int(x) for x in v.split(".")[:3]) < NODE_ENGINE:
        raise RuntimeError(f"node {v} is below the engine openclaw declares (>=24.16.0)")
    return node


def _entry(ctx: str, i: int, importance: int = 3) -> str:
    return f"- agmi-{ctx}-{i}: the limit is {40 + i}{ANNOTATION}{importance} -->"


class OpenClawMemoryAdapter(MemoryAdapter):
    """OpenClaw MEMORY.md, read through the memory_get read path."""

    name = "openclaw-memory-md"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True
    detection_point = "read"

    def __init__(self):
        self._root: str | None = None
        self._pkg = package_dir()
        self._sdk = sdk_entry(self._pkg)
        self._node = node_binary()
        self._helper: str | None = None
        self._seeded = 0

    @staticmethod
    def measured_on() -> str:
        return MEASURED_ON

    # --- lifecycle ---------------------------------------------------------

    def _ws(self, ctx: str) -> Path:
        return Path(self._root) / f"workspace-{ctx}"

    def _cfg(self) -> dict:
        return {"agents": {"list": [{"id": CTX, "workspace": str(self._ws(CTX))},
                                    {"id": OTHER, "workspace": str(self._ws(OTHER))}]}}

    def setup(self) -> None:
        self._root = tempfile.mkdtemp(prefix="agmi-openclaw-")
        for ctx in (CTX, OTHER):
            self._ws(ctx).mkdir()
            (self._ws(ctx) / MEMORY_FILE).write_text("", encoding="utf-8")
        (Path(self._root) / "state").mkdir()
        self._helper = str(Path(self._root) / "agmi-openclaw-read.mjs")
        Path(self._helper).write_text(HELPER, encoding="utf-8")
        self._seeded = 0

    def teardown(self) -> None:
        if self._root:
            shutil.rmtree(self._root, ignore_errors=True)
        self._root = None

    # --- the agent's write path: it writes MEMORY.md with its file tools ------

    def _path(self, ctx: str) -> Path:
        return self._ws(ctx) / MEMORY_FILE

    def _seed_ctx(self, ctx: str, n: int) -> None:
        self._write_lines(ctx, [_entry(ctx, i) for i in range(n)])

    def seed(self, n: int) -> None:
        self._seed_ctx(CTX, n)
        self._seeded = n

    def seed_other(self, n: int) -> None:
        self._seed_ctx(OTHER, n)

    # --- raw access, bypassing OpenClaw -------------------------------------

    def _lines(self, ctx: str) -> list[str]:
        text = self._path(ctx).read_text(encoding="utf-8")
        return [ln for ln in text.split("\n") if ln.strip()]

    def _write_lines(self, ctx: str, lines: list[str]) -> None:
        self._path(ctx).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def _read_ctx(self, ctx: str) -> list[Record]:
        return [Record(seq=i, fields={"ctx": ctx, "line": ln}) for i, ln in enumerate(self._lines(ctx))]

    def read_all_raw(self) -> list[Record]:
        return self._read_ctx(CTX)

    def read_other_raw(self) -> list[Record]:
        return self._read_ctx(OTHER)

    def write_raw(self, record: Record) -> None:
        lines = self._lines(CTX)
        if record.seq < len(lines):
            lines[record.seq] = record.fields["line"]
        else:
            lines.append(record.fields["line"])
        self._write_lines(CTX, lines)

    def delete_raw(self, seq: int) -> None:
        lines = self._lines(CTX)
        del lines[seq]
        self._write_lines(CTX, lines)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        lines = self._lines(CTX)
        lines[victim_seq] = donor.fields["line"]
        self._write_lines(CTX, lines)

    @staticmethod
    def _split(line: str) -> tuple[str, str]:
        body, sep, meta = line.partition(ANNOTATION)
        return body, (sep + meta) if sep else ""

    def read_meta(self, seq: int) -> dict:
        _, meta = self._split(self._lines(CTX)[seq])
        return {"annotation": meta}

    def write_meta(self, seq: int, meta: dict) -> None:
        lines = self._lines(CTX)
        body, old = self._split(lines[seq])
        new = f"{ANNOTATION}10 -->" if meta.get("agmi_meta_tampered") else meta.get("annotation", old)
        lines[seq] = body + new
        self._write_lines(CTX, lines)

    def mutate_payload(self, record: Record) -> Record:
        body, meta = self._split(record.fields["line"])
        record.fields["line"] = body + " [TAMPERED]" + meta
        return record

    def forge_record(self, template: Record) -> Record:
        return Record(seq=template.seq + 1,
                      fields={"ctx": CTX, "line": f"- agmi-forged: the limit is 999{ANNOTATION}3 -->"})

    # --- guard hooks (control C3) -----------------------------------------

    def identity_of(self, record):
        return f"{record.fields['ctx']}:{record.seq}"

    def payload_of(self, record):
        return self._split(record.fields["line"])[0]

    def owner_of(self, record):
        return record.fields["ctx"]

    # --- T9: the first agent's whole workspace rolls back --------------------

    def snapshot_store(self):
        return self._copy_store(self._ws(CTX))

    def restore_store(self, token) -> None:
        self._restore_store(token, self._ws(CTX))
        shutil.rmtree(Path(token).parent, ignore_errors=True)

    def append_genuine(self) -> None:
        lines = self._lines(CTX)
        lines.append(_entry(CTX, len(lines)))
        self._write_lines(CTX, lines)

    # --- the read path ------------------------------------------------------

    def _read(self, agent_id: str) -> dict:
        ops = [{"cfg": self._cfg(), "agentId": agent_id, "relPath": MEMORY_FILE}]
        env = dict(os.environ, OPENCLAW_STATE_DIR=str(Path(self._root) / "state"))
        proc = subprocess.run([self._node, self._helper, self._sdk.as_uri()],
                              input=json.dumps(ops), capture_output=True, text=True,
                              timeout=180, env=env, cwd=self._root)
        if proc.returncode != 0:
            raise RuntimeError(f"node exited {proc.returncode}: {proc.stderr.strip()[-400:]}")
        return json.loads(proc.stdout)[0]

    def read_served(self, agent_id: str = CTX) -> str | None:
        """The text OpenClaw's memory_get read path serves, or None if it refused."""
        out = self._read(agent_id)
        if not out["ok"] or out["result"].get("status") != "ok":
            return None
        return out["result"].get("text", "")

    def reload(self) -> None:
        # Every read is a fresh Node process, which is a restart.
        return None

    def verify(self) -> bool:
        self.verify_detail = None
        out = self._read(CTX)
        if not out["ok"]:
            self.verify_detail = out["error"]
            return False
        result = out["result"]
        if result.get("status") != "ok":
            self.verify_detail = f"memory_get status {result.get('status')}: {json.dumps(result)[:200]}"
            return False
        served = [ln for ln in result.get("text", "").split("\n") if ln.strip()]
        on_disk = self._lines(CTX)
        same = "the edited file as written" if served == on_disk else "content that differs from the file"
        self.verify_detail = f"memory_get served {len(served)} entries, {same}, no error"
        return True
