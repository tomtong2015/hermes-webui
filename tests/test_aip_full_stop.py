"""AIP Full Stop (api/background_process.py + /api/chat/cancel).

A user Stop must end everything the session set in motion — sibling wakeup
streams, background processes, queued and deferred wakeups — instead of just
the visible stream. These tests cover the HWUI-side state teardown and the
grace-window gate; the process-kill half lives in the agent's registry
(tools/process_registry.full_stop) and is tested there.
"""

import time

import pytest

from api import config as _cfg
from api.background_process import (
    FULL_STOP_GRACE_SECS,
    _FULL_STOPPED_AT,
    _FULL_STOPPED_LOCK,
    _recently_full_stopped,
    _start_server_side_wakeup_turn,
    full_stop_session,
)

SID = "sess-full-stop-test"


@pytest.fixture(autouse=True)
def _clean_state():
    yield
    with _FULL_STOPPED_LOCK:
        _FULL_STOPPED_AT.pop(SID, None)
    with _cfg.DEFERRED_PROCESS_WAKEUPS_LOCK:
        _cfg.DEFERRED_PROCESS_WAKEUPS.pop(SID, None)
    _cfg.PENDING_BG_TASK_COMPLETIONS.discard(SID)
    with _cfg.PROCESS_SESSION_INDEX_LOCK:
        for k in [k for k, v in _cfg.PROCESS_SESSION_INDEX.items() if v == SID]:
            _cfg.PROCESS_SESSION_INDEX.pop(k, None)


def test_full_stop_drops_deferred_and_pending():
    with _cfg.DEFERRED_PROCESS_WAKEUPS_LOCK:
        _cfg.DEFERRED_PROCESS_WAKEUPS[SID] = [
            {"process_id": "proc_1", "wakeup_prompt": "[IMPORTANT: ...]"}
        ]
    _cfg.PENDING_BG_TASK_COMPLETIONS.add(SID)

    summary = full_stop_session(SID)

    assert summary["deferred_dropped"] == 1
    with _cfg.DEFERRED_PROCESS_WAKEUPS_LOCK:
        assert SID not in _cfg.DEFERRED_PROCESS_WAKEUPS
    assert SID not in _cfg.PENDING_BG_TASK_COMPLETIONS


def test_full_stop_stamps_grace_window():
    assert not _recently_full_stopped(SID)
    full_stop_session(SID)
    assert _recently_full_stopped(SID)
    # Expired stamp lifts the gate.
    with _FULL_STOPPED_LOCK:
        _FULL_STOPPED_AT[SID] = time.monotonic() - (FULL_STOP_GRACE_SECS + 1)
    assert not _recently_full_stopped(SID)


def test_full_stop_empty_session_id_is_noop():
    assert full_stop_session("") == {}
    assert full_stop_session(None) == {}


def test_wakeup_turn_suppressed_during_grace_window(monkeypatch):
    calls = []

    import api.routes as routes_mod

    monkeypatch.setattr(
        routes_mod,
        "start_session_turn",
        lambda *a, **kw: calls.append(a) or {"_status": 200},
        raising=True,
    )

    full_stop_session(SID)
    _start_server_side_wakeup_turn(SID, "[IMPORTANT: ghost]", process_id="proc_g")
    time.sleep(0.3)  # would-be daemon thread dispatch window
    assert calls == []

    # Outside the grace window the same call goes through.
    with _FULL_STOPPED_LOCK:
        _FULL_STOPPED_AT[SID] = time.monotonic() - (FULL_STOP_GRACE_SECS + 1)
    _start_server_side_wakeup_turn(SID, "[IMPORTANT: real]", process_id="proc_r")
    deadline = time.time() + 5
    while not calls and time.time() < deadline:
        time.sleep(0.05)
    assert len(calls) == 1
