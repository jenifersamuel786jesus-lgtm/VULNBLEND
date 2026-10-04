from threading import Event
import time

import vulblend.services.background_scans as background_scans


def test_scan_is_submitted_as_background_job(monkeypatch):
    started = Event()
    release = Event()
    monkeypatch.setattr(background_scans, "audit", lambda *args, **kwargs: None)

    def fake_run(scan_id, config, app):
        started.set()
        release.wait(timeout=2)
        return {"status": "completed", "findings": []}

    monkeypatch.setattr(background_scans, "run_scan", fake_run)
    assert background_scans.start_scan("scan-live-test", {}, {}) is True
    assert started.wait(timeout=1)
    assert background_scans.is_running("scan-live-test") is True
    release.set()
    for _ in range(20):
        if not background_scans.is_running("scan-live-test"):
            break
        time.sleep(.02)
    assert background_scans.is_running("scan-live-test") is False
