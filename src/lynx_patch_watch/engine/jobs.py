"""Scan job queue: DB-backed queue + serial worker with per-project file locks.

- The web app enqueues jobs (scan_jobs); ``lpw serve`` runs a background worker
  that executes them serially.
- Each project is guarded by an fcntl file lock so a CLI ``lpw scan`` cannot
  race the worker on the same git mirror.
- On startup, jobs left ``running`` by a previous process are marked failed.
"""

from __future__ import annotations

import errno
import fcntl
import logging
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from lynx_patch_watch.engine.orchestrator import scan_project
from lynx_patch_watch.engine.rules import RuleSet
from lynx_patch_watch.store import Store

logger = logging.getLogger(__name__)


class ProjectLock:
    """Cross-process advisory lock for one project (fcntl on a lock file)."""

    def __init__(self, locks_dir: Path, project_id: str) -> None:
        self.locks_dir = Path(locks_dir)
        self.project_id = project_id
        self._fh = None

    def acquire(self, timeout: float = 0.0) -> bool:
        self.locks_dir.mkdir(parents=True, exist_ok=True)
        path = self.locks_dir / f"{self.project_id}.lock"
        self._fh = open(path, "w")
        deadline = time.time() + max(0.0, timeout)
        while True:
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.time() >= deadline:
                    self._fh.close()
                    self._fh = None
                    return False
                time.sleep(0.2)

    def release(self) -> None:
        if self._fh is not None:
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            finally:
                self._fh.close()
                self._fh = None

    @contextmanager
    def held(self, timeout: float = 0.0) -> Iterator[None]:
        if not self.acquire(timeout=timeout):
            raise ProjectLockError(f"project {self.project_id} is locked by another scan")
        try:
            yield
        finally:
            self.release()


class ProjectLockError(RuntimeError):
    pass


class ScanWorker:
    """Serial background worker that drains the scan_jobs table."""

    def __init__(self, store: Store, *, ruleset: RuleSet, settings: Any, locks_dir: Path) -> None:
        self.store = store
        self.ruleset = ruleset
        self.settings = settings
        self.locks_dir = Path(locks_dir)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._ruleset_loader = None  # optional callable to reload rules each cycle

    def set_ruleset_loader(self, loader) -> None:
        self._ruleset_loader = loader

    def start(self) -> None:
        stale = self.store.fail_stale_running_jobs()
        if stale:
            logger.info("marked %d stale running scan job(s) as failed", stale)
        self._thread = threading.Thread(target=self._loop, name="lpw-scan-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            job = self.store.next_queued_job()
            if job is None:
                self._stop.wait(1.0)
                continue
            self.run_job(job)

    def run_job(self, job: dict[str, Any]) -> None:
        job_id = job["id"]
        project_id = job["project_id"]
        project = self.store.get_project(project_id)
        if project is None or not project.get("enabled", True):
            self.store.mark_job_done(job_id, "failed", error="project missing or disabled")
            return
        if self._ruleset_loader is not None:
            try:
                self.ruleset = self._ruleset_loader()
            except Exception as exc:  # noqa: BLE001
                logger.warning("ruleset reload failed, using cached: %s", exc)

        lock = ProjectLock(self.locks_dir, project_id)
        try:
            with lock.held(timeout=30.0):
                self.store.mark_job_running(job_id)
                outcome = scan_project(
                    self.store,
                    project,
                    ruleset=self.ruleset,
                    settings=self.settings,
                    job_id=job_id,
                )
        except ProjectLockError as exc:
            self.store.mark_job_done(job_id, "failed", error=str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            logger.exception("job %s failed", job_id)
            self.store.mark_job_done(job_id, "failed", error=str(exc))
            return
        status = "done" if outcome.status in ("done", "skipped") else "failed"
        self.store.mark_job_done(job_id, status, error=outcome.error)


def run_scan_with_lock(
    store: Store,
    project: dict[str, Any],
    *,
    ruleset: RuleSet,
    settings: Any,
    locks_dir: Path,
    full: bool = False,
):
    """CLI-side scan entry: takes the project lock, then scans."""
    lock = ProjectLock(locks_dir, project["id"])
    with lock.held(timeout=0.0):
        return scan_project(store, project, ruleset=ruleset, settings=settings, full=full)
