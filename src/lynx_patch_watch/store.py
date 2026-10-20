"""SQLite store for lynx-patch-watch.

New module (not ported). Schema per plan:

- schema_version table for migrations; WAL enabled; busy_timeout=5000.
- projects / advisories / advisory_items / scan_jobs / scan_runs /
  check_results / findings (append-only ledger) / manual_reviews / audit_log.
- Latest conclusion per (project, item) = MAX(id) row in ``findings``
  (same pattern as msw store.py:388).
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 2

_MIGRATIONS: dict[int, list[str]] = {
    # version 2: incremental-scan fingerprint on scan_runs
    2: ["ALTER TABLE scan_runs ADD COLUMN advisory_fingerprint TEXT"],
}

_PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")

_PROJECT_COLUMNS = (
    "id", "name", "type", "detected_type", "scan_mode", "git_url", "branch",
    "local_path", "declared_version", "declared_edition", "declared_patches",
    "owners", "env", "notes", "enabled", "created_at", "updated_at",
)


def _project_value(column: str, value: Any) -> Any:
    if column == "enabled":
        return 1 if (value is None or value) else 0
    if column in ("declared_patches", "owners") and isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return value


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def valid_project_id(project_id: str) -> bool:
    return bool(_PROJECT_ID_RE.match(project_id or ""))


def _risk_official_sort_key(row: dict[str, Any]) -> tuple:
    """Newest Adobe bulletin first: APSB YY-NNN, then published_at, then item_id."""
    pub = (row.get("published_at") or "").strip()
    advisory = row.get("advisory_id") or ""
    m = re.search(r"APSB(\d{2})-(\d+)", advisory, re.IGNORECASE)
    year = int(m.group(1)) if m else -1
    seq = int(m.group(2)) if m else -1
    has_pub = 1 if pub else 0
    return (year, seq, has_pub, pub, row.get("item_id") or "")


class Store:
    # None = untested, True/False = filesystem WAL capability (cached per process).
    _wal_supported: bool | None = None

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = self._open()
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _open(self) -> sqlite3.Connection:
        """Open a connection with WAL + busy timeout.

        Some sandboxed filesystems break SQLite rollback journals / WAL shared
        memory ("disk I/O error"). A failed WAL attempt leaves the fresh file
        marked as WAL, so we reset the (still empty) file, remember that WAL is
        unusable here, and fall back to journal_mode=OFF with exclusive
        locking. Data-bearing files are never touched — the error propagates.
        """
        if Store._wal_supported is False:
            return self._open_nojournal()
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute("PRAGMA journal_mode = WAL").fetchone()
            if not row or str(row[0]).lower() != "wal":
                raise sqlite3.OperationalError(f"journal_mode=WAL not effective: {row}")
            conn.execute("PRAGMA busy_timeout = 5000").fetchone()
            Store._wal_supported = True
            return conn
        except sqlite3.OperationalError:
            conn.close()
            Store._wal_supported = False
            self._discard_empty_wal_polluted_file()
        return self._open_nojournal()

    def _open_nojournal(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            # fetchone() forces the pragma to complete; without it the journal
            # mode change may not take effect on all drivers/filesystems.
            row = conn.execute("PRAGMA journal_mode = OFF").fetchone()
            if not row or str(row[0]).lower() != "off":
                raise sqlite3.OperationalError(f"journal_mode=OFF not effective: {row}")
        except sqlite3.OperationalError:
            # A leftover (un-deletable) rollback journal from a previous
            # process looks like a hot journal and blocks reopening. Zeroing
            # its size clears that state; this path only runs on filesystems
            # where normal journal handling is already broken.
            conn.close()
            self._zero_sibling_journals()
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            conn.row_factory = sqlite3.Row
            row = conn.execute("PRAGMA journal_mode = OFF").fetchone()
            if not row or str(row[0]).lower() != "off":
                raise sqlite3.OperationalError(f"journal_mode=OFF not effective: {row}")
        conn.execute("PRAGMA locking_mode = EXCLUSIVE").fetchone()
        conn.execute("PRAGMA busy_timeout = 5000").fetchone()
        return conn

    def _zero_sibling_journals(self) -> None:
        for suffix in ("-journal", "-wal", "-shm"):
            path = self.db_path.parent / (self.db_path.name + suffix)
            try:
                if path.is_file() and path.stat().st_size > 0:
                    with path.open("r+b") as fh:
                        fh.truncate(0)
            except OSError:
                continue

    def _discard_empty_wal_polluted_file(self) -> None:
        """Reset a just-created DB file whose failed WAL attempt marked it WAL.

        Only touches files that cannot hold user data (single header page and
        no schema), so real databases are never destroyed. Truncation is used
        instead of unlink because some sandboxed filesystems intercept deletes;
        sibling journal files are truncated too — a non-empty leftover rollback
        journal would otherwise trigger hot-journal recovery on the next open.
        """
        path = self.db_path
        try:
            if not path.is_file():
                return
            if path.stat().st_size > 4096:
                return  # has data; refuse to touch
            with path.open("rb") as fh:
                header = fh.read(100)
            if len(header) >= 48 and header[40:44] not in (b"\x00\x00\x00\x00",):
                return  # non-zero schema cookie → schema present
            targets = [path] + [path.parent / (path.name + s) for s in ("-journal", "-wal", "-shm")]
            for target in targets:
                if target.is_file():
                    with target.open("r+b") as fh:
                        fh.truncate(0)
        except OSError:
            return

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER NOT NULL,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL DEFAULT 'auto',
                    detected_type TEXT,
                    scan_mode TEXT NOT NULL DEFAULT 'manual',
                    git_url TEXT,
                    branch TEXT DEFAULT 'main',
                    local_path TEXT,
                    declared_version TEXT,
                    declared_edition TEXT,
                    declared_patches TEXT,
                    owners TEXT,
                    env TEXT,
                    notes TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS advisories (
                    id TEXT PRIMARY KEY,
                    product TEXT,
                    title TEXT,
                    priority TEXT,
                    published_at TEXT,
                    modified_at TEXT,
                    url TEXT,
                    raw_json TEXT,
                    detail_status TEXT NOT NULL DEFAULT 'missing',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS advisory_items (
                    item_id TEXT PRIMARY KEY,
                    advisory_id TEXT NOT NULL,
                    cve_id TEXT,
                    severity TEXT,
                    cvss REAL,
                    packages TEXT,
                    fix_kind TEXT,
                    fingerprints TEXT,
                    title TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    trigger TEXT,
                    queued_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    error TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    job_id INTEGER,
                    git_commit TEXT,
                    ruleset_hash TEXT,
                    status TEXT NOT NULL,
                    skip_reason TEXT,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    error TEXT
                );

                CREATE TABLE IF NOT EXISTS check_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER NOT NULL,
                    project_id TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    checker TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 0,
                    evidence_json TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER,
                    project_id TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    decided_by TEXT NOT NULL DEFAULT 'scan',
                    evidence_hash TEXT,
                    source TEXT NOT NULL DEFAULT 'scan',
                    confidence REAL NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS manual_reviews (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    item_id TEXT,
                    status TEXT NOT NULL,
                    note TEXT,
                    reviewer TEXT,
                    due_date TEXT,
                    evidence_hash_at_review TEXT,
                    stale INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT,
                    action TEXT NOT NULL,
                    target TEXT,
                    detail TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_findings_project_item
                    ON findings (project_id, item_id, id);
                CREATE INDEX IF NOT EXISTS idx_findings_scan_run
                    ON findings (scan_run_id);
                CREATE INDEX IF NOT EXISTS idx_check_results_run
                    ON check_results (scan_run_id);
                CREATE INDEX IF NOT EXISTS idx_scan_runs_project
                    ON scan_runs (project_id, id);
                CREATE INDEX IF NOT EXISTS idx_scan_jobs_status
                    ON scan_jobs (status, id);
                CREATE INDEX IF NOT EXISTS idx_manual_reviews_project_item
                    ON manual_reviews (project_id, item_id, id);
                CREATE UNIQUE INDEX IF NOT EXISTS uniq_manual_reviews_project_item
                    ON manual_reviews (project_id, COALESCE(item_id, ''));
                CREATE INDEX IF NOT EXISTS idx_advisory_items_advisory
                    ON advisory_items (advisory_id);
                CREATE INDEX IF NOT EXISTS idx_audit_log_created
                    ON audit_log (created_at);
                """
            )
            row = conn.execute(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
            ).fetchone()
            current = row["version"] if row else 0
            for version in range(current + 1, SCHEMA_VERSION + 1):
                for statement in _MIGRATIONS.get(version, []):
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (version, _utcnow()),
                )

    # ------------------------------------------------------------------
    # projects
    # ------------------------------------------------------------------

    def upsert_project(self, record: dict[str, Any]) -> None:
        """Insert or update a project.

        Only fields present in ``record`` are written; omitted fields keep their
        existing values. NOT NULL columns without schema defaults (created_at)
        are always filled on insert.
        """
        now = _utcnow()
        record = dict(record)
        existing = self.get_project(record.get("id") or "")
        if existing is None:
            record.setdefault("type", "auto")
            record.setdefault("scan_mode", "manual")
            record.setdefault("branch", "main")
            record.setdefault("enabled", True)
        # NOT NULL columns without schema defaults are always filled (keeping
        # existing values on update) so the INSERT side of the upsert is valid.
        record.setdefault("name", existing["name"] if existing else record.get("id") or "")
        record.setdefault("created_at", existing["created_at"] if existing else now)
        record["updated_at"] = now

        insert_cols = [c for c in _PROJECT_COLUMNS if c in record]
        placeholders = ", ".join("?" for _ in insert_cols)
        updates = ", ".join(f"{c}=excluded.{c}" for c in insert_cols if c != "id")
        values = [_project_value(c, record.get(c)) for c in insert_cols]
        with self.connect() as conn:
            conn.execute(
                f"INSERT INTO projects ({', '.join(insert_cols)}) VALUES ({placeholders}) "
                f"ON CONFLICT(id) DO UPDATE SET {updates}",
                values,
            )

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        return self._project_row(row) if row else None

    def list_projects(self, *, include_disabled: bool = True) -> list[dict[str, Any]]:
        sql = "SELECT * FROM projects"
        if not include_disabled:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY id"
        with self.connect() as conn:
            rows = conn.execute(sql).fetchall()
        return [self._project_row(r) for r in rows]

    def delete_project(self, project_id: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM projects WHERE id=?", (project_id,))

    @staticmethod
    def _project_row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        for key in ("declared_patches", "owners"):
            raw = data.get(key)
            if raw:
                try:
                    data[key] = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    data[key] = []
            else:
                data[key] = []
        data["enabled"] = bool(data.get("enabled"))
        return data

    # ------------------------------------------------------------------
    # advisories + advisory_items
    # ------------------------------------------------------------------

    def upsert_advisory(self, record: dict[str, Any]) -> None:
        now = _utcnow()
        raw_json = record.get("raw_json")
        if isinstance(raw_json, (dict, list)):
            raw_json = json.dumps(raw_json, ensure_ascii=False)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO advisories (
                    id, product, title, priority, published_at, modified_at, url,
                    raw_json, detail_status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    product=excluded.product,
                    title=excluded.title,
                    priority=excluded.priority,
                    published_at=excluded.published_at,
                    modified_at=excluded.modified_at,
                    url=excluded.url,
                    raw_json=excluded.raw_json,
                    detail_status=excluded.detail_status,
                    updated_at=excluded.updated_at
                """,
                (
                    record["id"],
                    record.get("product"),
                    record.get("title"),
                    record.get("priority"),
                    record.get("published_at"),
                    record.get("modified_at"),
                    record.get("url"),
                    raw_json,
                    record.get("detail_status") or "missing",
                    record.get("created_at") or now,
                    now,
                ),
            )

    def get_advisory(self, advisory_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT a.*,
                       (SELECT COUNT(*) FROM advisory_items i WHERE i.advisory_id = a.id) AS item_count
                FROM advisories a
                WHERE a.id=?
                """,
                (advisory_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_advisories(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM advisories ORDER BY id DESC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["item_count"] = None
            except Exception:  # noqa: BLE001
                pass
            out.append(d)
        # item counts
        with self.connect() as conn:
            counts = {
                r["advisory_id"]: r["c"]
                for r in conn.execute(
                    "SELECT advisory_id, COUNT(*) AS c FROM advisory_items GROUP BY advisory_id"
                )
            }
        for d in out:
            d["item_count"] = counts.get(d["id"], 0)
        out.sort(key=_risk_official_sort_key, reverse=True)
        return out

    def advisory_fingerprint(self) -> str:
        """Hash over advisory ids + modified_at, for incremental-scan skip logic."""
        with self.connect() as conn:
            rows = conn.execute("SELECT id, modified_at FROM advisories ORDER BY id").fetchall()
        payload = "|".join(f"{r['id']}@{r['modified_at'] or ''}" for r in rows)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def upsert_advisory_item(self, record: dict[str, Any]) -> None:
        now = _utcnow()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO advisory_items (
                    item_id, advisory_id, cve_id, severity, cvss, packages,
                    fix_kind, fingerprints, title, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(item_id) DO UPDATE SET
                    advisory_id=excluded.advisory_id,
                    cve_id=excluded.cve_id,
                    severity=excluded.severity,
                    cvss=excluded.cvss,
                    packages=excluded.packages,
                    fix_kind=excluded.fix_kind,
                    fingerprints=excluded.fingerprints,
                    title=excluded.title,
                    updated_at=excluded.updated_at
                """,
                (
                    record["item_id"],
                    record["advisory_id"],
                    record.get("cve_id"),
                    record.get("severity"),
                    record.get("cvss"),
                    _maybe_json(record.get("packages")),
                    record.get("fix_kind"),
                    _maybe_json(record.get("fingerprints")),
                    record.get("title"),
                    record.get("created_at") or now,
                    now,
                ),
            )

    def list_advisory_items(self, advisory_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM advisory_items"
        params: list[Any] = []
        if advisory_id:
            sql += " WHERE advisory_id=?"
            params.append(advisory_id)
        sql += " ORDER BY item_id"
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._item_row(r) for r in rows]

    def get_advisory_item(self, item_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM advisory_items WHERE item_id=?", (item_id,)).fetchone()
        return self._item_row(row) if row else None

    @staticmethod
    def _item_row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        for key in ("packages", "fingerprints"):
            raw = data.get(key)
            if raw:
                try:
                    data[key] = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    data[key] = []
            else:
                data[key] = []
        return data

    # ------------------------------------------------------------------
    # scan jobs / runs
    # ------------------------------------------------------------------

    def enqueue_scan_job(self, project_id: str, trigger: str = "manual") -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO scan_jobs (project_id, status, trigger, queued_at) VALUES (?, 'queued', ?, ?)",
                (project_id, trigger, _utcnow()),
            )
            return int(cur.lastrowid)

    def list_scan_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM scan_jobs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def next_queued_job(self) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM scan_jobs WHERE status='queued' ORDER BY id ASC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def mark_job_running(self, job_id: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE scan_jobs SET status='running', started_at=? WHERE id=?",
                (_utcnow(), job_id),
            )

    def mark_job_done(self, job_id: int, status: str, error: str | None = None) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE scan_jobs SET status=?, finished_at=?, error=? WHERE id=?",
                (status, _utcnow(), error, job_id),
            )

    def fail_stale_running_jobs(self) -> int:
        """Mark jobs still marked running from a previous process as failed."""
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE scan_jobs SET status='failed', finished_at=?, error='stale running job (restart)' WHERE status='running'",
                (_utcnow(),),
            )
            return cur.rowcount or 0

    def start_scan_run(
        self,
        project_id: str,
        *,
        job_id: int | None = None,
        git_commit: str | None = None,
        ruleset_hash: str | None = None,
        advisory_fingerprint: str | None = None,
    ) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO scan_runs (project_id, job_id, git_commit, ruleset_hash, advisory_fingerprint, status, started_at)
                VALUES (?, ?, ?, ?, ?, 'running', ?)
                """,
                (project_id, job_id, git_commit, ruleset_hash, advisory_fingerprint, _utcnow()),
            )
            return int(cur.lastrowid)

    def finish_scan_run(
        self,
        scan_run_id: int,
        status: str,
        git_commit: str | None = None,
        error: str | None = None,
        skip_reason: str | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE scan_runs
                SET finished_at=?, status=?, git_commit=COALESCE(?, git_commit),
                    error=?, skip_reason=?
                WHERE id=?
                """,
                (_utcnow(), status, git_commit, error, skip_reason, scan_run_id),
            )

    def list_scan_runs(self, project_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        sql = "SELECT * FROM scan_runs"
        params: list[Any] = []
        if project_id:
            sql += " WHERE project_id=?"
            params.append(project_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def latest_scan_run(self, project_id: str) -> dict[str, Any] | None:
        rows = self.list_scan_runs(project_id=project_id, limit=1)
        return rows[0] if rows else None

    def recent_failed_scans(self, limit: int = 10) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_runs WHERE status IN ('error', 'failed') ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # check results + findings ledger
    # ------------------------------------------------------------------

    def insert_check_result(
        self,
        *,
        scan_run_id: int,
        project_id: str,
        item_id: str,
        checker: str,
        outcome: str,
        confidence: float,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO check_results (
                    scan_run_id, project_id, item_id, checker, outcome, confidence,
                    evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_run_id,
                    project_id,
                    item_id,
                    checker,
                    outcome,
                    confidence,
                    json.dumps(evidence or {}, ensure_ascii=False),
                    _utcnow(),
                ),
            )

    def insert_finding(
        self,
        *,
        scan_run_id: int | None,
        project_id: str,
        item_id: str,
        status: str,
        decided_by: str = "scan",
        evidence_hash: str | None = None,
        source: str = "scan",
        confidence: float = 0.0,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO findings (
                    scan_run_id, project_id, item_id, status, decided_by,
                    evidence_hash, source, confidence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_run_id,
                    project_id,
                    item_id,
                    status,
                    decided_by,
                    evidence_hash,
                    source,
                    confidence,
                    _utcnow(),
                ),
            )

    def list_latest_findings(self, project_id: str | None = None) -> list[dict[str, Any]]:
        """Latest finding per (project_id, item_id), optionally filtered by project."""
        sql = """
            SELECT f.*
            FROM findings f
            INNER JOIN (
                SELECT project_id, item_id, MAX(id) AS max_id
                FROM findings
                GROUP BY project_id, item_id
            ) latest ON f.id = latest.max_id
        """
        params: list[Any] = []
        if project_id:
            sql += " WHERE f.project_id = ?"
            params.append(project_id)
        sql += " ORDER BY f.project_id, f.item_id"
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get_latest_finding(self, project_id: str, item_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM findings
                WHERE project_id=? AND item_id=?
                ORDER BY id DESC LIMIT 1
                """,
                (project_id, item_id),
            ).fetchone()
        return dict(row) if row else None

    def count_latest_by_status(self, project_id: str | None = None) -> dict[str, int]:
        counts = {
            "vulnerable": 0,
            "conflict": 0,
            "fixed": 0,
            "declared": 0,
            "unknown": 0,
            "not_applicable": 0,
            "error": 0,
        }
        for row in self.list_latest_findings(project_id=project_id):
            status = row.get("status") or "unknown"
            if status in counts:
                counts[status] += 1
            else:
                counts["unknown"] += 1
        return counts

    def first_finding_time(self, project_id: str, item_id: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT MIN(created_at) AS first_at FROM findings WHERE project_id=? AND item_id=?",
                (project_id, item_id),
            ).fetchone()
        return row["first_at"] if row else None

    def finding_times(self) -> dict[tuple[str, str], tuple[str | None, str | None]]:
        """(project_id, item_id) → (first finding time, first fixed time), in one query."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT project_id, item_id, MIN(created_at) AS first_at,
                       MIN(CASE WHEN status='fixed' THEN created_at END) AS fixed_at
                FROM findings GROUP BY project_id, item_id
                """
            ).fetchall()
        return {(r["project_id"], r["item_id"]): (r["first_at"], r["fixed_at"]) for r in rows}

    def open_counts_by_scan_run(self, scan_run_ids: list[int]) -> dict[int, int]:
        """Unfixed (vulnerable/conflict/unknown) finding counts per scan run."""
        if not scan_run_ids:
            return {}
        placeholders = ",".join("?" for _ in scan_run_ids)
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT scan_run_id, COUNT(*) AS c FROM findings
                WHERE scan_run_id IN ({placeholders})
                  AND status IN ('vulnerable','conflict','unknown')
                GROUP BY scan_run_id
                """,
                list(scan_run_ids),
            ).fetchall()
        return {r["scan_run_id"]: r["c"] for r in rows}

    def fixed_finding_time(self, project_id: str, item_id: str) -> str | None:
        """First time the ledger recorded a fixed (or conflict-free positive) status."""
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT MIN(created_at) AS fixed_at FROM findings
                WHERE project_id=? AND item_id=? AND status='fixed'
                """,
                (project_id, item_id),
            ).fetchone()
        return row["fixed_at"] if row else None

    # ------------------------------------------------------------------
    # manual reviews
    # ------------------------------------------------------------------

    def upsert_manual_review(
        self,
        *,
        project_id: str,
        item_id: str | None,
        status: str,
        note: str | None = None,
        reviewer: str | None = None,
        due_date: str | None = None,
        evidence_hash_at_review: str | None = None,
        stale: bool = False,
    ) -> int:
        now = _utcnow()
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO manual_reviews (
                    project_id, item_id, status, note, reviewer, due_date,
                    evidence_hash_at_review, stale, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, COALESCE(item_id, '')) DO UPDATE SET
                    status=excluded.status,
                    note=excluded.note,
                    reviewer=excluded.reviewer,
                    due_date=excluded.due_date,
                    evidence_hash_at_review=excluded.evidence_hash_at_review,
                    stale=excluded.stale,
                    updated_at=excluded.updated_at
                """,
                (
                    project_id,
                    item_id,
                    status,
                    note,
                    reviewer,
                    due_date,
                    evidence_hash_at_review,
                    1 if stale else 0,
                    now,
                    now,
                ),
            )
            return int(cur.lastrowid)

    def list_manual_reviews(self, project_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM manual_reviews"
        params: list[Any] = []
        if project_id:
            sql += " WHERE project_id=?"
            params.append(project_id)
        sql += " ORDER BY id DESC"
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["stale"] = bool(d.get("stale"))
            out.append(d)
        return out

    def get_manual_review(self, project_id: str, item_id: str | None) -> dict[str, Any] | None:
        with self.connect() as conn:
            if item_id:
                row = conn.execute(
                    "SELECT * FROM manual_reviews WHERE project_id=? AND item_id=? ORDER BY id DESC LIMIT 1",
                    (project_id, item_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM manual_reviews WHERE project_id=? AND (item_id IS NULL OR item_id='') ORDER BY id DESC LIMIT 1",
                    (project_id,),
                ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["stale"] = bool(d.get("stale"))
        return d

    def mark_manual_review_stale(self, project_id: str, item_id: str | None) -> None:
        with self.connect() as conn:
            if item_id:
                conn.execute(
                    "UPDATE manual_reviews SET stale=1, updated_at=? WHERE project_id=? AND item_id=?",
                    (_utcnow(), project_id, item_id),
                )
            else:
                conn.execute(
                    "UPDATE manual_reviews SET stale=1, updated_at=? WHERE project_id=? AND (item_id IS NULL OR item_id='')",
                    (_utcnow(), project_id),
                )

    def refresh_manual_review_staleness(self, project_id: str, item_id: str, evidence_hash: str | None) -> None:
        """Mark a review stale when the auto evidence hash changed since review."""
        review = self.get_manual_review(project_id, item_id)
        if not review:
            return
        recorded = review.get("evidence_hash_at_review")
        if recorded and evidence_hash and recorded != evidence_hash:
            self.mark_manual_review_stale(project_id, item_id)

    # ------------------------------------------------------------------
    # audit log
    # ------------------------------------------------------------------
    def audit(self, actor: str | None, action: str, target: str | None = None, detail: Any = None) -> None:
        payload = detail
        if isinstance(detail, (dict, list)):
            payload = json.dumps(detail, ensure_ascii=False)
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO audit_log (actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?)",
                (actor, action, target, payload, _utcnow()),
            )

    def list_audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # settings (key/value, e.g. api token hash)
    # ------------------------------------------------------------------

    def get_setting(self, key: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str | None) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (key, value, _utcnow()),
            )

    @staticmethod
    def hash_api_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _maybe_json(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)
