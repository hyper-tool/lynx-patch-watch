"""lynx-patch-watch command line interface (``lpw``)."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

import click

from lynx_patch_watch import __version__
from lynx_patch_watch.config import (
    AppSettings,
    ensure_data_dirs,
    load_env_secrets,
    load_settings,
    default_root,
)
from lynx_patch_watch.store import Store


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _context(root: Optional[Path], config_dir: Optional[Path], verbose: bool) -> dict[str, Any]:
    _setup_logging(verbose)
    root = (root or default_root()).resolve()
    config_dir = (config_dir or (root / "config")).resolve()
    settings = load_settings(config_dir, root)
    paths = ensure_data_dirs(settings)
    store = Store(settings.db_path)
    return {"root": root, "config_dir": config_dir, "settings": settings, "paths": paths, "store": store}


def _ruleset(settings: AppSettings):
    from lynx_patch_watch.engine.rules import load_ruleset

    return load_ruleset(Path(settings.rules.dir))


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="lpw")
def cli() -> None:
    """lynx-patch-watch: patch installation checker for Magento/Commerce."""


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--from-html", "from_html", type=click.Path(path_type=Path, exists=True), default=None,
              help="Ingest a single browser-saved bulletin detail page (bypasses Akamai blocks).")
@click.option("--fixture-dir", type=click.Path(path_type=Path, file_okay=False), default=None,
              help="Offline ingest from a directory with collection.json + saved detail pages.")
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--config-dir", type=click.Path(path_type=Path), default=None)
@click.option("--full", is_flag=True, help="Re-fetch detail pages even when modified_at is unchanged.")
@click.option("-v", "--verbose", is_flag=True)
def ingest(
    from_html: Optional[Path],
    fixture_dir: Optional[Path],
    root: Optional[Path],
    config_dir: Optional[Path],
    full: bool,
    verbose: bool,
) -> None:
    """Fetch Adobe Commerce bulletins into the local store."""
    ctx = _context(root, config_dir, verbose)
    settings: AppSettings = ctx["settings"]
    store: Store = ctx["store"]

    if from_html is not None:
        from lynx_patch_watch.engine.ingest import ingest_from_html_file

        report = ingest_from_html_file(store, from_html)
        click.echo(
            f"ingested {from_html}: advisories={report.advisories} items={report.items}"
        )
        return

    from lynx_patch_watch.adapters.magento.source import ChimeraAdvisorySource
    from lynx_patch_watch.engine.ingest import ingest_from_source

    fixture = fixture_dir or (Path(settings.advisory.fixture_dir) if settings.advisory.fixture_dir else None)
    source = ChimeraAdvisorySource(
        chimera_url=settings.advisory.chimera_url,
        commerce_mnemonic=settings.advisory.commerce_mnemonic,
        detail_url_template=settings.advisory.detail_url_template,
        user_agent=settings.advisory.user_agent,
        request_timeout_seconds=settings.advisory.request_timeout_seconds,
        detail_fetch_limit=settings.advisory.detail_fetch_limit,
        follow_release_notes=settings.advisory.follow_release_notes,
        kb_fetch_limit_per_bulletin=settings.advisory.kb_fetch_limit_per_bulletin,
        fixture_dir=fixture,
        local_index_html=Path(settings.advisory.local_index_html) if settings.advisory.local_index_html else None,
    )
    report = ingest_from_source(store, source, refetch_unchanged=full)
    click.echo(
        "ingest: advisories={advisories} items={items} "
        "details(ok={details_ok} blocked={details_blocked} missing={details_missing}) refetched={refetched}".format(
            **report.__dict__
        )
    )
    for warning in report.warnings:
        click.echo(f"warning: {warning}", err=True)
    if report.details_blocked:
        click.echo(
            "note: some detail pages were blocked (Akamai). Use --from-html or --fixture-dir to complete them.",
            err=True,
        )


@cli.command("import-msw")
@click.option("--db", "db_path", required=True, type=click.Path(path_type=Path, exists=True))
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--config-dir", type=click.Path(path_type=Path), default=None)
@click.option("-v", "--verbose", is_flag=True)
def import_msw(db_path: Path, root: Optional[Path], config_dir: Optional[Path], verbose: bool) -> None:
    """Import advisories + risk items from an magento-security-watcher database.

    msw findings are NOT imported (their first-seen times would pollute the ledger).
    """
    ctx = _context(root, config_dir, verbose)
    from lynx_patch_watch.engine.ingest import import_msw as _import

    counts = _import(ctx["store"], db_path)
    click.echo(f"imported from msw: advisories={counts['advisories']} items={counts['items']}")


# ---------------------------------------------------------------------------
# detect / scan
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("path", type=click.Path(path_type=Path, exists=True, file_okay=False))
def detect(path: Path) -> None:
    """Detect the project type / version / edition of a workspace."""
    from lynx_patch_watch.detect import detect as _detect

    result = _detect(path)
    click.echo(
        json.dumps(
            {
                "type": result.type,
                "version": result.version,
                "edition": result.edition,
                "confidence": result.confidence,
                "signals": result.signals,
            },
            indent=2,
            ensure_ascii=False,
        )
    )


@cli.command()
@click.option("--project", "project_ids", multiple=True, help="Project id (repeatable). Default: all enabled.")
@click.option("--local-workspace", type=click.Path(path_type=Path, file_okay=False), default=None,
              help="Ad-hoc local workspace: create/refresh a one-off project and scan it.")
@click.option("--full", is_flag=True, help="Ignore the incremental-scan skip.")
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--config-dir", type=click.Path(path_type=Path), default=None)
@click.option("-v", "--verbose", is_flag=True)
def scan(
    project_ids: tuple[str, ...],
    local_workspace: Optional[Path],
    root: Optional[Path],
    config_dir: Optional[Path],
    full: bool,
    verbose: bool,
) -> None:
    """Scan projects and record findings."""
    ctx = _context(root, config_dir, verbose)
    settings: AppSettings = ctx["settings"]
    store: Store = ctx["store"]
    ruleset = _ruleset(settings)
    locks_dir = ctx["paths"]["locks"]

    from lynx_patch_watch.engine.jobs import ProjectLock, ProjectLockError
    from lynx_patch_watch.engine.orchestrator import scan_project

    if local_workspace is not None:
        project = store.get_project("adhoc-local")
        if project is None:
            store.upsert_project(
                {
                    "id": "adhoc-local",
                    "name": f"Ad-hoc {local_workspace.name}",
                    "type": "auto",
                    "scan_mode": "local",
                    "local_path": str(local_workspace),
                }
            )
            project = store.get_project("adhoc-local")
        else:
            store.upsert_project({"id": "adhoc-local", "local_path": str(local_workspace)})
            project = store.get_project("adhoc-local")
        project_ids = ("adhoc-local",)

    projects = [p for p in store.list_projects() if p.get("enabled", True)]
    if project_ids:
        wanted = set(project_ids)
        projects = [p for p in projects if p["id"] in wanted]
        missing = wanted - {p["id"] for p in projects}
        for m in sorted(missing):
            click.echo(f"warning: unknown or disabled project {m}", err=True)

    if not projects:
        click.echo("no projects to scan")
        return

    failures = 0
    for project in projects:
        lock = ProjectLock(locks_dir, project["id"])
        try:
            with lock.held(timeout=0.0):
                outcome = scan_project(
                    store, project, ruleset=ruleset, settings=settings, full=full
                )
        except ProjectLockError as exc:
            click.echo(f"{project['id']}: skipped ({exc})", err=True)
            failures += 1
            continue
        if outcome.status == "error":
            click.echo(f"{project['id']}: ERROR {outcome.error}", err=True)
            failures += 1
            continue
        if outcome.status == "skipped":
            click.echo(f"{project['id']}: skipped ({outcome.skip_reason})")
            continue
        counts = _status_counts(outcome)
        click.echo(
            f"{project['id']}: scanned {len(outcome.verdicts)} item(s) — " + " ".join(
                f"{k}={v}" for k, v in sorted(counts.items()) if v
            )
        )
    if failures:
        sys.exit(1)


def _status_counts(outcome) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in outcome.verdicts:
        counts[v.status] = counts.get(v.status, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# projects
# ---------------------------------------------------------------------------


@cli.group()
def projects() -> None:
    """Project registry commands."""


@projects.command("list")
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--config-dir", type=click.Path(path_type=Path), default=None)
def projects_list(root: Optional[Path], config_dir: Optional[Path]) -> None:
    ctx = _context(root, config_dir, False)
    store: Store = ctx["store"]
    rows = store.list_projects()
    if not rows:
        click.echo("(no projects)")
        return
    for p in rows:
        click.echo(
            "{id:<24} {name:<24} type={type:<8} mode={mode:<7} enabled={enabled}".format(
                id=p["id"],
                name=(p.get("name") or "")[:24],
                type=p.get("type") or "auto",
                mode=p.get("scan_mode") or "manual",
                enabled=p.get("enabled"),
            )
        )


@projects.command("import-yaml")
@click.argument("yaml_file", type=click.Path(path_type=Path, exists=True))
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--config-dir", type=click.Path(path_type=Path), default=None)
@click.option("-v", "--verbose", is_flag=True)
def projects_import_yaml(yaml_file: Path, root: Optional[Path], config_dir: Optional[Path], verbose: bool) -> None:
    """Import msw-style projects.yaml (credentials are stripped, never stored)."""
    ctx = _context(root, config_dir, verbose)
    store: Store = ctx["store"]
    import yaml

    data = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or {}
    items = data.get("projects") or []
    if not isinstance(items, list):
        raise click.ClickException("projects.yaml must contain a 'projects' list")
    imported = 0
    for item in items:
        if not isinstance(item, dict) or not item.get("id"):
            click.echo("warning: skipping entry without id", err=True)
            continue
        git_url = item.get("git_url") or ""
        redacted = _strip_credentials(git_url)
        if redacted != git_url:
            click.echo(
                f"warning: {item['id']}: git_url contained plaintext credentials — stripped. "
                "Rotate the exposed credentials!",
                err=True,
            )
        store.upsert_project(
            {
                "id": str(item["id"]),
                "name": item.get("name") or str(item["id"]),
                "type": "magento",
                "scan_mode": "git" if git_url else "manual",
                "git_url": redacted or None,
                "branch": item.get("branch") or "main",
                "owners": item.get("owners") or [],
                "notes": item.get("notes"),
                "enabled": item.get("enabled", True),
            }
        )
        store.audit("cli", "project.import_yaml", str(item["id"]), {"file": str(yaml_file)})
        imported += 1
    click.echo(f"imported {imported} project(s) from {yaml_file}")


def _strip_credentials(git_url: str) -> str:
    from urllib.parse import urlparse, urlunparse

    if "://" not in git_url or "@" not in git_url:
        return git_url
    try:
        p = urlparse(git_url)
        if not (p.username or p.password):
            return git_url
        netloc = f"{p.hostname or 'unknown'}" + (f":{p.port}" if p.port else "")
        return urlunparse((p.scheme, netloc, p.path, "", p.query, ""))
    except Exception:  # noqa: BLE001
        return ""


# ---------------------------------------------------------------------------
# excel
# ---------------------------------------------------------------------------


@cli.group()
def excel() -> None:
    """Excel template / import / export commands."""


@excel.command("template")
@click.argument("out_file", type=click.Path(path_type=Path))
def excel_template(out_file: Path) -> None:
    """Write the blank import template (.xlsx)."""
    from lynx_patch_watch.excel.template import build_template

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_bytes(build_template())
    click.echo(f"wrote template {out_file}")


@excel.command("export")
@click.argument("out_file", type=click.Path(path_type=Path))
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--config-dir", type=click.Path(path_type=Path), default=None)
def excel_export(out_file: Path, root: Optional[Path], config_dir: Optional[Path]) -> None:
    """Export the whole store to a 4-sheet workbook."""
    ctx = _context(root, config_dir, False)
    from lynx_patch_watch.excel.exporter import build_export

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_bytes(build_export(ctx["store"]))
    click.echo(f"wrote export {out_file}")


@excel.command("import")
@click.argument("xlsx_file", type=click.Path(path_type=Path, exists=True))
@click.option("--dry-run", is_flag=True, help="Preview only; do not write.")
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--config-dir", type=click.Path(path_type=Path), default=None)
@click.option("-v", "--verbose", is_flag=True)
def excel_import(xlsx_file: Path, dry_run: bool, root: Optional[Path], config_dir: Optional[Path], verbose: bool) -> None:
    """Import projects / manual reviews from a filled-in workbook."""
    ctx = _context(root, config_dir, verbose)
    store: Store = ctx["store"]
    from lynx_patch_watch.excel.importer import apply_import, import_preview

    content = xlsx_file.read_bytes()
    preview = import_preview(store, content)
    for err in preview.errors:
        click.echo(f"row {err.row} ({err.sheet}): {err.message}", err=True)
    click.echo(
        f"preview: create={len(preview.to_create)} update={len(preview.to_update)} "
        f"unchanged={len(preview.unchanged)} reviews={len(preview.reviews)} errors={len(preview.errors)}"
    )
    if dry_run:
        return
    if preview.errors:
        raise click.ClickException(
            f"{len(preview.errors)} row error(s); fix them and retry (nothing was written)"
        )
    result = apply_import(store, content, actor="cli")
    store.audit("cli", "excel.import", str(xlsx_file), result.summary())
    click.echo(f"imported: created={result.created} updated={result.updated} reviews={result.reviews}")


# ---------------------------------------------------------------------------
# export-status / serve / hash-password
# ---------------------------------------------------------------------------


@cli.command("export-status")
@click.option("--project", "project_id", required=True)
@click.option("--out", "out_file", required=True, type=click.Path(path_type=Path))
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--config-dir", type=click.Path(path_type=Path), default=None)
def export_status(project_id: str, out_file: Path, root: Optional[Path], config_dir: Optional[Path]) -> None:
    """Export a project's patch status JSON (for Magento admin injection)."""
    ctx = _context(root, config_dir, False)
    store: Store = ctx["store"]
    from lynx_patch_watch.engine.orchestrator import project_advisory_status

    project = store.get_project(project_id)
    if project is None:
        raise click.ClickException(f"unknown project: {project_id}")
    statuses = project_advisory_status(store, project_id)
    payload = {
        "project": project_id,
        "generated_at": _utcnow(),
        "advisories": statuses,
    }
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    click.echo(f"wrote {out_file}")


@cli.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--config-dir", type=click.Path(path_type=Path), default=None)
@click.option("--host", default=None)
@click.option("--port", type=int, default=None)
@click.option("-v", "--verbose", is_flag=True)
def serve(root: Optional[Path], config_dir: Optional[Path], host: Optional[str], port: Optional[int], verbose: bool) -> None:
    """Run the web dashboard (with the background scan worker)."""
    ctx = _context(root, config_dir, verbose)
    settings: AppSettings = ctx["settings"]
    import uvicorn

    from lynx_patch_watch.web.app import create_app

    app = create_app(root=ctx["root"], config_dir=ctx["config_dir"], settings=settings, store=ctx["store"])
    uvicorn.run(
        app,
        host=host or settings.web.host,
        port=port or settings.web.port,
        log_level="debug" if verbose else "info",
    )


@cli.command("hash-password")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
def hash_password(password: str) -> None:
    """Generate an argon2 password hash for LPW_ADMIN_PASSWORD_HASH."""
    from argon2 import PasswordHasher

    ph = PasswordHasher()
    click.echo(ph.hash(password))


@cli.command("api-token")
@click.option("--rotate", is_flag=True, help="Always generate a new token (invalidates the old one).")
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--config-dir", type=click.Path(path_type=Path), default=None)
def api_token(rotate: bool, root: Optional[Path], config_dir: Optional[Path]) -> None:
    """Create or rotate the read-only API token for the Magento module.

    Only the SHA-256 hash of the token is stored in the database; the token
    itself is shown once and must be copied into the Lynx_PatchWatch module's
    configuration. The Magento module sends it as ``?token=...`` on
    ``/api/projects/{id}/status``.
    """
    import secrets

    ctx = _context(root, config_dir, False)
    store: Store = ctx["store"]
    existing = store.get_setting("api_token_hash")
    if existing and not rotate:
        raise click.ClickException(
            "an API token is already set; use --rotate to replace it"
        )
    token = secrets.token_urlsafe(32)
    store.set_setting("api_token_hash", Store.hash_api_token(token))
    store.audit("cli", "api_token.create", "api_token_hash", {"rotate": bool(rotate)})
    click.echo(token)
    click.echo(
        "token hash stored; copy the line above into Lynx_PatchWatch config (api_token).",
        err=True,
    )


def _utcnow() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
