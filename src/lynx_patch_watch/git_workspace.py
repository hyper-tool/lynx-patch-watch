"""Git workspace management (clone/fetch mirrors, credential redaction).

Ported from msw ``git_workspace.py`` (credential expansion via ${ENV} added per
the lpw plan). msw: src/magento_security_watcher/git_workspace.py
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class GitWorkspaceError(RuntimeError):
    pass


def expand_env_placeholders(text: str) -> str:
    """Expand ${ENV_VAR} placeholders from the process environment.

    Unknown variables are left untouched (and surface as git errors, which are
    redacted before logging).
    """

    def _sub(match: re.Match[str]) -> str:
        name = match.group(1)
        return os.environ.get(name, match.group(0))

    return _ENV_VAR_RE.sub(_sub, text or "")


def _redact_git_args(args: list[str]) -> list[str]:
    """Avoid logging credentials embedded in git URLs."""
    out: list[str] = []
    for a in args:
        if "://" in a and "@" in a:
            try:
                p = urlparse(a)
                if p.username or p.password:
                    host = p.hostname or "unknown"
                    port = f":{p.port}" if p.port else ""
                    netloc = f"***@{host}{port}"
                    out.append(urlunparse((p.scheme, netloc, p.path, "", p.query, "")))
                    continue
            except Exception:  # noqa: BLE001
                out.append("***")
                continue
        out.append(a)
    return out


class GitWorkspace:
    def __init__(self, mirrors_dir: Path, timeout: int = 600) -> None:
        self.mirrors_dir = mirrors_dir
        self.mirrors_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout

    def project_dir(self, project_id: str) -> Path:
        return self.mirrors_dir / project_id

    def sync(self, project_id: str, git_url: str, branch: str) -> tuple[Path, str]:
        """Fetch remote and checkout branch into a working tree. Returns (path, commit_sha)."""
        git_url = expand_env_placeholders(git_url)
        path = self.project_dir(project_id)
        if not (path / ".git").exists():
            logger.info("git clone project=%s branch=%s → %s", project_id, branch, path)
            self._run(["git", "clone", "--branch", branch, "--single-branch", git_url, str(path)])
        else:
            logger.info("git fetch/reset project=%s branch=%s path=%s", project_id, branch, path)
            self._run(["git", "remote", "set-url", "origin", git_url], cwd=path)
            self._run(["git", "fetch", "origin", branch], cwd=path)
            self._run(["git", "checkout", "-B", branch, f"origin/{branch}"], cwd=path)
            self._run(["git", "reset", "--hard", f"origin/{branch}"], cwd=path)
            self._run(["git", "clean", "-fd"], cwd=path)

        commit = self._run(["git", "rev-parse", "HEAD"], cwd=path).stdout.strip()
        logger.debug("git sync done project=%s commit=%s", project_id, commit)
        return path, commit

    def rev_parse(self, path: Path, rev: str) -> str | None:
        """Resolve a rev to a full sha; None when unknown."""
        try:
            proc = self._run(["git", "rev-parse", "--verify", rev], cwd=path)
        except GitWorkspaceError:
            return None
        sha = proc.stdout.strip()
        return sha or None

    def is_ancestor(self, path: Path, ancestor: str, descendant: str = "HEAD") -> bool | None:
        """git merge-base --is-ancestor; False when not an ancestor, None when git fails.

        Exit status 1 means "not an ancestor"; anything else non-zero (unknown
        rev, broken repo) is an error.
        """
        try:
            proc = self._run(
                ["git", "merge-base", "--is-ancestor", ancestor, descendant],
                cwd=path,
                ok_returncodes=(0, 1),
            )
        except GitWorkspaceError:
            return None
        return proc.returncode == 0

    def log_grep(self, path: Path, pattern: str, limit: int = 20) -> list[str]:
        """git log --grep -E pattern; returns commit shas (may be empty)."""
        try:
            proc = self._run(
                [
                    "git",
                    "log",
                    "--grep",
                    pattern,
                    "-E",
                    "--pretty=format:%H",
                    f"-{max(1, limit)}",
                ],
                cwd=path,
            )
        except GitWorkspaceError:
            return []
        return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]

    def file_lines_at(self, path: Path, rev: str, rel_path: str) -> list[str] | None:
        """Read a file at a given rev; None when absent."""
        try:
            proc = self._run(["git", "show", f"{rev}:{rel_path}"], cwd=path)
        except GitWorkspaceError:
            return None
        return proc.stdout.splitlines()

    def _run(
        self,
        args: list[str],
        cwd: Path | None = None,
        ok_returncodes: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess[str]:
        safe = _redact_git_args(args)
        logger.debug("git run: %s (cwd=%s)", " ".join(safe), cwd)
        try:
            proc = subprocess.run(
                args,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitWorkspaceError(f"git timeout: {' '.join(safe)}") from exc
        if proc.returncode not in ok_returncodes:
            err = (proc.stderr or "").strip()
            logger.error("git failed rc=%s cmd=%s stderr=%s", proc.returncode, " ".join(safe), err)
            raise GitWorkspaceError(
                f"git failed ({proc.returncode}): {' '.join(safe)}\n{err}"
            )
        return proc
