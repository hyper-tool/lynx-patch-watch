"""CLI smoke tests: api-token create / rotate, hash-password."""

from __future__ import annotations

import re

from click.testing import CliRunner

from lynx_patch_watch.cli import cli
from lynx_patch_watch.store import Store

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{30,}$")


def _run_api_token(tmp_path, *extra):
    runner = CliRunner()
    base = ["api-token", "--root", str(tmp_path), "--config-dir", str(tmp_path / "config")]
    return runner.invoke(cli, [*base, *extra])


def _first_token_line(output: str) -> str:
    for line in output.splitlines():
        if _TOKEN_RE.match(line.strip()):
            return line.strip()
    raise AssertionError(f"no token line found in: {output!r}")


def test_api_token_create_and_rotate(tmp_path):
    db = tmp_path / "data" / "db" / "lpw.sqlite"

    # First create.
    res = _run_api_token(tmp_path)
    assert res.exit_code == 0, res.output
    token1 = _first_token_line(res.output)
    assert _TOKEN_RE.match(token1)
    store = Store(db)
    assert store.get_setting("api_token_hash") == Store.hash_api_token(token1)

    # Second create without --rotate is rejected (token already set).
    res = _run_api_token(tmp_path)
    assert res.exit_code != 0

    # --rotate replaces the token.
    res = _run_api_token(tmp_path, "--rotate")
    assert res.exit_code == 0, res.output
    token2 = _first_token_line(res.output)
    assert token2 != token1
    assert store.get_setting("api_token_hash") == Store.hash_api_token(token2)
    # Old token must no longer validate.
    assert store.get_setting("api_token_hash") != Store.hash_api_token(token1)
