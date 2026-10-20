"""Settings + secrets loading for lynx-patch-watch.

New module (not ported); mirrors msw's config.py layout minus LLM/NVD/WeCom
concerns (explicitly out of scope for this phase).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from lynx_patch_watch.browser_identity import BROWSER_USER_AGENT


class AdvisorySettings(BaseModel):
    # Adobe chimera CaaS collection endpoint for security bulletins cards.
    chimera_url: str = (
        "https://www.adobe.com/chimera-api/collection"
        "?originSelection=hawks"
        "&contentTypeTags=caas:content-type/documentation"
        "&collectionTags=caas:trust-center/security-bulletin"
        "&excludeContentWithTags="
        "&language=en&country=US"
        "&complexQuery=&excludeIds=&currentEntityId=&featuredCards=&environment="
        "&draft=false&size=250"
    )
    # Only cards whose contentArea.detailText equals this mnemonic are Commerce bulletins.
    commerce_mnemonic: str = "caas:mnemonics/adobe-commerce"
    # Template for bulletin detail URLs when the card omits one.
    detail_url_template: str = "https://www.adobe.com/trust/security/products/commerce/{aid_lower}"
    # Browser-saved HTML of a bulletin detail page (bypasses Akamai blocks).
    local_index_html: Optional[str] = None
    # Local directory of *.json fixtures (offline ingest / tests).
    fixture_dir: Optional[str] = None
    user_agent: str = BROWSER_USER_AGENT
    detail_fetch_limit: int = 15
    request_timeout_seconds: float = 45.0
    follow_release_notes: bool = True
    kb_fetch_limit_per_bulletin: int = 2
    # Disk cache for downloaded upstream .patch files (git_commit checker).
    patch_cache_dir: str = "data/cache/patches"


class ScanSettings(BaseModel):
    # Root directory that local_path workspaces must live under (None = unset, then
    # any absolute path is rejected).
    local_root: Optional[str] = None
    fetch_timeout_seconds: int = 600
    mirrors_dir: str = "data/mirrors"
    # Re-fetch advisories older than this many hours on `lpw scan` (0 = always).
    advisory_max_age_hours: int = 6


class WebSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080
    # Empty → loopback only (see IP allowlist middleware).
    allowed_cidrs: List[str] = Field(default_factory=list)
    trust_x_forwarded_for: bool = False
    session_idle_timeout_minutes: int = 120
    login_rate_limit_max_attempts: int = 5
    login_rate_limit_window_seconds: int = 300


class RulesSettings(BaseModel):
    # Directory holding YAML check rules (built-in examples + user custom).
    dir: str = "rules/magento"


class AppSettings(BaseModel):
    data_dir: str = "data"
    db_path: str = "data/db/lpw.sqlite"
    advisory: AdvisorySettings = Field(default_factory=AdvisorySettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    web: WebSettings = Field(default_factory=WebSettings)
    rules: RulesSettings = Field(default_factory=RulesSettings)

    def resolve(self, root: Path) -> "AppSettings":
        """Resolve relative paths against project root."""
        data = self.model_copy(deep=True)
        data.data_dir = _resolve(root, data.data_dir)
        data.db_path = _resolve(root, data.db_path)
        data.scan.mirrors_dir = _resolve(root, data.scan.mirrors_dir)
        data.advisory.patch_cache_dir = _resolve(root, data.advisory.patch_cache_dir)
        if data.scan.local_root:
            data.scan.local_root = _resolve(root, data.scan.local_root)
        if data.advisory.fixture_dir:
            data.advisory.fixture_dir = _resolve(root, data.advisory.fixture_dir)
        if data.advisory.local_index_html:
            data.advisory.local_index_html = _resolve(root, data.advisory.local_index_html)
        data.rules.dir = _resolve(root, data.rules.dir)
        return data


def _resolve(root: Path, value: str) -> str:
    if Path(value).is_absolute():
        return value
    return str((root / value).resolve())


class EnvSecrets(BaseSettings):
    """Secrets from process env and/or project-root ``.env`` (never commit .env)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    lpw_admin_password_hash: Optional[str] = None
    lpw_session_secret: Optional[str] = None

    @property
    def admin_password_hash(self) -> Optional[str]:
        return self.lpw_admin_password_hash

    @property
    def session_secret(self) -> Optional[str]:
        return self.lpw_session_secret


def load_env_secrets(root: Optional[Path] = None) -> EnvSecrets:
    """Load secrets from ``<root>/.env`` (and real environment variables)."""
    root = (root or default_root()).resolve()
    env_file = root / ".env"
    # pydantic-settings accepts _env_file even when the path is missing.
    return EnvSecrets(_env_file=env_file)  # type: ignore[call-arg]


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return data


def load_settings(config_dir: Path, root: Optional[Path] = None) -> AppSettings:
    root = root or config_dir.parent
    settings_path = config_dir / "settings.yaml"
    raw = load_yaml(settings_path)
    settings = AppSettings.model_validate(raw)
    return settings.resolve(root)


def ensure_data_dirs(settings: AppSettings) -> Dict[str, Path]:
    base = Path(settings.data_dir)
    paths = {
        "data": base,
        "db": Path(settings.db_path).parent,
        "mirrors": Path(settings.scan.mirrors_dir),
        "patch_cache": Path(settings.advisory.patch_cache_dir),
        "locks": base / "locks",
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)
    return paths


def default_root() -> Path:
    env = os.environ.get("LPW_ROOT")
    if env:
        return Path(env).resolve()
    return Path.cwd().resolve()
