"""Safety checks for authorized laboratory targets and source paths."""
from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse

from ..config import ALLOWED_HOSTS, ROOT

BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata.azure.internal"}

class ScopeError(ValueError):
    pass


def validate_target(url: str, authorized: bool, allowed_hosts: set[str] | None = None) -> dict:
    if not authorized:
        raise ScopeError("Authorization confirmation is required before scanning.")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("Only HTTP(S) laboratory targets are supported.")
    host = parsed.hostname.lower()
    hosts = allowed_hosts or ALLOWED_HOSTS
    if host in BLOCKED_HOSTS or host not in hosts:
        raise ScopeError(f"Target host '{host}' is not on the VulnBlend laboratory allowlist.")
    try:
        resolved = {ipaddress.ip_address(socket.gethostbyname(host))}
    except (socket.gaierror, ValueError):
        resolved = set()
    for address in resolved:
        if address.is_link_local or address.is_unspecified or address.is_reserved:
            raise ScopeError("Target resolves to a blocked network address.")
        if not (address.is_private or address.is_loopback):
            raise ScopeError("Public targets are disabled by default.")
    return {"scheme": parsed.scheme, "host": host, "port": parsed.port or (443 if parsed.scheme == "https" else 80), "base": f"{parsed.scheme}://{host}:{parsed.port}" if parsed.port else f"{parsed.scheme}://{host}"}


def validate_source_path(source_path: str) -> Path:
    path = Path(source_path).expanduser().resolve()
    if not path.exists() or not path.is_dir():
        raise ScopeError("Source directory does not exist.")
    allowed_root = ROOT.resolve()
    if allowed_root not in path.parents and path != allowed_root:
        raise ScopeError("Source directory must be inside the VulnBlend workspace.")
    return path


def validate_route(route: str, allowed_paths: list[str], excluded_paths: list[str]) -> bool:
    if not route.startswith("/"):
        return False
    if any(route == excluded or route.startswith(excluded.rstrip("/") + "/") for excluded in excluded_paths):
        return False
    return not allowed_paths or any(route == allowed or route.startswith(allowed.rstrip("/") + "/") for allowed in allowed_paths)
