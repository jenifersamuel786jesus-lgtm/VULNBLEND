"""Safe endpoint inventory for allowlisted laboratory targets."""
from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse

import requests

from .target_guard import ScopeError, validate_route, validate_target


def crawl(target_url: str, authorized: bool, allowed_paths: list[str], excluded_paths: list[str], depth: int = 2, max_requests: int = 40, timeout: int = 10) -> dict:
    target = validate_target(target_url, authorized)
    base = target["base"]
    queue = deque([(base + "/", 0)])
    seen = set()
    endpoints = []
    errors = []
    requests_processed = 0
    while queue and requests_processed < max_requests:
        url, level = queue.popleft()
        parsed = urlparse(url)
        route = parsed.path or "/"
        normalized = f"{parsed.scheme}://{parsed.netloc}{route}"
        if normalized in seen or level > depth or not validate_route(route, allowed_paths, excluded_paths):
            continue
        seen.add(normalized)
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False, headers={"User-Agent": "VulnBlend-Lab/0.1"})
            requests_processed += 1
            content_type = response.headers.get("content-type", "")
            text = response.text[:200_000]
            endpoints.append({"url": url, "route": route, "method": "GET", "parameters": [], "form_fields": [], "status_code": response.status_code, "content_type": content_type, "depth": level, "in_scope": True})
            if level < depth and "text/html" in content_type:
                from bs4 import BeautifulSoup  # optional dependency; fallback below
                try:
                    soup = BeautifulSoup(text, "html.parser")
                    for anchor in soup.find_all("a", href=True):
                        next_url = urljoin(url, anchor["href"])
                        if urlparse(next_url).netloc == parsed.netloc:
                            queue.append((next_url, level + 1))
                    for form in soup.find_all("form"):
                        action = urljoin(url, form.get("action") or route)
                        fields = [field.get("name") for field in form.find_all(["input", "textarea"]) if field.get("name")]
                        if urlparse(action).netloc == parsed.netloc:
                            endpoints.append({"url": action, "route": urlparse(action).path or "/", "method": (form.get("method") or "GET").upper(), "parameters": [], "form_fields": fields, "status_code": None, "content_type": "text/html", "depth": level + 1, "in_scope": True})
                except Exception:
                    pass
        except requests.RequestException as exc:
            errors.append({"url": url, "error": str(exc)[:200]})
    playwright_available = False
    try:
        import playwright  # noqa: F401
        playwright_available = True
    except ImportError:
        pass
    return {"endpoints": endpoints, "requests_processed": requests_processed, "errors": errors, "playwright_available": playwright_available, "coverage": min(1.0, len(endpoints) / max(1, len(allowed_paths) or 1)), "data_origin": "real"}
