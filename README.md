# VulnBlend

VulnBlend is a locally restricted academic research dashboard for controlled hybrid web vulnerability analysis. It combines Python AST static analysis, safe dynamic probes, endpoint inventory, evidence correlation, transparent risk prioritization, experiment metrics, and report exports.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py --server.address 0.0.0.0 --server.port 3000
```

Open the local Streamlit URL. The first run creates `data/vulnblend.db` and seeds a clearly labelled laboratory dataset. Use **New Scan** to run analysis against the included `testbed/app` source directory or an explicitly registered laboratory target.

## Docker lab

```bash
docker compose up --build
```

The Compose network is marked internal. The scanner is intended to communicate only with the deliberately vulnerable `testbed` service. Do not register public production systems. VulnBlend rejects unsupported schemes, public hosts, cloud metadata addresses, out-of-scope redirects, and targets without authorization confirmation.

## Architecture

`app.py` owns the Streamlit shell and routes to dedicated modules in `pages/`. The `vulblend/` package contains SQLite migrations, repositories, safety controls, the AST analyzer, crawler/dynamic adapters, correlation, risk scoring, experiment metrics, and reporting. `testbed/` contains the isolated lab target and ground truth metadata.

## Evidence and data policy

Static matches are potential findings until corroborated. Dynamic testing uses harmless markers and baseline comparisons. Evidence is minimized and redacted before persistence. Demo rows carry `data_origin=demo` and are visibly labelled in the interface. The risk formula and thresholds are research choices, not a security standard.

## Tests

```bash
pytest -q
python -m compileall app.py vulblend pages
```

Playwright is optional in a basic local install; if browser binaries are unavailable, the UI reports a partial/blocked crawl instead of fabricating coverage.

## Known limitations

The first release is optimized for Python web patterns and SQLi/XSS lab cases. Full authenticated crawling, additional languages, production-grade multi-user authentication, persistent background workers, and trained ML risk prediction are future extensions. Never use this application to scan systems without explicit authorization.
