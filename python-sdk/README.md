# hydra-py

Python client for [Hydra](https://github.com/Videe91/hydra) — the programmable living database for agentic AI systems.

**Status: Patch 1 (foundation). No public client surface yet — the foundation is built before the methods land.**

## Install

Local development:

```bash
pip install -e ./python-sdk
```

Once published:

```bash
pip install hydra-py
```

## Roadmap

This SDK is being built across five small patches:

1. **Foundation** (this patch) — HTTP client, types, errors, tests
2. **Ingest + query** — the most-used methods
3. **Lineage + diagnostics** — the living-database loop
4. **Schemas + replication** — completing the v0 surface
5. **Sync mirror + docs + quickstart**

See [HYDRA_SDK_DESIGN_RULES.md](../HYDRA_SDK_DESIGN_RULES.md) at the repo root for the immutable design rules every patch follows.

## Development

```bash
cd python-sdk
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src
```

## License

MIT.
