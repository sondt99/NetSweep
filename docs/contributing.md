# Contributing

Thanks for improving NetSweep.

## Before you start

1. Read [security.md](security.md) — only test on authorized systems.  
2. Open an issue for large changes when possible.  
3. Use the [issue templates](https://github.com/sondt99/NetSweep/issues/new/choose).  

## Development setup

```bash
git clone https://github.com/sondt99/NetSweep.git
cd NetSweep
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -q
```

## Code guidelines

- Put new logic under **`netsweep/`** only (`run.py` stays a thin launcher).  
- Respect layering: `cli` → `scan` → `net`/`config`/`policy`/`data`.  
- Prefer type hints and small, testable functions.  
- Do not reintroduce shell=True for user-controlled data.  
- Redact secrets in logs/exports.  
- Keep default security limits enforced.  

## Pull requests

Use the PR template checklist:

- [ ] Tests added/updated  
- [ ] `pytest tests/ -q` passes  
- [ ] CHANGELOG updated for user-visible changes  
- [ ] No secrets or scan artifacts committed  
- [ ] Linked issue (`Fixes #…`)  

## Versioning

- Patch: bugfixes  
- Minor (e.g. 5.1 → 5.2): features, non-breaking package changes  
- Major (6.0): public API freezes / remotions as needed  

## Security reports

Do not file public exploit details for unfixed issues. Use [SECURITY.md](../SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the MIT License covering this project.
