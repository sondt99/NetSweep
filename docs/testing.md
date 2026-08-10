# Testing

## Run the suite

```bash
pip install -e ".[dev]"
pytest tests/ -q
pytest tests/ -v --tb=short
pytest --cov=netsweep --cov-report=term-missing -q
```

`pyproject.toml` sets `pythonpath = ["."]` so imports resolve from the repo root.

## Layout

```text
tests/
├── conftest.py                 # log isolation, path setup
├── test_config.py
├── test_device_info.py
├── test_error_handler.py
├── test_host_scanner.py
├── test_main.py
├── test_network_scanner.py
├── test_network_utils.py
├── test_port_scanner.py
├── test_service_detector.py
├── test_system_utils.py
└── test_v5_security_fixes.py   # hardening regressions
```

## Conventions

1. Import **implementation modules** under `netsweep.*` when monkeypatching:

   ```python
   import netsweep.scan.device as device_info_module
   from netsweep.scan.device import DeviceInfo
   ```

2. Prefer loopback TCP listeners over real network targets.  
3. Never call external vendor APIs without mocking `requests.get`.  
4. Scapy paths: mock `sr1` on `netsweep.scan.ports`.  
5. Keep tests offline-friendly (CI without root / without nmap).  

## What is well covered

- Config load/save/validate  
- Device liveness edge cases (ARP false-alive regression)  
- Port connect open/closed classification  
- Service banner classification and export redaction  
- Menu helpers and in-process scanner dispatch  
- Scope / port parse / banner redaction security fixes  

## Gaps / future tests

- Full interactive menu loops  
- Live LAN integration (mark `@pytest.mark.live`)  
- Root-only SYN/UDP with real scapy  
- Bash `netscan.sh` (bats/shellspec)  

## Writing a new regression test

```python
# tests/test_my_fix.py
def test_behavior():
    """Regression: short description of the bug that existed."""
    ...
```

Run a single file:

```bash
pytest tests/test_my_fix.py -v
```

## Continuous integration

No required CI config is mandated by the package, but a typical GitHub Actions job is:

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: pip install -e ".[dev]"
- run: pytest tests/ -q
```
