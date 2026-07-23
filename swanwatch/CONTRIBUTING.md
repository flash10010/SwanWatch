# Contributing

1. Fork the repository and create a focused branch.
2. Keep dependencies minimal and avoid external cloud services by default.
3. Add or update tests for parser and security-sensitive changes.
4. Run `python -m unittest discover -s tests` and `python -m py_compile app.py`.
5. Open a pull request describing the user impact, security implications, and upgrade notes.

Feature adapters for SMART, NUT/UPS, GeoIP and additional notification systems should remain optional and fail closed.
