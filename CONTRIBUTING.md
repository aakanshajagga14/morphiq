# Contributing to MorphIQ

Thank you for helping improve MorphIQ. Bug reports, documentation fixes, tests, and focused feature proposals are welcome.

## Development setup

1. Fork and clone the repository.
2. Create a virtual environment with Python 3.11 or newer.
3. Install development dependencies:

   ```bash
   python -m pip install -e ".[dev]"
   ```

4. Create a branch from `main`.
5. Run the test suite before opening a pull request:

   ```bash
   pytest
   ```

## Pull requests

- Keep each pull request focused on one change.
- Add or update tests when behavior changes.
- Update the README or configuration documentation when public behavior changes.
- Do not commit logs, databases, model weights, credentials, or local environment files.
- Explain security implications for changes to detection, firewall, parsing, or LLM behavior.

## Reporting security issues

Do not disclose exploitable vulnerabilities in a public issue. Follow the private reporting guidance in [SECURITY.md](SECURITY.md).
