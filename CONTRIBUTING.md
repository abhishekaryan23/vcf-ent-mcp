# Contributing

Thanks for looking. This is an unofficial, under-testing project maintained by one person, so small and focused changes are easiest to review.

## Before you start

- Open an issue first for anything bigger than a bug fix or a doc correction.
- Read the README's "Known limitations" and `docs/audits/independent_review_2026_11_02.md`: several open items are already tracked there.
- Do not test against a production VCF, and never put real hostnames, addresses, tokens or passwords in code, tests, docs or issues. Use fictional names (`corp.example`, `corp.com`, `nwg.lab`).

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

The suite runs offline against simulators and in an isolated temporary home directory (see `tests/conftest.py`); a test must never write outside the repository or a temp folder, or depend on your machine. API-contract tests read Broadcom's specifications from your own clone: set `VCF_API_SPECS_DIR` to a checkout of github.com/vmware/vcf-api-specs to include them. Broadcom's specification data is not committed here.

Guidelines:

- Add or update a test with every behaviour change; keep failures actionable (say what to change).
- Security-relevant paths (auth, approvals, SSRF guard, credential handling, safety profile) need a test that fails without the fix.
- Keep user-facing text and docs honest: describe only what exists and say when something is unverified against a real appliance.
- Keep the diff focused, and write commit messages that say why.

## License of contributions

This project is licensed under the [MIT License](LICENSE). By submitting a contribution you agree that it is provided under the same license.

## Security issues

Do not file them as public issues; follow [SECURITY.md](SECURITY.md).
