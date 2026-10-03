# Releasing rce-path

The repository builds version 0.1.0 as a wheel and source distribution. Before a
public release, verify availability/ownership of the normalized name `rce-path`
on PyPI and TestPyPI. Configure the repository URL in project metadata after the
actual GitHub repository exists. The local project currently has no Git remote.

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests
python -m mypy
python -m build
python -m twine check dist/*
```

Install the built wheel in a fresh environment and run `rce-path --version` and
`rce-path scan --help`. Run `python scripts/check_install.py` with that environment's
Python for an offline CLI, metadata, typed-marker, and non-execution smoke test.
CI tests Linux and Windows on Python 3.11–3.14. The labeled
fixture gate checks all supported classifications, sink spans, safe controls,
top-level non-execution, and limits. Provider tests run without external access.

To test upload manually (an explicit publishing action):

```bash
python -m twine upload --repository testpypi dist/*
```

Use your TestPyPI credentials and install the exact version in a clean environment.
Install Pydantic from PyPI first, then install the package from TestPyPI with
`--no-deps` to avoid mixing dependency indexes. See the
[official TestPyPI guide](https://packaging.python.org/en/latest/guides/using-testpypi/).

For GitHub/PyPI trusted publishing:

1. Create the GitHub repository and commit this project, including its workflows.
2. Configure a pending/active PyPI publisher for `rce-path`, the repository owner
   and name, workflow `publish.yml`, and environment `pypi`.
3. Create/protect the GitHub `pypi` environment with required reviewers.
4. Ensure `pyproject.toml`, `rce_path.__version__`, CLI version, and report version
   agree; tag the commit `rce-path-v0.1.0` and push that tag.
5. The workflow verifies version, runs tests/checks, builds and checks artifacts,
   then publishes through OIDC. It does not use a stored PyPI API token.

The workflow is present but needs a GitHub repository and PyPI publisher setup.
Use a new version for each upload; PyPI does not allow overwriting a release.
