# Installation

## From PyPI

Use Python 3.11, 3.12 or 3.13 in a fresh virtual environment. On 3.12, use
3.12.4 or later: on CPython 3.12.0 to 3.12.3 (Ubuntu 24.04 ships 3.12.3) a
file with a very long line can leave a scan incomplete (exit 3). ShadowScan
needs a POSIX platform — CI covers Linux and macOS, and deployments are
validated on Linux x86_64. Windows is unsupported: the confined file reader
needs `O_NOFOLLOW` and `dir_fd`, so every command except `--help` and
`--version` exits 1 there, even though the universal wheel installs.

```bash
python -m pip install NexusShadowScan            # or: pipx install NexusShadowScan
python -m pip install "NexusShadowScan[cloud]"   # adds the AWS, GCP, Azure and OCI SDKs
shadowscan connectors                            # smoke test: fails on an unsupported platform, --help does not
```

The distribution is `NexusShadowScan`; the command and Python imports are
`shadowscan`. Do not install the unrelated PyPI package named `shadowscan`.
The wheel ships the scanner only: the bundled `agent-card.yaml`, `examples/`
directory and test fixtures that the [quick start](quickstart.md) uses come
from a repository checkout.
Releases reach PyPI only through the maintainer-approved
[publish job](../operations/publishing.md), which uploads the universal wheel
and the sdist that the release-evidence workflow built and attested. Check a
downloaded file against this repository with
`gh attestation verify <file> --repo aisecnomad/Nexus-ShadowScan`.
0.1.2 was published as a wheel only, attested before the repository was
renamed; verify it with `--repo aisecnomad/Project-Nexus`.

A plain `pip install` resolves dependencies from the live index. For a
deployment, prefer the hash-locked install.

## From a reviewed revision (hash-locked)

For deployment on Linux x86_64, use a reviewed full commit SHA and the
repository's hash-locked runtime dependencies. CI validates Python 3.11, 3.12
and 3.13 on Linux x86_64; see
[production deployment](../production.md#install-from-a-reviewed-revision)
for the release evidence and platform limits.

```bash
SHADOWSCAN_REVISION="REPLACE_WITH_REVIEWED_40_CHARACTER_SHA"
git clone https://github.com/aisecnomad/Nexus-ShadowScan.git
cd Nexus-ShadowScan
git checkout --detach "$SHADOWSCAN_REVISION"
test "$(git rev-parse HEAD)" = "$SHADOWSCAN_REVISION"
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements-build.lock
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
python -m pip install --no-deps dist/nexusshadowscan-*.whl
python -m pip check
cd "$(mktemp -d)"   # leave the checkout: `python -m` would import ./shadowscan instead of the wheel
python -m shadowscan.signatures.validate
python -m shadowscan.mappings.validate
shadowscan connectors
```

Use a fresh virtual environment when migrating from earlier Project Nexus
builds, whose distribution names were `shadowscan` or
`project-nexus-shadowscan` (installed from a checkout or git revision — neither
was published to PyPI, and the unrelated `shadowscan` package on PyPI is a
different project), to avoid overlapping files from the old distribution.

The runtime lock includes core and all cloud SDK dependencies, even for a
code-only worker. Retain the selected commit and built wheel hash. Other
platforms need a separately validated lock; a commit SHA alone does not pin
transitive dependencies.

The [consumer CI workflow](../operations/ci.md#github-actions) checks out the
reviewed scanner commit, installs both runtime and build locks with hash checks,
and installs its built wheel without resolving new runtime dependencies.

## Docker

The disposable non-root worker uses the reviewed index digest pinned in its
literal `Dockerfile` `FROM` line. Review that pin and any Dependabot update:

```bash
docker build --tag shadowscan:reviewed .
```

See [production deployment](../production.md) for container isolation and
rollout acceptance requirements.
