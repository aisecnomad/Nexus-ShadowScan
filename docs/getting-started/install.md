# Installation

## From PyPI

The published alpha `0.1.3` supports Python 3.11–3.14 (on 3.12, use 3.12.4 or
later). Use a fresh virtual environment:

```bash
python -m pip install NexusShadowScan            # or: pipx install NexusShadowScan
python -m pip install "NexusShadowScan[cloud]"   # adds the AWS, GCP, Azure and OCI SDKs
shadowscan --help
```

The distribution is `NexusShadowScan`; the command and Python imports are
`shadowscan`. Do not install the unrelated PyPI package named `shadowscan`.
Releases reach PyPI only through the maintainer-approved
[publish job](../operations/publishing.md), which uploads the universal wheel
and the sdist that the release-evidence workflow built and attested. Check a
downloaded file against this repository with
`gh attestation verify <file> --repo aisecnomad/Nexus-ShadowScan`.
The 0.1.2 wheel was attested before the repository was renamed; verify it with `--repo aisecnomad/Project-Nexus`.

A plain `pip install` resolves dependencies from the live index. For a
deployment, prefer the hash-locked install.

The current source branch can include changes made after the release. The
PyPI command above does not install them; use a reviewed source revision
below, or consult the
[0.1.3 documentation](https://github.com/aisecnomad/Nexus-ShadowScan/blob/v0.1.3/README.md)
for the published command set.

## From a reviewed revision (hash-locked)

For deployment on Linux x86_64, use a reviewed full commit SHA and the
repository's hash-locked runtime dependencies. CI validates Python 3.11, 3.12,
3.13 and 3.14 on Linux x86_64; see
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
python -m shadowscan.signatures.validate
python -m shadowscan.mappings.validate
shadowscan --help
```

Use a fresh virtual environment when migrating from earlier Project Nexus
builds, which were distributed as `shadowscan` or `project-nexus-shadowscan`, to
avoid overlapping files from the old distribution.

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
