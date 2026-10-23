# Publishing a release

This runbook is for the maintainer. It covers the one-time setup and the
per-release steps that put a reviewed ShadowScan release on PyPI as
`NexusShadowScan`, so that `pip install NexusShadowScan` installs it.

Publishing is a manual maintainer action and comes after the
[release process](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/GOVERNANCE.md#release-process):
independent human review of the exact candidate commit and the acceptance
evidence for its deployment scope. Coding agents prepare candidates. They
never push a version tag, dispatch the workflow with `publish` set, or approve
a deployment.

## How an upload is gated

The [release-evidence workflow](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/workflows/release.yml)
(**Release candidate evidence**) is the only path to the package index. No
package-index token exists: PyPI trusts this repository's workflow and
environment through OpenID Connect (trusted publishing).

Release tags are annotated and may be unsigned. No personal SSH or GPG signing
key is required: package provenance comes from the workflow's GitHub
attestations and the PyPI publish attestations. These identify the build and
publishing workflow; they do not establish a personal signature on the Git tag
or replace independent human review.

| Job | What it enforces | Permissions |
|---|---|---|
| `build` | Runs on `main` only. The commit must equal `expected_commit` and have successful push CI and CodeQL runs. Checks the live merge ruleset against the administrator readback passed at dispatch (see below). From a clean `git archive`, `python -m build --no-isolation` writes the sdist and then builds the wheel from that sdist with the hash-locked backend. `tools/release/distributions.py` requires one universal `py3-none-any` wheel and one sdist of the same version, with identical core metadata and package files, and an sdist of plain files under one root without the test suite. The job then installs the wheel outside the checkout, smoke-scans, and records the SBOM and `SHA256SUMS`. | read |
| `attest` | GitHub provenance attestations for the candidate files and SBOM attestations for the wheel and sdist. No checkout. | `id-token`, `attestations` |
| `publication-input` | Reassembles the attested bytes and checks for exactly one wheel and one sdist of the same version. | none |
| `publication-gate` | Runs only when `publish` is `testpypi` or `pypi`. Requires one wheel and one sdist whose digests match, a public release version (no `.dev`, `.post` or local part), and, for `pypi`, the tag `v<version>` on the reviewed commit. | `contents: read` |
| `publish` | Waits for approval in the protected environment named by `publish`. Checks out nothing, verifies the digests, and uploads only that wheel and sdist with [`pypa/gh-action-pypi-publish`](https://github.com/pypa/gh-action-pypi-publish), which checks their metadata and adds PEP 740 attestations. | `id-token` only |
| `release-assets` | Optional, after successful `pypi` publication and another protected `pypi` approval. Verifies the original bundles against the exact source SHA and release workflow, checks the existing tag/release, and attaches the candidate and bundles without replacing mismatched assets. Never creates a release or tag. | `contents: write` only |

With the default `publish: none`, the workflow builds and attests a review
bundle and uploads nothing. `tests/test_repository_policy.py` fails CI if any
of these gates is removed, or if any other workflow, job or command uploads a
package. `attach_github_release` defaults to `false`. It is effective only
with `publish: pypi`; evidence-only and TestPyPI runs cannot attach assets.

## One-time setup

1. **PyPI and TestPyPI accounts.** They are separate accounts. Both require
   two-factor authentication; prefer a hardware security key.
2. **Pending trusted publishers.** On PyPI, open
   [Publishing](https://pypi.org/manage/account/publishing/) and add a GitHub
   pending publisher:

   | Field | Value |
   |---|---|
   | PyPI project name | `NexusShadowScan` |
   | Owner | `aisecnomad` |
   | Repository name | `Nexus-ShadowScan` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

   Repeat on [TestPyPI](https://test.pypi.org/manage/account/publishing/) with
   the environment name `testpypi`. A pending publisher does not reserve the
   name, and someone else can still register it. Publish the first release
   soon after you register the publisher. Do not remove the publisher
   afterwards; it becomes the project's publisher. The publisher names the
   repository, so a rename needs the steps in
   [Renaming the repository](#renaming-the-repository).
3. **GitHub environments.** Under **Settings → Environments**, create `pypi`
   and `testpypi`:
   - **Required reviewers:** the maintainer. Add a second reviewer and turn on
     **Prevent self-review** as soon as one exists.
   - **Deployment branches and tags:** selected branches only, `main`.
   - **Secrets:** none. Trusted publishing needs no token, and a stored token
     would bypass these gates.
4. **Protect release tags.** Use an active tag ruleset targeting `v*` that
   blocks updates and deletion, with no bypass actors. The maintainer creates
   the initial tag after review. The publication gate reads the tag before the
   approval wait, and the ruleset keeps that answer true until the upload.

## Per release

1. **Prepare the candidate.** Set the same version in `pyproject.toml`,
   `shadowscan/__init__.py` and `CITATION.cff` (CI checks that they match).
   Date the release headings in `CHANGELOG.md`, `docs/engineering-log.md` and
   `RELEASE_NOTES.md` and remove "unreleased" from them. `README.md` is the
   PyPI project description, frozen with every upload (the TestPyPI rehearsal
   included), so it must already read correctly for the published release: no
   planned date, no earlier release named as the latest, no wording that calls
   the candidate unpublished, and its images pinned to a commit on `main` whose
   `docs/assets` files are byte-identical to the candidate's. CI's depth-1
   checkouts cannot read the pinned commit, so in a full clone checked out at
   the candidate run
   `SHADOWSCAN_RELEASE_CANDIDATE=1 python -m pytest -rs tests/test_repository_consistency.py -k readme_images`
   and confirm both tests passed rather than skipped; re-pin the images in a
   reviewed change if they fail. Merge through the normal review process.
2. **Review and accept the exact commit**, as the
   [release process](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/GOVERNANCE.md#release-process)
   requires. A green CI run is not that review.
3. **Rehearse on TestPyPI.** The upload freezes `README.md` as that
   version's project description, so first repeat the step 1 `readme_images` check in a
   full clone at the reviewed commit. Dispatch **Release candidate evidence** on
   `main` from an administrator-authenticated GitHub CLI, then approve the
   `testpypi` deployment:

   ```bash
   gh workflow run release.yml --repo aisecnomad/Nexus-ShadowScan --ref main \
     -f expected_commit=<reviewed-40-character-sha> \
     -f ci_run_id=<its successful push CI run> \
     -f codeql_run_id=<its successful push CodeQL run> \
     -f ruleset_readback="$(gh api repos/aisecnomad/Nexus-ShadowScan/rulesets/23913372)" \
     -f publish=testpypi
   ```

   GitHub withholds the ruleset's `bypass_actors` from the workflow's
   read-only token, and an omitted field cannot prove that nobody can bypass
   the rules. `ruleset_readback` supplies it from your administrator read. The
   build job accepts the readback only if it matches the job's own read in
   every other field, `updated_at` included, so take it just before you
   dispatch, and the evidence records where `bypass_actors` came from.
   Check the project page renders, then install in a throwaway environment.
   Use `--no-deps`, so that TestPyPI, where anyone can register names, never
   supplies a dependency:

   ```bash
   python -m venv /tmp/nss && . /tmp/nss/bin/activate
   python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
   python -m pip install --no-deps --index-url https://test.pypi.org/simple/ NexusShadowScan==0.1.3
   # Leave the checkout: `python -m` would otherwise import its source, not the installed wheel.
   cd "$(mktemp -d)" && shadowscan --help && python -m shadowscan.signatures.validate && python -m shadowscan.mappings.validate
   ```

4. **Tag the reviewed commit.** Create an annotated tag on that exact commit.
   The default release path uses an unsigned tag and needs no personal signing
   key. `--no-sign` overrides any local `tag.gpgSign` preference:

   ```bash
   git tag --no-sign -a v0.1.3 -m "NexusShadowScan 0.1.3" <reviewed-40-character-sha>
   git push origin refs/tags/v0.1.3
   ```

   A maintainer may instead sign the annotated tag with `git tag -s` when a
   signing key is available. Signing is optional. Both routes require the
   reviewed commit, immutable tag protections, successful CI and CodeQL,
   artifact attestations, and approval in the protected publishing environment.

5. **Publish.** Dispatch the workflow again with the same inputs, a fresh
   `ruleset_readback`, and `publish: pypi`, then approve the `pypi`
   deployment. The gate rejects the
   run unless `v<version>` points at `expected_commit`.

   To attach evidence automatically, first create a **draft GitHub release**
   for that existing tag, with the version's release notes. Set
   `-f attach_github_release=true` on this production dispatch. After the
   index upload succeeds, approve the separate `release-assets` job in the
   protected `pypi` environment. This attaches to your existing draft; it
   does not publish it. A draft supports attachment before GitHub makes an
   immutable release final. Existing mutable releases are also supported.
6. **Verify what was published.** Both files must be on the index, and each
   must match its attestation. Download them into a hash-locked environment,
   so that preparing the sdist's metadata uses the locked backend rather than
   one resolved from the index:

   ```bash
   version=0.1.3
   python -m venv "${TMPDIR:-/tmp}/rebuild" && "${TMPDIR:-/tmp}/rebuild/bin/python" -m pip install \
     --require-hashes --only-binary=:all: -r requirements-build.lock
   "${TMPDIR:-/tmp}/rebuild/bin/python" -m pip download --no-deps --only-binary=:all: \
     --dest dists "NexusShadowScan==$version"
   "${TMPDIR:-/tmp}/rebuild/bin/python" -m pip download --no-deps --no-binary=:all: --no-build-isolation \
     --dest dists "NexusShadowScan==$version"
   for file in "dists/nexusshadowscan-$version-py3-none-any.whl" "dists/nexusshadowscan-$version.tar.gz"; do
     gh attestation verify "$file" --repo aisecnomad/Nexus-ShadowScan
   done
   ```

   Compare both SHA-256 digests with `SHA256SUMS` in the retained
   `release-candidate-<SHA>` artifact. On PyPI, each file's provenance should
   name this repository, `release.yml` and the `pypi` environment.

   To confirm the wheel from source rather than from the attestation, rebuild
   it the way `release.yml` does and compare digests. The wheel is built from
   the sdist, which normalizes file modes, and every wheel entry is stamped
   with the commit time (`SOURCE_DATE_EPOCH`), so a rebuild of the tagged
   commit with the same hash-locked backend and a default umask yields the
   same wheel; `make build` applies the same stamp to a local build. The sdist
   itself is not byte-reproducible, because setuptools records build-time file
   times in it; its attestation and `SHA256SUMS` entry identify it.

   ```bash
   git -c advice.detachedHead=false checkout --detach "v$version"
   SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" "${TMPDIR:-/tmp}/rebuild/bin/python" -m build \
     --no-isolation --outdir "${TMPDIR:-/tmp}/rebuild/dist" .
   sha256sum "${TMPDIR:-/tmp}/rebuild/dist/"nexusshadowscan-*.whl dists/nexusshadowscan-*.whl
   ```

   A differing wheel digest means the published wheel was not built from that
   commit with that backend; treat it as a release incident. Release 0.1.2
   predates the sdist: it was a wheel built with `pip wheel` from a
   `git archive`, and was attested as `aisecnomad/Project-Nexus` before the rename.
7. **Optionally, publish the GitHub release by hand** after checking the
   index and its fresh-install smoke test. If step 5 attached the evidence to
   your draft, verify the job's asset digest receipt and publish that draft.
   The workflow never creates or publishes a GitHub release.

   The attachment job executes the standard-library helper
   `tools/release/assets.py` from the reviewed source. It verifies the
   original Sigstore bundles with GitHub CLI, constraining the repository,
   `release.yml`, `refs/heads/main`, source SHA, signer SHA and hosted-runner
   identity. It checks the candidate's recorded run, checksums and tag, then
   uploads all checksummed candidate files (including the wheel, sdist,
   runtime SBOM and dependency locks), `SHA256SUMS`,
   `provenance.sigstore.json` and `sbom.sigstore.json`.
   It reads back GitHub's SHA-256 asset digests. A retry skips matching assets;
   a conflicting or unverifiable asset fails, without `--clobber`.
   Partial upload failures must be investigated before retrying the failed
   job. Do not rerun the successful PyPI upload just to retry attachments.

   For manual attachment, download `release-publication-input-<SHA>` from the
   exact production run. A verification-only check is:

   ```bash
   python -m tools.release.assets --directory publication-input \
     --repository aisecnomad/Nexus-ShadowScan --commit "$commit" --run-id "$run_id"
   ```

   Set `commit` and `run_id` to the reviewed SHA and successful production
   run first. Only a maintainer adds `--upload` to attach the verified files
   to an existing release; the default command performs no mutation.

   The provenance bundle covers every candidate file, `SHA256SUMS` included.
   Anyone can verify a downloaded file against the original bundle from the
   same release:

   ```bash
   gh attestation verify "nexusshadowscan-$version-py3-none-any.whl" \
     --repo aisecnomad/Nexus-ShadowScan --bundle provenance.sigstore.json \
     --signer-workflow aisecnomad/Nexus-ShadowScan/.github/workflows/release.yml \
     --source-ref refs/heads/main --source-digest "$commit" --signer-digest "$commit" \
     --deny-self-hosted-runners
   ```

   For the SBOM bundle, add `--predicate-type https://cyclonedx.org/bom` and
   use `--bundle sbom.sigstore.json`. Verification identifies build provenance;
   it does not prove independent review or tenant acceptance.

   As checked on October 20, 2026, the upstream OpenSSF Scorecard
   [signature probe](https://github.com/ossf/scorecard/blob/main/probes/releasesAreSigned/impl.go)
   recognizes `.sigstore.json` assets by filename, without verifying their
   signatures. Our helper verifies the original bundles cryptographically;
   their filenames qualify for Scorecard's signature category, worth 8 per
   release under its current
   [evaluator](https://github.com/ossf/scorecard/blob/main/checks/evaluation/signed_releases.go).
   Its separate
   [provenance probe](https://github.com/ossf/scorecard/blob/main/probes/releasesHaveProvenance/impl.go)
   recognizes `.intoto.jsonl` filenames for the 10-point category. Preserve
   the original Sigstore format; do not rename bundles to satisfy that check.

   The probes inspect the first five release entries and skip entries without
   assets. The evaluator rounds down the average of the resulting per-release
   scores, including zero for releases with neither recognized asset type.
   Attaching these verified bundles therefore does not guarantee a
   Signed-Releases score of 10. The
   [aggregate score](https://github.com/ossf/scorecard#aggregate-score)
   also weights other checks by risk; an overall score above 8.5 requires an
   observed Scorecard result and is not promised by this workflow.
8. **Record the publication.** Until this step lands, the repository
   describes the candidate as prepared, not published. In one reviewed change
   on `main`, update every place that names the published release, with the
   day the tag and the upload happened:
   - `docs/reference/product-guide.md`: the **Release state** bullet
     (published version, tag, PyPI and GitHub release links), the "PyPI
     requirements" note under **Install** (the Python range of the published
     wheel) and the link to the published alpha's documentation. `README.md`
     names no release and needs no change here: it shipped as the frozen
     description (step 1), and an edit after the upload never reaches PyPI.
   - `docs/getting-started/install.md`: the published version, its Python
     range and the attestation `--repo` note.
   - `docs/connectors.md`: the release-status refresh date and the
     "Published" row of the evidence table (release page and the approval of
     the release source tree, named as independent only when its reviewer
     is not an author or co-author of that change; see GOVERNANCE.md).
   - `docs/operations/openssf-best-practices.md`: the `version_tags` row and
     the `release_notes` evidence; `docs/operations/reviewer-packet.md`: the
     version string that must not be read as published.
   - `ROADMAP.md` (the "Done" release bullet) and `SECURITY.md`
     (supported versions).
   - `CHANGELOG.md`, `RELEASE_NOTES.md`, `docs/engineering-log.md` and
     `CITATION.cff`: the release date, when the tag landed on another day
     than the headings say.
   - `tests/test_repository_consistency.py`: the pins that name the published
     version and its Python range, so the tests keep guarding the new text.

   `make policy` and `make docs` must pass on that change.
9. **Open the next candidate.** Bump the version (for example to `0.1.4`) and
   add a new unreleased section to the changelog and release notes.

## Renaming the repository

The trusted publishers, the attestation identity and the Pages address all
contain the repository name; GitHub's redirects cover only web, API and Git
URLs. The repository was renamed from `aisecnomad/Project-Nexus` to
`aisecnomad/Nexus-ShadowScan`. For this or any later rename, in this order:

1. Rename it under **Settings → General → Repository name**. Rulesets,
   environments, secrets and the numeric repository ID, which the scheduled
   governance audit is pinned to, carry over.
2. Merge the change that updates the in-repository references. The weekly
   governance audit compares each ruleset's `source` with the name in
   `tools/governance/rulesets.py`, so it fails, rather than skips, until that
   change is on `main`.
3. On PyPI and TestPyPI, add a trusted publisher with the new repository name
   (same workflow `release.yml` and environment `pypi` or `testpypi`), then
   remove the publisher that names the old repository. The OIDC token carries
   the new name, so an upload fails until the publisher matches it.
4. Check GitHub Pages: a project site is served only under the new name, and
   the old path does not redirect. Update links to it, and dispatch the Docs
   workflow with `publish: true` again if the site is deployed from it.
5. Point local clones at the new URL with
   `git remote set-url origin https://github.com/aisecnomad/Nexus-ShadowScan.git`.
6. Upload the first release under the new name more than 14 days after the
   last release, by PyPI upload time; otherwise PyPI flags it with a
   **Change of provenance** warning that stays on that release (see below).
   If it cannot wait, name the rename in that release's notes.

Attestations keep the name they were signed under. Verify files released
before a rename with the old `--repo` value, as the install instructions do
for 0.1.2.

PyPI shows a **Change of provenance** warning on a release whose
attestations name a different repository or workflow file from the
previous attested release, when that release was uploaded within 14 days
before it (the window includes its far edge). As checked on October 22, 2026,
PyPI's [comparison](https://github.com/pypi/warehouse/blob/4969cf8c4598fb3a5503e1ae88b90db5541240a6/warehouse/attestations/models.py)
matches the publisher's repository name, not the numeric repository ID, and
its [window](https://github.com/pypi/warehouse/blob/4969cf8c4598fb3a5503e1ae88b90db5541240a6/warehouse/packaging/models.py)
is measured back from that release's own upload, so it never expires.
Release 0.1.3 was uploaded 13 days and 20 hours after 0.1.2 and carries the
warning, with the former repository listed as removed and the new one as
added. Both signing certificates name the same Source Repository Identifier
(`1174915264`), which links the two names.

The warning cannot be cleared on 0.1.3 short of deleting 0.1.2, and 0.1.2
stays: attestations cannot be replaced, a file name cannot be uploaded twice,
PyPI offers maintainers no way to dismiss the warning, and yanking 0.1.2 does
not change the comparison. Deleting 0.1.2 would remove a published release
that the install instructions verify with the old `--repo` value, and its file
name could never be uploaded again. The next release from the same repository
and `release.yml` carries no warning: within 14 days of 0.1.3 it is compared
with 0.1.3, and after that it has nothing to compare against. The project
page then shows that release. For a later rename, count the 14 days from the
last release's PyPI upload time, not from the dates in the headings: 0.1.2 and
0.1.3 are dated 14 calendar days apart, yet 0.1.3 was uploaded inside the
window. Otherwise name the rename in the first release's notes, where PyPI's
[guidance](https://github.com/pypi/warehouse/blob/4969cf8c4598fb3a5503e1ae88b90db5541240a6/docs/user/using-pypi/package-security/provenance.md#change-of-provenance)
asks users to confirm the change.

## When something goes wrong

- **A gate fails.** Fix the cause and dispatch again. Check the tag's target
  before pushing; a mistaken local tag can be corrected before it reaches the
  remote. Once pushed, the tag is immutable even if no package was uploaded.
  Prepare a new version if an incorrect tag reached the remote.
- **A bad file reached PyPI.** PyPI never accepts the same file name twice,
  even after deletion. Yank the release in the PyPI project settings, so
  that resolvers skip it unless it is pinned exactly, and publish a fixed
  version. Prefer yanking to deleting, and explain the reason in the yank
  message and the release notes.
- **Suspected compromise of the repository or its workflow.** Remove the trusted
  publisher on PyPI first; this stops further uploads with nothing to rotate.
  Then follow [SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md).
