"""A release uploads one universal wheel and the sdist it was built from, or nothing."""

from __future__ import annotations

import io
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from tools.release import distributions
from tools.release.distributions import release_distributions, verify_distributions

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.1"
SDIST_ROOT = f"nexusshadowscan-{VERSION}"
DIST_INFO = f"nexusshadowscan-{VERSION}.dist-info"
METADATA = (
    f"Metadata-Version: 2.4\nName: NexusShadowScan\nVersion: {VERSION}\n"
    "Requires-Python: <3.15,>=3.11\n\n# Nexus ShadowScan\n"
).encode()
WHEEL = b"Wheel-Version: 1.0\nGenerator: setuptools (84.0.0)\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
PACKAGE = {
    "shadowscan/__init__.py": b'__version__ = "0.1.1"\n',
    "shadowscan/signatures/data/frameworks/frameworks.yaml": b"signatures: []\n",
}


def _sdist_files() -> dict[str, bytes]:
    return {
        "PKG-INFO": METADATA,
        "pyproject.toml": b'[project]\nname = "NexusShadowScan"\n',
        "README.md": b"# Nexus ShadowScan\n",
        "LICENSE": b"Apache License\n",
        "NOTICE": b"Nexus ShadowScan\n",
        "setup.cfg": b"[egg_info]\n",
        **PACKAGE,
    }


def _wheel_files() -> dict[str, bytes]:
    return {
        **PACKAGE,
        f"{DIST_INFO}/METADATA": METADATA,
        f"{DIST_INFO}/WHEEL": WHEEL,
        f"{DIST_INFO}/licenses/LICENSE": b"Apache License\n",
        f"{DIST_INFO}/licenses/NOTICE": b"Nexus ShadowScan\n",
        f"{DIST_INFO}/RECORD": b"",
    }


def _write_sdist(
    path: Path, files: dict[str, bytes], extra: Callable[[tarfile.TarFile], None] | None = None
) -> None:
    with tarfile.open(path, "w:gz") as archive:
        directory = tarfile.TarInfo(SDIST_ROOT)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, data in files.items():
            info = tarfile.TarInfo(f"{SDIST_ROOT}/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        if extra is not None:
            extra(archive)


def _write_wheel(path: Path, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)


def _pair(
    directory: Path,
    *,
    sdist: dict[str, bytes] | None = None,
    wheel: dict[str, bytes] | None = None,
    extra: Callable[[tarfile.TarFile], None] | None = None,
    wheel_name: str = f"nexusshadowscan-{VERSION}-py3-none-any.whl",
    sdist_name: str = f"nexusshadowscan-{VERSION}.tar.gz",
) -> Path:
    directory.mkdir(exist_ok=True)
    _write_sdist(directory / sdist_name, _sdist_files() if sdist is None else sdist, extra)
    _write_wheel(directory / wheel_name, _wheel_files() if wheel is None else wheel)
    return directory


def test_matching_universal_wheel_and_sdist_pass(tmp_path: Path) -> None:
    assert verify_distributions(_pair(tmp_path / "dist")) == {
        "version": VERSION,
        "wheel": f"nexusshadowscan-{VERSION}-py3-none-any.whl",
        "sdist": f"nexusshadowscan-{VERSION}.tar.gz",
    }


def _symlink(archive: tarfile.TarFile) -> None:
    link = tarfile.TarInfo(f"{SDIST_ROOT}/shadowscan/linked.py")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    archive.addfile(link)


def _hardlink(archive: tarfile.TarFile) -> None:
    link = tarfile.TarInfo(f"{SDIST_ROOT}/shadowscan/linked.py")
    link.type = tarfile.LNKTYPE
    link.linkname = f"{SDIST_ROOT}/LICENSE"
    archive.addfile(link)


def _outside_root(archive: tarfile.TarFile) -> None:
    info = tarfile.TarInfo("elsewhere/setup.py")
    info.size = 0
    archive.addfile(info, io.BytesIO(b""))


def _traversal(archive: tarfile.TarFile) -> None:
    info = tarfile.TarInfo(f"{SDIST_ROOT}/../escape.py")
    info.size = 0
    archive.addfile(info, io.BytesIO(b""))


def _absolute(archive: tarfile.TarFile) -> None:
    info = tarfile.TarInfo("/tmp/escape.py")
    info.size = 0
    archive.addfile(info, io.BytesIO(b""))


def _current_directory(name: str) -> Callable[[tarfile.TarFile], None]:
    def add(archive: tarfile.TarFile) -> None:
        directory = tarfile.TarInfo(name)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)

    return add


def _duplicate(archive: tarfile.TarFile) -> None:
    data = b"replaced\n"
    info = tarfile.TarInfo(f"{SDIST_ROOT}/shadowscan/__init__.py")
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        pytest.param(_symlink, "not a regular file", id="symlink"),
        pytest.param(_hardlink, "not a regular file", id="hardlink"),
        pytest.param(_outside_root, "outside", id="outside-root"),
        pytest.param(_traversal, "unsafe member path", id="parent-traversal"),
        pytest.param(_absolute, "unsafe member path", id="absolute-path"),
        pytest.param(_duplicate, "repeats member", id="duplicate-member"),
        pytest.param(_current_directory("./"), "unsafe member path", id="dot-slash"),
        pytest.param(_current_directory("."), "unsafe member path", id="dot"),
    ],
)
def test_sdist_members_must_be_plain_files_under_one_root(
    tmp_path: Path, extra: Callable[[tarfile.TarFile], None], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        verify_distributions(_pair(tmp_path / "dist", extra=extra))


@pytest.mark.parametrize(
    ("limit", "message"),
    [("_MAX_MEMBERS", "too many members"), ("_MAX_MEMBER_BYTES", "exceeds the size limit")],
)
def test_sdist_member_count_and_size_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: str, message: str
) -> None:
    # Lowered just below what the fixture sdist needs; the pair passes with the real bounds.
    sdist = _sdist_files()
    needed = len(sdist) + 1 if limit == "_MAX_MEMBERS" else max(map(len, sdist.values()))
    monkeypatch.setattr(distributions, limit, needed - 1)
    with pytest.raises(ValueError, match=message):
        verify_distributions(_pair(tmp_path / "dist"))


@pytest.mark.parametrize(
    ("limit", "message"),
    [("_MAX_MEMBERS", "too many members"), ("_MAX_MEMBER_BYTES", "exceeds the size limit")],
)
def test_wheel_member_count_and_size_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: str, message: str
) -> None:
    # The sdist stays within the lowered bound, so only the wheel's own members cross it.
    sdist = _sdist_files()
    if limit == "_MAX_MEMBERS":
        monkeypatch.setattr(distributions, limit, len(sdist) + 1)
        extra = {f"{DIST_INFO}/extra-{index}": b"" for index in range(len(sdist))}
    else:
        bound = max(map(len, sdist.values()))
        monkeypatch.setattr(distributions, limit, bound)
        extra = {f"{DIST_INFO}/oversized": b"x" * (bound + 1)}
    with pytest.raises(ValueError, match=message):
        verify_distributions(_pair(tmp_path / "dist", wheel={**_wheel_files(), **extra}))


def _without(name: str) -> dict[str, bytes]:
    files = _sdist_files()
    del files[name]
    return files


@pytest.mark.parametrize("name", ["PKG-INFO", "pyproject.toml", "README.md", "LICENSE", "NOTICE"])
def test_sdist_must_carry_build_inputs_and_licence_notices(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError, match=f"sdist is missing {name}"):
        verify_distributions(_pair(tmp_path / "dist", sdist=_without(name)))


def test_sdist_must_not_ship_a_partial_test_suite(tmp_path: Path) -> None:
    """Regression: setuptools adds tests/test*.py by default, without fixtures or conftest."""
    sdist = {**_sdist_files(), "tests/test_release_evidence.py": b"def test(): ...\n"}
    with pytest.raises(ValueError, match="test suite"):
        verify_distributions(_pair(tmp_path / "dist", sdist=sdist))


@pytest.mark.parametrize(
    ("tag", "purelib"),
    [("cp312-cp312-manylinux_2_17_x86_64", "true"), ("py3-none-any", "false")],
    ids=["platform-tag", "not-purelib"],
)
def test_wheel_must_be_universal_pure_python(tmp_path: Path, tag: str, purelib: str) -> None:
    wheel = {
        **_wheel_files(),
        f"{DIST_INFO}/WHEEL": f"Wheel-Version: 1.0\nRoot-Is-Purelib: {purelib}\nTag: {tag}\n".encode(),
    }
    with pytest.raises(ValueError, match="py3-none-any"):
        verify_distributions(_pair(tmp_path / "dist", wheel=wheel))


def test_wheel_must_not_declare_extra_tags(tmp_path: Path) -> None:
    wheel = {**_wheel_files(), f"{DIST_INFO}/WHEEL": WHEEL.replace(b"\n\n", b"\nTag: py2-none-any\n\n")}
    with pytest.raises(ValueError, match="single tag py3-none-any"):
        verify_distributions(_pair(tmp_path / "dist", wheel=wheel))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        pytest.param(
            {"shadowscan/__init__.py": b'__version__ = "9.9.9"\n'},
            "package files differ",
            id="changed-module",
        ),
        pytest.param({"shadowscan/extra.py": b"x = 1\n"}, "different package files", id="wheel-only-module"),
        pytest.param({"other/module.py": b"x = 1\n"}, "outside shadowscan/", id="foreign-top-level"),
        pytest.param({f"{DIST_INFO}/licenses/NOTICE": b"other\n"}, "NOTICE differs", id="changed-notice"),
        pytest.param(
            {f"{DIST_INFO}/METADATA": METADATA + b"changed description\n"},
            "METADATA differs from sdist PKG-INFO",
            id="changed-metadata",
        ),
    ],
)
def test_wheel_must_ship_exactly_what_the_sdist_builds(
    tmp_path: Path, change: dict[str, bytes], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        verify_distributions(_pair(tmp_path / "dist", wheel={**_wheel_files(), **change}))


def test_missing_package_file_in_wheel_is_rejected(tmp_path: Path) -> None:
    wheel = _wheel_files()
    del wheel["shadowscan/signatures/data/frameworks/frameworks.yaml"]
    with pytest.raises(ValueError, match="different package files"):
        verify_distributions(_pair(tmp_path / "dist", wheel=wheel))


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        pytest.param(METADATA.replace(b"Name: NexusShadowScan", b"Name: shadowscan"), "not NexusShadowScan"),
        pytest.param(METADATA.replace(f"Version: {VERSION}".encode(), b"Version: 9.9.9"), "version does not"),
        pytest.param(METADATA.replace(b"Name: NexusShadowScan\n", b""), "exactly one Name"),
    ],
    ids=["other-project", "other-version", "no-name"],
)
def test_core_metadata_must_name_this_project_and_version(
    tmp_path: Path, metadata: bytes, message: str
) -> None:
    sdist = {**_sdist_files(), "PKG-INFO": metadata}
    wheel = {**_wheel_files(), f"{DIST_INFO}/METADATA": metadata}
    with pytest.raises(ValueError, match=message):
        verify_distributions(_pair(tmp_path / "dist", sdist=sdist, wheel=wheel))


@pytest.mark.parametrize(
    ("names", "message"),
    [
        pytest.param(
            ["nexusshadowscan-0.1.1-py3-none-any.whl"],
            "exactly one wheel and exactly one sdist",
            id="no-sdist",
        ),
        pytest.param(
            ["nexusshadowscan-0.1.1.tar.gz"], "exactly one wheel and exactly one sdist", id="no-wheel"
        ),
        pytest.param(
            [
                "nexusshadowscan-0.1.1-py3-none-any.whl",
                "nexusshadowscan-0.1.0-py3-none-any.whl",
                "nexusshadowscan-0.1.1.tar.gz",
            ],
            "exactly one wheel",
            id="two-wheels",
        ),
        pytest.param(
            [
                "nexusshadowscan-0.1.1-py3-none-any.whl",
                "nexusshadowscan-0.1.1.tar.gz",
                "nexusshadowscan-0.1.0.tar.gz",
            ],
            "exactly one sdist",
            id="two-sdists",
        ),
        pytest.param(
            ["nexusshadowscan-0.1.1-py3-none-any.whl", "nexusshadowscan-0.1.0.tar.gz"],
            "versions differ",
            id="skew",
        ),
        pytest.param(
            ["nexusshadowscan-0.1.1-cp312-cp312-linux_x86_64.whl", "nexusshadowscan-0.1.1.tar.gz"],
            "py3-none-any",
            id="platform-wheel",
        ),
        pytest.param(
            ["NexusShadowScan-0.1.1-py3-none-any.whl", "NexusShadowScan-0.1.1.tar.gz"],
            "py3-none-any",
            id="unnormalized-names",
        ),
    ],
)
def test_release_holds_one_wheel_and_one_sdist_of_one_version(names: list[str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        release_distributions([Path(name) for name in names])


def test_unreadable_archive_is_rejected(tmp_path: Path) -> None:
    directory = _pair(tmp_path / "dist")
    (directory / f"nexusshadowscan-{VERSION}.tar.gz").write_bytes(b"not a gzip stream")
    with pytest.raises(ValueError, match="cannot be read"):
        verify_distributions(directory)


def test_distribution_directory_must_hold_only_regular_files(tmp_path: Path) -> None:
    directory = _pair(tmp_path / "dist")
    (directory / "nested").mkdir()
    with pytest.raises(ValueError, match="only regular files"):
        verify_distributions(directory)


def test_cli_exit_status_reports_the_verdict(tmp_path: Path) -> None:
    directory = _pair(tmp_path / "dist")
    command = [sys.executable, "-m", "tools.release.distributions", "--directory", str(directory)]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 0 and "match" in result.stdout, result.stderr
    (directory / f"nexusshadowscan-{VERSION}-py3-none-any.whl").unlink()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode != 0 and "exactly one wheel" in result.stderr


def test_manifest_in_keeps_the_test_suite_out_of_the_sdist() -> None:
    assert "prune tests" in (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
