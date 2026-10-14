"""Check that a release candidate holds one universal wheel and its matching sdist.

`python -m build` writes the sdist and then builds the wheel from that sdist, so
a file the sdist omits is missing from the wheel too. This module checks the
pair the package index will receive: names, version, the `py3-none-any` tag,
identical core metadata and identical package files, and an sdist made only of
regular files and directories under one root. It reads the archives without
extracting them. It does not authenticate their origin; the workflow's
attestations do that.
"""

from __future__ import annotations

import argparse
import re
import tarfile
import zipfile
from email.parser import BytesHeaderParser
from pathlib import Path, PurePosixPath

PROJECT = "NexusShadowScan"
_NORMALIZED = "nexusshadowscan"
_PACKAGE = "shadowscan/"
_VERSION = r"(?P<version>[0-9][0-9A-Za-z.+!]*)"
_WHEEL = re.compile(rf"{_NORMALIZED}-{_VERSION}-py3-none-any\.whl")
_SDIST = re.compile(rf"{_NORMALIZED}-{_VERSION}\.tar\.gz")
# Files the sdist must carry at its root to rebuild the wheel and its licence notices.
_SDIST_ROOT_FILES = ("PKG-INFO", "pyproject.toml", "README.md", "LICENSE", "NOTICE")
_LICENSE_FILES = ("LICENSE", "NOTICE")
_MAX_MEMBERS = 5_000
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024


def release_distributions(files: list[Path]) -> tuple[Path, Path, str]:
    """The one wheel and one sdist among ``files``, named for the same version."""
    wheels = [path for path in files if path.name.endswith(".whl")]
    sdists = [path for path in files if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("expected exactly one wheel and exactly one sdist; remove stale distributions")
    wheel = _WHEEL.fullmatch(wheels[0].name)
    sdist = _SDIST.fullmatch(sdists[0].name)
    if wheel is None or sdist is None:
        raise ValueError(
            f"expected {_NORMALIZED}-<version>-py3-none-any.whl and {_NORMALIZED}-<version>.tar.gz"
        )
    if wheel["version"] != sdist["version"]:
        raise ValueError("wheel and sdist versions differ")
    return wheels[0], sdists[0], wheel["version"]


def _headers(data: bytes) -> dict[str, list[str]]:
    message = BytesHeaderParser().parsebytes(data)
    headers: dict[str, list[str]] = {}
    for key, value in message.items():
        headers.setdefault(key.lower(), []).append(str(value))
    return headers


def _single(headers: dict[str, list[str]], key: str, source: str) -> str:
    values = headers.get(key.lower(), [])
    if len(values) != 1:
        raise ValueError(f"{source} must declare exactly one {key}")
    return values[0]


def _check_identity(metadata: bytes, version: str, source: str) -> None:
    headers = _headers(metadata)
    name = _single(headers, "Name", source)
    if name != PROJECT:
        raise ValueError(f"{source} names {name!r}, not {PROJECT}")
    if _single(headers, "Version", source) != version:
        raise ValueError(f"{source} version does not match the file name")


class _Budget:
    """Bound what is read from an archive: member count, member size and total bytes."""

    def __init__(self) -> None:
        self.members = 0
        self.total = 0

    def count(self) -> None:
        self.members += 1
        if self.members > _MAX_MEMBERS:
            raise ValueError("distribution has too many members")

    def charge(self, size: int) -> None:
        self.total += size
        if size > _MAX_MEMBER_BYTES or self.total > _MAX_TOTAL_BYTES:
            raise ValueError("distribution member exceeds the size limit")


def _safe_relative(name: str, source: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or "\\" in name or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{source} has an unsafe member path: {name!r}")
    return path


def _read_sdist(path: Path, version: str) -> tuple[bytes, dict[str, bytes]]:
    """PKG-INFO and every regular file below the sdist root, keyed by relative path."""
    root = f"{_NORMALIZED}-{version}"
    budget = _Budget()
    files: dict[str, bytes] = {}
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive:
            budget.count()
            relative = _safe_relative(member.name, "sdist")
            if relative.parts[0] != root:
                raise ValueError(f"sdist member {member.name!r} is outside {root}/")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"sdist member {member.name!r} is not a regular file or directory")
            inner = PurePosixPath(*relative.parts[1:]).as_posix()
            if inner in files:
                raise ValueError(f"sdist repeats member {member.name!r}")
            budget.charge(member.size)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"sdist member {member.name!r} cannot be read")
            files[inner] = stream.read()
    missing = [name for name in _SDIST_ROOT_FILES if name not in files]
    if missing:
        raise ValueError("sdist is missing " + ", ".join(missing))
    if any(name.startswith("tests/") for name in files):
        raise ValueError("sdist ships part of the test suite; it runs only from a repository checkout")
    return files["PKG-INFO"], files


def _read_wheel(path: Path, version: str) -> tuple[bytes, dict[str, bytes]]:
    """METADATA and every file in the wheel, keyed by archive path."""
    dist_info = f"{_NORMALIZED}-{version}.dist-info/"
    budget = _Budget()
    files: dict[str, bytes] = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            budget.count()
            _safe_relative(info.filename, "wheel")
            if info.is_dir():
                continue
            if not info.filename.startswith((_PACKAGE, dist_info)):
                raise ValueError(f"wheel member {info.filename!r} is outside {_PACKAGE} and {dist_info}")
            if info.filename in files:
                raise ValueError(f"wheel repeats member {info.filename!r}")
            budget.charge(info.file_size)
            files[info.filename] = archive.read(info)
    for name in ("METADATA", "WHEEL", "RECORD"):
        if dist_info + name not in files:
            raise ValueError(f"wheel is missing {dist_info}{name}")
    wheel = _headers(files[dist_info + "WHEEL"])
    if wheel.get("tag") != ["py3-none-any"] or wheel.get("root-is-purelib") != ["true"]:
        raise ValueError("wheel must be pure Python with the single tag py3-none-any")
    return files[dist_info + "METADATA"], files


def verify_distributions(directory: Path) -> dict[str, str]:
    """Raise unless ``directory`` holds a matching universal wheel and sdist."""
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("distribution directory must be a real directory")
    files = sorted(directory.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("distribution directory must contain only regular files")
    wheel_path, sdist_path, version = release_distributions(files)
    try:
        sdist_metadata, sdist_files = _read_sdist(sdist_path, version)
        wheel_metadata, wheel_files = _read_wheel(wheel_path, version)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
        raise ValueError(f"distribution archive cannot be read: {exc}") from None
    _check_identity(sdist_metadata, version, "sdist PKG-INFO")
    _check_identity(wheel_metadata, version, "wheel METADATA")
    if sdist_metadata != wheel_metadata:
        raise ValueError("wheel METADATA differs from sdist PKG-INFO")
    sdist_package = {name: data for name, data in sdist_files.items() if name.startswith(_PACKAGE)}
    wheel_package = {name: data for name, data in wheel_files.items() if name.startswith(_PACKAGE)}
    if not sdist_package or sdist_package.keys() != wheel_package.keys():
        raise ValueError("wheel and sdist ship different package files")
    if changed := sorted(name for name in sdist_package if sdist_package[name] != wheel_package[name]):
        raise ValueError("wheel and sdist package files differ: " + ", ".join(changed[:5]))
    dist_info = f"{_NORMALIZED}-{version}.dist-info/licenses/"
    for name in _LICENSE_FILES:
        if wheel_files.get(dist_info + name) != sdist_files[name]:
            raise ValueError(f"wheel {name} differs from the sdist's")
    return {"version": version, "wheel": wheel_path.name, "sdist": sdist_path.name}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        checked = verify_distributions(args.directory)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"{PROJECT} {checked['version']}: {checked['wheel']} and {checked['sdist']} match")


if __name__ == "__main__":
    main()
