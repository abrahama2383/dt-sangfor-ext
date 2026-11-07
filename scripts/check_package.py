"""Checks a built extension package: size, signature, and wheels for every target platform.

Usage: .venv/bin/python scripts/check_package.py dist/<package>.zip
"""

from __future__ import annotations

import io
import re
import sys
import zipfile
from pathlib import Path

MAX_BYTES = 25 * 1024 * 1024
REQUIRED_WHEELS = (
    r"cryptography-50\.0\.2-cp39-abi3-.*manylinux2014_x86_64.*\.whl",
    r"cryptography-50\.0\.2-cp311-abi3-.*manylinux2014_x86_64.*\.whl",
    r"cryptography-50\.0\.2-cp39-abi3-win_amd64\.whl",
    r"cryptography-50\.0\.2-cp311-abi3-win_amd64\.whl",
    r"cffi-.*-cp310-cp310-.*manylinux2014_x86_64.*\.whl",
    r"cffi-.*-cp314-cp314-.*manylinux2014_x86_64.*\.whl",
    r"cffi-.*-cp310-cp310-win_amd64\.whl",
    r"cffi-.*-cp314-cp314-win_amd64\.whl",
    r"pysnmp-7\.1\.31-py3-none-any\.whl",
    r"requests-2\.34\.2-py3-none-any\.whl",
    r"dt_extensions_sdk-1\.11\.3-py3-none-any\.whl",
    r"sangfor_hci-.*-py3-none-any\.whl",
)
FORBIDDEN_WHEELS = (r"macosx",)


def check(package: Path) -> list[str]:
    problems = []
    size = package.stat().st_size
    if size >= MAX_BYTES:
        problems.append(f"package is {size / 1048576:.1f} MB, over the {MAX_BYTES / 1048576:g} MB limit")
    try:
        with zipfile.ZipFile(package) as outer:
            names = set(outer.namelist())
            for required in ("extension.zip", "extension.zip.sig"):
                if required not in names:
                    problems.append(f"missing {required} (was the package signed?)")
            if "extension.zip" not in names:
                return problems
            with zipfile.ZipFile(io.BytesIO(outer.read("extension.zip"))) as inner:
                inner_names = inner.namelist()
    except zipfile.BadZipFile as exc:
        problems.append(f"not a valid zip: {exc}")
        return problems
    if "extension.yaml" not in inner_names:
        problems.append("extension.zip has no extension.yaml")
    wheels = [Path(name).name for name in inner_names if name.endswith(".whl")]
    for pattern in REQUIRED_WHEELS:
        if not any(re.fullmatch(pattern, wheel) for wheel in wheels):
            problems.append(f"no wheel matching {pattern}")
    for pattern in FORBIDDEN_WHEELS:
        bad = [wheel for wheel in wheels if re.search(pattern, wheel)]
        if bad:
            problems.append(f"unexpected {pattern} wheels (build with --only-extra-platforms): {bad}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: check_package.py <package.zip>")
        return 2
    package = Path(argv[0])
    problems = check(package)
    if problems:
        print("PACKAGE NOT OK")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"PACKAGE OK ({package.stat().st_size / 1048576:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
