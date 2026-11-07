import importlib.util
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("check_package", ROOT / "scripts" / "check_package.py")
check_package = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_package)

GOOD_WHEELS = [
    "cryptography-50.0.2-cp39-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "cryptography-50.0.2-cp311-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "cryptography-50.0.2-cp39-abi3-win_amd64.whl",
    "cryptography-50.0.2-cp311-abi3-win_amd64.whl",
    "cffi-2.1.1-cp310-cp310-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "cffi-2.1.1-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "cffi-2.1.1-cp310-cp310-win_amd64.whl",
    "cffi-2.1.1-cp314-cp314-win_amd64.whl",
    "pysnmp-7.1.31-py3-none-any.whl",
    "requests-2.34.2-py3-none-any.whl",
    "dt_extensions_sdk-1.11.3-py3-none-any.whl",
    "sangfor_hci-0.1.0-py3-none-any.whl",
]


def make_package(tmp_path, wheels, with_sig=True):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("extension.yaml", "name: custom:sangfor-hci\n")
        for wheel in wheels:
            z.writestr(f"lib/{wheel}", b"x")
    path = tmp_path / "custom_sangfor-hci-0.1.0.zip"
    with zipfile.ZipFile(path, "w") as outer:
        outer.writestr("extension.zip", inner.getvalue())
        if with_sig:
            outer.writestr("extension.zip.sig", b"sig")
    return path


def test_good_package_passes(tmp_path):
    assert check_package.check(make_package(tmp_path, GOOD_WHEELS)) == []


def test_missing_windows_wheel_and_signature_are_reported(tmp_path):
    wheels = [w for w in GOOD_WHEELS if w != "cryptography-50.0.2-cp311-abi3-win_amd64.whl"]
    problems = check_package.check(make_package(tmp_path, wheels, with_sig=False))
    assert any("extension.zip.sig" in p for p in problems)
    assert any("cp311-abi3-win_amd64" in p for p in problems)


def test_macos_wheels_are_rejected(tmp_path):
    wheels = GOOD_WHEELS + ["cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl"]
    assert any("macosx" in p for p in check_package.check(make_package(tmp_path, wheels)))


def test_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(check_package, "MAX_BYTES", 10)
    assert any("25 MB" in p or "limit" in p for p in check_package.check(make_package(tmp_path, GOOD_WHEELS)))
