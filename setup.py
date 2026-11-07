from __future__ import annotations

from pathlib import Path

from setuptools import find_packages, setup


def find_version() -> str:
    version = "0.0.1"
    extension_yaml_path = Path(__file__).parent / "extension" / "extension.yaml"
    try:
        with open(extension_yaml_path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("version"):
                    version = line.split(" ")[-1].strip().strip('"')
                    break
    except OSError:
        pass
    return version


setup(
    name="sangfor_hci",
    version=find_version(),
    description="Sangfor HCI monitoring for Dynatrace Managed (Extensions 2.0, Python)",
    author="Rifqi Fitriady",
    packages=find_packages(include=["sangfor_hci", "sangfor_hci.*"]),
    python_requires=">=3.10",
    include_package_data=True,
    install_requires=[
        "dt-extensions-sdk==1.11.3",
        "requests==2.34.2",
        "pysnmp==7.1.31",
        "cryptography==50.0.2",
    ],
    extras_require={"dev": ["dt-extensions-sdk[cli]==1.11.3"]},
)
