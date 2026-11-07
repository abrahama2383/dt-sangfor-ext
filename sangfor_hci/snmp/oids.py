"""Sangfor aCloud private MIB (enterprise 35047). The single source of truth for OIDs.

Source: Zabbix community template Virtualization/Sangfor/template_hci (2025), whose item keys
carry the MIB object names (aCloudHostCpuUseRate and so on).
"""

from __future__ import annotations

from dataclasses import dataclass

ROOT = "1.3.6.1.4.1.35047.3.2.1"
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
VERSION = f"{ROOT}.1.0"
BMC_IPMI_IP = f"{ROOT}.2.7.1.0"
BMC_IPMI_VERSION = f"{ROOT}.2.7.2.0"
BMC_VERSION = f"{ROOT}.2.7.3.0"


@dataclass(frozen=True)
class Scalar:
    metric: str
    oid: str
    ratio: bool  # True: Sangfor sends 0-1, report percent


HOST_CPU = Scalar("host.cpu.usage", f"{ROOT}.2.1.1.0", True)
HOST_MEMORY = Scalar("host.memory.usage", f"{ROOT}.2.2.1.0", True)
HOST_DISK = Scalar("hw.disk.usage", f"{ROOT}.2.3.1.0", True)


@dataclass(frozen=True)
class Column:
    metric: str
    suffix: str  # column number under the table entry
    kind: str  # "number" | "status" | "gb"


@dataclass(frozen=True)
class Table:
    name: str  # dimension becomes sangfor.<name>
    entry: str  # table entry OID
    name_column: str
    columns: tuple[Column, ...]

    def column_oid(self, suffix: str) -> str:
        return f"{self.entry}.{suffix}"


TABLES = (
    Table("cpu", f"{ROOT}.2.1.2.1", "8", (Column("hw.cpu.temperature", "7", "number"),)),
    Table(
        "fs",
        f"{ROOT}.2.5.1",
        "2",
        (
            Column("hw.fs.size", "3", "gb"),
            Column("hw.fs.used", "4", "gb"),
            Column("hw.fs.available", "5", "gb"),
            Column("hw.fs.usage", "6", "number"),
        ),
    ),
    Table(
        "port",
        f"{ROOT}.2.12.1",
        "3",
        (Column("hw.optical.tx.power", "4", "number"), Column("hw.optical.rx.power", "5", "number")),
    ),
    Table("raid", f"{ROOT}.2.14.1", "3", (Column("hw.raid.ok", "5", "status"),)),
    Table("fan", f"{ROOT}.2.16.1", "2", (Column("hw.fan.speed", "3", "number"), Column("hw.fan.ok", "4", "status"))),
    Table("ssd", f"{ROOT}.2.18.1", "4", (Column("hw.ssd.life", "9", "number"),)),
)
