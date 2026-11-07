"""Synchronous SNMP v2c/v3 reads on pysnmp 7's asyncio API. One SnmpEngine per call."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    next_cmd,
    usmAesCfb128Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoPrivProtocol,
)

_AUTH = {"MD5": usmHMACMD5AuthProtocol, "SHA": usmHMACSHAAuthProtocol, "SHA256": usmHMAC192SHA256AuthProtocol}
_PRIV = {
    "NONE": usmNoPrivProtocol,
    "DES": usmDESPrivProtocol,
    "AES128": usmAesCfb128Protocol,
    "AES256": usmAesCfb256Protocol,
}
_EMPTY_TYPES = ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null")


class SnmpError(Exception):
    pass


@dataclass(frozen=True)
class SnmpTarget:
    address: str
    port: int
    version: str  # "v2c" | "v3"
    timeout: float
    community: str = field(default="", repr=False)
    v3_user: str = ""
    v3_auth_protocol: str = "SHA"
    v3_auth_key: str = field(default="", repr=False)
    v3_priv_protocol: str = "AES128"
    v3_priv_key: str = field(default="", repr=False)
    v3_context_name: str = ""


def _is_empty(value: object) -> bool:
    return type(value).__name__ in _EMPTY_TYPES


class SnmpClient:
    def __init__(self, target: SnmpTarget, retries: int = 1):
        self._target = target
        self._retries = retries

    def get(self, oids: list[str]) -> dict[str, str]:
        return asyncio.run(self._get(oids))

    def walk(self, base_oid: str) -> dict[str, str]:
        return asyncio.run(self._walk(base_oid))

    def has_subtree(self, base_oid: str) -> bool:
        return asyncio.run(self._has_subtree(base_oid))

    @property
    def _label(self) -> str:
        return f"{self._target.address}:{self._target.port}"

    def _auth(self):
        target = self._target
        if target.version == "v2c":
            return CommunityData(target.community, mpModel=1)
        priv = _PRIV[target.v3_priv_protocol]
        return UsmUserData(
            target.v3_user,
            authKey=target.v3_auth_key,
            privKey=None if priv is usmNoPrivProtocol else target.v3_priv_key,
            authProtocol=_AUTH[target.v3_auth_protocol],
            privProtocol=priv,
        )

    def _context(self) -> ContextData:
        if self._target.version == "v3" and self._target.v3_context_name:
            return ContextData(contextName=self._target.v3_context_name.encode("utf-8"))
        return ContextData()

    async def _transport(self) -> UdpTransportTarget:
        return await UdpTransportTarget.create(
            (self._target.address, self._target.port), timeout=self._target.timeout, retries=self._retries
        )

    def _check(self, error_indication, error_status, error_index) -> None:
        if error_indication:
            raise SnmpError(f"{self._label} {error_indication}")
        if error_status:
            raise SnmpError(f"{self._label} {error_status.prettyPrint()} at index {int(error_index)}")

    async def _get(self, oids: list[str]) -> dict[str, str]:
        engine = SnmpEngine()
        try:
            error_indication, error_status, error_index, var_binds = await get_cmd(
                engine,
                self._auth(),
                await self._transport(),
                self._context(),
                *[ObjectType(ObjectIdentity(oid)) for oid in oids],
            )
            self._check(error_indication, error_status, error_index)
            return {str(oid): value.prettyPrint() for oid, value in var_binds if not _is_empty(value)}
        finally:
            engine.close_dispatcher()

    async def _walk(self, base_oid: str) -> dict[str, str]:
        engine = SnmpEngine()
        result: dict[str, str] = {}
        try:
            async for error_indication, error_status, error_index, var_binds in bulk_walk_cmd(
                engine,
                self._auth(),
                await self._transport(),
                self._context(),
                0,
                25,
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False,
            ):
                self._check(error_indication, error_status, error_index)
                for oid, value in var_binds:
                    if not _is_empty(value):
                        result[str(oid)] = value.prettyPrint()
            return result
        finally:
            engine.close_dispatcher()

    async def _has_subtree(self, base_oid: str) -> bool:
        engine = SnmpEngine()
        try:
            error_indication, error_status, error_index, var_binds = await next_cmd(
                engine, self._auth(), await self._transport(), self._context(), ObjectType(ObjectIdentity(base_oid))
            )
            if error_indication:
                raise SnmpError(f"{self._label} {error_indication}")
            if error_status:
                return False
            return any(str(oid).startswith(base_oid + ".") and not _is_empty(value) for oid, value in var_binds)
        finally:
            engine.close_dispatcher()
