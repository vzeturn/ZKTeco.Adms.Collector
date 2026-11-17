"""
Where the SQL connection string lives on an on-premises host.

Stored in the Windows registry under ``HKLM\\SOFTWARE\\AdmsCollector\\AttendanceDb``, value
``ConnectionString`` (REG_BINARY), encrypted at rest with **DPAPI**. This is the same decision
the desktop pull tool's ``AttendanceDbConfig`` makes, for the same reasons:

* The connection string carries SQL credentials. It must never sit in plaintext on disk, in source, or
  in a file that gets overwritten by a redeploy.
* The registry survives replacing the application folder, so the operator configures the database once
  and upgrades do not wipe it.

One deliberate difference from the desktop app
----------------------------------------------
the desktop pull tool uses ``DataProtectionScope.CurrentUser`` -- correct for a desktop app run by one
operator. This is a service, and the IIS application pool identity is not the identity that installs
it, so CurrentUser would mean the value could only be written by a process already running as the app
pool. Machine scope is used instead, which means **any process on this host can decrypt it**. That is
an honest downgrade, and it is mitigated by:

* an ACL on the registry key restricting read to the app pool identity and Administrators (applied by
  ``deploy/set-db-connection.ps1``), and
* a SQL login with the narrow grants in ``sql/grant-least-privilege.sql``, so what the value unlocks
  is bounded -- no DELETE on ``CheckInOut`` or ``NHANVIEN``.

DPAPI machine scope still means the ciphertext is useless if copied to another machine, which is the
property that matters most when a backup or a disk leaves the building.

Implemented with ``ctypes`` against ``crypt32.dll`` rather than pulling in ``pywin32``: it is about
sixty lines, and this service's whole dependency list is otherwise ``pyodbc`` plus ``waitress``.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import winreg

from .errors import ConfigError

__all__ = ["DbConnectionStore", "protect", "unprotect"]

# ── DPAPI ────────────────────────────────────────────────────────────────────────────────

CRYPTPROTECT_UI_FORBIDDEN = 0x01
CRYPTPROTECT_LOCAL_MACHINE = 0x04

#: Extra entropy mixed into the blob. Not a secret on its own -- it is in this source file -- but it
#: means a DPAPI blob produced by some other application on the same host cannot be swapped in.
_ENTROPY = b"AdmsCollector.AttendanceDb.v1"


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> _Blob:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))


def _blob_bytes(blob: _Blob) -> bytes:
    return ctypes.string_at(blob.pbData, blob.cbData)


def _free(blob: _Blob) -> None:
    if blob.pbData:
        ctypes.windll.kernel32.LocalFree(blob.pbData)


def protect(plaintext: str) -> bytes:
    """Encrypt with DPAPI at machine scope. Raises :class:`ConfigError` on failure."""
    data_in = _blob(plaintext.encode("utf-8"))
    entropy = _blob(_ENTROPY)
    data_out = _Blob()

    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(data_in),
        None,
        ctypes.byref(entropy),
        None,
        None,
        CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(data_out),
    )
    if not ok:
        raise ConfigError(f"DPAPI encryption failed (error {ctypes.GetLastError()}).")
    try:
        return _blob_bytes(data_out)
    finally:
        _free(data_out)


def unprotect(ciphertext: bytes) -> str:
    """
    Decrypt a DPAPI blob. Raises :class:`ConfigError` on failure.

    Failure here is expected and meaningful, not exceptional: it is what happens when the blob was
    written on a different machine, so the message says so rather than reporting a bare Win32 code.
    """
    data_in = _blob(ciphertext)
    entropy = _blob(_ENTROPY)
    data_out = _Blob()

    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(data_in),
        None,
        ctypes.byref(entropy),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(data_out),
    )
    if not ok:
        raise ConfigError(
            f"DPAPI decryption failed (error {ctypes.GetLastError()}). A DPAPI machine-scope blob "
            "cannot be decrypted on a different host -- re-run deploy/set-db-connection.ps1 on this "
            "machine."
        )
    try:
        return _blob_bytes(data_out).decode("utf-8")
    finally:
        _free(data_out)


# ── Registry ─────────────────────────────────────────────────────────────────────────────

DEFAULT_SUBKEY = r"SOFTWARE\AdmsCollector\AttendanceDb"
VALUE_NAME = "ConnectionString"


class DbConnectionStore:
    """
    Reads and writes the DPAPI-protected connection string in the registry.

    HKLM rather than HKCU: the value has to be readable by the IIS application pool identity, which is
    not the identity that installed the service.
    """

    __slots__ = ("_subkey", "_hive")

    def __init__(self, subkey: str = DEFAULT_SUBKEY, hive: int = winreg.HKEY_LOCAL_MACHINE) -> None:
        self._subkey = subkey
        self._hive = hive

    def load(self) -> str | None:
        """The decrypted connection string, or ``None`` when nothing is configured."""
        try:
            # KEY_WOW64_64KEY so a 32-bit Python cannot silently read a different registry view than
            # the 64-bit installer wrote to.
            with winreg.OpenKey(
                self._hive, self._subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as key:
                value, kind = winreg.QueryValueEx(key, VALUE_NAME)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ConfigError(
                f"Could not read HKLM\\{self._subkey}. The application pool identity needs read "
                f"access to that key ({exc})."
            ) from exc

        if kind != winreg.REG_BINARY or not value:
            raise ConfigError(
                f"HKLM\\{self._subkey}\\{VALUE_NAME} is not a REG_BINARY DPAPI blob. Re-run "
                "deploy/set-db-connection.ps1."
            )
        return unprotect(bytes(value))

    def save(self, connection_string: str) -> None:
        """Encrypt and store. An empty value clears the configuration."""
        if not connection_string.strip():
            self.clear()
            return
        cipher = protect(connection_string)
        with winreg.CreateKeyEx(
            self._hive, self._subkey, 0, winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_BINARY, cipher)

    def clear(self) -> None:
        try:
            with winreg.OpenKey(
                self._hive, self._subkey, 0, winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
            ) as key:
                winreg.DeleteValue(key, VALUE_NAME)
        except FileNotFoundError:
            pass

    @property
    def is_configured(self) -> bool:
        try:
            return self.load() is not None
        except ConfigError:
            return False
