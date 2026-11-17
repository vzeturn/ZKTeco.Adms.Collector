"""
ADMS attendance collector — receives ZKTeco PUSH (ADMS) traffic and writes it into the
ATTENDANCEDB attendance database.

Where this fits
---------------
A desktop pull tool pulls from devices over the 32-bit ``zkemkeeper`` COM SDK:
the operator (or a scheduled sweep) opens a TCP session to each device on port 4370 and
drags the log buffer across. That model needs a Windows box on the same network as every
device, and a device only reaches the database when someone asks it to.

This service inverts the direction. In ADMS/PUSH mode the *device* is the client: it dials
out over plain HTTP to a configured server address, uploads punches and user changes as they
happen, and polls for commands. Nothing needs to be reachable *at* the device, so devices
behind NAT at remote sites work, and punches land in the database seconds after they occur.

What is deliberately shared with the desktop pull tool
------------------------------------------------------
* The same target schema. Punches go through ``dbo.CheckInOut_add`` with ``KieuCham='1'``
  and ``NguonCham=''``, employees through a MERGE on ``NHANVIEN.MaChamCong``, templates into
  ``dbo.TEMPLATE`` / ``dbo.Face``. Rows produced here are indistinguishable from rows the
  desktop app produces, so both can run against one database during a migration.
* The same idempotency guard. ``dbo.CheckInOut_add`` is a bare INSERT with no existence
  check, so duplicate suppression is the caller's job — see
  :mod:`adms.db.attendance`. This matters more here than in the desktop app: a device that
  does not receive our ``OK`` re-sends the same batch.
* The same secret handling. The connection string is never in source, never logged, never in
  an exception message. The desktop app keeps it DPAPI-encrypted in HKCU; here it is DPAPI-encrypted
  in the registry on IIS, or injected as an environment variable in a container.
* The same shape: ports (:mod:`adms.ports`) with pure protocol code
  (:mod:`adms.protocol`) on one side and SQL adapters (:mod:`adms.db`) on the other, wired
  by hand in :mod:`adms.composition`.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "1.0.0"
