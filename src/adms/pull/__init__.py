"""
adms.pull -- on-demand attendance/roster PULL agent.

Everything else in :mod:`adms` is push-only by design (see the top-level README's "What problem
this solves" section): a device dials out to this service, and nothing here ever opens a
connection *to* a device. That inversion is deliberate and stays true for the ADMS collector.

This subpackage is a second, separate tool, run by hand (whenever an
operator wants), that does the opposite on purpose: it dials out to a configured list of devices
over the vendor TCP protocol (port 4370, via the third-party ``pyzk`` client), for three jobs:

* Pull each device's employee roster into ``NHANVIEN`` -- ``adms.db.employees.SqlServerEmployeeStore``.
* Pull each device's attendance buffer into ``CheckInOut`` / ``ADMS_ATTLOG_RAW`` -- exactly the same
  adapters and the same dedup key (``MaChamCong``, ``GioCham``) the push collector uses, so a punch
  pulled here is indistinguishable from one pushed there.
* Synchronise employees between devices that share a configured "area" (``PullGroup``), so enrolling
  someone at one reader in an office eventually shows up on every other reader in that office.

It is intentionally not a background service: no scheduler, no daemon loop. An operator runs
``python -m adms.pull.cli`` when they want a pull to happen, and every run is logged in full --
structured JSON (via ``adms.logging_setup``, the same logger the collector uses) and a durable
history in ``ADMS_PULL_RUN`` / ``ADMS_PULL_LOG`` -- so a problem with one device never hides inside
a silently-partial run.
"""

from __future__ import annotations
