"""
Process hosting for the on-premises deployment.

IIS does not execute Python. It reverse-proxies to a child process it starts and supervises via
**AspNetCoreModuleV2** (out-of-process), and that child is :mod:`adms.hosting.serve` running
``waitress``. IIS keeps
what it is good at -- owning port 80, access logging, auto-start, health-based recycling, Windows
service integration -- and the Python process only ever handles a normal WSGI call.
"""

from __future__ import annotations

__all__: list[str] = []
