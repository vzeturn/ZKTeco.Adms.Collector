"""
Admin console -- a small web UI for operating the collector.

WHY THIS IS A SEPARATE APPLICATION ON A SEPARATE PORT
-----------------------------------------------------
The device endpoint is deliberately unauthenticated, because the ADMS protocol cannot carry a
credential, and it is deliberately plain HTTP, because ZKTeco firmware speaks nothing else. Both of
those are acceptable only because that endpoint is confined to a device network segment.

None of it applies here. The users are people with browsers, so this side gets password
authentication, revocable server-side sessions, CSRF protection, lockout, and an audit trail -- and it
can and should be served over HTTPS.

Mounting the console under ``/admin`` on the device site would have collapsed those two very different
security postures into one binding, one firewall rule and one TLS decision. So it is a second WSGI
application (:mod:`adms.admin.app`), served by a second process on a second port
(:mod:`adms.admin.serve`), behind a second IIS site. The two share the domain models, the ports and the
SQL adapters; they share no HTTP surface.

The console never talks to a device directly. Everything it does is a database write: flipping
``ADMS_DEVICE.Enabled``, linking a serial to a ``MAYCHAMCONG`` row, or appending to ``ADMS_COMMAND``.
The collector picks commands up on the device's next poll. That keeps the console out of the data path
entirely -- it cannot stall or corrupt an upload in progress.
"""

from __future__ import annotations

__all__: list[str] = []
