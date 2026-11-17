"""
Pure ADMS/PUSH protocol code: bytes in, values out.

Nothing here touches a database, the network, the clock or the environment, which is what makes
the protocol layer the part you can reason about and exercise without a device or a SQL Server.
Adapters live in :mod:`adms.db`, orchestration in :mod:`adms.service`.

The protocol itself is not published by ZKTeco in a form we can rely on; the layouts encoded
here were reconstructed from the vendor's PushSDK developer guide, the behaviour of the
official ADMS server, and observed traffic. Each parser therefore documents the variants it
accepts and errs toward accepting a line it half-understands, because the alternative is
discarding attendance data over a firmware quirk.
"""

from __future__ import annotations

from .attlog import parse_attlog
from .commands import parse_acks, render_commands
from .handshake import build_handshake
from .operlog import parse_operlog
from .options import parse_options
from .routes import ResolvedRoute, Route, resolve
from .text import decode_body, parse_kv, parse_timestamp, split_fields, split_lines, to_bool, to_int

__all__ = [
    "parse_attlog",
    "parse_operlog",
    "parse_options",
    "parse_acks",
    "render_commands",
    "build_handshake",
    "resolve",
    "Route",
    "ResolvedRoute",
    "decode_body",
    "split_lines",
    "split_fields",
    "parse_kv",
    "parse_timestamp",
    "to_int",
    "to_bool",
]
