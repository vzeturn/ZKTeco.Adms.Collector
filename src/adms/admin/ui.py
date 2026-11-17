"""
HTML rendering and the stylesheet for the admin console.

The only module that produces HTML. No routing, no database, no session logic: every public function
takes plain values and returns ``str``, and *every* interpolated value passes through :func:`esc` or
:func:`esc_attr` on the way in. That rule is not a precaution here, it is the threat model. A device's
``DeviceName``, ``FirmwareVersion``, ``Platform``, ``PushVersion`` and the raw lines in
``ADMS_UNPARSED`` all arrive from an **unauthenticated** endpoint, and ``ADMS_AUTO_REGISTER_DEVICES``
can mint a row from a serial a stranger chose -- so a device name is attacker-controllable input that
lands in an administrator's browser. The escaping tests exist to prove that path is closed.

Functions that compose already-escaped fragments take them as ``body``/``rows`` and are never handed
raw data; that naming convention is what lets a reader tell "this argument is trusted HTML" from "this
argument is a value to escape".

This file holds task 2.1: the escaping helpers, the stylesheet constant with its ETag, and time
formatting. The page-rendering functions are added by their own tasks against this foundation.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from adms.admin.auth import Principal
    from adms.admin.store import (
        AuditRow,
        DeletionEventRow,
        DeviceRow,
        EmployeeRow,
        GrantResult,
        RosterSyncRow,
        UserRow,
    )

__all__ = [
    "STYLESHEET",
    "STYLESHEET_ETAG",
    "ZONE_LABEL",
    "activity_page",
    "audit_page",
    "change_password_page",
    "confirm_page",
    "dashboard",
    "device_detail",
    "device_list",
    "employees_page",
    "error_page",
    "esc",
    "esc_attr",
    "local_time",
    "page",
    "roster_sync_page",
    "sessions_page",
    "sign_in_page",
    "users_page",
]


# ── Brand mark ────────────────────────────────────────────────────────────────────────────────────
#
# The ADMS Collector mark, drawn as inline SVG so it needs no external file (which the CSP
# would block off-origin) and no data-URI. It is a blue rounded plate carrying a white clock glyph
# (a circle outline with two hands). ``currentColor`` is avoided; the two mark colours are named so the
# mark reads the same on any surface. The tagline is
# rendered as HTML beside it (not baked into the SVG) so it can wrap and be read by assistive tech.

#: The mark is painted by the stylesheet as a ``background-image`` (a data-URI SVG), not emitted as
#: inline ``<svg>`` in the HTML. That keeps the escaping invariant strict -- the page's XSS guard can go
#: on rejecting any literal ``<svg`` in a rendered document -- and keeps the brand recipe in one place.
#: The HTML side is just an empty, labelled box.
_LOGO_HTML = '<span class="logo-mark" role="img" aria-label="ADMS Collector"></span>'


def _initials(name: str) -> str:
    """Up to two initials for the user avatar chip. Falls back to '?' for an empty/blank name."""
    parts = [p for p in name.split() if p]
    if not parts:
        return "?"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


def _brand_lockup(*, compact: bool = False) -> str:
    """
    The logo mark plus the wordmark and system name, as one lockup used in the top bar and the
    sign-in brand panel. ``compact`` drops the tagline line for the dense top bar.
    """
    tagline = "" if compact else '<span class="brand-tag">Attendance Device Management</span>'
    return (
        '<span class="brand-lockup">'
        f"{_LOGO_HTML}"
        '<span class="brand-words">'
        '<span class="brand-name">ADMS <em>Collector</em></span>'
        f"{tagline}"
        "</span></span>"
    )


# ── Escaping ───────────────────────────────────────────────────────────────────────────────────

# The five HTML metacharacters, replaced in one pass. ``&`` must be first so the entities introduced by
# the later replacements are not themselves re-escaped -- doing it in any other order double-escapes and
# the UI shows ``&amp;lt;``. A single str.translate does all five at once, which also sidesteps that
# ordering hazard entirely and cannot partially apply.
_ESCAPE_MAP = {
    ord("&"): "&amp;",
    ord("<"): "&lt;",
    ord(">"): "&gt;",
    ord('"'): "&quot;",
    ord("'"): "&#x27;",
}


def esc(value: object) -> str:
    """
    Escape a value for HTML text or attribute context.

    ``None`` becomes ``""`` (not the word ``"None"``), everything else is stringified and its five
    metacharacters replaced. Never raises -- control characters, lone surrogates and arbitrary Unicode
    all pass through as themselves, escaped only where they are one of the five. Escaping is single-pass
    by construction: a value already containing ``&amp;`` is treated as the literal text it is, so the
    caller escapes exactly once per interpolation and never twice.
    """
    if value is None:
        return ""
    return str(value).translate(_ESCAPE_MAP)


#: Attribute and text escaping are identical here: because ``esc`` already handles both quote
#: characters, a value is safe in either context. Kept as a named function so call sites read as a
#: statement about where the value is going, and so the two could diverge later without touching them.
esc_attr = esc


# ── Time ────────────────────────────────────────────────────────────────────────────────────────

#: Stored timestamps are UTC; the console shows them shifted to the site's offset with the zone stated,
#: so a reader is never left guessing which clock a punch time is on (Requirement 6.7). The label is
#: built from the offset rather than hard-coded so a site on a different offset stays honest.
ZONE_LABEL = "UTC+7"


def local_time(value: dt.datetime | None, offset_hours: int) -> str:
    """
    Render a stored UTC timestamp in site-local time, with the zone named.

    ``None`` -> an em dash, because a missing timestamp is a real and common state (a device that has
    never reported) and rendering it as a blank cell hides that from the reader. The zone suffix is
    always present so the value cannot be misread as UTC.
    """
    if value is None:
        return "—"
    shifted = value + dt.timedelta(hours=offset_hours)
    sign = "+" if offset_hours >= 0 else "-"
    label = f"UTC{sign}{abs(offset_hours)}"
    return f"{shifted:%Y-%m-%d %H:%M} {label}"


# ── Stylesheet ────────────────────────────────────────────────────────────────────────────────────
#
# One string, served from /assets/console.css with an ETag (D10). No CDN, no @font-face, no build step,
# nothing fetched off-origin, because the host may have no route to the internet -- and because a
# Content-Security-Policy with no unsafe-inline is only possible if the CSS is not inlined per page.
#
# Design language: quiet, legible, administrative. A system font stack, generous whitespace, a hairline
# border and a single restrained accent. Colour and spacing are CSS custom properties so one change
# ripples everywhere; light and dark are both first-class via prefers-color-scheme, both meeting 4.5:1
# on body text; and device state is never carried by colour alone -- the markup pairs every state pill
# with its text label. The :focus-visible ring is never removed and is the one piece of chrome that is
# allowed to be loud.

STYLESHEET = """\
/* ============================================================================================
   Tokens -- two tiers (DTCG). Tier 1 PRIMITIVE: raw palette, scales, no meaning. Tier 2 SEMANTIC:
   roles that map to primitives. Every element/component rule below references SEMANTIC tokens
   only, so a re-theme is a change to the semantic block -- never a hunt through the rules. Dark
   mode redefines the semantic block (and the two primitives that must invert); it never
   re-hardcodes a colour inside a rule.
   ============================================================================================ */
:root {
  color-scheme: light dark;

  /* -- Tier 1: primitive -------------------------------------------------------------------- */
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", "Cascadia Code", Consolas, "Liberation Mono", monospace;

  /* Neutral zinc ramp -- the shadcn/ui greyscale. Cool, near-desaturated; carries the whole surface
     system so the UI reads as calm chrome and the single accent is the only colour with a job. */
  --gray-0:   #ffffff;
  --gray-25:  #fafafa;
  --gray-50:  #f4f4f5;
  --gray-100: #ececee;
  --gray-200: #e4e4e7;
  --gray-300: #d4d4d8;
  --gray-400: #a1a1aa;
  --gray-500: #71717a;
  --gray-600: #52525b;
  --gray-800: #27272a;
  --gray-900: #18181b;

  /* Accent -- a single restrained blue. It is the ONLY colour with a role: links, the primary button,
     and the active-nav marker. Never a surface, never a rail. Tuned so on-white and on-dark both clear
     WCAG 2.2 AA, with a lighter sibling for the dark ground. */
  --blue-300: #93c5fd;
  --blue-400: #60a5fa;
  --blue-500: #2563eb;
  --blue-600: #1d4ed8;
  --blue-700: #1e40af;
  --cyan-300: #93c5fd;
  --cyan-500: #2563eb;
  --cyan-600: #1d4ed8;

  --red-fg:   #b91c1c;  --red-bg:   #fef2f2;  --red-border:   #fecaca;
  --green-fg: #15803d;  --green-bg: #f0fdf4;  --green-border: #bbf7d0;
  --amber-fg: #b45309;  --amber-bg: #fffbeb;  --amber-border: #fde68a;

  --space-1: 0.25rem; --space-2: 0.5rem;  --space-3: 0.75rem;
  --space-4: 1rem;    --space-5: 1.5rem;  --space-6: 2.5rem;

  --text-xs:  0.75rem;  --text-sm: 0.8125rem; --text-base: 0.9375rem;
  --text-lg:  1.0625rem; --text-xl: 1.3125rem; --text-2xl: 1.625rem;

  --radius-sm: 4px; --radius-md: 6px; --radius-lg: 8px;
  --hairline: 1px;

  --shadow-1: 0 1px 2px rgba(24, 24, 27, 0.04);
  --shadow-2: 0 1px 3px rgba(24, 24, 27, 0.08), 0 1px 2px rgba(24, 24, 27, 0.04);

  --dur-fast: 120ms; --dur-base: 180ms;
  --ease: cubic-bezier(0.2, 0, 0, 1);

  /* -- Tier 2: semantic (the only tokens the rules use) ------------------------------------- */
  --bg: var(--gray-50);
  --surface: var(--gray-0);
  --surface-2: var(--gray-50);
  --surface-hover: var(--gray-100);
  --border: var(--gray-200);
  --border-strong: var(--gray-300);
  --field-border: var(--gray-400);        /* input/select borders -- >=3:1 non-text contrast (WCAG 2.2) */

  --text: var(--gray-900);
  --text-dim: var(--gray-600);
  --text-faint: var(--gray-500);

  --brand: var(--blue-500);               /* accent alias kept for the avatar + eyebrow tints */
  --brand-deep: var(--blue-700);
  --accent: var(--blue-500);              /* primary actions, links, active nav -- the one colour */
  --accent-hover: var(--blue-600);
  --accent-text: #ffffff;
  --accent-soft: color-mix(in srgb, var(--blue-500) 10%, var(--surface));  /* active-nav wash */
  --spark: var(--blue-500);               /* active-nav marker; no longer a separate hue */

  /* Sidebar reads as chrome, not brand: the same neutral surface as the app, set off by a hairline.
     The active item is marked with the accent, not a coloured rail -- this is the shadcn admin look and
     it fixes light (over-branded) and dark (glowing blue rail) in one move. */
  --sidebar: var(--gray-25);
  --sidebar-ink: var(--text-dim);
  --sidebar-ink-strong: var(--text);
  --sidebar-hover: var(--gray-100);
  --sidebar-active-bg: var(--accent-soft);
  --sidebar-border: var(--border);

  --danger: var(--red-fg);    --danger-bg: var(--red-bg);    --danger-border: var(--red-border);
  --danger-text: #ffffff;     --danger-hover: #991b1b;
  --ok: var(--green-fg);      --ok-bg: var(--green-bg);      --ok-border: var(--green-border);
  --warn: var(--amber-fg);    --warn-bg: var(--amber-bg);    --warn-border: var(--amber-border);

  --focus: var(--blue-500);
  --shadow-card: var(--shadow-1);

  /* The sign-in brand panel: a restrained neutral-dark wash with a faint accent bloom -- premium and
     quiet, not a saturated gradient. Declared as a token so the one "brand" surface stays in one place. */
  --brand-wash: linear-gradient(155deg, var(--gray-900) 0%, #232329 100%);
}

@media (prefers-color-scheme: dark) {
  :root {
    /* Zinc-dark: neutral, layered surfaces with borders that stay visible against the ground. */
    --bg: #09090b;
    --surface: #18181b;
    --surface-2: #1f1f23;
    --surface-hover: #27272a;
    --border: #2a2a2e;
    --border-strong: #3f3f46;
    --field-border: #52525b;

    --text: #fafafa;
    --text-dim: #a1a1aa;
    --text-faint: #71717a;

    --brand: var(--blue-400);
    --brand-deep: #1e40af;
    --accent: var(--blue-400);
    --accent-hover: #93c5fd;
    --accent-text: #0b1220;
    --accent-soft: color-mix(in srgb, var(--blue-400) 16%, var(--surface));
    --spark: var(--blue-400);

    --sidebar: #101013;
    --sidebar-ink: #a1a1aa;
    --sidebar-ink-strong: #fafafa;
    --sidebar-hover: #1f1f23;
    --sidebar-active-bg: var(--accent-soft);
    --sidebar-border: #2a2a2e;

    --danger: #f87171;  --danger-bg: #2a1416;  --danger-border: #5b2326;
    --danger-text: #0b1220;  --danger-hover: #fca5a5;
    --ok: #4ade80;      --ok-bg: #0f2418;      --ok-border: #1f4030;
    --warn: #fbbf24;    --warn-bg: #2a2010;    --warn-border: #4a3a15;

    --focus: var(--blue-400);
    --shadow-card: 0 1px 2px rgba(0, 0, 0, 0.5), 0 1px 3px rgba(0, 0, 0, 0.4);
    --brand-wash: linear-gradient(155deg, #101013 0%, #18181b 100%);
  }
}

/* ============================================================================================
   Base
   ============================================================================================ */
* { box-sizing: border-box; }
html { font-size: 100%; }
body {
  margin: 0;
  font-family: var(--font);
  font-size: var(--text-base);
  line-height: 1.55;
  color: var(--text);
  background: var(--bg);
  -webkit-text-size-adjust: 100%;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent-hover); text-decoration: underline; }

/* The focus ring is the one loud piece of chrome, and it is never removed. */
:focus-visible {
  outline: 3px solid var(--focus);
  outline-offset: 2px;
  border-radius: var(--radius-sm);
}

.skip-link {
  position: absolute;
  left: -999px;
  top: 0;
  background: var(--accent);
  color: var(--accent-text);
  padding: var(--space-2) var(--space-4);
  border-radius: 0 0 var(--radius-md) 0;
  z-index: 10;
  font-weight: 600;
}
.skip-link:focus { left: 0; }

/* Present to assistive tech, removed from the visual flow -- for a per-row control whose column
   header already names it, so a repeated visible label would be noise. */
.visually-hidden {
  position: absolute;
  width: 1px; height: 1px;
  padding: 0; margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
form.inline {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
}
/* A cell that holds several inline action forms (Save / Unlock / Delete): wrap and space them so a
   narrow column stacks them cleanly instead of colliding into one unreadable pile. */
.row-actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  align-items: center;
}
label.check {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  min-height: 1.5rem;              /* 24px minimum hit target (WCAG 2.2 SC 2.5.8) */
  color: var(--text);
  cursor: pointer;
}
/* Native checkbox: enlarge from the ~13px UA default to a 24px target and tint it with the accent. */
input[type="checkbox"] {
  width: 1.25rem;
  height: 1.25rem;
  accent-color: var(--accent);
  cursor: pointer;
}

/* ============================================================================================
   Icons -- monochrome glyphs painted with ``mask-image`` from a data-URI SVG, so a single
   ``background-color: currentColor`` colours them and they inherit the surrounding ink (white in the
   sidebar, tone colour in a metric chip). No inline <svg> in the HTML: the escaping guard stays strict.
   ============================================================================================ */
.nav-icon, .metric-icon, .empty-icon {
  flex: none;
  display: inline-block;
  background-color: currentColor;
  -webkit-mask-repeat: no-repeat; mask-repeat: no-repeat;
  -webkit-mask-position: center;  mask-position: center;
  -webkit-mask-size: contain;     mask-size: contain;
}
.nav-icon { width: 1.15rem; height: 1.15rem; }
.metric-icon { width: 1.25rem; height: 1.25rem; }
.empty-icon { width: 1.75rem; height: 1.75rem; color: var(--text-faint); }
.i-grid   { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>'); }
.i-device { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="9" y1="18" x2="15" y2="18"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="9" y1="18" x2="15" y2="18"/></svg>'); }
.i-pulse  { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3 8 4-16 3 8h4"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3 8 4-16 3 8h4"/></svg>'); }
.i-users  { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/></svg>'); }
.i-key    { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.5 12.5 20 3"/><path d="M16 7l3 3"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.5 12.5 20 3"/><path d="M16 7l3 3"/></svg>'); }
.i-shield { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5z"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5z"/></svg>'); }
.i-power  { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/></svg>'); }
.i-wifi   { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 16a5 5 0 0 1 7 0"/><line x1="12" y1="19.5" x2="12" y2="19.5"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 16a5 5 0 0 1 7 0"/><line x1="12" y1="19.5" x2="12" y2="19.5"/></svg>'); }
.i-mute   { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 5 6 9H3v6h3l5 4z"/><line x1="22" y1="9" x2="16" y2="15"/><line x1="16" y1="9" x2="22" y2="15"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 5 6 9H3v6h3l5 4z"/><line x1="22" y1="9" x2="16" y2="15"/><line x1="16" y1="9" x2="22" y2="15"/></svg>'); }
.i-unlink { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 0 1 3.5 8.5"/><line x1="8" y1="12" x2="12" y2="12"/><line x1="2" y1="2" x2="22" y2="22"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 0 1 3.5 8.5"/><line x1="8" y1="12" x2="12" y2="12"/><line x1="2" y1="2" x2="22" y2="22"/></svg>'); }
.i-clock  { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>'); }
.i-queue  { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><circle cx="3.5" cy="6" r="1.2"/><circle cx="3.5" cy="12" r="1.2"/><circle cx="3.5" cy="18" r="1.2"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><circle cx="3.5" cy="6" r="1.2"/><circle cx="3.5" cy="12" r="1.2"/><circle cx="3.5" cy="18" r="1.2"/></svg>'); }
.i-alert  { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12" y2="17"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12" y2="17"/></svg>'); }
.i-dot    { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="black"><circle cx="12" cy="12" r="5"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="black"><circle cx="12" cy="12" r="5"/></svg>'); }
.i-inbox  { -webkit-mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5.5 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.5A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.5z"/></svg>');           mask-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5.5 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.5A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.5z"/></svg>'); }

/* ============================================================================================
   App shell -- fixed brand sidebar + content column (modern admin layout)
   ============================================================================================ */
body.app {
  display: grid;
  grid-template-columns: 16rem 1fr;
  min-height: 100vh;
}

/* -- Sidebar: a neutral chrome rail (surface + hairline), not a brand wash. Active item is accent-marked. -- */
.sidebar {
  position: sticky;
  top: 0;
  align-self: start;
  height: 100vh;
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
  padding: var(--space-5) var(--space-3);
  background: var(--sidebar);
  color: var(--sidebar-ink);
  border-right: var(--hairline) solid var(--sidebar-border);
  overflow-y: auto;
}
.sidebar-brand {
  padding: 0 var(--space-2) var(--space-4);
  border-bottom: var(--hairline) solid var(--sidebar-border);
}
.sidebar .brand-name { color: var(--sidebar-ink-strong); }
.sidebar .brand-name em { color: var(--sidebar-ink); }
.sidebar .brand-tag { color: var(--text-faint); }

/* -- Top bar: slim, page title left, user chip right. Lives in the content column. -- */
header.topbar {
  position: sticky;
  top: 0;
  z-index: 5;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  padding: var(--space-4) var(--space-6);
  background: color-mix(in srgb, var(--surface) 88%, transparent);
  -webkit-backdrop-filter: saturate(1.4) blur(8px);
  backdrop-filter: saturate(1.4) blur(8px);
  border-bottom: var(--hairline) solid var(--border);
}
header.topbar h1 { margin: 0; font-size: var(--text-xl); font-weight: 650; letter-spacing: -0.01em; }

/* -- Brand lockup: mark + wordmark, shared by the sidebar and the sign-in brand panel -- */
.brand-lockup { display: inline-flex; align-items: center; gap: var(--space-3); }
/* The brand mark: a data-URI SVG (blue rounded plate, white clock: circle outline and two hands). Kept off the HTML so the
   page's escaping guard can reject any literal <svg> in a document. Brand colours are baked into the
   asset -- the one place a literal hex is legitimate. */
.logo-mark {
  flex: none;
  display: block;
  width: 34px; height: 34px;
  background-image: url('data:image/svg+xml,\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 34 34">\
<rect width="34" height="34" rx="8" fill="%232563eb"/>\
<circle cx="17" cy="17" r="8.5" fill="none" stroke="%23ffffff" stroke-width="2"/>\
<path d="M17 17V11.5" fill="none" stroke="%23ffffff" stroke-width="2" stroke-linecap="round"/>\
<path d="M17 17l3.5 2.5" fill="none" stroke="%23ffffff" stroke-width="2" stroke-linecap="round"/></svg>');
  background-size: contain;
  background-repeat: no-repeat;
}
.brand-words { display: inline-flex; flex-direction: column; line-height: 1.15; }
.brand-name {
  font-weight: 700;
  font-size: var(--text-base);
  letter-spacing: 0.02em;
  color: var(--text);
  text-transform: uppercase;
}
.brand-name em { font-style: normal; font-weight: 500; color: var(--text-dim); }
.brand-tag {
  font-size: var(--text-xs);
  color: var(--text-faint);
  letter-spacing: 0.02em;
}

/* -- User chip: initials avatar + name/role stack. A grid so the stack never collapses inline. -- */
.who {
  display: inline-grid;
  grid-template-columns: auto auto;
  align-items: center;
  gap: var(--space-3);
}
.avatar {
  grid-row: 1 / span 2;
  flex: none;
  width: 2.25rem; height: 2.25rem;
  border-radius: 50%;
  display: grid; place-items: center;
  background: linear-gradient(145deg, var(--brand) 0%, var(--brand-deep) 100%);
  color: #ffffff;
  font-size: var(--text-sm);
  font-weight: 700;
  letter-spacing: 0.02em;
}
.who-text { display: flex; flex-direction: column; line-height: 1.2; min-width: 0; }
.who-name { font-size: var(--text-sm); font-weight: 650; color: var(--text); }
.who-role {
  font-size: var(--text-xs);
  color: var(--text-faint);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

/* -- Sidebar navigation: stacked links, icon + label, cyan-lit active pill -- */
nav.mainnav {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
nav.mainnav a {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-3) var(--space-3);
  border-radius: var(--radius-md);
  color: var(--sidebar-ink);
  text-decoration: none;
  font-size: var(--text-sm);
  font-weight: 500;
  transition: background-color var(--dur-fast) var(--ease), color var(--dur-fast) var(--ease);
}
nav.mainnav a:hover {
  color: var(--sidebar-ink-strong);
  text-decoration: none;
  background: var(--sidebar-hover);
}
nav.mainnav a[aria-current="page"] {
  color: var(--accent);
  font-weight: 600;
  background: var(--sidebar-active-bg);
}
nav.mainnav a[aria-current="page"] .nav-icon { color: var(--accent); }
nav.mainnav .nav-icon { color: inherit; opacity: 0.85; }

/* ============================================================================================
   Layout + headings
   ============================================================================================ */
.content { display: flex; flex-direction: column; min-width: 0; }
main {
  flex: 1;
  width: 100%;
  max-width: 76rem;
  margin: 0 auto;
  padding: var(--space-6);
}
h1 {
  font-size: var(--text-2xl);
  font-weight: 650;
  letter-spacing: -0.01em;
  margin: 0 0 var(--space-5);
}
h2 {
  font-size: var(--text-xl);
  font-weight: 600;
  letter-spacing: -0.005em;
  margin: var(--space-6) 0 var(--space-4);
}

/* ============================================================================================
   Cards -- hairline border + soft diffuse shadow (quiet luxury: the shadow is the depth cue).
   ============================================================================================ */
.card {
  background: var(--surface);
  border: var(--hairline) solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-card);
  padding: var(--space-5);
  margin-bottom: var(--space-5);
}
/* A table can be wider than the column; it scrolls inside its own well, the page body never does. */
.table-wrap {
  overflow-x: auto;
  border: var(--hairline) solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--surface);
  box-shadow: var(--shadow-card);
  margin-bottom: var(--space-5);
}
.table-wrap > table { margin: 0; }
.table-wrap caption { padding: var(--space-4) var(--space-4) var(--space-3); }

/* ============================================================================================
   Metrics -- each counter is its own card: icon chip + figure + caption. A tone (ok/warn/danger)
   colours the chip when the count is worth attention; the caption always names it, so meaning is
   never colour-only.
   ============================================================================================ */
.metrics {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(13rem, 1fr));
  gap: var(--space-4);
  margin-bottom: var(--space-6);
}
.metric {
  display: flex;
  align-items: center;
  gap: var(--space-4);
  padding: var(--space-4) var(--space-5);
  background: var(--surface);
  border: var(--hairline) solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-card);
  transition: box-shadow var(--dur-base) var(--ease), transform var(--dur-base) var(--ease);
}
.metric:hover { box-shadow: var(--shadow-2); transform: translateY(-1px); }
.metric-icon {
  width: 1.35rem; height: 1.35rem;
  flex: none;
  padding: 0.7rem;
  border-radius: var(--radius-md);
  box-sizing: content-box;
  color: var(--brand);
  background: color-mix(in srgb, var(--brand) 12%, var(--surface));
}
.metric.ok     .metric-icon { color: var(--ok);     background: var(--ok-bg); }
.metric.warn   .metric-icon { color: var(--warn);   background: var(--warn-bg); }
.metric.danger .metric-icon { color: var(--danger); background: var(--danger-bg); }
.metric-body { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.metric .n {
  font-size: var(--text-2xl);
  font-weight: 700;
  line-height: 1.05;
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.02em;
}
.metric .k {
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-dim);
  font-weight: 600;
}

/* ============================================================================================
   Tables
   ============================================================================================ */
table {
  width: 100%;
  border-collapse: collapse;
  font-variant-numeric: tabular-nums;
}
caption {
  text-align: left;
  color: var(--text-dim);
  font-size: var(--text-sm);
  padding-bottom: var(--space-3);
  line-height: 1.4;
}
th, td {
  text-align: left;
  padding: var(--space-3) var(--space-4);
  border-bottom: var(--hairline) solid var(--border);
  vertical-align: middle;
  white-space: nowrap;
}
thead th {
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-faint);
  font-weight: 600;
  border-bottom-color: var(--border-strong);
  white-space: nowrap;
}
th[scope="row"] { color: var(--text-dim); font-weight: 600; white-space: nowrap; }
/* A two-line cell: the name (never wrapping) over a muted secondary line (a machine code, an id). */
.cell-name { display: block; font-weight: 500; color: var(--text); white-space: nowrap; }
.cell-sub {
  display: block;
  font-size: var(--text-xs);
  color: var(--text-faint);
  font-variant-numeric: tabular-nums;
  margin-top: 1px;
}
tbody tr {
  transition: background-color var(--dur-fast) var(--ease);
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: var(--surface-2); }
td.empty {
  color: var(--text-dim);
  text-align: center;
  padding: var(--space-6) var(--space-3);
}
td.empty > span:not(.empty-icon) { display: block; }
td.empty .empty-icon { margin: 0 auto var(--space-3); }

/* ============================================================================================
   State pills -- a colour AND a shape (the leading dot), so meaning survives greyscale; the
   state word is always printed as text beside the pill too (never colour alone).
   ============================================================================================ */
.pill {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  padding: 0.125rem var(--space-3) 0.125rem var(--space-2);
  border-radius: 999px;
  font-size: var(--text-sm);
  font-weight: 500;
  border: var(--hairline) solid var(--border);
  background: var(--surface-2);
  color: var(--text-dim);
}
.pill .dot {
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: currentColor;
  flex: none;
}
.pill.ok     { color: var(--ok);     background: var(--ok-bg);     border-color: var(--ok-border); }
.pill.warn   { color: var(--warn);   background: var(--warn-bg);   border-color: var(--warn-border); }
.pill.danger { color: var(--danger); background: var(--danger-bg); border-color: var(--danger-border); }

/* ============================================================================================
   Forms
   ============================================================================================ */
label {
  display: block;
  font-size: var(--text-sm);
  font-weight: 600;
  margin-bottom: var(--space-2);
  color: var(--text);
}
input:not([type="checkbox"]):not([type="radio"]), select, textarea {
  font: inherit;
  color: var(--text);
  background: var(--surface);
  border: var(--hairline) solid var(--field-border);
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-3);
  width: 100%;
  max-width: 28rem;
  transition: border-color var(--dur-fast) var(--ease), box-shadow var(--dur-fast) var(--ease);
}
input:hover, select:hover, textarea:hover { border-color: var(--text-faint); }
input:focus-visible, select:focus-visible, textarea:focus-visible {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--focus) 30%, transparent);
}
input:disabled, select:disabled, textarea:disabled {
  background: var(--surface-2);
  color: var(--text-faint);
  cursor: not-allowed;
}
[aria-invalid="true"] { border-color: var(--danger); }
[aria-invalid="true"]:focus-visible {
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--danger) 28%, transparent);
}
.field { margin-bottom: var(--space-4); }
.hint { font-size: var(--text-sm); color: var(--text-dim); margin-top: var(--space-2); }

/* ============================================================================================
   Buttons -- full state set: default / hover / active / focus-visible / disabled.
   ============================================================================================ */
button, .btn {
  font: inherit;
  font-weight: 600;
  cursor: pointer;
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-5);
  border: var(--hairline) solid var(--border-strong);
  background: var(--surface);
  color: var(--text);
  transition: background-color var(--dur-fast) var(--ease),
              border-color var(--dur-fast) var(--ease),
              box-shadow var(--dur-fast) var(--ease),
              transform var(--dur-fast) var(--ease);
}
button:hover, .btn:hover { background: var(--surface-hover); border-color: var(--text-faint); }
button:active, .btn:active { transform: translateY(1px); }
button:disabled, .btn:disabled {
  cursor: not-allowed;
  opacity: 0.55;
  transform: none;
  background: var(--surface-2);
}
button.primary, .btn.primary {
  background: var(--accent);
  color: var(--accent-text);
  border-color: transparent;
  box-shadow: var(--shadow-1);
}
button.primary:hover, .btn.primary:hover { background: var(--accent-hover); border-color: transparent; }
button.danger, .btn.danger {
  background: var(--danger);
  color: var(--danger-text);
  border-color: transparent;
  box-shadow: var(--shadow-1);
}
button.danger:hover, .btn.danger:hover {
  background: var(--danger-hover);
  border-color: transparent;
}

button.primary.block, .btn.primary.block { display: block; width: 100%; margin-top: var(--space-2); }

/* ============================================================================================
   Auth layout -- the pre-sign-in split: brand panel + content panel (quiet-luxury front door)
   ============================================================================================ */
body.auth { background: var(--bg); }
.auth-grid {
  min-height: 100vh;
  display: grid;
  grid-template-columns: minmax(0, 22rem) 1fr;
}
.auth-brand {
  position: relative;
  background: var(--brand-wash);
  color: #ffffff;
  display: flex;
  padding: var(--space-6) var(--space-5);
  overflow: hidden;
}
/* A soft cyan bloom in the corner: depth without noise. Decorative, so it rides on the aria-hidden panel. */
.auth-brand::after {
  content: "";
  position: absolute;
  right: -30%; top: -30%;
  width: 80%; aspect-ratio: 1;
  background: radial-gradient(circle, color-mix(in srgb, var(--spark) 55%, transparent) 0%, transparent 70%);
  pointer-events: none;
}
/* Fills the panel height and pushes the lockup to the top, the pitch to the bottom -- the rail reads
   top-to-bottom rather than floating mid-height. */
.auth-brand-inner {
  position: relative;
  flex: 1;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: var(--space-5);
}
/* On the dark brand wash the lockup ink flips to white; the mark keeps its own colours. */
.auth-brand .brand-name { color: #ffffff; }
.auth-brand .brand-name em { color: rgba(255, 255, 255, 0.82); }
.auth-brand .brand-tag { color: rgba(255, 255, 255, 0.72); }
.auth-pitch {
  margin: 0;
  max-width: 22rem;
  font-size: var(--text-lg);
  line-height: 1.5;
  color: rgba(255, 255, 255, 0.9);
}
.auth-main {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--space-6) var(--space-5);
}
.auth-card {
  width: 100%;
  max-width: 24rem;
  background: var(--surface);
  border: var(--hairline) solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-2);
  padding: var(--space-6) var(--space-5);
}
.auth-card h1 { font-size: var(--text-xl); margin-bottom: var(--space-2); }
.auth-lead { margin: 0 0 var(--space-5); color: var(--text-dim); font-size: var(--text-sm); }

/* ============================================================================================
   Alerts + notices
   ============================================================================================ */
.alert {
  border: var(--hairline) solid var(--danger-border);
  background: var(--danger-bg);
  color: var(--danger);
  border-radius: var(--radius-md);
  padding: var(--space-4);
  margin-bottom: var(--space-5);
}
.alert ul { margin: 0; padding-left: var(--space-5); }
.notice {
  border: var(--hairline) solid var(--border);
  background: var(--surface-2);
  color: var(--text);
  border-radius: var(--radius-md);
  padding: var(--space-4);
  margin-bottom: var(--space-5);
}

/* ============================================================================================
   Utilities + tabs
   ============================================================================================ */
.muted { color: var(--text-dim); }
.mono { font-family: var(--mono); font-size: 0.95em; }
.stack { display: flex; flex-direction: column; gap: var(--space-4); align-items: flex-start; }
/* A small uppercase kicker above a heading -- the "eyebrow" of a section or an error page. */
.eyebrow {
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-weight: 700;
  color: var(--accent);
  margin: 0;
}
.tabs {
  display: flex;
  gap: var(--space-4);
  margin-bottom: var(--space-5);
  border-bottom: var(--hairline) solid var(--border-strong);
}
.tabs a {
  padding: var(--space-3) 0;
  color: var(--text-dim);
  font-weight: 500;
  border-bottom: 2px solid transparent;
  margin-bottom: -1px;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}
.tabs a:hover { color: var(--text); text-decoration: none; border-bottom-color: var(--border-strong); }
.tabs a[aria-current="page"] {
  color: var(--text);
  font-weight: 600;
  border-bottom-color: var(--accent);
}

/* ============================================================================================
   Responsive: table -> block cards, one-column grid.
   ============================================================================================ */
@media (max-width: 52rem) {
  /* The rail becomes a full-width top band; nav lays out horizontally under the brand. */
  body.app { grid-template-columns: 1fr; }
  .sidebar {
    position: static;
    height: auto;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-4);
    border-right: none;
    border-bottom: var(--hairline) solid var(--sidebar-border);
  }
  .sidebar-brand { padding: 0 0 var(--space-3); }
  nav.mainnav { flex-direction: row; flex-wrap: wrap; gap: var(--space-2); }
}
@media (max-width: 40rem) {
  main { padding: var(--space-5) var(--space-4); }
  header.topbar { padding-left: var(--space-4); padding-right: var(--space-4); }
  header.topbar .who-text { display: none; }   /* keep the avatar, drop the name/role to save the row */
  header.topbar h1 { font-size: var(--text-lg); }
  .brand-tag { display: none; }
  .metrics { grid-template-columns: 1fr; }
  /* The auth split stacks: brand becomes a slim banner above the card. */
  .auth-grid { grid-template-columns: 1fr; min-height: 100dvh; }
  .auth-brand { padding: var(--space-5) var(--space-4); }
  .auth-brand-inner { gap: var(--space-3); }
  .auth-pitch { display: none; }
  .auth-main { padding: var(--space-5) var(--space-4); align-items: flex-start; }
  /* The scrollable well becomes a plain container; each row is now its own card. */
  .table-wrap { overflow-x: visible; border: none; background: none; box-shadow: none; }
  table, thead, tbody, th, td, tr, caption { display: block; width: auto; }
  thead { position: absolute; left: -999px; }
  caption { padding: 0 0 var(--space-3) !important; white-space: normal; }
  /* Each row is a bordered card; the column header is gone, so reprint it from data-label. */
  tbody tr {
    border: var(--hairline) solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    padding: var(--space-3) var(--space-4);
    margin-bottom: var(--space-3);
  }
  tbody tr:last-child { margin-bottom: 0; }
  /* A flex row keeps label and value on one line, label left, value right. */
  td {
    border: none;
    padding: var(--space-2) 0;
    display: flex;
    gap: var(--space-4);
    justify-content: space-between;
    align-items: baseline;
    white-space: normal;
  }
  td + td { border-top: var(--hairline) solid var(--border); }
  /* The value side may hold long serials; let it shrink and wrap instead of overflowing. */
  td[data-label]::before {
    content: attr(data-label);
    flex: 0 0 auto;
    font-size: var(--text-xs);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-faint);
    font-weight: 600;
  }
  td[data-label] > * { min-width: 0; text-align: right; word-break: break-word; }
  /* In a card the value sits on the right; keep its two lines right-aligned under the label. */
  td .cell-name, td .cell-sub { text-align: right; white-space: normal; }
  /* A blank data-label (a spacer column) prints no prefix and takes the full width. */
  td[data-label=""]::before { content: none; }
  td.empty { display: block; text-align: center; padding: var(--space-6) var(--space-4); }
  td.empty::before { content: none; }
  td.empty + td, td + td.empty { border-top: none; }
}

/* No motion for those who ask for none: transitions and animations off, ring stays. */
@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; animation: none !important; }
}
"""

#: First 16 hex of the stylesheet's SHA-256, computed at import. The route returns this as the ETag and
#: answers 304 when it matches, so a page load is one small HTML document after the first visit. 16 hex
#: is 64 bits -- ample to distinguish stylesheet revisions, and a full digest would only bloat headers.
STYLESHEET_ETAG = hashlib.sha256(STYLESHEET.encode("utf-8")).hexdigest()[:16]


# ── Page shell ────────────────────────────────────────────────────────────────────────────────────
#
# Every rendered page is a whole document produced here. The shell owns the invariants the structure
# tests pin: a doctype, ``lang="en"``, exactly one ``<h1>`` (the page title), the skip link as the very
# first focusable element with a target that exists, and the ``<nav>`` / ``<main>`` landmarks. ``body``
# is trusted, already-escaped HTML assembled by a caller; every *value* the shell interpolates itself --
# the title, the principal's name, a flash message -- is passed through :func:`esc`.

_MAIN_ID = "main"  # the skip link's target; the id lives on <main>

#: (href, label, key, capability-attr, icon). Order is the nav order. A link is shown only if the
#: principal has the capability, so a viewer never sees a link to a page that would 403. ``None`` means
#: "any signed-in user". ``icon`` names a glyph in ``_NAV_ICONS`` (a data-URI SVG mask). Navigation is
#: the one place a role leaks into ui.py, and it is read-only.
_NAV = (
    ("/", "Dashboard", "dashboard", None, "grid"),
    ("/devices", "Devices", "devices", None, "device"),
    ("/roster-sync", "Roster sync", "roster-sync", None, "pulse"),
    ("/activity", "Activity", "activity", None, "pulse"),
    ("/users", "Users", "users", "can_administer", "users"),
    ("/employees", "Employees", "employees", "can_administer", "device"),
    ("/sessions", "Sessions", "sessions", "can_administer", "key"),
    ("/audit", "Audit", "audit", None, "shield"),
)


def _nav(principal: Principal | None, active: str) -> str:
    """The sidebar's primary navigation: one link per section, each with a mask-painted icon and label."""
    if principal is None:
        return ""
    items = []
    for href, label, key, cap, icon in _NAV:
        if cap is not None and not getattr(principal, cap):
            continue
        current = ' aria-current="page"' if key == active else ""
        items.append(
            f'<a href="{esc_attr(href)}"{current}>'
            f'<span class="nav-icon i-{icon}" aria-hidden="true"></span>'
            f'<span class="nav-label">{esc(label)}</span></a>'
        )
    return f'<nav class="mainnav" aria-label="Primary">{"".join(items)}</nav>'


def _alert(messages: list[str], *, ident: str = "form-errors") -> str:
    """A live-announced error region. Empty string when there is nothing to say."""
    if not messages:
        return ""
    items = "".join(f"<li>{esc(m)}</li>" for m in messages)
    return (
        f'<div id="{ident}" class="alert" role="alert" aria-live="polite">'
        f"<ul>{items}</ul></div>"
    )


def _hidden(name: str, value: str) -> str:
    return f'<input type="hidden" name="{esc_attr(name)}" value="{esc_attr(value)}">'


def page(
    *,
    title: str,
    body: str,
    principal: Principal | None,
    active: str = "",
    message: str = "",
    error: str = "",
    csrf: str = "",  # noqa: ARG001 -- part of the shared signature; forms in `body` carry their own token
) -> str:
    """
    Wrap already-escaped ``body`` in the full document: head, skip link, top bar, nav and ``<main>``.

    ``title`` becomes the one ``<h1>`` and the ``<title>``. ``message`` and ``error`` are page-level
    flashes (a success notice, a non-form error) and are escaped here. ``csrf`` is accepted so callers
    can pass it uniformly, but the shell renders no form of its own -- the forms live in ``body`` and
    carry their own field.
    """
    who = ""
    if principal is not None:
        initials = _initials(principal.display_name)
        who = (
            '<div class="who">'
            f'<span class="avatar" aria-hidden="true">{esc(initials)}</span>'
            '<span class="who-text">'
            f'<span class="who-name">{esc(principal.display_name)}</span>'
            f'<span class="who-role">{esc(principal.role)}</span>'
            "</span></div>"
        )
    flash = ""
    if error:
        flash += f'<div class="alert" role="alert" aria-live="polite">{esc(error)}</div>'
    if message:
        flash += f'<div class="notice">{esc(message)}</div>'

    # App shell: a fixed brand sidebar (its own <nav> landmark) + a content column whose slim top bar
    # carries the page title and the user chip. The sidebar renders only for a signed-in principal;
    # standalone pages (sign-in, errors) use ``_standalone`` and never reach here.
    sidebar = (
        '<aside class="sidebar">'
        f'<div class="sidebar-brand">{_brand_lockup()}</div>'
        f"{_nav(principal, active)}"
        "</aside>\n"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{esc(title)} &middot; ADMS Console</title>\n"
        '<link rel="stylesheet" href="/assets/console.css">\n'
        "</head>\n"
        '<body class="app">\n'
        f'<a class="skip-link" href="#{_MAIN_ID}">Skip to content</a>\n'
        f"{sidebar}"
        '<div class="content">\n'
        '<header class="topbar">'
        f'<h1>{esc(title)}</h1>'
        f"{who}</header>\n"
        f'<main id="{_MAIN_ID}">\n'
        f"{flash}"
        f"{body}\n"
        "</main>\n"
        "</div>\n"
        "</body>\n"
        "</html>\n"
    )


def _standalone(*, title: str, body: str, lead: str = "") -> str:
    """
    A full document with no nav and no principal, for the pages shown before sign-in: a two-panel
    "auth" layout with the brand on the left and the content (the one ``<h1>`` and ``body``) on the
    right. On a narrow screen the brand panel collapses to a slim header above the content. ``lead`` is
    an optional escaped-by-caller sub-heading shown under the title.
    """
    lead_html = f'<p class="auth-lead">{lead}</p>' if lead else ""
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{esc(title)} &middot; ADMS Collector</title>\n"
        '<link rel="stylesheet" href="/assets/console.css">\n'
        "</head>\n"
        "<body class=\"auth\">\n"
        f'<a class="skip-link" href="#{_MAIN_ID}">Skip to content</a>\n'
        '<div class="auth-grid">\n'
        '<aside class="auth-brand" aria-hidden="true">\n'
        '<div class="auth-brand-inner">'
        f"{_brand_lockup()}"
        '<p class="auth-pitch">Manage attendance terminals, users and activity '
        "across every site from one console.</p>"
        "</div>\n"
        "</aside>\n"
        f'<main id="{_MAIN_ID}" class="auth-main">\n'
        '<div class="auth-card">\n'
        f"<h1>{esc(title)}</h1>\n"
        f"{lead_html}"
        f"{body}\n"
        "</div>\n"
        "</main>\n"
        "</div>\n"
        "</body>\n"
        "</html>\n"
    )


def sign_in_page(*, error: str = "", username: str = "", next_url: str = "", csrf: str = "") -> str:
    """
    The unauthenticated sign-in form.

    On a failed attempt the caller passes a single, deliberately vague ``error`` (Property 10) and the
    ``username`` so it need not be retyped; the password is never echoed. ``next_url`` rides along as a
    hidden field so a caller redirected here is returned to where they were going. ``csrf`` is the
    double-submit token whose secret the caller also set in a cookie; the POST handler verifies the two
    agree, which is what guards the form without a session (and works on plain HTTP).
    """
    alert = _alert([error]) if error else ""
    nxt = _hidden("next", next_url) if next_url else ""
    tok = _hidden("csrf_token", csrf) if csrf else ""
    body = (
        '<form method="post" action="/sign-in">'
        f"{alert}"
        f"{tok}"
        '<div class="field">'
        '<label for="username">Username</label>'
        f'<input id="username" name="username" type="text" autocomplete="username" '
        f'autocapitalize="none" spellcheck="false" required value="{esc_attr(username)}">'
        "</div>"
        '<div class="field">'
        '<label for="password">Password</label>'
        '<input id="password" name="password" type="password" '
        'autocomplete="current-password" required>'
        "</div>"
        f"{nxt}"
        '<button type="submit" class="primary block">Sign in</button>'
        "</form>"
    )
    return _standalone(
        title="Sign in", body=body,
        lead="Use your console account to continue.",
    )


def change_password_page(*, problems: list[str], forced: bool, csrf: str) -> str:
    """
    The change-password form, shown voluntarily or forced after a reset (``must_change_password``).

    ``problems`` are the messages from a rejected attempt; when non-empty the field is marked invalid
    and described by the alert. ``forced`` adds a line explaining why the user cannot proceed until they
    change it, which the voluntary variant omits.
    """
    invalid = ' aria-invalid="true"' if problems else ""
    described = ' aria-describedby="pw-errors"' if problems else ""
    alert = _alert(problems, ident="pw-errors")
    reason = (
        '<p class="notice">Your password was reset and must be changed before you continue.</p>'
        if forced
        else ""
    )
    body = (
        f"{reason}"
        '<form method="post" action="/change-password">'
        f"{alert}"
        f"{_hidden('csrf_token', csrf)}"
        '<div class="field">'
        '<label for="current">Current password</label>'
        '<input id="current" name="current" type="password" '
        'autocomplete="current-password" required>'
        "</div>"
        '<div class="field">'
        '<label for="new-password">New password</label>'
        f'<input id="new-password" name="new_password" type="password" '
        f'autocomplete="new-password" required{invalid}{described}>'
        '<p class="hint">At least 12 characters. Not a common password. '
        "Must not contain your username.</p>"
        "</div>"
        '<button type="submit" class="primary">Change password</button>'
        "</form>"
    )
    return _standalone(title="Change password", body=body)


def confirm_page(
    *,
    title: str,
    prompt: str,
    action: str,
    hidden: dict[str, str],
    csrf: str,
    danger: bool = True,
) -> str:
    """
    A server-rendered "are you sure" page: the one interstitial that stands in for JavaScript.

    ``prompt`` is a value and is escaped. ``action`` is where the confirming POST goes; ``hidden``
    carries whatever ids the handler needs, and every value is escaped. ``danger`` styles the confirm
    button as destructive, which is the default because this page exists for destructive actions.
    """
    fields = "".join(_hidden(name, value) for name, value in hidden.items())
    button_class = "danger" if danger else "primary"
    body = (
        '<div class="stack">'
        f"<p>{esc(prompt)}</p>"
        f'<form method="post" action="{esc_attr(action)}">'
        f"{_hidden('csrf_token', csrf)}"
        f"{fields}"
        f'<button type="submit" class="{button_class}">{esc(title)}</button>'
        "</form>"
        "</div>"
    )
    return _standalone(title=title, body=body)


def error_page(status: int, heading: str, detail: str) -> str:
    """A whole-document error page. ``heading`` and ``detail`` are values and are escaped."""
    body = (
        '<div class="stack">'
        f'<p class="eyebrow">Error {esc(status)}</p>'
        f"<p>{esc(detail)}</p>"
        '<p><a href="/">Return to the dashboard</a></p>'
        "</div>"
    )
    return _standalone(title=heading, body=body)


# ── Data pages ──────────────────────────────────────────────────────────────────────────────────
#
# Each function turns rows into one already-escaped ``body`` fragment and wraps it in the authenticated
# shell via :func:`page`. Every value is passed through :func:`esc`; the device network reaches these
# pages (a DeviceName, an unparsed line) so the escaping is the threat model, not decoration. Timestamps
# render in site-local time with the zone named (Property 28); the offset defaults to +7 to match
# ``ZONE_LABEL`` and is overridable so a site on another offset stays honest.

#: The queue control's command menu. Each entry is (form value, human label, destructive?). Destructive
#: members are offered only to a principal that ``can_send_destructive_command`` and each still passes
#: through a confirm page in the handler. The mapping from value to device command text lives in the
#: handler's allow-list (D7), not here -- ui.py names the choices, it does not decide policy.
_COMMAND_MENU = (
    ("REBOOT", "Reboot", False),
    ("INFO", "Request info", False),
    ("CHECK", "Check data", False),
    ("DATA QUERY USERINFO", "Query users", False),
    ("SET OPTION", "Sync clock", False),
    ("CLEAR DATA", "Clear data (erases users on device)", True),
    ("CLEAR LOG", "Clear log (erases punches on device)", True),
    ("CLEAR PHOTO", "Clear photos (erases photos on device)", True),
)

#: Device state -> the pill class that carries its colour. The state word is always printed as text
#: beside the pill, so meaning never rides on colour alone (WCAG 2.2, Requirement 6.6).
_STATE_CLASS = {
    "Online": "ok",
    "Silent": "danger",
    "Not linked": "warn",
    "Never seen": "warn",
    "Disabled": "",  # a deliberately-off device is a neutral state, not a warning -- grey, not amber
}


def _pill(text: str, cls: str = "") -> str:
    """A status pill: a coloured dot (a non-colour cue for greyscale/colour-blind users) beside the
    label. Every caller also prints the state as plain text nearby, so meaning is never colour-only."""
    classes = f"pill {cls}".rstrip()
    return f'<span class="{classes}"><span class="dot"></span>{esc(text)}</span>'


def _state_pill(state: str) -> str:
    return _pill(state, _STATE_CLASS.get(state, ""))


def _empty_state(colspan: int, message: str) -> str:
    """The single 'no rows yet' cell: a muted icon above the message, so an empty table reads as a
    deliberate state rather than a truncated one."""
    return (
        f'<tr><td colspan="{colspan}" class="empty">'
        '<span class="empty-icon i-inbox" aria-hidden="true"></span>'
        f"<span>{esc(message)}</span>"
        "</td></tr>"
    )


def _data_table(
    *,
    caption: str,
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    empty: str,
) -> str:
    """One captioned, header-scoped data table.

    ``headers`` are plain labels (escaped here). Each row is a sequence of *already-built* HTML cells,
    one per header. Every ``<td>`` carries ``data-label`` so the mobile card layout can name each field
    once the table reflows to blocks. ``caption`` is trusted HTML (callers compose it with ``esc``).
    """
    head = "".join(f'<th scope="col">{esc(h)}</th>' for h in headers)
    if rows:
        body = "".join(
            "<tr>"
            + "".join(
                f'<td data-label="{esc_attr(label)}">{cell}</td>'
                for label, cell in zip(headers, cells)
            )
            + "</tr>"
            for cells in rows
        )
    else:
        body = _empty_state(len(headers), empty)
    # Self-wrapped in a scrollable, bordered well: the table is its own card, and a row wider than the
    # column scrolls inside this well rather than pushing the page body sideways.
    return (
        '<div class="table-wrap">'
        f"<table><caption>{caption}</caption>"
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
        "</div>"
    )


def _metric(label: str, value: object, *, icon: str = "dot", tone: str = "") -> str:
    """A dashboard counter card: an icon chip, the big tabular figure, and its uppercase caption.

    ``icon`` names a glyph in ``_METRIC_ICONS``; ``tone`` (``""``/``ok``/``warn``/``danger``) colours the
    icon chip so an at-risk count reads at a glance -- never by colour alone, the label always states it.
    """
    tone_cls = f" {tone}" if tone else ""
    return (
        f'<div class="metric{tone_cls}">'
        f'<span class="metric-icon i-{icon}" aria-hidden="true"></span>'
        '<span class="metric-body">'
        f'<span class="n">{esc(value)}</span>'
        f'<span class="k">{esc(label)}</span>'
        "</span></div>"
    )


def _yesno(value: bool) -> str:
    return "Yes" if value else "No"


def dashboard(
    summary: dict, devices: Sequence[DeviceRow], principal: Principal, *, offset_hours: int = 7
) -> str:
    """The landing page: the summary counters, then the device table so the state is one glance away."""
    # (label, summary-key, icon, tone-when-nonzero). ``tone`` empties out at zero so a clean board is
    # calm: an amber "Silent" chip appears only when something is actually silent. "Online" is the one
    # positive signal, so its tone is green when present.
    counters = (
        ("Devices", "devices", "device", ""),
        ("Enabled", "enabled", "power", ""),
        ("Online", "online", "wifi", "ok"),
        ("Silent", "silent", "mute", "warn"),
        ("Not linked", "unlinked", "unlink", "warn"),
        ("Punches (24h)", "punches_24h", "clock", ""),
        ("Pending commands", "pending_cmds", "queue", ""),
        ("Stuck commands", "stuck_cmds", "alert", "danger"),
        ("Unprojected punches", "unprojected", "alert", "warn"),
        ("Non-numeric pins", "bad_pins", "alert", "warn"),
        # multi-device-employee-sync. "Behind" is the one that matters at a glance -- a device
        # counted here is owed at least one Roster_Version and has not yet caught up, which is
        # the operator-visible symptom of a missed Fan_Out or an overdue Backfill.
        ("Roster sync devices", "roster_devices", "device", ""),
        ("Roster sync behind", "roster_behind", "alert", "warn"),
        ("Deletions fanned out (24h)", "deletions_24h", "shield", ""),
    )
    cells = ""
    for label, key, icon, risk_tone in counters:
        value = summary.get(key, 0)
        tone = risk_tone if (risk_tone and isinstance(value, int) and value > 0) else ""
        cells += _metric(label, value, icon=icon, tone=tone)
    body = (
        f'<section class="metrics">{cells}</section>'
        "<h2>Devices</h2>"
        f"{_device_table(devices, offset_hours)}"
    )
    return page(title="Dashboard", body=body, principal=principal, active="dashboard")


def _device_table(devices: Sequence[DeviceRow], offset_hours: int) -> str:
    return _data_table(
        caption=(
            "Registered devices, most in need of attention first. "
            f"Times shown in {esc(_offset_label(offset_hours))}."
        ),
        headers=("Serial", "Name", "State", "Machine", "Sync group", "Last seen", "Punches 24h", "Pending"),
        rows=[
            (
                f'<a href="/devices/{esc_attr(d.serial)}" class="mono">{esc(d.serial)}</a>',
                f'<span class="cell-name">{esc(d.device_name)}</span>',
                _state_pill(d.state),
                f'<span class="cell-name">{esc(d.machine_name)}</span>',
                _sync_group_cell(d),
                esc(local_time(d.last_seen_utc, offset_hours)),
                esc(d.punches_last_24h),
                esc(d.pending_commands),
            )
            for d in devices
        ],
        empty="No devices registered yet.",
    )


def _sync_group_cell(d: DeviceRow) -> str:
    """
    A device's Roster_Sync membership, as one cell: the group label when it has one, a plain dash
    when it does not (never a warning pill -- no SyncGroup is the default, inert state for most of
    an estate, not a problem). ``pins_owed > 0`` gets an amber pill because that is the one
    Roster_Sync-specific condition an operator actually needs to notice from the device table
    alone; the full breakdown lives on the dedicated Roster Sync page.
    """
    if not d.sync_group:
        return '<span class="cell-sub">&mdash;</span>'
    owed = d.roster_pins_owed or 0
    label = f"{esc(d.sync_group)}"
    if owed > 0:
        return (
            f'<span class="cell-name">{label}</span>'
            f'<span class="cell-sub">{_pill(f"{owed} owed", "warn")}</span>'
        )
    return f'<span class="cell-name">{label}</span><span class="cell-sub">{_pill("current", "ok")}</span>'


def device_list(devices: Sequence[DeviceRow], principal: Principal, *, offset_hours: int = 7) -> str:
    """Every registered device with its full row, one table."""
    # The list is a scan surface, not a spec sheet: it carries the columns you triage by (identity, state,
    # recency, load). Firmware / platform / push / IP / contact count are per-device facts that live on the
    # detail page, so they are dropped here rather than crushed into a 12-column row that wraps and empties.
    table = _data_table(
        caption=f"All devices. Times shown in {esc(_offset_label(offset_hours))}.",
        headers=("Serial", "Name", "State", "Machine", "Sync group", "Last seen", "Punches 24h", "Pending"),
        rows=[
            (
                f'<a href="/devices/{esc_attr(d.serial)}" class="mono">{esc(d.serial)}</a>',
                f'<span class="cell-name">{esc(d.device_name)}</span>',
                _state_pill(d.state),
                (
                    f'<span class="cell-name">{esc(d.machine_name)}</span>'
                    f'<span class="cell-sub">{esc(d.machine_code)}</span>'
                ),
                _sync_group_cell(d),
                esc(local_time(d.last_seen_utc, offset_hours)),
                esc(d.punches_last_24h),
                esc(d.pending_commands),
            )
            for d in devices
        ],
        empty="No devices registered yet.",
    )
    body = table
    return page(title="Devices", body=body, principal=principal, active="devices")


def device_detail(
    device: DeviceRow,
    machines: list[dict],
    commands: list[dict],
    punches: list[dict],
    principal: Principal,
    csrf: str,
    *,
    offset_hours: int = 7,
) -> str:
    """One device: its facts, the link-to-machine form, the queue control, and command history."""
    body = (
        _device_facts(device, offset_hours)
        + _enable_form(device, csrf)
        + _link_form(device, machines, csrf)
        + _queue_form(device, principal, csrf)
        + _command_history(commands, offset_hours)
        + _device_punches(punches, offset_hours)
    )
    return page(title=device.serial, body=body, principal=principal, active="devices")


def _device_facts(d: DeviceRow, offset_hours: int) -> str:
    facts = (
        ("Name", esc(d.device_name)),
        ("State", _state_pill(d.state)),
        ("Enabled", esc(_yesno(d.enabled))),
        ("Machine", f"{esc(d.machine_name)} ({esc(d.machine_code)})"),
        ("Firmware", esc(d.firmware)),
        ("Platform", esc(d.platform)),
        ("Push version", esc(d.push_version)),
        ("Last seen", esc(local_time(d.last_seen_utc, offset_hours))),
        ("Last IP", esc(d.last_ip)),
        ("Contacts", esc(d.contact_count)),
        ("Sync group", _device_sync_group_fact(d)),
    )
    rows = "".join(f'<tr><th scope="row">{esc(k)}</th><td>{v}</td></tr>' for k, v in facts)
    return (
        '<div class="card"><table><caption>Device details, times in '
        f"{esc(_offset_label(offset_hours))}.</caption><tbody>{rows}</tbody></table></div>"
    )


def _device_sync_group_fact(d: DeviceRow) -> str:
    """
    The device-detail page's Roster_Sync line: no group is stated plainly (not a warning -- most
    devices are never opted in), a group with nothing owed reads as caught up, and a group with a
    gap links to the Roster Sync page rather than repeating that page's own breakdown here.
    """
    if not d.sync_group:
        return '<span class="cell-sub">Not in a sync group</span>'
    owed = d.roster_pins_owed or 0
    if owed > 0:
        return (
            f"{esc(d.sync_group)} &middot; "
            f'<a href="/roster-sync">{_pill(f"{owed} versions owed", "warn")}</a>'
        )
    return f"{esc(d.sync_group)} &middot; {_pill('current', 'ok')}"


def _enable_form(d: DeviceRow, csrf: str) -> str:
    """Turn a device on or off. Enabling is a plain POST; disabling routes through the confirm page
    because it stops the device accepting pushes until someone turns it back on."""
    if d.enabled:
        return (
            '<h2>Availability</h2><div class="card">'
            '<p class="hint">This device is enabled and accepting pushes. '
            "Disabling it stops new punches until it is re-enabled.</p>"
            f'<a class="btn danger" href="/devices/{esc_attr(d.serial)}/confirm">'
            "Disable device</a></div>"
        )
    return (
        '<h2>Availability</h2><div class="card">'
        '<p class="hint">This device is disabled and refuses pushes. '
        "Enable it to let it report punches again.</p>"
        f'<form method="post" action="/devices/{esc_attr(d.serial)}/enable">'
        f"{_hidden('csrf_token', csrf)}"
        '<button type="submit" class="primary">Enable device</button></form></div>'
    )


def _link_form(d: DeviceRow, machines: list[dict], csrf: str) -> str:
    options = ['<option value="">— Not linked —</option>']
    for m in machines:
        selected = " selected" if m["code"] == d.machine_code else ""
        idmcc = "" if m["numeric_id"] is None else f" · IDMCC {esc(m['numeric_id'])}"
        options.append(
            f'<option value="{esc_attr(m["code"])}"{selected}>'
            f'{esc(m["name"])} ({esc(m["code"])}){idmcc}</option>'
        )
    return (
        '<h2>Machine</h2><div class="card">'
        f'<form method="post" action="/devices/{esc_attr(d.serial)}/link">'
        f"{_hidden('csrf_token', csrf)}"
        '<div class="field"><label for="mamcc">Linked machine</label>'
        f'<select id="mamcc" name="mamcc">{"".join(options)}</select>'
        '<p class="hint">IDMCC is shown because it is not unique across machines; '
        "the name tells you which one you picked.</p></div>"
        '<button type="submit">Save link</button></form></div>'
    )


def _queue_form(d: DeviceRow, principal: Principal, csrf: str) -> str:
    options = []
    for value, label, destructive in _COMMAND_MENU:
        if destructive and not principal.can_send_destructive_command:
            continue
        options.append(f'<option value="{esc_attr(value)}">{esc(label)}</option>')
    return (
        '<h2>Queue a command</h2><div class="card">'
        f'<form method="post" action="/devices/{esc_attr(d.serial)}/commands">'
        f"{_hidden('csrf_token', csrf)}"
        '<div class="field"><label for="command">Command</label>'
        f'<select id="command" name="command">{"".join(options)}</select>'
        '<p class="hint">The device picks the command up on its next poll, so it is delivered '
        "within about a poll interval; a destructive command asks you to confirm first.</p></div>"
        '<button type="submit" class="primary">Queue command</button></form></div>'
    )


def _command_history(commands: list[dict], offset_hours: int) -> str:
    table = _data_table(
        caption=f"Commands for this device, times in {esc(_offset_label(offset_hours))}.",
        headers=("ID", "Command", "Status", "By", "Queued", "Sent", "Acked", "Return"),
        rows=[
            (
                esc(c["id"]),
                esc(c["text"]),
                esc(c["status"]),
                esc(c["created_by"]),
                esc(local_time(c["created_utc"], offset_hours)),
                esc(local_time(c["sent_utc"], offset_hours)),
                esc(local_time(c["acked_utc"], offset_hours)),
                f"{esc(c['return_code'])} {esc(c['return_cmd'])}",
            )
            for c in commands
        ],
        empty="No commands queued.",
    )
    return f'<h2>Command history</h2>{table}'


def _device_punches(punches: list[dict], offset_hours: int) -> str:
    table = _data_table(
        caption=f"Latest punches from this device, times in {esc(_offset_label(offset_hours))}.",
        headers=("Pin", "Punch time", "Status", "Verify", "Received"),
        rows=[
            (
                esc(p["pin"]),
                esc(local_time(p["punch_time"], offset_hours)),
                esc(p["status"]),
                esc(p["verify"]),
                esc(local_time(p["received_utc"], offset_hours)),
            )
            for p in punches
        ],
        empty="No recent punches.",
    )
    return f'<h2>Recent punches</h2>{table}'


def activity_page(
    tab: str,
    punches: list[dict],
    uploads: list[dict],
    unparsed: list[dict],
    principal: Principal,
    *,
    offset_hours: int = 7,
) -> str:
    """The three activity streams, one tab at a time: punches, uploads, unparsed lines."""
    tabs = (("punches", "Punches"), ("uploads", "Uploads"), ("unparsed", "Unparsed"))
    links = "".join(
        f'<a href="/activity?tab={esc_attr(key)}"'
        f'{" aria-current=\"page\"" if key == tab else ""}>{esc(label)}</a>'
        for key, label in tabs
    )
    if tab == "uploads":
        table = _upload_table(uploads, offset_hours)
    elif tab == "unparsed":
        table = _unparsed_table(unparsed, offset_hours)
    else:
        table = _punch_table(punches, offset_hours)
    body = f'<nav class="tabs" aria-label="Activity">{links}</nav>{table}'
    return page(title="Activity", body=body, principal=principal, active="activity")


def _punch_table(punches: list[dict], offset_hours: int) -> str:
    return _data_table(
        caption=f"Recent punches, times in {esc(_offset_label(offset_hours))}.",
        headers=("Serial", "Pin", "Punch time", "Status", "Verify", "Received"),
        rows=[
            (
                esc(p["serial"]),
                esc(p["pin"]),
                esc(local_time(p["punch_time"], offset_hours)),
                esc(p["status"]),
                esc(p["verify"]),
                esc(local_time(p["received_utc"], offset_hours)),
            )
            for p in punches
        ],
        empty="No recent punches.",
    )


def _upload_table(uploads: list[dict], offset_hours: int) -> str:
    return _data_table(
        caption=f"Recent uploads, times in {esc(_offset_label(offset_hours))}.",
        headers=("Serial", "Table", "Records", "Body bytes", "Received"),
        rows=[
            (
                esc(u["serial"]),
                esc(u["table"]),
                esc(u["records"]),
                esc(u["body_len"]),
                esc(local_time(u["received_utc"], offset_hours)),
            )
            for u in uploads
        ],
        empty="No recent uploads.",
    )


def _unparsed_table(unparsed: list[dict], offset_hours: int) -> str:
    return _data_table(
        caption=(
            "Lines the collector could not parse, times in "
            f"{esc(_offset_label(offset_hours))}."
        ),
        headers=("Serial", "Table", "Raw line", "Received"),
        rows=[
            (
                esc(u["serial"]),
                esc(u["table"]),
                f'<span class="mono">{esc(u["line"])}</span>',
                esc(local_time(u["received_utc"], offset_hours)),
            )
            for u in unparsed
        ],
        empty="No unparsed lines.",
    )


_ROLES: tuple[str, ...] = ("viewer", "operator", "admin")


def _role_select(selected: str, *, ident: str = "") -> str:
    """A role picker. ``selected`` is compared, not printed raw; each option value is a fixed literal."""
    id_attr = f' id="{esc_attr(ident)}"' if ident else ""
    options = "".join(
        f'<option value="{r}"{" selected" if r == selected else ""}>{r}</option>'
        for r in _ROLES
    )
    return f'<select name="role"{id_attr}>{options}</select>'


def users_page(
    users: list[UserRow], principal: Principal, csrf: str, *, offset_hours: int = 7
) -> str:
    """Console users. No password, hash or token is ever printed; only the facts an admin acts on."""
    admin = principal.can_administer
    headers = ["Username", "Name", "Role", "Enabled", "Status", "Last login"]
    if admin:
        headers.append("Actions")
    table = _data_table(
        caption=f"Console users, times in {esc(_offset_label(offset_hours))}.",
        headers=headers,
        rows=[
            [
                esc(u.username),
                esc(u.display_name),
                esc(u.role),
                esc(_yesno(u.is_enabled)),
                _user_status(u),
                esc(local_time(u.last_login_utc, offset_hours)),
                *([_user_actions(u, principal, csrf)] if admin else []),
            ]
            for u in users
        ],
        empty="No users.",
    )
    intro = _user_create_form(csrf) if admin else ""
    body = f'{intro}{table}'
    return page(title="Users", body=body, principal=principal, active="users", csrf=csrf)


def _user_create_form(csrf: str) -> str:
    """The add-user form. Server-rendered, no JavaScript; the temporary password is forced to change."""
    return (
        '<form method="post" action="/users" class="card">'
        "<h2>Add user</h2>"
        f"{_hidden('csrf_token', csrf)}"
        '<div class="field"><label for="new-username">Username</label>'
        '<input id="new-username" name="username" required autocomplete="off"></div>'
        '<div class="field"><label for="new-display">Name</label>'
        '<input id="new-display" name="display_name" autocomplete="off"></div>'
        '<div class="field"><label for="new-role">Role</label>'
        f'{_role_select("viewer", ident="new-role")}</div>'
        '<div class="field"><label for="new-pw">Temporary password</label>'
        '<input id="new-pw" name="password" type="password" autocomplete="new-password" required>'
        '<p class="hint">At least 12 characters. The user must change it on first sign-in.</p></div>'
        '<button type="submit" class="primary">Add user</button>'
        "</form>"
    )


def _user_actions(u: UserRow, principal: Principal, csrf: str) -> str:
    """Per-row controls: update role/enabled, unlock, delete. The actor's own row cannot self-delete."""
    enabled_checked = " checked" if u.is_enabled else ""
    role_id = f"role-{u.user_id}"
    enabled_id = f"enabled-{u.user_id}"
    update = (
        f'<form method="post" action="/users/{esc_attr(u.user_id)}/update" class="inline">'
        f"{_hidden('csrf_token', csrf)}"
        f'{_hidden("display_name", u.display_name)}'
        f'<label class="visually-hidden" for="{role_id}">Role for {esc(u.username)}</label>'
        f"{_role_select(u.role, ident=role_id)}"
        f'<label class="check" for="{enabled_id}">'
        f'<input id="{enabled_id}" type="checkbox" name="enabled" value="1"{enabled_checked}> Enabled</label>'
        '<button type="submit">Save</button></form>'
    )
    unlock = (
        f'<form method="post" action="/users/{esc_attr(u.user_id)}/unlock" class="inline">'
        f"{_hidden('csrf_token', csrf)}<button type=\"submit\">Unlock</button></form>"
        if u.locked_until_utc is not None
        else ""
    )
    if u.user_id != principal.user_id:
        delete = (
            f'<form method="post" action="/users/{esc_attr(u.user_id)}/delete" class="inline">'
            f"{_hidden('csrf_token', csrf)}<button type=\"submit\" class=\"danger\">Delete</button></form>"
        )
    else:
        # Your own row: show the control disabled rather than a blank gap, so the reason is discoverable.
        delete = (
            '<button type="button" class="danger" disabled '
            'title="You cannot delete the account you are signed in as">Delete</button>'
        )
    return f'<div class="row-actions">{update}{unlock}{delete}</div>'


def _user_status(u: UserRow) -> str:
    if u.locked_until_utc is not None:
        return f'{_pill("Locked", "danger")} ({esc(u.failed_attempts)} failed)'
    if u.must_change_password:
        return _pill("Must change password", "warn")
    return '<span class="muted">Active</span>'


def employees_page(
    principal: Principal,
    csrf: str,
    *,
    employee: EmployeeRow | None = None,
    result: GrantResult | None = None,
) -> str:
    """
    Grant or revoke device-administrator rights for an employee found by PIN.

    Three states share one page: no employee loaded (just the lookup form), an employee loaded
    (their current state plus grant/revoke controls), and a completed action (the resulting state
    plus a note of how many devices were queued). No password is ever printed back.
    """
    message = _grant_message(result) if result is not None else ""
    body = _employee_lookup_form(csrf)
    if employee is not None:
        body += _employee_card(employee, csrf)
    return page(
        title="Employees", body=body, principal=principal, active="employees",
        message=message, csrf=csrf,
    )


def _employee_lookup_form(csrf: str) -> str:
    """The PIN lookup form. Server-rendered, no JavaScript; the PIN is the employee's device number."""
    return (
        '<form method="post" action="/employees/lookup" class="card">'
        "<h2>Find an employee</h2>"
        f"{_hidden('csrf_token', csrf)}"
        '<div class="field"><label for="lookup-pin">PIN</label>'
        '<input id="lookup-pin" name="pin" inputmode="numeric" pattern="[0-9]*" required '
        'autocomplete="off">'
        '<p class="hint">The employee\'s device number (NHANVIEN.MaChamCong).</p></div>'
        '<button type="submit" class="primary">Look up</button>'
        "</form>"
    )


def _employee_card(e: EmployeeRow, csrf: str) -> str:
    """Current state of one employee plus the grant/revoke control and an optional password field."""
    admin_pill = (
        _pill("Administrator", "danger") if e.is_admin else '<span class="muted">Standard user</span>'
    )
    facts = _data_table(
        caption=f"Employee {esc(e.pin)}.",
        headers=("PIN", "Name", "Card", "Role", "Enabled"),
        rows=[[
            esc(e.pin),
            esc(e.name) or '<span class="muted">(no name)</span>',
            esc(e.card) or '<span class="muted">—</span>',
            admin_pill,
            esc(_yesno(e.is_enabled)),
        ]],
        empty="",
    )
    if e.is_admin:
        action, label, cls = f"/employees/{esc_attr(e.pin)}/revoke-admin", "Revoke admin", "danger"
    else:
        action, label, cls = f"/employees/{esc_attr(e.pin)}/grant-admin", "Grant admin", "primary"
    control = (
        f'<form method="post" action="{action}" class="card">'
        "<h2>Device administrator rights</h2>"
        f"{_hidden('csrf_token', csrf)}"
        '<div class="field"><label for="grant-pw">Device password (optional)</label>'
        '<input id="grant-pw" name="password" inputmode="numeric" pattern="[0-9]*" '
        'autocomplete="off">'
        '<p class="hint">One to eight digits. Leave blank to keep the current password unchanged.</p>'
        "</div>"
        f'<button type="submit" class="{cls}">{esc(label)}</button>'
        "</form>"
    )
    return f'{facts}{control}'


def _grant_message(r: GrantResult) -> str:
    """Plain-language summary of what the save did, for the page-level success notice."""
    if r.devices_queued == 0:
        push = "no enabled devices to push to"
    elif r.devices_queued == 1:
        push = "queued for 1 device"
    else:
        push = f"queued for {r.devices_queued} devices"
    parts = [f"Saved and {push}"]
    if r.placeholder_created:
        parts.append("a password-only record was created")
    return "; ".join(parts) + "."


def sessions_page(
    sessions: list[dict], principal: Principal, csrf: str, *, offset_hours: int = 7
) -> str:
    """Live sessions, so an admin can end one. The session token itself is never shown."""
    table = _data_table(
        caption=f"Active sessions, times in {esc(_offset_label(offset_hours))}.",
        headers=("User", "IP", "Agent", "Signed in", "Last seen", "Expires", "Actions"),
        rows=[
            (
                f'{esc(s["username"])} <span class="muted">{esc(s["display_name"])}</span>',
                esc(s["ip"]),
                f'<span class="mono">{esc(s["user_agent"])}</span>',
                esc(local_time(s["created_utc"], offset_hours)),
                esc(local_time(s["last_seen_utc"], offset_hours)),
                esc(local_time(s["expires_utc"], offset_hours)),
                (
                    f'<form method="post" action="/sessions/{esc_attr(s["user_id"])}/revoke" class="inline">'
                    f"{_hidden('csrf_token', csrf)}"
                    '<button type="submit" class="danger">End all</button></form>'
                ),
            )
            for s in sessions
        ],
        empty="No active sessions.",
    )
    body = table
    return page(title="Sessions", body=body, principal=principal, active="sessions", csrf=csrf)


def audit_page(entries: list[AuditRow], principal: Principal, *, offset_hours: int = 7) -> str:
    """The append-only audit trail, newest first. Read-only; nothing here is a control."""
    table = _data_table(
        caption=f"Audit trail, newest first, times in {esc(_offset_label(offset_hours))}.",
        headers=("When", "User", "Action", "Target", "Detail", "IP", "Outcome"),
        rows=[
            (
                esc(local_time(e.when_utc, offset_hours)),
                esc(e.username),
                esc(e.action),
                esc(e.target),
                esc(e.detail),
                esc(e.ip),
                _outcome(e.succeeded),
            )
            for e in entries
        ],
        empty="No audit entries.",
    )
    body = table
    return page(title="Audit", body=body, principal=principal, active="audit")


def _outcome(succeeded: bool) -> str:
    return _pill("Success", "ok") if succeeded else _pill("Failed", "danger")


def roster_sync_page(
    statuses: Sequence[RosterSyncRow],
    deletions: Sequence[DeletionEventRow],
    principal: Principal,
    *,
    offset_hours: int = 7,
) -> str:
    """
    multi-device-employee-sync operator view: per-device Backfill status, and the delete
    fan-out audit trail (ISO 27001 traceability -- see adms.db.roster_sync's own module
    docstring for why a deletion's version snapshot, not NHANVIEN's current state, is the
    durable record).

    Read-only, like ``/audit``: this page answers "why doesn't the new reader have everyone
    yet" and "was this deletion actually propagated", not a place to change SyncGroup (that
    stays direct SQL, per Requirement 25.6 -- a console form is out of scope for this feature).
    """
    status_table = _data_table(
        caption=(
            "Enabled, linked devices with a Sync_Group, most behind first. "
            f"Times shown in {esc(_offset_label(offset_hours))}."
        ),
        headers=("Serial", "Name", "Sync group", "Cursor", "Group max", "Versions owed"),
        rows=[
            (
                f'<a href="/devices/{esc_attr(s.serial)}" class="mono">{esc(s.serial)}</a>',
                f'<span class="cell-name">{esc(s.device_name)}</span>',
                esc(s.sync_group),
                esc(s.roster_sync_stamp),
                esc(s.group_max_version),
                _pill(f"{s.pins_owed} owed", "warn") if s.pins_owed > 0 else _pill("current", "ok"),
            )
            for s in statuses
        ],
        empty="No device is currently in a Sync_Group -- Roster_Sync is inert until one is assigned.",
    )
    deletion_table = _data_table(
        caption=(
            "Deletions fanned out, newest first -- a deletion anywhere (the desktop app, an "
            "operator, or a device's own admin menu, where detected) removed here from every "
            f"other device in the same group. Times shown in {esc(_offset_label(offset_hours))}."
        ),
        headers=("When", "PIN", "Sync group", "Version", "Commands enqueued"),
        rows=[
            (
                esc(local_time(d.updated_utc, offset_hours)),
                esc(d.pin),
                esc(d.sync_group),
                esc(d.roster_version),
                esc(d.commands_enqueued),
            )
            for d in deletions
        ],
        empty="No deletion has been fanned out yet.",
    )
    body = (
        "<h2>Backfill status</h2>"
        f"{status_table}"
        "<h2>Delete fan-out audit trail</h2>"
        f"{deletion_table}"
    )
    return page(title="Roster sync", body=body, principal=principal, active="roster-sync")


def _offset_label(offset_hours: int) -> str:
    sign = "+" if offset_hours >= 0 else "-"
    return f"UTC{sign}{abs(offset_hours)}"
