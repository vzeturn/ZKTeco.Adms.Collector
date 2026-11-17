"""
Design-system invariants for the console stylesheet and its shared render helpers.

These guard the properties a re-theme or a careless edit could silently break: a status pill carries a
non-colour cue (the ``.dot``) so its meaning survives greyscale and colour blindness; every ``var(--x)``
the rules reference is actually defined (a token typo is an invisible bug -- the property falls back to
its initial value with no error); the ``:focus-visible`` ring is present and never neutralised; and the
empty-state helper renders one consistent cell for a zero-row table.
"""

from __future__ import annotations

import re

from adms.admin import ui


# ── The status pill carries a shape, not colour alone ───────────────────────────────────────────


def test_state_pill_emits_a_non_colour_dot_and_the_text_label() -> None:
    # The dot is the greyscale-safe cue; the word is the screen-reader/text cue. Both must be present,
    # so meaning never rides on colour alone. Mutation check: delete the ``<span class="dot">`` from
    # ``_pill`` and this assertion goes red.
    html = ui._state_pill("Silent")
    assert '<span class="dot"></span>' in html
    assert "Silent" in html


def test_every_pill_variant_keeps_the_dot() -> None:
    for text, cls in (("Success", "ok"), ("Failed", "danger"), ("Locked", "danger")):
        html = ui._pill(text, cls)
        assert '<span class="dot"></span>' in html, cls
        assert f">{text}</span>" in html, cls


# ── The stylesheet defines every semantic token its rules consume ───────────────────────────────


def test_stylesheet_defines_every_custom_property_it_references() -> None:
    css = ui.STYLESHEET
    referenced = set(re.findall(r"var\((--[a-z0-9-]+)", css))
    defined = set(re.findall(r"(--[a-z0-9-]+)\s*:", css))
    missing = referenced - defined
    assert not missing, f"undefined custom properties referenced: {sorted(missing)}"


def test_stylesheet_declares_the_two_token_tiers() -> None:
    css = ui.STYLESHEET
    # A primitive (raw palette) and a semantic (role) token must both exist, and the semantic one must
    # be defined in terms of the primitive -- proof the two-tier indirection is real, not decorative.
    assert "--gray-0:" in css
    assert "--surface: var(--gray-0)" in css


# ── The focus ring is present and not neutralised ───────────────────────────────────────────────


def test_focus_visible_ring_is_present_and_not_removed() -> None:
    css = ui.STYLESHEET
    block = re.search(r":focus-visible\s*\{([^}]*)\}", css)
    assert block is not None, ":focus-visible rule is missing"
    body = block.group(1)
    assert "outline:" in body
    assert "outline: none" not in body and "outline:none" not in body


# ── Empty state renders one consistent cell ─────────────────────────────────────────────────────


def test_empty_state_spans_the_table_and_shows_the_message() -> None:
    html = ui._empty_state(7, "No devices yet.")
    assert 'colspan="7"' in html
    assert 'class="empty"' in html
    assert "No devices yet." in html


def test_empty_state_escapes_its_message() -> None:
    html = ui._empty_state(3, "<script>x</script>")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# ── The data-table helper names every cell for the mobile card layout ───────────────────────────


def test_data_table_labels_every_cell_with_its_column_header() -> None:
    # On a narrow screen the table reflows to blocks and the header row is hidden; each ``<td>`` reprints
    # its column name from ``data-label`` (a CSS ``::before``). Every cell must carry it, or a value goes
    # nameless on mobile. Mutation check: drop ``data-label`` from ``_data_table`` and this goes red.
    html = ui._data_table(
        caption="Cap.",
        headers=("Serial", "State"),
        rows=[("abc", "<span>ok</span>")],
        empty="None.",
    )
    assert '<td data-label="Serial">abc</td>' in html
    assert '<td data-label="State"><span>ok</span></td>' in html
    assert "<caption>Cap.</caption>" in html
    assert '<th scope="col">Serial</th>' in html


def test_data_table_renders_the_empty_state_when_there_are_no_rows() -> None:
    html = ui._data_table(caption="Cap.", headers=("A", "B", "C"), rows=[], empty="Nothing here.")
    assert 'colspan="3"' in html
    assert "Nothing here." in html


def test_mobile_reflow_reprints_the_column_label_from_data_label() -> None:
    css = ui.STYLESHEET
    # The card layout depends on this exact pairing: the header is hidden and the label comes back via
    # ``content: attr(data-label)``. If either half is edited away, mobile rows lose their field names.
    assert "content: attr(data-label)" in css
    assert re.search(r"thead\s*\{[^}]*position:\s*absolute", css)


# ── Field borders clear the 3:1 non-text contrast bar (WCAG 2.2) ─────────────────────────────────


def test_input_border_uses_the_dedicated_field_border_token() -> None:
    css = ui.STYLESHEET
    # Text inputs must draw their border from ``--field-border`` (a >=3:1 grey), not the decorative
    # ``--border`` / ``--border-strong``. Mutation check: point the input rule back at ``--border-strong``
    # (1.73:1) and this goes red.
    assert "--field-border:" in css
    rule = re.search(r"input:not\(\[type=\"checkbox\"\]\)[^{]*\{([^}]*)\}", css)
    assert rule is not None, "the text-input rule is missing or was renamed"
    assert "var(--field-border)" in rule.group(1)


def test_checkbox_is_excluded_from_the_text_input_geometry() -> None:
    css = ui.STYLESHEET
    # The 24px checkbox must not inherit the text field's full-width / padded / bordered box. The generic
    # rule explicitly excludes it; a dedicated rule sizes it. Both halves are asserted here.
    assert 'input:not([type="checkbox"]):not([type="radio"])' in css
    block = re.search(r'input\[type="checkbox"\]\s*\{([^}]*)\}', css)
    assert block is not None, "the checkbox sizing rule is missing"
    body = block.group(1)
    assert "width: 1.25rem" in body and "height: 1.25rem" in body
