"""Tests for the JavaScript masking used by the static analyzer."""

from utils.js_source import mask_javascript


def test_masks_a_line_comment() -> None:
    masked = mask_javascript("var a = 1; // eval(x)\nvar b = 2;")
    assert "eval" not in masked
    assert "var a = 1;" in masked
    assert "var b = 2;" in masked


def test_masks_a_block_comment_and_keeps_newlines() -> None:
    source = "/*\ndocument.write(x);\n*/\nrun();"
    masked = mask_javascript(source)
    assert "document.write" not in masked
    assert masked.count("\n") == source.count("\n")
    assert "run();" in masked


def test_masks_string_literals() -> None:
    masked = mask_javascript("var note = 'javascript:alert(1)'; use(note);")
    assert "javascript" not in masked
    assert "var note =" in masked
    assert "use(note);" in masked


def test_keeps_every_offset() -> None:
    source = "eval(x) // eval(y)"
    masked = mask_javascript(source)
    assert len(masked) == len(source)
    assert masked.index("eval") == source.index("eval")


def test_keeps_live_code_alive() -> None:
    masked = mask_javascript("el.innerHTML = location.hash;")
    assert "innerHTML" in masked
    assert "location.hash" in masked


def test_handles_an_escaped_quote() -> None:
    masked = mask_javascript("var s = 'a\\'b'; eval(s);")
    assert "eval(s)" in masked
    assert "a\\'b" not in masked
