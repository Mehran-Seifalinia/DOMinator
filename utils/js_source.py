"""JavaScript source helpers for the static analysis.

The patterns are regular expressions over source text, so a sink that is only
mentioned in a comment, a string literal or a data block is reported as if it
were live code. Masking removes those regions before matching.
"""


def mask_javascript(source: str) -> str:
    """Blank out comments and string literals, keeping every offset intact.

    Masked characters become spaces and newlines are preserved, so match
    positions, line numbers and the original text used as context all stay
    valid. The caller keeps the unmasked source for its reports.

    Regex literals are not recognised: a division or a pattern containing a
    slash can still confuse the scanner, which is why the result is only used
    to suppress matches, never to prove one.
    """
    characters = list(source)
    length = len(source)

    def blank(position: int) -> None:
        if source[position] != "\n":
            characters[position] = " "

    index = 0
    while index < length:
        character = source[index]
        following = source[index + 1] if index + 1 < length else ""

        if character == "/" and following == "/":
            while index < length and source[index] != "\n":
                blank(index)
                index += 1
            continue

        if character == "/" and following == "*":
            blank(index)
            blank(index + 1)
            index += 2
            while index < length and not (
                source[index] == "*" and index + 1 < length and source[index + 1] == "/"
            ):
                blank(index)
                index += 1
            for _ in range(2):
                if index < length:
                    blank(index)
                    index += 1
            continue

        if character in "\"'`":
            quote = character
            blank(index)
            index += 1
            while index < length:
                if source[index] == "\\":
                    blank(index)
                    if index + 1 < length:
                        blank(index + 1)
                    index += 2
                    continue
                if source[index] == quote:
                    blank(index)
                    index += 1
                    break
                blank(index)
                index += 1
            continue

        index += 1

    return "".join(characters)
