#!/usr/bin/env python3

# License: MIT License
# Original Code: github.com/nschloe/termtables
# Modified during porting of sipvicious from py2 to py3

import re
from collections.abc import Sequence

style = '-|++++++++++=++'


def _create_padding_tuple(padding):
    # self._padding is a 4-tuple: top, right, bottom, left (just like CSS)
    if isinstance(padding, int):
        out = (padding, padding, padding, padding)
    else:
        if len(padding) == 1:
            out = (padding[0], padding[0], padding[0], padding[0])
        elif len(padding) == 2:
            out = (padding[0], padding[1], padding[0], padding[1])
        elif len(padding) == 3:
            out = (padding[0], padding[1], padding[2], padding[1])
        else:
            assert len(padding) == 4
            out = (padding[0], padding[1], padding[2], padding[3])
    return out


def _create_alignment(alignment, num_columns):
    if len(alignment) == 1:
        alignment = num_columns * alignment
    assert len(alignment) == num_columns
    return alignment


def _remove_escape_sequences(string):
    # https://stackoverflow.com/a/14693789/353337
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", string)


def _get_column_widths(strings, num_columns):
    widths = num_columns * [0]
    for block in strings:
        for row in block:
            for j, item in enumerate(row):
                widths[j] = max(widths[j], len(_remove_escape_sequences(item)))
    return widths


def _align(strings, alignments, column_widths):
    for block in strings:
        for row in block:
            for k, (item, align, cw) in enumerate(zip(row, alignments, column_widths)):
                rest = cw - len(_remove_escape_sequences(item))
                if rest == 0:
                    # row[k] = item[:cw]
                    row[k] = item
                else:
                    assert rest > 0
                    if align == "l":
                        left = 0
                    elif align == "r":
                        left = rest
                    else:
                        assert align == "c"
                        left = rest // 2
                    right = rest - left
                    row[k] = " " * left + item + " " * right
    return strings


def _add_padding(strings, column_widths, padding):
    for block in strings:
        for row in block:
            for k, (item, cw) in enumerate(zip(row, column_widths)):
                cw += padding[1] + padding[3]
                s = []
                for _ in range(padding[0]):
                    s += [" " * cw]
                s += [" " * padding[3] + item + " " * padding[1]]
                for _ in range(padding[2]):
                    s += [" " * cw]
                row[k] = "\n".join(s)
    return strings


def _seq_but_not_str(obj):
    return isinstance(obj, Sequence) and not isinstance(obj, (str, bytes, bytearray))


def _get_depth(l):
    if _seq_but_not_str(l):
        return 1 + max(_get_depth(item) for item in l)
    return 0


def _hjoin_multiline(join_char, strings):
    """Horizontal join of multiline strings
    """
    cstrings = [string.split("\n") for string in strings]
    max_num_lines = max(len(item) for item in cstrings)
    pp = []
    for k in range(max_num_lines):
        p = [cstring[k] for cstring in cstrings]
        pp.append(join_char + join_char.join(p) + join_char)

    return "\n".join([p.rstrip() for p in pp])


def to_string(
    data, header=None, alignment="l", padding=(0, 1), style=style
):
    if len(data) == 0:
        return "no results"
    try:
        depth = len(data.shape)
    except AttributeError:
        depth = _get_depth(data)

    if depth == 2:
        data = [data]
    else:
        assert depth == 3

    if header:
        data = [[header]] + data

    # Make sure the data is consistent
    num_columns = len(data[0][0])
    for block in data:
        for row in block:
            assert len(row) == num_columns

    padding = _create_padding_tuple(padding)
    alignments = _create_alignment(alignment, num_columns)
    if style is None:
        border_chars, block_sep_chars = None, None
    else:
        if len(style) == 11:
            border_chars = style
            block_sep_chars = [
                border_chars[6],
                border_chars[0],
                border_chars[10],
                border_chars[7],
            ]
        else:
            assert len(style) == 15
            border_chars = style[:11]
            block_sep_chars = style[11:]

    strings = [[[str(item) for item in row] for row in block] for block in data]

    column_widths = _get_column_widths(strings, num_columns)
    column_widths_with_padding = [c + padding[1] + padding[3] for c in column_widths]

    # add spaces according to alignment
    strings = _align(strings, alignments, column_widths)

    # add spaces according to padding
    strings = _add_padding(strings, column_widths, padding)

    # Join `strings` from the innermost to the outermost index.
    join_char = border_chars[1] if border_chars else ""
    for block in strings:
        for k, row in enumerate(block):
            block[k] = _hjoin_multiline(join_char, row)

    if border_chars:
        bc = border_chars
        cwp = column_widths_with_padding
        intermediate_border_row = (
            "\n" + bc[6] + bc[10].join([s * bc[0] for s in cwp]) + bc[7] + "\n"
        )
    else:
        intermediate_border_row = "\n"

    for k, block in enumerate(strings):
        strings[k] = intermediate_border_row.join(block)

    if block_sep_chars:
        bs = block_sep_chars
        block_sep_row = (
            "\n" + bs[0] + bs[2].join([s * bs[1] for s in cwp]) + bs[3] + "\n"
        )
    else:
        block_sep_row = "\n"

    strings = block_sep_row.join(strings)

    if border_chars:
        bc = border_chars
        first_border_row = bc[2] + bc[8].join([s * bc[0] for s in cwp]) + bc[3] + "\n"
        last_border_row = "\n" + bc[4] + bc[9].join([s * bc[0] for s in cwp]) + bc[5]
    else:
        first_border_row = ""
        last_border_row = ""
    out = first_border_row + strings + last_border_row

    return out
