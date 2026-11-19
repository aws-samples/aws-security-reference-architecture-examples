"""Minimal block-style YAML helpers for static checks on CloudFormation templates.

No YAML parser is in the locked dependencies, and CloudFormation's short-form tags (!Sub, !Ref) need a custom
loader anyway, so the template checks read the text by indentation.
"""

from __future__ import annotations


def indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def child_block(lines: list, index: int) -> list:
    """Return the lines nested under lines[index], that is, the following lines indented further than it."""
    parent = indent(lines[index])
    block = []
    for line in lines[index + 1 :]:
        if line.strip() and indent(line) <= parent:
            break
        block.append(line)
    return block


def statements(lines: list) -> list:
    """Split every `Statement:` list into its items, whether or not an item has a Sid."""
    items: list = []
    for index, line in enumerate(lines):
        if line.strip() != "Statement:":
            continue
        block = child_block(lines, index)
        item_indent = min(indent(item) for item in block if item.lstrip().startswith("- "))
        for item in block:
            if item.strip() and indent(item) == item_indent and item.lstrip().startswith("- "):
                items.append([item])
            elif items and item.strip():
                items[-1].append(item)
    return items
