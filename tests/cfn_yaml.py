"""Minimal block-style YAML helpers for static checks on CloudFormation templates.

No YAML parser is in the locked dependencies, and CloudFormation's short-form tags (!Sub, !Ref) need a custom
loader anyway, so the template checks read the text by indentation.
"""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from pathlib import Path


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


def file_block(path: Path, header: str) -> list:
    """Return the lines nested under `header`, an exact line of the file such as '  rConfigurationRole:'."""
    lines = path.read_text().splitlines()
    return child_block(lines, lines.index(header))


def template_parameters(path: Path) -> dict:
    """Map each parameter name in the template's Parameters section to the lines of its definition."""
    lines = path.read_text().splitlines()
    section = child_block(lines, lines.index("Parameters:"))
    return {line.strip()[:-1]: child_block(section, index) for index, line in enumerate(section) if line.startswith("  p") and line.endswith(":")}


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


def values(statement: list, key: str) -> list:
    """Return the scalar or list values of `key` in a statement, without quotes or trailing comments.

    A value written with a short-form tag (for example !Sub) is returned as written, quotes included.
    """
    for index, line in enumerate(statement):
        match = re.match(rf"^\s*(?:- )?{re.escape(key)}:\s*(.*?)\s*$", line)
        if not match:
            continue
        inline = re.sub(r"\s+#.*$", "", match.group(1))
        found = [inline] if inline else [item.strip().removeprefix("- ") for item in child_block(statement, index) if item.strip()]
        found = [re.sub(r"\s+#.*$", "", value) for value in found]
        return [value if value.startswith("!") else value.strip("'\"") for value in found]
    return []


def condition(statement: list) -> list:
    """The statement's Condition block, one stripped line per operator or key, so a test can assert the whole condition."""
    for index, line in enumerate(statement):
        if line.strip() == "Condition:":
            return [item.strip() for item in child_block(statement, index) if item.strip()]
    return []


def string_equals(statement: list, key: str) -> list | None:
    """Values of `key` in the statement's StringEquals condition, or None if the statement has no such key there."""
    for index, line in enumerate(statement):
        if line.strip() != "Condition:":
            continue
        condition = child_block(statement, index)
        for operator_index, operator in enumerate(condition):
            if operator.strip() != "StringEquals:":
                continue
            keys = child_block(condition, operator_index)
            if any(re.match(rf"^\s*{re.escape(key)}:", item) for item in keys):
                return values(keys, key)
    return None


def allows(patterns: list, action: str) -> bool:
    """Return True if any IAM action pattern (case-insensitive, `*` and `?` wildcards) matches the action."""
    return any(fnmatchcase(action.lower(), pattern.lower()) for pattern in patterns)
