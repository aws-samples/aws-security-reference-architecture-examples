"""Minimal helpers to read top-level Terraform blocks and `aws_iam_policy_document` statements in tests.

Shared by the static tests that check Terraform IAM policies, next to `cfn_yaml.py` for CloudFormation. They match the layout
produced by `terraform fmt` (top-level blocks end with `}` in column 0, statements are indented two spaces). No AWS calls are made.
"""

from __future__ import annotations

import re
from pathlib import Path


def block(path: Path, header: str) -> str:
    """Return the body of the top-level block whose header matches the regular expression, e.g. `resource "aws_sqs_queue" "dlq"`."""
    match = re.search(header + r" \{\n(.*?)\n\}\n", path.read_text(), re.S)
    assert match, f"{header} not found in {path.name}"
    return match.group(1)


def policy_documents(path: Path, name_pattern: str = r"\w*") -> list:
    """Return the body of every `data "aws_iam_policy_document"` block whose name matches the regular expression."""
    documents = re.findall(rf'data "aws_iam_policy_document" "{name_pattern}" \{{\n(.*?)\n\}}\n', path.read_text(), re.S)
    assert documents, f"no aws_iam_policy_document matching {name_pattern!r} in {path.name}"
    return documents


def statements(document: str) -> list:
    """Return the text of each `statement { ... }` block of a policy document body."""
    return re.findall(r"statement \{(.*?)\n  \}", document, re.S)


def list_values(text: str, key: str) -> list:
    """Return the quoted strings of `key = [ ... ]` in a block (comments are ignored), or [] when the key is absent."""
    match = re.search(rf"\b{key}\s*=\s*\[(.*?)\]", text, re.S)
    return re.findall(r'"([^"]*)"', re.sub(r"#.*", "", match.group(1))) if match else []


def _collapse(expression: str) -> str:
    """Collapse whitespace in a list expression, so `[\n  "a",\n]` and `["a"]` compare equal."""
    collapsed = re.sub(r"\s+", " ", expression)
    return re.sub(r",?\s*\]$", "]", re.sub(r"^\[\s*", "[", collapsed))


def conditions(statement: str) -> list:
    """Return each `condition { ... }` block of a statement as a dict of `test`, `variable` and `values`.

    Comments are removed first. `values` is the expression text with whitespace collapsed (for example
    `["a.amazonaws.com"]` or `local.names`), so a test can assert the exact value. A `dynamic "condition"` block fails the call.
    """
    text = re.sub(r"#.*", "", statement)
    assert 'dynamic "condition"' not in text, "dynamic condition blocks are not supported by this helper"
    found = []
    for body in re.findall(r"\bcondition\s*\{(.*?)\n\s*\}", text, re.S):
        fields = {}
        for key in ("test", "variable"):
            match = re.search(rf'\b{key}\s*=\s*"([^"]*)"', body)
            fields[key] = match.group(1) if match else ""
        match = re.search(r"\bvalues\s*=\s*(\[.*?\]|\S+)", body, re.S)
        fields["values"] = _collapse(match.group(1)) if match else ""
        found.append(fields)
    return found
