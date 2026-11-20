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
