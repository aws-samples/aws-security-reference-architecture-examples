"""Static check: every partition interpolation in a Terraform string is part of a well-formed ARN prefix (no AWS calls are made).

Each ``${...partition}`` inside a quoted string must read ``arn:${...partition}:``. That catches an ARN without the ``arn:`` prefix, for
example ``"${...partition}:iam::123456789012:root"``, and one missing the colon after the partition, for example ``"arn:${...partition}iam::..."``.
"""

from __future__ import annotations

import re
from pathlib import Path

TERRAFORM = Path(__file__).resolve().parents[2] / "aws_sra_examples/terraform"
QUOTED_STRING = re.compile(r'"([^"\n]*)"')
PARTITION = re.compile(r"\$\{[^}]*partition\}")


def partition_interpolations() -> list[tuple[str, int, str, int, int]]:
    """Return (file, line number, string, start, end) for every partition interpolation that is part of a longer quoted string.

    A string that is only the interpolation (for example the value of an ``AWS_PARTITION`` parameter) is not an ARN and is skipped.
    """
    found = []
    for path in sorted(TERRAFORM.rglob("*.tf")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for string in QUOTED_STRING.findall(line):
                found += [
                    (str(path.relative_to(TERRAFORM)), number, string, m.start(), m.end()) for m in PARTITION.finditer(string) if m.group() != string
                ]
    return found


def is_arn_prefixed(string: str, start: int, end: int) -> bool:
    """Return True when the partition interpolation at string[start:end] reads ``arn:${...partition}:``."""
    return string[:start].endswith("arn:") and string[end:].startswith(":")


def test_partition_interpolations_are_found() -> None:
    assert len(partition_interpolations()) > 100


def test_every_partition_interpolation_is_inside_an_arn_prefix() -> None:
    bad = [f"{path}:{number}: {string}" for path, number, string, start, end in partition_interpolations() if not is_arn_prefixed(string, start, end)]
    assert not bad, "partition interpolations that are not written as 'arn:${...partition}:':\n" + "\n".join(bad)


def test_the_check_catches_a_missing_arn_prefix_and_a_missing_colon() -> None:
    def check(string: str) -> bool:
        return all(is_arn_prefixed(string, m.start(), m.end()) for m in PARTITION.finditer(string))

    assert check("arn:${data.aws_partition.current.partition}:iam::${var.account}:root")
    assert not check("${data.aws_partition.current.partition}:iam::${var.account}:root")
    assert not check("arn:${data.aws_partition.current.partition}iam::${var.account}:root")
