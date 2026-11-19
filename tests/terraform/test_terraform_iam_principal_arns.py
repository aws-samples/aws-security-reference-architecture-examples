"""Static check: every IAM principal or resource ARN built in the Terraform modules starts with "arn:" (no AWS calls are made)."""

from __future__ import annotations

import re
from pathlib import Path

TERRAFORM = Path(__file__).resolve().parents[2] / "aws_sra_examples/terraform"
# A quoted string containing ":iam::" (an IAM ARN), e.g. "arn:${...partition}:iam::${var.account}:root".
IAM_ARN_STRING = re.compile(r'"([^"\n]*:iam::[^"\n]*)"')


def iam_arn_strings() -> list[tuple[str, int, str]]:
    found = []
    for path in sorted(TERRAFORM.rglob("*.tf")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            found += [(str(path.relative_to(TERRAFORM)), number, value) for value in IAM_ARN_STRING.findall(line)]
    return found


def test_iam_arn_strings_are_found() -> None:
    assert len(iam_arn_strings()) > 20


def test_every_iam_arn_starts_with_arn_prefix() -> None:
    bad = [f"{path}:{number}: {value}" for path, number, value in iam_arn_strings() if not value.startswith("arn:")]
    assert not bad, "IAM ARNs without the 'arn:' prefix:\n" + "\n".join(bad)
