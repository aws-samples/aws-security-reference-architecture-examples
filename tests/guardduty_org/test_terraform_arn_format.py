"""Static check: IAM ARNs in the GuardDuty Terraform modules have no empty path segment ("//")."""

from __future__ import annotations

import re
from pathlib import Path

TF_DIR = Path(__file__).resolve().parents[2] / "aws_sra_examples/terraform/solutions/guard_duty"


def test_iam_arns_have_no_double_slash() -> None:
    files = sorted(TF_DIR.glob("*/main.tf"))
    assert files, "no Terraform modules found"
    for file in files:
        for number, line in enumerate(file.read_text().splitlines(), 1):
            assert not re.search(
                r"arn:[^\"\s]*:(iam|kms|s3|sns|sqs|lambda|guardduty|organizations)[^\"\s]*//", line
            ), f"{file.name}:{number} has '//' in an ARN: {line.strip()}"
