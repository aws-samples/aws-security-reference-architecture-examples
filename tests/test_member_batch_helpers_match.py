"""The member-batch helper is copied into each Lambda (they are packaged separately); keep the copies identical."""

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MODULES = [
    "aws_sra_examples/solutions/guardduty/guardduty_org/lambda/src/guardduty.py",
    "aws_sra_examples/solutions/detective/detective_org/lambda/src/detective.py",
    "aws_sra_examples/solutions/securityhub/securityhub_org/lambda/src/securityhub.py",
]


def helper_source(path: str) -> str:
    text = (REPO / path).read_text()
    start = text.index("def process_in_batches(")
    end = text.index("    LOGGER.warning(message)\n", start)
    return text[start:end]


def test_member_batch_helpers_are_identical() -> None:
    first, *others = (helper_source(path) for path in MODULES)
    assert all(other == first for other in others), "process_in_batches/process_batch differ between solutions"
