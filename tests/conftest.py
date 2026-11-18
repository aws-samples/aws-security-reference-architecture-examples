"""Test configuration for the ``guardduty_org`` solution."""

import os
import sys
from pathlib import Path

SOLUTION_LAMBDA_SRC = Path(__file__).resolve().parents[1] / "aws_sra_examples" / "solutions" / "guardduty" / "guardduty_org" / "lambda" / "src"

sys.path.insert(0, str(SOLUTION_LAMBDA_SRC))

# ``guardduty.py`` builds boto3 clients while importing, so give it inert values.
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
