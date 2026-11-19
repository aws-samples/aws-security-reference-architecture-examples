"""Regression test for the lint configuration (#388).

Lints tests/lint/negative_control.py with ruff, flake8 and complexipy, using the
repository's own configuration, and checks that every expected rule code is
still reported. Also checks that every rule family selected in the
configuration has a control, so a newly selected family can't go untested.
"""

import configparser
import json
import re
import shutil
# Runs the repository's own lint tools with fixed arguments.
import subprocess  # nosec B404
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONTROL = Path(__file__).with_name("negative_control.py").relative_to(REPO)

# One code per selected ruff entry (pyproject.toml [tool.ruff.lint] select).
EXPECTED_RUFF = {
    "A001", "ARG001", "B006", "C401", "C901", "COM818", "D103", "D417", "ERA001", "EXE001", "F841", "FIX002",
    "ISC001", "ISC002", "N802", "PT015", "RET504", "RSE102", "S108", "SIM102", "T100", "T201", "TD002",
    "UP031", "UP032", "YTT101",
    *(f"PTH{n}" for n in range(100, 125)),
}
# One code per selected flake8 family (.flake8 select).
EXPECTED_FLAKE8 = {"CFQ002", "DUO104", "E225", "ECE001", "TAE002", "W291"}
# complexipy must fail this function at the configured max-complexity-allowed.
COMPLEXIPY_FUNCTION = "deep_nesting"


def _tool(name: str) -> str:
    """Return the path of a lint tool installed next to the running interpreter."""
    candidate = Path(sys.executable).parent / name
    found = str(candidate) if candidate.exists() else shutil.which(name)
    assert found, f"{name} is not installed in this environment"
    return found


def _run(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([_tool(name), *args], cwd=REPO, capture_output=True, text=True, check=False)


def _covers(selector: str, codes: set[str]) -> bool:
    """True if a code belongs to the selector: the exact code, or the prefix followed by a digit."""
    return any(code == selector or re.fullmatch(rf"{re.escape(selector)}\d+", code) for code in codes)


def test_ruff_reports_every_expected_code() -> None:
    result = _run("ruff", "check", "--no-cache", "--output-format", "json", "--exit-zero", str(CONTROL))
    assert result.returncode == 0, result.stderr
    reported = {item["code"] for item in json.loads(result.stdout)}
    missing = sorted(EXPECTED_RUFF - reported)
    assert not missing, f"ruff no longer reports: {missing}"


def test_every_selected_ruff_family_has_a_control() -> None:
    select = tomllib.loads((REPO / "pyproject.toml").read_text())["tool"]["ruff"]["lint"]["select"]
    uncovered = [selector for selector in select if not _covers(selector, EXPECTED_RUFF)]
    assert not uncovered, f"selected in pyproject.toml but no control in {CONTROL}: {uncovered}"


def test_flake8_reports_every_expected_code() -> None:
    result = _run("flake8", "--format=%(code)s", "--exit-zero", str(CONTROL))
    assert result.returncode == 0, result.stderr
    reported = set(result.stdout.split())
    missing = sorted(EXPECTED_FLAKE8 - reported)
    assert not missing, f"flake8 no longer reports: {missing}"


def test_every_selected_flake8_family_has_a_control() -> None:
    config = configparser.ConfigParser()
    config.read(REPO / ".flake8")
    select = [item.strip() for item in config["flake8"]["select"].split(",") if item.strip()]
    uncovered = [selector for selector in select if not _covers(selector, EXPECTED_FLAKE8)]
    assert not uncovered, f"selected in .flake8 but no control in {CONTROL}: {uncovered}"


def test_complexipy_fails_the_complex_function() -> None:
    result = _run("complexipy", str(CONTROL), "--failed")
    assert result.returncode != 0, f"complexipy passed {CONTROL}:\n{result.stdout}"
    assert COMPLEXIPY_FUNCTION in result.stdout, result.stdout
