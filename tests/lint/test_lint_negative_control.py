"""Regression test for the lint configuration (#388).

Lints tests/lint/negative_control.py with ruff, flake8 and complexipy, using the
repository's own configuration, and checks that every expected rule code is
still reported. Also checks that every rule family selected in the
configuration has a control, so a newly selected family can't go untested.

The control file only sees settings that apply to it, so settings scoped to
other paths (excludes, per-file ignores) and the complexipy table are pinned:
changing them fails test_path_scoped_lint_settings_are_pinned until PINNED_* is
updated, so the change is reviewed rather than silent.
"""

import configparser
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONTROL = Path(__file__).with_name("negative_control.py").relative_to(REPO)

# One code per selected ruff entry (pyproject.toml [tool.ruff.lint] select).
EXPECTED_RUFF = {
    "A001",
    "ARG001",
    "B006",
    "C401",
    "C901",
    "COM818",
    "D103",
    "D417",
    "ERA001",
    "EXE003",
    "F841",
    "FIX002",
    "ISC001",
    "ISC002",
    "N802",
    "PT015",
    "RET504",
    "RSE102",
    "S108",
    "SIM102",
    "T100",
    "T201",
    "TD002",
    "UP031",
    "UP032",
    "YTT101",
    *(f"PTH{n}" for n in range(100, 125)),
}
# One code per selected flake8 family (.flake8 select).
EXPECTED_FLAKE8 = {"CFQ002", "DUO138", "E225", "ECE001", "TAE002", "W504"}
# complexipy must fail this function at the configured max-complexity-allowed.
COMPLEXIPY_FUNCTION = "deep_nesting"

# Settings that can disable rules for aws_sra_examples/ without affecting the
# control file. Absent keys are pinned as None. Update these only after checking
# that the change doesn't silence a rule family for the solutions code.
RUFF_PATH_SCOPED_KEYS = ("exclude", "extend-exclude", "per-file-ignores", "extend-per-file-ignores", "extend-select", "extend-ignore")
PINNED_RUFF = {
    "tool.ruff": dict.fromkeys(RUFF_PATH_SCOPED_KEYS),
    "tool.ruff.lint": {
        **dict.fromkeys(RUFF_PATH_SCOPED_KEYS),
        "per-file-ignores": {"**/inline_lambda.py": ["D100", "D103"]},
    },
}
FLAKE8_PATH_SCOPED_KEYS = ("exclude", "extend-exclude", "per-file-ignores", "extend-select", "extend-ignore")
PINNED_FLAKE8 = {**dict.fromkeys(FLAKE8_PATH_SCOPED_KEYS), "exclude": [".git", "__pycache__", ".vscode"]}
PINNED_COMPLEXIPY = {"max-complexity-allowed": 15}


def _tool(name: str) -> str:
    """Return the path of a lint tool installed next to the running interpreter."""
    candidate = Path(sys.executable).parent / name
    found = str(candidate) if candidate.exists() else shutil.which(name)
    assert found, f"{name} is not installed in this environment"
    return found


def _run(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([_tool(name), *args], cwd=REPO, capture_output=True, text=True, check=False)


def _covers(selector: str, codes: set[str]) -> bool:
    """Return True if a code belongs to the selector: the exact code, or the prefix followed by a digit."""
    return any(code == selector or re.fullmatch(rf"{re.escape(selector)}\d+", code) for code in codes)


def test_ruff_reports_every_expected_code() -> None:
    result = _run("ruff", "check", "--no-cache", "--output-format", "json", "--exit-zero", str(CONTROL))
    assert result.returncode == 0, result.stderr
    reported = {item["code"] for item in json.loads(result.stdout)}
    missing = sorted(EXPECTED_RUFF - reported)
    assert not missing, f"ruff no longer reports: {missing}"


def _pyproject() -> dict:
    return tomllib.loads((REPO / "pyproject.toml").read_text())


def _flake8_config() -> configparser.SectionProxy:
    config = configparser.ConfigParser()
    config.read(REPO / ".flake8")
    return config["flake8"]


def _flake8_list(value: str | None) -> list[str] | None:
    return None if value is None else [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]


def test_every_selected_ruff_family_has_a_control() -> None:
    lint = _pyproject()["tool"]["ruff"]["lint"]
    select = [*lint["select"], *lint.get("extend-select", [])]
    uncovered = [selector for selector in select if not _covers(selector, EXPECTED_RUFF)]
    assert not uncovered, f"selected in pyproject.toml but no control in {CONTROL}: {uncovered}"


def test_flake8_reports_every_expected_code() -> None:
    result = _run("flake8", "--format=%(code)s", "--exit-zero", str(CONTROL))
    assert result.returncode == 0, result.stderr
    reported = set(result.stdout.split())
    missing = sorted(EXPECTED_FLAKE8 - reported)
    assert not missing, f"flake8 no longer reports: {missing}"


def test_every_selected_flake8_family_has_a_control() -> None:
    flake8 = _flake8_config()
    select = [*(_flake8_list(flake8.get("select")) or []), *(_flake8_list(flake8.get("extend-select")) or [])]
    uncovered = [selector for selector in select if not _covers(selector, EXPECTED_FLAKE8)]
    assert not uncovered, f"selected in .flake8 but no control in {CONTROL}: {uncovered}"


def test_complexipy_fails_the_complex_function() -> None:
    result = _run("complexipy", str(CONTROL), "--failed")
    assert result.returncode != 0, f"complexipy passed {CONTROL}:\n{result.stdout}"
    assert COMPLEXIPY_FUNCTION in result.stdout, result.stdout


def test_path_scoped_lint_settings_are_pinned() -> None:
    pyproject = _pyproject()
    ruff = {
        "tool.ruff": {key: pyproject["tool"]["ruff"].get(key) for key in RUFF_PATH_SCOPED_KEYS},
        "tool.ruff.lint": {key: pyproject["tool"]["ruff"]["lint"].get(key) for key in RUFF_PATH_SCOPED_KEYS},
    }
    flake8 = {key: _flake8_list(_flake8_config().get(key)) for key in FLAKE8_PATH_SCOPED_KEYS}
    complexipy = pyproject["tool"].get("complexipy")
    changed = {
        name: {"pinned": pinned, "actual": actual}
        for name, pinned, actual in (("ruff", PINNED_RUFF, ruff), ("flake8", PINNED_FLAKE8, flake8), ("complexipy", PINNED_COMPLEXIPY, complexipy))
        if pinned != actual
    }
    assert not changed, f"path-scoped lint settings changed; review them, then update PINNED_* in {Path(__file__).name}: {changed}"
