#!/bin/sh
"""Lint negative control: one deliberate violation for each selected rule family.

tests/lint/test_lint_negative_control.py lints this file with ruff, flake8 and
complexipy, using the repository configuration, and fails if any expected code
is missing. That catches configuration or tool changes that silently stop a
rule family from reporting.

This file is never imported or run. CI lints only aws_sra_examples/, so the
normal lint runs don't see it.

To add a rule family: add it to the configuration, add a violation here with the
code in a trailing comment, and add the code to EXPECTED_* in the test.
"""
# EXE003 comes from the non-Python shebang above (independent of platform and file mode).

import os
import re
import sys
from typing import Dict, List, Tuple

import py


def NotSnakeCase(unused_arg, items=[]):  # N802, ARG001, B006
    """Doc."""
    return items


def undocumented():  # D103
    return 1


def missing_arg_doc(a: int, b: int) -> int:  # D417
    """Add numbers.

    Args:
        a: first number

    Returns:
        The sum.
    """
    return a + b


def misc_rules(value: int, path: str) -> object:
    """Collection of single-line violations."""
    list = [1]  # A001
    squares = set(x for x in range(3))  # C401
    assert False  # PT015
    if value:
        if path:  # SIM102
            pass
    joined = "a" "b"  # ISC001
    multiline = "a" \
        "b"  # ISC002
    tmp = "/tmp/negative-control"  # S108
    breakpoint()  # T100
    print(squares, joined, multiline, tmp)  # T201
    # print("commented out code")  # ERA001
    # TODO: tidy this up  # TD002, FIX002
    formatted = "%s" % value  # UP031
    fstring = "{}".format(value)  # UP032
    short_version = sys.version[:3]  # YTT101
    bare_tuple = 1,  # COM818
    unused = 1  # F841
    re.compile("(a+)+$")  # DUO138
    if value < 0:
        raise ValueError()  # RSE102
    result = formatted + fstring + short_version + str(bare_tuple)
    return result  # RET504


def pathlib_rules(p: str, q: str) -> None:
    """One os.path / os call per selected PTH rule."""
    os.path.abspath(p)  # PTH100
    os.chmod(p, 0o644)  # PTH101
    os.mkdir(p)  # PTH102
    os.makedirs(p)  # PTH103
    os.rename(p, q)  # PTH104
    os.replace(p, q)  # PTH105
    os.rmdir(p)  # PTH106
    os.remove(p)  # PTH107
    os.unlink(p)  # PTH108
    os.getcwd()  # PTH109
    os.path.exists(p)  # PTH110
    os.path.expanduser(p)  # PTH111
    os.path.isdir(p)  # PTH112
    os.path.isfile(p)  # PTH113
    os.path.islink(p)  # PTH114
    os.readlink(p)  # PTH115
    os.stat(p)  # PTH116
    os.path.isabs(p)  # PTH117
    os.path.join(p, q)  # PTH118
    os.path.basename(p)  # PTH119
    os.path.dirname(p)  # PTH120
    os.path.samefile(p, q)  # PTH121
    os.path.splitext(p)  # PTH122
    open(p).close()  # PTH123
    py.path.local(p)  # PTH124


def flake8_rules(a, b, c, d, e, f, g, h, i):  # CFQ002 (more than max-parameters-amount = 8)
    """flake8-only families."""
    x=a  # E225
    pattern = (a +
               b)  # W504
    total = (a + b) * (c - d) / (e + f) - (g * h) + (i % a) - (b // c) + (d ** e)  # ECE001
    return x, pattern, total


def annotation_rule(value: Dict[str, List[Dict[str, Tuple[int, ...]]]]) -> None:  # TAE002
    """flake8-annotations-complexity."""
    return None


def deep_nesting(a: int, b: int, c: int, d: int) -> int:  # C901 (ruff), complexipy
    """Cognitive and cyclomatic complexity above the configured limit of 15."""
    total = 0
    for i in range(a):
        if i % 2:
            for j in range(b):
                if j % 3:
                    while c:
                        if d and i or j and c:
                            total += 1
                        elif d > 2:
                            total += 2
                        elif d > 3:
                            total += 3
                        else:
                            total -= 1
                        c -= 1
                elif j > 5 and i < 3 or d:
                    total += 4
        elif i > 7:
            try:
                total += i // d
            except ZeroDivisionError:
                total = 0
            if total > 100:
                break
        elif i > 8 or a > b:
            total += 5
        elif i > 9 and c:
            total += 6
        elif i > 10:
            total += 7
    return total
