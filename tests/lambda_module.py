"""Load an SRA Lambda module for unit tests without leaking it into other tests.

Each solution's Lambda source directory has its own sibling modules with common names
(`app`, `common`). Loading one by putting its directory on sys.path would let the next
test's `import common` pick up the wrong solution's module, so this loads the module
under a unique name and restores sys.modules and sys.path afterwards. AWS credentials and
profiles are replaced with inert values while the module runs its import-time code.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
FAKE_AWS_ENV = {"AWS_DEFAULT_REGION": "us-east-1", "AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SESSION_TOKEN": "testing"}


def load_lambda_module(solution_src: str, module_name: str, unique_name: str) -> ModuleType:
    """Import `<solution_src>/<module_name>.py` as `unique_name`, isolated from other solutions' modules.

    Args:
        solution_src: Lambda source directory, relative to the repository root
        module_name: module file name without `.py`
        unique_name: name to register the module under

    Returns:
        The loaded module.
    """
    src_dir = REPO / solution_src
    siblings = {path.stem for path in src_dir.glob("*.py")}
    saved_modules = {name: sys.modules.pop(name) for name in list(sys.modules) if name in siblings}
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")} | FAKE_AWS_ENV
    sys.path.insert(0, str(src_dir))
    try:
        with mock.patch.dict(os.environ, env, clear=True):
            spec = importlib.util.spec_from_file_location(unique_name, src_dir / f"{module_name}.py")
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(src_dir))
        for name in siblings:
            sys.modules.pop(name, None)
        sys.modules.update(saved_modules)
    return module
