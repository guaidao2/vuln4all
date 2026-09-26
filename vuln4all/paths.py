"""定位 vuln4all 的家目录 —— 也就是 modules/ 和 workspace/ 所在的地方。

查找顺序：
1. 环境变量 VULN4ALL_HOME
2. 从当前目录逐级往上找，第一个同时含 modules/ 和 vuln4all/ 的目录
3. 兜底：当前目录
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_HOME = "VULN4ALL_HOME"


def find_home(start: "Path | None" = None) -> Path:
    env = os.environ.get(ENV_HOME)
    if env:
        return Path(env).expanduser().resolve()

    cur = Path(start or Path.cwd()).resolve()
    for cand in (cur, *cur.parents):
        if (cand / "modules").is_dir() and (cand / "vuln4all").is_dir():
            return cand
    return cur


def modules_dir(home: Path) -> Path:
    return Path(home) / "modules"


def workspace_dir(home: Path) -> Path:
    return Path(home) / "workspace"
