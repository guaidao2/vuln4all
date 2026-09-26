"""把一个模块目录 import 进来，并且保证它炸了也不会拖垮整个靶场。"""

from __future__ import annotations

import importlib.util
import hashlib
import re
import sys
from pathlib import Path

from .contract import Vuln, validate_info

#: 模块入口文件名。每个题目目录下必须有一个。
ENTRY_FILE = "module.py"


def module_name_for(module_id: str) -> str:
    """给模块起一个**保证唯一**的 Python 模块名。

    光把 / 和 - 换成 _ 是不够的：sqli/login-bypass 和 sqli/login_bypass 会得到
    同一个名字，后加载的把先加载的从 sys.modules 里顶掉，而且一声不响。
    所以尾巴上挂一段 id 的哈希 —— 可读的部分留着好看，唯一性由哈希保证。
    """
    readable = re.sub(r"[^0-9A-Za-z]+", "_", module_id).strip("_") or "module"
    digest = hashlib.sha1(module_id.encode("utf-8")).hexdigest()[:8]
    return "v4a_mod_%s_%s" % (readable, digest)


def load_vuln_class(directory: Path, module_id: str) -> tuple:
    """导入 <directory>/module.py，返回 (类和实例, None) 或 (None, 错误信息)。

    目录会被当成一个包来加载，所以模块里可以写 `from . import helpers`，
    也可以有兄弟 .py 文件，不会和别的模块撞名。
    """
    directory = Path(directory)
    source = directory / ENTRY_FILE
    if not source.is_file():
        return None, "找不到入口文件 %s" % ENTRY_FILE

    name = module_name_for(module_id)
    spec = importlib.util.spec_from_file_location(
        name,
        str(source),
        submodule_search_locations=[str(directory)],
    )
    if spec is None or spec.loader is None:
        return None, "无法为 %s 建立 import spec" % source

    module = importlib.util.module_from_spec(spec)
    # 先塞进 sys.modules，相对导入才能工作
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException as exc:  # noqa: BLE001 - 故意兜底，坏模块不能弄死全家
        sys.modules.pop(name, None)
        return None, "导入出错：%s: %s" % (type(exc).__name__, exc)

    candidates = [
        obj
        for obj in vars(module).values()
        if isinstance(obj, type)
        and issubclass(obj, Vuln)
        and obj is not Vuln
        and obj.__module__ == module.__name__
    ]
    if not candidates:
        return None, "module.py 里找不到继承 Vuln 的类"
    if len(candidates) > 1:
        names = ", ".join(sorted(c.__name__ for c in candidates))
        return None, "module.py 里有 %d 个 Vuln 子类（%s），只能有一个" % (
            len(candidates),
            names,
        )

    cls = candidates[0]
    problems = validate_info(getattr(cls, "info", None))
    if problems:
        return None, "契约不合规：" + "；".join(problems)

    return cls, None


def forget(module_id: str) -> None:
    """从 sys.modules 里摘掉一个模块（reload 用）。"""
    prefix = module_name_for(module_id)
    for key in [k for k in sys.modules if k == prefix or k.startswith(prefix + ".")]:
        sys.modules.pop(key, None)
