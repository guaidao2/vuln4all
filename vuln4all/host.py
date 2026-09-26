"""把 core 的页面和所有模块的 app 拼成一个 WSGI 应用。

用的是 werkzeug 的 DispatcherMiddleware：按路径前缀把请求转发给对应的子应用，
并把 SCRIPT_NAME 设好 —— 所以模块内部用 Flask 的 url_for() 生成出来的 URL
自动带正确前缀，模块作者不需要关心自己被挂在哪。
"""

from __future__ import annotations

from pathlib import Path

from werkzeug.middleware.dispatcher import DispatcherMiddleware

from .registry import Registry
from .ui import create_core_app


def build(registry: Registry, home: Path) -> DispatcherMiddleware:
    core = create_core_app(registry, home)

    mounts = {}
    for path, (_entry, _key, app) in registry.mount_map().items():
        mounts[path] = app

    return DispatcherMiddleware(core, mounts)


def describe_mounts(registry: Registry) -> str:
    lines = ["  %-46s -> %s" % ("/", "core（清单页 / 体检页）")]
    for entry in registry.entries:
        if not entry.ok:
            lines.append("  %-46s -> [加载失败] %s" % ("-", entry.id))
            continue
        for mount in entry.mounts:
            tag = "（隐藏）" if mount.hidden else ""
            lines.append("  %-46s -> %s%s" % (mount.path + "/", entry.id, tag))
    return "\n".join(lines)
