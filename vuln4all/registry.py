"""发现 modules/ 下的所有题目，把它们加载、建好 app、算好挂载点。

模块 id 就是它在 modules/ 下的路径，例如 modules/sqli/login_bypass 的 id 是
"sqli/login_bypass"。分类取第一段（sqli），名字取最后一段（login_bypass）。
"""

from __future__ import annotations

import posixpath
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

from . import paths
from .contract import Vuln, Ctx
from .loader import ENTRY_FILE, load_vuln_class

MARKER = ".initialized"

#: 这个前缀下的路径归 core 自己用，模块不许占用
RESERVED_PREFIXES = ("/__vuln4all", "/v", "/")


@dataclass
class MountSpec:
    key: str
    path: str
    hidden: bool = False


@dataclass
class ModuleEntry:
    id: str
    category: str
    name: str
    directory: Path
    info: dict = field(default_factory=dict)
    ctx: Optional[Ctx] = None
    instance: Optional[Vuln] = None
    apps: dict = field(default_factory=dict)
    mounts: List[MountSpec] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.apps)

    @property
    def display_name(self) -> str:
        return str(self.info.get("name") or self.id)

    @property
    def main_path(self) -> str:
        for mount in self.mounts:
            if mount.key == "":
                return mount.path
        return "/v/" + self.id

    @property
    def visible_mounts(self) -> List[MountSpec]:
        return [m for m in self.mounts if not m.hidden]

    @property
    def hidden_mounts(self) -> List[MountSpec]:
        return [m for m in self.mounts if m.hidden]


class Registry:
    def __init__(self, home: Path):
        self.home = Path(home)
        self.entries: List[ModuleEntry] = []
        self.broken_dirs: List[tuple] = []  # (目录, 说明)
        self.conflicts: List[str] = []
        self.skipped_mounts: List[tuple] = []  # (模块, 路径, 已被谁占了)

    # ------------------------------------------------------------- 查询

    def get(self, module_id: str) -> Optional[ModuleEntry]:
        for entry in self.entries:
            if entry.id == module_id:
                return entry
        return None

    def loaded(self) -> List[ModuleEntry]:
        return [e for e in self.entries if e.ok]

    def failed(self) -> List[ModuleEntry]:
        return [e for e in self.entries if not e.ok]

    def categories(self) -> List[tuple]:
        """[(分类名, [模块…]), …]，按分类名和模块名排序。"""
        groups: dict = {}
        for entry in self.entries:
            groups.setdefault(entry.category, []).append(entry)
        return [
            (cat, sorted(items, key=lambda e: e.name))
            for cat, items in sorted(groups.items())
        ]

    def mount_map(self) -> dict:
        """{URL 前缀: (模块, 挂载键, WSGI 应用)}

        撞车的挂载点保留先注册的那个，后面的丢掉并记进 skipped_mounts ——
        一个模块写错了不该把别人的题也顶掉。
        """
        result = {}
        for entry in self.entries:
            if not entry.ok:
                continue
            for mount in entry.mounts:
                app = entry.apps.get(mount.key)
                if app is None:
                    continue
                if mount.path in result:
                    self.skipped_mounts.append((entry.id, mount.path, result[mount.path][0].id))
                    continue
                result[mount.path] = (entry, mount.key, app)
        return result

    def watched_files(self) -> List[str]:
        """给 --reload 用的：所有模块文件 + core 的 py 文件。"""
        files = []
        modules_root = paths.modules_dir(self.home)
        if modules_root.is_dir():
            files.extend(str(p) for p in modules_root.rglob("*") if p.is_file())
        core_root = Path(__file__).resolve().parent
        files.extend(str(p) for p in core_root.rglob("*.py") if p.is_file())
        files.extend(str(p) for p in core_root.rglob("*.html") if p.is_file())
        return files

    # ------------------------------------------------------------- 发现

    @classmethod
    def discover(cls, home: Path, setup: bool = True) -> "Registry":
        reg = cls(home)
        reg._scan(setup=setup)
        reg._check_conflicts()
        return reg

    def _scan(self, setup: bool) -> None:
        modules_root = paths.modules_dir(self.home)
        if not modules_root.is_dir():
            return

        sources = sorted(modules_root.rglob(ENTRY_FILE), key=lambda p: str(p).lower())
        claimed = set()

        for source in sources:
            directory = source.parent
            rel = directory.relative_to(modules_root).as_posix()

            # 这个模块目录本身、它下面的一切（templates/、static/……），
            # 以及它到 modules/ 之间的所有上级目录，都算「已认领」
            claimed.add(directory.resolve())
            for descendant in directory.rglob("*"):
                claimed.add(descendant.resolve())
            for parent in directory.parents:
                claimed.add(parent.resolve())
                if parent == modules_root:
                    break

            entry = ModuleEntry(
                id=rel,
                category=(rel.split("/")[0] if "/" in rel else rel),
                name=rel.split("/")[-1],
                directory=directory,
            )
            self.entries.append(entry)
            self._build(entry, setup=setup)

        # 有些目录放了东西但没有 module.py，多半是新手忘了，报出来
        for candidate in sorted(modules_root.rglob("*")):
            if not candidate.is_dir() or candidate == modules_root:
                continue
            if candidate.name.startswith((".", "__")) or candidate.name == "__pycache__":
                continue
            if candidate.resolve() in claimed:
                continue
            if any(p.is_file() for p in candidate.iterdir()):
                self.broken_dirs.append(
                    (candidate.relative_to(modules_root).as_posix(), "没有 %s" % ENTRY_FILE)
                )

    def _build(self, entry: ModuleEntry, setup: bool) -> None:
        cls_or_none, error = load_vuln_class(entry.directory, entry.id)
        if error:
            entry.error = error
            return

        entry.instance = cls_or_none()
        entry.info = dict(getattr(cls_or_none, "info", {}) or {})
        entry.ctx = Ctx(entry.id, entry.info, self.home)

        try:
            apps = entry.instance.create_app(entry.ctx)
        except BaseException as exc:  # noqa: BLE001
            entry.error = "create_app() 出错：%s: %s" % (type(exc).__name__, exc)
            return

        if not isinstance(apps, dict) or not apps:
            entry.error = (
                "create_app() 必须返回 {挂载键: 应用} 这样的非空 dict，"
                "实际返回了 %s" % type(apps).__name__
            )
            return

        for key, app in apps.items():
            if not isinstance(key, str):
                entry.error = "挂载键必须是字符串，出现了 %r" % (key,)
                return
            if not callable(app):
                entry.error = "挂载键 %r 对应的值不是 WSGI 应用（不可调用）" % key
                return
        entry.apps = dict(apps)
        entry.mounts = [
            MountSpec(
                key=key,
                path=entry.ctx.mount_path(key),
                hidden=entry.ctx.is_hidden(key),
            )
            for key in apps
        ]

        if setup:
            self._ensure_setup(entry)

    def _check_conflicts(self) -> None:
        seen: dict = {}
        for entry in self.entries:
            if not entry.ok:
                continue
            for mount in entry.mounts:
                path = mount.path.rstrip("/") or "/"
                if path in ("", "/"):
                    self.conflicts.append("%s 想把挂载点放在 / ，那是 core 的地盘" % entry.id)
                    continue
                if path.startswith("/__vuln4all"):
                    self.conflicts.append(
                        "%s 的挂载点 %s 撞上了 core 保留前缀 /__vuln4all" % (entry.id, path)
                    )
                if path in seen:
                    self.conflicts.append(
                        "%s 和 %s 都想挂在 %s" % (seen[path], entry.id, path)
                    )
                    continue
                seen[path] = entry.id

    # --------------------------------------------------------------- 状态

    def ensure_setup(self, entry: ModuleEntry) -> None:
        self._ensure_setup(entry)

    def _ensure_setup(self, entry: ModuleEntry) -> None:
        if entry.instance is None or entry.ctx is None:
            return
        ctx = entry.ctx
        ctx.workspace.mkdir(parents=True, exist_ok=True)
        marker = ctx.workspace / MARKER
        if marker.exists():
            return
        try:
            entry.instance.setup(ctx)
            marker.write_text("vuln4all\n", encoding="utf-8")
        except BaseException as exc:  # noqa: BLE001
            entry.warnings.append("setup() 出错：%s: %s" % (type(exc).__name__, exc))

    def reset(self, entry: ModuleEntry) -> None:
        """把一道题恢复出厂：清空它的 workspace，重跑 setup()。"""
        if entry.ctx is None or entry.instance is None:
            raise RuntimeError("模块没有加载成功，无法 reset")

        ctx = entry.ctx
        try:
            entry.instance.reset(ctx)
        except BaseException as exc:  # noqa: BLE001
            entry.warnings.append("模块自己的 reset() 出错：%s: %s" % (type(exc).__name__, exc))

        if ctx.workspace.exists():
            for child in ctx.workspace.iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    try:
                        child.unlink()
                    except OSError:
                        pass
        ctx.workspace.mkdir(parents=True, exist_ok=True)

        entry.instance.setup(ctx)
        (ctx.workspace / MARKER).write_text("vuln4all\n", encoding="utf-8")


def join_url(base: str, *parts: str) -> str:
    joined = posixpath.join(base.rstrip("/"), *[p.strip("/") for p in parts])
    return "/" + joined.lstrip("/")
