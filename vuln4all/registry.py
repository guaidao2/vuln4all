"""发现 modules/ 下的所有题目，把它们加载、建好 app、算好挂载点。

模块 id 就是它在 modules/ 下的路径，例如 modules/sqli/login_bypass 的 id 是
"sqli/login_bypass"。分类取第一段（sqli），名字取最后一段（login_bypass）。
"""

from __future__ import annotations

import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

from . import paths
from .contract import Vuln, Ctx
from .loader import ENTRY_FILE, load_vuln_class

MARKER = ".initialized"

#: core 自己用的前缀，其下任何路径模块都不许占
RESERVED_PREFIXES = ("/__vuln4all",)
#: 只禁止「精确占住」的路径。注意 "/v" 是模块的聚居区 ——
#: 模块就该住在 /v/<模块id>/ 里，但不许直接占住 /v 或 / 本身。
RESERVED_EXACT = ("/", "/v")


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

    def run_check(self) -> dict:
        """跑模块自己的 check()，把结果规范化成一个固定形状。

        返回 {"supported", "solved", "objectives", "error"}：
          · supported=False 表示这道题没实现 check()（不是错误）
          · objectives 是 {目标名: bool}
          · error 只在 check() 抛异常或返回了非法类型时才有值

        **只读、可重复调用。** 对外面那几个入口（CLI / HTTP / 体检）都走这里。
        """
        blank = {"supported": False, "solved": False, "objectives": {}, "error": None}
        if self.instance is None or self.ctx is None:
            return dict(blank, error=self.error)

        try:
            raw = self.instance.check(self.ctx)
        except Exception as exc:  # noqa: BLE001 - check 抛什么都得兜住，但别吞 KeyboardInterrupt
            return dict(
                blank, supported=True, error="%s: %s" % (type(exc).__name__, exc)
            )

        if raw is None:
            return blank

        if isinstance(raw, dict):
            objectives = {str(key): bool(value) for key, value in raw.items()}
            return {
                "supported": True,
                # 空字典不算通关：一道题总得有点目标
                "solved": bool(objectives) and all(objectives.values()),
                "objectives": objectives,
                "error": None,
            }

        if isinstance(raw, bool):
            return {"supported": True, "solved": raw, "objectives": {}, "error": None}

        return dict(
            blank,
            supported=True,
            error="check() 返回了 %s，只支持 bool 或 {目标名: bool}"
            % type(raw).__name__,
        )

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
        # 统一 resolve：后面要拿它跟目录的 parents 做比较，相对路径比不中
        self.home = Path(home).resolve()
        self.entries: List[ModuleEntry] = []
        self.broken_dirs: List[tuple] = []  # (目录, 说明)
        self.conflicts: List[str] = []
        self.skipped_mounts: List[tuple] = []  # (模块, 路径, 已被谁占了)
        # reset 会删目录再重建，被并发的请求线程或另一个 reset 插进来就半死不活
        self._reset_lock = threading.Lock()
        self._warnings_lock = threading.Lock()

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

    def check_report(self) -> dict:
        """把所有题目的 check() 结果汇总成一份机器可读的报告。

        这是整个靶场对外的那一个接口：CLI 的 `vuln4all check`、
        HTTP 的 /__vuln4all/check、清单页的进度统计都走它。
        """
        modules = []
        solved = 0
        supported = 0
        errored = 0
        failed = 0

        for entry in self.entries:
            result = entry.run_check()
            if result["supported"]:
                supported += 1
            if result["solved"]:
                solved += 1
            if result["error"] and entry.ok:
                errored += 1
            if not entry.ok:
                failed += 1
            modules.append(
                {
                    "id": entry.id,
                    "name": entry.display_name,
                    "difficulty": str(entry.info.get("difficulty") or ""),
                    "cwe": str(entry.info.get("cwe") or ""),
                    "mount": entry.main_path,
                    "loaded": entry.ok,
                    "supported": result["supported"],
                    "solved": result["solved"],
                    "objectives": result["objectives"],
                    "error": result["error"],
                }
            )

        return {
            "total": len(modules),
            "supported": supported,
            "solved": solved,
            "errored": errored,
            # 加载失败的模块单独计数：它和"check 出错"不是一回事，但对 CI /
            # 基准测试来说同样是不能忽略的坏消息，不能藏在 errored 里。
            "failed": failed,
            "modules": modules,
        }

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

        冲突的挂载点在 _resolve_conflicts 里就已经被摘掉了，这里只管组装。
        每次调用都重算 skipped_mounts，免得清单页重复显示同一条。
        """
        self.skipped_mounts = []
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
        reg._resolve_conflicts()
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
            # 清一下：万一以后有人对同一个 Ctx 再调一次 create_app()，
            # 残留的键会让「忘了传 mount=」的检查失效
            entry.ctx.mounts_used.clear()
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

        # 多挂载点最常见、也最隐蔽的错：第二个 app 忘了传 mount=，
        # 于是两个 app 共用同一个 session cookie 名和 path，互相覆盖。
        # 这个错不会抛异常，只会让登录状态莫名其妙地串。
        wrong_mounts = sorted(set(apps) - entry.ctx.mounts_used)
        if wrong_mounts:
            entry.problems.append(
                "挂载键 %s 对应的 app 不是用 ctx.flask(..., mount=%r) 建的 —— "
                "它的 session cookie 会和别的主入口共用，登录状态会串。"
                "请改成 ctx.flask(__name__, mount=%r)"
                % (
                    "、".join(repr(k) for k in wrong_mounts),
                    wrong_mounts[0],
                    wrong_mounts[0],
                )
            )

        entry.mounts = [
            MountSpec(
                key=key,
                path=entry.ctx.mount_path(key),
                hidden=entry.ctx.is_hidden(key),
            )
            for key in apps
        ]

        # 把「跑一遍这道题的 check()」绑进 ctx，这样模块自己的模板也能拿到进度
        # （base.html 的进度区块走 VULN.check_view()）。
        entry.ctx.bind_checker(entry.run_check)

        if setup:
            self._ensure_setup(entry)

    def _resolve_conflicts(self) -> None:
        """算挂载点冲突，并且**真的把冲突的那个摘掉**。

        只记录不拦截是不够的：一个模块声明 {"path": "/__vuln4all/status"} 就能
        按最长前缀命中 DispatcherMiddleware，把 core 的体检页/重置入口整个盖掉，
        而且命令行只打印一句警告，照样把靶场起起来。所以这里直接摘掉。

        摘掉单个挂载点，不牵连这个模块的其他入口；但如果被摘掉的是主挂载点
        （键为 ""），这个模块就没法从清单页进出了，直接判加载失败。
        """
        # 模块之间按 id 排序决定谁先占位，保证每次启动结果一致
        seen: dict = {}
        for entry in sorted(self.entries, key=lambda e: e.id):
            if not entry.ok:
                continue
            kept: List[MountSpec] = []
            for mount in entry.mounts:
                path = mount.path.rstrip("/") or "/"
                reason = None

                if path in RESERVED_EXACT:
                    reason = "%s 是 core 或模块聚居区本身，不能占" % path
                else:
                    for reserved in RESERVED_PREFIXES:
                        if path == reserved or path.startswith(reserved + "/"):
                            reason = "撞上了 core 保留前缀 %s" % reserved
                            break
                if reason is None and path in seen:
                    reason = "已经被 %s 占了" % seen[path]

                if reason is None:
                    seen[path] = entry.id
                    kept.append(mount)
                    continue

                self.conflicts.append(
                    "%s 的挂载点 %s 被摘掉了：%s" % (entry.id, mount.path, reason)
                )
                entry.problems.append("挂载点 %s 被摘掉：%s" % (mount.path, reason))
                entry.apps.pop(mount.key, None)
                if mount.key == "":
                    entry.error = (
                        "主挂载点 %s 被摘掉（%s），这道题没法从清单页进出" % (mount.path, reason)
                    )

            entry.mounts = kept
            if not entry.error and not kept:
                entry.error = "所有挂载点都被摘掉了，这道题不可用"

    # --------------------------------------------------------------- 状态

    def _note(self, entry: ModuleEntry, message: str) -> None:
        """往 entry.warnings 追加要加锁 —— doctor 可能正在并发读这个列表。"""
        with self._warnings_lock:
            entry.warnings.append(message)

    def ensure_setup(self, entry: ModuleEntry) -> None:
        self._ensure_setup(entry)

    def _ensure_setup(self, entry: ModuleEntry) -> None:
        if entry.instance is None or entry.ctx is None:
            return
        ctx = entry.ctx
        ctx.workspace.mkdir(parents=True, exist_ok=True)
        with self._reset_lock:
            marker = ctx.workspace / MARKER
            if marker.exists():
                return
            try:
                entry.instance.setup(ctx)
                marker.write_text("vuln4all\n", encoding="utf-8")
            except BaseException as exc:  # noqa: BLE001
                self._note(entry, "setup() 出错：%s: %s" % (type(exc).__name__, exc))

    def reset(self, entry: ModuleEntry) -> None:
        """把一道题恢复出厂：摘标记 → 清空 workspace → 重跑 setup()。

        持 `_reset_lock`。这保证了 reset 和 reset 之间、reset 和首次 setup 之间
        不会交叉出「标记在、数据没了」的半死目录。

        说清楚它**不**保证什么：它没有和请求线程互斥。如果 reset 正在删某个
        模块的 sqlite 文件，而另一条线程正好握着那个库的连接在查，那条请求
        会拿到一个数据库错误。单进程教学靶场里这可以接受（刷新一下就好），
        真要挡住得在模块的数据访问上加锁。
        """
        if entry.ctx is None or entry.instance is None:
            raise RuntimeError("模块没有加载成功，无法 reset")

        ctx = entry.ctx
        with self._reset_lock:
            # 先摘掉 marker：万一中途炸了，下次启动会重跑 setup，而不是
            # 看到一个空目录却以为已经初始化过了
            marker = ctx.workspace / MARKER
            try:
                marker.unlink()
            except OSError:
                pass

            try:
                entry.instance.reset(ctx)
            except BaseException as exc:  # noqa: BLE001
                self._note(entry, "模块自己的 reset() 出错：%s: %s" % (type(exc).__name__, exc))

            # 清目录要和进度写入互斥：否则一个正好在写的 mark() 会在清理之后
            # 把 progress.json 重新落盘，进度就从 reset 底下漏过去了 ——
            # 而"reset 之后所有 check() 回到未通关"是验证脚本里的一条硬断言。
            with ctx.progress.lock:
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
            marker.write_text("vuln4all\n", encoding="utf-8")
