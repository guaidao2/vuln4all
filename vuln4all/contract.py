"""模块契约：Vuln 基类 + 运行时上下文 Ctx。

这是整个 vuln4all 的核心。想加一道题，你只需要：

    from vuln4all import Vuln

    class MyVuln(Vuln):
        info = {"name": "...", "description": "..."}

        def create_app(self, ctx):
            app = ctx.flask(__name__)
            @app.route("/")
            def index():
                return "随便你写多不安全"
            return {"": app}

把这段放进 modules/<分类>/<名字>/module.py，重启靶场，首页就多一道题。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import uuid
from pathlib import Path

from flask import Flask
from flask.helpers import get_root_path
from jinja2 import ChoiceLoader, FileSystemLoader

# 只有这两个字段是必填的，其余全部可选 —— 老模块不会因为新增字段而失效
REQUIRED_INFO = ("name", "description")

# 强烈建议填的（doctor 会提醒）
RECOMMENDED_INFO = ("author", "cwe", "owasp", "difficulty", "hint", "solution", "refs")

#: 难度标签。**这只是个给人看的标记，core 不为它做任何机制** ——
#: 跟 Metasploit 的 info 一样，纯元数据。填别的值也能跑，只是 doctor 会提醒一句。
DIFFICULTIES = ("入门", "进阶", "困难")

#: 难度 -> CSS 类名后缀，用来上色
DIFFICULTY_KEYS = {"入门": "easy", "进阶": "medium", "困难": "hard"}

CORE_TEMPLATES = str(Path(__file__).resolve().parent / "templates")


def difficulty_key(value: object) -> str:
    """难度标签 -> 样式用的键。认不出来就返回空串（不上色）。"""
    return DIFFICULTY_KEYS.get(str(value or "").strip(), "")


def slug(module_id: str) -> str:
    """把模块 id 变成能安全放进 cookie 名里的形式：sqli/login_bypass -> sqli_login_bypass

    只用来拼 cookie 名。cookie 名不能带 / 和空格，而且不同挂载点的 cookie 还有
    SESSION_COOKIE_PATH 兜底区分，所以这里不需要保证单射。
    模块名和 workspace 目录都不走这个函数 —— 它们各有更严的约束。
    """
    return re.sub(r"[^0-9A-Za-z]+", "_", module_id).strip("_") or "module"


class Progress:
    """模块的通关进度。

    落盘在 workspace/progress.json。选文件而不是内存变量，有两个原因：

    1. **core 的 reset 会清空整个 workspace**，所以进度自动归零 —— 模块不用为了
       进度去实现 reset() 那个钩子。
    2. 重启靶场不丢，方便"打了一半明天接着打"。

    靶场是多线程跑的，读写都加锁；写盘用「先写临时文件再原子替换」，
    免得并发写出一份截断的 JSON。
    """

    def __init__(self, path: Path, log=None):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._log = log

    def _load(self) -> dict:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict) -> bool:
        # 临时文件名带上 pid 和 uuid：同一台机器上可能有第二个进程在读同一个
        # --home（比如一边跑着靶场一边跑 `vuln4all check`），共用固定名字会互相踩。
        tmp = self._path.with_name(
            "%s.%d.%s.tmp" % (self._path.name, os.getpid(), uuid.uuid4().hex[:8])
        )
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(
                json.dumps(data, ensure_ascii=False, sort_keys=True), encoding="utf-8"
            )
            tmp.replace(self._path)
            return True
        except OSError as exc:
            # 最可能的原因：正好有人在 reset，workspace 被清掉了。
            # 这不值得让一个请求 500，记一句就算了。
            if self._log is not None:
                self._log.warning("进度写不进去（%s）：%s", self._path, exc)
            try:
                tmp.unlink()
            except OSError:
                pass
            return False

    @property
    def lock(self):
        """给 core 用的那把锁。

        reset 清空 workspace 的时候要拿着它 —— 否则一个正在写的 mark()
        能把 progress.json 在清理之后重新落盘，进度就从 reset 底下漏过去了。
        """
        return self._lock

    def all(self) -> dict:
        """{目标名: bool} 的快照。"""
        with self._lock:
            return self._load()

    def achieved(self, key: str) -> bool:
        return bool(self.all().get(key))

    def mark(self, key: str) -> bool:
        """记一个目标达成。返回 True 表示这次**确实记上了**（之前没有，而且写盘成功）。"""
        with self._lock:
            data = self._load()
            if data.get(key) is True:
                return False
            data[key] = True
            return self._save(data)


class Ctx:
    """交给模块的运行时上下文。

    模块能从这里拿到：自己的私有目录、生成 URL 的工具、日志器、通关进度，
    以及一个已经接好线的 Flask 应用。
    """

    def __init__(self, module_id: str, info: dict, home: "Path", logger=None):
        parts = str(module_id).split("/")
        if not module_id or any(p in ("", ".", "..") for p in parts):
            # 模块 id 是从 modules/ 下的目录路径算出来的，正常不可能长这样。
            # 但 workspace 是直接拼路径的，这里挡一下，免得以后有人换个来源
            # 传进来就穿出 workspace 以外。
            raise ValueError("模块 id 不合法：%r" % (module_id,))
        self.id = module_id
        self.info = info
        self.home = Path(home)
        #: 模块的私有目录。所有持久化（sqlite、上传文件……）都放这儿。
        #: 模块之间物理隔离，reset 就是清空这个目录再重跑 setup()。
        #: 路径按模块 id 分层展开（sqli/login_bypass -> workspace/sqli/login_bypass），
        #: 这样天然不会有两个模块撞到同一个目录。
        self.workspace = self.home / "workspace" / Path(*module_id.split("/"))
        self.log = logger or logging.getLogger("vuln4all." + module_id)
        # 由模块 id 派生，保证重启后 session 不会失效
        self._secret = hashlib.sha256(("vuln4all:" + module_id).encode()).hexdigest()
        #: create_app() 里实际用过的挂载键。registry 会拿它跟返回的 dict 比对，
        #: 抓「多挂载点忘了传 mount=」这个不会报错的坑。
        self.mounts_used = set()
        #: 通关进度。写在 workspace 里，所以 reset 会自动清零。
        #: 用法：ctx.progress.mark("读了机密文件") / ctx.progress.achieved("...")
        self.progress = Progress(self.workspace / "progress.json", self.log)
        self._checker = None

    # --------------------------------------------------------------- 进度

    def bind_checker(self, fn) -> None:
        """由 registry 调用，把「跑一遍模块的 check()」绑上来。

        模块自己不用管这个方法。
        """
        self._checker = fn

    def check_view(self) -> dict:
        """给模板用的当前进度快照。

        返回 {"supported": bool, "solved": bool, "objectives": {名: bool}, "error": str|None}。
        模块没实现 check() 时 supported=False。
        """
        if self._checker is None:
            return {"supported": False, "solved": False, "objectives": {}, "error": None}
        return self._checker()

    # ------------------------------------------------------------------ URL

    def _declared_mount(self, key: str) -> dict:
        mounts = self.info.get("mounts") or {}
        if not isinstance(mounts, dict):
            return {}
        value = mounts.get(key)
        return value if isinstance(value, dict) else {}

    def mount_path(self, key: str = "") -> str:
        """某个挂载键对应的 URL 前缀（不带结尾斜杠）。

        默认规则：主挂载点 "" 挂在 /v/<模块id>/，其余键挂在 /v/<模块id>/<键>/。
        想改就在 info["mounts"] 里覆盖，例如伪装成真实内网路径：

            info = {"mounts": {"internal": {"path": "/internal/admin", "hidden": True}}}
        """
        declared = self._declared_mount(key)
        explicit = declared.get("path")
        if explicit:
            return "/" + str(explicit).strip("/")
        if not key:
            return "/v/" + self.id.strip("/")
        return "/v/%s/%s" % (self.id.strip("/"), str(key).strip("/"))

    def url(self, key: str = "", path: str = "/") -> str:
        """生成 URL。跨挂载点的链接必须走这里，不要手写以 / 开头的字符串。

            ctx.url("", "/login")        -> /v/sqli/login_bypass/login
            ctx.url("attacker", "/")     -> 攻击者站点的地址

        自己应用内部的路由不用这个，直接用 Flask 的 url_for() 就行 ——
        core 挂了 DispatcherMiddleware，SCRIPT_NAME 已经设好，前缀会自动带上。
        """
        base = self.mount_path(key)
        suffix = (path or "").lstrip("/")
        return base + "/" + suffix if suffix else base + "/"

    def is_hidden(self, key: str) -> bool:
        return bool(self._declared_mount(key).get("hidden"))

    # ---------------------------------------------------------------- Flask

    def flask(self, import_name: str, mount: str = "") -> Flask:
        """建一个已经接好 core 的 Flask 应用。

        它帮你做了四件事：
        1. 模块自己的 templates/ 优先，找不到再找 core 的（所以
           {% extends "vuln4all/base.html" %} 直接能用）
        2. 注入 VULN / V4A_HOME / V4A_STATIC 三个模板全局变量
        3. 把 session cookie 按挂载点隔离（否则同一个域名下多个挂载点
           的 session 会互相覆盖 —— 这是多挂载点最容易踩的坑）
        4. 建好 workspace 目录

        多挂载点的模块要显式传 mount="键名"。
        """
        root = Path(get_root_path(import_name))
        app = Flask(import_name)
        app.jinja_env.loader = ChoiceLoader(
            [
                FileSystemLoader(str(root / "templates")),
                FileSystemLoader(CORE_TEMPLATES),
            ]
        )
        app.jinja_env.globals["VULN"] = self
        app.jinja_env.globals["V4A_HOME"] = "/"
        app.jinja_env.globals["V4A_STATIC"] = "/__vuln4all/static"
        app.jinja_env.globals["V4A_STATUS"] = "/__vuln4all/status"
        app.jinja_env.globals["V4A_RESET"] = "/__vuln4all/reset"
        app.jinja_env.globals["V4A_CHECK"] = "/__vuln4all/check"
        app.jinja_env.globals["V4A_DIFF_KEY"] = difficulty_key
        app.jinja_env.globals["V4A_BANNER"] = (
            "这是故意留洞的靶场。只在本机或隔离环境跑，绝不要暴露到公网或生产网络。"
        )

        app.secret_key = self._secret + ":" + (mount or "main")
        app.config["SESSION_COOKIE_NAME"] = "v4a_%s_%s" % (slug(self.id), mount or "main")
        app.config["SESSION_COOKIE_PATH"] = self.mount_path(mount)
        # 记一笔，registry 会拿它跟 create_app() 返回的键比对：
        # 多挂载点忘了传 mount= 的话，两个 app 会共用 cookie 名和 path，
        # session 互相覆盖，而且一声不响
        self.mounts_used.add(mount)
        # 显式写出来，好让这道 CSRF 题的教学点站得住脚：
        # 同一个 host 下 SameSite=Lax 挡不住跨路径的 CSRF
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
        app.config["SESSION_COOKIE_HTTPONLY"] = True

        self.workspace.mkdir(parents=True, exist_ok=True)
        return app

    # -------------------------------------------------------------- 调试用

    def __repr__(self) -> str:
        return "<Ctx %s>" % self.id


class Vuln:
    """所有靶场模块的基类。"""

    #: 题目元信息。必填：name / description。推荐：author / cwe / owasp /
    #: hint / solution / refs。可选：mounts / tags。
    info: dict = {}

    def create_app(self, ctx: Ctx) -> dict:
        """必需。返回 {挂载键: WSGI 应用}，主挂载点的键是空字符串 ""。

            return {"": app}                       # 只有一个入口
            return {"": shop, "internal": admin}   # 带一个"内网"入口
        """
        raise NotImplementedError("模块必须实现 create_app(ctx)")

    # 下面三个都是可选的，不实现也能跑。

    def setup(self, ctx: Ctx) -> None:
        """首次初始化。造数据库、写初始文件都放这儿。

        什么时候会被调用：workspace/<模块>/ 里还没有 .initialized 标记时。
        reset 之后也会重新调用一次。所以尽量写成可重复执行的。
        """

    def reset(self, ctx: Ctx) -> None:
        """只有模块在进程内存里留了状态时才需要实现。

        常规的 reset（清空 workspace 目录 + 重跑 setup）core 已经包了，
        你什么都不用做。真需要把内存里的东西也归零，才写这个。
        """

    def check(self, ctx: Ctx):
        """可选：报告这道题当前的通关进度。**不实现就返回 None。**

        两种返回值：

            True / False               是否通关
            {"目标名": True/False, ...} 每个小目标的达成情况，"通关" = 全都达成

        两条硬性要求：

        1. **必须无副作用、可重复调用。** CLI 的 `vuln4all check`、
           HTTP 的 `/__vuln4all/check`、以及体检都会随时调它。
           调两次必须得到同样的结果。
        2. **必须自己读状态，不要依赖"上一次请求"。** 它拿不到 request / session ——
           这是一个关于**服务端当前状态**的问题，不是关于某个浏览器的问题。

        要记进度就用 `ctx.progress.mark(...)`；能直接从服务端状态推出来的
        （比如数据库里的值、上传目录里的文件），直接推更可靠。

        目标名会显示给用户看，写清楚一点，别只写 "solved"。
        """
        return None


def validate_info(info: object) -> "list[str]":
    """返回契约违规列表（空列表 = 合规）。"""
    problems = []
    if not isinstance(info, dict):
        return ["info 必须是 dict，实际是 %s" % type(info).__name__]

    for key in REQUIRED_INFO:
        if not str(info.get(key, "")).strip():
            problems.append("缺少必填字段 info[%r]" % key)

    mounts = info.get("mounts")
    if mounts is not None:
        if not isinstance(mounts, dict):
            problems.append("info['mounts'] 必须是 dict")
        else:
            for key, value in mounts.items():
                if not isinstance(value, dict):
                    problems.append("info['mounts'][%r] 必须是 dict" % key)
                    continue
                path = value.get("path")
                if path is not None and not str(path).startswith("/"):
                    problems.append("info['mounts'][%r]['path'] 必须以 / 开头" % key)
    return problems
