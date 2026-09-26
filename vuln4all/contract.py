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
import logging
import re
from pathlib import Path

from flask import Flask
from flask.helpers import get_root_path
from jinja2 import ChoiceLoader, FileSystemLoader

# 只有这两个字段是必填的，其余全部可选 —— 老模块不会因为新增字段而失效
REQUIRED_INFO = ("name", "description")

# 强烈建议填的（doctor 会提醒）
RECOMMENDED_INFO = ("author", "cwe", "owasp", "hint", "solution", "refs")

CORE_TEMPLATES = str(Path(__file__).resolve().parent / "templates")


def slug(module_id: str) -> str:
    """把模块 id 变成能安全当文件名的形式：sqli/login_bypass -> sqli_login_bypass"""
    return re.sub(r"[^0-9A-Za-z]+", "_", module_id).strip("_") or "module"


class Ctx:
    """交给模块的运行时上下文。

    模块能从这里拿到：自己的私有目录、生成 URL 的工具、日志器，以及一个
    已经接好线的 Flask 应用。
    """

    def __init__(self, module_id: str, info: dict, home: "Path", logger=None):
        self.id = module_id
        self.info = info
        self.home = Path(home)
        #: 模块的私有目录。所有持久化（sqlite、上传文件……）都放这儿。
        #: 模块之间物理隔离，reset 就是清空这个目录再重跑 setup()。
        self.workspace = self.home / "workspace" / slug(module_id)
        self.log = logger or logging.getLogger("vuln4all." + module_id)
        # 由模块 id 派生，保证重启后 session 不会失效
        self._secret = hashlib.sha256(("vuln4all:" + module_id).encode()).hexdigest()

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
        app.jinja_env.globals["V4A_BANNER"] = (
            "这是故意留洞的靶场。只在本机或隔离环境跑，绝不要暴露到公网或生产网络。"
        )

        app.secret_key = self._secret + ":" + (mount or "main")
        app.config["SESSION_COOKIE_NAME"] = "v4a_%s_%s" % (slug(self.id), mount or "main")
        app.config["SESSION_COOKIE_PATH"] = self.mount_path(mount)
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

    def check(self, ctx: Ctx) -> bool:
        """可选：自动判定"是否已经打通"，给以后的自动化用。默认不实现。"""
        return False


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
