"""core 自己的页面：清单页、体检页、重置入口、静态资源。"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, redirect, render_template, request, url_for

from . import doctor as doctor_mod
from .contract import DIFFICULTIES, difficulty_key
from .registry import Registry

STATIC_URL_PATH = "/__vuln4all/static"
STATUS_URL = "/__vuln4all/status"
RESET_URL = "/__vuln4all/reset"
RESET_DONE_URL = "/__vuln4all/reset-done"
CHECK_URL = "/__vuln4all/check"

DANGER_BANNER = "这是故意留洞的靶场。只在本机或隔离环境跑，绝不要暴露到公网或生产网络。"


def _difficulty_breakdown(registry: Registry) -> "list":
    """[(难度, 题数)] —— 按 DIFFICULTIES 的顺序排，没填难度的模块不计入。"""
    counts: dict = {}
    for entry in registry.loaded():
        level = str(entry.info.get("difficulty", "")).strip()
        if level:
            counts[level] = counts.get(level, 0) + 1
    known = [(d, counts.pop(d)) for d in DIFFICULTIES if d in counts]
    # 非标准档位也让它出现在筛选项里，别悄悄吞掉
    return known + sorted(counts.items())


def _safe_next(value: str) -> str:
    """允许重定向回来的路径只能是站内相对路径，避免开放重定向。

    要挡住的是这几种：
      · //evil.com          协议相对 URL
      · /\\evil.com          有些浏览器把 \\ 当 /，等价于上面那条
      · javascript:xxx       带 scheme 的
    路径里出现普通冒号（/a:b）是允许的，只有「像 scheme 的冒号」才拦。
    """
    value = (value or "").strip()
    if any(ch in value for ch in ("\\", "\r", "\n", "\t")):
        return "/"
    if re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", value):
        return "/"
    if value.startswith("/") and not value.startswith("//"):
        return value
    return "/"


def _same_origin(origin: str, host: str) -> bool:
    """来源校验：只在浏览器会带 Origin 的时候才校验（curl 不带，就放行）。

    这不是要跟 CSRF 比谁更强 —— 它只是防止你浏览别的网页时，那个页面偷偷
    对你的本地靶场发一个 POST 把题目全重置了。curl / 脚本不受影响。

    只比主机名，不比端口和 scheme：本地靶场的访问方式五花八门
    （127.0.0.1 / localhost / IPv6 字面量 / 换端口），比端口很容易把
    合法的同站请求误判成跨站 —— 那是可用性事故，比漏拦一条严重。
    """
    origin = (origin or "").strip()
    if not origin:
        return True
    if origin in ("null", "file://"):
        return False

    def hostname_of(netloc: str) -> str:
        netloc = (netloc or "").strip().lower()
        if netloc.startswith("["):  # IPv6 字面量：[::1]:8800
            return netloc[1:].split("]", 1)[0]
        return netloc.rsplit(":", 1)[0] if ":" in netloc else netloc

    return hostname_of(urlsplit(origin).netloc) == hostname_of(host)


def create_core_app(registry: Registry, home: Path) -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path=STATIC_URL_PATH,
    )
    app.jinja_env.globals.update(
        VULN=None,
        V4A_HOME="/",
        V4A_STATIC=STATIC_URL_PATH,
        V4A_STATUS=STATUS_URL,
        V4A_RESET=RESET_URL,
        V4A_CHECK=CHECK_URL,
        V4A_DIFF_KEY=difficulty_key,
        V4A_BANNER=DANGER_BANNER,
    )
    app.config["HOME"] = str(home)

    @app.route("/")
    def index():
        report = registry.check_report()
        return render_template(
            "vuln4all/index.html",
            registry=registry,
            difficulties=_difficulty_breakdown(registry),
            report=report,
            solved_ids={m["id"] for m in report["modules"] if m["solved"]},
            title="vuln4all 靶场",
        )

    @app.route(CHECK_URL)
    def check_all():
        """整份进度报告。给脚本、扫描器、AI agent 用的那一个接口。"""
        return jsonify(registry.check_report())

    @app.route(CHECK_URL + "/<path:module_id>")
    def check_one(module_id):
        entry = registry.get(module_id.strip("/"))
        if entry is None:
            return jsonify({"error": "没有这个题目", "id": module_id}), 404
        result = entry.run_check()
        return jsonify(
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

    @app.route(STATUS_URL)
    def status():
        findings = doctor_mod.check(registry, smoke=False)
        return render_template(
            "vuln4all/status.html",
            registry=registry,
            findings=findings,
            summary=doctor_mod.summarize(findings),
            has_errors=doctor_mod.has_errors(findings),
            home=str(home),
            title="体检",
        )

    @app.route(RESET_URL, methods=["POST"])
    def reset():
        if not _same_origin(request.headers.get("Origin", ""), request.host):
            return (
                render_template(
                    "vuln4all/module_error.html",
                    message="这个重置请求来自别的站点，已拒绝。",
                    target="/",
                    title="拒绝",
                ),
                403,
            )

        module_id = request.form.get("id", "").strip()
        target = _safe_next(request.form.get("next", ""))

        if module_id == "*":
            failed = []
            for entry in registry.entries:
                if entry.ctx is None or entry.instance is None:
                    continue
                try:
                    registry.reset(entry)
                except Exception as exc:  # noqa: BLE001
                    # 一道题炸了不该让剩下的题都重置不了
                    failed.append("%s: %s" % (entry.id, type(exc).__name__))
            if failed:
                return (
                    render_template(
                        "vuln4all/module_error.html",
                        message="这几道题重置失败：%s" % "；".join(failed),
                        target="/",
                        title="部分失败",
                    ),
                    500,
                )
            return redirect(url_for("reset_done", n="全部", next=target), code=303)

        entry = registry.get(module_id)
        if entry is None:
            return (
                render_template(
                    "vuln4all/module_error.html",
                    message="找不到题目：%s" % module_id,
                    target="/",
                    title="出错了",
                ),
                404,
            )
        try:
            registry.reset(entry)
        except Exception as exc:  # noqa: BLE001
            return (
                render_template(
                    "vuln4all/module_error.html",
                    message="重置 %s 失败：%s: %s" % (module_id, type(exc).__name__, exc),
                    target="/",
                    title="重置失败",
                ),
                500,
            )
        return redirect(url_for("reset_done", n=module_id, next=target), code=303)

    @app.route(RESET_DONE_URL)
    def reset_done():
        return render_template(
            "vuln4all/reset_done.html",
            module_id=request.args.get("n", ""),
            target=_safe_next(request.args.get("next", "")),
            title="已重置",
        )

    @app.errorhandler(404)
    def not_found(_exc):
        return (
            render_template(
                "vuln4all/module_error.html",
                message="没有这个路径：%s" % request.path,
                target="/",
                title="404",
            ),
            404,
        )

    return app
