"""core 自己的页面：清单页、体检页、重置入口、静态资源。"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, redirect, render_template, request, url_for

from . import doctor as doctor_mod
from .registry import Registry

STATIC_URL_PATH = "/__vuln4all/static"
STATUS_URL = "/__vuln4all/status"
RESET_URL = "/__vuln4all/reset"
RESET_DONE_URL = "/__vuln4all/reset-done"

DANGER_BANNER = "这是故意留洞的靶场。只在本机或隔离环境跑，绝不要暴露到公网或生产网络。"


def _safe_next(value: str) -> str:
    """允许重定向回来的路径只能是站内相对路径，避免开放重定向。"""
    value = (value or "").strip()
    if value.startswith("/") and not value.startswith("//"):
        return value
    return "/"


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
        V4A_BANNER=DANGER_BANNER,
    )
    app.config["HOME"] = str(home)

    @app.route("/")
    def index():
        return render_template(
            "vuln4all/index.html", registry=registry, title="vuln4all 靶场"
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
        module_id = request.form.get("id", "").strip()
        target = _safe_next(request.form.get("next", ""))

        if module_id == "*":
            for entry in registry.entries:
                if entry.ctx is not None and entry.instance is not None:
                    registry.reset(entry)
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
