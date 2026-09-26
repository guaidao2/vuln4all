"""vuln4all —— 模块化 Web 漏洞靶场。

给模块作者用的东西都从这里导出，所以你只需要：

    from vuln4all import Vuln

常用到的 Flask 名字也一并转出来了，省得在模块里再 import 一次 Flask。
"""

from __future__ import annotations

from flask import (
    Flask,
    abort,
    flash,
    make_response,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from markupsafe import Markup, escape

from .contract import Ctx, Vuln

__version__ = "0.1.0"
__author__ = "guaidao2"

__all__ = [
    "Vuln",
    "Ctx",
    "Flask",
    "request",
    "session",
    "render_template",
    "render_template_string",
    "redirect",
    "url_for",
    "send_file",
    "send_from_directory",
    "make_response",
    "abort",
    "flash",
    "Markup",
    "escape",
    "__version__",
]
