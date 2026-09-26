"""`vuln4all new` 用的脚手架：生成一个能立刻跑起来的模块骨架。

生成的骨架是「真能跑」的 —— 不用改一行就能启动，doctor 也会通过。
先把能跑的东西放进去，再往上面加洞，比对着文档从零写靠谱。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

MODULE_TEMPLATE = '''"""{name} —— TODO 一句话说清这题在教什么。"""

from vuln4all import Vuln, render_template, request


class {cls}(Vuln):
    info = {{
        "name": "{name}",
        "author": ["guaidao2"],
        "cwe": "TODO，例如 CWE-89",
        "owasp": "TODO，例如 A03:2021 - Injection",
        "difficulty": "TODO，入门 / 进阶 / 困难 三选一",
        "description": "TODO 一句话说清漏洞在哪。",
        "hint": "TODO 给新手的提示：先试什么、观察什么。别直接写答案。",
        "solution": "TODO 具体怎么打通，最好给一条能直接复制的 payload。",
        "refs": [],
        # 想多挂几个入口（比如 SSRF 的“内网服务”、CSRF 的“攻击者站点”）就这样写：
        # "mounts": {{"internal": {{"path": "/internal/admin", "hidden": True}}}},
    }}

    # 可选。首次运行和 reset 之后会被调用一次，用来造初始数据。
    def setup(self, ctx):
        pass

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            who = request.args.get("name", "world")
            # 注意：这里故意用了 |safe，也就是不转义 —— 这就是洞所在。
            # 真做题目时，把这一行换成你想要的漏洞写法。
            return render_template("index.html", who=who)

        # 键 "" 是主挂载点，会挂在 {mount_hint}/
        return {{"": app}}
'''

TEMPLATE_INDEX = """{% extends "vuln4all/base.html" %}
{% block title %}{{ VULN.info.name }}{% endblock %}

{% block content %}
<h1>Hello, {{ who | safe }}</h1>

<p>这是脚手架生成的骨架。把它改成你想教的漏洞就行。</p>

<form method="get" action="{{ url_for('index') }}">
  <label>name <input type="text" name="name" value="{{ who }}"></label>
  <button type="submit">提交</button>
</form>
{% endblock %}
"""

WRITEUP = """# {name}

## 这一题在教什么

TODO

## 漏洞在哪

TODO 指出来到这题的关键代码，让学习者能对上号。

## 怎么打通

TODO 分步写，先给方向再给 payload。

## 怎么修

TODO 这题最重要的一部分：讲清楚正确写法长什么样，
以及为什么现在的写法是错的。
"""


def class_name_for(module_id: str) -> str:
    parts = re.split(r"[^0-9A-Za-z]+", module_id)
    name = "".join(p[:1].upper() + p[1:] for p in parts if p)
    if not name:
        name = "NewVuln"
    if name[0].isdigit():
        name = "V" + name
    return name


def create_module(directory: Path, module_id: str, force: bool = False) -> List[Path]:
    directory = Path(directory)
    (directory / "templates").mkdir(parents=True, exist_ok=True)

    files = {
        directory / "module.py": MODULE_TEMPLATE.format(
            name=module_id.split("/")[-1].replace("_", " "),
            cls=class_name_for(module_id),
            mount_hint="/v/" + module_id,
        ),
        directory / "templates" / "index.html": TEMPLATE_INDEX,
        directory / "writeup.md": WRITEUP.format(name=module_id),
    }

    created = []
    for path, content in files.items():
        if path.exists() and not force:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        # 显式用 LF：开发在 Windows 上，不写死的话生成的会是 CRLF，
        # 推到 Linux 之后跨平台 diff 全是噪音
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        created.append(path)
    return created
