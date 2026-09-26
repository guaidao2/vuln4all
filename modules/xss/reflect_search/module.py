"""搜索框的反射型 XSS —— 让新手亲手看到「编码 / 转义」到底是干什么用的。

输入被原样塞进 HTML，没有任何转义。
"""

import re

from vuln4all import Vuln, render_template, request

#: 通关目标名。mark() 和 check() 共用同一个常量，免得拼错字。
#: 注意：目标名会渲染到页面上，别把 payload 字面量写进来。
GOAL = "让可执行的脚本标签被原样发回浏览器"

#: 什么样的输入算"这是攻击载荷"。
#: 要的是一个**真的标签**，因为只有标签才会被执行：
#:   <script>...</script>
#:   <img src=x onerror=...>、<svg onload=...>   （任何带 on* 事件处理器的标签）
#: 光写 javascript: 或 onload= 不算 —— 那些会被当纯文字渲染在 <p> 里，不构成 XSS。
PAYLOAD = re.compile(
    r"(?is)<\s*script\b"                 # <script>
    r"|<\s*[a-z][^>]*\son\w+\s*="        # 标签里带 on* 事件处理器
)


class ReflectSearch(Vuln):
    info = {
        "name": "搜索框的反射型 XSS",
        "author": ["guaidao2"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "difficulty": "入门",
        "description": (
            "搜索页把你输入的关键词原样塞回了 HTML 页面里，一个字符都没有转义。"
            "于是你输入的不只是「文字」，还能是「标签」甚至「脚本」。"
        ),
        "hint": (
            "先输入 <b>hello</b> —— 如果页面上「hello」变成了粗体，说明你写的标签"
            "被浏览器当成标签解析了，而不是当文字显示。"
            "这一步先确认无害的东西能生效，再换成能执行代码的标签。"
        ),
        "solution": (
            "搜索框输入：<script>alert(document.cookie)</script>\n\n"
            "如果被浏览器拦了（有些浏览器会拦地址栏里的脚本），换这个：\n"
            "<img src=x onerror=alert(document.cookie)>\n\n"
            "原理：服务端把关键词原样拼进 HTML。浏览器收到的是\n"
            "  <p>你搜索的内容：<script>alert(document.cookie)</script></p>\n"
            "它分不清哪段是页面作者写的、哪段是用户输入，于是照常执行。"
        ),
        "refs": [
            "https://portswigger.net/web-security/cross-site-scripting",
            "https://owasp.org/www-community/attacks/xss/",
        ],
    }

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            keyword = request.args.get("q", "")
            if PAYLOAD.search(keyword):
                # 关键词会被 |safe 原样渲染进 HTML，所以到这一步脚本一定发出去了
                ctx.progress.mark(GOAL)
            return render_template("search.html", keyword=keyword)

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
