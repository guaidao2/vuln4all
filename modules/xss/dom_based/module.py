"""欢迎页里的 DOM 型 XSS。

这一题最容易被漏掉，原因是：**看响应体根本看不出来。**

反射型 XSS 里，payload 会被服务端拼进返回的 HTML —— 你 curl 一下就能看到。
这一题不一样：服务端压根不碰你给的那段字符串，它是浏览器上的 JS 自己
从地址栏里读出来、再用 innerHTML 拼进页面的。

所以判断这种漏洞只能靠**读前端代码**，不能靠看响应。
"""

import json
import re

from vuln4all import Vuln, jsonify, render_template, request, url_for

#: 通关目标名。mark() 和 check() 共用同一个常量，免得拼错字。
GOAL = "让页面上的 JS 拿着你的输入去拼 innerHTML（DOM 型 XSS 成立）"

#: 什么样的输入算"这是攻击载荷"。要的是真的标签。
PAYLOAD = re.compile(
    r"(?is)<\s*script\b"
    r"|<\s*[a-z][^>]*\son\w+\s*="
)


class DomBased(Vuln):
    info = {
        "name": "欢迎页里的 DOM 型 XSS",
        "author": ["guaidao2"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "difficulty": "进阶",
        "description": (
            "欢迎语是**前端 JS** 从地址栏里读出来、用 innerHTML 拼进页面的。"
            "服务端从头到尾没碰过你输入的那段字符串 —— 所以这个漏洞"
            "在返回的 HTML 里一个字都看不到。"
        ),
        "hint": (
            "curl 一下这个页面（带上你的 payload），你会发现响应体里**找不到它**。\n"
            "那它是怎么出现在页面上的？去看页面里的 <script>。\n"
            "重点看两件事：它从哪里取输入（location 的哪一部分），"
            "以及它把结果放进了什么属性（innerHTML / textContent / ...）。"
        ),
        "solution": (
            "payload 直接给在地址栏里：\n\n"
            "  ?name=<img src=x onerror=alert(1)>\n"
            "  #<img src=x onerror=alert(1)>\n\n"
            "两种都行，进度都会记上。区别只在于服务端看不看得见：\n"
            "  · ?name=...   查询参数，**会**发给服务器（服务器的访问日志里能看到）\n"
            "  · #...        fragment，浏览器**根本不会**把它发给服务器\n"
            "fragment 那种，服务端连你带了 payload 都不知道 —— 页面里那一小段 fetch\n"
            "只是靶场为了记进度加的回报通路，真实网站不会有。\n"
            "所以 fragment 型在真实环境里服务端**完全没有痕迹**，这也是它难查的原因。\n\n"
            "关键是：这段输入从来没经过服务端 ——\n"
            "页面的 JS 读了 location，然后 document.getElementById('greet').innerHTML = ...\n"
            "HTML 里的 <img onerror> 是**浏览器**创建出来的，不是服务器发过来的。"
        ),
        "refs": [
            "https://portswigger.net/web-security/cross-site-scripting/dom-based",
            "https://owasp.org/www-community/attacks/DOM_Based_XSS",
        ],
    }

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            supplied = request.args.get("name", "")

            if supplied and PAYLOAD.search(supplied):
                ctx.progress.mark(GOAL)

            # 下面这两行看着绕，但都不是多余的：
            #
            # 模板里**没有任何地方**输出 supplied —— 这正是这一题的关键。
            # 先渲染一遍，用它的结果去验证"响应体里到底有没有这段字符串"，
            # 把这个结论显示给做题的人看。如果哪天有人不小心在模板里把它输出了，
            # 这个面板会立刻变成"有"，而不是继续骗人。
            html = render_template(
                "index.html",
                has_input=bool(supplied),
                exposes_payload=False,
                hit_url=url_for("dom_hit"),
            )
            exposes = bool(supplied) and supplied in html
            if exposes:
                html = render_template(
                    "index.html",
                    has_input=bool(supplied),
                    exposes_payload=True,
                    hit_url=url_for("dom_hit"),
                )
            return html

        @app.route("/__dom_hit", methods=["POST"])
        def dom_hit():
            """页面里的 JS 自己回报一句"我从 fragment 收到了一段 payload"。

            为什么需要这个口子：fragment（`#...`）根本不会发给服务端，
            所以走 `#<img onerror=...>` 那条路时服务端这边什么都不知道 ——
            但那是一条货真价实的 DOM 型 XSS，不该因为服务端看不见就不算数。

            （顺带说明为什么这个洞难查：攻击载荷完全不出现在任何一条
            服务端能看到的记录里。这条回报通路是靶场为了记进度特意加的，
            真实网站不会有。）

            端点要求把 fragment 的内容一起报上来并当场校验 —— 空 POST 不算数。
            这样"报了但没真带 payload"过不了，跟 ?name= 那条路的严格程度一致。
            """
            try:
                reported = str(json.loads(request.get_data(as_text=True) or "{}").get("hash", ""))
            except (ValueError, AttributeError):
                reported = ""
            if not reported or not PAYLOAD.search(reported):
                return jsonify({"ok": False, "error": "没看到 payload"}), 400
            ctx.progress.mark(GOAL)
            return jsonify({"ok": True})

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
