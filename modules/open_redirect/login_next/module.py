"""登录后的跳转 —— 开放重定向。

业务场景是"登录成功后跳回你原来想去的地方"：登录页带一个 `next` 参数，
登录成功后跳过去。

这类功能天然危险：`next` 是用户可控的，而"跳到哪里"是一个**能被用于钓鱼的
信任动作** —— 受害者看到的是自家域名下的链接，点下去却到了攻击者的站点。

这一题的看点是那层"防跳转"校验：它写得挺认真（站外地址一律不放行），
但两条规则各自有一个怎么都想不到的漏洞。
"""

import re
import sqlite3
from urllib.parse import urlsplit

from vuln4all import Vuln, redirect, render_template, request, session

DB_NAME = "portal.db"

#: 自家域名。校验规则会用到它。
OWN_HOST = "vuln4all.local"

GOAL = "让登录后的跳转指向站外域名"

USERS = {"alice": "alice123"}


def looks_internal(next_url):
    """开发的"防跳转"校验：站外地址一律不放行。

    ↓↓↓ 两条规则各自有一个漏洞 ↓↓↓

    规则一：「以 / 开头的都是站内相对路径」
        —— 但 `//evil.example` 也以 / 开头。而以 `//` 开头的是
           **协议相对 URL**：浏览器会补上当前页面的协议，
           然后跳到 `evil.example` 去。

    规则二：「提到了自家域名的就算站内」
        —— 子串匹配，没有做域名边界检查。`vuln4all.local.evil.example`
           里确实"提到了"自家域名，但它属于 evil.example。

    ↑↑↑ 正确做法：把 next 解析成 URL，取出 host，判断它是不是空
        （空 = 站内相对路径）或者精确等于自家域名 ↑↑↑
    """
    if next_url.startswith("/"):
        return True
    if OWN_HOST in next_url:
        return True
    return False


class OpenRedirect(Vuln):
    info = {
        "name": "登录跳转处的开放重定向",
        "author": ["guaidao2"],
        "cwe": "CWE-601",
        "owasp": "A01:2021 - Broken Access Control",
        "difficulty": "入门",
        "description": (
            "登录成功后跳回 `next` 指定的地址。"
            "服务端有一层「站外地址不放行」的校验，"
            "但两条规则各自留了一个漏洞 —— 一个漏在开头的 `//`，"
            "一个漏在子串匹配。"
        ),
        "hint": (
            "先用一个普通的站内路径试（比如 `/home`），确认功能正常。\n"
            "再用一个明显的站外地址试（比如 `https://evil.example/x`），"
            "看它是不是被拦下了 —— 拦下了就说明校验存在。\n"
            "然后去读那两条规则，一条一条问自己：\n"
            "  · 「以 / 开头就算站内」—— 有没有哪种**以 / 开头但其实不是站内**的写法？\n"
            "  · 「提到自家域名就算站内」—— 有没有办法让一个**别人的域名**里"
            "   「提到」自家域名？域名是从左往右读还是从右往左读？"
        ),
        "solution": (
            "两条规则各有一个绕过。\n\n"
            "绕过一：协议相对 URL。\n\n"
            "  next=//evil.example/\n\n"
            "  它以 `/` 开头，所以规则一说「这是站内相对路径」。\n"
            "  但 `//host/path` 是**协议相对 URL** —— 浏览器会补上当前页面的协议\n"
            "  （http 或 https），然后跳到 `evil.example` 去。\n"
            "  也就是说：`//` 开头的不是「路径」，是「省略了协议的主机」。\n\n"
            "  curl -i -X POST -d 'user=alice&password=alice123' \\\n"
            "       --data-urlencode 'next=//evil.example/' <登录地址>\n"
            "  看响应里的 Location 头。\n\n"
            "绕过二：子串匹配，没做域名边界检查。\n\n"
            "  next=https://vuln4all.local.evil.example/\n\n"
            "  它「提到了」自家域名，所以规则二放行。\n"
            "  但域名是**从右往左**读的：最右边的那段才是顶级域。\n"
            "  `vuln4all.local.evil.example` 属于 `evil.example`，不属于 `vuln4all.local`。\n\n"
            "还有哪些写法值得试（不同的下游组件行为不一样）：\n\n"
            "  //evil.example/\n"
            "  ///evil.example/\n"
            "  ////evil.example/\n"
            "  https://evil.example/\n"
            "  https:/evil.example/          浏览器会把缺的斜杠补上\n"
            "  https:///evil.example/        同上\n"
            "  \\\\evil.example/             有些浏览器把 \\ 当 / 处理\n"
            "  https://vuln4all.local@evil.example/     @ 前面是用户信息，后面才是主机\n"
            "  https://evil.example#vuln4all.local      用 fragment 骗字符串检查\n"
            "  https://evil.example/?vuln4all.local\n"
            "  %09//evil.example/            前面加个空白\n\n"
            "**注意最后那几行的实际效果取决于浏览器**，不同浏览器对畸形 URL 的\n"
            "纠正行为不一样。这也是开放重定向这个洞的一个特点：\n"
            "**它的「能不能打」由客户端决定，不由服务端决定。**\n"
            "所以修的时候要想的是「哪些写法会到我手里」，而不是「哪种写法能绕过」。"
        ),
        "refs": [
            "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE accounts (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            );
            INSERT INTO accounts (username, password) VALUES ('alice', 'alice123');
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def check_password(user, password):
            con = sqlite3.connect(db_path)
            try:
                return (
                    con.execute(
                        "SELECT 1 FROM accounts WHERE username=? AND password=?",
                        (user, password),
                    ).fetchone()
                    is not None
                )
            finally:
                con.close()

        @app.route("/")
        def index():
            return render_template(
                "index.html",
                next_url=request.args.get("next", ""),
                blocked=None,
                result=None,
                own_host=OWN_HOST,
            )

        @app.route("/login", methods=["POST"])
        def login():
            user = request.form.get("user", "")
            password = request.form.get("password", "")
            next_url = request.form.get("next", "").strip() or "/home"

            if not check_password(user, password):
                return render_template(
                    "index.html", next_url=next_url, blocked=None,
                    result={"error": "用户名或密码不对"}, own_host=OWN_HOST,
                )

            session["user"] = user

            # ↓↓↓ 校验：站外地址一律不放行 ↓↓↓
            if not looks_internal(next_url):
                return render_template(
                    "index.html", next_url=next_url, blocked=next_url,
                    result={"error": None}, own_host=OWN_HOST,
                )
            # ↑↑↑ 校验"通过"之后就不再看了 —— 而这两条规则各有漏洞 ↑↑↑

            resp = redirect(next_url)

            # 判定：跳转目标解析出来的主机不是我们自己的
            parts = urlsplit(next_url)
            if parts.netloc and parts.netloc != request.host:
                ctx.progress.mark(GOAL)

            return resp

        @app.route("/home")
        def home():
            return render_template(
                "index.html", next_url="", blocked=None,
                result={"error": None, "home": True, "user": session.get("user")},
                own_host=OWN_HOST,
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}


_ = re  # URL 相关的工具在"正确做法"那段注释里用得到
