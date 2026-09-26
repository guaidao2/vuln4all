"""个人签名处的 XSS —— 带标签过滤。

这一题的过滤器不是"命中就拦"，而是**删除**：它把自己认识的危险片段
从输入里 `re.sub` 掉，然后把删剩下的东西存库、原样渲染。

删除式过滤器比拦截式危险得多，因为**删除是可逆的**：攻击者可以构造
"删掉之后正好拼出危险内容"的输入。这一题的两个解法都建立在这上面。

（作为对照，`sqli/keyword_filter` 那道用的是拦截式过滤器 ——
两者要绕的思路完全不同，那道的 writeup 里有一张对照表。）
"""

import html
import re
import sqlite3
from datetime import datetime

from vuln4all import Vuln, render_template, request

DB_NAME = "signatures.db"

GOAL = "让过滤之后的值里仍然有可执行的标记"

# ------------------------------------------------------------------ 过滤层
#
# 一份"删除式"黑名单。写成 strip 而不是 block 是有意的：
# 真实项目里的"输入净化"大多就是长这样 —— 作者觉得自己删掉了危险的东西。
#
# 注意每一条规则描述的都是"已知的攻击长什么样"，而不是"什么结构是危险的"。
# 这就是所有盲区的来源。
RULES = [
    ("script 标签",  r"(?is)<\s*/?\s*script[^>]*>"),
    ("img 标签",     r"(?is)<\s*img[^>]*>"),
    ("svg 标签",     r"(?is)<\s*svg[^>]*>"),
    ("脚本伪协议",   r"(?is)(javascript|vbscript|data)\s*:"),
    ("常见弹窗函数", r"(?is)\b(alert|confirm|prompt)\b"),
]

COMPILED = [(name, re.compile(pattern)) for name, pattern in RULES]

#: 判定用的检测器。
#:
#: 它跟 RULES **完全独立**，而且故意写得比 RULES 严格 ——
#: 这一题要判的就是"过滤器有没有被绕过"，所以判定不能复用过滤器自己的逻辑，
#: 否则过滤器漏掉的东西判定也会一起漏掉。
#:
#: 每一条都要求标记出现在**真实的标签 / 属性上下文里**，而不是光看几个字符。
#: 为什么：早先的版本只写 `on\w+\s*=`，结果纯文本「onerror= 只是文字」
#: 也被判成可执行 —— 学习者随便打一行字就"通关"了。这是实测跑出来的。
#:
#: 认这几类可执行标记：
#:   · 真的 script 标签
#:   · 标签里的事件处理器（属性名前面必须有空白或 `/`）
#:   · 标签属性里的脚本伪协议
#:   · srcdoc / meta refresh 这种"会把内容再当 HTML 解析一遍"的容器
EXECUTABLE = re.compile(
    r"(?is)"
    r"<\s*/?\s*script"
    r"|<\s*[a-z][^>]*?[\s/]on\w+\s*=\s*[^\s>]"
    r"|<\s*[a-z]+[^>]*?\s(?:href|src|action|formaction|data)\s*=\s*[\"']?\s*"
    r"(?:javascript|vbscript)\s*:"
    r"|<\s*(?:iframe|object|embed|frame)\b[^>]*\ssrcdoc\s*="
    r"|<\s*meta[^>]*http-equiv\s*=\s*[\"']?refresh"
)


def sanitize(value):
    """把命中的片段删掉，返回"净化"后的值。"""
    for _, pattern in COMPILED:
        value = pattern.sub("", value)
    return value


def looks_executable(value):
    """过滤之后还残留可执行标记吗？

    看两种形态：原文、以及 HTML 实体解码之后的形态 ——
    因为有些绕过（比如 srcdoc）是把 payload 编码起来塞进容器的，
    解码之后才会变成真正的标签。
    """
    for form in (value, html.unescape(value)):
        if EXECUTABLE.search(form):
            return True
    return False


class TagFilter(Vuln):
    info = {
        "name": "带标签过滤的 XSS（删除式）",
        "author": ["guaidao2"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "difficulty": "困难",
        "description": (
            "个人签名会先经过一层「净化」：把 script / img / svg 标签、"
            "脚本伪协议、alert 这类函数都从输入里删掉，然后存库、原样渲染。\n"
            "页面上会把「删前 / 删后」都打给你看 —— 你要做的是让**删完剩下的东西**"
            "依然能在浏览器里执行。"
        ),
        "hint": (
            "先在签名里写点普通 HTML（比如 `<b>粗体</b>`），看页面上「删前 / 删后」"
            "两块分别是什么。搞清楚它到底是拦还是删。\n"
            "确认是「删」之后，思路就变了：不用去找它漏掉的标签 ——\n"
            "**去找它删掉之后会拼回来的东西。**\n"
            "两条路可以试：\n"
            "  · 嵌套写法：让它删掉中间那段之后，两边正好接成一个完整标签\n"
            "  · 换一层：有没有哪个标签会把属性里的内容**再当一次 HTML 解析**？\n"
            "    那样你就能把 payload 编码起来塞进去 —— 过滤器看到的就只是编码后的文本。"
        ),
        "solution": (
            "先把过滤器的性质确认清楚：它是**删除**，不是拦截。\n"
            "所以在签名里写 `<script>fetch('/')</script>`，删完什么也不剩。\n\n"
            "路子一：嵌套写法，让它自己把标签拼回来。\n\n"
            "   <scr<script>ipt>fetch('/')</scr</script>ipt>\n\n"
            "   规则删的是 `<script...>` 这个整体。拆开看：\n"
            "     <scr | <script> | ipt>          删掉中间 → <script>\n"
            "     </scr | </script> | ipt>        删掉中间 → </script>\n"
            "   所以删完剩下：<script>fetch('/')</script>\n\n"
            "路子二：换个容器，让浏览器再解析一次。\n\n"
            "   <iframe srcdoc=\"&lt;svg/onload=fetch('/')&gt;\"></iframe>\n\n"
            "   srcdoc 属性的值会被浏览器**当成一段独立 HTML 再解析一遍**。\n"
            "   而过滤器看到的是一个实体编码的字符串：\n"
            "     - 没有 `<script`\n"
            "     - 没有 `on...=`（`onload=` 前面是 `/`，但规则里根本没有事件处理器这条）\n"
            "     - 没有 `javascript:`\n"
            "     - 用的是 `fetch`，不是被拦的 alert/confirm/prompt\n"
            "   所以它一字不动地放行。浏览器渲染这一步才把实体解码成真正的\n"
            "   `<svg onload=...>` 并执行。\n\n"
            "这一题的教训：\n"
            "  · **删除式过滤器是可逆的。** 你删了中间那段，两边可能接成新的东西。\n"
            "  · **过滤器和输出上下文是脱节的。** srcdoc 里的内容会被解析两次，\n"
            "    过滤器只看了一次，而且是看的外观（编码后的字符串）。\n"
            "  · 黑名单永远列不全。你没法枚举「所有能执行 JS 的东西」——\n"
            "    这条清单只会越来越长，然后还是会漏。"
        ),
        "refs": [
            "https://portswigger.net/web-security/cross-site-scripting/contexts",
            "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE signatures (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                author  TEXT NOT NULL,
                body    TEXT NOT NULL,
                created TEXT NOT NULL
            );
            INSERT INTO signatures (author, body, created) VALUES
                ('运维组', '有问题来这里留言，别私聊。', '2026-02-01 09:15');
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def all_rows():
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return con.execute(
                    "SELECT author, body, created FROM signatures ORDER BY id"
                ).fetchall()
            finally:
                con.close()

        @app.route("/", methods=["GET", "POST"])
        def index():
            raw = ""
            cleaned = ""
            hit_rules = []

            if request.method == "POST":
                author = request.form.get("author", "").strip() or "匿名"
                raw = request.form.get("body", "")
                if raw:
                    hit_rules = [name for name, p in COMPILED if p.search(raw)]
                    cleaned = sanitize(raw)
                    con = sqlite3.connect(db_path)
                    try:
                        con.execute(
                            "INSERT INTO signatures (author, body, created) VALUES (?,?,?)",
                            (author, cleaned, datetime.now().strftime("%Y-%m-%d %H:%M")),
                        )
                        con.commit()
                    finally:
                        con.close()
                    if looks_executable(cleaned):
                        ctx.progress.mark(GOAL)

            rows = all_rows()
            armed = sum(1 for r in rows if looks_executable(r["body"] or ""))
            return render_template(
                "index.html",
                raw=raw,
                cleaned=cleaned,
                hit_rules=hit_rules,
                rules=[name for name, _ in RULES],
                rows=rows,
                armed=armed,
            )

        @app.route("/清空", methods=["POST"])
        def clear():
            con = sqlite3.connect(db_path)
            try:
                con.execute("DELETE FROM signatures")
                con.commit()
            finally:
                con.close()
            return render_template(
                "index.html", raw="", cleaned="", hit_rules=[],
                rules=[name for name, _ in RULES], rows=[], armed=0,
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """直接从库里推：只要有一条签名的正文里还残着可执行标记，就算达成。

        跟 `xss/stored_guestbook` 同一个思路 —— 能从业已存在的状态推出来的，
        就别再另存一份进度。清空留言之后进度会自然回退。
        """
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        try:
            bodies = [r[0] or "" for r in con.execute("SELECT body FROM signatures")]
        except sqlite3.Error:
            return {GOAL: False}
        finally:
            con.close()
        return {GOAL: any(looks_executable(b) for b in bodies)}
