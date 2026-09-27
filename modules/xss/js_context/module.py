"""搜索建议处的 XSS —— 注入点在 JavaScript 字符串里。

业务场景是"站内搜索"：搜什么，页面上的 JS 就记住什么，用来做"最近搜索"。

看它把用户输入放在哪儿：

    <script>
      var recentQuery = {{ 用户输入被序列化之后填在这里 }};
    </script>

这个位置很特别，两个坑叠在一起：

  一、**这是 JS 上下文，不是 HTML 上下文。**
     所以"HTML 转义"在这里是错的 —— 它管不到 JS 的语法。

  二、**`<script>` 是"原始文本"元素。**
     HTML 实体在它里面**不会被解码**。所以 `&lt;/script&gt;` 关不掉它 ——
     但**原文的** `</script>` 能。字面文本一出现，script 元素就结束了。

第二点是最反直觉的地方：**唯一能打断它的，是一个不带任何转义的 `</script>`。**

（顺带说明为什么 `json.dumps` 不够：它处理了 JS 的字符串语法，
 但没处理"这段 JSON 是要嵌进 HTML 的 script 元素里"这件事。
 Flask 的 `|tojson` 会把 `<` 转成 `\\u003c`，正是为了这个。）
"""

import html
import json
import re

from vuln4all import Vuln, render_template, request

#: 开发的"过滤"：不许出现 `script` 标签。
#: 注意它拦的是**开始标签**，而漏洞用的是**结束标签**。
RULES = [
    ("script 开始标签", r"(?i)<\s*script"),
]

COMPILED = [(name, re.compile(pattern)) for name, pattern in RULES]

#: 判定：嵌进去的 JSON 里出现了能关掉 script 元素的东西。
BREAKOUT = re.compile(r"(?i)<\s*/\s*script|<[a-z][^>]*\son\w+\s*=")

GOAL = "让嵌进 <script> 的那段值里出现能打断 script 元素的东西"


def inspect(value):
    for name, pattern in COMPILED:
        if pattern.search(value):
            return name
    return None


class JsContext(Vuln):
    info = {
        "name": "搜索建议处的 XSS（注入点在 JS 字符串里）",
        "author": ["guaidao2"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "difficulty": "进阶",
        "description": (
            "搜索关键词会被嵌进页面里的一段 `<script>`，当作 JS 变量保存。\n"
            "服务端把值用 `json.dumps` 序列化了一下，还过滤了 `<script` —— "
            "看起来做了防护。\n"
            "但有两个反直觉的事实：这是 **JS 上下文**（HTML 转义管不到），"
            "而 `<script>` 是**原始文本元素**（`&lt;/script&gt;` 关不掉它，"
            "原文的 `</script>` 能）。"
        ),
        "hint": (
            "先搜点东西，然后**看页面的源代码** —— 你输入的内容被放在哪了？\n"
            "注意它不在 HTML 正文里，而是在一段 `<script>` 里面。\n"
            "然后问三个问题：\n"
            "  一、这个位置是 HTML 上下文还是 JS 上下文？\n"
            "     （如果在 JS 里，那把 `<` 转义成 `&lt;` 有什么用？）\n"
            "  二、`<script>` 元素里面，HTML 实体会被解码吗？\n"
            "     （试试搜 `&lt;b&gt;`，看页面源码里它有没有变成 `<b>`。）\n"
            "  三、过滤器拦的是哪种标签？\n"
            "     （提示：开始标签和**结束标签**是两个不同的字符串。）\n"
            "想清楚第二点，你就知道该怎么打断那个 script 了。"
        ),
        "solution": (
            "一、先看清位置。搜点什么，然后看页面源代码，你会看到类似这一行：\n\n"
            "     var recentQuery = \"<你输入的内容>\";\n\n"
            "   它在 `<script>` 里面 —— 这是个 **JS 上下文**。\n\n"
            "二、试一下 HTML 转义在这里有没有用。搜 `&lt;b&gt;`：\n\n"
            "   页面源码里的 script 部分**原样**是 `&lt;b&gt;` ——\n"
            "   它没有被解码成 `<b>`。\n\n"
            "   为什么：**`<script>` 是 HTML 里的「原始文本元素」**。\n"
            "   在它里面，浏览器只找一件事：`</script`。\n"
            "   所有 HTML 实体（`&lt;`、`&amp;`…）都不解码。\n\n"
            "   所以：\n"
            "     · `&lt;/script&gt;` **关不掉**这个 script 元素（它只是普通文本）\n"
            "     · **原文的** `</script>` **能** —— 一出现，script 元素就结束了\n\n"
            "三、过滤器拦的是 `<script`（开始标签）。那就只用**结束**标签：\n\n"
            "     </script><img src=x onerror=alert(1)>\n\n"
            "   拼出来的源码是：\n\n"
            "     var recentQuery = \"</script><img src=x onerror=alert(1)>\";\n\n"
            "   浏览器解析到这里：\n"
            "     1. `var recentQuery = \"` 是一段脚本\n"
            "     2. 遇到 `</script>` —— **script 元素结束**\n"
            "     3. 后面的 `<img src=x onerror=...>` 被当成普通 HTML\n"
            "     4. `src=x` 加载失败 → `onerror` 执行\n\n"
            "   过滤器一次都没命中（它拦的是 `<script`，没有斜杠）。\n\n"
            "四、为什么 `json.dumps` 不够。\n\n"
            "   它做的是 JS 层面的序列化：引号、反斜杠、控制字符都处理了。\n"
            "   但它**不知道这段 JSON 是要嵌进 HTML 的**。\n"
            "   而在 HTML 里，`</script>` 的语义不是「JS 字符串里的字符」，\n"
            "   是「结束这个元素」。\n\n"
            "   正确做法是**按最终上下文转义**：\n\n"
            "     # Flask/Jinja 的做法：\n"
            "     var recentQuery = {{ q | tojson }};\n"
            "     # tojson 会把 < 转成 \\u003c，于是 </script> 变成\n"
            "     #   \\u003c/script>  —— 在 JS 里是同一个字符串，在 HTML 里不再是结束标签\n\n"
            "   手写的话：\n\n"
            "     json.dumps(q).replace(\"<\", \"\\\\u003c\").replace(\">\", \"\\\\u003e\").replace(\"&\", \"\\\\u0026\")\n\n"
            "这一题真正的教训（比「某个 payload」重要得多）：\n\n"
            "  · **转义必须匹配最终上下文。**\n"
            "    HTML 正文、HTML 属性、`<script>` 里、JS 字符串里、URL 里、CSS 里 ——\n"
            "    六个地方六套规则。在这一题里用「HTML 转义」是错的：\n"
            "    那个值从来不作为 HTML 文本出现，它作为 JS 源码出现。\n\n"
            "  · **「我用了 json.dumps / 我转义了尖括号」都不算数。**\n"
            "    要问的是：这段字节最终会被谁解析？按那个解析器的语法，\n"
            "    什么字符有特殊含义？\n\n"
            "  · **黑名单又漏了符号的形状。**\n"
            "    `<script` 和 `</script>` 是两个不同的字符串；\n"
            "    而且就算两个都拦，还有 `<img onerror>`、`<svg onload>` 一大串。"
        ),
        "refs": [
            "https://portswigger.net/web-security/cross-site-scripting/contexts",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    }

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/", methods=["GET", "POST"])
        def index():
            q = ""
            embedded = None
            blocked = None
            raw_block = None

            if request.method == "POST":
                q = request.form.get("q", "")

                blocked = inspect(q)
                if blocked is None:
                    # ↓↓↓ 洞就在这里：json.dumps 只处理了 JS 语法，  ↓↓↓
                    #     没处理"这段 JSON 要嵌进 HTML 的 script 元素里"
                    embedded = json.dumps(q, ensure_ascii=False)
                    # ↑↑↑ 正确做法：{{ q | tojson }}（它会把 < 转成 \\u003c） ↑↑↑
                    if BREAKOUT.search(embedded):
                        ctx.progress.mark(GOAL)
                else:
                    # 被拦的时候也把它嵌进去，好让做题的人看清过滤器看到了什么
                    raw_block = html.escape(q)

            return render_template(
                "index.html",
                q=q,
                embedded=embedded,
                blocked=blocked,
                raw_block=raw_block,
                rules=[name for name, _ in RULES],
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
