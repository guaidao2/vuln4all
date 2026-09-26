"""搜索框的反射型 XSS —— 让新手亲手看到「编码 / 转义」到底是干什么用的。

输入被原样塞进 HTML，没有任何转义。
"""

from vuln4all import Vuln, render_template, request


class ReflectSearch(Vuln):
    info = {
        "name": "搜索框的反射型 XSS",
        "author": ["guaidao2"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
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
            return render_template("search.html", keyword=keyword)

        return {"": app}
