"""聊天链接预览的 SSRF —— 带 IP 字面量黑名单。

前面那道 `ssrf/url_preview` 拦的是**主机名**（白名单子串匹配）。
这一题换了思路：它取出 URL 里的 host，然后用一份黑名单去匹配
`localhost`、`127.0.0.1`、私有网段这些**字面量**。

问题在于：同一个 IP 地址有无穷多种写法。黑名单枚举的是一串字符串，
而真正决定"请求连到哪去"的是**解析之后的结果**。这两者之间的差距就是绕过空间。
"""

import http.client
import re
from urllib.parse import urlsplit

from vuln4all import Vuln, render_template, request

#: 内网管理后台返回的东西。它出现在预览结果里 = 绕进去了。
SENTINEL = "INTRANET-ADMIN-4e82d1"

MOUNT = "intranet"
INTRANET_PATH = "/intranet/"

GOAL = "让预览服务自己连上内网管理后台"

# ------------------------------------------------------------------ 过滤层
#
# 这份黑名单是"IP 字面量"式的：它枚举了一堆**字符串**，
# 而每个字符串只是某个地址的**一种写法**。
#
# 这是 SSRF 防护里最典型的坑 —— 作者把"地址"当成了"字符串"。
RULES = [
    ("回环地址字面量", r"(?i)\blocalhost\b|\b127\.0\.0\.1\b|\b0\.0\.0\.0\b|::1"),
    ("私有网段字面量", r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
                       r"|\b192\.168\.\d{1,3}\.\d{1,3}\b"
                       r"|\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
    ("内网主机名后缀", r"(?i)\.local\b|\.internal\b|\.lan\b"),
]

COMPILED = [(name, re.compile(pattern)) for name, pattern in RULES]


def inspect(value):
    for name, pattern in COMPILED:
        if pattern.search(value):
            return name
    return None


class IpFormatFilter(Vuln):
    info = {
        "name": "带 IP 字面量黑名单的 SSRF",
        "author": ["guaidao2"],
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "difficulty": "困难",
        "description": (
            "聊天消息里的链接会被服务端抓取来生成预览。抓取之前会把 host "
            "拿去跟一份黑名单比对：`localhost`、`127.0.0.1`、私有网段、"
            "`.internal` 之类。\n"
            "内网里有一个管理后台。黑名单列的是**字符串**，"
            "而决定请求去哪的是**解析之后的地址** —— 这两者之间的差距就是绕过空间。"
        ),
        "hint": (
            "先确认黑名单的形状：把内网后台的地址（页面上给了）原样打进去，"
            "看它报哪条规则。\n"
            "然后想一个问题：`127.0.0.1` 这个地址，除了写成 `127.0.0.1`，"
            "还有别的写法吗？\n"
            "从一个 IP 地址出发，想想它可以被表示成什么形式 ——\n"
            "它本质上是一个 32 位整数，那么：\n"
            "  · 直接写成整数行不行？\n"
            "  · 十六进制、八进制呢？\n"
            "  · 中间那几段能不能省掉？\n"
            "  · IPv6 那边有没有等价的写法？\n"
            "关键不是「黑名单列了哪些串」，而是「操作系统最后会把它解析成哪个地址」。"
        ),
        "solution": (
            "一、目标是 127.0.0.1，但 `127.0.0.1` 这个写法会被第一条规则拦掉。\n\n"
            "二、同一个地址有很多等价写法，黑名单一个都不认识：\n\n"
            "     十进制整数      http://2130706433:端口/intranet/\n"
            "     十六进制        http://0x7f000001:端口/intranet/\n"
            "     八进制          http://017700000001:端口/intranet/\n"
            "     省略后三段      http://127.1:端口/intranet/\n"
            "     0 也能连本机    http://0:端口/intranet/\n"
            "     IPv6 十六进制   http://[::ffff:7f00:1]:端口/intranet/\n\n"
            "   端口和路径页面上都给了。随便挑一个就能拿到内网后台的内容。\n\n"
            "   为什么这些能成：`socket.getaddrinfo()` 用的是和 `inet_aton()`"
            "同一套\n"
            "   解析规则 —— 它接受十进制/八进制/十六进制的整数形式，也接受缺段的简写。\n"
            "   而黑名单只会做字符串匹配。\n\n"
            "   注意 `[::ffff:127.0.0.1]` 那种写法**不行** —— 字符串里带着\n"
            "   `127.0.0.1`，第一条规则照样拦得到。要写成 `::ffff:7f00:1`\n"
            "   （同一个地址的十六进制形式），黑名单才匹配不上。\n"
            "   这类「差一点就被拦」的细节，自己试的时候很容易踩。\n\n"
            "三、还有一类思路跟表示形式无关：\n\n"
            "   · 302 重定向：让服务端先访问一个你控制的地址，那个地址 302 到内网 ——\n"
            "     校验只看第一次请求的 host（这一题的预览服务跟 3 跳重定向，也不重校验）\n"
            "   · DNS 重绑定：域名第一次解析到公网（过校验），第二次解析到内网\n"
            "     （真正连接时）—— 校验和连接之间有时间差\n"
            "   · 用户信息混淆：`http://内网地址@外部域名/`（`ssrf/url_preview` 讲的就是这个）\n\n"
            "这一题的教训：\n"
            "  · **地址不是字符串。** 校验地址必须校验它**解析之后的值**。\n"
            "  · 黑名单在「同一事物的多种表示」面前是无效的 —— 表示形式有无穷多种，\n"
            "    而语义只有一个。\n"
            "  · 正确做法是「解析 → 拿到真正的 IP → 按类型判断」：\n"
            "    `ipaddress.ip_address(...)` 和 `.is_private` / `.is_loopback` /\n"
            "    `.is_link_local`，而不是在字符串里找 `127`。"
        ),
        "refs": [
            "https://portswigger.net/web-security/ssrf",
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        ],
        "mounts": {MOUNT: {"path": INTRANET_PATH, "hidden": True}},
    }

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        intranet = ctx.flask(__name__, mount=MOUNT)

        # ------------------------------------------------------ 内网后台

        @intranet.route("/")
        def admin_home():
            return render_template("intranet.html", marker=SENTINEL)

        # ------------------------------------------------------ 预览服务

        def fetch(url, hops=0):
            """抓一个 URL 回来。最多跟 3 跳重定向。"""
            if hops > 3:
                return "(重定向太多，放弃)"
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https"):
                return "(只支持 http/https)"
            host = parts.hostname
            if not host:
                return "(URL 里没有主机名)"
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            try:
                conn = http.client.HTTPConnection(host, parts.port or 80, timeout=6)
                conn.request("GET", path, headers={"Host": parts.netloc})
                resp = conn.getresponse()
                body = resp.read(65536).decode("utf-8", "replace")
                # 跟着 3xx 走 —— 注意：**没有对重定向目标重新做校验**
                if resp.status in (301, 302, 303, 307, 308):
                    location = resp.getheader("Location", "")
                    if location:
                        return fetch(location, hops + 1)
                return body
            except Exception as exc:  # noqa: BLE001
                return "(抓取失败：%s)" % exc

        @app.route("/", methods=["GET", "POST"])
        def index():
            url = request.form.get("url", "") if request.method == "POST" else ""
            blocked = None
            preview = None

            if url:
                host = urlsplit(url).hostname or ""
                # ↓↓↓ 黑名单匹配的是 host 这个**字符串** ↓↓↓
                blocked = inspect(host)
                # ↑↑↑ 正确做法：先解析出 IP，再判断它是不是内网/回环 ↑↑↑
                if blocked is not None:
                    blocked = "%s　host = %s" % (blocked, host)
                else:
                    preview = fetch(url)
                    if SENTINEL in preview:
                        ctx.progress.mark(GOAL)

            return render_template(
                "index.html",
                url=url,
                blocked=blocked,
                preview=preview,
                rules=[name for name, _ in RULES],
                intranet_root="http://127.0.0.1:%s%s" % (self._port(request), INTRANET_PATH),
            )

        return {"": app, MOUNT: intranet}

    @staticmethod
    def _port(req):
        """从请求的 Host 里取出端口，好让页面上能给出内网后台的完整地址。"""
        host = req.host
        return host.rsplit(":", 1)[1] if ":" in host else "80"

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
