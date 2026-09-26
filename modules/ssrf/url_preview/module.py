"""聊天应用里的"链接预览" —— SSRF。

业务场景是"团队聊天工具"：贴一个图片链接，服务端会去抓回来显示预览。
抓取前有个白名单校验，但它只是朴素地做了子串匹配。

这道题用两个挂载点：
  · 主入口    —— 聊天应用，带那个有洞的抓取功能
  · 内网后台  —— 一个不该被外人访问的管理页，只接受来自服务器本机的请求
"""

import http.client
from urllib.parse import urljoin, urlsplit

from vuln4all import Vuln, render_template, request

#: 白名单锚点。注意这是个**根本不存在的域名** —— 只是拿来当校验标记用的。
ALLOW_TOKEN = "img.vuln4all.local"

#: 内网后台页面里的一句话。抓取结果里出现它 = SSRF 打通了。
INTERNAL_MARKER = "内部管理后台"

#: 通关目标名。mark() 和 check() 共用同一个常量，免得拼错字。
GOAL = "让服务器替我们去访问了那个只允许本机访问的内网后台"

MAX_BYTES = 6000
MAX_HOPS = 3


def fetch(url: str, timeout: float = 5.0):
    """按 URL 的真实语义去抓。

    这里用 urlsplit + http.client，而不是 urllib.request —— 因为 urllib 的
    Request.host 不会剥离 URL 里的 userinfo，会把 `a@b` 整串当主机名去解析，
    和 requests / curl / 浏览器的行为都不一样。既然这题讲的就是
    「校验时和连接时对同一个 URL 的理解不一致」，那抓取这一侧必须是**真实**的理解。

    返回 (最终 URL, 正文)。
    """
    current = url
    for _ in range(MAX_HOPS + 1):
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https"):
            raise ValueError("只支持 http/https，收到 %r" % parts.scheme)
        host = parts.hostname
        if not host:
            raise ValueError("这个 URL 里没有主机名")

        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(host, parts.port or 443, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)

        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        try:
            conn.request(
                "GET",
                path,
                headers={
                    "User-Agent": "vuln4all-preview/1.0",
                    "Host": parts.netloc.rsplit("@", 1)[-1],
                    "Accept": "*/*",
                },
            )
            resp = conn.getresponse()
            payload = resp.read(MAX_BYTES).decode("utf-8", errors="replace")
            status = resp.status
            location = resp.getheader("Location")
        finally:
            conn.close()

        # 跟一层跳转 —— 真实的抓取器都会跟
        if status in (301, 302, 303, 307, 308) and location:
            current = urljoin(current, location)
            continue
        return current, status, payload

    raise ValueError("跳转次数太多了")


class UrlPreview(Vuln):
    info = {
        "name": "链接预览处的 SSRF",
        "author": ["guaidao2"],
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "difficulty": "进阶",
        "description": (
            "聊天工具的链接预览会由**服务器**去抓取你给的 URL。"
            "抓取前的白名单只做了子串匹配，所以你能让服务器去访问它自己能碰到、"
            "而你碰不到的地方 —— 比如那个只允许本机访问的内网管理后台。"
        ),
        "hint": (
            "白名单检查是「URL 里必须出现 img.vuln4all.local 这个字符串」。"
            "注意：是**字符串**，不是**主机名**。想想 URL 里除了主机名，还有哪些位置"
            "可以塞字符串？(用户名、路径、查询串、#fragment……)\n"
            "另外留意页面会告诉你服务器最终解析出的主机名是什么 —— 那是给你对答案用的。"
        ),
        "solution": (
            "用 URL 的「用户名」部分骗过子串检查：\n\n"
            "  http://img.vuln4all.local@127.0.0.1:8800/internal-admin/\n"
            "                            ^^^^^^^^^^^^^^^ 真正的主机是这一段\n\n"
            "@ 前面是 userinfo，@ 后面才是 host。检查代码只在整串里找 "
            "img.vuln4all.local，找到了就放行；而 urllib 真正去连的是 127.0.0.1。\n\n"
            "端口填你地址栏里那个。内网后台只接受来自 127.0.0.1 的请求 —— "
            "而这次请求正好是服务器自己发出的，所以它放行了。\n\n"
            "同类绕过（换个目标时都值得抄一遍）：\n"
            "  http://2130706433/            127.0.0.1 的十进制\n"
            "  http://0x7f000001/            十六进制\n"
            "  http://127.1/                 省略写法\n"
            "  http://[::1]/                 IPv6 回环\n"
            "  http://allowed.com#@evil.com  用 fragment 截断\n"
            "  http://evil.com/allowed.com   反过来把白名单串放进路径"
        ),
        "refs": [
            "https://portswigger.net/web-security/ssrf",
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        ],
        # 内网后台挂在 /internal-admin/，而且不出现在清单页上
        "mounts": {"internal": {"path": "/internal-admin", "hidden": True}},
    }

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        internal = ctx.flask(__name__, mount="internal")

        @app.route("/", methods=["GET", "POST"])
        def index():
            url = ""
            body = None
            error = None

            if request.method == "POST":
                url = request.form.get("url", "").strip()

                # ↓↓↓ 洞就在这里：只在整串里找子串，没有真正看 host 是谁 ↓↓↓
                if ALLOW_TOKEN not in url:
                    error = "只允许抓取 %s 上的图片" % ALLOW_TOKEN
                # ↑↑↑ 正确做法见 writeup：解析出 host，做精确白名单，
                #     解析不了就拒绝；而且还要防 DNS 重绑定 + 禁跳转 ↑↑↑

                if error is None:
                    try:
                        _final, _status, body = fetch(url)
                    except Exception as exc:  # noqa: BLE001
                        error = "%s: %s" % (type(exc).__name__, exc)

                if body is not None and INTERNAL_MARKER in body:
                    error = None
                    ctx.progress.mark(GOAL)

            parsed_host = None
            if url:
                try:
                    parsed_host = urlsplit(url).hostname
                except ValueError:
                    parsed_host = None

            return render_template(
                "index.html",
                url=url,
                body=body,
                error=error,
                allow_token=ALLOW_TOKEN,
                parsed_host=parsed_host,
                port=request.host.split(":")[-1] if ":" in request.host else "80",
                base=request.host_url,
                hit=bool(body) and INTERNAL_MARKER in body,
            )

        @internal.route("/")
        def admin():
            # 只允许服务器本机访问 —— 真实的网络隔离大多长这样（只监听回环 / 防火墙）
            if request.remote_addr not in ("127.0.0.1", "::1"):
                return (
                    render_template("admin.html", denied=True, marker=INTERNAL_MARKER),
                    403,
                )
            return render_template("admin.html", denied=False, marker=INTERNAL_MARKER)

        return {"": app, "internal": internal}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
