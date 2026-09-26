"""密码重置链接处的 Host 头注入。

业务场景是"忘记密码"：用户提交邮箱，服务端生成一条重置链接发给他。

问题在于那条链接的**域名**是从请求里来的。而请求里的域名是客户端能改的 ——
于是攻击者可以让服务端"帮它"生成一条指向自己域名的重置链接。

这一题的两个看点：

  1. 应用"部署在反向代理后面"，所以它优先信 `X-Forwarded-Host`，
     再退回 `Host`。**信任何一个都是洞** —— 这两个头都是客户端能设的。
  2. 那个白名单校验是子串匹配，没有做域名边界检查。
"""

import re
import secrets
import sqlite3
from datetime import datetime

from vuln4all import Vuln, render_template, request

DB_NAME = "accounts.db"

#: 自家的对外域名。白名单校验会用到它。
ALLOWED_HOST = "vuln4all.local"

#: 「受信主机」列表：生产域名 + 本地调试用的地址。
#: 真实项目里这份列表通常就长这样 —— 运维会把测试地址也加进去。
ALLOWED = (ALLOWED_HOST, "127.0.0.1", "localhost")

#: 攻击者想要的域名。它出现在生成的重置链接里就算打穿。
EVIL_HOST = "evil.example"

GOAL = "让服务端生成一条指向站外域名的密码重置链接"


def pick_host(req):
    """决定"本站点的对外地址"该用哪个。

    开发的理由听起来挺合理：这服务跑在反向代理后面，
    所以代理给的 `X-Forwarded-Host` 比原始 `Host` 更"真实"。

    ↓↓↓ 洞就在这里 ↓↓↓
    这两个头**都是客户端能设的**。反代只有在它自己会覆盖这两个头时才可信 ——
    而"配置正确"这件事本身没有任何东西保证。

    正确做法：把站点对外地址写进服务端配置（或者一个受信的白名单），
    永远不要从请求头里推。
    """
    return (req.headers.get("X-Forwarded-Host") or req.host or "").strip()


def bare_host(host):
    """去掉端口、转小写。"""
    return (host or "").split(":")[0].strip().lower()


def blocked_host(host):
    """开发的"白名单"：受信列表里提到它就算自家。

    ↓↓↓ 洞就在这里 ↓↓↓
    子串匹配，没有做域名边界检查。
    """
    bare = bare_host(host)
    if not bare:
        return None
    if any(allowed in bare for allowed in ALLOWED):
        # ↑↑↑ 正确做法：`bare in ALLOWED`（整串精确匹配）—— 注意这里没有 any ↑↑↑
        return None
    return "站外主机"


class PasswordReset(Vuln):
    info = {
        "name": "密码重置链接处的 Host 头注入",
        "author": ["guaidao2"],
        "cwe": "CWE-644",
        "owasp": "A01:2021 - Broken Access Control",
        "difficulty": "进阶",
        "description": (
            "「忘记密码」会用请求里的域名拼出一条重置链接发给用户。"
            "而域名来自 `X-Forwarded-Host` 或 `Host` —— 两个都是客户端能设的。\n"
            "于是一个伪造的请求头，就能让服务端**替你**生成一条指向你域名的重置链接。"
        ),
        "hint": (
            "先正常提交一次邮箱，看服务端生成的重置链接长什么样 —— "
            "链接里的域名是从哪来的？\n"
            "然后想：这个值在 HTTP 请求的哪个部分？客户端能不能改？\n"
            "改完之后会撞上那个白名单校验（它会把结果告诉你），"
            "再看那个校验是怎么判断「是不是自家域名」的 ——\n"
            "和「子串里出现了自家域名」是一回事吗？"
        ),
        "solution": (
            "一、先看清正常情况：\n\n"
            "   curl -i -X POST --data-urlencode 'email=alice@corp.example' \\\n"
            "        'http://<靶场>/v/host_header/password_reset/forgot'\n\n"
            "   页面上会显示服务端「发出」的那封邮件，里面有重置链接。\n"
            "   它的域名就是请求里的域名。\n\n"
            "二、直接把 Host 头改掉：\n\n"
            "   curl -i -X POST -H 'Host: evil.example' \\\n"
            "        --data-urlencode 'email=alice@corp.example' <地址>\n\n"
            "   会被白名单拦下 —— 正好，说明校验存在。\n\n"
            "三、绕那个白名单。它做的是子串匹配，没有域名边界检查。\n"
            "   域名是从右往左读的，所以构造一个「含自家域名、但不是自家域名」的主机：\n\n"
            "   curl -i -X POST -H 'Host: {{ALLOWED}}.evil.example' \\\n"
            "        --data-urlencode 'email=alice@corp.example' <地址>\n\n"
            "   服务端会生成一条指向 `vuln4all.local.evil.example` 的重置链接。\n\n"
            "四、还有一条更省事的路：`X-Forwarded-Host`。\n"
            "   这个应用优先用它（因为「部署在反代后面」）：\n\n"
            "   curl -i -X POST -H 'X-Forwarded-Host: evil.example' \\\n"
            "        --data-urlencode 'email=alice@corp.example' <地址>\n\n"
            "   注意：这个写法**不用绕白名单** —— `evil.example` 里没有自家域名，\n"
            "   所以它会被拦。得跟第三步合起来用：\n\n"
            "   curl -i -X POST -H 'X-Forwarded-Host: vuln4all.local.evil.example' ...\n\n"
            "五、拿到的东西怎么用：\n"
            "   受害者会收到一封来自**自家服务**的密码重置邮件，\n"
            "   里面的链接指向攻击者的域名，而 token 就在 URL 里。\n"
            "   受害者一点，token 就发到攻击者服务器上了 → 改掉密码 → 接管账号。\n"
            "   这一步叫「密码重置投毒」。\n\n"
            "关于这套栈上的边界（值得知道）：\n"
            "  · `Host: good.example@evil.example` —— Werkzeug 会把 host 解析成**空字符串**，\n"
            "    所以这条路在这套栈上不通（换个框架可能就通）。\n"
            "  · 发两个 Host 头 —— Werkzeug 一样给出空的 host，也不通。\n"
            "  · 但在**原始 socket** 里，请求行可以写成绝对 URI：\n"
            "      GET http://evil.example/forgot HTTP/1.1\n"
            "      Host: vuln4all.local\n"
            "    这种情况 Werkzeug 取的是**请求行里的**那个（evil.example）。\n"
            "    也就是说：前面挂反代的时候，「哪个头/哪一段算数」取决于反代的实现。\n\n"
            "这一题的教训：\n"
            "  · 站点对外地址是**配置**，不是**请求数据**。永远不要从请求头里推。\n"
            "  · 域名比较必须精确匹配或按段匹配（`endswith('.' + host)`），\n"
            "    不能子串匹配 —— 这一条跟 `cors/credentials`、`ssrf` 是一个道理。"
        ),
        "refs": [
            "https://portswigger.net/web-security/host-header",
            "https://cwe.mitre.org/data/definitions/644.html",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE accounts (
                email  TEXT PRIMARY KEY,
                reset_token   TEXT,
                reset_sent_at TEXT
            );
            INSERT INTO accounts (email, reset_token, reset_sent_at) VALUES
                ('alice@corp.example', NULL, NULL);

            CREATE TABLE mailbox (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                to_addr TEXT NOT NULL,
                body    TEXT NOT NULL,
                sent_at TEXT NOT NULL,
                host    TEXT NOT NULL
            );
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)

        def record_mail(to_addr, body, host):
            con = sqlite3.connect(db_path)
            try:
                con.execute(
                    "INSERT INTO mailbox (to_addr, body, sent_at, host) VALUES (?,?,?,?)",
                    (to_addr, body, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), host),
                )
                con.commit()
            finally:
                con.close()

        def mailbox():
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return [
                    dict(r)
                    for r in con.execute(
                        "SELECT to_addr, body, sent_at, host FROM mailbox ORDER BY id"
                    )
                ]
            finally:
                con.close()

        def set_token(email, token):
            con = sqlite3.connect(db_path)
            try:
                con.execute(
                    "UPDATE accounts SET reset_token=?, reset_sent_at=? WHERE email=?",
                    (token, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), email),
                )
                con.commit()
            finally:
                con.close()

        @app.route("/")
        def index():
            return render_template(
                "index.html",
                mail=mailbox(),
                error=None,
                last=None,
                real_host=request.host,
                allowed=list(ALLOWED),
                evil_host=EVIL_HOST,
            )

        @app.route("/forgot", methods=["POST"])
        def forgot():
            email = request.form.get("email", "").strip()
            error = None
            last = None

            # ↓↓↓ 域名从请求头里来 ↓↓↓
            host = pick_host(request)
            # ↑↑↑ 正确做法：从配置里读站点对外地址，或者干脆用相对链接 ↑↑↑

            blocked = blocked_host(host)
            if blocked is not None:
                error = "邮箱不存在，或者这个域名不被允许：%s（%s）" % (host, blocked)
            else:
                token = secrets.token_urlsafe(16)
                # ↓↓↓ 用那个域名拼绝对链接 ↓↓↓
                link = "http://%s/reset?token=%s" % (host, token)
                set_token(email, token)
                record_mail(email, link, host)
                last = {"host": host, "link": link, "token": token}

                # 判定：链接的域名不是受信列表里那一项。
                # 注意比的是**配置里的受信列表**，不是 request.host ——
                # request.host 本身就是被投毒的那个头，拿它当基准等于自己跟自己比。
                bare = bare_host(host)
                if bare and bare not in ALLOWED:
                    ctx.progress.mark(GOAL)

            return render_template(
                "index.html",
                mail=mailbox(),
                error=error,
                last=last,
                real_host=request.host,
                allowed=list(ALLOWED),
                evil_host=EVIL_HOST,
            )

        @app.route("/清空", methods=["POST"])
        def clear():
            con = sqlite3.connect(db_path)
            try:
                con.execute("DELETE FROM mailbox")
                con.execute("UPDATE accounts SET reset_token=NULL, reset_sent_at=NULL")
                con.commit()
            finally:
                con.close()
            return render_template(
                "index.html", mail=[], error=None, last=None,
                real_host=request.host, allowed=list(ALLOWED), evil_host=EVIL_HOST,
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}


_ = re  # 域名解析相关的工具在"正确做法"那段注释里用得到
