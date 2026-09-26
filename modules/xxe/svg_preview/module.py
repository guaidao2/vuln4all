"""SVG 元数据提取处的 XXE。

业务场景是"上传 SVG 图标，服务端把标题和作者读出来展示"。

坑在解析器上：Python 的 `xml` 默认**不解析外部实体**（这是安全的默认值），
而这个模块的开发"为了支持可引入的片段"显式把 `feature_external_ges`
打开了，还自己实现了一个 resolveEntity 去读文件。

真实世界里的 XXE 就是这么来的 —— 默认配置本来是安全的，
是有人为了"方便"把那道闸门打开了，或者换了一个"更灵活"的解析器。
"""

import io
import os
import sqlite3
from urllib.parse import urlsplit
from urllib.request import url2pathname
from xml.sax import make_parser
from xml.sax.handler import ContentHandler, EntityResolver, feature_external_ges

from vuln4all import Vuln, render_template, request

DB_NAME = "icons.db"

SECRET_DIR = "private"
SECRET_FILE = "ops-token.txt"
#: 目标文件里的内容。它出现在提取出来的元数据里 = 读到了。
SENTINEL = "ICON-OPS-a17f4e"

MAX_UPLOAD = 256 * 1024
#: 实体展开后的上限。不设的话，billion laughs 能把内存吃光。
MAX_EXPANDED = 64 * 1024

GOAL = "用外部实体读到服务器上的文件（内容会出现在图标标题里）"


# ------------------------------------------------------------------ 解析层
#
# 这就是那个"被打开了闸门"的解析器。两个地方合起来才构成 XXE：
#
#   1. `feature_external_ges = True` —— 让 expat 去解析**外部通用实体**
#      （Python 3 的默认值是 False，也就是默认不解析）
#   2. 自己实现的 resolveEntity —— 按 SYSTEM 里给的路径去读文件
#
# 少任何一个都不成立。这也是为什么这道题值得单独拿出来讲：
# "默认安全"不等于"用起来安全"。
class SvgMetadata(ContentHandler, EntityResolver):
    """把 SVG 里的 <title> / <author> 抠出来。

    （用 sax 是因为它能在流式解析里处理实体展开 —— 顺手就开了外部实体。）

    注意：expat **不支持**外部**参数**实体，所以这一题只能用普通实体做带内
    读取，做不了参数实体那一套（blind / OOB 的手法在这套栈上不成立。）

    两个基类都要继承：`ContentHandler` 提供 startElement 之类的内容回调，
    `EntityResolver` 提供 resolveEntity。只继承后者的话，
    parser 把它当内容处理器用的时候那些回调根本不会被调用 —— 什么都抠不出来。
    """

    def __init__(self):
        super().__init__()
        self.title = []
        self.author = []
        self.stack = []
        self.buffer = []
        self.expanded = 0
        self.error = None

    def resolveEntity(self, publicId, systemId):
        """按 SYSTEM 标识符读文件。

        ↓↓↓ 洞就在这里 ↓↓↓
        正确做法：返回空流，或者干脆不打开 feature_external_ges。
        """
        try:
            parts = urlsplit(systemId)
            if parts.scheme == "file":
                path = url2pathname(parts.path)
            else:
                # 非 file:// 的（比如 http://）也照读 —— 那就变成 SSRF 了
                path = systemId
            with open(path, "rb") as handle:
                return io.BytesIO(handle.read(MAX_EXPANDED))
        except OSError:
            return io.BytesIO(b"")

    # ------------------------------------------------------------ sax 回调

    def startElement(self, name, attrs):
        self.stack.append(name)
        del self.buffer[:]

    def endElement(self, name):
        text = "".join(self.buffer)
        del self.buffer[:]
        if name == "title":
            self.title.append(text)
        elif name == "author":
            self.author.append(text)
        if self.stack and self.stack[-1] == name:
            self.stack.pop()

    def characters(self, content):
        # 累计展开后的字符数，防止 billion laughs 撑爆内存
        self.expanded += len(content)
        if self.expanded > MAX_EXPANDED:
            raise ValueError("实体展开后太大了，中止")
        self.buffer.append(content)


def parse_metadata(blob):
    """返回 (title, author, error)。"""
    parser = make_parser()
    try:
        # ↓↓↓ 闸门就在这里被打开了 ↓↓↓
        parser.setFeature(feature_external_ges, True)
        # ↑↑↑ 默认就是 False（不解析外部实体）—— 这一行把默认的安全值改掉了 ↑↑↑
    except Exception as exc:  # noqa: BLE001
        return "", "", "解析器不支持设置外部实体开关：%s" % exc

    handler = SvgMetadata()
    parser.setContentHandler(handler)
    parser.setEntityResolver(handler)
    try:
        parser.parse(io.BytesIO(blob))
    except Exception as exc:  # noqa: BLE001
        return (
            "".join(handler.title).strip(),
            "".join(handler.author).strip(),
            "%s: %s" % (type(exc).__name__, exc),
        )
    return (
        "".join(handler.title).strip(),
        "".join(handler.author).strip(),
        None,
    )


class SvgPreview(Vuln):
    info = {
        "name": "SVG 元数据提取处的 XXE",
        "author": ["guaidao2"],
        "cwe": "CWE-611",
        "owasp": "A05:2021 - Security Misconfiguration",
        "difficulty": "困难",
        "description": (
            "上传 SVG 图标，服务端把 `<title>` 和 `<author>` 读出来展示。"
            "解析用的是 Python 的 sax，但开发显式打开了"
            "「解析外部实体」这个开关，还自己实现了读文件的回调。\n"
            "于是 SVG 里一句 `<!ENTITY ... SYSTEM \"file:///...\">` 就能"
            "把服务器上的文件读出来，内容会出现在图标标题里。"
        ),
        "hint": (
            "先传一个普通 SVG 看服务端提出了哪些字段（title / author）。\n"
            "然后想：XML 的 `<!DOCTYPE>` 里可以声明实体，而实体的内容可以"
            "**来自一个外部地址**。那个地址被支持哪些协议？\n"
            "重点是 `SYSTEM` 那个标识符 —— 服务端会拿它去干什么？\n"
            "先试试 `file:///etc/hostname`（读得到的话，内容会显示在标题里）。"
        ),
        "solution": (
            "一、构造一个带外部实体的 SVG：\n\n"
            "   <?xml version=\"1.0\"?>\n"
            "   <!DOCTYPE svg [ <!ENTITY xxe SYSTEM \"file:///etc/hostname\"> ]>\n"
            "   <svg xmlns=\"http://www.w3.org/2000/svg\">\n"
            "     <title>&xxe;</title>\n"
            "     <author>test</author>\n"
            "   </svg>\n\n"
            "   传上去，标题那一栏会显示 /etc/hostname 的内容。\n\n"
            "二、读这一题的目标文件（页面下半部分给了完整路径）：\n\n"
            "   <!ENTITY xxe SYSTEM \"file://<目标文件的完整路径>\">\n\n"
            "   那串 ICON-OPS- 开头的凭据出现在标题里就通关了。\n\n"
            "三、还可以读什么：\n"
            "     file:///etc/passwd\n"
            "     file:///proc/self/environ      环境变量（常常有密钥）\n"
            "     file:///proc/self/cmdline      启动参数\n"
            "     file:///root/.ssh/id_rsa       私钥\n\n"
            "关于这一题的边界（值得知道）：\n"
            "  · expat **不支持**外部**参数**实体，所以参数实体那一套\n"
            "    （blind XXE / OOB 外带 / error-based）在这套栈上不成立。\n"
            "    这里能做的是**带内**读取：读到的内容直接显示在响应里。\n"
            "  · 真实环境里遇到不出网、不回显的目标，才会需要参数实体那一套。\n"
            "    那时候的思路是让服务端把数据发到你控制的服务器上，或者\n"
            "    故意制造一个解析错误把内容带进报错里。\n\n"
            "这一题真正的教训：\n"
            "  **Python 的 xml 默认是安全的**（默认不解析外部实体）。\n"
            "  这个洞的存在完全是因为有人把那道闸门打开了 ——\n"
            "  想支持「可引入的片段」、想用「更灵活」的解析器、\n"
            "  或者直接照抄了一段开了闸门的代码。\n"
            "  「默认安全」和「用起来安全」是两件事。"
        ),
        "refs": [
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://docs.python.org/3/library/xml.html#xml-vulnerabilities",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        con = sqlite3.connect(str(ctx.workspace / DB_NAME))
        con.executescript(
            """
            CREATE TABLE icons (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                name   TEXT NOT NULL,
                title  TEXT NOT NULL,
                author TEXT NOT NULL
            );
            """
        )
        con.commit()
        con.close()

        (ctx.workspace / SECRET_DIR).mkdir(parents=True, exist_ok=True)
        (ctx.workspace / SECRET_DIR / SECRET_FILE).write_text(
            "图标库后台凭据\n接口令牌：" + SENTINEL + "\n", encoding="utf-8"
        )

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)
        secret_path = ctx.workspace / SECRET_DIR / SECRET_FILE

        def add_icon(name, title, author):
            con = sqlite3.connect(db_path)
            try:
                con.execute(
                    "INSERT INTO icons (name, title, author) VALUES (?,?,?)",
                    (name, title, author),
                )
                con.commit()
            finally:
                con.close()

        def all_icons():
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                return con.execute(
                    "SELECT name, title, author FROM icons ORDER BY id"
                ).fetchall()
            finally:
                con.close()

        @app.route("/", methods=["GET", "POST"])
        def index():
            result = None
            error = None

            if request.method == "POST":
                uploaded = request.files.get("icon")
                if uploaded is None or not uploaded.filename:
                    error = "没选文件"
                else:
                    blob = uploaded.read(MAX_UPLOAD + 1)
                    if len(blob) > MAX_UPLOAD:
                        error = "文件太大了（上限 %d KB）" % (MAX_UPLOAD // 1024)
                    else:
                        title, author, error = parse_metadata(blob)
                        result = {
                            "name": os.path.basename(uploaded.filename),
                            "title": title,
                            "author": author,
                            "missing": not title and not author,
                        }
                        if not error and (title or author):
                            add_icon(result["name"], title, author)
                        if SENTINEL in title or SENTINEL in author:
                            ctx.progress.mark(GOAL)

            return render_template(
                "index.html",
                result=result,
                error=error,
                icons=all_icons(),
                secret_path=str(secret_path),
            )

        @app.route("/清空", methods=["POST"])
        def clear():
            con = sqlite3.connect(db_path)
            try:
                con.execute("DELETE FROM icons")
                con.commit()
            finally:
                con.close()
            return render_template(
                "index.html", result=None, error=None, icons=[],
                secret_path=str(secret_path),
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
