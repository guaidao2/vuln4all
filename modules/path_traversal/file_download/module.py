"""企业网盘的文件下载处 —— 路径穿越。

业务场景是"给同事传文件的内部网盘"：页面上列出一批文档，点一下就能下载。
下载接口把用户给的文件名直接拼进了路径。
"""

from pathlib import Path

from vuln4all import Vuln, render_template, request

#: 藏在"服务目录之外"的机密文件里的一句话。读到它就说明穿越成功了。
MARKER = "vuln4all{path_traversal_ok}"

#: 读文件的上限。没有它的话 `?name=/dev/zero` 会把一个请求线程永久挂住并一直吃内存
#: （靶场是 threaded=True，一个请求就够）。真实系统同样该有这个限制。
MAX_READ = 256 * 1024

#: 通关目标名。mark() 和 check() 共用同一个常量，免得拼错字。
GOAL = "穿越出共享目录，读到里面的机密文件"


def read_text_capped(path: Path) -> str:
    if not path.is_file():
        raise OSError("不是一个普通文件")
    size = path.stat().st_size
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read(MAX_READ)
    if size > MAX_READ:
        text += "\n...（还有 %d 字节没显示）" % (size - MAX_READ)
    return text


class FileDownload(Vuln):
    info = {
        "name": "网盘下载处的路径穿越",
        "author": ["guaidao2"],
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "difficulty": "入门",
        "description": (
            "内部网盘的下载接口把「文件名」直接拼进了服务器路径，"
            "没有做任何规范化。于是 `../` 可以带你走出共享目录。"
        ),
        "hint": (
            "先正常点一个文件下载，看看地址栏里的 name 参数长什么样。"
            "服务器把它当路径的一部分用了 —— 那 `..` 会把你带到哪去？"
            "另外别忘了试一下以 `/` 开头的绝对路径，Python 的 os.path.join 在这里有个坑。"
        ),
        "solution": (
            "**通关条件**：读到内部资料里那句 vuln4all{...} 标记。下面两条路都通，"
            "但只有第一条会触发页面上的通关提示。\n\n"
            "一、相对路径穿越：\n"
            "  /download?name=../内部资料/薪资表.csv\n\n"
            "二、绝对路径直接顶掉基准目录 —— 这是 os.path.join 的陷阱：\n"
            "  /download?name=/etc/passwd\n"
            "  os.path.join('/srv/files', '/etc/passwd') 的结果是 '/etc/passwd'，\n"
            "  不是 '/srv/files/etc/passwd'。只要 name 以 / 开头，基准目录就整个失效。\n"
            "  这条读的不是靶场内的文件，所以不会触发通关提示 —— 它演示的是另一个错法，\n"
            "  两边都值得亲手试一遍。\n\n"
            "三、想看看到底穿到哪了，页面会把服务器真正尝试打开的绝对路径回显给你。"
        ),
        "refs": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://portswigger.net/web-security/file-path-traversal",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        shared = ctx.workspace / "共享文档"
        shared.mkdir(parents=True, exist_ok=True)
        (shared / "新员工入职指南.md").write_text(
            "# 新员工入职指南\n\n1. 领电脑\n2. 加群\n3. 找组长要权限\n",
            encoding="utf-8",
        )
        (shared / "周报模板.md").write_text(
            "# 本周周报\n\n## 做了什么\n\n## 下周计划\n",
            encoding="utf-8",
        )
        (shared / "团建通知.txt").write_text(
            "下周五团建，地点待定。\n", encoding="utf-8"
        )

        # 这个目录不在共享范围里 —— 但下载接口没拦住 ../ 就能进来
        private = ctx.workspace / "内部资料"
        private.mkdir(parents=True, exist_ok=True)
        (private / "薪资表.csv").write_text(
            "姓名,部门,月薪\n"
            "张三,安全组,28000\n"
            "李四,运维组,24000\n"
            "王五,研发组,31000\n"
            "\n"
            "# %s\n" % MARKER,
            encoding="utf-8",
        )

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        shared = ctx.workspace / "共享文档"

        def listing():
            return sorted(
                (p.name for p in shared.iterdir() if p.is_file()), key=str.lower
            )

        @app.route("/")
        def index():
            return render_template("index.html", names=listing())

        @app.route("/download")
        def download():
            name = request.args.get("name", "")
            if not name:
                return render_template("index.html", names=listing(), error="没给 name")

            # ↓↓↓ 洞就在这里：用户给的 name 直接拼进路径，没有规范化、没有白名单 ↓↓↓
            target = shared / name
            # ↑↑↑ 正确做法：先 resolve()，再检查结果还在 shared 里面 ↑↑↑

            try:
                content = read_text_capped(target)
            except OSError as exc:
                return (
                    render_template(
                        "index.html",
                        names=listing(),
                        error="打不开这个文件：%s" % exc,
                        # 顺手把服务器真正去开的绝对路径漏出去 —— 真实的错法
                        tried=str(target.expanduser()),
                        name=name,
                    ),
                    404,
                )

            hit = MARKER in content
            if hit:
                ctx.progress.mark(GOAL)

            return render_template(
                "result.html",
                name=name,
                content=content,
                # 服务器把用户输入解析成了这个绝对路径
                resolved=str(target.expanduser()),
                escaped=name.startswith("/") or ".." in name,
                hit=hit,
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
