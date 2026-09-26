"""企业网盘下载处的路径穿越 —— 带编码过滤。

这一题有两处要绕，而且是叠起来的：

  1. 过滤器拦了 `..` 和路径分隔符 —— 但它看的是**第一次解码之后**的值，
     而应用为了"支持带特殊字符的文件名"自己又解了一次码。两次解码之间
     就是绕过空间。
  2. 过滤器还拦了一批敏感文件名（token / passwd / .env ...），
     所以光绕过路径还不够 —— 你想读的那个文件名本身也在黑名单里。

两处合起来的解法：**双重百分号编码**，而且编码的位置要挑得让黑名单匹配不上。
"""

import re
from urllib.parse import unquote

from vuln4all import Vuln, render_template, request

DOWNLOAD_DIR = "shared"
PRIVATE_DIR = "private"
TOKEN_FILE = "ops-token.txt"

#: 目标文件里的内容。它出现在下载响应里 = 穿越成功。
SENTINEL = "NETDISK-TOKEN-9c41b7"

#: 一次最多读回多少字节。不做这个限制的话，双编码能把路径变成
#: `/dev/zero` 之类的设备文件，`read_text()` 在它上面永远读不完。
MAX_READ = 256 * 1024

GOAL = "把下载目录外面的凭据文件下下来"

#: 下载目录里本来给同事看的文件。
PUBLIC_FILES = {
    "readme.txt": "这个目录放对外共享的资料。\n新增文件请找运维。\n",
    "q1-report.txt": "2026 年第一季度运维报告\n巡检 3 次，无重大故障。\n",
    "onboarding.txt": "新同事接入指引\n1. 申请账号\n2. 配置双因素\n",
}

# ------------------------------------------------------------------ 过滤层
#
# 这次是一份"输入检查"式的过滤器：它拦的是**特征**，不是"结构"。
# 而且它有一个更隐蔽的假设 —— 它以为"我看到的字符串"就是
# "应用最终会拿去做文件操作的那个字符串"。
# 这个假设在有多次解码的项目里是错的。
RULES = [
    # 拦上级目录。看起来很直接。
    ("上级目录",   r"\.\."),
    # 拦路径分隔符。这样一来"../"和绝对路径都进不来了。
    ("路径分隔符", r"[/\\]"),
    # 拦一批敏感文件名。真实 WAF 里很常见的一类规则。
    ("敏感文件名", r"(?i)token|secret|passwd|shadow|\.ssh|\.env|id_rsa"),
]

COMPILED = [(name, re.compile(pattern)) for name, pattern in RULES]


def inspect(value):
    for name, pattern in COMPILED:
        if pattern.search(value):
            return name
    return None


class EncodingFilter(Vuln):
    info = {
        "name": "带编码过滤的路径穿越（双重解码）",
        "author": ["guaidao2"],
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "difficulty": "困难",
        "description": (
            "网盘下载接口前面挂了一份过滤器：拦 `..`、拦路径分隔符、"
            "还拦了一批敏感文件名。\n"
            "但过滤器看的是**第一次解码之后**的值，而应用自己又解了一次码 ——"
            "两次解码之间就是绕过空间。而且你想读的那个文件名本身也在黑名单里。"
        ),
        "hint": (
            "先正常下一个共享目录里的文件，确认页面和参数都通。\n"
            "再打一条经典 payload：`../private/ops-token.txt`，看过滤器报哪条规则。\n"
            "然后想两件事：\n"
            "  · 过滤器看到的那串字符串，跟应用真正拿去拼路径的字符串，"
            "  是同一个吗？（提示：看页面上「这次请求经过的处理」那块）\n"
            "  · 就算路径绕过去了，文件名里的敏感词也还在黑名单里 ——"
            "  编码能不能只编码**一个字符**？"
        ),
        "solution": (
            "一、过滤器命中规则「上级目录」，说明 `..` 是明文被拦的。\n\n"
            "二、关键在于应用对参数解码了两次：\n"
            "     · 第一次是 Flask 解析查询串的时候（所有人都这样）\n"
            "     · 第二次是应用**自己**又调了一次 unquote()\n"
            "   过滤器跑在两次之间。所以你只要写「一次解码之后仍然不含 `..` 和 `/`，\n"
            "   但两次解码之后含」的东西就行了 —— 那就是**双重百分号编码**：\n\n"
            "     %252e%252e%252f\n\n"
            "   拆开看：\n"
            "     %252e  --一次解码-->  %2e  --两次解码-->  .\n"
            "     %252f  --一次解码-->  %2f  --两次解码-->  /\n"
            "   所以 %252e%252e%252f 三次解码之后就是 ../\n\n"
            "   而过滤器看到的是 `%2e%2e%2f` —— 里面既没有 `.` 也没有 `/`。\n\n"
            "三、路径绕过之后还有文件名那一关。目标叫 ops-token.txt，\n"
            "   里面的 `token` 命中了「敏感文件名」规则。\n"
            "   但**编码只需要覆盖匹配到的那几个字符** —— 把 t 换成 %74 即可：\n\n"
            "     ops-%2574oken.txt\n\n"
            "   过滤器看到 `%2574oken.txt`，匹配不到 `token`；\n"
            "   两次解码之后变成 `ops-token.txt`。\n\n"
            "四、完整 payload（注意斜杠也要双重编码）：\n\n"
            "     %252e%252e%252fprivate%252fops-%2574oken.txt\n\n"
            "   读出来那串 NETDISK-TOKEN 就算通关。\n\n"
            "为什么 `....//` 在这里没用：\n"
            "  那一招是针对**删除式**过滤器的（删掉 `../` 之后 `....//` 剩下 `../`）。\n"
            "  这一题是**拦截式** —— 命中就不执行，`....//` 里照样含有 `..`，\n"
            "  一样被拦。\n"
            "  先搞清楚过滤器是拦还是删，再决定用什么 payload。\n\n"
            "顺带一提：早年流行的超长 UTF-8 编码（`%c0%ae` 表示 `.`）在现代\n"
            "语言里已经不可用了 —— Python 的 unquote 会把它当非法 UTF-8 处理掉。\n"
            "「知道某个老技巧已经失效了」也是一种知识。"
        ),
        "refs": [
            "https://portswigger.net/web-security/file-path-traversal",
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        shared = ctx.workspace / DOWNLOAD_DIR
        private = ctx.workspace / PRIVATE_DIR
        shared.mkdir(parents=True, exist_ok=True)
        private.mkdir(parents=True, exist_ok=True)
        for name, body in PUBLIC_FILES.items():
            (shared / name).write_text(body, encoding="utf-8")
        (private / TOKEN_FILE).write_text(
            "网盘后台凭据\n接口令牌：" + SENTINEL + "\n", encoding="utf-8"
        )

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        shared = ctx.workspace / DOWNLOAD_DIR

        @app.route("/")
        def index():
            return render_template(
                "index.html",
                files=sorted(p.name for p in shared.iterdir() if p.is_file()),
                blocked=None,
                raw="",
                decoded=None,
                result=None,
                rules=[name for name, _ in RULES],
                shared_dir=str(shared),
                private_dir=PRIVATE_DIR,
                token_file=TOKEN_FILE,
            )

        @app.route("/download")
        def download():
            name = request.args.get("file", "")

            # ↓↓↓ 过滤层：检查的是**第一次解码之后**的值 ↓↓↓
            blocked = inspect(name)
            if blocked is not None:
                return render_template(
                    "index.html",
                    files=sorted(p.name for p in shared.iterdir() if p.is_file()),
                    blocked=blocked,
                    raw=name,
                    decoded=None,
                    result=None,
                    rules=[name for name, _ in RULES],
                    shared_dir=str(shared),
                    private_dir=PRIVATE_DIR,
                    token_file=TOKEN_FILE,
                )

            # ↓↓↓ 这里就是根因：为了"支持带特殊字符的文件名"又解了一次码 ↓↓↓
            real = unquote(name)
            # ↑↑↑ 双重解码。过滤器跑到这里之前就结束了，两次解码之间是盲区。↑↑↑

            # 到这里才是"应用真正拿去拼路径的字符串"
            target = shared / real

            # 只读普通文件，而且只读前面一段。
            # 不做这两个检查的话，双编码能把 real 变成 `/dev/zero` 之类的设备文件 ——
            # `read_text()` 在它上面永远读不完，一个请求就把 worker 占死了。
            # （`path_traversal/file_download` 那道踩过同一个坑。）
            if not target.is_file():
                content = "读不到这个文件（不是普通文件，或者不存在）。"
            else:
                with open(target, "rb") as handle:
                    raw = handle.read(MAX_READ)
                    truncated = bool(handle.read(1))
                content = raw.decode("utf-8", "replace")
                if truncated:
                    content += "\n...（文件太大，只显示了前 %d 字节）" % MAX_READ

            if SENTINEL in content:
                ctx.progress.mark(GOAL)

            return render_template(
                "index.html",
                files=sorted(p.name for p in shared.iterdir() if p.is_file()),
                blocked=None,
                raw=name,
                decoded=real,
                result={"name": real, "content": content},
                rules=[name for name, _ in RULES],
                shared_dir=str(shared),
                private_dir=PRIVATE_DIR,
                token_file=TOKEN_FILE,
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        return {GOAL: ctx.progress.achieved(GOAL)}
