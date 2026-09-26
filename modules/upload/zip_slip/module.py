"""批量上传头像包时的 Zip Slip。

业务场景：运营同学要把一批头像打包成一个 zip 传上来，服务端解压到上传目录。

开发的心思花在了"别让人传可执行文件"上，于是自己手写了一个解压循环去过滤后缀 ——
**这条手写的循环里没有对成员路径做任何规范化**，于是 zip 里一个带 `../` 的成员名
就能把文件写到上传目录外面去。

（顺带说一句：Python 标准库的 `ZipFile.extractall()` 从 3.6 起已经会把 `..`
和绝对路径清掉。所以这个洞恰恰出现在"不用标准库、自己写循环"的地方 ——
而这正是真实世界里 Zip Slip 的典型成因：开发想加点自己的过滤/改名逻辑。）
"""

import io
import os
import shutil
import zipfile

from vuln4all import Vuln, render_template, request

#: 上传目录和它的上一级。解压目标是前者，被保护的文件在后者。
UPLOAD_DIR = "上传的头像"
GUARD_DIR = "运营公告"

#: 被保护的文件。它被写坏 = 文件落到了上传目录外面。
ANNOUNCEMENT = "公告.txt"
BASELINE = "值班表还没更新，有变动我会在这里说。\n"

#: 开发想防的是"别让人传可执行文件"。
BLOCKED_EXT = (".php", ".phtml", ".py", ".sh", ".jsp", ".asp", ".exe", ".so")

#: 防 zip 炸弹：单个包和总解压量都设上限。
MAX_ARCHIVE = 2 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_MEMBERS = 200

GOAL = "让压缩包里的文件落到了上传目录外面（覆盖了运营公告）"


def safe_member_name(name: str) -> str:
    """把成员名收敛成一个单纯的文件名。

    这是正确做法里最关键的一行 —— 这一题故意没用它。
    """
    return os.path.basename(name.replace("\\", "/"))


class ZipSlip(Vuln):
    info = {
        "name": "批量上传头像包时的 Zip Slip",
        "author": ["guaidao2"],
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "difficulty": "困难",
        "description": (
            "运营同学可以把一批头像打包成 zip 传上来，服务端解压到上传目录。"
            "解压那一步是自己写的循环 —— 它过滤了可执行后缀，"
            "却**没有对压缩包里的成员路径做任何处理**。"
            "zip 里的成员名可以带 `../`，于是文件被写到了上传目录外面。"
        ),
        "hint": (
            "先传一个正常的 zip 看看。然后注意：解压目标是"
            "「上传的头像」这个目录，但它在服务器的什么位置？它的上一级有什么？\n"
            "关键问题不是后缀过滤（那是另一道上传题的重点），"
            "而是：**压缩包里那个成员名，服务端是当「名字」用了，还是当「路径」用了？**"
        ),
        "solution": (
            "一、先做一个「正常」的恶意 zip。压缩包的成员名可以完全由你指定，"
            "命令行工具会帮你规范化掉，所以用 Python 手搓：\n\n"
            "   import zipfile\n"
            "   z = zipfile.ZipFile('evil.zip', 'w')\n"
            "   z.writestr(zipfile.ZipInfo('../运营公告/公告.txt'),\n"
            "              '这里已经被我改了')\n"
            "   z.close()\n\n"
            "   注意成员名是 `../运营公告/公告.txt` —— 往上走一级，"
            "就出了「上传的头像」这个目录。\n\n"
            "二、把这个 zip 传上去。页面会告诉你有一个成员被解压到了上传目录外面。\n\n"
            "三、回到首页看一眼：最上面那条运营公告已经被换掉了。\n"
            "   那个文件本来在「上传的头像」的**上一级**，正常上传永远碰不到它。\n\n"
            "还能往哪写？\n"
            "  · ../../../../tmp/anything      写到系统临时目录\n"
            "  · /etc/cron.d/xxx              绝对路径（有些解压实现不过滤这个）\n"
            "  · ~/.ssh/authorized_keys       写过就是登录\n"
            "真实环境里这一步通常直接就是 getshell。"
        ),
        "refs": [
            "https://portswigger.net/web-security/file-path-traversal",
            "https://security.snyk.io/research/zip-slip-vulnerability",
        ],
    }

    # ------------------------------------------------------------ 生命周期

    def setup(self, ctx):
        (ctx.workspace / UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
        (ctx.workspace / GUARD_DIR).mkdir(parents=True, exist_ok=True)
        (ctx.workspace / GUARD_DIR / ANNOUNCEMENT).write_text(BASELINE, encoding="utf-8")

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        upload_dir = ctx.workspace / UPLOAD_DIR
        guard_dir = ctx.workspace / GUARD_DIR

        @app.route("/", methods=["GET", "POST"])
        def index():
            report = None
            if request.method == "POST":
                report = self._handle_upload(ctx, upload_dir)

            announcement = (guard_dir / ANNOUNCEMENT).read_text(
                encoding="utf-8", errors="replace"
            )
            return render_template(
                "index.html",
                report=report,
                announcement=announcement,
                baseline=BASELINE.strip(),
                upload_dir=UPLOAD_DIR,
                guard_dir=GUARD_DIR,
                files=sorted(p.name for p in upload_dir.iterdir() if p.is_file()),
            )

        @app.route("/重新开始", methods=["POST"])
        def reset_files():
            """把上传目录清空、公告恢复原样。只动这一题自己的 workspace。"""
            shutil.rmtree(upload_dir, ignore_errors=True)
            upload_dir.mkdir(parents=True, exist_ok=True)
            (guard_dir / ANNOUNCEMENT).write_text(BASELINE, encoding="utf-8")
            return render_template(
                "index.html",
                report=None,
                announcement=BASELINE,
                baseline=BASELINE.strip(),
                upload_dir=UPLOAD_DIR,
                guard_dir=GUARD_DIR,
                files=[],
            )

        return {"": app}

    # ------------------------------------------------------------ 解压逻辑

    def _handle_upload(self, ctx, upload_dir):
        """把 zip 里的成员逐个写到上传目录。洞在最后那个 target 上。"""
        uploaded = request.files.get("package")
        if uploaded is None or not uploaded.filename:
            return {"error": "没选文件"}

        raw = uploaded.read(MAX_ARCHIVE + 1)
        if len(raw) > MAX_ARCHIVE:
            return {"error": "压缩包太大了（上限 %d KB）" % (MAX_ARCHIVE // 1024)}

        try:
            archive = zipfile.ZipFile(io.BytesIO(raw))
        except zipfile.BadZipFile:
            return {"error": "这不是一个合法的 zip"}

        total = 0
        written, blocked, escaped = [], [], []

        for info in archive.infolist()[:MAX_MEMBERS]:
            if info.is_dir():
                continue
            name = info.filename

            # 开发想防的是"别让人传可执行文件" —— 心思都花在这上面了
            if name.lower().endswith(BLOCKED_EXT):
                blocked.append(name)
                continue

            total += info.file_size
            if total > MAX_TOTAL:
                return {"error": "解压后总量太大，停在第 %d 个成员" % len(written)}

            # ↓↓↓ 洞就在这里：成员名被当成了路径，没有任何规范化 ↓↓↓
            target = upload_dir / name
            # ↑↑↑ 正确做法：upload_dir / safe_member_name(name)，
            #     或者干脆用 archive.extractall() ↑↑↑

            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            except OSError as exc:
                return {"error": "写文件失败：%s" % exc}

            written.append(name)
            if upload_dir.resolve() not in target.resolve().parents:
                escaped.append(name)

        if escaped:
            ctx.progress.mark(GOAL)

        return {
            "error": None,
            "written": written,
            "blocked": blocked,
            "escaped": escaped,
        }

    # ---------------------------------------------------------------- 进度

    def check(self, ctx):
        """直接看那条公告有没有被改掉 —— 不用记进度。

        能从业已存在的状态推出来的，就别另存一份。
        """
        path = ctx.workspace / GUARD_DIR / ANNOUNCEMENT
        try:
            current = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            # 文件被删掉也算"被动了"
            return {GOAL: True}
        return {GOAL: current != BASELINE}
