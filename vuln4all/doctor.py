"""体检：一个模块写得合不合规、能不能跑起来。

`vuln4all doctor` 就是跑这一套。CI 里也应该跑它 —— 这是「别人敢提交模块」
的前提，不然模块质量会烂得很快。
"""

from __future__ import annotations

import importlib.metadata
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .contract import DIFFICULTIES, RECOMMENDED_INFO
from .loader import ENTRY_FILE
from .registry import Registry

ERROR = "error"
WARN = "warn"
INFO = "info"

_PLACEHOLDER = re.compile(r"\bTODO\b", re.I)

#: 疑似硬编码绝对路径的写法。跨挂载点链接必须走 ctx.url()，否则挂载点一改就烂。
#: 放行 /__vuln4all/... —— 那是 core 自己的固定路径，模块指向它是对的。
_HARDCODED_URL_PATTERNS = [
    (re.compile(r"""href\s*=\s*["']/(?!__vuln4all)"""), 'href="/…"'),
    (re.compile(r"""action\s*=\s*["']/(?!__vuln4all)"""), 'action="/…"'),
    (re.compile(r"""src\s*=\s*["']/(?!__vuln4all)"""), 'src="/…"'),
    (re.compile(r"""redirect\(\s*["']/(?!__vuln4all)"""), 'redirect("/…")'),
    (re.compile(r"""["']/v/"""), '"/v/…"'),
]


@dataclass
class Finding:
    level: str
    scope: str
    message: str


def _installed(dist: str) -> bool:
    try:
        importlib.metadata.version(dist)
        return True
    except importlib.metadata.PackageNotFoundError:
        return False
    except Exception:  # noqa: BLE001
        return False


def check(registry: Registry, smoke: bool = True) -> List[Finding]:
    findings: List[Finding] = []

    for conflict in registry.conflicts:
        findings.append(Finding(ERROR, "core", conflict))

    for directory, reason in registry.broken_dirs:
        findings.append(
            Finding(WARN, directory, "这个目录下%s，所以不会被加载" % reason)
        )

    for entry in registry.entries:
        # 先报 problems：挂载点被摘掉时，entry.error 只说"主挂载点被摘了"，
        # 而 problems 里才写得清是被谁抢了 / 撞了哪个保留前缀。
        # 以前这里先 continue，把最有用的那条诊断信息吞掉了。
        for problem in entry.problems:
            findings.append(Finding(ERROR, entry.id, problem))

        if entry.error:
            findings.append(Finding(ERROR, entry.id, entry.error))
            continue

        # 拷一份再遍历：reset 会在别的线程往这个列表里追加
        for warning in list(entry.warnings):
            findings.append(Finding(WARN, entry.id, warning))

        if not entry.mounts:
            findings.append(Finding(ERROR, entry.id, "没有算出任何挂载点"))
        elif not any(m.key == "" for m in entry.mounts):
            findings.append(
                Finding(WARN, entry.id, "没有主挂载点（键为 \"\"），清单页将无处可链")
            )

        for key in RECOMMENDED_INFO:
            if not str(entry.info.get(key, "")).strip():
                findings.append(
                    Finding(INFO, entry.id, "建议补上 info[%r]，会影响清单页和教学体验" % key)
                )

        findings.extend(_check_placeholders(entry))

        # 难度只是个标签，填错了不影响运行 —— 所以只提醒，不当错误
        difficulty = str(entry.info.get("difficulty", "")).strip()
        if difficulty and difficulty not in DIFFICULTIES:
            findings.append(
                Finding(
                    WARN,
                    entry.id,
                    "info['difficulty'] = %r 不在常用档位里（%s），清单页上不会上色"
                    % (difficulty, " / ".join(DIFFICULTIES)),
                )
            )

        findings.extend(_check_source(entry))
        findings.extend(_check_workspace(entry, probe=smoke))
        findings.extend(_check_requirements(entry))
        findings.extend(_check_hook(entry, determinism=smoke))

        if smoke:
            findings.extend(_smoke(entry))

    return findings


def _check_hook(entry, determinism: bool) -> List[Finding]:
    """核对 check() 这个对外接口。

    它现在是对外承诺的机器可读接口（CLI 的 check、HTTP 的 /__vuln4all/check、
    扫描器和 AI agent 都会调），所以有三件事必须成立：
    返回类型合法、不抛异常、**调两次结果一样**。
    """
    first = entry.run_check()

    if first["error"]:
        return [Finding(ERROR, entry.id, "check() 有问题：%s" % first["error"])]

    if not first["supported"]:
        # 没实现 check() 是允许的，不算问题，也不刷屏
        return []

    if not determinism:
        return []

    # 光比"两次结果一样"是不够的：一个会写文件、删文件、消费队列的 check()
    # 只要每次都给出同样的答案就能蒙混过去。所以再比一次 workspace 的指纹 ——
    # 文件清单 + progress.json 的内容。check() 是只读查询，这两样都不该变。
    before = _workspace_fingerprint(entry)
    first = entry.run_check()
    second = entry.run_check()
    after = _workspace_fingerprint(entry)

    findings = []
    if before != after:
        findings.append(
            Finding(
                WARN,
                entry.id,
                "check() 动了 workspace 里的东西 —— 它必须是无副作用的只读查询"
                "（前后文件清单/进度不一样）",
            )
        )

    if (first["solved"], first["objectives"]) != (second["solved"], second["objectives"]):
        findings.append(
            Finding(
                WARN,
                entry.id,
                "check() 连着调两次结果不一样（第一次 %r，第二次 %r）"
                % (first["objectives"] or first["solved"], second["objectives"] or second["solved"]),
            )
        )
        return findings

    done = sum(1 for value in first["objectives"].values() if value)
    total = len(first["objectives"])
    if total:
        state = "已通关" if first["solved"] else "未通关"
        findings.append(
            Finding(INFO, entry.id, "check()：%s（%d/%d 个目标）" % (state, done, total))
        )
    else:
        findings.append(
            Finding(INFO, entry.id, "check()：%s" % ("已通关" if first["solved"] else "未通关"))
        )
    return findings


def _workspace_fingerprint(entry) -> tuple:
    """workspace 的当前指纹：(排序后的文件清单, progress.json 的内容)。

    用来验证 check() 没偷偷动东西。读不动就返回一个空指纹（不因为读不了
    就报成"变了"）。
    """
    if entry.ctx is None:
        return ()
    workspace = entry.ctx.workspace
    try:
        names = tuple(sorted(p.name for p in workspace.iterdir()))
    except OSError:
        names = ()
    try:
        progress = (workspace / "progress.json").read_bytes()
    except OSError:
        progress = b""
    return (names, progress)


def _check_placeholders(entry) -> List[Finding]:
    """抓没改完的骨架。

    `vuln4all new` 生成的 info 里全是 TODO 占位文本。忘了改的话，题目会带着
    "TODO 一句话说清漏洞在哪" 出现在清单页上 —— 这个检查直接把它指出来。

    比在文档里写一句"记得改"有用：它不依赖任何人记得，也不依赖任何人读文档。
    """
    leftovers = []
    for key, value in entry.info.items():
        if key == "mounts":
            continue
        texts = value if isinstance(value, (list, tuple, set)) else [value]
        for text in texts:
            if isinstance(text, str) and _PLACEHOLDER.search(text):
                # 连原文一起打出来，比只报字段名好定位
                leftovers.append("%s（%s）" % (key, text.strip()[:40]))
                break
    if not leftovers:
        return []
    return [
        Finding(
            WARN,
            entry.id,
            "info 里这些字段还带着 TODO 占位文本（多半是脚手架生成后没改完）：%s。"
            "这些字会直接显示在清单页和题目页上" % "、".join(sorted(leftovers)),
        )
    ]


def _check_source(entry) -> List[Finding]:
    """扫模块自己的 py 和模板，找硬编码的绝对路径。

    模板必须一起扫 —— `href="/..."` 这类写法基本都写在 HTML 里，
    只查 module.py 等于只查了一半。
    """
    directory = Path(entry.directory)
    targets = []
    entry_file = directory / ENTRY_FILE
    if entry_file.is_file():
        targets.append(entry_file)
    targets.extend(sorted(p for p in directory.rglob("*.html") if p.is_file()))

    hits = set()
    for path in targets:
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern, label in _HARDCODED_URL_PATTERNS:
            if pattern.search(text):
                hits.add("%s（%s）" % (label, path.name))
    if not hits:
        return []
    return [
        Finding(
            WARN,
            entry.id,
            "疑似硬编码了绝对路径：%s。跨挂载点的链接请用 ctx.url()，"
            "自己应用内部的路由请用 url_for()，否则改挂载点时会静默烂掉"
            % "、".join(sorted(hits)),
        )
    ]


def _check_workspace(entry, probe: bool) -> List[Finding]:
    """检查 workspace 能不能写。

    probe=True 时真的写一个文件试（只有 CLI 的 doctor 会这么干）。
    体检页面走 probe=False —— 一个 GET 请求不该在磁盘上留下副作用，
    而且在只读检出上会让每道题都误报「不可写」。
    """
    if entry.ctx is None:
        return []
    workspace = entry.ctx.workspace
    try:
        workspace.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return [Finding(ERROR, entry.id, "workspace 建不出来：%s" % exc)]

    if not os.access(str(workspace), os.W_OK | os.X_OK):
        return [Finding(ERROR, entry.id, "workspace 不可写：%s" % workspace)]

    if probe:
        try:
            test = workspace / ".doctor-write-test"
            test.write_text("x", encoding="utf-8")
            test.unlink()
        except OSError as exc:
            return [Finding(ERROR, entry.id, "workspace 写不进去：%s" % exc)]
    return []


def _check_requirements(entry) -> List[Finding]:
    req = Path(entry.directory) / "requirements.txt"
    if not req.is_file():
        return []
    missing = []
    for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        dist = re.split(r"[<>=!\[; ]", line, maxsplit=1)[0].strip()
        if dist and not _installed(dist):
            missing.append(dist)
    if missing:
        return [
            Finding(
                ERROR,
                entry.id,
                "缺少依赖：%s。装一下（pip install %s）或者在模块里去掉对它的使用"
                % (", ".join(missing), " ".join(missing)),
            )
        ]
    return []


def _smoke(entry) -> List[Finding]:
    """对每个挂载点发一个 GET /，确认模块不会一进门就炸。"""
    out = []
    for mount in entry.mounts:
        app = entry.apps.get(mount.key)
        if app is None:
            continue
        try:
            with app.test_client() as client:
                resp = client.get("/")
            code = resp.status_code
        except BaseException as exc:  # noqa: BLE001
            out.append(
                Finding(ERROR, entry.id, "挂载点 %r 一访问就炸：%s: %s" % (mount.key, type(exc).__name__, exc))
            )
            continue
        if code >= 500:
            out.append(
                Finding(ERROR, entry.id, "挂载点 %r 的首页返回 %d" % (mount.key, code))
            )
        else:
            out.append(Finding(INFO, entry.id, "挂载点 %s 冒烟通过（HTTP %d）" % (mount.path, code)))
    return out


def summarize(findings: List[Finding]) -> dict:
    counter = {ERROR: 0, WARN: 0, INFO: 0}
    for finding in findings:
        counter[finding.level] = counter.get(finding.level, 0) + 1
    return counter


def has_errors(findings: List[Finding]) -> bool:
    return any(f.level == ERROR for f in findings)
