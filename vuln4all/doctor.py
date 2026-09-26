"""体检：一个模块写得合不合规、能不能跑起来。

`vuln4all doctor` 就是跑这一套。CI 里也应该跑它 —— 这是「别人敢提交模块」
的前提，不然模块质量会烂得很快。
"""

from __future__ import annotations

import importlib.metadata
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .contract import RECOMMENDED_INFO
from .loader import ENTRY_FILE
from .registry import Registry

ERROR = "error"
WARN = "warn"
INFO = "info"

#: 疑似硬编码绝对路径的写法。跨挂载点链接必须走 ctx.url()，否则挂载点一改就烂。
_HARDCODED_URL_PATTERNS = [
    (re.compile(r"""href\s*=\s*["']/"""), 'href="/…"'),
    (re.compile(r"""action\s*=\s*["']/"""), 'action="/…"'),
    (re.compile(r"""src\s*=\s*["']/"""), 'src="/…"'),
    (re.compile(r"""redirect\(\s*["']/"""), 'redirect("/…")'),
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
        if entry.error:
            findings.append(Finding(ERROR, entry.id, entry.error))
            continue

        for problem in entry.problems:
            findings.append(Finding(ERROR, entry.id, problem))
        for warning in entry.warnings:
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

        findings.extend(_check_source(entry))
        findings.extend(_check_workspace(entry))
        findings.extend(_check_requirements(entry))

        if smoke:
            findings.extend(_smoke(entry))

    return findings


def _check_source(entry) -> List[Finding]:
    source = Path(entry.directory) / ENTRY_FILE
    if not source.is_file():
        return []
    text = source.read_text(encoding="utf-8", errors="replace")
    if len([m for m in entry.mounts if m.key != ""]) == 0:
        # 只有一个挂载点，硬编码路径的危害小一些，但仍然提醒
        pass
    hits = sorted({label for pattern, label in _HARDCODED_URL_PATTERNS if pattern.search(text)})
    if hits:
        return [
            Finding(
                WARN,
                entry.id,
                "疑似硬编码了绝对路径（%s）。跨挂载点的链接请用 ctx.url()，"
                "自己应用内部的路由请用 url_for()，否则改挂载点时会静默烂掉" % "、".join(hits),
            )
        ]
    return []


def _check_workspace(entry) -> List[Finding]:
    if entry.ctx is None:
        return []
    workspace = entry.ctx.workspace
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        probe = workspace / ".doctor-write-test"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return [Finding(ERROR, entry.id, "workspace 不可写：%s" % exc)]
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
