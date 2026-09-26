"""命令行入口：list / run / reset / new / doctor。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import doctor as doctor_mod
from . import host as host_mod
from .paths import find_home
from .registry import Registry

DEFAULT_PORT = 8800
LOOPBACK = ("127.0.0.1", "localhost", "::1")

RULE = "=" * 74


def _load(home: Path, setup: bool = True) -> Registry:
    return Registry.discover(home, setup=setup)


# ----------------------------------------------------------------- 列出题目


def cmd_list(args) -> int:
    registry = _load(args.home, setup=False)
    if not registry.entries:
        print("modules/ 下一个题目都没有。用 `vuln4all new <分类>/<名字>` 起个头。")
        return 0

    for category, entries in registry.categories():
        if args.category and category != args.category:
            continue
        print("\n[%s]" % category)
        for entry in entries:
            if entry.error:
                print("  !! %-28s 加载失败：%s" % (entry.id, entry.error))
                continue
            cwe = entry.info.get("cwe") or "-"
            print("  %-32s %s" % (entry.id, entry.display_name))
            print("  %-32s %s  挂载 %s" % ("", cwe, entry.main_path + "/"))
            extra = [m for m in entry.mounts if m.key]
            if extra:
                for mount in extra:
                    tag = "隐藏" if mount.hidden else "公开"
                    print("  %-32s └─ [%s] %s/" % ("", tag, mount.path))
    print()
    return 0


# ----------------------------------------------------------------- 启动靶场


def cmd_run(args) -> int:
    registry = _load(args.home)

    print(RULE)
    print("  vuln4all 靶场  ——  故意有漏洞，只在本机或隔离环境跑")
    print("  绝不要把它暴露到公网 / 生产网络 / 你能被访问到的任何地址")
    print(RULE)
    print("挂载情况：")
    print(host_mod.describe_mounts(registry))

    failed = registry.failed()
    if failed:
        print("\n下面这些题目没加载成功（不影响其他题目）：")
        for entry in failed:
            print("  !! %s：%s" % (entry.id, entry.error))
    if registry.conflicts:
        print("\n挂载点冲突：")
        for conflict in registry.conflicts:
            print("  !! %s" % conflict)

    if args.host not in LOOPBACK and not args.i_know_what_im_doing:
        print(RULE)
        print("  你正在把靶场绑到 %s —— 别人能扫到你这些漏洞。" % args.host)
        print("  真要这么干，请加上 --i-know-what-im-doing")
        print(RULE)
        return 2

    app = host_mod.build(registry, args.home)

    shown_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    print("\n首页：http://%s:%d/" % (shown_host, args.port))
    print("体检：http://%s:%d/__vuln4all/status\n" % (shown_host, args.port))

    from werkzeug.serving import run_simple

    try:
        run_simple(
            args.host,
            args.port,
            app,
            use_reloader=args.reload,
            use_debugger=False,
            # 一定要多线程：否则一个请求里再往自己发请求（很多题会这么干）会死锁
            threaded=True,
            extra_files=registry.watched_files() if args.reload else None,
        )
    except KeyboardInterrupt:
        print("\n已停止。")
    return 0


# ------------------------------------------------------------------- 重置


def cmd_reset(args) -> int:
    registry = _load(args.home)
    if args.all:
        targets = registry.loaded()
        if not targets:
            print("没有可重置的题目。")
            return 0
    else:
        if not args.module:
            print("要重置哪一道？给个 id，或者用 --all 重置全部。", file=sys.stderr)
            return 2
        entry = registry.get(args.module)
        if entry is None:
            print("没有这个题目：%s" % args.module, file=sys.stderr)
            return 2
        targets = [entry]

    failed = 0
    for entry in targets:
        try:
            registry.reset(entry)
        except Exception as exc:  # noqa: BLE001
            # 一道题炸了不该让剩下的题都重置不了
            print("  !! %s 重置失败：%s: %s" % (entry.id, type(exc).__name__, exc))
            failed += 1
            continue
        print("  已重置 %s" % entry.id)

    if failed:
        print("\n有 %d 道题没重置成功。" % failed, file=sys.stderr)
        return 1
    return 0


# ------------------------------------------------------------------- 体检


def cmd_doctor(args) -> int:
    registry = _load(args.home, setup=args.smoke)
    findings = doctor_mod.check(registry, smoke=args.smoke)

    if args.module:
        findings = [f for f in findings if f.scope in (args.module, "core")]

    labels = {doctor_mod.ERROR: "错误", doctor_mod.WARN: "警告", doctor_mod.INFO: "提示"}
    for finding in findings:
        print("[%s] %-28s %s" % (labels.get(finding.level, finding.level), finding.scope, finding.message))

    summary = doctor_mod.summarize(findings)
    print(
        "\n共 %d 个模块：%d 个错误、%d 个警告、%d 条提示"
        % (
            len(registry.entries),
            summary.get(doctor_mod.ERROR, 0),
            summary.get(doctor_mod.WARN, 0),
            summary.get(doctor_mod.INFO, 0),
        )
    )
    return 1 if doctor_mod.has_errors(findings) else 0


# ------------------------------------------------------------------- 新建


def cmd_new(args) -> int:
    from .scaffold import create_module

    module_id = args.module_id.replace("\\", "/").strip("/")
    if module_id.count("/") != 1 or not all(module_id.split("/")):
        print(
            "格式是 <分类>/<名字>，例如 sqli/login_bypass、xss/reflect_search",
            file=sys.stderr,
        )
        return 2

    directory = args.home / "modules" / module_id
    if directory.exists() and not args.force:
        print("%s 已经存在了。要覆盖请加 --force" % directory, file=sys.stderr)
        return 2

    created = create_module(directory, module_id, force=args.force)
    print("建好了：")
    for path in created:
        print("  %s" % path.relative_to(args.home))
    print("\n接着改 %s 就行。" % (directory / "module.py").relative_to(args.home))
    return 0


# ------------------------------------------------------------------- 装配


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln4all",
        description="模块化 Web 漏洞靶场 —— 丢一个模块进去，就多一道题",
    )
    parser.add_argument(
        "--home",
        type=Path,
        default=None,
        help="靶场根目录（含 modules/）。默认自动往上找。",
    )
    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser("list", help="列出所有题目")
    p_list.add_argument("--category", default=None, help="只看某一类")
    p_list.set_defaults(func=cmd_list)

    p_run = sub.add_parser("run", help="启动靶场")
    p_run.add_argument("--host", default="127.0.0.1", help="绑定地址，默认只绑本机")
    p_run.add_argument("--port", type=int, default=DEFAULT_PORT, help="端口，默认 %d" % DEFAULT_PORT)
    p_run.add_argument("--reload", action="store_true", help="改了模块文件自动重启")
    p_run.add_argument(
        "--i-know-what-im-doing",
        dest="i_know_what_im_doing",
        action="store_true",
        help="允许绑到非本机地址",
    )
    p_run.set_defaults(func=cmd_run)

    p_reset = sub.add_parser("reset", help="把题目恢复出厂")
    p_reset.add_argument("module", nargs="?", default=None, help="题目 id")
    p_reset.add_argument("--all", action="store_true", help="重置全部")
    p_reset.set_defaults(func=cmd_reset)

    p_doc = sub.add_parser("doctor", help="体检：检查模块合不合规")
    p_doc.add_argument("module", nargs="?", default=None, help="只看某一道题")
    p_doc.add_argument("--no-smoke", action="store_true", help="跳过冒烟请求")
    p_doc.set_defaults(func=cmd_doctor, smoke=True)

    p_new = sub.add_parser("new", help="生成一个新题目的骨架")
    p_new.add_argument("module_id", metavar="<分类>/<名字>", help="例如 sqli/login_bypass")
    p_new.add_argument("--force", action="store_true", help="已存在也覆盖")
    p_new.set_defaults(func=cmd_new)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    if getattr(args, "home", None) is None:
        args.home = find_home()
    else:
        args.home = Path(args.home).expanduser().resolve()

    if hasattr(args, "no_smoke") and args.no_smoke:
        args.smoke = False

    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
