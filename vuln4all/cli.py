"""命令行入口：list / run / reset / new / doctor。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import config
from . import doctor as doctor_mod
from . import host as host_mod
from .paths import find_home
from .registry import Registry

DEFAULT_PORT = config.DEFAULTS["port"]

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

    # 命令行 > vuln4all.ini > 默认值。argparse 那边用了 SUPPRESS，
    # 所以"用户没写"和"用户写了默认值"能区分开。
    overrides = {key: getattr(args, key) for key in ("host", "port", "reload") if hasattr(args, key)}
    if getattr(args, "lan", False):
        # 只在用户没显式写 --host 时才替他把地址定成 0.0.0.0。
        # 否则 `--lan --host 192.168.1.5` 会被悄悄放大成"所有网卡"，
        # 比用户要求的更宽 —— 这种"帮忙"很危险。
        if "host" not in overrides:
            overrides["host"] = "0.0.0.0"
        overrides["allow_remote"] = True
    if getattr(args, "i_know_what_im_doing", False):
        overrides["allow_remote"] = True

    settings, notes = config.resolve(args.home, overrides)
    host = str(settings["host"])
    port = int(settings["port"])
    reload_ = bool(settings["reload"])

    print(RULE)
    print("  vuln4all 靶场  ——  故意有漏洞，只在本机或隔离环境跑")
    print("  绝不要把它暴露到公网 / 生产网络 / 你能被访问到的任何地址")
    print(RULE)

    for note in notes:
        print("配置：%s" % note)
    if notes:
        print()

    if not config.is_loopback(host) and not settings["allow_remote"]:
        print(RULE)
        if config.is_wildcard(host):
            print("  你正在把靶场绑到 %s —— 同网段的所有人都能连进来打这些漏洞。" % host)
        else:
            print("  你正在把靶场绑到 %s —— 那里的人能连进来打这些漏洞。" % host)
        print()
        print("  确认要这么做，二选一：")
        print("    · 命令行加 --lan")
        print("    · 在 vuln4all.ini 里写 allow_remote = true")
        print(RULE)
        return 2

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

    app = host_mod.build(registry, args.home)

    print()
    for label, url in config.reachable_urls(host, port, "/"):
        print("  %-6s %s" % (label, url))
    for label, url in config.reachable_urls(host, port, "/__vuln4all/status"):
        print("  %-6s %s" % (label, url))

    if not config.is_loopback(host):
        print()
        print(RULE)
        print("  已经开放到局域网。两件必须知道的事：")
        print("  1. 所有题目的数据是**共享**的 —— 谁点了「重置」，大家的进度一起清空。")
        print("     单进程架构就是互相干扰的，多人同时打请各自拿一个副本。")
        print("  2. 这些漏洞是真的。别把这个地址带到公网、别用真数据、别连生产网。")
        print(RULE)

    print("\n（Ctrl+C 停止）\n")

    # 显式 flush：nohup / systemd 下 stdout 是块缓冲的，不刷一下的话
    # 上面这些地址和警告会一直卡在缓冲区里 —— 进程被 kill 就全丢了，
    # 用户只看到一个"起来了但什么都没说"的空白日志。
    sys.stdout.flush()

    from werkzeug.serving import run_simple

    try:
        run_simple(
            host,
            port,
            app,
            use_reloader=reload_,
            use_debugger=False,
            # 一定要多线程：否则一个请求里再往自己发请求（很多题会这么干）会死锁
            threaded=True,
            extra_files=registry.watched_files() if reload_ else None,
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


# ------------------------------------------------------------- 通关进度


def cmd_check(args) -> int:
    registry = _load(args.home)
    report = registry.check_report()

    want = args.module.strip("/") if args.module else None
    if want and registry.get(want) is None:
        print("没有这个题目：%s" % args.module, file=sys.stderr)
        return 2

    # 加载失败和 check 出错都不是"跑通了"，退出码要反映出来
    exit_code = 1 if (report["errored"] or report["failed"]) else 0

    if args.json:
        payload = report
        if want:
            # --json 也要尊重位置参数，不然脚本会以为拿到的是单题结果
            payload = dict(
                report,
                modules=[m for m in report["modules"] if m["id"] == want],
            )
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False))
        return exit_code

    rows = [m for m in report["modules"] if want is None or m["id"] == want]
    for item in rows:
        if not item["loaded"]:
            print("  ??   %-36s 加载失败" % item["id"])
            continue
        if not item["supported"]:
            print("  --   %-36s 没实现 check()" % item["id"])
            continue
        print("  %-3s %-36s %s" % ("OK" if item["solved"] else "--", item["id"],
                                  "已通关" if item["solved"] else "未通关"))
        for name, done in item["objectives"].items():
            print("         [%s] %s" % ("x" if done else " ", name))
        if item["error"]:
            print("         !! %s" % item["error"])

    print()
    print(
        "  已通关 %d / %d（%d 道实现了 check()，%d 道 check 出错，%d 道加载失败）"
        % (report["solved"], report["total"], report["supported"],
           report["errored"], report["failed"])
    )
    print("  机器可读版本：vuln4all check --json，或者 GET %s" % "/__vuln4all/check")
    return exit_code


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

    p_check = sub.add_parser(
        "check",
        help="报告每道题的通关进度",
        description="跑每道题的 check()，报告当前进度。退出码只在有题目出错时才非 0。",
    )
    p_check.add_argument("module", nargs="?", default=None, help="只看某一道题")
    p_check.add_argument("--json", action="store_true", help="输出 JSON（给脚本用）")
    p_check.set_defaults(func=cmd_check)

    p_run = sub.add_parser(
        "run",
        help="启动靶场",
        description="启动靶场。host/port 的优先级：命令行 > vuln4all.ini > 默认值。",
    )
    # 默认用 SUPPRESS：这样“用户没写”和“用户写了默认值”能区分开，
    # 配置文件里的值才有机会生效。
    p_run.add_argument(
        "--host",
        default=argparse.SUPPRESS,
        help="绑定地址。默认 127.0.0.1（只本机）；0.0.0.0 表示所有网卡",
    )
    p_run.add_argument(
        "--port",
        type=int,
        default=argparse.SUPPRESS,
        help="端口，默认 %d" % DEFAULT_PORT,
    )
    p_run.add_argument(
        "--lan",
        action="store_true",
        help="开放到局域网：等价于 --host 0.0.0.0，并且算作“我知道别人能连进来”的确认",
    )
    p_run.add_argument(
        "--reload",
        action="store_true",
        default=argparse.SUPPRESS,
        help="改了模块文件自动重启（开发时用，多人玩的时候别开）",
    )
    p_run.add_argument(
        "--no-reload",
        dest="reload",
        action="store_false",
        default=argparse.SUPPRESS,
        help="关掉配置文件里的 reload = true",
    )
    p_run.add_argument(
        "--i-know-what-im-doing",
        dest="i_know_what_im_doing",
        action="store_true",
        help="显式指定非本机地址时，用它确认你知道后果（--lan 也能起同样作用）",
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


def main(argv=None, default_home=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    if getattr(args, "home", None) is None:
        # main.py 会把自己的位置传进来，保证在任意工作目录下都能找到 modules/
        args.home = Path(default_home).resolve() if default_home else find_home()
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
