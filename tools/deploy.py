#!/usr/bin/env python3
"""把 vuln4all 同步到一台远端主机上跑。

本机不要跑这个靶场 —— 它是故意留洞的。开发在本地，验证在远程。

    python3 tools/deploy.py --host 192.168.44.149 --user root --password root \
        --path /root/Desktop/vuln4all

推完之后可以直接带 --run 跑命令：

    python3 tools/deploy.py ... --run "python3 -m vuln4all doctor"

依赖 paramiko（走密码 SSH）。Kali 上装：apt install python3-paramiko
"""

from __future__ import annotations

import argparse
import os
import posixpath
import sys
from pathlib import Path

try:
    import paramiko
except ImportError:  # pragma: no cover
    print("需要 paramiko。Kali 上：apt install python3-paramiko", file=sys.stderr)
    raise SystemExit(2)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: 这些东西不往远端推
EXCLUDE_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "workspace",
    "build",
    "dist",
    ".pytest_cache",
}
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".swp", ".log")


def iter_files(root: Path):
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for name in filenames:
            if name.endswith(EXCLUDE_SUFFIXES):
                continue
            path = Path(current) / name
            yield path, path.relative_to(root).as_posix()


def connect(args):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("连接 %s@%s:%d …" % (args.user, args.host, args.port))
    client.connect(
        args.host,
        port=args.port,
        username=args.user,
        password=args.password,
        timeout=args.timeout,
        banner_timeout=args.timeout,
        auth_timeout=args.timeout,
    )
    return client


def run(client, command: str, quiet: bool = False) -> int:
    if not quiet:
        print("$ %s" % command)
    _stdin, stdout, stderr = client.exec_command(command, timeout=600)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.rstrip())
    if err.strip():
        print(err.rstrip(), file=sys.stderr)
    return code


def make_dirs(sftp, remote_root: str, relative_dirs) -> None:
    wanted = {remote_root}
    for rel in relative_dirs:
        parts = rel.split("/")
        for index in range(1, len(parts) + 1):
            wanted.add(posixpath.join(remote_root, *parts[:index]))
    for path in sorted(wanted, key=len):
        try:
            sftp.stat(path)
        except IOError:
            sftp.mkdir(path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="把 vuln4all 同步到远端主机")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", default=None)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--path", required=True, help="远端项目根目录")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--run", default=None, help="同步完成后在远端跑的命令")
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="顺便删掉远端 workspace/（靶场运行时数据，会被 setup() 重新生成）",
    )
    parser.add_argument("--root", default=str(PROJECT_ROOT), help="本地要推的目录")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if not args.password:
        import getpass

        args.password = getpass.getpass("SSH 密码：")

    local_root = Path(args.root).resolve()
    if not (local_root / "vuln4all").is_dir():
        print("本地 %s 下没有 vuln4all/，--root 给错了吧？" % local_root, file=sys.stderr)
        return 2

    client = connect(args)
    try:
        sftp = client.open_sftp()

        if args.fresh:
            target = posixpath.join(args.path, "workspace")
            print("清掉远端 %s（靶场的运行时数据，下一次启动会重新 setup）" % target)
            run(client, "rm -rf %s" % target, quiet=args.quiet)

        print("建目录 %s" % args.path)
        run(client, "mkdir -p %s" % args.path, quiet=args.quiet)
        make_dirs(sftp, args.path, [])

        entries = list(iter_files(local_root))
        dirs = {posixpath.dirname(rel) for _path, rel in entries if posixpath.dirname(rel)}
        make_dirs(sftp, args.path, dirs)

        uploaded = 0
        for path, rel in entries:
            remote = posixpath.join(args.path, rel)
            sftp.put(str(path), remote)
            uploaded += 1
            if not args.quiet:
                print("  → %s" % rel)

        sftp.close()
        print("\n推了 %d 个文件到 %s:%s" % (uploaded, args.host, args.path))

        if args.run:
            print()
            code = run(client, "cd %s && %s" % (args.path, args.run))
            return code
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
