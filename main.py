#!/usr/bin/env python3
"""vuln4all 靶场的主入口。

直接跑就是启动靶场：

    python main.py                  # 起靶场（默认 127.0.0.1:8800）
    python main.py --port 9000
    python main.py --lan            # 开放到局域网（多人一起打）

其它子命令照常用：

    python main.py list             # 列出所有题目
    python main.py check            # 报告每道题的通关进度
    python main.py doctor           # 体检
    python main.py reset --all      # 全部重置
    python main.py new xss/dom_based

也可以继续用 `python -m vuln4all ...`，两条路等价。

注意：这是故意留洞的靶场，只在本机或隔离环境跑。
"""

from __future__ import annotations

import sys
from pathlib import Path

#: 项目根目录（这个文件所在的地方），靶场的 modules/ 和 workspace/ 都在它下面。
ROOT = Path(__file__).resolve().parent

#: 支持 `python main.py` 这种「什么都不带就启动」的用法
SUBCOMMANDS = ("list", "check", "run", "reset", "doctor", "new")


def _argv() -> list:
    """把裸命令行补成 argparse 认的形式。

    规则：参数里只要有已知子命令就原样交给 argparse（这样 `--home X list`
    这种"全局选项在前、子命令在后"的写法也能正常走）；一个都没有，就默认当 run。
    """
    argv = list(sys.argv[1:])
    if not argv:
        return ["run"]
    if argv[0] in ("-h", "--help"):
        return argv
    if any(token in SUBCOMMANDS for token in argv):
        return argv
    return ["run"] + argv


def main() -> int:
    # 让 `python main.py` 在任意工作目录下都能 import 到 vuln4all
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    from vuln4all.cli import main as cli_main

    return cli_main(_argv(), default_home=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
