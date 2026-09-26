"""运行配置 + 网络信息。

配置优先级：**命令行参数 > vuln4all.ini > 内置默认值**。

在靶场根目录放一个 `vuln4all.ini`，`python3 main.py` 就按它跑，
不用每次敲一长串参数（多人一起打靶场时很有用）：

    [vuln4all]
    host = 0.0.0.0
    port = 8800
    allow_remote = true
    reload = false

`allow_remote = true` 是你对"我知道别人能连进来"的确认。写在配置文件里
就等于确认过了 —— 这种情况下命令行再写 `--host 0.0.0.0` 也能过（配置文件
本身就是那份确认）。

**命令行**显式指定非本机地址、而配置文件里又没确认时，仍然要求 `--lan` 或
`--i-know-what-im-doing` —— 防止手滑把 `--host 127.0.0.1` 敲成 `--host 0.0.0.0`。
"""

from __future__ import annotations

import configparser
import ipaddress
import socket
from pathlib import Path

CONFIG_NAME = "vuln4all.ini"
EXAMPLE_NAME = "vuln4all.ini.example"
SECTION = "vuln4all"

DEFAULTS = {
    "host": "127.0.0.1",
    "port": 8800,
    "allow_remote": False,
    "reload": False,
}

#: 这些值算"只在本机"
LOOPBACK = ("127.0.0.1", "localhost", "::1", "127.0.0.0")

#: 绑这些地址意味着"所有网卡"，需要明确确认
WILDCARD = ("0.0.0.0", "::", "*")


def is_loopback(host: str) -> bool:
    """这个地址算不算"只在本机"。认不出来的一律当**不是**回环（fail-closed）。

    顺带处理几种容易漏的写法：`localhost.`（尾点）、`[::1]`（带方括号）、
    `::ffff:127.0.0.1`（IPv4 映射的 IPv6）。
    """
    host = (host or "").strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.rstrip(".")
    if host in LOOPBACK:
        return True
    if host.startswith("::ffff:"):
        host = host[7:]
    return host.startswith("127.")


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_wildcard(host: str) -> bool:
    return (host or "").strip().lower() in WILDCARD


def _as_bool(value, default=False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value or "").strip().lower()
    if text in ("1", "true", "yes", "on", "y"):
        return True
    if text in ("0", "false", "no", "off", "n"):
        return False
    return default


def read_file(home: Path) -> "tuple[dict, list]":
    """读 vuln4all.ini。返回 (设置, 提示信息)。读不动不算错，报一句就行。"""
    path = Path(home) / CONFIG_NAME
    notes = []
    if not path.is_file():
        return {}, notes

    parser = configparser.ConfigParser(interpolation=None)
    # interpolation=None 很重要：默认的 %-插值会让配置里任何一个百分号
    # （比如带 zone 的 IPv6 fe80::1%eth0）抛异常，然后**整个文件被丢掉** ——
    # 连 host/port 一起静默降回默认值。
    try:
        parser.read(path, encoding="utf-8")
    except (configparser.Error, OSError) as exc:
        notes.append("读 %s 失败（%s），这次用默认值" % (CONFIG_NAME, exc))
        return {}, notes

    if SECTION not in parser:
        notes.append("%s 里没有 [%s] 段，忽略了" % (CONFIG_NAME, SECTION))
        return {}, notes

    section = parser[SECTION]
    found = {}
    if "host" in section:
        found["host"] = section["host"].strip()
    if "port" in section:
        try:
            found["port"] = int(section["port"].strip())
        except ValueError:
            notes.append("%s 里的 port=%r 不是数字，忽略了" % (CONFIG_NAME, section["port"]))
    if "allow_remote" in section:
        found["allow_remote"] = _as_bool(section["allow_remote"])
    if "reload" in section:
        found["reload"] = _as_bool(section["reload"])

    unknown = [k for k in section if k not in ("host", "port", "allow_remote", "reload")]
    if unknown:
        notes.append("%s 里有不认识的键：%s" % (CONFIG_NAME, "、".join(unknown)))

    notes.append("读到了 %s" % path)
    return found, notes


def resolve(home: Path, overrides: "dict | None" = None) -> "tuple[dict, list]":
    """把默认值、配置文件、命令行覆盖合成最终设置。"""
    settings = dict(DEFAULTS)
    file_settings, notes = read_file(home)
    settings.update(file_settings)
    for key, value in (overrides or {}).items():
        if value is not None and key in DEFAULTS:
            settings[key] = value
    try:
        settings["port"] = int(settings["port"])
    except (TypeError, ValueError):
        notes.append("端口 %r 不合法，退回 %d" % (settings["port"], DEFAULTS["port"]))
        settings["port"] = DEFAULTS["port"]
    if not 1 <= settings["port"] <= 65535:
        notes.append(
            "端口 %r 超出 1-65535，退回 %d" % (settings["port"], DEFAULTS["port"])
        )
        settings["port"] = DEFAULTS["port"]
    return settings, notes


def local_ips() -> "list[str]":
    """本机的非回环 IPv4 地址 —— 用来告诉别人「局域网里该访问哪个地址」。

    不依赖任何第三方库：先问一次"默认出口地址"（UDP connect 不会真发包），
    再补上主机名解析出来的地址。

    **私有网段（10/8、172.16/12、192.168/16）排前面。** 否则在开了 VPN /
    Tailscale 的机器上，会把一个别人根本连不上的地址当成"局域网地址"念出来。
    """
    found = set()

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            found.add(probe.getsockname()[0])
        finally:
            probe.close()
    except OSError:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass

    ips = [ip for ip in found if not ip.startswith("127.")]
    return sorted(ips, key=lambda ip: (not is_private_ip(ip), ip))


def url_for(host: str, port: int, path: str = "/") -> str:
    """拼一个给人看的 URL。绑 0.0.0.0 时用回环地址展示。"""
    shown = "127.0.0.1" if is_wildcard(host) else host
    return "http://%s:%d%s" % (shown, port, path)


def reachable_urls(host: str, port: int, path: str = "/") -> "list[tuple]":
    """返回 [(标签, URL)]，启动时打给用户看。"""
    urls = [("本机", url_for("127.0.0.1", port, path))]
    if not is_loopback(host):
        for ip in local_ips():
            label = "局域网" if is_private_ip(ip) else "其他"
            urls.append((label, url_for(ip, port, path)))
    return urls
