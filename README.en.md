# vuln4all

[中文](README.md) · **English**

**A modular web vulnerability range. Drop a module in, get a new challenge.**

Like Metasploit: you don't touch the core, you don't register anything in a table, and
you don't edit anyone else's files. Drop a `module.py` into
`modules/<category>/<name>/`, restart, and it shows up on the index page.

Author: **guaidao2**

To add a challenge, see the **[module development guide](docs/DEVELOPMENT.md)**.
That document is in Chinese only, so this README carries a compact English version of
the module contract (see [Module contract](#module-contract) below) — enough to write a
working module without reading Chinese.

> **Warning: this range contains deliberate vulnerabilities. Run it locally, or in an
> isolated VM. Never expose it to the public internet, a production network, or any
> address other people can reach.**
>
> The vulnerabilities are real, and **isolation between modules is zero** — see
> [What this does not do](#what-this-does-not-do).

---

## Run it

```bash
python3 main.py
```

That is the whole thing. By default it binds `127.0.0.1:8800` only.

**To run it on a LAN (for a group):**

```bash
python3 main.py --lan            # binds 0.0.0.0, and counts as "I know others can connect"
```

On startup it prints both the **local** and the **LAN** address, so you can just hand the
LAN one to whoever needs it.

A config file is easier if you do this often:

```bash
cp vuln4all.ini.example vuln4all.ini
# then edit host / port / allow_remote
```

Precedence: **command line > `vuln4all.ini` > defaults**.

Two things you must know once it is on a LAN:

1. **All challenge state is shared.** Whoever clicks "reset" wipes everyone's progress.
   Single-process architecture is mutually interfering by design — for a group, give
   each person their own copy.
2. These vulnerabilities are real. Keep it off the public internet, don't use real data,
   and don't point it at a production network.

Then open <http://127.0.0.1:8800/>:

- `/` — the challenge index (generated automatically; grouped by category, with search
  plus category and difficulty filters)
- `/__vuln4all/status` — the health-check page
- every challenge page has a "reset this challenge" button and two collapsible sections:
  **hint** and **solution**

## Commands

`main.py` is the entry point. With no subcommand it starts the range:

```bash
python3 main.py                        # start the range (127.0.0.1:8800)
python3 main.py --lan                  # expose it on the LAN
python3 main.py --port 9000            # change the port
python3 main.py list                   # list every challenge
python3 main.py list --category sqli   # only one category
python3 main.py check                  # report progress for every challenge
python3 main.py check --json           # same, machine readable
python3 main.py reset sqli/login_bypass  # factory-reset one challenge
python3 main.py reset --all            # reset everything
python3 main.py doctor                 # health check: are the modules valid and loadable?
python3 main.py new xss/dom_based      # scaffold a new challenge
```

Once installed as a package, `vuln4all <subcommand>` and `python3 -m vuln4all <subcommand>`
are equivalent.

`python3 main.py doctor` exits non-zero when there are errors, so you can wire it into CI.

## Add a challenge

**One directory, one `module.py`, one set of templates. That's it.**

```bash
python3 main.py new sqli/login_bypass
```

The scaffold **runs immediately**, and then you add the vulnerability:

```python
"""SQL injection at the login form"""

from vuln4all import Vuln, render_template, request, redirect, url_for


class LoginBypass(Vuln):
    info = {
        "name": "SQL injection at the login form",
        "author": ["your name"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "description": "One sentence on where the flaw is.",
        "hint": "A nudge for the learner: what to try first, what to look at. Don't give the answer.",
        "solution": "How to break it, ideally with a payload that can be copy-pasted.",
        "refs": ["https://portswigger.net/web-security/sql-injection"],
    }

    def setup(self, ctx):
        """Runs once on first start, and again after every reset. Seed data here."""
        (ctx.workspace / "data.db").write_bytes(b"...")

    def create_app(self, ctx):
        app = ctx.flask(__name__)

        @app.route("/")
        def index():
            return render_template("index.html")

        return {"": app}      # the "" key is the main mount
```

## Module contract

### Required

| Member | Meaning |
|---|---|
| `info: dict` | must contain `name` and `description`; everything else is optional |
| `create_app(ctx) -> dict` | returns `{mount key: WSGI app}`; `""` is the main mount |

### Optional

| Member | When you need it |
|---|---|
| `setup(ctx)` | seed initial data. Called on first run and after every reset |
| `reset(ctx)` | **only if your module keeps state in process memory** |
| `check(ctx) -> bool` | machine-readable "is this solved yet?" |

### What goes in `info`

| Key | Meaning |
|---|---|
| `name` / `description` | **required** |
| `author` / `cwe` / `owasp` / `refs` | recommended; shown on the index and the challenge page |
| `difficulty` | recommended. The values are the Chinese labels `入门` / `进阶` / `困难` (easy / medium / hard). It is a **label only** — the core branches on nothing. Other values still run; `doctor` will mention it |
| `hint` / `solution` | recommended; rendered as the two collapsible sections — the heart of a teaching range |
| `mounts` | override mount paths and mark hidden entries, see below |

`description`, `hint` and `solution` support two pieces of markup: `**bold**` and
`` `monospace` ``. Everything else is treated as plain text.

## Multiple mounts

A challenge can have several entry points. That is how the SSRF challenge gets its
"internal service" and the CSRF challenge gets its "attacker site":

```python
info = {
    ...
    "mounts": {
        # default is /v/<module-id>/<key>/ — override it to any path:
        "attacker": {"path": "/evil-site"},
        # or hide it so it doesn't show up on the index page:
        "internal": {"path": "/internal/admin", "hidden": True},
    },
}

def create_app(self, ctx):
    portal = ctx.flask(__name__)                     # main entry
    evil   = ctx.flask(__name__, mount="attacker")   # second entry
    return {"": portal, "attacker": evil}
```

**On a multi-mount module you must pass `mount="key"` to `ctx.flask()`.** That call also
isolates the session cookie name and path per mount — without it, several mounts under
the same hostname overwrite each other's sessions, and the failure is very hard to trace.
**`doctor` checks this**: a mount key returned by `create_app()` that was never registered
through `ctx.flask()` is an error.

Mount collisions are refused outright: if a path hits a reserved core prefix
(`/__vuln4all`, `/v`) or another module got there first, that mount is **removed** (not
just warned about) and `doctor` reports ERROR. If the main mount is the one removed, the
challenge is marked as failed to load — a broken challenge must not displace another
challenge or the core's health-check page.

## Generating URLs

**Never hardcode a path that starts with `/`.** The prefix is assigned by the core, and it
will rot silently when a mount path changes.

| Situation | Use |
|---|---|
| A route inside your own app | `url_for('function_name')` — Flask's own; the prefix is added for you |
| Across mounts (going to another entry) | `ctx.url("key", "/path")` |

```python
ctx.url("", "/login")          # -> /v/sqli/login_bypass/login
ctx.url("attacker", "/")       # -> /evil-site/
```

`vuln4all doctor` reports hardcoded absolute paths as warnings.

## State and reset

Every module gets a **private directory**: `ctx.workspace`, which is
`workspace/<module-id>/`, with `/` in the module id expanding into directory levels.
So `sqli/login_bypass` gets `workspace/sqli/login_bypass/`. Everything a module persists
(sqlite files, uploads, …) goes there, and modules are physically separated.

Reset is three steps, all handled by the core:

```
remove the init marker  ->  wipe workspace/<module-id>/  ->  run setup(ctx) again
```

The marker is removed first so that if the process dies halfway, the next start re-runs
`setup()` instead of seeing a non-empty directory and assuming it was initialised. The
whole thing holds a lock, so concurrent resets can't interleave into a half-dead
directory.

So **as long as your `setup()` is repeatable, you write zero reset code**. The "reset this
challenge" button and `python3 main.py reset` both take this path.

Only if you keep state in process memory (a shared counter for a race-condition
challenge, say) do you need to implement `reset(ctx)` yourself — or just restart the
process, which under a single-process architecture is the most thorough reshuffle there is.

## Project layout

```
vuln4all/
├── main.py                      # entry point: python3 main.py starts the range
├── vuln4all.ini.example         # config template (copy to vuln4all.ini to use)
├── vuln4all/                    # the core
│   ├── contract.py              #   Vuln base class + Ctx (the module contract)
│   ├── config.py                #   runtime config (host/port) + local IP detection
│   ├── registry.py              #   discover modules/, load, assign mounts, find collisions
│   ├── loader.py                #   importlib dynamic import; a broken module doesn't take down the rest
│   ├── host.py                  #   prefix dispatch, assembled into one WSGI app
│   ├── doctor.py                #   health check
│   ├── scaffold.py              #   skeleton generation for the `new` subcommand
│   ├── ui.py                    #   index page / status page / reset entry
│   ├── cli.py                   #   command line
│   ├── templates/vuln4all/      #   the shared shell, base.html and friends
│   └── static/style.css         #   design system
├── modules/                     # <- every challenge lives here, one directory each
│   ├── sqli/login_bypass/
│   ├── xss/dom_based/
│   ├── ...                      #   46 challenges across 20 categories — see the table below
├── tools/                       # helper scripts
│   ├── deploy.py                #   sync a copy of the project to another machine
│   └── verify.sh                #   end-to-end verification: start the range and attack every challenge
└── workspace/                   # created at runtime; per-challenge private data, safe to delete
```

Several challenges can share one category. The three SQLi entries in a row under
`sqli/` are deliberate: they teach three different things (closing a quote → UNION →
blind), and merging them into one challenge would teach none of them.

The five "filter bypass" challenges are a group with a different shape: the vulnerability
itself is the same as another challenge in the same category, and what's added is a
filter. The point becomes "a filter describes what an attack *looks like*, not what
structure is dangerous". Each filter lives inside its own module (a small regex ruleset);
nothing external is involved.

The four `business_logic` challenges are a third shape: not variants of one bug, but four
scenarios of one **way of thinking** (change a value → change a combination → change a
count → change an order). What they share is "every individual validation is correct" —
what's missing is something structural: combination checks, idempotency, a state model.

## The challenges

46 challenges across 20 categories. The `difficulty` column shows the Chinese labels the
code actually stores — `入门` (easy) / `进阶` (medium) / `困难` (hard) — as a label only.

| Difficulty | Challenge | Scenario | The flaw |
|---|---|---|---|
| 入门 | `sqli/login_bypass` | Employee login | String-concatenated SQL; `admin' --` |
| 进阶 | `sqli/union_query` | Product search | UNION works, but the page shows no errors — count columns and find the display position yourself |
| 困难 | `sqli/time_blind` | Badge lookup | The page never changes; response time is the only signal |
| 困难 | `sqli/keyword_filter` | Staff directory | The blacklist matches literals; `UNION  SELECT` with two spaces gets through |
| 入门 | `sqli/numeric_injection` | Parcel tracking | A numeric injection point needs no quote at all — "escape the quotes" does nothing here |
| 进阶 | `sqli/order_by_injection` | Product listing | No UNION in `ORDER BY`; the sort order itself is the channel |
| 进阶 | `sqli/identifier_injection` | Analytics dashboard | Parameterisation can't reach identifiers; schema qualification and a subquery both bypass the blacklist |
| 困难 | `sqli/boolean_blind` | Coupon lookup | Only a boolean left; binary search / `hex()` / `group_concat` for speed |
| 困难 | `sqli/sleepless_time_blind` | Ticket lookup | No `SLEEP()` available — a recursive CTE as a CPU burner |
| 困难 | `sqli/second_order` | Password change | The injection point is a username read back out of the database; parameterisation was only half done |
| 入门 | `xss/reflect_search` | Site search | `\|safe` turns off Jinja's autoescaping |
| 入门 | `xss/stored_guestbook` | Guestbook | The payload is stored, so it fires on every later page view |
| 进阶 | `xss/dom_based` | Welcome page | Front-end JS builds `innerHTML` from `location`; the server never sees it |
| 困难 | `xss/tag_filter` | Signature wall | A stripping filter is reversible; `<scr<script>ipt>` reassembles after removal |
| 入门 | `idor/order_detail` | Order centre | Looks up by order number without checking ownership (horizontal) |
| 进阶 | `idor/admin_endpoint` | Internal tools | The admin entry is only `display:none`, and the endpoint never checks the role (vertical) |
| 入门 | `path_traversal/file_download` | Company file share | `os.path.join` defeated by `../` and absolute paths |
| 困难 | `path_traversal/encoding_filter` | Company file share | The filter and the decoding layer disagree; double encoding plus encoding one character of a sensitive word |
| 入门 | `ssti/jinja2_profile` | Team SaaS | User input is rendered as a Jinja2 template |
| 困难 | `ssti/sandbox_escape` | Welcome message | A self-relaxed sandbox blocklist misses `__getattribute__` |
| 进阶 | `csrf/password_change` | Account page + attacker site | The password-change endpoint ignores where the request came from |
| 进阶 | `csrf/json_api` | Account page + attacker site | The endpoint parses JSON without checking Content-Type; a `text/plain` form can forge it |
| 进阶 | `upload/avatar` | Avatar upload | A case-sensitive extension blacklist plus trusting the client's Content-Type |
| 困难 | `upload/zip_slip` | Bulk avatar archive | A hand-written extraction loop treats a zip member name as a path |
| 困难 | `upload/tar_symlink` | Theme package | `tarfile.extractall()` filters nothing by default; a symlink can point outside |
| 进阶 | `command_injection/ping_tool` | Ops diagnostics panel | User input concatenated into a shell command |
| 困难 | `command_injection/space_filter` | Ops diagnostics panel | The separator blacklist misses newline; spaces become `${IFS}` |
| 进阶 | `ssrf/url_preview` | Chat link preview | The allowlist does substring matching; `@` gets past it |
| 困难 | `ssrf/ip_format_filter` | Chat link preview | The blacklist lists IP literals; another notation (decimal / hex / octal) walks through |
| 困难 | `jwt/kid_injection` | Open API platform | The signing key is chosen by the token's own `kid`; `kid=/dev/null` means an empty key |
| 困难 | `deserialization/pickle_cookie` | Account preferences | Preferences serialised into a cookie; `pickle.loads` runs arbitrary code |
| 困难 | `xxe/svg_preview` | Icon library | External entities were explicitly enabled; `<!ENTITY ... SYSTEM "file://...">` reads files |
| 进阶 | `cors/credentials` | Partner API | Reflects any Origin and allows credentials; the allowlist does substring matching |
| 入门 | `open_redirect/login_next` | Unified login | `//evil.example` and a domain substring both fool the "internal redirect" check |
| 进阶 | `host_header/password_reset` | Forgot password | The reset link's hostname comes from a request header; the trusted list does substring matching |
| 入门 | `business_logic/price_tamper` | Points shop | Unit price and quantity both come from the client |
| 进阶 | `business_logic/coupon_stacking` | Points shop | Every value is legal; what's missing is a combination check, and a field name can be sent twice |
| 进阶 | `business_logic/refund_logic` | Points shop | The refund amount comes from the client, and nothing records that a refund happened — refund one order many times |
| 困难 | `business_logic/state_machine` | Points shop | "Refunded" is a boolean field, not a state, so an order can be refunded and then confirmed as received |
| 入门 | `info_leak/backup_files` | Static site | `.env` / `.git` / backups sit in the document root; just request them |
| 困难 | `sqli/quote_filter` | Inventory lookup | Quotes, comments and `union` are all blocked; a numeric point needs no quote, and `char()` builds literals |
| 进阶 | `xss/js_context` | Site search | The value is embedded in a JS string inside `<script>`; `</script>` ends the element, and the filter only blocks the opening tag |
| 困难 | `dos/regex_backtracking` | Article tagging | Catastrophic backtracking: a 27-byte input stalls validation for 3 seconds, and every 2 more characters multiplies that by 4 |
| 进阶 | `flask_session/forged_cookie` | Subscription SaaS | A weak secret is hardcoded, so sessions can be signed by anyone |
| 困难 | `race_condition/coupon_redeem` | Limited-time coupon | check-then-act is not atomic; concurrent redemption |
| 困难 | `jwt/alg_none` | Open API platform | The verification algorithm is read from the `alg` the token declares about itself |

## Frontend

`vuln4all/static/style.css` is a self-contained design system, and `base.html` is the
shell. A module template that does `{% extends "vuln4all/base.html" %}` gets the challenge
page header, the hint/solution sections and the reset button for free.

These class names are a **public API**. Restyle them freely, but renaming one means
updating every module:

| Class | Purpose |
|---|---|
| `btn` / `btn-ghost` | buttons |
| `payload` | monospace blocks: command lines, payloads |
| `findings` | data tables (order lists, health-check results) |
| `mono` / `muted` / `err` / `ok` / `small` | text styles |
| `badge` / `tag` | small badges |

The index page's search box and category filter are plain JavaScript, with no dependencies.

## Two design principles

**1. Self-containment beats DRY.**

Modules are allowed to copy-paste code. Changing a challenge should require reading only
that challenge's files, not first understanding a shared abstraction layer. Only things
that genuinely belong to the framework (`base.html`, `ctx`) live in the core.

**2. Keep the contract narrow, and make the defaults safe.**

Mount paths are **assigned by the framework**, so hardcoding one into a module is an
implicit cross-layer coupling — and when the mount changes later, it breaks *silently*
(a 404 link, no exception, no log entry). Silent failures are the most expensive kind, so
the design makes them impossible from the start: predictable defaults, exactly one way to
reference another mount, and a `doctor` that actively hunts down this class of coupling.

## What this does not do

Listed honestly, so you don't get burned:

- **Isolation is zero.** Every module runs in the same Python process. A command-injection
  challenge hands you a shell on the whole range, not a sandbox around that challenge.
  That is the inevitable price of a single-process architecture — use it locally, alone.
  If you genuinely need isolation, move to subprocesses or containers: `create_app()`
  returns a WSGI app, so a reverse proxy in front is enough and the interface does not change.
- **WSGI only.** Flask and bare WSGI work; ASGI frameworks such as FastAPI are not supported.
- **No cross-module links.** `ctx.url()` can only address mounts belonging to its own module.
- **One process shares state.** Several people attacking the same challenge at once interfere with each other.
- **No flags and no scoreboard**, deliberately. This is a teaching range, not a CTF
  platform: the challenge page tells you when you're through, and the learning comes from
  each challenge's `hint` / `solution` / `writeup.md`.

## Requirements

At runtime the only dependency is Flask: `pip install flask`.
(On distributions with a system-managed Python, Debian and Kali for instance, use
`apt install python3-flask`.)

## License

MIT — see [LICENSE](LICENSE) for the full text.
