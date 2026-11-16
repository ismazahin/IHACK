# Attack & Defense Technique Catalog — I-Hack Finals

> **Purpose:** a searchable index of (almost) every bug class you'll meet in an A/D CTF.
> You can't use AI during the event, so **use this now** to go study each technique:
> every entry has a **`search:`** line — type that into a search engine / your notes and
> learn the exploit *and* the fix before the day.
>
> **How entries are laid out:**
> - **What** — one line on the bug.
> - **Attack** — how you exploit it to read the flag.
> - **Find it** — how you spot it in the service you're given (you may only read *your/given*
>   material — no scanning other teams).
> - **Defend** — the minimal patch that stops it without breaking SLA.
> - **search:** — exact terms to look it up.
>
> A/D services are almost always **web apps** or **pwn binaries**, sometimes **crypto** or a
> **custom network service**. Sections ordered by how often they show up.

---

## 0. Service triage — what to do with any service before attacking

You get source code and/or a binary (never scan other teams). First pass, every service:

- **Web:** read the routes/handlers. Grep the source for danger sinks:
  `search: grep for dangerous functions source code audit`
  - SQL: `execute(`, `query(`, string-built SQL
  - Command: `system(`, `exec(`, `popen(`, `subprocess`, `os.system`, backticks
  - File: `open(`, `read_file`, `include`, `require`, `fopen`, path joins with user input
  - Deserialize: `pickle.loads`, `yaml.load`, `unserialize`, `Marshal.load`, `ObjectInputStream`
  - Template: `render_template_string`, `Template(`, `{{ }}` with user input
  - Auth: where sessions/tokens/passwords are checked
- **Pwn:** `search: checksec pwntools` → run `checksec --file=./svc`. Note Canary / NX / PIE /
  RELRO. Then `strings`, `nm`, and load in **Ghidra** (on the pwnbox) to read `main`/handlers.
- **Where's the flag?** Find how the checker stores it: a `flag.txt`, a DB row, an env var, a
  user record, a file named by the checker. Your exploit's job is to reach exactly that.

---

## 1. WEB EXPLOITATION

### 1.1 SQL Injection (SQLi)
- **What:** user input concatenated into an SQL query.
- **Attack:** `UNION SELECT` the flag column; or error-based / boolean-blind / time-blind extraction.
- **Find it:** string-built queries; inputs that change results with `'`, `"`, `-- -`.
- **Defend:** parameterised queries / prepared statements; whitelist input; least-privilege DB user.
- **search:** `sql injection UNION based cheat sheet`, `sqlmap`, `boolean blind sqli`, `prepared statements fix`

### 1.2 NoSQL Injection
- **What:** injection into MongoDB/Redis-style queries (operators instead of strings).
- **Attack:** `{"$ne": null}`, `{"$gt": ""}` to bypass auth or dump data.
- **Find it:** JSON body passed straight into a Mongo query; `$where` with JS.
- **Defend:** cast/validate types; reject query operators in user input.
- **search:** `nosql injection mongodb payloads`, `$ne authentication bypass`

### 1.3 Command Injection / OS Injection
- **What:** user input reaches a shell command.
- **Attack:** `; cat flag.txt`, `| id`, `$(cat /flag)`, `` `...` ``, newline injection.
- **Find it:** `system()`, `exec`, `popen`, `subprocess(..., shell=True)`, `os.system`, ping/dns/convert features.
- **Defend:** avoid the shell (`subprocess([...], shell=False)`); strict allowlist; no user input in command strings.
- **search:** `os command injection payload list`, `shell=True vulnerability`, `command injection filter bypass`

### 1.4 Path Traversal / Local File Inclusion (LFI)
- **What:** user controls a file path.
- **Attack:** `../../../../flag.txt`, `....//`, absolute paths, null byte, PHP `php://filter`, LFI→RCE via logs.
- **Find it:** `open(user_path)`, `include($file)`, download/view/avatar endpoints.
- **Defend:** canonicalise + confine to a base dir (`os.path.realpath` startswith base); allowlist filenames.
- **search:** `path traversal payloads`, `LFI to RCE log poisoning`, `php filter wrapper`

### 1.5 Server-Side Template Injection (SSTI)
- **What:** user input rendered as a template.
- **Attack:** `{{7*7}}` → if 49, escalate to RCE (`{{config}}`, `{{''.__class__...}}` in Jinja2).
- **Find it:** `render_template_string`, `Template(user_input)`, reflected math.
- **Defend:** never render user input as a template; use sandboxed/logic-less templates; pass data as variables.
- **search:** `SSTI jinja2 payload RCE`, `tplmap`, `server side template injection cheat sheet`

### 1.6 Insecure Deserialization
- **What:** app deserialises attacker-controlled objects.
- **Attack:** crafted pickle/PHP/Java/YAML object → RCE on load.
- **Find it:** `pickle.loads`, `yaml.load` (not safe_load), `unserialize`, `readObject`, base64 blobs in cookies.
- **Defend:** `yaml.safe_load`; signed/whitelisted formats; use JSON; HMAC-verify serialized data.
- **search:** `insecure deserialization python pickle exploit`, `ysoserial`, `php object injection`

### 1.7 Authentication / Authorization bypass (incl. IDOR)
- **What:** weak login, or accessing another user's data by changing an ID.
- **Attack:** IDOR (`/user/2/flag` → change the 2), default creds, logic flaws, forced browsing.
- **Find it:** object IDs in URLs/params; missing "is this *my* resource?" check.
- **Defend:** enforce per-object ownership checks server-side; non-guessable IDs; proper access control.
- **search:** `IDOR insecure direct object reference`, `broken access control OWASP`, `authentication bypass logic flaw`

### 1.8 JWT attacks
- **What:** JSON Web Token misconfig.
- **Attack:** `alg:none`, weak HMAC secret (crack with `hashcat`/`jwt_tool`), `RS256→HS256` confusion, `kid` injection.
- **Find it:** `eyJ...` tokens; a signing library that trusts the header `alg`.
- **Defend:** pin the algorithm server-side; strong secret; verify signature properly.
- **search:** `jwt_tool attacks`, `jwt alg none bypass`, `jwt rs256 hs256 confusion`

### 1.9 Server-Side Request Forgery (SSRF)
- **What:** server fetches a URL you control.
- **Attack:** reach internal services / metadata / the flag service via `http://127.0.0.1/...`, `file://`.
- **Find it:** "fetch URL", webhook, image-from-URL, PDF/preview features.
- **Defend:** allowlist destinations; block internal ranges & non-HTTP schemes; resolve-then-validate.
- **search:** `SSRF payloads cheat sheet`, `SSRF filter bypass`, `gopher ssrf`

### 1.10 XML External Entity (XXE)
- **What:** XML parser resolves external entities.
- **Attack:** `<!ENTITY xxe SYSTEM "file:///flag.txt">` to read files.
- **Find it:** endpoints that parse XML/SVG/DOCX uploads.
- **Defend:** disable external entities/DTD in the parser.
- **search:** `XXE payload read file`, `xxe billion laughs`, `disable external entities <language>`

### 1.11 File upload → RCE
- **What:** upload of an executable/interpreted file served back.
- **Attack:** upload `shell.php`/`.jsp`, bypass extension/content-type filters, then browse to it.
- **Find it:** upload features; where files are stored & whether they're served/executed.
- **Defend:** allowlist extensions & content types; store outside webroot; randomise names; no execution.
- **search:** `file upload bypass webshell`, `upload filter bypass double extension`

### 1.12 Cross-Site Scripting (XSS) — *situational in A/D*
- **What:** user input reflected/stored as HTML/JS. Usually only useful if a bot/admin visits.
- **Attack:** steal admin cookie/flag if there's a headless visitor; often NOT scored in pure A/D.
- **Defend:** output-encode; CSP. Don't over-invest unless the service has a bot.
- **search:** `stored xss exploit`, `xss steal cookie`, `csp bypass`

### 1.13 Other web classes to recognise
- **search:** `HTTP request smuggling`, `CRLF injection`, `open redirect`, `race condition web TOCTOU`,
  `prototype pollution nodejs`, `mass assignment`, `GraphQL introspection abuse`, `CORS misconfiguration`,
  `cache poisoning`, `host header injection`, `python format string injection {0.__class__}`

---

## 2. BINARY EXPLOITATION (PWN)

> First always: `checksec`, then Ghidra/`objdump -d`. Mitigations present decide the technique.

### 2.1 Stack buffer overflow → ret2win
- **What:** overflow a stack buffer, overwrite the saved return address.
- **Attack:** padding to offset + address of a `win()`/`print_flag()` function.
- **Find it:** `gets`, `scanf("%s")`, `strcpy`, `read(fd, buf, bignum)`, fixed `char buf[N]`.
- **Defend:** bounds-check input; recompile with stack canary (`-fstack-protector`) if you can.
- **search:** `ret2win ctf`, `pwntools cyclic offset`, `buffer overflow 64 bit stack alignment movaps`

### 2.2 ret2libc / ret2system
- **What:** no `win()`? Return into libc to call `system("/bin/sh")`.
- **Attack:** leak a libc address (e.g. `puts(puts@got)`), compute base, ROP to `system`.
- **Find it:** overflow + NX enabled + no win function; a usable leak primitive.
- **search:** `ret2libc attack tutorial`, `GOT leak puts`, `libc database offset`, `one_gadget`

### 2.3 Return-Oriented Programming (ROP)
- **What:** chain existing code gadgets to do arbitrary work (bypass NX).
- **Attack:** build chains with `ROPgadget`/`ropper`; `pop rdi; ret` etc.
- **search:** `ROP chain pwntools`, `ROPgadget tutorial`, `ret2csu`, `SROP sigreturn`

### 2.4 Format string
- **What:** `printf(user_input)` with no format.
- **Attack:** `%p` leaks (stack/canary/libc), `%n` arbitrary write (e.g. overwrite GOT/return addr).
- **Find it:** `printf(buf)`, `fprintf`, `snprintf` with user input as the format.
- **Defend:** `printf("%s", buf)` — always a fixed format string.
- **search:** `format string exploit %n`, `format string leak canary`, `pwntools fmtstr_payload`

### 2.5 Global Offset Table (GOT) overwrite
- **What:** redirect a library call by overwriting its GOT entry.
- **Attack:** write `system`/`win` over `puts@got` etc. (via format string / arbitrary write).
- **Defend:** compile Full RELRO (`-Wl,-z,relro,-z,now`) to make GOT read-only.
- **search:** `GOT overwrite exploit`, `full relro bypass`, `got plt hijack`

### 2.6 Heap exploitation
- **What:** corruption of glibc heap metadata / chunk reuse.
- **Attack:** use-after-free, double-free, tcache poisoning, fastbin dup, overlapping chunks.
- **Find it:** `malloc`/`free` of user-sized buffers; a menu program (add/edit/delete/view).
- **search:** `heap exploitation how2heap`, `tcache poisoning`, `use after free ctf`, `double free fastbin`

### 2.7 Integer / off-by-one / other memory bugs
- **search:** `integer overflow exploit`, `off by one null byte poison null`, `signed unsigned comparison bug`,
  `array index out of bounds exploit`, `uninitialized memory leak`

### 2.8 Shellcode (when NX is off)
- **What:** inject and jump to your own machine code.
- **search:** `shellcode execstack ret2shellcode`, `jmp rsp`, `msfvenom shellcode` (or pwntools `asm(shellcraft...)`)

---

## 3. CRYPTO (when a service does its own crypto)

- **Weak/known keys & reuse:** `search: xor repeating key crypto`, `rsa small e`, `rsa common modulus`, `rsa wiener low private exponent`
- **ECB mode:** `search: aes ecb penguin byte at a time decryption`, `ecb cut and paste attack`
- **CBC:** `search: padding oracle attack`, `cbc bit flipping attack`
- **Nonce/IV reuse:** `search: nonce reuse stream cipher`, `AES-GCM nonce reuse forbidden attack`, `ECDSA nonce reuse private key`
- **Hash issues:** `search: hash length extension attack hashpump`, `md5 collision`, `weak hmac secret crack hashcat`
- **PRNG:** `search: mersenne twister predict`, `insecure random token prediction`
- **Tools on pwnbox:** `z3-solver`, `sympy`, `gmpy2`, `pycryptodome`, `hashcat`, `john`.
- **Defend:** use vetted libraries, random nonces, strong keys, authenticated encryption — but in A/D you
  mostly *exploit* these; defending means swapping the weak primitive while keeping the checker's I/O identical.

---

## 4. CUSTOM / NETWORK SERVICE LOGIC

Many A/D services are a bespoke TCP server (Python/Go/C). Bugs are often **logic**, not memory:
- **search:** `authentication logic flaw`, `race condition TOCTOU exploit`, `integer truncation`,
  `trusting client supplied length`, `path/permission check bypass`, `backdoor hardcoded credential ctf`
- **Find it:** read the protocol handler end to end; look for the planted shortcut (a debug command,
  a magic value, a missing check). Organisers plant an intended bug — your job is to spot it.
- **Defend:** remove the backdoor / add the missing check, keep every legitimate command working.

---

## 5. DEFENSE — techniques that keep SLA while blocking attacks

> Rule reminders: **no firewall edits**, **never turn the service off**, **always re-test the happy
> path** after a patch (if normal use still works, the checker stays green).

### 5.1 Source-level patching (your main defense)
- Fix the exact sink: parameterise the query, add the ownership check, confine the file path,
  switch `yaml.load`→`safe_load`, `printf(buf)`→`printf("%s",buf)`, remove the planted backdoor/debug route.
- **search:** `secure coding fix <bug class>`, `input validation allowlist`, `least privilege`

### 5.2 Binary patching (when you only have a binary)
- Patch bytes to neuter the bug: NOP a dangerous call, shrink a read length, redirect a jump.
- **search:** `binary patching ghidra`, `patchelf`, `NOP out function call hex edit`, `radare2 write mode`

### 5.3 Recompile with mitigations (if you have source)
- `search:` `gcc stack protector fPIE relro now fortify source` — turn on canary/NX/PIE/Full RELRO/FORTIFY.
- Keep the binary's behaviour identical so the checker still passes.

### 5.4 Steal-and-replay defense (fits your attack focus)
- Capture attacks on your own box (`tcpdump`/Wireshark), confirm the bug, patch it, **and reuse the
  attacker's exploit against everyone else**. One capture = a patch + a free exploit.
- **search:** `tcpdump capture replay`, `wireshark follow tcp stream`, `pcap extract http request`

### 5.5 Watchdog / integrity (only if it doesn't risk SLA)
- Restore the flag file/service from backup if tampered; restart a crashed service automatically.
- **search:** `service watchdog script restart`, `file integrity monitor`
- ⚠️ Keep automation **≥2s** loops; nothing that looks like flooding or that blocks the checker.

### 5.6 Harden without breaking I/O
- Remove debug endpoints, default creds, verbose errors, exposed admin routes — only when the checker
  doesn't rely on them.
- **search:** `remove debug endpoint production`, `disable stack trace error page`

---

## 6. Quick "which technique?" decision guide

| You see… | Likely bug | Go study |
|----------|-----------|----------|
| Input lands in an SQL string | SQLi | 1.1 |
| A "ping/convert/run" feature | Command injection | 1.3 |
| A `file=`/download/view param | Path traversal / LFI | 1.4 |
| `{{7*7}}` renders as 49 | SSTI | 1.5 |
| Base64 cookie / object blob | Deserialization / JWT | 1.6 / 1.8 |
| An ID in the URL you can change | IDOR / access control | 1.7 |
| "Fetch this URL" feature | SSRF | 1.9 |
| XML/SVG/DOCX upload | XXE / upload RCE | 1.10 / 1.11 |
| `gets`/`strcpy`/`read` + `char buf[N]` | Stack overflow | 2.1–2.3 |
| `printf(buf)` | Format string | 2.4 |
| add/edit/delete/view menu on heap | Heap exploit | 2.6 |
| Service does its own encryption | Crypto bug | 3 |
| A weird magic command / hardcoded value | Backdoor / logic flaw | 4 |

---

## 7. Study plan (before the event)
- [ ] Do one hands-on lab per **bold** technique in sections 1–2 (your focus areas).
- [ ] For each: exploit it **and** write the one-line fix — you need both sides.
- [ ] Practice reading source fast: grep the danger sinks in section 0 on any open-source app.
- [ ] Practice `checksec` → pick-technique on 5 old pwn binaries.
- [ ] Practice the capture→replay flow once (section 5.4) — it's your highest-value A/D move.
- [ ] Keep this file + the playbook as offline notes on the day (no AI allowed).
```
