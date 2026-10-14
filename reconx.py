#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconX v1.0 - Web Recon & Audit Toolkit
Jalan di Ubuntu/Debian, Termux, macOS, Windows (Python 3.8+).

Fitur:
  - DNS, redirect chain (http/https/www), header + audit keamanan, cookie, TLS
  - robots.txt, sitemap (index/gz), file umum (security.txt, openapi, dll)
  - Crawler multi-thread: URL, form, email, subdomain, domain eksternal, aset
  - Endpoint hint dari file JavaScript (mode deep)
  - Tree ala sitemap + export JSON / TXT / HTML

PAKAI HANYA pada website milik sendiri atau dengan izin tertulis.

Contoh:
  python3 reconx.py                       # mode interaktif
  python3 reconx.py -u example.com        # profil standard
  python3 reconx.py -u example.com -p deep -y
"""
import sys, os, re, io, ssl, json, time, zlib, socket, random, string, hashlib
import argparse, subprocess, importlib
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, urldefrag, urlunparse
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET

VERSION = "1.0"


# ----------------------------------------------------------------- bootstrap
def _ensure(pkg, mod=None):
    try:
        importlib.import_module(mod or pkg)
        return
    except ImportError:
        pass
    print(f"[*] Menginstall dependency: {pkg} ...")
    for extra in ([], ["--break-system-packages"]):
        cmd = [sys.executable, "-m", "pip", "install", "-q", pkg] + extra
        try:
            if subprocess.call(cmd) == 0:
                importlib.invalidate_caches()
                importlib.import_module(mod or pkg)
                return
        except Exception:
            pass
    print(f"[!] Gagal install '{pkg}'. Install manual:")
    print("    Ubuntu : sudo apt install python3-pip && pip3 install requests rich")
    print("    Termux : pkg install python && pip install requests rich")
    sys.exit(1)


_ensure("requests")
_ensure("rich")

import requests
import urllib3
from requests.adapters import HTTPAdapter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.rule import Rule
from rich.text import Text
from rich.markup import escape
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------------------------------------------------- config
UA = f"Mozilla/5.0 (compatible; ReconX/{VERSION}; +security-audit)"
TIMEOUT = 12
console = Console()
REPORT = []
STATE = {"insecure_ssl": False}

PROFILES = {
    "quick":    {"crawl": False, "depth": 0, "max": 0,   "js": False},
    "standard": {"crawl": True,  "depth": 2, "max": 150, "js": False},
    "deep":     {"crawl": True,  "depth": 4, "max": 600, "js": True},
}

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.8"})
_ad = HTTPAdapter(pool_connections=32, pool_maxsize=32)
SESSION.mount("http://", _ad)
SESSION.mount("https://", _ad)

REDIR = (301, 302, 303, 307, 308)
SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".avif", ".css", ".woff", ".woff2",
            ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".webm", ".avi", ".mov", ".zip", ".rar", ".gz", ".7z",
            ".tar", ".exe", ".apk", ".iso", ".dmg", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt",
            ".pptx", ".map", ".js", ".mjs")

SEC_HEADERS = [
    ("Strict-Transport-Security", "HSTS", 20),
    ("Content-Security-Policy", "CSP", 25),
    ("X-Frame-Options", "Anti-Clickjacking", 15),
    ("X-Content-Type-Options", "Anti-MIME-Sniffing", 15),
    ("Referrer-Policy", "Referrer-Policy", 10),
    ("Permissions-Policy", "Permissions-Policy", 10),
    ("Cross-Origin-Opener-Policy", "COOP", 5),
]
LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator",
                "x-drupal-cache", "x-runtime", "x-backend-server", "via"]

COMMON = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/.well-known/security.txt", "/security.txt",
    "/humans.txt", "/ads.txt", "/manifest.json", "/site.webmanifest", "/favicon.ico", "/crossdomain.xml",
    "/feed", "/rss.xml", "/atom.xml", "/wp-json/", "/.well-known/openid-configuration",
    "/.well-known/change-password", "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association", "/api", "/swagger.json", "/openapi.json",
    "/api-docs", "/graphql",
]

TECH_HEADERS = {
    "cf-ray": "Cloudflare", "x-vercel-id": "Vercel", "x-amz-cf-id": "AWS CloudFront",
    "x-nf-request-id": "Netlify", "x-github-request-id": "GitHub Pages", "fly-request-id": "Fly.io",
    "x-litespeed-cache": "LiteSpeed", "x-drupal-cache": "Drupal", "x-shopify-stage": "Shopify",
    "x-pingback": "WordPress", "x-wp-total": "WordPress",
}
TECH_HTML = [
    ("wp-content", "WordPress"), ("/_next/", "Next.js"), ("__next_data__", "Next.js"), ("/_nuxt/", "Nuxt"),
    ("ng-version", "Angular"), ("data-reactroot", "React"), ("cdn.shopify.com", "Shopify"),
    ("drupal-settings-json", "Drupal"), ("/media/jui/", "Joomla"), ("gatsby", "Gatsby"),
    ("jquery", "jQuery"), ("bootstrap", "Bootstrap"), ("tailwind", "Tailwind CSS"),
    ("googletagmanager.com", "Google Tag Manager"), ("google-analytics.com", "Google Analytics"),
    ("recaptcha", "reCAPTCHA"), ("cdn.jsdelivr.net", "jsDelivr CDN"), ("cdnjs.cloudflare.com", "cdnjs"),
]
TECH_COOKIES = {
    "phpsessid": "PHP", "laravel_session": "Laravel", "jsessionid": "Java (JSP/Servlet)",
    "asp.net_sessionid": "ASP.NET", "connect.sid": "Node.js/Express", "csrftoken": "Django",
    "__cf_bm": "Cloudflare", "ci_session": "CodeIgniter",
}

JS_RE = re.compile(
    r"""["'`]((?:https?:)?//[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%\-]{6,}"""
    r"""|/(?:api|v[0-9]+|graphql|rest|auth|oauth|admin|login|logout|user|users|account|upload|download|ws|socket)"""
    r"""[A-Za-z0-9_\-./{}:%?=&]*)["'`]"""
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,10}")


# ------------------------------------------------------------------- helpers
def emit(*items):
    for x in items:
        console.print(x)
        REPORT.append(x)


def short(e):
    return f"{type(e).__name__}: {str(e)[:70]}"


def dedupe(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def stc(s):
    if s is None:
        return "red"
    return "green" if s < 300 else "yellow" if s < 400 else "red" if s < 500 else "magenta"


def tbl(title, *cols, **kw):
    t = Table(title=title, box=box.ROUNDED, header_style="bold cyan", title_style="bold white",
              border_style="grey50", **kw)
    for c in cols:
        t.add_column(c, overflow="fold")
    return t


def http(url, method="GET", stream=False, **kw):
    kw.setdefault("timeout", TIMEOUT)
    kw.setdefault("allow_redirects", False)
    try:
        return SESSION.request(method, url, stream=stream, **kw)
    except requests.exceptions.SSLError:
        SESSION.verify = False
        STATE["insecure_ssl"] = True
        return SESSION.request(method, url, stream=stream, **kw)


def read_body(r, limit=2_000_000):
    buf = b""
    try:
        for ch in r.iter_content(65536):
            buf += ch
            if len(buf) >= limit:
                break
    except Exception:
        pass
    finally:
        r.close()
    return buf


def site_key(h):
    h = (h or "").lower()
    return h[4:] if h.startswith("www.") else h


def scope_of(host, root):
    k = site_key(host)
    if k == root:
        return "internal"
    if k.endswith("." + root):
        return "subdomain"
    return "external"


def clean(href, base):
    href = (href or "").strip()
    if not href or href.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "#", "sms:",
                                            "whatsapp:", "blob:", "about:")):
        return None
    try:
        u, _ = urldefrag(urljoin(base, href))
        p = urlparse(u)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        netloc = p.hostname.lower()
        if p.port and not ((p.scheme == "http" and p.port == 80) or (p.scheme == "https" and p.port == 443)):
            netloc += f":{p.port}"
        return urlunparse((p.scheme, netloc, p.path or "/", "", p.query, ""))
    except Exception:
        return None


def asset_type(path, kind):
    if path.endswith((".js", ".mjs")):
        return "js"
    if path.endswith(".css"):
        return "css"
    if path.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".avif")):
        return "image"
    if path.endswith((".woff", ".woff2", ".ttf", ".eot", ".otf")):
        return "font"
    if path.endswith((".mp4", ".mp3", ".webm", ".avi", ".mov")):
        return "media"
    if path.endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx")):
        return "document"
    if path.endswith((".zip", ".rar", ".gz", ".7z", ".tar", ".exe", ".apk", ".iso", ".dmg")):
        return "archive"
    return {"script": "js", "img": "image"}.get(kind, kind)


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.meta = [], [], {}
        self.title, self._t = "", False

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag in ("a", "link", "area") and a.get("href"):
            self.links.append((tag if tag != "area" else "a", a["href"]))
        elif tag in ("script", "img", "iframe", "source", "video", "audio", "embed", "track") and a.get("src"):
            self.links.append((tag, a["src"]))
        elif tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": (a.get("method") or "GET").upper()})
            if a.get("action"):
                self.links.append(("form", a["action"]))
        elif tag == "meta":
            n = (a.get("name") or a.get("http-equiv") or a.get("property") or "").lower()
            c = a.get("content", "")
            if n:
                self.meta[n] = c
            if n == "refresh":
                m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", c, re.I)
                if m:
                    self.links.append(("refresh", m.group(1).strip()))
        elif tag == "title":
            self._t = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._t = False

    def handle_data(self, d):
        if self._t and len(self.title) < 200:
            self.title += d


def parse_html(text, base):
    p = LinkParser()
    try:
        p.feed(text)
        p.close()
    except Exception:
        pass
    links = []
    for k, h in p.links:
        c = clean(h, base)
        if c:
            links.append((k, c))
    forms = [{"action": clean(f["action"], base) or base, "method": f["method"]} for f in p.forms]
    return " ".join(p.title.split()), links, forms, p.meta


def find_emails(t):
    bad = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js")
    return {m.lower() for m in EMAIL_RE.findall(t) if not m.lower().endswith(bad)}


# ------------------------------------------------------------------ analysis
def dns_info(host):
    out = {"host": host, "ips": [], "canonical": None, "aliases": [], "rdns": {}, "error": None}
    try:
        out["ips"] = sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except socket.gaierror as e:
        out["error"] = str(e)
        return out
    try:
        c, al, _ = socket.gethostbyname_ex(host)
        out["canonical"], out["aliases"] = c, al
    except Exception:
        pass
    for ip in out["ips"][:6]:
        try:
            out["rdns"][ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            out["rdns"][ip] = "-"
    return out


def trace(url, max_hops=15):
    hops, cur, seen = [], url, set()
    for _ in range(max_hops):
        if cur in seen:
            hops.append({"url": cur, "status": None, "error": "redirect loop terdeteksi"})
            break
        seen.add(cur)
        try:
            t = time.time()
            r = http(cur, stream=True)
            ms = int((time.time() - t) * 1000)
        except Exception as e:
            hops.append({"url": cur, "status": None, "error": short(e)})
            break
        loc, st = r.headers.get("Location"), r.status_code
        hops.append({"url": cur, "status": st, "location": loc, "ms": ms, "server": r.headers.get("Server", "")})
        r.close()
        if st in REDIR and loc:
            cur = urljoin(cur, loc)
            continue
        break
    return hops, hops[-1]["url"], hops[-1].get("status") is not None


def variants(host):
    is_ip = bool(re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", host))
    base = site_key(host)
    hosts = [host] if is_ip else dedupe([base, "www." + base])
    starts = [f"{s}://{h}/" for s in ("http", "https") for h in hosts]

    def one(u):
        hops, final, ok = trace(u)
        return {"start": u, "final": final, "redirects": max(len(hops) - 1, 0),
                "status": hops[-1].get("status"), "ok": ok}

    with ThreadPoolExecutor(4) as ex:
        return list(ex.map(one, starts))


def set_cookies(r):
    try:
        return r.raw.headers.getlist("Set-Cookie")
    except Exception:
        v = r.headers.get("Set-Cookie")
        return [v] if v else []


def parse_cookies(raw):
    out = []
    for c in raw:
        parts = [x.strip() for x in c.split(";")]
        fl = [x.lower() for x in parts[1:]]
        ss = next((x.split("=", 1)[1] for x in fl if x.startswith("samesite=")), "-")
        out.append({"name": parts[0].split("=", 1)[0], "secure": "secure" in fl,
                    "httponly": "httponly" in fl, "samesite": ss})
    return out


def audit_headers(h, scheme):
    hl = {k.lower(): v for k, v in h.items()}
    rows, score = [], 0
    for name, label, w in SEC_HEADERS:
        v = hl.get(name.lower())
        ok = v is not None
        if name == "X-Frame-Options" and not ok and "frame-ancestors" in hl.get("content-security-policy", "").lower():
            ok, v = True, "(via CSP frame-ancestors)"
        if name == "Strict-Transport-Security" and scheme != "https":
            ok = False
        if name == "X-Content-Type-Options" and ok and v.strip().lower() != "nosniff":
            ok = False
        if ok:
            score += w
        rows.append((name, label, ok, v or "-", w))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    leaks = [(k, hl[k]) for k in LEAK_HEADERS if k in hl]
    return rows, score, grade, leaks


def detect_tech(headers, html, cookies, meta):
    hl = {k.lower(): v for k, v in headers.items()}
    t = set()
    if hl.get("server"):
        t.add("Server: " + hl["server"])
    if hl.get("x-powered-by"):
        t.add("X-Powered-By: " + hl["x-powered-by"])
    for k, v in TECH_HEADERS.items():
        if k in hl:
            t.add(v)
    if "wp-json" in hl.get("link", ""):
        t.add("WordPress")
    if "cloudfront" in hl.get("via", "").lower():
        t.add("AWS CloudFront")
    low = html.lower()[:600000]
    for needle, name in TECH_HTML:
        if needle in low:
            t.add(name)
    if meta.get("generator"):
        t.add("Generator: " + meta["generator"])
    for c in cookies:
        n = c["name"].lower()
        for k, v in TECH_COOKIES.items():
            if n == k:
                t.add(v)
        if n.startswith("wordpress_"):
            t.add("WordPress")
    return sorted(t)


def tls_info(host, port):
    res = {"ok": False}
    cert = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=min(TIMEOUT, 6)) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                c = ss.cipher()
                res.update(ok=True, verified=True, version=ss.version(), cipher=c[0] if c else "-")
    except ssl.SSLCertVerificationError as e:
        res["verify_error"] = getattr(e, "verify_message", None) or str(e)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=min(TIMEOUT, 6)) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    c = ss.cipher()
                    res.update(ok=True, verified=False, version=ss.version(), cipher=c[0] if c else "-")
        except Exception:
            pass
    except Exception as e:
        res["error"] = short(e)
        return res
    if cert:
        try:
            subj = dict(x[0] for x in cert.get("subject", ()))
            iss = dict(x[0] for x in cert.get("issuer", ()))
            na = ssl.cert_time_to_seconds(cert["notAfter"])
            nb = ssl.cert_time_to_seconds(cert["notBefore"])
            res.update(
                subject=subj.get("commonName", "-"),
                issuer=iss.get("organizationName") or iss.get("commonName", "-"),
                not_before=datetime.fromtimestamp(nb, timezone.utc).strftime("%Y-%m-%d"),
                not_after=datetime.fromtimestamp(na, timezone.utc).strftime("%Y-%m-%d"),
                days_left=int((na - time.time()) / 86400),
                san=[v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
            )
        except Exception:
            pass
    return res


def probe(url):
    out = {"url": url, "status": None}
    try:
        t = time.time()
        r = http(url, stream=True)
        ct = r.headers.get("Content-Type", "").split(";")[0].strip().lower()
        loc = r.headers.get("Location")
        st = r.status_code
        b = read_body(r, 65536)
        out.update(status=st, ctype=ct, location=loc, size=len(b),
                   hash=hashlib.md5(b[:2048]).hexdigest(), ms=int((time.time() - t) * 1000))
    except Exception as e:
        out["error"] = short(e)
    return out


def baseline(origin):
    rnd = "".join(random.choices(string.ascii_lowercase, k=14))
    p = probe(f"{origin}/{rnd}.xyz")
    return {"status": p.get("status"), "hash": p.get("hash"), "location": p.get("location")}


def classify(p, bl):
    st = p.get("status")
    if st is None:
        return "error"
    if st == 200 and (bl["status"] != 200 or p.get("hash") != bl["hash"]):
        return "found"
    if st in REDIR:
        return "none" if (bl["status"] == st and bl.get("location") == p.get("location")) else "redirect"
    if st in (401, 403) and bl["status"] not in (401, 403):
        return "protected"
    return "none"


def fetch_robots(origin):
    url = origin + "/robots.txt"
    try:
        r = http(url, stream=True, allow_redirects=True)
        ct = r.headers.get("Content-Type", "").lower()
        st = r.status_code
        b = read_body(r, 1_000_000)
    except Exception as e:
        return {"found": False, "error": short(e)}
    txt = b.decode("utf-8", "replace")
    if st != 200 or "html" in ct or not re.search(r"(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:", txt):
        return {"found": False, "status": st}
    out = {"found": True, "url": url, "agents": [], "disallow": [], "allow": [], "sitemaps": [], "crawl_delay": []}
    for line in txt.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if not v:
            continue
        if k == "user-agent":
            out["agents"].append(v)
        elif k == "disallow":
            out["disallow"].append(v)
        elif k == "allow":
            out["allow"].append(v)
        elif k == "sitemap":
            out["sitemaps"].append(v)
        elif k == "crawl-delay":
            out["crawl_delay"].append(v)
    for k in ("agents", "disallow", "allow", "sitemaps"):
        out[k] = dedupe(out[k])
    return out


def _local(tag):
    return tag.split("}")[-1].lower()


def parse_sitemaps(cands, max_maps=40, max_urls=20000):
    queue, seen, urls, maps = list(cands), set(), [], []
    while queue and len(seen) < max_maps:
        u = queue.pop(0)
        if u in seen:
            continue
        seen.add(u)
        try:
            r = http(u, stream=True, allow_redirects=True)
            st = r.status_code
            b = read_body(r, 15_000_000)
        except Exception:
            continue
        if st != 200 or not b:
            continue
        if b[:2] == b"\x1f\x8b":
            try:
                b = zlib.decompressobj(31).decompress(b, 60_000_000)
            except Exception:
                continue
        try:
            root = ET.fromstring(b)
        except ET.ParseError:
            continue
        kind = _local(root.tag)
        want = "sitemap" if kind == "sitemapindex" else "url" if kind == "urlset" else None
        if not want:
            continue
        locs = []
        for el in root:
            if _local(el.tag) == want:
                for c in el:
                    if _local(c.tag) == "loc" and c.text and c.text.strip():
                        locs.append(c.text.strip())
        if kind == "sitemapindex":
            maps.append({"url": u, "type": "index", "count": len(locs)})
            queue.extend(locs)
        else:
            maps.append({"url": u, "type": "urlset", "count": len(locs)})
            urls.extend(locs)
        if len(urls) >= max_urls:
            break
    return {"maps": maps, "urls": dedupe(urls)[:max_urls]}


def scan_js(js_urls, limit=25):
    def one(u):
        try:
            r = http(u, stream=True, allow_redirects=True)
            b = read_body(r, 1_500_000)
            return set(JS_RE.findall(b.decode("utf-8", "replace")))
        except Exception:
            return set()

    eps = set()
    with ThreadPoolExecutor(6) as ex:
        for s in ex.map(one, js_urls[:limit]):
            eps |= s
    noise = ("w3.org", "schema.org", "xmlns", "reactjs.org", "npmjs.com", "mozilla.org", "github.com/facebook")
    return sorted(e for e in eps if len(e) < 200 and not any(n in e for n in noise))


def crawl_one(url):
    res = {"url": url, "status": None}
    try:
        t = time.time()
        r = http(url, stream=True)
        ct = r.headers.get("Content-Type", "").split(";")[0].strip().lower()
        res.update(status=r.status_code, ctype=ct, location=r.headers.get("Location"),
                   server=r.headers.get("Server", ""), ms=int((time.time() - t) * 1000))
        if r.status_code in REDIR and res["location"]:
            res["redirect_to"] = clean(res["location"], url)
            r.close()
            return res
        if r.status_code < 400 and "html" in ct:
            body = read_body(r, 1_500_000)
            text = body.decode("utf-8", "replace")
            title, links, forms, _ = parse_html(text, url)
            res.update(size=len(body), title=title[:90], links=links, forms=forms,
                       emails=sorted(find_emails(text)))
        else:
            try:
                res["size"] = int(r.headers.get("Content-Length") or 0)
            except ValueError:
                res["size"] = 0
            r.close()
    except Exception as e:
        res["error"] = short(e)
    return res


def crawl(starts, root, depth, max_pages, threads, tick):
    seen, frontier = set(starts), list(starts)
    pages, disc, ext, subs, forms, emails, assets = {}, {}, {}, set(), [], set(), {}
    for d in range(depth + 1):
        if not frontier or len(pages) >= max_pages:
            break
        batch, frontier = frontier[: max_pages - len(pages)], []
        with ThreadPoolExecutor(threads) as ex:
            for res in ex.map(crawl_one, batch):
                res["depth"] = d
                pages[res["url"]] = res
                tick()
                for f in res.get("forms", []):
                    forms.append({"page": res["url"], **f})
                emails.update(res.get("emails", []))
                items = []
                if res.get("redirect_to"):
                    items.append(("redirect", res["redirect_to"]))
                items += res.get("links", [])
                for kind, u in items:
                    hn = (urlparse(u).hostname or "").lower()
                    sc = scope_of(hn, root)
                    if u not in disc:
                        disc[u] = {"kind": kind, "scope": sc, "from": res["url"]}
                    if sc == "external":
                        ext.setdefault(hn, set()).add(u)
                        continue
                    if sc == "subdomain":
                        subs.add(hn)
                        continue
                    path = urlparse(u).path.lower()
                    if kind in ("script", "img", "source", "video", "audio", "embed", "track") or path.endswith(SKIP_EXT):
                        assets[u] = asset_type(path, kind)
                        continue
                    if u not in seen:
                        seen.add(u)
                        frontier.append(u)
    return {"pages": pages, "disc": disc, "external": ext, "subdomains": subs, "forms": forms,
            "emails": emails, "assets": assets}


# ------------------------------------------------------------------- display
def banner():
    art = ("╦═╗╔═╗╔═╗╔═╗╔╗╔═╗ ╦\n"
           "╠╦╝║╣ ║  ║ ║║║║╔╩╦╝\n"
           "╩╚═╚═╝╚═╝╚═╝╝╚╝╩ ╚═")
    t = Text(art + f"\nWeb Recon & Audit Toolkit  v{VERSION}", style="bold cyan", justify="center")
    console.print(Panel(t, box=box.DOUBLE, border_style="cyan", subtitle="[dim]gunakan hanya dengan izin[/]"))


def show_dns(d):
    t = tbl("DNS & Jaringan", "Item", "Nilai", show_header=False)
    t.add_row("Host", escape(d["host"]))
    if d["canonical"] and d["canonical"] != d["host"]:
        t.add_row("Canonical", escape(d["canonical"]))
    if d["aliases"]:
        t.add_row("Alias/CNAME", escape(", ".join(d["aliases"])))
    for ip in d["ips"]:
        t.add_row("IP", f"{ip}  [dim]{escape(d['rdns'].get(ip, '-'))}[/]")
    emit(Rule("[bold cyan]1. DNS & Jaringan[/]"), t)


def show_trace(hops, var):
    tr = Tree("[bold]Redirect chain[/]")
    node = tr
    for h in hops:
        if h.get("status") is None:
            node = node.add(f"[red]ERR[/] {escape(h['url'])} [dim]{escape(h.get('error', ''))}[/]")
        else:
            node = node.add(f"[{stc(h['status'])}]{h['status']}[/] {escape(h['url'])} [dim]{h['ms']}ms[/]")
    t = tbl("Uji varian (http/https/www)", "Mulai", "Redirect", "Status", "Tujuan akhir")
    for v in var:
        t.add_row(escape(v["start"]), str(v["redirects"]), f"[{stc(v['status'])}]{v['status'] or 'ERR'}[/]",
                  escape(v["final"]))
    emit(Rule("[bold cyan]2. Redirect[/]"), tr, t)


def show_http(final, status, hdrs, title, tech, allow, size, ms):
    t = tbl("Ringkasan HTTP", "Item", "Nilai", show_header=False)
    t.add_row("URL akhir", escape(final))
    t.add_row("Status", f"[{stc(status)}]{status}[/]")
    t.add_row("Content-Type", escape(hdrs.get("Content-Type", "-")))
    t.add_row("Ukuran (dibaca)", f"{size:,} bytes")
    t.add_row("Waktu respons", f"{ms} ms")
    if title:
        t.add_row("Judul halaman", escape(title))
    if allow:
        t.add_row("Metode (OPTIONS)", escape(allow))
    if tech:
        t.add_row("Teknologi", escape(", ".join(tech)))
    h = tbl("Response headers", "Header", "Nilai")
    for k, v in hdrs.items():
        h.add_row(f"[bold]{escape(k)}[/]", escape(v if len(v) < 350 else v[:350] + " ..."))
    emit(Rule("[bold cyan]3. HTTP & Header[/]"), t, h)


def show_security(rows, score, grade, leaks, cookies):
    t = tbl("Audit header keamanan", "Header", "Fungsi", "Status", "Nilai")
    for name, label, ok, v, w in rows:
        t.add_row(name, label, "[green]ADA[/]" if ok else "[red]TIDAK ADA[/]", escape(v[:80]))
    gc = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}[grade]
    emit(t, Panel(f"Skor: [bold]{score}/100[/]   Grade: [bold {gc}]{grade}[/]", box=box.ROUNDED,
                  border_style=gc, expand=False))
    if leaks:
        lt = tbl("Header yang membocorkan info teknologi", "Header", "Nilai")
        for k, v in leaks:
            lt.add_row(k, escape(v))
        emit(lt)
    if cookies:
        ct = tbl("Cookie", "Nama", "Secure", "HttpOnly", "SameSite")
        for c in cookies:
            ct.add_row(escape(c["name"]), "[green]ya[/]" if c["secure"] else "[red]tidak[/]",
                       "[green]ya[/]" if c["httponly"] else "[red]tidak[/]", c["samesite"])
        emit(ct)


def show_tls(tl):
    t = tbl("TLS / Sertifikat", "Item", "Nilai", show_header=False)
    if not tl.get("ok"):
        t.add_row("Status", f"[red]tidak tersedia[/] {escape(tl.get('error', ''))}")
    else:
        t.add_row("Verifikasi", "[green]valid[/]" if tl.get("verified") else
                  f"[red]GAGAL[/] {escape(str(tl.get('verify_error', '')))}")
        t.add_row("Protokol", f"{tl.get('version')}  [dim]{tl.get('cipher')}[/]")
        if "subject" in tl:
            d = tl["days_left"]
            dc = "red" if d < 15 else "yellow" if d < 30 else "green"
            t.add_row("Subject (CN)", escape(tl["subject"]))
            t.add_row("Penerbit", escape(tl["issuer"]))
            t.add_row("Berlaku", f"{tl['not_before']} s/d {tl['not_after']}  [{dc}]({d} hari lagi)[/]")
            if tl.get("san"):
                san = tl["san"]
                t.add_row("SAN", escape(", ".join(san[:12]) + (f" (+{len(san) - 12})" if len(san) > 12 else "")))
    emit(Rule("[bold cyan]4. TLS[/]"), t)


def show_discovery(robots, sm, files, rpaths):
    parts = [Rule("[bold cyan]5. robots.txt, sitemap & file umum[/]")]
    if robots.get("found"):
        t = tbl("robots.txt", "Direktif", "Nilai")
        for a in robots["agents"][:10]:
            t.add_row("User-agent", escape(a))
        for p in robots["disallow"][:60]:
            t.add_row("[red]Disallow[/]", escape(p))
        for p in robots["allow"][:30]:
            t.add_row("[green]Allow[/]", escape(p))
        for p in robots["sitemaps"]:
            t.add_row("[cyan]Sitemap[/]", escape(p))
        for p in robots["crawl_delay"]:
            t.add_row("Crawl-delay", escape(p))
        parts.append(t)
    else:
        parts.append(Text("robots.txt tidak ditemukan.", style="yellow"))
    if sm["maps"]:
        t = tbl(f"Sitemap ({len(sm['urls'])} URL terkumpul)", "Sitemap", "Tipe", "Entri")
        for m in sm["maps"]:
            t.add_row(escape(m["url"]), m["type"], str(m["count"]))
        parts.append(t)
    else:
        parts.append(Text("Sitemap tidak ditemukan.", style="yellow"))
    t = tbl("File & endpoint umum", "Path", "Hasil", "Status", "Tipe")
    colors = {"found": "green", "protected": "yellow", "redirect": "cyan"}
    shown = [f for f in files if f["class"] in colors]
    for f in shown:
        t.add_row(escape(f["path"]), f"[{colors[f['class']]}]{f['class']}[/]", str(f["status"]),
                  escape(f.get("ctype", "")))
    if shown:
        parts.append(t)
    else:
        parts.append(Text("Tidak ada file umum tambahan yang terdeteksi.", style="dim"))
    hit = [r for r in rpaths if r["class"] in colors]
    if rpaths:
        if hit:
            t = tbl(f"Path dari robots.txt yang merespons ({len(hit)}/{len(rpaths)} dicek)", "Path", "Hasil", "Status")
            for r in hit:
                t.add_row(escape(r["path"]), f"[{colors[r['class']]}]{r['class']}[/]", str(r["status"]))
            parts.append(t)
        else:
            parts.append(Text(f"{len(rpaths)} path dari robots.txt dicek: tidak ada yang merespons.", style="dim"))
    emit(*parts)


def show_crawl(cr, js_eps):
    pages = cr["pages"]
    stat = {}
    for p in pages.values():
        k = str(p.get("status") or "ERR")
        stat[k] = stat.get(k, 0) + 1
    line = "  ".join(f"[{stc(int(k) if k.isdigit() else None)}]{k}[/]:{v}" for k, v in sorted(stat.items()))
    t = tbl(f"Hasil crawl ({len(pages)} halaman)  {line}", "Sts", "D", "URL", "Info")
    rows = sorted(pages.values(), key=lambda p: (p["depth"], p["url"]))
    for p in rows[:60]:
        st = p.get("status")
        info = p.get("title") or p.get("redirect_to") or p.get("location") or p.get("error") or p.get("ctype", "")
        t.add_row(f"[{stc(st)}]{st or 'ERR'}[/]", str(p["depth"]), escape(p["url"]), escape(str(info)))
    parts = [Rule("[bold cyan]6. Crawl[/]"), t]
    if len(rows) > 60:
        parts.append(Text(f"... {len(rows) - 60} halaman lain ada di file export.", style="dim"))
    at = {}
    for v in cr["assets"].values():
        at[v] = at.get(v, 0) + 1
    if at:
        a = tbl("Aset internal", "Tipe", "Jumlah")
        for k, v in sorted(at.items(), key=lambda x: -x[1]):
            a.add_row(k, str(v))
        parts.append(a)
    if cr["external"]:
        e = tbl(f"Domain eksternal ({len(cr['external'])})", "Domain", "URL")
        for h, us in sorted(cr["external"].items(), key=lambda x: -len(x[1]))[:25]:
            e.add_row(escape(h), str(len(us)))
        parts.append(e)
    if cr["subdomains"]:
        s = tbl(f"Subdomain terdeteksi ({len(cr['subdomains'])})", "Subdomain")
        for h in sorted(cr["subdomains"])[:40]:
            s.add_row(escape(h))
        parts.append(s)
    if cr["forms"]:
        f = tbl(f"Form ({len(cr['forms'])})", "Metode", "Action", "Di halaman")
        for x in cr["forms"][:20]:
            f.add_row(x["method"], escape(x["action"]), escape(x["page"]))
        parts.append(f)
    if cr["emails"]:
        parts.append(Panel(escape("\n".join(sorted(cr["emails"])[:30])), title="Email", border_style="grey50", box=box.ROUNDED))
    if js_eps:
        j = tbl(f"Endpoint hint dari JavaScript ({len(js_eps)})", "Endpoint")
        for e in js_eps[:50]:
            j.add_row(escape(e))
        parts.append(j)
    emit(*parts)


def build_tree(urls, label, max_nodes=150):
    tree = Tree(f"[bold cyan]{escape(label)}[/]")
    nodes, count, trunc = {}, 0, False
    for u in sorted(urls):
        segs = [s for s in urlparse(u).path.split("/") if s]
        cur, key = tree, ()
        for s in segs:
            key += (s,)
            if key not in nodes:
                if count >= max_nodes:
                    trunc = True
                    break
                nodes[key] = cur.add(escape("/" + s))
                count += 1
            cur = nodes[key]
    if trunc:
        tree.add("[dim]... selengkapnya di urls.txt[/]")
    return tree


def show_findings(F):
    t = tbl("Temuan & rekomendasi", "Level", "Keterangan")
    cmap = {"crit": "bold red", "warn": "yellow", "info": "cyan", "ok": "green"}
    order = {"crit": 0, "warn": 1, "info": 2, "ok": 3}
    for lv, tx in sorted(F, key=lambda x: order[x[0]]):
        t.add_row(f"[{cmap[lv]}]{lv.upper()}[/]", escape(tx))
    emit(Rule("[bold cyan]Ringkasan Temuan[/]"), t)


# ---------------------------------------------------------------------- scan
def scan(target, prof, depth=None, max_pages=None, threads=10, outdir=None, force_js=False):
    REPORT.clear()
    t0 = time.time()
    P = PROFILES[prof]
    depth = P["depth"] if depth is None else depth
    max_pages = P["max"] if max_pages is None else max_pages
    do_crawl = P["crawl"] and max_pages > 0
    do_js = P["js"] or force_js

    raw = target.strip()
    had_scheme = bool(re.match(r"^https?://", raw, re.I))
    u = raw if had_scheme else "https://" + raw
    p = urlparse(u)
    host = p.hostname
    if not host:
        console.print("[red]Target tidak valid.[/]")
        return
    start_url = u if p.path else u.rstrip("/") + "/"
    data = {"tool": f"ReconX {VERSION}", "target": raw, "profile": prof,
            "started": datetime.now(timezone.utc).isoformat()}
    F = []

    emit(Panel(f"[bold]Target:[/] {escape(raw)}   [bold]Profil:[/] {prof}", border_style="cyan", box=box.ROUNDED))

    # 1. DNS
    with console.status("[cyan]Resolving DNS...[/]"):
        d = dns_info(host)
    data["dns"] = d
    if d["error"]:
        emit(Panel(f"[red]DNS gagal:[/] {escape(d['error'])}", border_style="red"))
        return
    show_dns(d)

    # 2. Redirect
    with console.status("[cyan]Menelusuri redirect...[/]"):
        hops, final, ok = trace(start_url)
        if not ok and not had_scheme:
            h2, f2, ok2 = trace("http://" + raw.lstrip("/") + ("" if p.path else "/"))
            if ok2:
                hops, final, ok = h2, f2, ok2
        var = variants(host)
    data["redirects"] = {"chain": hops, "variants": var}
    show_trace(hops, var)
    if not ok:
        emit(Panel("[red]Situs tidak dapat dijangkau.[/]", border_style="red"))
        return
    for v in var:
        if v["start"].startswith("http://") and v["ok"] and not v["final"].startswith("https://"):
            F.append(("warn", f"{v['start']} tidak diarahkan ke HTTPS"))
    if len({site_key(urlparse(v["final"]).hostname or "") for v in var if v["ok"]}) > 1:
        F.append(("info", "Varian www/non-www berakhir di host berbeda (cek canonical host)"))
    fp = urlparse(final)
    origin = f"{fp.scheme}://{fp.netloc}"
    root = site_key(fp.hostname)

    # 3. HTTP
    with console.status("[cyan]Menganalisis response & header...[/]"):
        t1 = time.time()
        r = http(final, stream=True)
        status, hdrs = r.status_code, dict(r.headers)
        raw_cookies = set_cookies(r)
        body = read_body(r, 1_500_000)
        ms = int((time.time() - t1) * 1000)
        text = body.decode("utf-8", "replace")
        title, _, _, meta = parse_html(text, final) if "html" in hdrs.get("Content-Type", "").lower() else ("", [], [], {})
        cookies = parse_cookies(raw_cookies)
        tech = detect_tech(hdrs, text, cookies, meta)
        allow = None
        try:
            ro = http(final, "OPTIONS")
            allow = ro.headers.get("Allow")
        except Exception:
            pass
        rows, score, grade, leaks = audit_headers(hdrs, fp.scheme)
    data["http"] = {"final": final, "status": status, "headers": hdrs, "title": title, "tech": tech,
                    "options_allow": allow, "cookies": cookies,
                    "security": {"score": score, "grade": grade, "missing": [x[0] for x in rows if not x[2]]},
                    "leaks": leaks}
    show_http(final, status, hdrs, title, tech, allow, len(body), ms)
    show_security(rows, score, grade, leaks, cookies)
    miss = [x[1] for x in rows if not x[2]]
    if miss:
        F.append(("warn" if score < 75 else "info", f"Header keamanan belum ada: {', '.join(miss)}"))
    if leaks:
        F.append(("info", "Header membocorkan teknologi: " + ", ".join(f"{k}={v}" for k, v in leaks)))
    for c in cookies:
        bad = [n for n, v in (("Secure", c["secure"]), ("HttpOnly", c["httponly"])) if not v]
        if bad:
            F.append(("warn", f"Cookie '{c['name']}' tanpa flag {'/'.join(bad)}"))
    if STATE["insecure_ssl"]:
        F.append(("crit", "Verifikasi sertifikat gagal saat request (scan dilanjutkan tanpa verifikasi)"))

    # 4. TLS
    with console.status("[cyan]Mengecek TLS...[/]"):
        tl = tls_info(fp.hostname, fp.port or 443)
    data["tls"] = tl
    show_tls(tl)
    if tl.get("ok"):
        if tl.get("verified") is False:
            F.append(("crit", f"Sertifikat TLS tidak valid: {tl.get('verify_error')}"))
        if tl.get("days_left") is not None:
            if tl["days_left"] < 0:
                F.append(("crit", "Sertifikat TLS sudah kedaluwarsa"))
            elif tl["days_left"] < 30:
                F.append(("warn", f"Sertifikat TLS habis dalam {tl['days_left']} hari"))
        if tl.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
            F.append(("warn", f"Protokol TLS usang: {tl['version']}"))
    elif fp.scheme == "https":
        F.append(("warn", "Koneksi TLS langsung gagal"))

    # 5. Discovery
    with console.status("[cyan]Mengambil robots.txt, sitemap & file umum...[/]"):
        robots = fetch_robots(origin)
        cands = robots.get("sitemaps", []) + [origin + x for x in (
            "/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml", "/sitemap.xml.gz",
            "/wp-sitemap.xml", "/sitemaps.xml")]
        sm = parse_sitemaps(dedupe(cands))
        bl = baseline(origin)
        with ThreadPoolExecutor(8) as ex:
            files = list(ex.map(probe, [origin + x for x in COMMON]))
        for x, pth in zip(files, COMMON):
            x["path"] = pth
            x["class"] = classify(x, bl)
        rp = []
        if robots.get("found"):
            cand = dedupe([x for x in robots["disallow"] + robots["allow"]
                           if x.startswith("/") and x != "/" and not any(c in x for c in "*$?")])[:40]
            with ThreadPoolExecutor(8) as ex:
                rp = list(ex.map(probe, [origin + x for x in cand]))
            for x, pth in zip(rp, cand):
                x["path"] = pth
                x["class"] = classify(x, bl)
    data["discovery"] = {"robots": robots, "sitemaps": sm, "files": files, "robots_paths": rp}
    show_discovery(robots, sm, files, rp)
    api = [x["path"] for x in files if x["class"] == "found" and x["path"] in
           ("/swagger.json", "/openapi.json", "/api-docs", "/graphql")]
    if api:
        F.append(("warn", "Dokumentasi/endpoint API terbuka: " + ", ".join(api)))
    if not any(x["class"] == "found" and "security.txt" in x["path"] for x in files):
        F.append(("info", "security.txt tidak ditemukan (disarankan untuk kontak pelaporan keamanan)"))
    hit = [x["path"] for x in rp if x["class"] in ("found", "protected")]
    if hit:
        F.append(("info", f"{len(hit)} path di robots.txt dapat diakses/terproteksi: {', '.join(hit[:6])}"))

    # 6. Crawl
    cr = None
    js_eps = []
    all_urls = set(sm["urls"])
    all_urls.add(final)
    if do_crawl:
        starts = dedupe([s for s in (clean(final, final), clean(origin + "/", origin)) if s])
        with Progress(SpinnerColumn(), TextColumn("[cyan]Crawling[/]"), BarColumn(),
                      TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn(),
                      console=console, transient=True) as prog:
            task = prog.add_task("crawl", total=max_pages)
            cr = crawl(starts, root, depth, max_pages, threads, lambda: prog.advance(task))
        if do_js:
            js_urls = sorted(u for u, k in cr["assets"].items() if k == "js")
            with console.status("[cyan]Memindai file JavaScript...[/]"):
                js_eps = scan_js(js_urls)
        show_crawl(cr, js_eps)
        all_urls |= set(cr["pages"]) | set(cr["disc"])
        light = {u: {k: v for k, v in pg.items() if k not in ("links",)} for u, pg in cr["pages"].items()}
        data["crawl"] = {"pages": light, "external": cr["external"], "subdomains": cr["subdomains"],
                         "forms": cr["forms"], "emails": cr["emails"], "assets": cr["assets"],
                         "js_endpoints": js_eps}
        if cr["forms"]:
            F.append(("info", f"{len(cr['forms'])} form ditemukan (periksa CSRF & validasi input)"))
        errs = sum(1 for pg in cr["pages"].values() if (pg.get("status") or 0) >= 500)
        if errs:
            F.append(("warn", f"{errs} halaman merespons error 5xx saat crawl"))

    # Tree
    internal = [u for u in all_urls if scope_of(urlparse(u).hostname or "", root) == "internal"
                and not urlparse(u).path.lower().endswith(SKIP_EXT)
                and not (cr and u in cr["assets"])]
    emit(Rule("[bold cyan]Peta URL (ala sitemap)[/]"), build_tree(internal, origin))

    show_findings(F or [("ok", "Tidak ada temuan menonjol")])

    dur = time.time() - t0
    data["findings"] = F
    data["finished"] = datetime.now(timezone.utc).isoformat()
    data["duration_sec"] = round(dur, 1)
    data["all_urls"] = sorted(all_urls)

    sumt = tbl("Ringkasan", "Metrik", "Nilai", show_header=False)
    sumt.add_row("URL akhir", escape(final))
    sumt.add_row("Grade header", f"{grade} ({score}/100)")
    sumt.add_row("URL unik terkumpul", str(len(all_urls)))
    sumt.add_row("URL di sitemap", str(len(sm["urls"])))
    if cr:
        sumt.add_row("Halaman di-crawl", str(len(cr["pages"])))
        sumt.add_row("Domain eksternal", str(len(cr["external"])))
    sumt.add_row("Durasi", f"{dur:.1f} detik")
    emit(sumt)

    path = export(data, sorted(all_urls), outdir, host)
    console.print(Panel(f"[green]Laporan tersimpan di:[/]\n{escape(path)}\n"
                        "[dim]report.html · report.txt · data.json · urls.txt[/]", border_style="green", box=box.ROUNDED))


def export(data, urls, outdir, host):
    base = outdir or os.path.join(os.getcwd(), "recon_results")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    try:
        d = os.path.join(base, f"{name}_{ts}")
        os.makedirs(d, exist_ok=True)
    except OSError:
        d = os.path.join(os.path.expanduser("~"), "recon_results", f"{name}_{ts}")
        os.makedirs(d, exist_ok=True)

    def enc(o):
        if isinstance(o, (set, tuple)):
            return sorted(o) if isinstance(o, set) else list(o)
        return str(o)

    with open(os.path.join(d, "data.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=enc)
    with open(os.path.join(d, "urls.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(urls) + "\n")
    rc = Console(record=True, file=io.StringIO(), width=110, force_terminal=True, color_system="truecolor")
    for x in REPORT:
        rc.print(x)
    rc.save_html(os.path.join(d, "report.html"), clear=False)
    rc.save_text(os.path.join(d, "report.txt"))
    return d


# ---------------------------------------------------------------------- main
def consent():
    return Confirm.ask("[yellow]Saya memiliki izin untuk menguji target ini (milik sendiri / izin tertulis)?[/]",
                       default=True)


def interactive(a):
    if not a.yes and not consent():
        return
    while True:
        target = Prompt.ask("\n[bold cyan]Target[/] (domain/URL, kosong = keluar)", default="").strip()
        if not target:
            break
        console.print("[1] Quick     - tanpa crawl (paling cepat)\n"
                      "[2] Standard  - crawl kedalaman 2, maks 150 halaman\n"
                      "[3] Deep      - crawl kedalaman 4, maks 600 halaman + analisis JS")
        m = Prompt.ask("Profil", choices=["1", "2", "3"], default="2")
        prof = {"1": "quick", "2": "standard", "3": "deep"}[m]
        scan(target, prof, a.depth, a.max_pages, a.threads, a.out, a.js)
        if not Confirm.ask("Scan target lain?", default=True):
            break


def main():
    global TIMEOUT
    ap = argparse.ArgumentParser(description="ReconX - Web Recon & Audit Toolkit")
    ap.add_argument("-u", "--url", help="target (domain atau URL)")
    ap.add_argument("-p", "--profile", choices=list(PROFILES), default="standard")
    ap.add_argument("-d", "--depth", type=int, help="override kedalaman crawl")
    ap.add_argument("-m", "--max-pages", type=int, help="override jumlah halaman maksimum")
    ap.add_argument("-t", "--threads", type=int, default=10)
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--js", action="store_true", help="paksa analisis file JavaScript")
    ap.add_argument("-o", "--out", help="folder output (default ./recon_results)")
    ap.add_argument("-y", "--yes", action="store_true", help="lewati konfirmasi izin")
    a = ap.parse_args()
    TIMEOUT = max(3, a.timeout)
    banner()
    if a.url:
        if not a.yes and not consent():
            return
        scan(a.url, a.profile, a.depth, a.max_pages, a.threads, a.out, a.js)
    else:
        interactive(a)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Dihentikan oleh pengguna.[/]")
        sys.exit(130)
