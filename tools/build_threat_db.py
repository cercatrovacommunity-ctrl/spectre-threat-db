#!/usr/bin/env python3
"""
Spectre Advisor - Offline Threat DB (SPDB v1), Zero-Day ML Weights & Ed25519 Manifest Builder

يُشغَّل هذا السكربت محلياً أو عبر GitHub Actions لتوليد:
- assets/threat_db/threats.bin
- assets/threat_db/whitelist.bin
- lib/features/link_analyzer/domain/url_ml_weights.dart
- (اختيارياً لتحديثات OTA) manifest.json + manifest.sig (توقيع Ed25519 بفصل نطاقي)

تنسيق الملف الثنائي (SPDB v1 - Big-Endian):
  [0..3]   Magic bytes        : b"SPDB"
  [4..5]   Format version     : uint16 (1)
  [6..7]   Database type      : uint16 (1 = threats, 2 = whitelist)
  [8..15]  Build timestamp    : uint64 (UTC Unix epoch seconds)
  [16..19] Entry count        : uint32
  [20..23] Flags / reserved   : uint32 (0)
  [24..55] Integrity digest   : 32 bytes = SHA-256(header[0..24] + payload)
  [56..]   Sorted payload     : entry_count * 8 bytes (unique strictly ascending SHA-256[:8])
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import random
import re
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

# تفعيل UTF-8 على Windows PowerShell لتفادي أخطاء الترميز
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SPDB_MAGIC = b"SPDB"
SPDB_VERSION = 1
SPDB_HEADER_SIZE = 56
SPDB_ENTRY_SIZE = 8
DB_TYPE_THREATS = 1
DB_TYPE_WHITELIST = 2

MANIFEST_SCHEMA_VERSION = 1
MANIFEST_SIGNATURE_DOMAIN = b"SPECTRE-SPDB-MANIFEST-V1\n"
DEFAULT_KEY_ID = "spectre-spdb-2026-v1"

MAX_DOWNLOAD_BYTES = 60 * 1024 * 1024  # 60 MB حد أمان ضد الملفات الضخمة أو Zip Bombs
MAX_REDIRECTS = 5
REQUEST_TIMEOUT_SEC = 45
MAX_RETRIES = 2
MIN_SAFE_THREATS = 10_000
MIN_SUCCEEDED_FEEDS = 2
USER_AGENT = "SpectreAdvisor-SPDB-Builder/2.1"

# مصادر التهديدات المفتوحة والمجانية مرتبة من الأعلى دقةً إلى الأوسع تغطيةً
THREAT_FEEDS = [
    ("OpenPhish", "https://openphish.com/feed.txt", "url"),
    ("URLHaus-Online", "https://urlhaus.abuse.ch/downloads/text_online/", "url"),
    (
        "PhishingDatabase-ActiveLinks",
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-today.txt",
        "url",
    ),
    (
        "HaGeZi-TIF-Mini",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.mini.txt",
        "domain",
    ),
    (
        "PhishingArmy-Extended",
        "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "domain",
    ),
    (
        "PhishingDatabase-ActiveDomains",
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "domain",
    ),
]

TRANCO_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"

# مطابقة 100% مع القائمة الرمادية ومختصرات الروابط في heuristics_engine.dart
FREE_HOSTING_GRAYLIST = {
    "sites.google.com", "forms.gle", "pages.dev", "workers.dev",
    "firebaseapp.com", "web.app", "github.io", "gitlab.io", "netlify.app",
    "vercel.app", "herokuapp.com", "onrender.com", "surge.sh", "weebly.com",
    "wixsite.com", "blogspot.com", "wordpress.com", "000webhostapp.com",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "azurewebsites.net",
    "glitch.me", "repl.co", "replit.app", "duckdns.org", "no-ip.org",
    "ddns.net", "notion.site", "carrd.co", "typeform.com", "jotform.com",
    "ipfs.io", "docs.google.com", "storage.googleapis.com", "appspot.com",
    "run.app", "cloudfunctions.net",
    "s3.amazonaws.com", "cloudfront.net", "blob.core.windows.net", "r2.dev",
    "fly.dev", "railway.app", "webflow.io", "b-cdn.net", "hf.space",
    "streamlit.app", "pythonanywhere.com", "koyeb.app", "canva.site",
    "tilda.ws", "square.site", "godaddysites.com", "myshopify.com",
}

FILE_SHARING_GRAYLIST = {
    "drive.google.com", "dropbox.com", "dl.dropboxusercontent.com",
    "mediafire.com", "mega.nz", "mega.co.nz", "onedrive.live.com",
    "1drv.ms", "t.me", "telegram.me", "cdn.discordapp.com",
    "media.discordapp.net", "wetransfer.com", "we.tl", "gofile.io",
    "pixeldrain.com", "sendspace.com", "zippyshare.com", "anonfiles.com",
    "upload.ee", "catbox.moe", "files.fm", "4shared.com", "pastebin.com",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "shorturl.at",
    "is.gd", "v.gd", "rebrand.ly", "ow.ly", "goo.gl", "tiny.cc", "s.id",
    "bl.ink", "buff.ly", "bit.do", "lnkd.in", "t.ly", "short.io", "clck.ru",
    "adf.ly", "ouo.io", "shrinkme.io", "linktr.ee", "snip.ly", "dub.sh",
    "dub.co", "qr.ae", "u.to", "x.co", "han.gl", "soo.gd", "bc.vc", "za.gl",
    "shrtco.de", "kutt.it", "gg.gg", "urls.fr", "short.cm", "lc.chat",
    "mcaf.ee", "su.pr", "fb.me", "amzn.to", "spoti.fi", "nyti.ms", "wapo.st",
    "tr.im", "cli.re", "po.st", "q.gs", "j.mp", "aka.ms", "g.co",
}

EXCLUDED_FROM_WHITELIST = (
    FREE_HOSTING_GRAYLIST | FILE_SHARING_GRAYLIST | SHORTENER_DOMAINS
)

# نطاقات رسمية ومحلية موثوقة (الجزائر والعالم) تُضمن دائماً في whitelist.bin
CURATED_TRUSTED_DOMAINS = {
    "google.com", "google.dz", "google.fr", "youtube.com", "youtu.be",
    "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "wa.me",
    "messenger.com", "m.me", "threads.net", "x.com", "twitter.com", "tiktok.com",
    "linkedin.com", "reddit.com", "pinterest.com", "snapchat.com",
    "wikipedia.org", "wikimedia.org", "github.com", "gitlab.com",
    "stackoverflow.com", "flutter.dev", "dart.dev", "pub.dev",
    "microsoft.com", "live.com", "office.com", "outlook.com",
    "apple.com", "icloud.com", "amazon.com", "amazon.fr", "ebay.com",
    "aliexpress.com", "paypal.com", "netflix.com", "spotify.com",
    "zoom.us", "adobe.com", "cloudflare.com", "openai.com", "anthropic.com",
    "bbc.com", "aljazeera.net", "reuters.com", "wise.com", "paysera.com",
    # نطاقات رسمية ومؤسساتية وخدماتية موثوقة في الجزائر
    "poste.dz", "algerietelecom.dz", "mobilis.dz", "djezzy.dz", "ooredoo.dz",
    "satim.dz", "ouedkniss.com", "sonelgaz.dz", "yassir.com", "aps.dz",
    "echoroukonline.com", "ennaharonline.com", "elkhabar.com", "elwatan-dz.com",
    "bna.dz", "cpa-bank.dz", "badrbank.dz", "bea.dz", "cnepbanque.dz",
    "bdl.dz", "bank-of-algeria.dz", "airalgerie.dz", "sntf.dz",
    "cnas.dz", "casnos.dz", "anem.dz", "anpdp.dz", "autoentrepreneur.dz",
    "interieur.gov.dz", "mjustice.dz", "education.gov.dz", "mesrs.dz",
    "sante.gov.dz", "mf.gov.dz", "commerce.gov.dz", "mpt.gov.dz",
    "usthb.dz", "univ-alger.dz", "univ-oran1.dz", "umc.edu.dz", "esi.dz",
}

MULTI_PART_PUBLIC_SUFFIXES = {
    "com.dz", "gov.dz", "org.dz", "net.dz", "edu.dz", "asso.dz", "pol.dz",
    "art.dz", "tm.dz", "com.eg", "gov.eg", "edu.eg", "org.eg",
    "com.sa", "gov.sa", "edu.sa", "org.sa", "net.sa",
    "co.ma", "ac.ma", "gov.ma", "org.ma", "net.ma",
    "com.tn", "gov.tn", "org.tn", "net.tn",
    "co.ae", "gov.ae", "org.ae", "net.ae",
    "com.qa", "com.kw", "com.bh", "com.om", "com.jo", "com.lb", "com.iq",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "com.br", "net.br", "org.br", "gov.br",
    "com.tr", "gov.tr", "org.tr", "net.tr", "gen.tr",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "co.kr", "or.kr", "go.kr",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.mx", "com.ar", "com.co", "com.pe", "com.ve",
    "com.sg", "com.my", "com.hk", "com.tw", "com.ph", "co.id",
    "co.za", "co.nz", "com.ng", "co.ke",
    "com.ua", "com.pl", "com.ru", "com.es", "com.fr", "com.de", "com.it",
    "co.il", "org.il", "gov.il",
}

# لواحق مرتفعة الاستغلال وكلمات حساسة مطابقة لطبقة الذكاء الاصطناعي في Dart
ML_HIGH_ABUSE_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "loan",
    "work", "shop", "icu", "cam", "rest", "cfd", "sbs", "cyou", "monster",
    "quest", "vip", "live", "online", "site", "website", "space", "fun",
    "cc", "pw", "ws", "info", "biz", "club", "life", "world", "pro",
}

ML_HOST_KEYWORDS = (
    "login", "signin", "verify", "secure", "update", "account", "bank",
    "wallet", "support", "auth", "confirm", "billing", "recover", "unlock",
    "suspend", "alert", "service", "portal", "client", "pay", "card",
    "baridi", "ccp", "poste", "bonus", "gift", "prize", "free",
)

VALID_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$"
)
HEX_LABEL_RE = re.compile(r"^[0-9a-f]{8,}$")


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """منع هبوط التشفير (HTTPS -> HTTP/FTP) أثناء تتبع التحويلات وتقييد عدد القفزات."""

    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not isinstance(newurl, str) or not newurl.lower().startswith("https://"):
            raise urllib.error.URLError(
                f"تم حظر تحويل غير مشفر (HTTPS Downgrade Blocked): {newurl}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_bytes(url: str) -> bytes:
    """تحميل آمن عبر HTTPS فقط (مع حظر هبوط التشفير في التحويلات) وحد أقصى للحجم."""
    if not url.lower().startswith("https://"):
        raise ValueError(f"يُسمح ببروتوكول HTTPS فقط للتحميل الآمن: {url}")

    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        _HttpsOnlyRedirectHandler(),
    )
    last_exc: Exception | None = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with opener.open(req, timeout=REQUEST_TIMEOUT_SEC) as resp:
                final_url = resp.geturl()
                if not final_url.lower().startswith("https://"):
                    raise ValueError(f"انحرف الاتصال إلى بروتوكول غير مشفر: {final_url}")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise ValueError(
                            f"تجاوز الملف الحد الأقصى للحجم ({MAX_DOWNLOAD_BYTES} bytes)"
                        )
                    chunks.append(chunk)
                return b"".join(chunks)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_exc = exc
            if attempt < MAX_RETRIES:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise

    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"فشل تحميل الرابط لسبب غير متوقع: {url}")


def matches_domain_set(host: str, domain_set: set[str]) -> bool:
    if not host:
        return False
    if host in domain_set:
        return True
    parts = host.split(".")
    for i in range(1, len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in domain_set:
            return True
    return False


def _parse_ip_canonical(host: str) -> str | None:
    stripped = host.strip("[]")
    try:
        return str(ipaddress.ip_address(stripped))
    except ValueError:
        return None


def is_ip_address(host: str) -> bool:
    return _parse_ip_canonical(host) is not None


def _strip_www_safely(host: str) -> str:
    """مطابق تماماً لـ normalizeHostForLookup في Dart: يمنع بتر نطاقات مثل www.com أو www.dz."""
    if host.startswith("www.") and "." in host[4:]:
        return host[4:]
    return host


def normalize_host(raw_host: str) -> str | None:
    host = raw_host.strip().lower().rstrip(".")
    if not host:
        return None
    canonical_ip = _parse_ip_canonical(host)
    if canonical_ip is not None:
        return canonical_ip
    host = _strip_www_safely(host)
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    ascii_host = _strip_www_safely(ascii_host)
    if len(ascii_host) > 253 or not VALID_DOMAIN_RE.match(ascii_host):
        return None
    return ascii_host


def split_domain_parts(host: str) -> tuple[str, str, str, list[str]]:
    """يرجع (registered_domain, sld, tld, meaningful_subdomains) بشكل مطابق لـ Dart."""
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 1:
        return host, host, "", []

    last_two = f"{parts[-2]}.{parts[-1]}"
    tld_parts = 2 if (len(parts) >= 3 and last_two in MULTI_PART_PUBLIC_SUFFIXES) else 1
    tld = ".".join(parts[-tld_parts:])
    sld_index = len(parts) - tld_parts - 1
    if sld_index < 0:
        return host, parts[0], tld, []

    sld = parts[sld_index]
    reg = f"{sld}.{tld}"
    subs = [s for s in parts[:sld_index] if s not in ("www", "m", "mobile")]
    return reg, sld, tld, subs


def extract_registered_domain(host: str) -> str:
    if is_ip_address(host):
        return host
    reg, _, _, _ = split_domain_parts(host)
    return reg


def normalize_path(raw_path: str) -> str:
    """تطبيع مسار الرابط بشكل متطابق 100% مع normalizePathForLookup في Dart."""
    if not raw_path:
        return ""
    current = raw_path
    for _ in range(3):
        if "%" not in current:
            break
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    current = re.sub(r"/{2,}", "/", current.strip().lower())
    if not current or current == "/":
        return ""
    if not current.startswith("/"):
        current = f"/{current}"
    current = current.rstrip("/")
    return "" if current == "/" else current


def hash64(key: str) -> bytes:
    """بصمة SHA-256 مقطّعة إلى أول 8 بايتات (64-bit Big-Endian)."""
    return hashlib.sha256(key.encode("utf-8")).digest()[:8]


def fetch_tranco_domains(limit: int) -> list[str]:
    print(f"[1/4] تحميل قائمة Tranco Top {limit:,} ...")
    raw_zip = download_bytes(TRANCO_ZIP_URL)
    domains: list[str] = []
    seen: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
        csv_names = [n for n in zf.namelist() if n.lower().endswith(".csv")]
        if not csv_names:
            raise ValueError("أرشيف Tranco لا يحتوي ملف CSV")
        info = zf.getinfo(csv_names[0])
        if info.file_size > MAX_DOWNLOAD_BYTES:
            raise ValueError("حجم ملف CSV داخل أرشيف Tranco يتجاوز الحد المسموح")
        decompressed_bytes = 0
        with zf.open(info, "r") as f:
            for raw_line in f:
                decompressed_bytes += len(raw_line)
                if decompressed_bytes > MAX_DOWNLOAD_BYTES:
                    raise ValueError(
                        "تجاوز فك ضغط Tranco الحد الأقصى المسموح به (Zip Bomb Guard)"
                    )
                line = raw_line.decode("utf-8", errors="ignore").strip()
                if not line or "," not in line:
                    continue
                _, raw_dom = line.split(",", 1)
                norm = normalize_host(raw_dom)
                if not norm or is_ip_address(norm):
                    continue
                reg = extract_registered_domain(norm)
                if reg not in seen:
                    seen.add(reg)
                    domains.append(reg)
                    if len(domains) >= limit:
                        break
    print(f"      -> تم استخراج {len(domains):,} نطاقاً فريداً من Tranco.")
    return domains


def fetch_threats(
    tranco_protected_set: set[str],
    max_entries: int,
) -> tuple[set[bytes], set[str], set[str]]:
    """
    تجميع التهديدات مع حماية ضد الأضرار الجانبية:
    - النطاقات المشتركة/الرمادية أو الموجودة في أعلى Tranco تُحظر بمسارها المحدد (u:) فقط.
    - نطاقات التصيد والبرمجيات الخبيثة المخصصة تُحظر بنطاقها (d:) وبمسارها (u:).
    """
    print("[2/4] تحميل وتنظيف قوائم التهديدات النشطة...")
    threat_hashes: set[bytes] = set()
    malicious_hosts: set[str] = set()
    malicious_reg_domains: set[str] = set()
    succeeded_feeds = 0

    for name, url, feed_kind in THREAT_FEEDS:
        if len(threat_hashes) >= max_entries:
            print(f"      -> تم بلوغ الحد الأقصى للتهديدات ({max_entries:,})، تخطّي {name}.")
            break
        try:
            raw = download_bytes(url).decode("utf-8", errors="ignore")
            succeeded_feeds += 1
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            print(f"      [تحذير] تعذر تحميل {name}: {exc}")
            continue

        added_here = 0
        for raw_line in raw.splitlines():
            if len(threat_hashes) >= max_entries:
                break
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if feed_kind == "domain":
                host = normalize_host(line)
                if not host or is_ip_address(host):
                    continue
                reg = extract_registered_domain(host)
                if (
                    matches_domain_set(host, EXCLUDED_FROM_WHITELIST)
                    or matches_domain_set(reg, CURATED_TRUSTED_DOMAINS)
                    or reg in tranco_protected_set
                ):
                    continue
                h = hash64(f"d:{host}")
                if h not in threat_hashes:
                    threat_hashes.add(h)
                    malicious_hosts.add(host)
                    malicious_reg_domains.add(reg)
                    added_here += 1
                continue

            # feed_kind == "url"
            candidate = line if "://" in line else f"http://{line}"
            try:
                parsed = urllib.parse.urlsplit(candidate)
            except ValueError:
                continue

            host = normalize_host(parsed.hostname or "")
            if not host:
                continue

            path = normalize_path(parsed.path or "")
            reg = extract_registered_domain(host)
            is_shared_or_popular = (
                matches_domain_set(host, EXCLUDED_FROM_WHITELIST)
                or matches_domain_set(reg, CURATED_TRUSTED_DOMAINS)
                or reg in tranco_protected_set
            )

            # 1. حظر الرابط المحدد (host + path) دائماً إن وُجد مسار
            if path:
                hu = hash64(f"u:{host}{path}")
                if hu not in threat_hashes:
                    threat_hashes.add(hu)
                    added_here += 1

            # 2. حظر النطاق الكامل (d:) فقط إذا لم يكن منصة مشتركة أو موقعاً شهيراً مخترقاً
            if not is_shared_or_popular and len(threat_hashes) < max_entries:
                hd = hash64(f"d:{host}")
                if hd not in threat_hashes:
                    threat_hashes.add(hd)
                    if not is_ip_address(host):
                        malicious_hosts.add(host)
                        malicious_reg_domains.add(reg)
                    added_here += 1

        print(f"      -> {name}: +{added_here:,} بصمة تهديد.")

    if succeeded_feeds < MIN_SUCCEEDED_FEEDS or len(threat_hashes) < MIN_SAFE_THREATS:
        raise RuntimeError(
            f"فشل بوابة أمان التهديدات: مصادر ناجحة={succeeded_feeds} (الحد الأدنى {MIN_SUCCEEDED_FEEDS}) "
            f"| بصمات={len(threat_hashes):,} (الحد الأدنى {MIN_SAFE_THREATS:,}). "
            "تم إيقاف البناء لحماية القاعدة من الاستبدال بملف ناقص."
        )

    return threat_hashes, malicious_hosts, malicious_reg_domains


def build_whitelist_hashes(
    tranco_domains: list[str],
    malicious_reg_domains: set[str],
    max_entries: int,
) -> tuple[set[bytes], list[str]]:
    print("[3/4] تنقية وبناء القائمة البيضاء (مع استبعاد الرمادية والمختصرات والتهديدات)...")
    clean_domains: set[str] = set()
    clean_ordered: list[str] = []

    for dom in sorted(CURATED_TRUSTED_DOMAINS):
        norm = normalize_host(dom)
        if not norm:
            continue
        reg = extract_registered_domain(norm)
        if not matches_domain_set(reg, EXCLUDED_FROM_WHITELIST) and reg not in clean_domains:
            clean_domains.add(reg)
            clean_ordered.append(reg)

    for reg in tranco_domains:
        if len(clean_domains) >= max_entries:
            break
        if matches_domain_set(reg, EXCLUDED_FROM_WHITELIST):
            continue
        if reg in malicious_reg_domains:
            continue
        if reg not in clean_domains:
            clean_domains.add(reg)
            clean_ordered.append(reg)

    hashes = {hash64(f"w:{dom}") for dom in clean_domains}
    print(f"      -> إجمالي نطاقات القائمة البيضاء الصافية: {len(hashes):,}.")
    return hashes, clean_ordered


# ============================================================================
# وحدة تدريب النموذج المحلي الخفيف (Zero-Day Host Classifier - Pure Python)
# ============================================================================

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    ent = 0.0
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    return ent


def extract_host_ml_features(host: str) -> list[float]:
    """
    استخراج 12 سمة إحصائية ولفظية من اسم المضيف فقط (متطابقة 100% مع طبقة Dart).
    """
    _, sld, tld, subs = split_domain_parts(host)
    host_len = len(host)
    sld_len = max(len(sld), 1)

    digits_sld = sum(1 for c in sld if "0" <= c <= "9")
    digits_host = sum(1 for c in host if "0" <= c <= "9")
    hyphens_host = host.count("-")
    vowels_sld = sum(1 for c in sld if c in "aeiou")

    max_digit_run = 0
    cur_digits = 0
    for c in host:
        if "0" <= c <= "9":
            cur_digits += 1
            if cur_digits > max_digit_run:
                max_digit_run = cur_digits
        else:
            cur_digits = 0

    max_cons_run = 0
    cur_cons = 0
    for c in sld:
        if "a" <= c <= "z" and c not in "aeiou":
            cur_cons += 1
            if cur_cons > max_cons_run:
                max_cons_run = cur_cons
        else:
            cur_cons = 0

    tld_last = tld.split(".")[-1] if tld else ""
    has_abuse_tld = 1.0 if tld_last in ML_HIGH_ABUSE_TLDS else 0.0
    has_keyword = 1.0 if any(kw in host for kw in ML_HOST_KEYWORDS) else 0.0
    has_hex_label = 1.0 if any(HEX_LABEL_RE.match(lbl) for lbl in host.split(".")) else 0.0

    return [
        min(host_len, 80) / 80.0,
        min(len(sld), 40) / 40.0,
        min(len(subs), 5) / 5.0,
        digits_sld / sld_len,
        digits_host / max(host_len, 1),
        min(hyphens_host, 6) / 6.0,
        _shannon_entropy(sld) / 5.0,
        min(max_digit_run, 10) / 10.0,
        min(max_cons_run, 10) / 10.0,
        vowels_sld / sld_len,
        has_abuse_tld,
        has_keyword + (0.5 * has_hex_label),
    ]


def _sigmoid(z: float) -> float:
    if z >= 30.0:
        return 1.0
    if z <= -30.0:
        return 0.0
    return 1.0 / (1.0 + math.exp(-z))


def train_and_export_ml_weights(
    malicious_hosts: set[str],
    benign_domains: list[str],
    dart_out_path: Path,
    build_timestamp: int,
    max_per_class: int = 12_000,
) -> None:
    print("[4/4] تدريب نموذج الذكاء الاصطناعي المحلي (Logistic Regression - L2)...")
    rng = random.Random(42)

    mal_list = sorted(h for h in malicious_hosts if not is_ip_address(h))
    ben_list = [d for d in benign_domains if not is_ip_address(d)]
    rng.shuffle(mal_list)
    rng.shuffle(ben_list)

    n_per_class = min(len(mal_list), len(ben_list), max_per_class)
    if n_per_class < 500:
        raise RuntimeError("بيانات غير كافية لتدريب النموذج المحلي.")

    samples: list[tuple[list[float], float]] = []
    for h in mal_list[:n_per_class]:
        samples.append((extract_host_ml_features(h), 1.0))
    for d in ben_list[:n_per_class]:
        samples.append((extract_host_ml_features(d), 0.0))
    rng.shuffle(samples)

    split_idx = int(len(samples) * 0.8)
    train_data = samples[:split_idx]
    val_data = samples[split_idx:]
    num_features = len(train_data[0][0])

    means = [0.0] * num_features
    for x, _ in train_data:
        for j in range(num_features):
            means[j] += x[j]
    means = [m / len(train_data) for m in means]

    stds = [0.0] * num_features
    for x, _ in train_data:
        for j in range(num_features):
            diff = x[j] - means[j]
            stds[j] += diff * diff
    stds = [math.sqrt(s / len(train_data)) or 1.0 for s in stds]

    def standardize(vec: list[float]) -> list[float]:
        return [(vec[j] - means[j]) / stds[j] for j in range(num_features)]

    train_std = [(standardize(x), y) for x, y in train_data]
    val_std = [(standardize(x), y) for x, y in val_data]

    weights = [0.0] * num_features
    bias = 0.0
    lr = 0.25
    l2_reg = 0.005
    epochs = 160
    n_train = float(len(train_std))

    for _ in range(epochs):
        grad_w = [0.0] * num_features
        grad_b = 0.0
        for x, y in train_std:
            z = bias + sum(weights[j] * x[j] for j in range(num_features))
            err = _sigmoid(z) - y
            grad_b += err
            for j in range(num_features):
                grad_w[j] += err * x[j]
        bias -= lr * (grad_b / n_train)
        for j in range(num_features):
            weights[j] -= lr * ((grad_w[j] / n_train) + l2_reg * weights[j])

    if not math.isfinite(bias) or not all(
        math.isfinite(v) for v in (*means, *stds, *weights)
    ):
        raise RuntimeError("تولدت قيم رقمية غير صالحة (NaN/Inf) أثناء تدريب النموذج المحلي.")

    high_threshold = 0.85
    tp = fp = tn = fn = 0
    tp_50 = fp_50 = tn_50 = fn_50 = 0
    for x, y in val_std:
        prob = _sigmoid(bias + sum(weights[j] * x[j] for j in range(num_features)))
        pred_50 = 1 if prob >= 0.50 else 0
        pred_hi = 1 if prob >= high_threshold else 0
        actual = int(y)

        if actual == 1 and pred_50 == 1:
            tp_50 += 1
        elif actual == 0 and pred_50 == 1:
            fp_50 += 1
        elif actual == 0 and pred_50 == 0:
            tn_50 += 1
        else:
            fn_50 += 1

        if actual == 1 and pred_hi == 1:
            tp += 1
        elif actual == 0 and pred_hi == 1:
            fp += 1
        elif actual == 0 and pred_hi == 0:
            tn += 1
        else:
            fn += 1

    acc_50 = (tp_50 + tn_50) / len(val_std) * 100.0
    fpr_hi = fp / max(fp + tn, 1) * 100.0
    prec_hi = tp / max(tp + fp, 1) * 100.0
    rec_hi = tp / max(tp + fn, 1) * 100.0

    print(
        f"      -> التحقق ({len(val_std):,} نطاق): دقة عامة={acc_50:.1f}% | "
        f"عند عتبة {high_threshold:.2f}: Precision={prec_hi:.1f}% | Recall={rec_hi:.1f}% | FPR={fpr_hi:.2f}%"
    )

    def fmt_list(vals: list[float]) -> str:
        return ",\n    ".join(f"{v:.6f}" for v in vals)

    dart_code = f"""// GENERATED CODE - DO NOT MODIFY BY HAND.
// أوزان نموذج التصنيف المحلي (Zero-Day Host Classifier) المولَّدة آلياً عبر tools/build_threat_db.py
// تاريخ التدريب UTC: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(build_timestamp))}

abstract final class UrlMlWeights {{
  static const int modelVersion = 1;
  static const int featureCount = {num_features};
  static const int trainedTimestampUtc = {build_timestamp};

  /// عتبة الاشتباه المتوسطة والعالية (مُعايَرة لتقليل الإنذارات الكاذبة إلى أدنى حد)
  static const double suspiciousThreshold = 0.78;
  static const double highConfidenceThreshold = {high_threshold:.2f};

  static const double bias = {bias:.6f};

  static const List<double> means = <double>[
    {fmt_list(means)},
  ];

  static const List<double> stds = <double>[
    {fmt_list(stds)},
  ];

  static const List<double> weights = <double>[
    {fmt_list(weights)},
  ];
}}
"""
    dart_out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dart_out_path.with_suffix(dart_out_path.suffix + ".tmp")
    tmp_path.write_text(dart_code, encoding="utf-8")
    os.replace(tmp_path, dart_out_path)
    print(f"      -> تم تصدير الأوزان إلى: {dart_out_path}")


# ============================================================================
# كتابة والتحقق الذاتي والتوقيع الرقمي Ed25519 لملفات SPDB v1 و manifest.json
# ============================================================================

def verify_spdb_bytes(data: bytes, expected_type: int) -> dict[str, object]:
    """تحقق ذاتي مطابق 100% لـ SpdbTable.fromBytes في Dart قبل التوقيع والنشر."""
    if len(data) < SPDB_HEADER_SIZE:
        raise ValueError("ملف SPDB أصغر من الترويسة.")
    magic, version, db_type, build_ts, count, flags = struct.unpack(
        ">4sHHQII", data[:24]
    )
    if magic != SPDB_MAGIC or version != SPDB_VERSION or db_type != expected_type or flags != 0:
        raise ValueError("ترويسة SPDB غير صالحة أو غير مطابقة.")
    expected_len = SPDB_HEADER_SIZE + (count * SPDB_ENTRY_SIZE)
    if len(data) != expected_len:
        raise ValueError(f"حجم SPDB غير مطابق: {len(data)} != {expected_len}")

    header_digest = data[24:56]
    computed = hashlib.sha256(data[:24] + data[SPDB_HEADER_SIZE:]).digest()
    if computed != header_digest:
        raise ValueError("فشل التحقق الذاتي من بصمة SHA-256 داخل SPDB.")

    # التحقق من الترتيب التصاعدي الصارم بدون تكرار
    prev: bytes | None = None
    for off in range(SPDB_HEADER_SIZE, len(data), SPDB_ENTRY_SIZE):
        cur = data[off : off + SPDB_ENTRY_SIZE]
        if prev is not None and cur <= prev:
            raise ValueError("فهرس SPDB غير مرتب تصاعدياً بصرامة.")
        prev = cur

    return {
        "spdb_version": version,
        "db_type": db_type,
        "build_timestamp_utc": build_ts,
        "entry_count": count,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "header_sha256": header_digest.hex(),
    }


def write_spdb_file(
    output_path: Path,
    db_type: int,
    hashes: set[bytes],
    build_timestamp: int,
) -> dict[str, object]:
    sorted_hashes = sorted(hashes)
    payload = b"".join(sorted_hashes)
    count = len(sorted_hashes)

    header_prefix = struct.pack(
        ">4sHHQII",
        SPDB_MAGIC,
        SPDB_VERSION,
        db_type,
        build_timestamp,
        count,
        0,
    )
    if len(header_prefix) != 24:
        raise RuntimeError("خطأ داخلي في حجم ترويسة SPDB.")

    digest = hashlib.sha256(header_prefix + payload).digest()
    if len(digest) != 32:
        raise RuntimeError("خطأ داخلي في حجم بصمة SHA-256.")

    full_bytes = header_prefix + digest + payload
    meta = verify_spdb_bytes(full_bytes, expected_type=db_type)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    tmp_path.write_bytes(full_bytes)
    os.replace(tmp_path, output_path)
    meta["filename"] = output_path.name
    return meta


def generate_ed25519_keypair(out_dir: Path) -> None:
    """توليد زوج مفاتيح Ed25519 جديد لمرة واحدة (المفتاح الخاص يُحفظ في GitHub Secrets فقط)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise RuntimeError(
            "مكتبة cryptography مطلوبة لتوليد مفاتيح Ed25519. ثبّتها عبر: pip install cryptography"
        ) from exc

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    priv_path = out_dir / "spectre_spdb_ed25519_private.pem"
    pub_path = out_dir / "spectre_spdb_ed25519_public.pem"

    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass

    print("=== تم توليد زوج مفاتيح Ed25519 بنجاح ===")
    print(f"• المفتاح الخاص (سري للغاية - أضفه لـ GitHub Secrets ولا ترفعه لـ Git): {priv_path}")
    print(f"• المفتاح العام PEM: {pub_path}")
    print(f"• المفتاح العام الخام (32-byte Base64 للتضمين في التطبيق): {base64.b64encode(public_raw).decode('ascii')}")
    print(f"• المفتاح العام الخام (Hex): {public_raw.hex()}")


def write_signed_manifest(
    out_dir: Path,
    threats_meta: dict[str, object],
    build_timestamp: int,
    key_id: str,
    sign_key_env: str | None,
) -> tuple[Path, Path | None]:
    """إنشاء manifest.json وتوقيعه بـ Ed25519 عبر متغير البيئة الآمن."""
    manifest_obj = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "key_id": key_id,
        "released_at_utc": build_timestamp,
        "min_app_spdb_version": SPDB_VERSION,
        "threats": {
            "filename": threats_meta["filename"],
            "spdb_version": threats_meta["spdb_version"],
            "db_type": threats_meta["db_type"],
            "build_timestamp_utc": threats_meta["build_timestamp_utc"],
            "entry_count": threats_meta["entry_count"],
            "size_bytes": threats_meta["size_bytes"],
            "sha256": threats_meta["sha256"],
            "header_sha256": threats_meta["header_sha256"],
        },
    }

    manifest_bytes = (
        json.dumps(manifest_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")

    manifest_path = out_dir / "manifest.json"
    tmp_manifest = manifest_path.with_suffix(".json.tmp")
    tmp_manifest.write_bytes(manifest_bytes)
    os.replace(tmp_manifest, manifest_path)

    sig_path: Path | None = None
    if sign_key_env:
        pem_raw = os.environ.get(sign_key_env, "").strip()
        if not pem_raw:
            raise RuntimeError(
                f"متغير البيئة '{sign_key_env}' فارغ أو غير موجود؛ تعذر توقيع manifest.json."
            )
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError as exc:
            raise RuntimeError(
                "مكتبة cryptography مطلوبة للتوقيع بـ Ed25519. ثبّتها عبر: pip install cryptography"
            ) from exc

        loaded_key = serialization.load_pem_private_key(
            pem_raw.encode("utf-8"), password=None
        )
        if not isinstance(loaded_key, Ed25519PrivateKey):
            raise RuntimeError("المفتاح الممرّر ليس مفتاح Ed25519 خاصاً صالحاً.")

        signed_message = MANIFEST_SIGNATURE_DOMAIN + manifest_bytes
        signature = loaded_key.sign(signed_message)
        # تحقق ذاتي فوري من التوقيع بالمفتاح العام قبل كتابته
        loaded_key.public_key().verify(signature, signed_message)

        sig_path = out_dir / "manifest.sig"
        tmp_sig = sig_path.with_suffix(".sig.tmp")
        tmp_sig.write_text(
            base64.b64encode(signature).decode("ascii") + "\n", encoding="utf-8"
        )
        os.replace(tmp_sig, sig_path)

    return manifest_path, sig_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="توليد قواعد SPDB v1 وأوزان النموذج المحلي والبيان الموقّع Ed25519 لتطبيق Spectre Advisor"
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("assets/threat_db"),
        help="مجلد حفظ ملفي threats.bin و whitelist.bin (الافتراضي: assets/threat_db)",
    )
    parser.add_argument(
        "--ml-out",
        type=Path,
        default=Path("lib/features/link_analyzer/domain/url_ml_weights.dart"),
        help="مسار تصدير أوزان النموذج المحلي بصيغة Dart",
    )
    parser.add_argument(
        "--max-whitelist",
        type=int,
        default=150_000,
        help="الحد الأقصى لنطاقات القائمة البيضاء (الافتراضي: 150000)",
    )
    parser.add_argument(
        "--max-threats",
        type=int,
        default=150_000,
        help="الحد الأقصى لبصمات التهديدات (الافتراضي: 150000)",
    )
    parser.add_argument(
        "--skip-whitelist",
        action="store_true",
        help="تخطّي كتابة whitelist.bin (مفيد لبناء تحديث threats.bin الأسبوعي فقط)",
    )
    parser.add_argument(
        "--skip-ml",
        action="store_true",
        help="تخطّي إعادة تدريب وتصدير url_ml_weights.dart (مفيد لـ GitHub Actions OTA)",
    )
    parser.add_argument(
        "--emit-manifest",
        action="store_true",
        help="توليد manifest.json لتحديثات OTA",
    )
    parser.add_argument(
        "--sign-key-env",
        type=str,
        default=None,
        help="اسم متغير البيئة الحاوي لمفتاح Ed25519 الخاص PEM لتوقيع manifest.json (مثلاً: SPECTRE_SPDB_ED25519_PRIVATE_KEY)",
    )
    parser.add_argument(
        "--key-id",
        type=str,
        default=DEFAULT_KEY_ID,
        help=f"معرّف مفتاح التوقيع داخل manifest.json (الافتراضي: {DEFAULT_KEY_ID})",
    )
    parser.add_argument(
        "--generate-keypair",
        type=Path,
        default=None,
        help="توليد زوج مفاتيح Ed25519 جديد في المجلد المحدد والخروج",
    )
    args = parser.parse_args()

    if args.generate_keypair is not None:
        generate_ed25519_keypair(args.generate_keypair)
        return 0

    build_ts = int(time.time())
    print("=== Spectre Advisor: بناء قواعد التهديدات والنموذج المحلي (SPDB v1 + ML) ===")

    # تحميل Tranco دائماً لحماية أعلى 50,000 موقع عالمي من الحظر النطاقي العرضي حتى في وضع --skip-whitelist
    tranco_limit = 50_000 if (args.skip_whitelist and args.skip_ml) else args.max_whitelist
    tranco_domains = fetch_tranco_domains(tranco_limit)
    if len(tranco_domains) < 50_000:
        raise RuntimeError(
            f"قائمة Tranco ناقصة ({len(tranco_domains):,} نطاق)؛ تم إيقاف البناء لحماية القاعدة."
        )

    tranco_protected = set(tranco_domains[:50_000])

    threat_hashes, malicious_hosts, malicious_reg_domains = fetch_threats(
        tranco_protected_set=tranco_protected,
        max_entries=args.max_threats,
    )

    clean_benign_domains: list[str] = []
    whitelist_meta: dict[str, object] | None = None
    if not args.skip_whitelist or not args.skip_ml:
        whitelist_hashes, clean_benign_domains = build_whitelist_hashes(
            tranco_domains=tranco_domains,
            malicious_reg_domains=malicious_reg_domains,
            max_entries=args.max_whitelist,
        )
        if not args.skip_whitelist:
            whitelist_path = args.out_dir / "whitelist.bin"
            whitelist_meta = write_spdb_file(
                whitelist_path, DB_TYPE_WHITELIST, whitelist_hashes, build_ts
            )

    if not args.skip_ml:
        train_and_export_ml_weights(
            malicious_hosts=malicious_hosts,
            benign_domains=clean_benign_domains,
            dart_out_path=args.ml_out,
            build_timestamp=build_ts,
        )

    threats_path = args.out_dir / "threats.bin"
    threats_meta = write_spdb_file(
        threats_path, DB_TYPE_THREATS, threat_hashes, build_ts
    )

    manifest_path: Path | None = None
    sig_path: Path | None = None
    if args.emit_manifest or args.sign_key_env:
        manifest_path, sig_path = write_signed_manifest(
            out_dir=args.out_dir,
            threats_meta=threats_meta,
            build_timestamp=build_ts,
            key_id=args.key_id,
            sign_key_env=args.sign_key_env,
        )

    threats_size = int(threats_meta["size_bytes"])
    print("\n=== اكتمل البناء والتحقق الذاتي بنجاح ===")
    print(f"• {threats_path} : {len(threat_hashes):>7,} بصمة | {threats_size / (1024 * 1024):.2f} MB")
    print(f"  SHA-256 : {threats_meta['sha256']}")
    if whitelist_meta is not None:
        wl_size = int(whitelist_meta["size_bytes"])
        print(
            f"• {args.out_dir / 'whitelist.bin'} : {int(whitelist_meta['entry_count']):>7,} نطاق | "
            f"{wl_size / (1024 * 1024):.2f} MB"
        )
    if not args.skip_ml:
        print(f"• {args.ml_out} : جاهز للدمج في المحرك")
    if manifest_path is not None:
        print(f"• {manifest_path} : جاهز للنشر")
    if sig_path is not None:
        print(f"• {sig_path} : موقّع بـ Ed25519 ومُتحقّق منه ذاتياً")
    print(f"• الطابع الزمني UTC : {build_ts} ({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(build_ts))})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
