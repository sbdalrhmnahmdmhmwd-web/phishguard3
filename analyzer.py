"""PhishGuard analyzer: rule-based URL risk scoring (standard library only).
Use it from code:  from analyzer import analyze
Or from terminal:  python analyzer.py "http://paypa1-login.xyz/verify"
"""
import ipaddress, math, re, sys, json
from collections import Counter
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "support", "loan", "icu", "buzz", "rest"}
KEYWORDS = ["login", "signin", "verify", "update", "secure", "account", "password", "banking", "confirm",
            "wallet", "suspend", "unlock", "billing", "invoice", "recovery", "authenticate"]
BRANDS = ["paypal", "google", "facebook", "instagram", "microsoft", "apple", "amazon", "netflix",
          "whatsapp", "twitter", "linkedin", "github", "dropbox", "binance", "paymob", "fawry"]
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}


def _lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _normalize(label):
    label = label.translate(str.maketrans("013457", "oleast"))
    return label.replace("rn", "m").replace("vv", "w")


def _entropy(s):
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def _split_host(host):
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return labels[:-3], labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[:-2], labels[-2], labels[-1]
    return [], host, ""


def analyze(raw):
    raw = (raw or "").strip()
    if not raw or len(raw) > 2048:
        raise ValueError("Enter a URL between 1 and 2048 characters.")
    has_scheme = "://" in raw
    p = urlparse(raw if has_scheme else "http://" + raw)
    host = (p.hostname or "").lower()
    if not host:
        raise ValueError("That doesn't look like a URL.")

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    sub, main, suffix = ([], host, "") if is_ip else _split_host(host)
    path = p.path + ("?" + p.query if p.query else "")
    findings = []

    def add(points, title, why):
        findings.append({"points": points, "title": title, "why": why})

    if has_scheme and p.scheme == "http":
        add(10, "No HTTPS", "The connection isn't encrypted, so anything you type (passwords, card numbers) can be read on the way. Real login pages use HTTPS.")
    if is_ip:
        add(30, "Raw IP address instead of a domain name", "Legit companies use names like paypal.com. Attackers often host on a bare IP because it's quick and anonymous.")
    if "@" in (p.netloc or ""):
        add(25, "Contains an @ symbol", "Browsers ignore everything before the @, so 'bank.com@evil.com' actually goes to evil.com.")
    if host.startswith("xn--") or ".xn--" in host:
        add(25, "Punycode (xn--) in the domain", "This can hide lookalike characters, like a Cyrillic 'а' that looks exactly like a Latin 'a'.")
    if host in SHORTENERS:
        add(20, "URL shortener", "You can't see where it really leads. Attackers use shorteners to hide the real destination.")
    if suffix.split(".")[-1] in RISKY_TLDS:
        add(15, "Risky domain ending (." + suffix.split(".")[-1] + ")", "Cheap or free endings are used in a lot of phishing campaigns, so they get abused more than .com or .edu.")
    if len(sub) >= 3:
        add(15, str(len(sub)) + " subdomains stacked up", "Long chains like login.secure.account.example.com are used to push a trusted-looking word to the front.")
    if len(raw) > 100:
        add(10, "Very long URL", "Long URLs can bury the real domain or hide tracking and redirect data.")
    if host.count("-") >= 3 or (not is_ip and main.count("-") >= 2):
        add(10, "Many hyphens in the domain", "Domains like secure-paypal-login-verify.com are a classic phishing pattern.")
    if re.search(r"%[0-9a-fA-F]{2}", raw) and raw.count("%") >= 3:
        add(10, "Lots of percent-encoding", "Encoding is sometimes used to disguise what the link really contains.")
    if p.port and p.port not in (80, 443):
        add(10, "Unusual port :" + str(p.port), "Normal websites almost always use the standard web ports.")
    if re.search(r"(//|https?:)", path) and "redirect" in path.lower():
        add(10, "Redirect inside the URL", "The link may bounce you to a different site after loading.")

    hits = [k for k in KEYWORDS if k in (host + path).lower()]
    if hits:
        add(min(20, 7 * len(hits)), "Pressure words: " + ", ".join(hits[:4]), "Words like login, verify and update are used to make you feel you must act right now.")

    if not is_ip:
        norm = _normalize(main)
        for b in BRANDS:
            if main == b:
                break
            if norm == b or (len(b) >= 5 and _lev(main, b) == 1):
                add(35, "Looks like a fake of '" + b + "'", "'" + main + "' is one character away from the real brand. This trick is called typosquatting.")
                break
            if b in host or b in _normalize(host):
                add(30, "Uses the brand name '" + b + "' on a different domain", "The real domain is '" + main + "." + suffix + "', not " + b + ".com. Attackers put brand names in subdomains or paths to look official.")
                break
        if len(main) >= 12 and _entropy(main) > 3.3:
            add(10, "Random-looking domain name", "Auto-generated names are common in throwaway phishing sites.")
        if sum(ch.isdigit() for ch in main) >= 4:
            add(8, "Lots of digits in the domain", "Real brands rarely put numbers all over their domain name.")

    score = min(100, sum(f["points"] for f in findings))
    findings.sort(key=lambda f: -f["points"])
    verdict = "safe" if score < 25 else "suspicious" if score < 55 else "dangerous"
    return {
        "url": raw,
        "score": score,
        "verdict": verdict,
        "parts": {"scheme": p.scheme + "://" if has_scheme else "", "subdomain": ".".join(sub) + "." if sub else "",
                  "domain": main, "suffix": ("." + suffix) if suffix else "", "path": path},
        "findings": findings,
        "note": None if has_scheme else "No http:// or https:// was given, so the HTTPS check was skipped.",
    }


if __name__ == "__main__":
    print(json.dumps(analyze(sys.argv[1]), indent=2))
