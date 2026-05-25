# PhishGuard v3.0 — URL & NLP Analysis Model (Deterministic, no random)
import re, math
from urllib.parse import urlparse

TRUSTED_DOMAINS = {
  'google.com','github.com','microsoft.com','apple.com','amazon.com','facebook.com',
  'twitter.com','linkedin.com','youtube.com','wikipedia.org','stackoverflow.com',
  'reddit.com','paypal.com','stripe.com','shopify.com','netflix.com','spotify.com',
  'adobe.com','dropbox.com','slack.com','zoom.us','notion.so','claude.ai',
  'anthropic.com','openai.com','discord.com','telegram.org','whatsapp.com',
  'instagram.com','yahoo.com','bing.com','office.com','outlook.com','live.com',
  'vercel.app','netlify.app','heroku.com','render.com','railway.app','auth0.com',
  'allegro.pl','allegrolokalnie.pl','olx.pl','olx.com'
}
TRUSTED_TLDS   = ('.edu','.gov','.mil','.ac.uk','.gov.uk','.edu.in','.gov.in','.nic.in','.co.uk')
HIGH_RISK_TLDS = {
  '.xyz','.top','.pw','.cc','.club','.tk','.ml','.sbs','.icu','.vip',
  '.gq','.cf','.ga','.work','.racing','.date','.download','.cricket',
  '.lat','.lol','.cyou','.bond','.hair','.rest','.monster','.fun',
  '.cfd','.digital','.click','.live','.world','.shop','.store'
}
MEDIUM_RISK_TLDS = {'.pro','.online','.site','.info','.biz','.ws','.mobi'}
FREE_HOSTING     = {'000webhostapp.com','weebly.com','wixsite.com','wixstudio.com','wix.com','blogspot.com','wordpress.com','glitch.me','pages.dev','web.app','firebaseapp.com','surge.sh'}
URL_SHORTENERS   = {'bit.ly','tinyurl.com','t.co','ow.ly','buff.ly','rebrand.ly','cutt.ly','is.gd','rb.gy'}
FAKE_CCTLD_PATTERNS = ['.pl-','.uk-','.de-','.fr-','.it-','.es-','.ru-','.cn-','.jp-','.au-','.in-','.br-']

TOP_BRANDS = [
  'google','youtube','facebook','amazon','microsoft','apple','instagram','twitter',
  'linkedin','netflix','paypal','github','reddit','yahoo','bing','whatsapp',
  'telegram','discord','dropbox','spotify','adobe','stripe','shopify',
  'chase','wellsfargo','bankofamerica','citibank','hsbc','barclays','ebay',
  'walmart','fedex','ups','dhl','usps',
  'allegro','allegrolokalnie','olx','mercadolibre','rakuten','flipkart',
  'snapdeal','paytm','phonepe','lazada','tokopedia','shopee',
  'sbi','icici','hdfc','axis','kotak','santander','nationwide','lloyds','natwest'
]

DOMAIN_KEYWORDS = [
  'secure','login','verify','update','banking','account','confirm',
  'suspended','unusual','signin','webscr','checkout','oferta','offer',
  'payment','invoice','reward','prize','free','winner','bonus'
]

URGENCY_PHRASES = [
  'your account has been suspended','verify immediately','unauthorized access detected',
  'limited time offer','act now','click here to confirm','your account will be closed',
  'confirm your identity','unusual sign-in activity','we detected suspicious',
  'your password has expired','update your billing','verify your email',
  'your account is at risk','immediate action required','failure to verify',
  'your package could not be delivered','claim your prize','you have been selected',
  'reactivate your account','security alert','login attempt blocked'
]

OWASP = {
  'CREDENTIAL': 'OWASP A02:Cryptographic Failures',
  'ACCESS':     'OWASP A01:Broken Access Control',
  'DESIGN':     'OWASP A04:Insecure Design',
  'INTEGRITY':  'OWASP A08:Software & Data Integrity Failures',
  'SSRF':       'OWASP A10:Server-Side Request Forgery'
}

# ── Math ───────────────────────────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f/n) * math.log2(f/n) for f in freq.values())

def consonant_vowel_ratio(s: str) -> float:
    s = s.lower()
    v = sum(1 for c in s if c in 'aeiou')
    c = sum(1 for c in s if c in 'bcdfghjklmnpqrstvwxyz')
    return c / v if v > 0 else float(c)

def numeric_ratio(s: str) -> float:
    if not s: return 0.0
    return sum(1 for c in s if c.isdigit()) / len(s)

def _levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        ndp = [i]
        for j, cb in enumerate(b, 1):
            ndp.append(dp[j-1] if ca == cb else 1 + min(dp[j], ndp[-1], dp[j-1]))
        dp = ndp
    return dp[-1]

def _base_domain(hostname: str) -> str:
    parts = hostname.lstrip('www.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

def _is_trusted(hostname: str) -> bool:
    base = _base_domain(hostname)
    if hostname in TRUSTED_DOMAINS or base in TRUSTED_DOMAINS: return True
    return any(hostname.endswith(t) for t in TRUSTED_TLDS)

# ── NLP ────────────────────────────────────────────────────────────────────
def analyze_text(text: str) -> dict:
    findings, score = [], 0
    t = text.lower()
    matched = [p for p in URGENCY_PHRASES if p in t]
    if len(matched) >= 3:
        score += 35
        findings.append(f'[CRITICAL] Multiple urgency phrases: "{matched[0]}", "{matched[1]}" — social engineering — {OWASP["DESIGN"]}')
    elif matched:
        score += 15
        findings.append(f'[MEDIUM] Urgency language: "{matched[0]}" — {OWASP["DESIGN"]}')
    for brand in TOP_BRANDS:
        if brand in t:
            findings.append(f'[INFO] Text references brand "{brand}" — verify sender domain')
            break
    return {'score': min(score, 60), 'findings': findings}

# ── URL Analysis ───────────────────────────────────────────────────────────
def analyze_url(url: str) -> dict:
    findings, score = [], 0
    try:
        parsed   = urlparse(url if '://' in url else 'https://' + url)
        hostname = parsed.hostname or ''
        scheme   = parsed.scheme
        query    = parsed.query.lower()
    except Exception:
        return {'score': 0, 'risk_level': 'Safe', 'findings': [], 'is_phishing': False}

    base        = _base_domain(hostname)
    domain_part = base.rsplit('.', 1)[0] if '.' in base else base
    subdomains  = hostname.replace('www.', '').split('.')[:-2]

    if _is_trusted(hostname):
        return {'score': 0, 'risk_level': 'Safe', 'findings': [], 'is_phishing': False}

    def add(pts, msg):
        nonlocal score
        score += pts; findings.append(msg)

    if scheme == 'http':
        add(20, f'[HIGH] No HTTPS — {OWASP["CREDENTIAL"]}')

    tld = '.' + hostname.rsplit('.', 1)[-1] if '.' in hostname else ''
    if tld in HIGH_RISK_TLDS:          add(25, f'[HIGH] High-risk TLD "{tld}" — {OWASP["DESIGN"]}')
    elif tld in MEDIUM_RISK_TLDS:      add(10, f'[MEDIUM] Uncommon TLD "{tld}" — {OWASP["DESIGN"]}')

    if any(p in hostname for p in FAKE_CCTLD_PATTERNS):
        add(40, f'[CRITICAL] Fake ccTLD embedded in domain — domain spoofing — {OWASP["DESIGN"]}')

    if any(hostname.endswith(h) for h in FREE_HOSTING):
        add(15, f'[MEDIUM] Free hosting platform — {OWASP["DESIGN"]}')

    if base in URL_SHORTENERS:
        add(20, f'[HIGH] URL shortener — {OWASP["INTEGRITY"]}')

    if 'xn--' in hostname or any(ord(c) > 127 for c in hostname):
        add(35, f'[CRITICAL] Punycode/IDN homograph attack — {OWASP["DESIGN"]}')

    if re.match(r'^\d{{1,3}}(\.\d{{1,3}}){{3}}$', hostname):
        add(30, f'[HIGH] IP address as hostname — {OWASP["ACCESS"]}')

    for brand in TOP_BRANDS:
        if domain_part != brand and _levenshtein(domain_part, brand) <= 2 and len(domain_part) >= len(brand) - 1:
            add(40, f'[CRITICAL] Typosquatting — "{hostname}" mimics "{brand}" — {OWASP["DESIGN"]}')
            break

    for brand in TOP_BRANDS:
        if brand in hostname and not any(hostname.endswith(f'{brand}{s}') for s in ['.com','.pl','.org','.net']):
            add(30, f'[HIGH] Brand "{brand}" in non-official domain — {OWASP["DESIGN"]}')
            break

    entropy = shannon_entropy(domain_part)
    if entropy > 3.8:    add(30, f'[HIGH] Domain entropy {entropy:.2f} — DGA domain — {OWASP["INTEGRITY"]}')
    elif entropy > 3.2:  add(15, f'[MEDIUM] Elevated entropy {entropy:.2f} — {OWASP["INTEGRITY"]}')

    cvr = consonant_vowel_ratio(domain_part)
    if cvr > 3.5:
        add(20, f'[HIGH] Consonant/vowel ratio {cvr:.1f} — unreadable domain (DGA) — {OWASP["INTEGRITY"]}')

    # Numeric ratio checks
    dom_nr = numeric_ratio(domain_part)
    if dom_nr > 0.35:
        add(20, f'[HIGH] Domain is {round(dom_nr*100)}% digits — randomized pattern — {OWASP["INTEGRITY"]}')
    for sub in subdomains:
        sub_nr = numeric_ratio(sub)
        if sub_nr > 0.35:
            add(25, f'[HIGH] Subdomain "{sub}" is {round(sub_nr*100)}% digits — DGA pattern — {OWASP["INTEGRITY"]}')
            break

    # Random-looking subdomain entropy
    for sub in subdomains:
        if len(sub) >= 8 and shannon_entropy(sub) > 3.5:
            add(20, f'[HIGH] Random subdomain "{sub}" — phishing infrastructure — {OWASP["INTEGRITY"]}')
            break

    sub_count = hostname.count('.') - 1
    if sub_count >= 3:
        add(15, f'[MEDIUM] {sub_count} subdomain levels — {OWASP["ACCESS"]}')

    if base.count('-') >= 3:
        add(15, f'[MEDIUM] {base.count("-")} hyphens in domain')

    kw_hits = [k for k in DOMAIN_KEYWORDS if k in base]
    if kw_hits:
        add(min(len(kw_hits) * 12, 36), f'[HIGH] Sensitive keywords in domain: {", ".join(kw_hits)} — {OWASP["DESIGN"]}')

    redir = [p for p in ['redirect','returnurl','next','callback','goto','target'] if p in query]
    if redir:
        add(15, f'[MEDIUM] Redirect parameters: {", ".join(redir)} — {OWASP["SSRF"]}')

    if len(url) > 200:
        add(10, f'[LOW] URL length {len(url)} chars — obfuscation')

    if url.startswith('data:'):
        add(40, f'[CRITICAL] Data URI — {OWASP["INTEGRITY"]}')

    score      = min(score, 100)
    risk_level = 'Critical' if score >= 75 else 'High' if score >= 50 else 'Medium' if score >= 25 else 'Safe'

    return {
        'score':       score,
        'risk_level':  risk_level,
        'is_phishing': score >= 50,
        'entropy':     round(entropy, 2),
        'cvr':         round(cvr, 2),
        'findings':    findings
    }
