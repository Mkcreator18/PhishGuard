# PhishGuard v3.0 — Complete Master Prompt (Scratch to End)

Use this prompt to recreate the entire PhishGuard project from scratch with any AI coding tool.

---

## PROJECT OVERVIEW

Build **PhishGuard v3.0** — a production-grade Google Chrome Extension (Manifest V3) for real-time phishing detection and prevention, combined with a Python Flask backend. The system uses multi-layer detection: URL heuristics, Shannon entropy (DGA analysis), typosquatting detection, behavioral DOM analysis, Gmail NLP scanning, PhishTank live database integration, and IP geolocation intelligence.

---

## FOLDER STRUCTURE

```
PhishGuard-AI/
├── backend/
│   ├── app.py                    # Flask REST API + PhishTank integration
│   ├── model.py                  # Deterministic URL analyzer + NLP engine
│   └── requirements.txt          # flask, flask-cors, requests
├── extension/
│   ├── manifest.json             # Chrome MV3 manifest
│   ├── background.js             # Service worker (core engine)
│   ├── content.js                # DOM behavioral + Gmail NLP scanner
│   ├── openphish_database.txt    # Static phishing URL blocklist (one per line)
│   ├── shared/
│   │   └── constants.js          # All shared constants (imported everywhere)
│   ├── popup/
│   │   ├── popup.html            # Extension popup with Scanner + Gmail tabs
│   │   ├── popup.css             # Dark/light theme styles
│   │   └── popup.js              # Popup logic
│   ├── blocked/
│   │   ├── blocked.html          # Block page shown when threat detected
│   │   ├── blocked.css           # Block page styles (dark/light)
│   │   └── blocked.js            # Block page logic
│   ├── dashboard/
│   │   ├── dashboard.html        # Full analytics dashboard
│   │   ├── dashboard.css         # Dashboard styles
│   │   └── dashboard.js          # Dashboard logic + report generator
│   ├── settings/
│   │   ├── settings.html         # Settings page
│   │   ├── settings.css          # Settings styles
│   │   └── settings.js           # Settings logic
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
└── README.md
```

---

## PART 1 — SHARED CONSTANTS (extension/shared/constants.js)

Single source of truth imported by background.js, content.js, popup.js, dashboard.js, settings.js via manifest content_scripts and web_accessible_resources.

Include these constants:

**BLOCK_THRESHOLD** = 50

**TRUSTED_DOMAINS** — Set of 50+ known-safe domains including:
google.com, mail.google.com, docs.google.com, accounts.google.com, youtube.com,
github.com, gitlab.com, linkedin.com, microsoft.com, office.com, live.com,
outlook.com, apple.com, icloud.com, twitter.com, x.com, facebook.com,
instagram.com, whatsapp.com, telegram.org, discord.com, slack.com, zoom.us,
notion.so, anthropic.com, claude.ai, openai.com, chatgpt.com, paypal.com,
stripe.com, amazon.com, netflix.com, spotify.com, adobe.com, dropbox.com,
vercel.app, netlify.app, heroku.com, render.com, railway.app, supabase.com,
auth0.com, okta.com, allegro.pl, allegrolokalnie.pl, olx.pl, reddit.com,
stackoverflow.com, wikipedia.org, npmjs.com, pypi.org, cloudflare.com

**TRUSTED_TLDS** — Set: .edu, .edu.in, .ac.in, .ac.uk, .gov, .gov.in, .gov.uk, .mil, .int, .org, .co.uk, .com.au, .co.in, .nic.in

**COLLEGE_KEYWORDS** — Array: ['ssmrv','nmkrv','rvce','rvpu','rvengg','vtu','pes']

**HIGH_RISK_TLDS** — Set of 30+ abused TLDs:
.xyz, .top, .pw, .cc, .club, .tk, .ml, .sbs, .icu, .vip, .gq, .cf, .ga,
.work, .racing, .date, .download, .cricket, .lat, .lol, .cyou, .bond, .hair,
.rest, .monster, .fun, .cfd, .digital, .click, .live, .world, .shop, .store

**MEDIUM_RISK_TLDS** — Set: .pro, .online, .site, .info, .biz, .ws, .mobi

**FREE_HOSTING** — Set: 000webhostapp.com, weebly.com, wixsite.com, wixstudio.com,
wix.com, blogspot.com, wordpress.com, glitch.me, pages.dev, web.app,
firebaseapp.com, surge.sh, tiiny.site

**URL_SHORTENERS** — Set: bit.ly, tinyurl.com, t.co, ow.ly, buff.ly, rebrand.ly,
short.io, cutt.ly, is.gd, tiny.cc, rb.gy

**TOP_BRANDS** — Array of 50+ brand names for typosquatting and impersonation:
Global: google, youtube, facebook, amazon, microsoft, apple, instagram, twitter,
linkedin, netflix, paypal, github, reddit, wikipedia, yahoo, bing, whatsapp,
telegram, discord, dropbox, spotify, adobe, stripe, shopify
Banking: chase, wellsfargo, bankofamerica, citibank, hsbc, barclays, ebay,
walmart, fedex, ups, dhl, usps, sbi, icici, hdfc, axis, kotak, santander,
nationwide, lloyds, natwest
Regional: allegro, allegrolokalnie, olx, mercadolibre, rakuten, flipkart,
snapdeal, paytm, phonepe, lazada, tokopedia, shopee, grab, gojek

**FAKE_CCTLD_PATTERNS** — Array: ['.pl-','.uk-','.de-','.fr-','.it-','.es-',
'.ru-','.cn-','.jp-','.au-','.ca-','.in-','.br-','.nl-','.se-']

**SENSITIVITY_THRESHOLDS** — { STRICT: 35, BALANCED: 50, RELAXED: 65 }

**ENTROPY_HIGH** = 3.8 (Shannon entropy threshold for DGA detection)
**ENTROPY_MED**  = 3.2
**CVR_THRESHOLD** = 3.5 (consonant-to-vowel ratio — DGA indicator)
**NUMERIC_RATIO_THRESHOLD** = 0.35 (>35% digits in domain = suspicious)

**OWASP** — Object mapping threat categories to OWASP labels:
{ CREDENTIAL: 'OWASP A02:Cryptographic Failures',
  ACCESS: 'OWASP A01:Broken Access Control',
  DESIGN: 'OWASP A04:Insecure Design',
  INTEGRITY: 'OWASP A08:Software & Data Integrity Failures',
  INJECTION: 'OWASP A03:Injection',
  SSRF: 'OWASP A10:Server-Side Request Forgery' }

**URGENCY_PHRASES** — Array of 20+ phishing social engineering phrases:
'your account has been suspended', 'verify immediately',
'unauthorized access detected', 'limited time offer', 'act now',
'click here to confirm', 'your account will be closed',
'confirm your identity', 'unusual sign-in activity',
'we detected suspicious', 'your password has expired',
'update your billing', 'verify your email', 'your account is at risk',
'immediate action required', 'failure to verify',
'your package could not be delivered', 'claim your prize',
'you have been selected', 'reactivate your account',
'security alert', 'login attempt blocked'

---

## PART 2 — MANIFEST (extension/manifest.json)

```json
{
  "manifest_version": 3,
  "name": "PhishGuard v3.0",
  "version": "3.0.0",
  "description": "Real-Time Phishing Detection using Heuristics, Shannon Entropy, NLP and PhishTank",
  "permissions": ["activeTab","scripting","storage","webNavigation","tabs","notifications","declarativeNetRequest"],
  "host_permissions": ["<all_urls>"],
  "background": { "service_worker": "background.js" },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["shared/constants.js", "content.js"],
    "run_at": "document_end"
  }],
  "action": {
    "default_popup": "popup/popup.html",
    "default_title": "PhishGuard Security Scanner",
    "default_icon": { "16": "icons/icon16.png", "48": "icons/icon48.png", "128": "icons/icon128.png" }
  },
  "options_page": "settings/settings.html",
  "web_accessible_resources": [{
    "resources": ["blocked/blocked.html","dashboard/dashboard.html","settings/settings.html","shared/constants.js"],
    "matches": ["<all_urls>"]
  }]
}
```

---

## PART 3 — BACKGROUND SERVICE WORKER (extension/background.js)

Import shared/constants.js via importScripts().

### On startup:
1. Load openphish_database.txt into a Set using fetch + chrome.runtime.getURL('../openphish_database.txt')
2. Load PhishTank list from backend GET http://localhost:5000/phishtank/list (fail silently if offline)

### Math functions:
- **shannonEntropy(str)** — Calculate Shannon entropy. H = -Σ p(c) × log2(p(c))
- **consonantVowelRatio(str)** — Count consonants / vowels. Return consonant count if no vowels.
- **numericRatio(str)** — digits.length / str.length
- **levenshtein(a, b)** — Standard DP implementation for typosquatting detection

### isTrusted(hostname):
- Check TRUSTED_DOMAINS Set (exact hostname + base domain)
- Check COLLEGE_KEYWORDS array
- Check TRUSTED_TLDS Set (hostname.endsWith)
- Return true if any match → immediately safe

### scanURL(url) — DETERMINISTIC, returns {score, findings}:
For each check, call add(points, '[SEVERITY] message — OWASP tag'):

1. Return {score:0, findings:[]} if isTrusted(hostname)
2. OpenPhish blocklist match → +80, CRITICAL
3. PhishTank local cache match → +80, CRITICAL
4. HTTP protocol → +20, HIGH, OWASP A02
5. HIGH_RISK_TLDS match → +25, HIGH, OWASP A04
6. MEDIUM_RISK_TLDS match → +10, MEDIUM, OWASP A04
7. FAKE_CCTLD_PATTERNS in hostname (e.g. ".pl-", ".uk-") → +40, CRITICAL, OWASP A04
8. FREE_HOSTING match → +15, MEDIUM, OWASP A04
9. URL_SHORTENERS match → +20, HIGH, OWASP A08
10. Punycode (xn-- or non-ASCII chars) → +35, CRITICAL, OWASP A04
11. IP address as hostname → +30, HIGH, OWASP A01
12. Typosquatting: levenshtein(domainPart, brand) ≤ 2 for each TOP_BRANDS brand → +40, CRITICAL, OWASP A04
13. Brand name IN hostname but hostname doesn't end with brand.com/.pl/.org/.net → +30, HIGH, OWASP A04
14. Shannon entropy > ENTROPY_HIGH (3.8) → +30, HIGH, OWASP A08
15. Shannon entropy > ENTROPY_MED (3.2) → +15, MEDIUM, OWASP A08
16. consonantVowelRatio > CVR_THRESHOLD (3.5) → +20, HIGH, OWASP A08
17. numericRatio of domain part > 0.35 → +20, HIGH, OWASP A08
18. numericRatio of any SUBDOMAIN > 0.35 → +25, HIGH, OWASP A08
19. Any subdomain with length≥8 AND shannonEntropy>3.5 → +20, HIGH, OWASP A08
20. Subdomain depth ≥ 3 levels → +15, MEDIUM, OWASP A01
21. 3+ hyphens in hostname → +15, MEDIUM
22. Sensitive keywords in base domain (secure, login, verify, update, banking, account, confirm, suspended, unusual, signin, webscr, checkout, oferta, offer, payment, invoice, reward, prize, winner, bonus) → +12 each, HIGH, OWASP A04
23. Redirect params in query (redirect, returnurl, next, callback, goto, target) → +15, MEDIUM, OWASP A10
24. URL length > 200 → +10, LOW
25. Data URI → +40, CRITICAL, OWASP A08
Cap score at 100.

### State management — CRITICAL:
Use chrome.storage.session (NOT in-memory objects — service workers sleep and lose memory).
Key: "tab_{tabId}" → { score, findings, url, status, ts }
Functions: getState(tabId), setState(tabId, data), clearState(tabId)

### Badge:
- score ≥ 50: red "!" badge
- score 25–49: amber "?" badge
- score < 25: clear badge text

### handleNavigation(tabId, url):
1. Skip chrome://, about:, chrome-extension:// URLs
2. Check whitelist → setState safe, return
3. Check blacklist → block immediately, log, navigate to blocked.html
4. Run scanURL
5. Run PhishTank live check via GET localhost:5000/phishtank/check?url=... (async, add to score if match)
6. setState with result
7. If score ≥ threshold AND not in bypassedTabs → logThreat, navigate to blocked.html
8. Else → run enrichWithThreatIntel async (IP geolocation via ip-api.com)

### BYPASS handler — CRITICAL FIX:
When user clicks "Proceed Anyway" on blocked page:
1. Store bypassedTabs["{tabId}_{url}"] = true in chrome.storage.local BEFORE navigating
2. Call clearState(tabId)
3. setTimeout 100ms then chrome.tabs.update(tabId, {url})
4. Reply {ok:true}
The 100ms delay ensures storage write completes before webNavigation.onCommitted fires.

### Message handlers:
- GET_STATE: reply with getState(tabId)
- CONTENT_FINDINGS: merge extraScore+findings, re-evaluate threshold, block if exceeded
- BYPASS: store bypass flag with 100ms delay, clearState, navigate
- REPORT_PHISHING: add to reportedSites + blacklist + logThreat, notify backend
- RELOAD_PHISHTANK: re-fetch PhishTank list from backend

### Events:
- webNavigation.onCommitted (frameId === 0 only)
- webNavigation.onHistoryStateUpdated
- tabs.onRemoved → clearState

---

## PART 4 — CONTENT SCRIPT (extension/content.js)

Guard: if (window.__phishguardRan) return; window.__phishguardRan = true;

CRITICAL: Check if hostname is in TRUSTED_DOMAINS at the top — return immediately if trusted. This prevents false positives on trusted sites.

DOM behavioral checks (only run on non-trusted domains):
1. Password field + brand mention in page text but domain ≠ brand → +35, CRITICAL, OWASP A02
2. Form action submits to different hostname → +40, CRITICAL, OWASP A02
3. Hidden inputs with sensitive field names (pass|secret|card|cvv|ssn|dob|credit) — use word boundaries → +20, HIGH, OWASP A03
4. External scripts from HIGH_RISK_SRC TLDs → +30, HIGH, OWASP A08
5. 2+ cross-origin iframes → +20, MEDIUM, OWASP A04
6. Meta-refresh with delay < 5s → +25, HIGH, OWASP A04
7. STRICT clipboard check — ONLY flag if document.body has oncopy/oncut ATTRIBUTE, OR inline script (not external) contains clipboardData.setData. DO NOT scan innerHTML for "ClipboardEvent" — this causes false positives on legitimate React/framework sites. → +25, HIGH, OWASP A03
8. Redirect chain ≥ 3 (not 2) → +15, MEDIUM, OWASP A04
9. Page title contains brand but domain doesn't + domain doesn't end with .google.com → +25, HIGH, OWASP A04
10. 3+ URGENCY_PHRASES in body text → +20, MEDIUM, OWASP A04
11. Gmail scanner (only on mail.google.com):
    - Query .a3s and .gmail_quote elements
    - Check URGENCY_PHRASES in email text
    - Detect link text ≠ href domain mismatch
    - Detect brand mention with external link

Send via chrome.runtime.sendMessage({type:'CONTENT_FINDINGS', url, extraScore, findings}) only if extraScore > 0.

---

## PART 5 — POPUP (popup/popup.html + popup.css + popup.js)

### HTML Structure:
- Header: shield logo, theme toggle (moon/sun SVG), dashboard icon button, settings icon button
- Tab bar: "Scanner" tab | "📧 Gmail" tab
- Scanner pane:
  - Semi-circular SVG meter (viewBox 0 0 120 70, arc path from 10,70 to 110,70, radius 60, stroke-width 10, arc length 188)
  - Score number + "%" centered below meter
  - Status badge: ✅ Safe / ⚠️ Suspicious / 🚨 Threat Detected
  - URL display (truncated, title tooltip)
  - Findings list (only when threats exist) — use textContent NEVER innerHTML
  - Action buttons: Rescan, Report Phishing (shown only score ≥ 25)
- Gmail pane:
  - Info text, textarea for email paste, Scan button, result display
- Confirmation dialog overlay for Report Phishing

### JS behavior:
- On open: query active tab, send GET_STATE, render result
- Theme: stored in chrome.storage.sync as "theme"
- Scan state loaded from chrome.storage.session via background (persists across popup open/close)
- Rescan: remove session key, reload tab, close popup
- Report: show confirmation dialog → REPORT_PHISHING message
- Gmail tab: scan text using URGENCY_PHRASES from constants, scan embedded URLs using client-side heuristics
- NEVER use innerHTML with untrusted data

---

## PART 6 — BLOCKED PAGE (blocked/blocked.html + blocked.css + blocked.js)

### HTML:
- Pulsing red animated shield (CSS keyframes animation)
- "Threat Blocked" heading in red
- Blocked URL card (monospace, red text, textContent only)
- Risk score pill (red background)
- Primary threat reason box (left red border, textContent)
- Buttons: "← Go Back to Safety", "Proceed Anyway", "🚨 Report as Phishing"
- Confirmation dialog for report
- Footer: PhishGuard v3.0 · View Dashboard · Switch Theme

### JS behavior:
- Parse url, score, reason from URLSearchParams — use decodeURIComponent
- Go Back: history.back() OR chrome.tabs.create({url:'https://google.com'}) if no history
- Proceed Anyway: send BYPASS message to background. Background stores bypass flag, then navigates. Do NOT navigate from the blocked page itself.
- Report: show dialog → on confirm send REPORT_PHISHING → disable button, show "✅ Reported & Blocked"
- Theme toggle synced with chrome.storage.sync

### CSS:
Dark theme default (background: #0a0c12, radial red gradient at top).
Light theme (.light class on body): background: #fef2f2, surface: white, warm red tints.
Full CSS variable system, smooth transition on theme switch.

---

## PART 7 — DASHBOARD (dashboard/dashboard.html + dashboard.css + dashboard.js)

### HTML Sections:
1. Nav: logo, theme button, "⟳ PhishTank" reload button, "⬇ Download Report" button
2. Stats grid (4 cards): Total Threats, Critical ≥75, High 50–74, User Reported
3. Two-column row:
   - PhishTank status card: Backend status, entry count, last updated, API key status + numbered step guide to get API key
   - URL Scanner: input + Scan button, result display with score, entropy, CVR, PhishTank match info, findings list
4. Gmail Sandbox: textarea + scan button, result with score + findings
5. Charts row: Donut/pie chart (Canvas, no libraries), Line chart with gradient fill (Canvas)
6. Threat Log table: URL, Score chip, Primary Threat, Source (PhishTank vs Heuristic), Time
7. User-Reported Sites table

### URL Scanner — CRITICAL:
First try backend (POST localhost:5000/analyze, 6s timeout).
If backend offline → run full client-side JS heuristic scanner that MIRRORS background.js scoring.
The client-side scanner must implement all the same checks as background.js scanURL() function.
NEVER show 0% just because backend is offline.

### Gmail Sandbox:
Scan pasted text using URGENCY_PHRASES, extract and scan URLs using client-side scanner.
Also try backend POST /analyze/text for NLP analysis.

### Report Download:
Generate complete styled HTML report (dark theme) containing:
- Header with generation timestamp
- Executive summary (4 stat cards)
- OWASP breakdown table (frequency per category)
- User-Reported Sites table
- Full Threat Log (URL, score, primary threat, source, timestamp)
Escape all data with HTML entities before inserting.

### PhishTank API Key Guide (numbered steps in card):
1. Register at phishtank.com/register.php
2. Create free account & confirm email
3. Visit phishtank.com/api_register.php
4. Register your app → API key displayed
5. Run: set PHISHTANK_API_KEY=your_key && python app.py

---

## PART 8 — SETTINGS (settings/settings.html + settings.css + settings.js)

### Sections:
1. Detection Sensitivity: 3 radio cards (Strict ≥35 / Balanced ≥50 / Relaxed ≥65) — styled as clickable boxes, checked one gets accent border
2. Detection Modules (toggle switches): Behavioral DOM Analysis, Typosquatting, Punycode/IDN, URL Shortener, OpenPhish Lookup, Redirect Chain, Brand Impersonation, Malicious Script Detection, Shannon Entropy/DGA Analysis, Gmail NLP Scanner, IP Geolocation Intel
3. Personal Whitelist: text input + Add button (strips http:// and paths), list with × remove buttons
4. Personal Blacklist: same as whitelist
5. Data Management: "Clear Threat Logs" + "Reset All Data" buttons with confirm()
6. Save button → saves sensitivity + module toggles to chrome.storage.local

Theme synced with chrome.storage.sync.

---

## PART 9 — BACKEND (backend/app.py + backend/model.py)

### app.py:
Flask + CORS.
PhishTank integration:
- Download URL: http://data.phishtank.com/data/{API_KEY}/online-valid.json.bz2
- API key from env: PHISHTANK_API_KEY (empty string if not set)
- Use User-Agent: 'phishguard-security-extension/3.0'
- Decompress with bz2, parse JSON
- Refresh every 2 hours (PHISHTANK_REFRESH_INTERVAL = 7200)
- On 429 error: log clear message "Set PHISHTANK_API_KEY for higher limits", retry after 30 min
- Run in background daemon thread, wait 60s before first attempt
- URL lookup: match by exact URL, URL substring, OR hostname match

Endpoints:
- POST /analyze → analyze_url() + PhishTank enrichment
- POST /analyze/text → analyze_text() NLP
- GET /phishtank/list → return all URLs for extension caching
- GET /phishtank/check?url= → single URL check
- POST /phishtank/report → log user-reported URL to user_reported.txt
- POST /phishtank/reload → trigger background reload
- GET /phishtank/stats → {total_entries, last_updated, next_update_in, api_key_set, status}
- GET /health → {status, version, phishtank_entries}

### model.py:
Pure Python, NO random module, fully deterministic.
Implement all the same detection logic as background.js scanURL() in Python:
- shannon_entropy(s), consonant_vowel_ratio(s), numeric_ratio(s), _levenshtein(a,b)
- Same TRUSTED_DOMAINS, HIGH_RISK_TLDS, FREE_HOSTING, TOP_BRANDS etc.
- Same scoring rules with same point values
- Same FAKE_CCTLD_PATTERNS check
- analyze_url(url) → {score, risk_level, is_phishing, entropy, cvr, findings}
- analyze_text(text) → {score, findings} for email NLP
- risk_level: 'Critical' ≥75, 'High' ≥50, 'Medium' ≥25, 'Safe' <25

requirements.txt: flask>=3.0.0, flask-cors>=4.0.0, requests>=2.31.0

---

## PART 10 — DESIGN SYSTEM

### CSS Variables (Dark Theme — default):
```
--bg: #0f1117          (main background)
--surface: #1a1d27     (cards, popup body)
--surface2: #22263a    (inputs, hover states)
--border: #2e3248      (borders, dividers)
--text: #e8eaf0        (primary text)
--text-muted: #7b82a0  (secondary text, labels)
--accent: #6366f1      (indigo — buttons, active states, logo)
--safe: #22c55e        (green — safe status)
--warn: #f59e0b        (amber — suspicious)
--danger: #ef4444      (red — threats, blocked)
--radius: 10px (popup) / 12px (full pages)
```

### Light Theme (.light class on body):
```
--bg: #f4f6fb
--surface: #ffffff
--surface2: #eef0f8
--border: #d8dce8
--text: #1a1d27
--text-muted: #6b7280
```

Blocked page light theme uses warm red tints:
```
--bg: #fef2f2
--surface2: #fee2e2
--border: #fecaca
```

Font: Inter via Google Fonts import in every CSS file.
Theme toggle: chrome.storage.sync key "theme" ("dark"/"light").
Apply by toggling .light class on document.body — all colors auto-switch.
Theme must be consistent and synced across ALL pages: popup, blocked, dashboard, settings.

---

## CRITICAL REQUIREMENTS (Non-negotiable)

1. **NEVER use innerHTML with untrusted data** — always textContent for user-visible content from URLs/findings
2. **NEVER use localStorage** — use chrome.storage.sync (theme/settings) and chrome.storage.session (tab scan state)
3. **NEVER use in-memory objects for tab state in background.js** — service workers sleep, memory is lost. Always use chrome.storage.session
4. **NEVER use Math.random() in scoring** — fully deterministic
5. **isTrusted() defined ONCE in shared** — never duplicated across files
6. **Content script MUST check trusted domains at top** — skip ALL DOM scanning for trusted sites (prevents claude.ai, google.com false positives)
7. **Clipboard hijacking detection MUST be strict** — only flag document.body oncopy/oncut attribute OR clipboardData.setData in inline scripts. NEVER scan innerHTML for "ClipboardEvent" — legitimate React/framework code triggers false positives
8. **Bypass (Proceed Anyway) MUST**: store bypass flag in chrome.storage.local BEFORE navigating, use 100ms setTimeout, reply {ok:true}. Background navigates — never navigate from blocked.js itself
9. **URL Scanner in dashboard MUST have client-side fallback** — when backend is offline, run full JS heuristics client-side. Never show 0% just because Flask is offline
10. **PhishTank 429 handling** — log clear message with fix instructions, retry after 30 min, never crash
11. **Block threshold ≥ 50** (Balanced default). Strict=35, Relaxed=65
12. **Trusted domains always score 0** — claude.ai, anthropic.com, vercel.app, netlify.app, render.com, github.com etc. must never be flagged
13. **Hyphens alone do NOT trigger high score** — only flag if 3+ hyphens combined with other signals
14. **Report as Phishing**: confirmation dialog first, then auto-add to blacklist + reportedSites array + log threat. On blocked page: disable button, show "✅ Reported & Blocked" in green
15. **All pages**: Inter font, CSS variable design system, smooth .2s theme transition, consistent color scheme

---

## SETUP INSTRUCTIONS

### Extension:
1. Open chrome://extensions
2. Enable Developer mode
3. Load unpacked → select extension/ folder
4. Add icons: extension/icons/icon16.png, icon48.png, icon128.png (use any shield/security PNG)

### Backend (optional — for PhishTank + deep NLP):
```bash
cd backend
pip install -r requirements.txt
# Optional: get free API key at phishtank.com/api_register.php
set PHISHTANK_API_KEY=your_key_here   # Windows
export PHISHTANK_API_KEY=your_key_here # Mac/Linux
python app.py
```

### PhishTank API Key (free):
1. Register: https://www.phishtank.com/register.php
2. Get key: https://www.phishtank.com/api_register.php
3. Set env var and restart backend

---
*PhishGuard v3.0 — Heuristic + PhishTank + Shannon Entropy + NLP Phishing Detection*
