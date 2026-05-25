# PhishGuard v3.0

**Heuristic + PhishTank + Shannon Entropy + NLP-Based Real-Time Phishing Detection**

---

## Folder Structure

```
PhishGuard-AI/
├── backend/
│   ├── app.py                  # Flask API + PhishTank integration
│   ├── model.py                # Deterministic URL + NLP analyzer
│   ├── requirements.txt
│   └── user_reported.txt       # Auto-created: user-reported URLs
├── extension/
│   ├── manifest.json
│   ├── background.js           # Service worker + PhishTank live check
│   ├── content.js              # DOM behavioral + Gmail NLP scanner
│   ├── openphish_database.txt  # Static blocklist (one URL per line)
│   ├── shared/
│   │   └── constants.js        # All thresholds, brand lists, TLD sets
│   ├── popup/
│   ├── blocked/
│   ├── dashboard/              # PhishTank status, Gmail sandbox, URL scanner
│   ├── settings/
│   └── icons/
└── README.md
```

---

## Detection Layers

| Layer | Method | Catches |
|---|---|---|
| OpenPhish | Static blocklist | Known phishing URLs |
| PhishTank | Live API + local DB | Verified community-reported phishing |
| Heuristics | Rule-based scoring | Zero-day phishing, DGA, typosquatting |
| Shannon Entropy | Math | DGA-generated random domains |
| Consonant/Vowel Ratio | Math | Human-unreadable domains |
| Numeric Ratio | Math | Random numeric subdomains (e.g. 72634823g023) |
| Fake ccTLD | Pattern match | allegro.pl-evil.sbs style attacks |
| Levenshtein Distance | Edit distance | Typosquatting (allegro vs a1legro) |
| DOM Behavioral | content.js | Form hijack, credential harvest, scripts |
| Gmail NLP | content.js | Urgency language, link mismatches |
| IP Geolocation | ip-api.com | Proxy/VPN/datacenter abuse |

---

## Setup

### Extension
1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select `extension/` folder
4. Add your icon files: `icons/icon16.png`, `icons/icon48.png`, `icons/icon128.png`

### Backend (for PhishTank + NLP)
```bash
cd backend
pip install -r requirements.txt

# Optional: set your PhishTank API key
export PHISHTANK_API_KEY=your_key_here

python app.py
```

### Get a PhishTank API Key (free)
1. Register at https://www.phishtank.com/register.php
2. Go to https://www.phishtank.com/api_info.php
3. Request a free API key
4. Set: `export PHISHTANK_API_KEY=your_key`

Without a key, PhishTank allows limited downloads (still works, just rate-limited).

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/analyze` | Analyze URL (heuristics + PhishTank) |
| POST | `/analyze/text` | NLP analysis of email/page text |
| GET  | `/phishtank/list` | Get all PhishTank URLs for local caching |
| GET  | `/phishtank/check?url=...` | Check single URL against PhishTank |
| POST | `/phishtank/report` | Log user-reported phishing URL |
| GET  | `/phishtank/stats` | Database status and entry count |
| GET  | `/health` | Service health check |

---

## Why allegro.72634823g023.lat Is Now Detected

| Check | Result |
|---|---|
| `.lat` TLD | HIGH_RISK → +25 |
| Subdomain `72634823g023` is 77% digits | Numeric ratio → +25 |
| Shannon entropy of subdomain | High entropy → +20 |
| PhishTank lookup | If listed → +80 |
| **Total** | **≥70% → BLOCKED** |

## Why allegrolokalnie.pl-oferta7059717.sbs Is Now Detected

| Check | Result |
|---|---|
| `.sbs` TLD | HIGH_RISK → +25 |
| `.pl-` pattern in domain | Fake ccTLD → +40 |
| `allegrolokalnie` brand match | Brand in domain → +30 |
| `oferta` keyword | Sensitive keyword → +12 |
| **Total** | **≥100% → BLOCKED** |
