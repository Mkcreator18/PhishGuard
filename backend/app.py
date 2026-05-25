# PhishGuard v3.0 — Flask Backend with PhishTank Integration
import os, json, time, threading, requests, bz2, hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS
from model import analyze_url, analyze_text

app = Flask(__name__)
CORS(app)

# ── PhishTank Config ───────────────────────────────────────────────────────
PHISHTANK_API_KEY         = os.environ.get('PHISHTANK_API_KEY', '').strip()
PHISHTANK_CACHE           = []
PHISHTANK_URL_SET         = set()
PHISHTANK_LAST_UPDATE     = 0
PHISHTANK_REFRESH_INTERVAL = 7200   # 2 hours (avoid 429)
PHISHTANK_RETRY_AFTER     = 1800    # retry after 30 min on failure
_pt_lock                  = threading.Lock()

def _pt_url():
    if PHISHTANK_API_KEY:
        return f'http://data.phishtank.com/data/{PHISHTANK_API_KEY}/online-valid.json.bz2'
    # Without key: use the no-key endpoint (more rate-limited but works)
    return 'http://data.phishtank.com/data/online-valid.json.bz2'

def load_phishtank(force=False):
    global PHISHTANK_CACHE, PHISHTANK_URL_SET, PHISHTANK_LAST_UPDATE
    with _pt_lock:
        if not force and time.time() - PHISHTANK_LAST_UPDATE < PHISHTANK_REFRESH_INTERVAL:
            return
        try:
            print('[PhishGuard] Fetching PhishTank database...')
            headers = {
                'User-Agent': 'phishguard-security-extension/3.0 (research; contact@phishguard.dev)'
            }
            r = requests.get(_pt_url(), headers=headers, timeout=60, stream=True)
            r.raise_for_status()
            raw  = bz2.decompress(r.content)
            data = json.loads(raw)
            PHISHTANK_CACHE   = data
            PHISHTANK_URL_SET = set(
                e['url'].lower().strip() for e in data if e.get('url')
            )
            PHISHTANK_LAST_UPDATE = time.time()
            print(f'[PhishGuard] PhishTank loaded: {len(PHISHTANK_CACHE)} entries')
        except requests.HTTPError as e:
            status = e.response.status_code if e.response else 0
            if status == 429:
                print('[PhishGuard] PhishTank 429 rate-limited — set PHISHTANK_API_KEY env var for higher limits. Retrying in 30min.')
                PHISHTANK_LAST_UPDATE = time.time() - PHISHTANK_REFRESH_INTERVAL + PHISHTANK_RETRY_AFTER
            else:
                print(f'[PhishGuard] PhishTank HTTP error {status}: {e}')
        except Exception as e:
            print(f'[PhishGuard] PhishTank load failed: {e}')

def _pt_refresh_loop():
    # Wait 60s before first attempt to let server fully start
    time.sleep(60)
    while True:
        load_phishtank()
        time.sleep(300)

threading.Thread(target=_pt_refresh_loop, daemon=True).start()

# ── URL lookup helper ──────────────────────────────────────────────────────
def phishtank_lookup(url: str):
    url_lower = url.lower().strip()
    # Exact match
    for e in PHISHTANK_CACHE:
        db_url = e.get('url', '').lower().strip()
        if url_lower == db_url or url_lower in db_url or db_url in url_lower:
            return e
    # Hostname match
    try:
        from urllib.parse import urlparse
        host = urlparse(url_lower).hostname or ''
        for e in PHISHTANK_CACHE:
            db_host = urlparse(e.get('url','').lower()).hostname or ''
            if host and db_host and host == db_host:
                return e
    except Exception:
        pass
    return None

# ── Routes ─────────────────────────────────────────────────────────────────
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json(silent=True) or {}
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL required'}), 400

    result = analyze_url(url)

    # Enrich with PhishTank
    pt = phishtank_lookup(url)
    if pt:
        result['phishtank'] = {
            'found':        True,
            'phish_id':     pt.get('phish_id'),
            'verified':     pt.get('verified') == 'yes',
            'submitted_at': (pt.get('submission_time') or '')[:10],
            'target':       pt.get('target', 'Unknown')
        }
        result['score']       = min(100, result['score'] + 80)
        result['is_phishing'] = True
        result['findings'].insert(0,
            f"[CRITICAL] Verified PhishTank phishing site — Target: {pt.get('target','?')} — OWASP A08:Software & Data Integrity Failures"
        )
    return jsonify(result)

@app.route('/analyze/text', methods=['POST'])
def analyze_nlp():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '').strip()
    if not text:
        return jsonify({'error': 'text required'}), 400
    return jsonify(analyze_text(text))

@app.route('/phishtank/list', methods=['GET'])
def phishtank_list():
    return jsonify({
        'count':        len(PHISHTANK_CACHE),
        'last_updated': PHISHTANK_LAST_UPDATE,
        'urls':         list(PHISHTANK_URL_SET)
    })

@app.route('/phishtank/check', methods=['GET'])
def phishtank_check():
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({'error': 'url required'}), 400
    match = phishtank_lookup(url)
    if match:
        return jsonify({
            'in_database':  True,
            'valid':        match.get('verified') == 'yes',
            'phish_id':     match.get('phish_id'),
            'submitted_at': (match.get('submission_time') or '')[:10],
            'target':       match.get('target', 'Unknown')
        })
    return jsonify({'in_database': False})

@app.route('/phishtank/report', methods=['POST'])
def phishtank_report():
    data = request.get_json(silent=True) or {}
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'url required'}), 400
    with open('user_reported.txt', 'a') as f:
        f.write(f"{url}\n")
    return jsonify({'ok': True})

@app.route('/phishtank/reload', methods=['POST'])
def phishtank_reload():
    threading.Thread(target=load_phishtank, args=(True,), daemon=True).start()
    return jsonify({'ok': True, 'message': 'Reload started'})

@app.route('/phishtank/stats', methods=['GET'])
def phishtank_stats():
    elapsed  = time.time() - PHISHTANK_LAST_UPDATE
    next_upd = max(0, PHISHTANK_REFRESH_INTERVAL - elapsed)
    return jsonify({
        'total_entries':  len(PHISHTANK_CACHE),
        'last_updated':   PHISHTANK_LAST_UPDATE,
        'next_update_in': int(next_upd),
        'api_key_set':    bool(PHISHTANK_API_KEY),
        'status':         'ok' if PHISHTANK_CACHE else 'empty'
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status':            'ok',
        'version':           '3.0.0',
        'phishtank_entries': len(PHISHTANK_CACHE)
    })

if __name__ == '__main__':
    app.run(debug=False, port=5000)
