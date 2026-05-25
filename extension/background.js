// PhishGuard v3.0 — Background Service Worker
importScripts('shared/constants.js');

let openPhishList  = new Set();
let phishTankList  = new Set(); // loaded from backend or local cache

// ── Startup ────────────────────────────────────────────────────────────────
async function loadOpenPhish() {
  try {
    const res  = await fetch(chrome.runtime.getURL('../openphish_database.txt'));
    const text = await res.text();
    openPhishList = new Set(text.split('\n').map(l => l.trim().toLowerCase()).filter(Boolean));
    console.log(`[PhishGuard] OpenPhish: ${openPhishList.size} entries`);
  } catch (e) { console.warn('[PhishGuard] OpenPhish load failed:', e); }
}

async function loadPhishTank() {
  try {
    // Try our Flask backend first (which caches PhishTank hourly)
    const res  = await fetch('http://localhost:5000/phishtank/list', { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      const data = await res.json();
      phishTankList = new Set((data.urls || []).map(u => u.toLowerCase()));
      console.log(`[PhishGuard] PhishTank: ${phishTankList.size} entries`);
    }
  } catch { console.warn('[PhishGuard] PhishTank backend unavailable — skipping'); }
}

// ── Math helpers ───────────────────────────────────────────────────────────
function shannonEntropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  const n = s.length;
  return -Object.values(freq).reduce((sum, f) => { const p = f/n; return sum + p * Math.log2(p); }, 0);
}

function consonantVowelRatio(s) {
  const v = (s.match(/[aeiou]/gi) || []).length;
  const c = (s.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
  return v === 0 ? c : c / v;
}

function numericRatio(s) {
  const digits = (s.match(/\d/g) || []).length;
  return s.length ? digits / s.length : 0;
}

// ── Domain helpers ─────────────────────────────────────────────────────────
function getBaseDomain(hostname) {
  const p = hostname.replace(/^www\./, '').split('.');
  return p.length > 2 ? p.slice(-2).join('.') : p.join('.');
}

function isTrusted(hostname) {
  const base = getBaseDomain(hostname);
  if (TRUSTED_DOMAINS.has(hostname) || TRUSTED_DOMAINS.has(base)) return true;
  if (COLLEGE_KEYWORDS.some(k => hostname.includes(k))) return true;
  if ([...TRUSTED_TLDS].some(t => hostname.endsWith(t))) return true;
  return false;
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0));
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[a.length][b.length];
}

// ── PhishTank live lookup ──────────────────────────────────────────────────
async function checkPhishTankLive(url) {
  try {
    const res = await fetch(`http://localhost:5000/phishtank/check?url=${encodeURIComponent(url)}`,
      { signal: AbortSignal.timeout(4000) });
    if (res.ok) return await res.json();
  } catch {}
  return null;
}

// ── IP Geolocation (async enrichment) ─────────────────────────────────────
async function checkIP(hostname) {
  try {
    const r = await fetch(
      `https://ip-api.com/json/${hostname}?fields=status,country,isp,proxy,hosting`,
      { signal: AbortSignal.timeout(5000) });
    return r.ok ? await r.json() : null;
  } catch { return null; }
}

async function enrichWithThreatIntel(tabId, url) {
  const { mod_ip = true } = await chrome.storage.local.get('mod_ip');
  if (!mod_ip) return;
  let parsed; try { parsed = new URL(url); } catch { return; }
  if (isTrusted(parsed.hostname)) return;

  const ipData = await checkIP(parsed.hostname);
  if (!ipData || ipData.status !== 'success') return;

  const extra = []; let pts = 0;
  if (ipData.proxy)   { pts += 25; extra.push(`[HIGH] Server uses proxy/VPN infrastructure — ${OWASP.ACCESS}`); }
  if (ipData.hosting) { pts += 10; extra.push(`[MEDIUM] Bulk datacenter hosting (${ipData.isp}) — ${OWASP.DESIGN}`); }

  if (extra.length) {
    const existing = await getState(tabId) || {};
    await setState(tabId, {
      ...existing,
      score: Math.min(100, (existing.score || 0) + pts),
      findings: [...(existing.findings || []), ...extra]
    });
    updateBadge(tabId, Math.min(100, (existing.score || 0) + pts));
  }
}

// ── Core URL Scanner ───────────────────────────────────────────────────────
function scanURL(url) {
  const findings = []; let score = 0;
  let parsed; try { parsed = new URL(url); } catch { return { score: 0, findings: [] }; }

  const { hostname, protocol, searchParams } = parsed;
  const base       = getBaseDomain(hostname);
  const domainPart = base.replace(/\.\w+$/, '');
  const fullURL    = url.toLowerCase();

  if (isTrusted(hostname)) return { score: 0, findings: [] };

  const add = (pts, msg) => { score += pts; findings.push(msg); };

  // ── OpenPhish blocklist ──────────────────────────────────────────────────
  if ([...openPhishList].some(e => fullURL.includes(e)))
    add(80, `[CRITICAL] Matches OpenPhish known phishing database — ${OWASP.INTEGRITY}`);

  // ── PhishTank local cache ────────────────────────────────────────────────
  if ([...phishTankList].some(e => fullURL.includes(e)))
    add(80, `[CRITICAL] Matches PhishTank verified phishing database — ${OWASP.INTEGRITY}`);

  // ── Protocol ─────────────────────────────────────────────────────────────
  if (protocol === 'http:')
    add(20, `[HIGH] No HTTPS — plaintext transmission — ${OWASP.CREDENTIAL}`);

  // ── TLD risk ─────────────────────────────────────────────────────────────
  const tld = '.' + hostname.split('.').pop();
  if (HIGH_RISK_TLDS.has(tld))        add(25, `[HIGH] High-risk TLD "${tld}" — heavily abused by phishers — ${OWASP.DESIGN}`);
  else if (MEDIUM_RISK_TLDS.has(tld)) add(10, `[MEDIUM] Uncommon TLD "${tld}" — ${OWASP.DESIGN}`);

  // ── Fake ccTLD embedded in domain (e.g. allegro.pl-evil.sbs) ─────────────
  if (FAKE_CCTLD_PATTERNS.some(p => hostname.includes(p)))
    add(40, `[CRITICAL] Fake country-code TLD embedded in domain (e.g. ".pl-", ".uk-") — domain spoofing — ${OWASP.DESIGN}`);

  // ── Free hosting ─────────────────────────────────────────────────────────
  if ([...FREE_HOSTING].some(h => hostname.endsWith(h)))
    add(15, `[MEDIUM] Free hosting platform — low barrier for attackers — ${OWASP.DESIGN}`);

  // ── URL shortener ─────────────────────────────────────────────────────────
  if (URL_SHORTENERS.has(base))
    add(20, `[HIGH] URL shortener conceals real destination — ${OWASP.INTEGRITY}`);

  // ── Punycode / IDN ────────────────────────────────────────────────────────
  if (hostname.includes('xn--') || /[^\x00-\x7F]/.test(hostname))
    add(35, `[CRITICAL] Punycode/IDN homograph attack — fake unicode characters — ${OWASP.DESIGN}`);

  // ── IP as hostname ────────────────────────────────────────────────────────
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname))
    add(30, `[HIGH] Raw IP address used as hostname — ${OWASP.ACCESS}`);

  // ── Typosquatting (Levenshtein) ───────────────────────────────────────────
  for (const brand of TOP_BRANDS) {
    if (domainPart !== brand && levenshtein(domainPart, brand) <= 2 && domainPart.length >= brand.length - 1) {
      add(40, `[CRITICAL] Typosquatting — "${hostname}" closely mimics "${brand}" — ${OWASP.DESIGN}`);
      break;
    }
  }

  // ── Brand name in non-official domain ─────────────────────────────────────
  for (const brand of TOP_BRANDS) {
    if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`)
      && !hostname.endsWith(`${brand}.pl`) && !hostname.endsWith(`${brand}.org`)
      && !hostname.endsWith(`${brand}.net`)) {
      add(30, `[HIGH] Brand "${brand}" embedded in non-official domain — impersonation — ${OWASP.DESIGN}`);
      break;
    }
  }

  // ── Shannon Entropy / DGA ─────────────────────────────────────────────────
  const entropy = shannonEntropy(domainPart);
  if (entropy > ENTROPY_HIGH)
    add(30, `[HIGH] Domain entropy ${entropy.toFixed(2)} — DGA-generated domain likely — ${OWASP.INTEGRITY}`);
  else if (entropy > ENTROPY_MED)
    add(15, `[MEDIUM] Elevated domain entropy ${entropy.toFixed(2)} — possibly randomized — ${OWASP.INTEGRITY}`);

  // ── Consonant-Vowel Ratio ─────────────────────────────────────────────────
  const cvr = consonantVowelRatio(domainPart);
  if (cvr > CVR_THRESHOLD)
    add(20, `[HIGH] Consonant/vowel ratio ${cvr.toFixed(1)} — human-unreadable domain (DGA) — ${OWASP.INTEGRITY}`);

  // ── Numeric ratio in subdomain/domain (e.g. 72634823g023) ────────────────
  const subdomains = hostname.split('.').slice(0, -2); // everything before base domain
  for (const sub of subdomains) {
    const nr = numericRatio(sub);
    if (nr > NUMERIC_RATIO_THRESHOLD) {
      add(25, `[HIGH] Subdomain "${sub}" is ${Math.round(nr*100)}% digits — randomized/DGA pattern — ${OWASP.INTEGRITY}`);
      break;
    }
  }
  // Also check domain part itself
  const domNr = numericRatio(domainPart);
  if (domNr > NUMERIC_RATIO_THRESHOLD)
    add(20, `[HIGH] Domain contains ${Math.round(domNr*100)}% digits — suspicious randomized pattern — ${OWASP.INTEGRITY}`);

  // ── Subdomain depth ────────────────────────────────────────────────────────
  const subCount = hostname.split('.').length - 2;
  if (subCount >= 3)
    add(15, `[MEDIUM] ${subCount} subdomain levels — obfuscation tactic — ${OWASP.ACCESS}`);

  // ── Random-looking subdomain (high entropy subdomain) ────────────────────
  for (const sub of subdomains) {
    if (sub.length >= 8 && shannonEntropy(sub) > 3.5) {
      add(20, `[HIGH] Random-looking subdomain "${sub}" — typical of DGA/phishing infra — ${OWASP.INTEGRITY}`);
      break;
    }
  }

  // ── Hyphens ───────────────────────────────────────────────────────────────
  const hyphens = (hostname.match(/-/g) || []).length;
  if (hyphens >= 3)
    add(15, `[MEDIUM] ${hyphens} hyphens in domain — obfuscation pattern`);

  // ── Sensitive keywords in domain ──────────────────────────────────────────
  const kwHits = ['secure','login','verify','update','banking','account',
    'confirm','suspended','unusual','signin','webscr','checkout','oferta','offer']
    .filter(k => base.includes(k));
  if (kwHits.length)
    add(kwHits.length * 12, `[HIGH] Sensitive keywords in domain: ${kwHits.join(', ')} — ${OWASP.DESIGN}`);

  // ── Redirect params ───────────────────────────────────────────────────────
  const redirHits = ['redirect','returnurl','next','callback','goto','target']
    .filter(p => searchParams.has(p));
  if (redirHits.length)
    add(15, `[MEDIUM] Redirect parameters: ${redirHits.join(', ')} — ${OWASP.SSRF}`);

  // ── Long URL ──────────────────────────────────────────────────────────────
  if (url.length > 200)
    add(10, `[LOW] URL length ${url.length} chars — possible obfuscation`);

  // ── Data URI ──────────────────────────────────────────────────────────────
  if (url.startsWith('data:'))
    add(40, `[CRITICAL] Data URI — hides content from scanners — ${OWASP.INTEGRITY}`);

  return { score: Math.min(score, 100), findings };
}

// ── State ──────────────────────────────────────────────────────────────────
async function getState(tabId) {
  const r = await chrome.storage.session.get(`tab_${tabId}`);
  return r[`tab_${tabId}`] || null;
}
async function setState(tabId, data) {
  await chrome.storage.session.set({ [`tab_${tabId}`]: { ...data, ts: Date.now() } });
}
async function clearState(tabId) {
  await chrome.storage.session.remove(`tab_${tabId}`);
}

// ── Badge ──────────────────────────────────────────────────────────────────
function updateBadge(tabId, score) {
  if (score >= 50) {
    chrome.action.setBadgeText({ tabId, text: '!' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#ef4444' });
  } else if (score >= 25) {
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#f59e0b' });
  } else {
    chrome.action.setBadgeText({ tabId, text: '' });
  }
}

// ── Log ────────────────────────────────────────────────────────────────────
async function logThreat(url, score, findings) {
  const { threatLog = [] } = await chrome.storage.local.get('threatLog');
  const now = Date.now();
  // Deduplicate: skip if same URL was logged within the last 60 seconds
  const recentDupe = threatLog.find(e => e.url === url && (now - e.ts) < 60000);
  if (recentDupe) return;
  threatLog.unshift({ url, score, findings, ts: now });
  if (threatLog.length > 500) threatLog.length = 500;
  await chrome.storage.local.set({ threatLog });
}

// ── Navigation ─────────────────────────────────────────────────────────────
async function handleNavigation(tabId, url) {
  if (!url || /^(chrome|about|chrome-extension|moz-extension):/.test(url)) return;
  // Never scan the blocked page itself
  if (url.includes('blocked/blocked.html')) return;

  const { whitelist = [], blacklist = [], sensitivity = 'BALANCED', bypassedTabs = {} } =
    await chrome.storage.local.get(['whitelist','blacklist','sensitivity','bypassedTabs']);

  // Skip if this exact URL was already scanned for this tab (prevents duplicate from onCommitted + onHistoryState both firing)
  const existing = await getState(tabId);
  if (existing?.url === url && existing?.status !== undefined && (Date.now() - (existing.ts || 0)) < 5000) return;

  let parsed; try { parsed = new URL(url); } catch { return; }
  const base = getBaseDomain(parsed.hostname);

  // Whitelist
  if (whitelist.includes(base) || whitelist.includes(parsed.hostname)) {
    await setState(tabId, { score: 0, findings: [], url, status: 'safe' });
    updateBadge(tabId, 0); return;
  }

  // Blacklist
  if (blacklist.includes(base) || blacklist.includes(parsed.hostname)) {
    // Only redirect + log if not already on blocked page for this URL
    if (existing?.status === 'blocked' && existing?.url === url) return;
    const findings = [`[CRITICAL] Manually blacklisted by user — ${OWASP.ACCESS}`];
    await setState(tabId, { score: 100, findings, url, status: 'blocked' });
    updateBadge(tabId, 100);
    await logThreat(url, 100, findings);
    chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`blocked/blocked.html?url=${encodeURIComponent(url)}&score=100&reason=${encodeURIComponent('Manually blacklisted')}`) });
    return;
  }

  const threshold = SENSITIVITY_THRESHOLDS[sensitivity] ?? 50;
  let { score, findings } = scanURL(url);

  // PhishTank live check (async — adds to score if found)
  const ptResult = await checkPhishTankLive(url);
  if (ptResult?.in_database && ptResult?.valid) {
    score = Math.min(100, score + 80);
    findings.unshift(`[CRITICAL] Verified in PhishTank database (ID: ${ptResult.phish_id}) — submitted ${ptResult.submitted_at?.slice(0,10)} — ${OWASP.INTEGRITY}`);
  }

  await setState(tabId, { score, findings, url, status: score >= threshold ? 'threat' : 'safe' });
  updateBadge(tabId, score);

  if (score >= threshold && !bypassedTabs[`${tabId}_${url}`]) {
    await logThreat(url, score, findings);
    chrome.tabs.update(tabId, {
      url: chrome.runtime.getURL(`blocked/blocked.html?url=${encodeURIComponent(url)}&score=${score}&reason=${encodeURIComponent(findings[0] || 'Phishing indicators detected')}`)
    });
  } else {
    enrichWithThreatIntel(tabId, url);
  }
}

// ── Report phishing ────────────────────────────────────────────────────────
async function reportPhishing(url) {
  let parsed; try { parsed = new URL(url); } catch { return; }
  const base = getBaseDomain(parsed.hostname);
  const { reportedSites = [], blacklist = [] } = await chrome.storage.local.get(['reportedSites','blacklist']);
  if (!reportedSites.find(r => r.url === url)) reportedSites.unshift({ url, ts: Date.now() });
  if (reportedSites.length > 200) reportedSites.length = 200;
  if (!blacklist.includes(base)) blacklist.push(base);
  await chrome.storage.local.set({ reportedSites, blacklist });
  await logThreat(url, 100, ['[CRITICAL] Reported as phishing by user']);
  // Also submit to our backend for PhishTank submission
  try {
    fetch('http://localhost:5000/phishtank/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
  } catch {}
}

// ── Events ─────────────────────────────────────────────────────────────────
chrome.webNavigation.onCommitted.addListener(({ tabId, url, frameId, transitionType }) => {
  // Only main frame, skip reloads of same page via back/forward cache
  if (frameId !== 0) return;
  // Skip chrome-internal navigations
  if (/^(chrome|about|chrome-extension|data):/.test(url)) return;
  handleNavigation(tabId, url);
});

// onHistoryStateUpdated fires for SPA navigation (React/Vue route changes)
// We only process it if the URL actually changed from what we have in state
chrome.webNavigation.onHistoryStateUpdated.addListener(async ({ tabId, url }) => {
  if (/^(chrome|about|chrome-extension|data):/.test(url)) return;
  const existing = await getState(tabId);
  // Only process if URL changed (prevents double-fire with onCommitted)
  if (existing?.url === url) return;
  handleNavigation(tabId, url);
});
chrome.tabs.onRemoved.addListener(tabId => clearState(tabId));

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    switch (msg.type) {
      case 'GET_STATE':
        reply({ state: await getState(msg.tabId) }); break;
      case 'CONTENT_FINDINGS': {
        const tabId = sender.tab?.id || msg.tabId;
        const existing = await getState(tabId) || {};
        const merged = {
          ...existing,
          score: Math.min(100, (existing.score || 0) + msg.extraScore),
          findings: [...(existing.findings || []), ...msg.findings],
          url: msg.url
        };
        await setState(tabId, merged);
        updateBadge(tabId, merged.score);
        const { sensitivity = 'BALANCED' } = await chrome.storage.local.get('sensitivity');
        if (merged.score >= (SENSITIVITY_THRESHOLDS[sensitivity] ?? 50) && existing.status !== 'blocked') {
          await logThreat(msg.url, merged.score, merged.findings);
          await setState(tabId, { ...merged, status: 'blocked' });
          chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL(`blocked/blocked.html?url=${encodeURIComponent(msg.url)}&score=${merged.score}&reason=${encodeURIComponent(merged.findings[0] || 'Behavioral threat')}`)
          });
        }
        break;
      }
      case 'BYPASS': {
        // Store bypass BEFORE navigating so handleNavigation skips blocking
        const { bypassedTabs = {} } = await chrome.storage.local.get('bypassedTabs');
        bypassedTabs[`${msg.tabId}_${msg.url}`] = true;
        await chrome.storage.local.set({ bypassedTabs });
        // Clear existing state so popup shows fresh safe state
        await clearState(msg.tabId);
        // Small delay ensures storage write completes before navigation fires
        setTimeout(() => chrome.tabs.update(msg.tabId, { url: msg.url }), 100);
        reply({ ok: true });
        break;
      }
      case 'REPORT_PHISHING':
        await reportPhishing(msg.url); reply({ ok: true }); break;
      case 'GET_TAB_URL':
        reply({ url: (await chrome.tabs.get(msg.tabId)).url }); break;
      case 'RELOAD_PHISHTANK':
        await loadPhishTank(); reply({ ok: true, count: phishTankList.size }); break;
    }
  })();
  return true;
});

// ── Init ───────────────────────────────────────────────────────────────────
loadOpenPhish();
loadPhishTank();
