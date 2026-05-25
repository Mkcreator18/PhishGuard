// PhishGuard v3.0 — Popup
const ARC_LEN = 188;
const $ = id => document.getElementById(id);

// ── Theme ──────────────────────────────────────────────────────────────────
async function initTheme() {
  const { theme } = await chrome.storage.sync.get('theme');
  applyTheme(theme || 'dark');
}
function applyTheme(t) {
  document.body.classList.toggle('light', t === 'light');
  $('moonIcon').style.display = t === 'light' ? 'none' : '';
  $('sunIcon').style.display  = t === 'light' ? '' : 'none';
}
$('themeToggle').addEventListener('click', async () => {
  const { theme } = await chrome.storage.sync.get('theme');
  const next = (theme || 'dark') === 'dark' ? 'light' : 'dark';
  await chrome.storage.sync.set({ theme: next });
  applyTheme(next);
});

// ── Tabs ───────────────────────────────────────────────────────────────────
$('tabScan').addEventListener('click', () => switchTab('scan'));
$('tabGmail').addEventListener('click', () => switchTab('gmail'));
function switchTab(name) {
  $('paneScan').style.display  = name === 'scan'  ? '' : 'none';
  $('paneGmail').style.display = name === 'gmail' ? '' : 'none';
  $('tabScan').classList.toggle('active',  name === 'scan');
  $('tabGmail').classList.toggle('active', name === 'gmail');
}

// ── Navigation ─────────────────────────────────────────────────────────────
$('dashBtn').addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') }));
$('settingsBtn').addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('settings/settings.html') }));

// ── Meter ──────────────────────────────────────────────────────────────────
function renderMeter(score) {
  const filled = (score / 100) * ARC_LEN;
  const arc    = $('meterArc');
  arc.setAttribute('stroke-dasharray', `${filled} ${ARC_LEN - filled}`);
  arc.style.stroke = score >= 50 ? 'var(--danger)' : score >= 25 ? 'var(--warn)' : 'var(--safe)';
}

// ── Render scan state ──────────────────────────────────────────────────────
function renderState(state) {
  if (!state) {
    $('scoreVal').textContent = '0';
    $('statusBadge').textContent = 'No Data';
    $('statusBadge').className   = 'status-badge';
    renderMeter(0);
    $('findingsSection').style.display = 'none';
    $('reportBtn').style.display = 'none';
    return;
  }

  const { score = 0, findings = [], url = '' } = state;
  $('scoreVal').textContent = score;
  $('urlDisplay').textContent = url || '—';
  $('urlDisplay').title       = url;
  renderMeter(score);

  const badge = $('statusBadge');
  if (score >= 50)      { badge.textContent = '🚨 Threat Detected'; badge.className = 'status-badge danger'; }
  else if (score >= 25) { badge.textContent = '⚠️ Suspicious';      badge.className = 'status-badge warn';   }
  else                  { badge.textContent = '✅ Safe';             badge.className = 'status-badge safe';   }

  if (findings.length) {
    $('findingsSection').style.display = '';
    const list = $('findingsList');
    list.innerHTML = '';
    findings.forEach(f => {
      const li = document.createElement('li');
      li.textContent = f; // textContent — never innerHTML
      if (f.includes('[MEDIUM]'))                     li.className = 'warn-item';
      else if (f.includes('[LOW]')||f.includes('[INFO]')) li.className = 'low-item';
      list.appendChild(li);
    });
  } else {
    $('findingsSection').style.display = 'none';
  }

  $('reportBtn').style.display = score >= 25 ? '' : 'none';
}

// ── Load state ─────────────────────────────────────────────────────────────
async function load() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  $('urlDisplay').textContent = tab.url || '—';
  const res = await chrome.runtime.sendMessage({ type: 'GET_STATE', tabId: tab.id });
  renderState(res?.state);
  $('reportBtn').dataset.url   = tab.url;
  $('reportBtn').dataset.tabId = tab.id;
}

// ── Rescan ─────────────────────────────────────────────────────────────────
$('rescanBtn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;
  await chrome.storage.session.remove(`tab_${tab.id}`);
  chrome.tabs.reload(tab.id);
  window.close();
});

// ── Report phishing ────────────────────────────────────────────────────────
$('reportBtn').addEventListener('click', () => {
  $('dialogUrl').textContent = $('reportBtn').dataset.url;
  $('dialogOverlay').style.display = 'flex';
});
$('dialogCancel').addEventListener('click', () => { $('dialogOverlay').style.display = 'none'; });
$('dialogConfirm').addEventListener('click', async () => {
  const url = $('reportBtn').dataset.url;
  await chrome.runtime.sendMessage({ type: 'REPORT_PHISHING', url });
  $('dialogOverlay').style.display = 'none';
  $('statusBadge').textContent = '🚨 Reported & Blocked';
  $('statusBadge').className   = 'status-badge danger';
  $('reportBtn').style.display = 'none';
});

// ── Gmail sandbox (in popup tab) ───────────────────────────────────────────
$('gmailScanBtn').addEventListener('click', async () => {
  const text   = $('gmailInput').value.trim();
  const result = $('gmailResult');
  if (!text) return;

  const btn = $('gmailScanBtn');
  btn.disabled = true; btn.textContent = '🔍 Scanning…';

  // NLP scan using shared constants
  const matched = typeof URGENCY_PHRASES !== 'undefined'
    ? URGENCY_PHRASES.filter(p => text.toLowerCase().includes(p))
    : [];

  let score = 0;
  const findings = [];

  if (matched.length >= 3)      { score += 35; findings.push(`[CRITICAL] Multiple urgency phrases: "${matched[0]}", "${matched[1]}"`); }
  else if (matched.length >= 1) { score += 15; findings.push(`[MEDIUM] Urgency language: "${matched[0]}"`); }

  // Scan any URLs found in text
  const urls = text.match(/https?:\/\/[^\s<>"]+/gi) || [];
  for (const u of urls) {
    try {
      const h = new URL(u).hostname;
      const tld = '.' + h.split('.').pop();
      if (typeof HIGH_RISK_TLDS !== 'undefined' && HIGH_RISK_TLDS.has(tld)) {
        score += 25;
        findings.push(`[HIGH] Link to high-risk domain: ${h}`);
      } else {
        findings.push(`[INFO] Link found: ${h}`);
      }
    } catch {}
  }

  score = Math.min(score, 100);
  result.style.display = '';
  result.className = `gmail-result ${score >= 25 ? 'threat' : 'safe'}`;
  result.innerHTML = '';

  const header = document.createElement('div');
  header.style.fontWeight = '700';
  header.style.marginBottom = '4px';
  header.textContent = score >= 50 ? `🚨 ${score}% — High risk phishing email`
    : score >= 25 ? `⚠️ ${score}% — Suspicious content`
    : `✅ ${score}% — No threats found`;
  result.appendChild(header);

  if (findings.length) {
    const ul = document.createElement('ul');
    findings.forEach(f => {
      const li = document.createElement('li');
      li.textContent = f;
      ul.appendChild(li);
    });
    result.appendChild(ul);
  }

  btn.disabled = false; btn.textContent = '🔍 Scan Email';
});

// ── Init ───────────────────────────────────────────────────────────────────
initTheme();
load();
