// PhishGuard v3.0 — Blocked Page
const params     = new URLSearchParams(location.search);
const blockedUrl = decodeURIComponent(params.get('url') || '');
const score      = params.get('score') || '—';
const reason     = decodeURIComponent(params.get('reason') || 'Phishing indicators detected');

// Safe render using textContent only
document.getElementById('blockedUrl').textContent = blockedUrl || 'Unknown URL';
document.getElementById('riskScore').textContent  = score + '%';
document.getElementById('reasonText').textContent = reason;

// ── Theme ──────────────────────────────────────────────────────────────────
async function initTheme() {
  try {
    const { theme } = await chrome.storage.sync.get('theme');
    applyTheme(theme || 'dark');
  } catch { applyTheme('dark'); }
}
function applyTheme(t) {
  document.body.classList.toggle('light', t === 'light');
  document.getElementById('themeLink').textContent = t === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode';
}
document.getElementById('themeLink').addEventListener('click', async e => {
  e.preventDefault();
  const { theme } = await chrome.storage.sync.get('theme');
  const next = (theme || 'dark') === 'dark' ? 'light' : 'dark';
  await chrome.storage.sync.set({ theme: next });
  applyTheme(next);
});

// ── Go Back ────────────────────────────────────────────────────────────────
document.getElementById('goBackBtn').addEventListener('click', () => {
  if (history.length > 1) {
    history.back();
  } else {
    // No history — open new tab with safe page
    chrome.tabs.create({ url: 'https://www.google.com' });
  }
});

// ── Proceed Anyway ─────────────────────────────────────────────────────────
// This must store the bypass flag BEFORE navigating, then navigate directly
// without going through background.js navigation handler again
document.getElementById('proceedBtn').addEventListener('click', async () => {
  if (!blockedUrl) return;

  const btn = document.getElementById('proceedBtn');
  btn.disabled = true;
  btn.textContent = 'Opening…';

  try {
    // Get current tab id
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // Store bypass flag via background message — this sets bypassedTabs[tabId_url]
    await chrome.runtime.sendMessage({ type: 'BYPASS', tabId: tab.id, url: blockedUrl });
    // Background will immediately navigate to the URL after setting bypass
    // so no further action needed here
  } catch (e) {
    // Fallback if messaging fails — navigate directly
    location.href = blockedUrl;
  }
});

// ── Report Phishing ────────────────────────────────────────────────────────
document.getElementById('reportBtn').addEventListener('click', () => {
  document.getElementById('dialogOverlay').style.display = 'flex';
});

document.getElementById('dialogCancel').addEventListener('click', () => {
  document.getElementById('dialogOverlay').style.display = 'none';
});

document.getElementById('dialogConfirm').addEventListener('click', async () => {
  if (!blockedUrl) return;
  document.getElementById('dialogOverlay').style.display = 'none';
  try {
    await chrome.runtime.sendMessage({ type: 'REPORT_PHISHING', url: blockedUrl });
  } catch {}
  const btn = document.getElementById('reportBtn');
  btn.textContent = '✅ Reported & Blocked';
  btn.disabled    = true;
  btn.style.color = 'var(--safe)';
  btn.style.borderColor = 'var(--safe)';
});

// ── Dashboard link ─────────────────────────────────────────────────────────
document.getElementById('dashLink').addEventListener('click', e => {
  e.preventDefault();
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
});

initTheme();
