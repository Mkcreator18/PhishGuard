// PhishGuard v3.0 — Settings

const MODULES = [
  { key: 'mod_behavioral',   name: 'Behavioral DOM Analysis',       desc: 'Scans page structure, forms, and scripts for threats' },
  { key: 'mod_typosquat',    name: 'Typosquatting Detection',        desc: 'Flags domains mimicking trusted brands (Levenshtein)' },
  { key: 'mod_punycode',     name: 'Punycode / IDN Homograph',      desc: 'Detects fake unicode characters in domain names' },
  { key: 'mod_shortener',    name: 'URL Shortener Detection',        desc: 'Flags shortened URLs that hide real destinations' },
  { key: 'mod_openphish',    name: 'OpenPhish Database Lookup',      desc: 'Checks URLs against known phishing database' },
  { key: 'mod_redirect',     name: 'Redirect Chain Tracking',        desc: 'Warns when page is reached via multiple hops' },
  { key: 'mod_brand',        name: 'Brand Impersonation',            desc: 'Detects brand names embedded in unofficial domains' },
  { key: 'mod_scripts',      name: 'Malicious Script Detection',     desc: 'Flags external scripts from high-risk TLD domains' },
  { key: 'mod_entropy',      name: 'Shannon Entropy / DGA Analysis', desc: 'Mathematical randomness check — catches DGA domains' },
  { key: 'mod_gmail',        name: 'Gmail NLP Scanner',              desc: 'Scans email bodies for phishing language patterns' },
  { key: 'mod_ip',           name: 'IP Geolocation Intel',           desc: 'Checks server IP for proxy/datacenter abuse (ip-api.com)' },
];

async function load() {
  const stored = await chrome.storage.local.get(['sensitivity','whitelist','blacklist',...MODULES.map(m=>m.key)]);
  const { theme } = await chrome.storage.sync.get('theme');
  applyTheme(theme || 'dark');

  // Sensitivity
  const sens = stored.sensitivity || 'BALANCED';
  document.querySelector(`input[name="sensitivity"][value="${sens}"]`).checked = true;

  // Modules
  const container = document.getElementById('togglesContainer');
  container.innerHTML = MODULES.map(m => `
    <div class="toggle-row">
      <div class="toggle-info">
        <div class="toggle-name">${m.name}</div>
        <div class="toggle-desc">${m.desc}</div>
      </div>
      <label class="switch">
        <input type="checkbox" id="${m.key}" ${stored[m.key] !== false ? 'checked' : ''}>
        <span class="slider"></span>
      </label>
    </div>
  `).join('');

  // Whitelist & Blacklist
  renderList('whitelist', stored.whitelist || []);
  renderList('blacklist', stored.blacklist || []);
}

function applyTheme(t) {
  document.body.classList.toggle('light', t === 'light');
  document.getElementById('themeBtn').textContent = t === 'light' ? '🌙' : '☀️';
}

document.getElementById('themeBtn').addEventListener('click', async () => {
  const { theme } = await chrome.storage.sync.get('theme');
  const next = (theme || 'dark') === 'dark' ? 'light' : 'dark';
  await chrome.storage.sync.set({ theme: next });
  applyTheme(next);
});

function renderList(type, items) {
  const ul = document.getElementById(`${type}Items`);
  ul.innerHTML = items.map(d => `
    <li>
      <span>${d}</span>
      <button class="remove-btn" data-type="${type}" data-domain="${d}" title="Remove">×</button>
    </li>
  `).join('');
}

async function addDomain(type) {
  const input = document.getElementById(`${type}Input`);
  const domain = input.value.trim().replace(/^https?:\/\//,'').replace(/\/.*$/,'');
  if (!domain) return;
  const { [type]: list = [] } = await chrome.storage.local.get(type);
  if (!list.includes(domain)) {
    list.push(domain);
    await chrome.storage.local.set({ [type]: list });
    renderList(type, list);
  }
  input.value = '';
}

document.getElementById('addWhiteBtn').addEventListener('click', () => addDomain('whitelist'));
document.getElementById('addBlackBtn').addEventListener('click', () => addDomain('blacklist'));
document.getElementById('whitelistInput').addEventListener('keydown', e => e.key === 'Enter' && addDomain('whitelist'));
document.getElementById('blacklistInput').addEventListener('keydown', e => e.key === 'Enter' && addDomain('blacklist'));

document.addEventListener('click', async e => {
  if (!e.target.classList.contains('remove-btn')) return;
  const { type, domain } = e.target.dataset;
  const { [type]: list = [] } = await chrome.storage.local.get(type);
  const updated = list.filter(d => d !== domain);
  await chrome.storage.local.set({ [type]: updated });
  renderList(type, updated);
});

document.getElementById('saveBtn').addEventListener('click', async () => {
  const sens = document.querySelector('input[name="sensitivity"]:checked')?.value || 'BALANCED';
  const mods = Object.fromEntries(MODULES.map(m => [m.key, document.getElementById(m.key)?.checked ?? true]));
  await chrome.storage.local.set({ sensitivity: sens, ...mods });
  const status = document.getElementById('saveStatus');
  status.textContent = '✅ Saved!';
  setTimeout(() => status.textContent = '', 2000);
});

document.getElementById('clearLogsBtn').addEventListener('click', async () => {
  if (!confirm('Clear all threat logs?')) return;
  await chrome.storage.local.set({ threatLog: [], reportedSites: [] });
  alert('Logs cleared.');
});

document.getElementById('clearAllBtn').addEventListener('click', async () => {
  if (!confirm('Reset ALL PhishGuard data? This cannot be undone.')) return;
  await chrome.storage.local.clear();
  await chrome.storage.session.clear();
  alert('All data reset.');
  load();
});

load();
