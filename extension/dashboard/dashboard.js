// PhishGuard v3.0 — Dashboard

async function loadData() {
  const { threatLog = [], reportedSites = [] } = await chrome.storage.local.get(['threatLog','reportedSites']);
  const { theme } = await chrome.storage.sync.get('theme');
  applyTheme(theme || 'dark');
  // Always work with deduplicated log for display
  const dedupedLog = deduplicateLog(threatLog);
  renderStats(dedupedLog, reportedSites);
  renderPie(dedupedLog);
  renderLine(dedupedLog);
  renderLogTable(threatLog); // passes raw — dedup happens inside
  renderReportedTable(reportedSites);
  loadPhishTankStatus();
}

// ── Clean Duplicates ────────────────────────────────────────────────────────
document.getElementById('cleanDupesBtn').addEventListener('click', async () => {
  const { threatLog = [] } = await chrome.storage.local.get('threatLog');
  const cleaned = deduplicateLog(threatLog);
  await chrome.storage.local.set({ threatLog: cleaned });
  const btn = document.getElementById('cleanDupesBtn');
  btn.textContent = `✅ Removed ${threatLog.length - cleaned.length} dupes`;
  setTimeout(() => { btn.textContent = '🧹 Clean Log'; }, 2500);
  loadData();
});

// ── Theme ──────────────────────────────────────────────────────────────────
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

// ── PhishTank Status ───────────────────────────────────────────────────────
async function loadPhishTankStatus() {
  const els = {
    status:  document.getElementById('ptStatusVal'),
    entries: document.getElementById('ptEntries'),
    updated: document.getElementById('ptUpdated'),
    apikey:  document.getElementById('ptApiKey'),
  };
  try {
    const res = await fetch('http://localhost:5000/phishtank/stats', { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      const d = await res.json();
      els.status.textContent  = '🟢 Online';
      els.status.className    = 'pt-val online';
      els.entries.textContent = d.total_entries ? d.total_entries.toLocaleString() : '⚠️ 0 (loading…)';
      els.updated.textContent = d.last_updated ? new Date(d.last_updated * 1000).toLocaleTimeString() : 'Not yet';
      els.apikey.textContent  = d.api_key_set ? '✅ Key configured' : '⚠️ No key — rate limited';
      els.apikey.style.color  = d.api_key_set ? 'var(--safe)' : 'var(--warn)';
      return;
    }
  } catch {}
  els.status.textContent = '🔴 Backend offline';
  els.status.className   = 'pt-val offline';
  els.entries.textContent = 'N/A — start backend';
  els.updated.textContent = '—';
  els.apikey.textContent  = '—';
}

document.getElementById('reloadPTBtn').addEventListener('click', async () => {
  const btn = document.getElementById('reloadPTBtn');
  btn.disabled = true; btn.textContent = '⟳ Loading…';
  try {
    await fetch('http://localhost:5000/phishtank/reload', { method: 'POST', signal: AbortSignal.timeout(5000) });
    setTimeout(loadPhishTankStatus, 3000);
  } catch {}
  setTimeout(() => { btn.disabled = false; btn.textContent = '⟳ PhishTank'; }, 3000);
});

// ── Client-side JS heuristic scanner (mirrors background.js) ──────────────
function shannonEntropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  const n = s.length;
  return -Object.values(freq).reduce((sum, f) => { const p=f/n; return sum+p*Math.log2(p); }, 0);
}
function cvRatio(s) {
  const v = (s.match(/[aeiou]/gi)||[]).length;
  const c = (s.match(/[bcdfghjklmnpqrstvwxyz]/gi)||[]).length;
  return v===0 ? c : c/v;
}
function numRatio(s) { return s.length ? (s.match(/\d/g)||[]).length/s.length : 0; }
function lev(a,b) {
  const dp = Array.from({length:a.length+1},(_,i)=>Array.from({length:b.length+1},(_,j)=>i===0?j:j===0?i:0));
  for(let i=1;i<=a.length;i++) for(let j=1;j<=b.length;j++)
    dp[i][j]=a[i-1]===b[j-1]?dp[i-1][j-1]:1+Math.min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1]);
  return dp[a.length][b.length];
}
function getBase(h) { const p=h.replace(/^www\./,'').split('.'); return p.length>2?p.slice(-2).join('.'):p.join('.'); }
function isTrustedDomain(hostname) {
  const base = getBase(hostname);
  if (TRUSTED_DOMAINS.has(hostname)||TRUSTED_DOMAINS.has(base)) return true;
  if (COLLEGE_KEYWORDS.some(k=>hostname.includes(k))) return true;
  if ([...TRUSTED_TLDS].some(t=>hostname.endsWith(t))) return true;
  return false;
}

function clientSideScan(url) {
  const findings = []; let score = 0;
  let parsed; try { parsed = new URL(url); } catch { return {score:0,findings:['Invalid URL'],risk_level:'Unknown',is_phishing:false,entropy:0,cvr:0}; }
  const {hostname, protocol, searchParams} = parsed;
  const base       = getBase(hostname);
  const domainPart = base.replace(/\.\w+$/,'');
  const subdomains = hostname.replace(/^www\./,'').split('.').slice(0,-2);
  const fullURL    = url.toLowerCase();
  const add        = (pts,msg) => { score+=pts; findings.push(msg); };

  if (isTrustedDomain(hostname)) return {score:0,findings:['✅ Trusted domain — no threats detected'],risk_level:'Safe',is_phishing:false,entropy:shannonEntropy(domainPart).toFixed(2),cvr:cvRatio(domainPart).toFixed(2)};

  if (protocol==='http:')           add(20,`[HIGH] No HTTPS — ${OWASP.CREDENTIAL}`);

  const tld = '.'+hostname.split('.').pop();
  if (HIGH_RISK_TLDS.has(tld))       add(25,`[HIGH] High-risk TLD "${tld}" — ${OWASP.DESIGN}`);
  else if (MEDIUM_RISK_TLDS.has(tld))add(10,`[MEDIUM] Uncommon TLD "${tld}" — ${OWASP.DESIGN}`);

  if (FAKE_CCTLD_PATTERNS.some(p=>hostname.includes(p)))
    add(40,`[CRITICAL] Fake ccTLD embedded in domain (e.g. ".pl-", ".uk-") — ${OWASP.DESIGN}`);

  if ([...FREE_HOSTING].some(h=>hostname.endsWith(h)))
    add(15,`[MEDIUM] Free/shared hosting platform — ${OWASP.DESIGN}`);

  if (URL_SHORTENERS.has(base))
    add(20,`[HIGH] URL shortener conceals real destination — ${OWASP.INTEGRITY}`);

  if (hostname.includes('xn--')||/[^\x00-\x7F]/.test(hostname))
    add(35,`[CRITICAL] Punycode/IDN homograph attack — ${OWASP.DESIGN}`);

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname))
    add(30,`[HIGH] Raw IP address as hostname — ${OWASP.ACCESS}`);

  for (const brand of TOP_BRANDS) {
    if (domainPart!==brand && lev(domainPart,brand)<=2 && domainPart.length>=brand.length-1) {
      add(40,`[CRITICAL] Typosquatting — "${hostname}" mimics "${brand}" — ${OWASP.DESIGN}`); break;
    }
  }
  for (const brand of TOP_BRANDS) {
    if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`)
      && !hostname.endsWith(`${brand}.pl`) && !hostname.endsWith(`${brand}.org`)
      && !hostname.endsWith(`${brand}.net`)) {
      add(30,`[HIGH] Brand "${brand}" in non-official domain — ${OWASP.DESIGN}`); break;
    }
  }

  const entropy = shannonEntropy(domainPart);
  if (entropy>3.8)       add(30,`[HIGH] Domain entropy ${entropy.toFixed(2)} — DGA domain — ${OWASP.INTEGRITY}`);
  else if (entropy>3.2)  add(15,`[MEDIUM] Elevated entropy ${entropy.toFixed(2)} — ${OWASP.INTEGRITY}`);

  const cvr = cvRatio(domainPart);
  if (cvr>3.5) add(20,`[HIGH] Consonant/vowel ratio ${cvr.toFixed(1)} — unreadable domain — ${OWASP.INTEGRITY}`);

  if (numRatio(domainPart)>0.35)
    add(20,`[HIGH] Domain is ${Math.round(numRatio(domainPart)*100)}% digits — randomized pattern — ${OWASP.INTEGRITY}`);

  for (const sub of subdomains) {
    if (numRatio(sub)>0.35) {
      add(25,`[HIGH] Subdomain "${sub}" is ${Math.round(numRatio(sub)*100)}% digits — DGA pattern — ${OWASP.INTEGRITY}`); break;
    }
  }
  for (const sub of subdomains) {
    if (sub.length>=8 && shannonEntropy(sub)>3.5) {
      add(20,`[HIGH] Random-looking subdomain "${sub}" — phishing infra — ${OWASP.INTEGRITY}`); break;
    }
  }

  const subCount = hostname.split('.').length-2;
  if (subCount>=3) add(15,`[MEDIUM] ${subCount} subdomain levels — ${OWASP.ACCESS}`);

  const kwHits = ['secure','login','verify','update','banking','account','confirm',
    'suspended','unusual','signin','webscr','checkout','oferta','offer','payment',
    'invoice','reward','prize','winner','bonus'].filter(k=>base.includes(k));
  if (kwHits.length) add(kwHits.length*12,`[HIGH] Sensitive keywords in domain: ${kwHits.join(', ')} — ${OWASP.DESIGN}`);

  const redirHits = ['redirect','returnurl','next','callback','goto','target'].filter(p=>searchParams.has(p));
  if (redirHits.length) add(15,`[MEDIUM] Redirect parameters: ${redirHits.join(', ')} — ${OWASP.SSRF}`);
  if (url.length>200) add(10,`[LOW] URL length ${url.length} chars`);
  if (url.startsWith('data:')) add(40,`[CRITICAL] Data URI — ${OWASP.INTEGRITY}`);

  score = Math.min(score,100);
  const risk_level = score>=75?'Critical':score>=50?'High':score>=25?'Medium':'Safe';
  return { score, findings, risk_level, is_phishing: score>=50,
           entropy: entropy.toFixed(2), cvr: cvr.toFixed(2) };
}

// ── URL Scanner ─────────────────────────────────────────────────────────────
document.getElementById('urlScanBtn').addEventListener('click', async () => {
  const url = document.getElementById('urlSandboxInput').value.trim();
  if (!url) return;
  const btn = document.getElementById('urlScanBtn');
  const resultEl = document.getElementById('urlResult');
  btn.disabled = true; btn.textContent = 'Scanning…';
  resultEl.style.display = 'none';

  let data = null; let source = 'Client-side';
  try {
    const res = await fetch('http://localhost:5000/analyze', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({url}), signal: AbortSignal.timeout(6000)
    });
    if (res.ok) { data = await res.json(); source = 'Backend + PhishTank'; }
  } catch {}

  if (!data) { data = clientSideScan(url); source = 'Client-side (backend offline)'; }

  resultEl.style.display = '';
  resultEl.className = `url-result ${data.is_phishing ? 'threat' : 'safe'}`;
  resultEl.innerHTML = '';

  const scoreColor = data.score>=75?'var(--danger)':data.score>=50?'var(--danger)':data.score>=25?'var(--warn)':'var(--safe)';

  const header = document.createElement('div');
  header.className = 'url-result-header';
  header.innerHTML = `
    <span class="url-score-chip" style="background:${scoreColor}22;color:${scoreColor}">${data.score}%</span>
    <span style="font-weight:700">${data.risk_level} Risk</span>
    <span style="font-size:11px;color:var(--text-muted)">Entropy:${data.entropy} · CVR:${data.cvr} · ${source}</span>
  `;
  resultEl.appendChild(header);

  if (data.phishtank?.found) {
    const pt = document.createElement('div');
    pt.style.cssText = 'font-size:11px;padding:6px 10px;background:rgba(239,68,68,.1);border-radius:6px;margin:8px 0;color:var(--danger);font-weight:600';
    pt.textContent = `🚨 PhishTank Match — Target: ${data.phishtank.target} · Submitted: ${data.phishtank.submitted_at} · Verified: ${data.phishtank.verified?'Yes':'No'}`;
    resultEl.appendChild(pt);
  }

  if (data.findings?.length) {
    const ul = document.createElement('ul');
    ul.className = 'url-findings';
    data.findings.forEach(f => {
      const li = document.createElement('li');
      li.textContent = f;
      if (f.includes('[MEDIUM]')) li.className = 'warn-item';
      else if (f.includes('[LOW]')||f.includes('[INFO]')) li.className = 'low-item';
      ul.appendChild(li);
    });
    resultEl.appendChild(ul);
  }

  btn.disabled = false; btn.textContent = 'Scan';
});

// ── Gmail Sandbox ──────────────────────────────────────────────────────────
document.getElementById('sandboxScanBtn').addEventListener('click', async () => {
  const text = document.getElementById('gmailSandbox').value.trim();
  const result = document.getElementById('sandboxResult');
  if (!text) return;
  const btn = document.getElementById('sandboxScanBtn');
  btn.disabled = true; btn.textContent = '🔍 Scanning…';

  const matched = URGENCY_PHRASES.filter(p => text.toLowerCase().includes(p));
  let score = 0, findings = [];

  if (matched.length >= 3)      { score += 35; findings.push(`[CRITICAL] Multiple urgency phrases: "${matched[0]}", "${matched[1]}" — social engineering — ${OWASP.DESIGN}`); }
  else if (matched.length >= 1) { score += 15; findings.push(`[MEDIUM] Urgency language: "${matched[0]}" — ${OWASP.DESIGN}`); }

  const urlMatches = text.match(/https?:\/\/[^\s<>"]+/gi) || [];
  for (const u of urlMatches) {
    try {
      const scan = clientSideScan(u);
      if (scan.score > 0) {
        score += Math.min(scan.score, 40);
        findings.push(`[HIGH] Suspicious link in email: ${new URL(u).hostname} (score:${scan.score}%)`);
        findings.push(...scan.findings.slice(0,2));
      } else {
        findings.push(`[INFO] Link found: ${new URL(u).hostname} — appears safe`);
      }
    } catch {}
  }

  try {
    const res = await fetch('http://localhost:5000/analyze/text', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({text}), signal:AbortSignal.timeout(4000)
    });
    if (res.ok) {
      const d = await res.json();
      score = Math.max(score, d.score);
      d.findings?.forEach(f => { if (!findings.includes(f)) findings.push(f); });
    }
  } catch {}

  score = Math.min(score, 100);
  result.style.display = '';
  result.className = `sandbox-result ${score >= 25 ? 'threat' : 'safe'}`;
  result.innerHTML = '';

  const header = document.createElement('div');
  header.style.cssText = 'font-weight:700;margin-bottom:8px;font-size:13px';
  header.textContent = score >= 50
    ? `🚨 Threat Score: ${score}% — HIGH RISK phishing email`
    : score >= 25
    ? `⚠️ Score: ${score}% — Suspicious content`
    : `✅ Score: ${score}% — No phishing indicators found`;
  result.appendChild(header);

  if (findings.length) {
    const ul = document.createElement('ul');
    ul.style.cssText = 'list-style:none;display:flex;flex-direction:column;gap:4px;margin-top:4px';
    findings.forEach(f => {
      const li = document.createElement('li');
      li.textContent = f;
      li.style.cssText = 'font-size:11px;padding:5px 8px;background:rgba(0,0,0,.15);border-radius:6px;line-height:1.45';
      ul.appendChild(li);
    });
    result.appendChild(ul);
  }
  btn.disabled = false; btn.textContent = '🔍 Scan Email Text';
});

// ── Stats ──────────────────────────────────────────────────────────────────
function renderStats(log, reported) {
  const stats = [
    { label:'Total Threats',  val:log.length,                                            cls:'danger' },
    { label:'Critical (≥75)', val:log.filter(l=>l.score>=75).length,                    cls:'danger' },
    { label:'High (50–74)',   val:log.filter(l=>l.score>=50&&l.score<75).length,         cls:'warn'   },
    { label:'User Reported',  val:reported.length,                                       cls:'accent' }
  ];
  document.getElementById('statsGrid').innerHTML = stats.map(s =>
    `<div class="stat-card"><div class="stat-label">${s.label}</div><div class="stat-val ${s.cls}">${s.val}</div></div>`
  ).join('');
}

// ── Pie Chart ──────────────────────────────────────────────────────────────
function renderPie(log) {
  const canvas = document.getElementById('pieChart');
  const ctx = canvas.getContext('2d');
  const total = log.length || 1;
  const segs = [
    { label:'Critical ≥75', val:log.filter(l=>l.score>=75).length,                 color:'#ef4444' },
    { label:'High 50–74',   val:log.filter(l=>l.score>=50&&l.score<75).length,     color:'#f59e0b' },
    { label:'Medium 25–49', val:log.filter(l=>l.score>=25&&l.score<50).length,     color:'#6366f1' },
    { label:'Low <25',      val:log.filter(l=>l.score<25).length,                   color:'#22c55e' }
  ];
  const cx=100,cy=100,r=80; let angle=-Math.PI/2;
  ctx.clearRect(0,0,200,200);
  segs.forEach(s => {
    const sweep=(s.val/total)*2*Math.PI;
    ctx.beginPath(); ctx.moveTo(cx,cy); ctx.arc(cx,cy,r,angle,angle+sweep);
    ctx.closePath(); ctx.fillStyle=s.color; ctx.fill(); angle+=sweep;
  });
  ctx.beginPath(); ctx.arc(cx,cy,45,0,2*Math.PI);
  ctx.fillStyle=getComputedStyle(document.body).getPropertyValue('--surface').trim()||'#1a1d27'; ctx.fill();
  ctx.fillStyle=getComputedStyle(document.body).getPropertyValue('--text').trim()||'#e8eaf0';
  ctx.font='bold 22px Inter'; ctx.textAlign='center'; ctx.textBaseline='middle';
  ctx.fillText(log.length,cx,cy);
  document.getElementById('pieLegend').innerHTML = segs.map(s=>
    `<div class="legend-item"><div class="legend-dot" style="background:${s.color}"></div><span>${s.label}: ${s.val}</span></div>`
  ).join('');
}

// ── Line Chart ─────────────────────────────────────────────────────────────
function renderLine(log) {
  const canvas=document.getElementById('lineChart');
  const ctx=canvas.getContext('2d');
  const recent=[...log].reverse().slice(-20);
  if (!recent.length) return;
  const w=canvas.offsetWidth||640,h=200;
  canvas.width=w; canvas.height=h;
  const pad={t:16,r:16,b:32,l:40};
  const iw=w-pad.l-pad.r,ih=h-pad.t-pad.b;
  ctx.clearRect(0,0,w,h);
  ctx.strokeStyle='#2e3248'; ctx.lineWidth=1;
  [0,25,50,75,100].forEach(v=>{
    const y=pad.t+ih-(v/100)*ih;
    ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(pad.l+iw,y); ctx.stroke();
    ctx.fillStyle='#7b82a0'; ctx.font='10px Inter'; ctx.textAlign='right';
    ctx.fillText(v,pad.l-6,y+3);
  });
  const pts=recent.map((d,i)=>({x:pad.l+(i/Math.max(1,recent.length-1))*iw,y:pad.t+ih-(d.score/100)*ih}));
  ctx.beginPath(); pts.forEach((p,i)=>i===0?ctx.moveTo(p.x,p.y):ctx.lineTo(p.x,p.y));
  ctx.strokeStyle='#6366f1'; ctx.lineWidth=2; ctx.stroke();
  ctx.beginPath(); pts.forEach((p,i)=>i===0?ctx.moveTo(p.x,p.y):ctx.lineTo(p.x,p.y));
  ctx.lineTo(pts[pts.length-1].x,pad.t+ih); ctx.lineTo(pts[0].x,pad.t+ih); ctx.closePath();
  const grad=ctx.createLinearGradient(0,pad.t,0,pad.t+ih);
  grad.addColorStop(0,'rgba(99,102,241,.3)'); grad.addColorStop(1,'rgba(99,102,241,0)');
  ctx.fillStyle=grad; ctx.fill();
  pts.forEach(p=>{ctx.beginPath();ctx.arc(p.x,p.y,3,0,2*Math.PI);ctx.fillStyle='#6366f1';ctx.fill();});
}

// ── Tables ──────────────────────────────────────────────────────────────────
function deduplicateLog(log) {
  // Keep only the most recent entry per unique URL (deduplicate display)
  const seen = new Map();
  for (const e of log) {
    const key = e.url;
    if (!seen.has(key) || e.ts > seen.get(key).ts) seen.set(key, e);
  }
  return [...seen.values()].sort((a, b) => b.ts - a.ts);
}

function renderLogTable(log) {
  const tbody = document.getElementById('logBody');
  const empty = document.getElementById('emptyState');
  const deduped = deduplicateLog(log);
  if (!deduped.length) { tbody.innerHTML = ''; empty.style.display = ''; return; }
  empty.style.display = 'none';
  tbody.innerHTML = deduped.slice(0, 100).map(e => {
    const cls     = e.score >= 75 ? 'danger' : e.score >= 50 ? 'warn' : 'safe';
    const primary = (e.findings?.[0] || '').replace(/\[.*?\]\s?/, '').slice(0, 80);
    const isPT    = (e.findings?.[0] || '').includes('PhishTank');
    const src     = isPT
      ? '<span class="source-chip phishtank">PhishTank</span>'
      : '<span class="source-chip">Heuristic</span>';
    return `<tr>
      <td class="td-url">${escTxt(e.url)}</td>
      <td><span class="score-chip ${cls}">${e.score}%</span></td>
      <td style="font-size:11px;max-width:220px">${escTxt(primary)}</td>
      <td>${src}</td>
      <td style="white-space:nowrap;font-size:11px">${formatTime(e.ts)}</td>
    </tr>`;
  }).join('');
}

function renderReportedTable(reported) {
  const tbody=document.getElementById('reportedBody'),empty=document.getElementById('reportedEmpty');
  if (!reported.length){tbody.innerHTML='';empty.style.display='';return;}
  empty.style.display='none';
  tbody.innerHTML=reported.map(r=>
    `<tr><td class="td-url">${escTxt(r.url)}</td><td style="white-space:nowrap;font-size:11px">${formatTime(r.ts)}</td></tr>`
  ).join('');
}

// ── Download Report ─────────────────────────────────────────────────────────
document.getElementById('downloadBtn').addEventListener('click', async () => {
  const {threatLog=[],reportedSites=[]}=await chrome.storage.local.get(['threatLog','reportedSites']);
  const html=generateReport(threatLog,reportedSites);
  Object.assign(document.createElement('a'),{
    href:URL.createObjectURL(new Blob([html],{type:'text/html'})),
    download:`PhishGuard_Report_${new Date().toISOString().slice(0,10)}.html`
  }).click();
});

function generateReport(log,reported) {
  const now=new Date().toLocaleString();
  const critical=log.filter(l=>l.score>=75).length;
  const high=log.filter(l=>l.score>=50&&l.score<75).length;
  const owaspCount={};
  log.forEach(e=>(e.findings||[]).forEach(f=>{
    const m=f.match(/OWASP (A\d+:[^—\]]+)/);
    if(m) owaspCount[m[1].trim()]=(owaspCount[m[1].trim()]||0)+1;
  }));
  const owaspRows=Object.entries(owaspCount).sort((a,b)=>b[1]-a[1]).map(([k,v])=>
    `<tr><td>${escTxt(k)}</td><td style="font-weight:700;color:#ef4444">${v}</td></tr>`
  ).join('')||'<tr><td colspan="2" style="color:#888;text-align:center">No data</td></tr>';
  const rows=log.slice(0,200).map(e=>{
    const c=e.score>=75?'#ef4444':e.score>=50?'#f59e0b':'#22c55e';
    const p=(e.findings?.[0]||'—').replace(/\[.*?\]\s?/,'').slice(0,100);
    const isPT=(e.findings?.[0]||'').includes('PhishTank');
    return `<tr>
      <td style="font-family:monospace;font-size:10px;word-break:break-all;max-width:260px">${escTxt(e.url)}</td>
      <td><span style="background:${c}22;color:${c};padding:2px 10px;border-radius:99px;font-weight:700">${e.score}%</span></td>
      <td style="font-size:11px">${escTxt(p)}</td>
      <td style="font-size:10px;color:${isPT?'#6366f1':'#7b82a0'}">${isPT?'PhishTank':'Heuristic'}</td>
      <td style="white-space:nowrap;font-size:11px">${formatTime(e.ts)}</td>
    </tr>`;
  }).join('');
  const repRows=reported.map(r=>
    `<tr><td style="font-family:monospace;font-size:11px">${escTxt(r.url)}</td><td>${formatTime(r.ts)}</td></tr>`
  ).join('')||'<tr><td colspan="2" style="color:#888;text-align:center">None</td></tr>';

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>PhishGuard Report — ${now}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e8eaf0;padding:40px 32px}
.header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px;padding-bottom:20px;border-bottom:2px solid #2e3248}
.logo{font-size:22px;font-weight:800;color:#6366f1}
.meta{font-size:11px;color:#7b82a0;text-align:right;line-height:1.7}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:28px}
.stat{background:#1a1d27;border:1px solid #2e3248;border-radius:10px;padding:16px}
.stat-label{font-size:10px;color:#7b82a0;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
.stat-num{font-size:26px;font-weight:800}
.two-col{display:grid;grid-template-columns:1fr 2fr;gap:14px;margin-bottom:28px}
.section{margin-bottom:28px}
.section-title{font-size:12px;font-weight:700;color:#7b82a0;text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #2e3248}
table{width:100%;border-collapse:collapse;background:#1a1d27;border-radius:10px;overflow:hidden}
th{padding:9px 14px;background:#22263a;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:#7b82a0;text-align:left}
td{padding:9px 14px;border-bottom:1px solid #2e3248;color:#e8eaf0;vertical-align:top}
tr:last-child td{border-bottom:none}
.footer{margin-top:40px;text-align:center;font-size:10px;color:#4a5070;border-top:1px solid #2e3248;padding-top:20px}
</style></head><body>
<div class="header">
  <div class="logo">🛡 PhishGuard Security Report</div>
  <div class="meta">Generated: ${now}<br>v3.0 · Heuristic + PhishTank + Entropy + NLP · OWASP Mapped</div>
</div>
<div class="stats">
  <div class="stat"><div class="stat-label">Total Threats</div><div class="stat-num" style="color:#ef4444">${log.length}</div></div>
  <div class="stat"><div class="stat-label">Critical ≥75</div><div class="stat-num" style="color:#ef4444">${critical}</div></div>
  <div class="stat"><div class="stat-label">High 50–74</div><div class="stat-num" style="color:#f59e0b">${high}</div></div>
  <div class="stat"><div class="stat-label">User Reported</div><div class="stat-num" style="color:#6366f1">${reported.length}</div></div>
</div>
<div class="two-col">
  <div class="section"><div class="section-title">OWASP Breakdown</div>
  <table><thead><tr><th>Category</th><th>Hits</th></tr></thead><tbody>${owaspRows}</tbody></table></div>
  <div class="section"><div class="section-title">User-Reported Sites</div>
  <table><thead><tr><th>URL</th><th>Reported</th></tr></thead><tbody>${repRows}</tbody></table></div>
</div>
<div class="section"><div class="section-title">Full Threat Log</div>
<table><thead><tr><th>URL</th><th>Score</th><th>Primary Threat</th><th>Source</th><th>Time</th></tr></thead>
<tbody>${rows||'<tr><td colspan="5" style="text-align:center;color:#888">No threats logged</td></tr>'}</tbody></table></div>
<div class="footer">PhishGuard v3.0 · Heuristic + PhishTank + Shannon Entropy (DGA) + NLP Analysis · OWASP A01–A10</div>
</body></html>`;
}

function escTxt(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function formatTime(ts) { return ts?new Date(ts).toLocaleString([],{dateStyle:'short',timeStyle:'short'}):'—'; }

loadData();
