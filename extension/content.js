// PhishGuard v3.0 — Content Script (Behavioral DOM + Gmail NLP)
(function () {
  if (window.__phishguardRan) return;
  window.__phishguardRan = true;

  const url      = location.href;
  const hostname = location.hostname;
  const findings = [];
  let extraScore = 0;

  const add = (pts, msg) => { extraScore += pts; findings.push(msg); };

  function getBaseDomain(h) {
    const p = h.replace(/^www\./, '').split('.');
    return p.length > 2 ? p.slice(-2).join('.') : p.join('.');
  }

  const base = getBaseDomain(hostname);

  // ── Skip trusted domains entirely ─────────────────────────────────────────
  if (typeof TRUSTED_DOMAINS !== 'undefined') {
    if (TRUSTED_DOMAINS.has(hostname) || TRUSTED_DOMAINS.has(base)) return;
    if (typeof COLLEGE_KEYWORDS !== 'undefined' && COLLEGE_KEYWORDS.some(k => hostname.includes(k))) return;
    if (typeof TRUSTED_TLDS !== 'undefined' && [...TRUSTED_TLDS].some(t => hostname.endsWith(t))) return;
  }

  const BRANDS = ['google','paypal','amazon','microsoft','apple','facebook','instagram',
    'netflix','twitter','linkedin','github','yahoo','dropbox','stripe','ebay',
    'chase','wellsfargo','bankofamerica','citibank','hdfc','icici','sbi'];

  // ── 1. Password harvesting + brand mismatch ───────────────────────────────
  if (document.querySelector('input[type="password"]')) {
    const bodyText = (document.body?.innerText || '').toLowerCase();
    for (const brand of BRANDS) {
      if (bodyText.includes(brand) && !hostname.includes(brand)) {
        add(35, `[CRITICAL] Password field + "${brand}" brand on non-official domain — credential harvesting — OWASP A02`);
        break;
      }
    }
  }

  // ── 2. Form action mismatch ───────────────────────────────────────────────
  document.querySelectorAll('form[action]').forEach(form => {
    try {
      const actionHost = new URL(form.action, location.href).hostname;
      if (actionHost && actionHost !== hostname && actionHost !== `www.${hostname}`)
        add(40, `[CRITICAL] Form submits to external domain "${actionHost}" — data exfiltration — OWASP A02`);
    } catch {}
  });

  // ── 3. Hidden sensitive fields ────────────────────────────────────────────
  const hiddenSensitive = [...document.querySelectorAll('input[type="hidden"]')]
    .filter(i => /\b(pass|secret|card|cvv|ssn|dob|credit)\b/i.test(i.name + i.id));
  if (hiddenSensitive.length)
    add(20, `[HIGH] ${hiddenSensitive.length} hidden input(s) with sensitive field names — OWASP A03`);

  // ── 4. External scripts from high-risk TLDs ───────────────────────────────
  const HIGH_RISK_SRC = ['.xyz','.top','.pw','.tk','.ml','.gq','.cf','.ga','.sbs','.icu','.lat'];
  document.querySelectorAll('script[src]').forEach(s => {
    try {
      const sh = new URL(s.src).hostname;
      if (sh !== hostname && HIGH_RISK_SRC.some(t => sh.endsWith(t)))
        add(30, `[HIGH] External script from suspicious domain "${sh}" — OWASP A08`);
    } catch {}
  });

  // ── 5. Cross-origin iframes ────────────────────────────────────────────────
  let suspIframes = 0;
  document.querySelectorAll('iframe').forEach(f => {
    try { if (f.src && new URL(f.src).hostname !== hostname) suspIframes++; } catch {}
  });
  if (suspIframes >= 2)
    add(20, `[MEDIUM] ${suspIframes} cross-origin iframes — possible phishing overlay — OWASP A04`);

  // ── 6. Meta-refresh instant redirect ──────────────────────────────────────
  const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
  if (metaRefresh) {
    const delay = parseInt(metaRefresh.getAttribute('content') || '99');
    if (delay < 5)
      add(25, `[HIGH] Instant meta-refresh redirect (${delay}s) — evasion tactic — OWASP A04`);
  }

  // ── 7. Clipboard hijacking (strict — body attribute or inline script only) ─
  const bodyEl = document.body;
  if (bodyEl && (bodyEl.getAttribute('oncopy') || bodyEl.getAttribute('oncut')))
    add(25, '[HIGH] Inline clipboard override on body — hijacking risk — OWASP A03');
  document.querySelectorAll('script:not([src])').forEach(s => {
    if (/clipboardData\.setData\s*\(/i.test(s.textContent))
      add(25, '[HIGH] Inline script overrides clipboard — OWASP A03');
  });

  // ── 8. Redirect chain ─────────────────────────────────────────────────────
  if ((performance?.navigation?.redirectCount || 0) >= 3)
    add(15, `[MEDIUM] ${performance.navigation.redirectCount} redirect hops — obfuscated navigation — OWASP A04`);

  // ── 9. Page title brand mismatch ──────────────────────────────────────────
  const title = document.title.toLowerCase();
  for (const brand of BRANDS) {
    if (title.includes(brand) && !hostname.includes(brand)) {
      add(25, `[HIGH] Page title references "${brand}" but domain is "${hostname}" — OWASP A04`);
      break;
    }
  }

  // ── 10. NLP urgency language ──────────────────────────────────────────────
  if (typeof URGENCY_PHRASES !== 'undefined') {
    const bodyText = (document.body?.innerText || '').toLowerCase();
    const matched  = URGENCY_PHRASES.filter(p => bodyText.includes(p));
    if (matched.length >= 3)
      add(20, `[MEDIUM] Multiple urgency phrases detected: "${matched[0]}" — social engineering — OWASP A04`);
  }

  // ── 11. Gmail NLP Scanner ─────────────────────────────────────────────────
  if (hostname === 'mail.google.com') {
    initGmailScanner();
  }

  function scanEmailNode(el) {
    const text = (el.innerText || el.textContent || '').toLowerCase().trim();
    if (!text || text.length < 40) return;

    let gmailScore = 0;
    const gmailFindings = [];

    // Expanded urgency phrases for Gmail — covers CanIPhish + real-world patterns
    const GMAIL_PHRASES = [
      // Standard urgency
      'verify immediately','act now','click here to confirm','immediate action required',
      'your account will be closed','your account has been suspended','failure to verify',
      'unauthorized access','unusual sign-in','unusual activity','suspicious login',
      'suspicious activity detected','we detected suspicious','your account is at risk',
      // Password/security
      'your password has expired','password will expire','reset your password',
      'update your password','confirm your password','verify your identity',
      'confirm your identity','confirm your information','confirm personal information',
      'upcoming password expiry','password expiry',
      // Account threats
      'your account has been compromised','new device logged in','new sign-in',
      'login attempt','access attempt','someone tried to sign in',
      'strange account activity','new system access','account verification required',
      // Financial
      'update your billing','update your payment','payment failed','payment declined',
      'invoice attached','your invoice','billing information required',
      'claim your prize','you have been selected','you are eligible',
      // Delivery/package
      'your package could not be delivered','delivery failed','package on hold',
      'shipment requires','customs fee required',
      // Urgency time pressure
      'expires in 24 hours','expires today','limited time','within 24 hours',
      'respond immediately','urgent action','action required',
    ];

    const matched = GMAIL_PHRASES.filter(p => text.includes(p));
    if (matched.length >= 2) {
      gmailScore += 25;
      gmailFindings.push(`[HIGH] Email contains phishing urgency language: "${matched[0]}", "${matched[1]}" — social engineering — OWASP A04`);
    } else if (matched.length === 1) {
      gmailScore += 10;
      gmailFindings.push(`[MEDIUM] Suspicious email language: "${matched[0]}" — OWASP A04`);
    }

    // Link text ≠ href domain mismatch
    el.querySelectorAll('a[href]').forEach(a => {
      try {
        const href = new URL(a.href);
        const linkHost = href.hostname;
        if (!linkHost || linkHost === hostname) return;
        const linkBase = getBaseDomain(linkHost);
        const linkText = (a.innerText || a.textContent || '').trim().toLowerCase();

        // Link text shows a domain that differs from actual href
        if (linkText.includes('.') && !linkText.includes(linkBase) && linkText.length < 60) {
          gmailScore += 30;
          gmailFindings.push(`[CRITICAL] Email link text "${a.innerText.trim().slice(0,50)}" leads to different domain "${linkHost}" — phishing link — OWASP A02`);
        }

        // High-risk TLD in link
        if (typeof HIGH_RISK_TLDS !== 'undefined') {
          const tld = '.' + linkHost.split('.').pop();
          if (HIGH_RISK_TLDS.has(tld)) {
            gmailScore += 20;
            gmailFindings.push(`[HIGH] Email contains link to high-risk TLD domain "${linkHost}" — OWASP A08`);
          }
        }
      } catch {}
    });

    // Brand mention + external link
    for (const brand of BRANDS) {
      if (text.includes(brand)) {
        el.querySelectorAll('a[href]').forEach(a => {
          try {
            const lh = new URL(a.href).hostname;
            if (!lh.includes(brand) && !lh.endsWith('.google.com') && lh !== hostname) {
              gmailScore += 20;
              gmailFindings.push(`[HIGH] Email references "${brand}" but links to "${lh}" — impersonation — OWASP A04`);
            }
          } catch {}
        });
        break;
      }
    }

    if (gmailFindings.length) {
      extraScore += Math.min(gmailScore, 70);
      findings.push(...gmailFindings);
      sendFindings();
    }
  }

  function sendFindings() {
    if (extraScore > 0 && findings.length) {
      chrome.runtime.sendMessage({ type: 'CONTENT_FINDINGS', url, extraScore, findings });
    }
  }

  // Gmail loads email content dynamically — use MutationObserver
  function initGmailScanner() {
    // Selectors covering all known Gmail email body containers
    const EMAIL_SELECTORS = [
      '.a3s',           // classic Gmail email body
      '.ii.gt',         // message view body
      '.adn',           // thread view
      '[data-message-id] .ii',  // message with ID
      '.nH .if',        // newer Gmail structure
    ].join(', ');

    // Scan already-loaded emails
    document.querySelectorAll(EMAIL_SELECTORS).forEach(el => scanEmailNode(el));

    // Watch for dynamically loaded emails (Gmail is a SPA)
    const observer = new MutationObserver(mutations => {
      mutations.forEach(m => {
        m.addedNodes.forEach(node => {
          if (node.nodeType !== 1) return;
          // Check if the node itself or its children match email selectors
          const targets = [node, ...node.querySelectorAll(EMAIL_SELECTORS)];
          targets.forEach(el => {
            if (el.matches && el.matches(EMAIL_SELECTORS)) scanEmailNode(el);
          });
        });
      });
    });

    observer.observe(document.body, { childList: true, subtree: true });

    // Disconnect after 5 minutes to avoid memory leaks
    setTimeout(() => observer.disconnect(), 300000);
  }

  // ── Send findings (non-Gmail) ──────────────────────────────────────────────
  if (hostname !== 'mail.google.com' && extraScore > 0) {
    chrome.runtime.sendMessage({ type: 'CONTENT_FINDINGS', url, extraScore, findings });
  }
})();
