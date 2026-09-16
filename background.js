// background.js
// Core logic: destination-focused scanning against PhishTank (local DB) + VirusTotal
// (live API), a persistent URL-level result cache, and Telegram alerting when
// phishing is confirmed.
//
// ARCHITECTURE NOTE (redesigned): there is no "trusted domain" concept anymore.
// Source-page trust and destination-URL trust are permanently separate — the
// page you're on never determines whether a link you click gets scanned. The
// only thing that skips a scan is the link staying on the exact same origin
// as the current page (content.js), which isn't a trust decision at all —
// it's recognizing there's no new destination to evaluate. Every cross-origin
// destination is checked, every time, against the cache below.

const PHISHTANK_SYNC_ALARM = 'phishtank-sync';
const PHISHTANK_SYNC_PERIOD_MIN = 12 * 60; // resync twice a day
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h — re-verify a URL once a day, not every click
const VT_MALICIOUS_THRESHOLD = 3; // # of VT engines flagging malicious/phishing to call it "dangerous"
const VT_SUSPICIOUS_THRESHOLD = 1;
const URL_CACHE_MAX_ENTRIES = 2000;

let scanHistory = [];

// ---------- Persistent URL-level cache ----------
// Stored in chrome.storage.local, shaped exactly as requested:
//   { "https://example.com/login": { verdict: "safe", score: 95, scannedAt: 169... } }
// This replaces the old in-memory Map, which was wiped every time the MV3
// service worker went idle and restarted (which happens constantly during
// active browsing) — that silent cache loss was a real contributor to the
// repeated-scanning problem, separate from the trusted-domain bug.
async function getCachedResult(url) {
  const { urlCache } = await chrome.storage.local.get('urlCache');
  const entry = (urlCache || {})[url];
  if (entry && Date.now() - entry.scannedAt < CACHE_TTL_MS) return entry;
  return null;
}

async function setCachedResult(url, entry) {
  const { urlCache } = await chrome.storage.local.get('urlCache');
  const cache = urlCache || {};
  cache[url] = entry;

  const keys = Object.keys(cache);
  if (keys.length > URL_CACHE_MAX_ENTRIES) {
    keys.sort((a, b) => cache[a].scannedAt - cache[b].scannedAt);
    for (let i = 0; i < keys.length - URL_CACHE_MAX_ENTRIES; i++) delete cache[keys[i]];
  }
  await chrome.storage.local.set({ urlCache: cache });
}

// ---------- Risk Score (Feature 1) ----------
// Deterministic, signal-based — the SAME PhishTank/VirusTotal/heuristic outputs
// that already decide riskLevel also drive this number. No AI involvement.
// Weights are documented inline. The score is clamped into the bucket implied
// by the EXISTING riskLevel decision below, so the number can never contradict
// the classification your detection pipeline already made — it's a
// confidence/severity readout on top of that decision, not a second opinion.
//
//   0–29   -> safe
//   30–59  -> suspicious
//   60–100 -> dangerous
//
// Weight rationale:
//   PhishTank confirmed match   : +70  (single strongest signal available)
//   VirusTotal "malicious" hit  : +30 each, capped at +90 (3 engines already
//                                  crosses the existing VT_MALICIOUS_THRESHOLD
//                                  used to classify "dangerous", so 3*30=90
//                                  lands solidly in that bucket)
//   VirusTotal "suspicious" hit : +15 each, capped at +30 (1 engine alone
//                                  crosses VT_SUSPICIOUS_THRESHOLD, and
//                                  1*15=... only 15, so malicious weight is
//                                  what actually crosses 30 for the existing
//                                  1-engine "suspicious" trigger — suspicious
//                                  engines add supporting weight on top)
//   Heuristic indicators        : existing heuristicCheck() score, folded in
//                                  at 30% weight (max +25) as supporting
//                                  evidence alongside API results — never
//                                  enough alone to flip a clean API result
//                                  into a higher bucket, matching the fact
//                                  that heuristics only DRIVE classification
//                                  when both APIs are unavailable.
function computeRiskScore(riskLevel, phishtank, virustotal, heuristic) {
  let raw = 0;

  if (phishtank.checked && phishtank.isPhishing) raw += 70;

  if (virustotal.checked) {
    raw += Math.min(90, (virustotal.malicious || 0) * 30);
    raw += Math.min(30, (virustotal.suspicious || 0) * 15);
  }

  if (heuristic) {
    raw += Math.min(25, Math.round(heuristic.score * 0.3));
  }

  raw = Math.min(100, raw);

  // Guarantee the score always agrees with the bucket the existing
  // classification logic already chose (this never overrides riskLevel —
  // riskLevel is computed exactly as before; this only keeps the displayed
  // number consistent with that pre-existing decision).
  if (riskLevel === 'dangerous') return Math.max(raw, 60);
  if (riskLevel === 'suspicious') return Math.min(Math.max(raw, 30), 59);
  return Math.min(raw, 29);
}

// ---------- Settings ----------
// Credentials live in chrome.storage.SYNC (not .local) — tied to the user's
// Google/Chrome login, so on a new laptop signed into the same account with
// sync on, these values arrive automatically with no re-pasting.
async function getSettings() {
  const s = await chrome.storage.sync.get([
    'vtApiKey', 'telegramBotToken', 'telegramChatId', 'telegramEnabled', 'geminiApiKey'
  ]);
  return {
    vtApiKey: s.vtApiKey || '',
    telegramBotToken: s.telegramBotToken || '',
    telegramChatId: s.telegramChatId || '',
    telegramEnabled: s.telegramEnabled !== false,
    geminiApiKey: s.geminiApiKey || ''
  };
}

// The master power switch (popup toggle) stays in storage.LOCAL, not sync —
// a "just for this browser, right now" convenience switch, not a credential
// you'd want mirrored to every device you're signed into.
async function isExtensionEnabled() {
  const { extensionEnabled } = await chrome.storage.local.get('extensionEnabled');
  return extensionEnabled !== false; // default ON
}

// ---------- PhishTank local database ----------
// PhishTank's bulk feed (online-valid.json) is large; we store just a Set of
// normalized URLs in chrome.storage.local so lookups are instant and offline.
async function syncPhishTankDatabase() {
  try {
    console.log('[PhishTank] Syncing database...');
    const resp = await fetch('https://data.phishtank.com/data/online-valid.json', {
      headers: { 'User-Agent': 'phishtank/link-defender' }
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    const urlSet = {};
    for (const entry of data) {
      if (entry.url) {
        urlSet[normalizeUrl(entry.url)] = true;
      }
    }

    await chrome.storage.local.set({
      phishtankDB: urlSet,
      phishtankLastSync: Date.now(),
      phishtankCount: Object.keys(urlSet).length
    });
    console.log(`[PhishTank] Synced ${Object.keys(urlSet).length} known phishing URLs`);
  } catch (e) {
    // PhishTank rate-limits/blocks anonymous bulk downloads sometimes — fail soft.
    console.warn('[PhishTank] Sync failed, will retry next cycle:', e.message);
  }
}

function normalizeUrl(url) {
  try {
    const u = new URL(url);
    return (u.origin + u.pathname).replace(/\/$/, '').toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

async function checkPhishTankLocal(url) {
  const { phishtankDB } = await chrome.storage.local.get('phishtankDB');
  if (!phishtankDB) return { checked: false, isPhishing: false };
  const norm = normalizeUrl(url);
  return { checked: true, isPhishing: !!phishtankDB[norm] };
}

// ---------- VirusTotal ----------
function toVtUrlId(url) {
  // VT v3 wants base64url(url), no padding
  const b64 = btoa(unescape(encodeURIComponent(url)));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function checkVirusTotal(url, apiKey) {
  if (!apiKey) return { checked: false, reason: 'No VirusTotal API key configured' };

  const urlId = toVtUrlId(url);

  try {
    // Try fetching an existing report first (cheap, no quota cost beyond 1 lookup)
    let resp = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey }
    });

    if (resp.status === 404) {
      // Not seen before — submit it for analysis
      const submitResp = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`
      });
      if (!submitResp.ok) throw new Error(`Submit failed: HTTP ${submitResp.status}`);

      // Free tier is analysis-queue based; give it a moment then re-fetch the report.
      await new Promise(r => setTimeout(r, 4000));
      resp = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { 'x-apikey': apiKey }
      });
    }

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    return {
      checked: true,
      malicious,
      suspicious,
      harmless: stats.harmless || 0,
      isPhishing: malicious >= VT_MALICIOUS_THRESHOLD,
      isSuspicious: malicious >= VT_SUSPICIOUS_THRESHOLD || suspicious >= VT_SUSPICIOUS_THRESHOLD,
      permalink: `https://www.virustotal.com/gui/url/${urlId}`
    };
  } catch (e) {
    console.warn('[VirusTotal] check failed:', e.message);
    return { checked: false, reason: e.message };
  }
}

// ---------- Heuristic fallback (used only if both APIs are unavailable) ----------
function heuristicCheck(url) {
  const patterns = [
    { re: /(g00gle|go0gle|goog1e|faceb00k|paypa1|micros0ft)/i, weight: 60, name: 'Typosquatting' },
    { re: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, weight: 70, name: 'IP address URL' },
    { re: /\.(tk|ml|ga|cf|click|top|xyz|work)$/i, weight: 30, name: 'Suspicious TLD' },
    { re: /^http:\/\//i, weight: 15, name: 'No HTTPS' }
  ];
  let score = 0;
  const reasons = [];
  for (const p of patterns) {
    if (p.re.test(url)) { score += p.weight; reasons.push(p.name); }
  }
  return { score, reasons, isPhishing: score >= 60, isSuspicious: score >= 30 };
}

// ---------- Combined scan ----------
async function scanUrl(url, sourcePageUrl) {
  // Safety-net check — content.js already skips scanning when the extension is
  // off, but we guard here too in case a stray message ever gets through.
  if (!(await isExtensionEnabled())) {
    return { url, sourcePageUrl, riskLevel: 'safe', reasons: ['Extension is turned off'], sources: [], timestamp: Date.now() };
  }

  // Serve from the persistent URL cache if verified recently — this is what
  // stops the same link being re-scanned on every click, and unlike the old
  // in-memory Map, it survives the service worker being unloaded and restarted.
  const cached = await getCachedResult(url);
  if (cached) {
    return {
      url, sourcePageUrl, riskLevel: cached.verdict, reasons: cached.reasons,
      sources: cached.sources, vtPermalink: cached.vtPermalink,
      timestamp: cached.scannedAt, fromCache: true,
      riskScore: cached.riskScore,
      hasAiExplanation: !!cached.aiExplanation
    };
  }

  const settings = await getSettings();
  const [phishtank, virustotal] = await Promise.all([
    checkPhishTankLocal(url),
    checkVirusTotal(url, settings.vtApiKey)
  ]);

  let riskLevel = 'safe';
  let reasons = [];
  const sources = [];

  if (phishtank.checked) {
    sources.push('PhishTank');
    if (phishtank.isPhishing) {
      riskLevel = 'dangerous';
      reasons.push('Listed in PhishTank confirmed-phishing database');
    }
  }

  if (virustotal.checked) {
    sources.push('VirusTotal');
    if (virustotal.isPhishing) {
      riskLevel = 'dangerous';
      reasons.push(`${virustotal.malicious} security engines on VirusTotal flag this as malicious`);
    } else if (virustotal.isSuspicious && riskLevel !== 'dangerous') {
      riskLevel = 'suspicious';
      reasons.push(`${virustotal.malicious + virustotal.suspicious} engines flag this URL as suspicious`);
    }
  }

  // Fall back to heuristics ONLY FOR CLASSIFICATION if neither real source
  // responded — this branch is untouched from before.
  let heuristicForScoring = null;
  if (!phishtank.checked && !virustotal.checked) {
    const h = heuristicCheck(url);
    heuristicForScoring = h;
    sources.push('Heuristic (offline fallback)');
    reasons = h.reasons.length ? h.reasons : ['No suspicious patterns detected'];
    riskLevel = h.isPhishing ? 'dangerous' : h.isSuspicious ? 'suspicious' : 'safe';
  } else {
    // APIs DID respond, so heuristics don't drive riskLevel (unchanged
    // behavior) — but we still compute them as supporting evidence for the
    // Risk Score and for the "Why?" explanation, at reduced weight (see
    // computeRiskScore). This never changes the classification above.
    heuristicForScoring = heuristicCheck(url);
    if (heuristicForScoring.reasons.length) {
      reasons.push(...heuristicForScoring.reasons.map(r => `Heuristic: ${r}`));
    }
  }

  if (reasons.length === 0) reasons = ['No known threats found'];

  const riskScore = computeRiskScore(riskLevel, phishtank, virustotal, heuristicForScoring);

  const result = {
    url,
    sourcePageUrl,
    riskLevel,
    riskScore,
    reasons,
    sources,
    vtPermalink: virustotal.permalink || null,
    vtMalicious: virustotal.malicious || 0,
    vtSuspicious: virustotal.suspicious || 0,
    phishtankMatch: !!(phishtank.checked && phishtank.isPhishing),
    hasAiExplanation: false,
    timestamp: Date.now()
  };

  await setCachedResult(url, {
    verdict: riskLevel,
    riskScore,
    reasons,
    sources,
    vtPermalink: virustotal.permalink || null,
    vtMalicious: virustotal.malicious || 0,
    vtSuspicious: virustotal.suspicious || 0,
    phishtankMatch: !!(phishtank.checked && phishtank.isPhishing),
    scannedAt: Date.now()
  });
  await recordScan(result);

  if (riskLevel === 'dangerous') {
    await sendTelegramAlert(result, settings);
    notifyUser(result);
  }

  return result;
}

// ---------- History ----------
async function recordScan(result) {
  scanHistory.unshift(result);
  if (scanHistory.length > 500) scanHistory.pop();
  await chrome.storage.local.set({ scanHistory });
}

async function loadHistory() {
  const { scanHistory: saved } = await chrome.storage.local.get('scanHistory');
  scanHistory = saved || [];
}

// ---------- Telegram ----------
async function sendTelegramAlert(result, settings) {
  if (!settings.telegramEnabled) return;
  if (!settings.telegramBotToken || !settings.telegramChatId) {
    console.warn('[Telegram] Not configured — skipping alert');
    return;
  }

  const text =
    `🔴 *PHISHING LINK DETECTED*\n\n` +
    `*URL:* \`${escapeMd(result.url)}\`\n` +
    `*Risk Score:* ${result.riskScore ?? '—'}/100\n` +
    `*Found on:* \`${escapeMd(result.sourcePageUrl || 'unknown')}\`\n` +
    `*Sources:* ${result.sources.join(', ')}\n` +
    `*Reasons:*\n${result.reasons.map(r => `• ${escapeMd(r)}`).join('\n')}\n` +
    (result.vtPermalink ? `\n[View on VirusTotal](${result.vtPermalink})` : '') +
    `\n\n🕒 ${new Date(result.timestamp).toLocaleString()}`;

  try {
    const resp = await fetch(`https://api.telegram.org/bot${settings.telegramBotToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: settings.telegramChatId,
        text,
        parse_mode: 'Markdown',
        disable_web_page_preview: true
      })
    });
    if (!resp.ok) {
      const err = await resp.text();
      console.error('[Telegram] Send failed:', err);
    } else {
      console.log('[Telegram] Alert sent to group');
    }
  } catch (e) {
    console.error('[Telegram] Send error:', e.message);
  }
}

function escapeMd(text) {
  return String(text).replace(/([_*[\]()~`>#+\-=|{}.!])/g, '\\$1');
}

// ---------- Gemini "Why?" explanation (Feature 2) ----------
// CRITICAL: this section is ONLY ever invoked from the REQUEST_AI_EXPLANATION
// message handler below, which is ONLY ever sent by content.js in response to
// an explicit click on the "Why?" button. Nothing in scanUrl(), the
// webNavigation listener, or the context-menu handler calls this. Normal
// scanning has zero dependency on Gemini and zero added latency from it.
const GEMINI_MODEL = 'gemini-3.1-flash-lite';
const GEMINI_ENDPOINT = (apiKey) =>
  `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${apiKey}`;
const GEMINI_TIMEOUT_MS = 12000;

function buildGeminiPrompt(evidence) {
  // Only the security evidence Link Defender already generated is sent —
  // never page content, cookies, history, or anything else about the user.
  //
  // The old prompt just asked Gemini to "explain the evidence," and the old
  // schema asked for a "reasons" array — which is exactly the same list the
  // modal already shows as bullet points above this panel. That's why it felt
  // like Gemini was just repeating the screen back. This version explicitly
  // tells it what's already visible and asks it to add something the raw
  // detection data can't: read the actual URL itself, name what it looks like
  // it's impersonating (if anything), explain the real-world consequence in
  // concrete terms, and give one piece of practical advice.
  return (
    `You are a cybersecurity assistant embedded in a browser extension called Link Defender.\n\n` +
    `The user is ALREADY looking at, on screen, right above your answer:\n` +
    `- A Risk Score (0-100)\n` +
    `- Which sources were checked (PhishTank / VirusTotal)\n` +
    `- A bullet list of raw detection indicators (e.g. "Suspicious TLD", "Typosquatting", ` +
    `"3 VirusTotal detections")\n\n` +
    `Do NOT restate the risk score, the source names, or reword that bullet list back to them — ` +
    `they can already see all of that. Your job is to add analysis they CANNOT already see:\n\n` +
    `1. Look at the actual URL/domain string yourself (given below) and point out anything ` +
    `concrete you notice — e.g. which real, well-known brand or service this domain resembles ` +
    `or may be impersonating, or what specifically about the domain/path structure looks off. ` +
    `Be specific to THIS url, not a generic template.\n` +
    `2. In plain language, explain what this specific combination of signals typically means in ` +
    `practice, and what could realistically happen if someone entered information or downloaded ` +
    `something from this page — grounded only in the evidence given, never inventing claims the ` +
    `evidence doesn't support (e.g. do not say "this steals passwords" unless something in the ` +
    `evidence actually indicates that).\n` +
    `3. Give ONE short, practical, actionable tip.\n\n` +
    `Write 3-5 sentences for a non-technical reader. Vary your wording based on what's actually ` +
    `in the URL and evidence — do not produce a generic templated answer.\n\n` +
    `Evidence (for your analysis only — do not quote it back verbatim):\n${JSON.stringify(evidence, null, 2)}\n\n` +
    `Respond with ONLY a JSON object, no markdown fences, matching exactly this shape:\n` +
    `{"risk_level": "medium|high", "confidence": <integer 0-100>, ` +
    `"explanation": "<3-5 sentences of NEW analysis, not a repeat of the evidence above>", ` +
    `"advice": "<one short, concrete, actionable sentence>"}`
  );
}

function validateGeminiResult(obj) {
  if (!obj || typeof obj !== 'object') return false;
  if (typeof obj.explanation !== 'string' || !obj.explanation.trim()) return false;
  if (typeof obj.confidence !== 'number' || obj.confidence < 0 || obj.confidence > 100) return false;
  if (typeof obj.advice !== 'string' || !obj.advice.trim()) return false;
  if (typeof obj.risk_level !== 'string') return false;
  return true;
}

async function callGemini(evidence, apiKey) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), GEMINI_TIMEOUT_MS);

  try {
    const resp = await fetch(GEMINI_ENDPOINT(apiKey), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        contents: [{ parts: [{ text: buildGeminiPrompt(evidence) }] }],
        // Slightly higher than before (was 0.2) — a very low temperature was
        // part of why every explanation came out sounding like the same
        // filled-in template. This keeps answers grounded and JSON-valid
        // while allowing wording to actually vary URL-to-URL.
        generationConfig: { temperature: 0.45, responseMimeType: 'application/json' }
      })
    });
    clearTimeout(timeout);

    if (!resp.ok) {
      const errText = await resp.text().catch(() => '');
      throw new Error(`Gemini HTTP ${resp.status}${errText ? ': ' + errText.slice(0, 150) : ''}`);
    }

    const data = await resp.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) throw new Error('Empty response from Gemini');

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error('Gemini returned invalid JSON');
    }

    if (!validateGeminiResult(parsed)) throw new Error('Gemini response missing required fields');

    return {
      ok: true,
      risk_level: parsed.risk_level,
      confidence: Math.round(parsed.confidence),
      explanation: parsed.explanation.trim(),
      advice: parsed.advice.trim(),
      generatedAt: Date.now()
    };
  } catch (e) {
    clearTimeout(timeout);
    const reason = e.name === 'AbortError' ? 'Gemini request timed out' : e.message;
    return { ok: false, error: reason };
  }
}

// Persists the explanation onto the SAME cache entry the URL scan already
// uses (so it naturally expires with the existing 24h cache — no separate
// AI-cache lifetime to manage) and flags any matching history rows so the
// dashboard can show "AI Explanation Available" without calling Gemini again.
async function persistAiExplanation(url, explanation) {
  const { urlCache } = await chrome.storage.local.get('urlCache');
  const cache = urlCache || {};
  if (cache[url]) {
    cache[url].aiExplanation = explanation;
    await chrome.storage.local.set({ urlCache: cache });
  }

  let changed = false;
  for (const h of scanHistory) {
    if (h.url === url) { h.hasAiExplanation = true; changed = true; }
  }
  if (changed) await chrome.storage.local.set({ scanHistory });
}

async function getAiExplanation(url) {
  const { urlCache } = await chrome.storage.local.get('urlCache');
  const entry = (urlCache || {})[url];

  // Already explained for this scan — return the cached explanation, no
  // Gemini call. This is what makes repeated "Why?" clicks free.
  if (entry?.aiExplanation) {
    return { ...entry.aiExplanation, fromCache: true };
  }

  const settings = await getSettings();
  if (!settings.geminiApiKey) {
    return { ok: false, error: 'No Gemini API key configured (Options → Gemini AI)' };
  }
  if (!entry) {
    return { ok: false, error: 'No scan evidence found for this URL yet — scan it first' };
  }

  const evidence = {
    url,
    classification: entry.verdict,
    risk_score: entry.riskScore,
    indicators: entry.reasons,
    virustotal_detections: entry.vtMalicious || 0,
    virustotal_suspicious: entry.vtSuspicious || 0,
    phishtank_match: !!entry.phishtankMatch
  };

  const result = await callGemini(evidence, settings.geminiApiKey);
  if (result.ok) {
    await persistAiExplanation(url, result);
    return { ...result, fromCache: false };
  }
  return result; // { ok: false, error }
}

function notifyUser(result) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '🚨 Phishing link blocked',
    message: result.url.length > 70 ? result.url.slice(0, 70) + '…' : result.url,
    priority: 2
  });
}

// ---------- Right-click "Scan this link" (feature #7) ----------
// Context menus are created in the background because content scripts can't
// register them. When clicked, we run the same scanUrl() pipeline as a normal
// click, then message the *content script in that tab* to show the result —
// this is purely informational (no navigation to block), so it always shows
// a "Close" button rather than the Cancel/Proceed choice a real click gets.
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'link-defender-scan' || !info.linkUrl) return;
  const result = await scanUrl(info.linkUrl, tab.url);
  if (tab?.id) {
    chrome.tabs.sendMessage(tab.id, { type: 'SHOW_SCAN_RESULT', result }).catch(() => {
      // Content script may not be present on some pages (e.g. chrome:// or the
      // Chrome Web Store) — fall back to a system notification in that case.
      notifyManualScanResult(result);
    });
  }
});

function notifyManualScanResult(result) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: result.riskLevel === 'dangerous' ? '🚨 Dangerous link' : result.riskLevel === 'suspicious' ? '⚠️ Suspicious link' : '✅ Link looks safe',
    message: result.url.length > 70 ? result.url.slice(0, 70) + '…' : result.url,
    priority: result.riskLevel === 'dangerous' ? 2 : 0
  });
}

// ---------- webNavigation safety net ----------
// Catches actual top-level page navigations that never went through our click
// listener at all — a link opened via JS (window.location = x), a redirect
// chain landing somewhere unexpected, etc. frameId === 0 restricts this to the
// MAIN FRAME only, so iframes, CDN requests, API calls, images, and background
// JS never register as "the user navigating" — exactly the distinction you
// asked for. We can't block a navigation that has already committed, so this
// is after-the-fact: if the destination turns out to be flagged, we tell the
// content script (now loaded on the new page) to show a warning banner.
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return; // ignore subframes/iframes entirely
  if (!/^https?:/i.test(details.url)) return;

  const cached = await getCachedResult(details.url);
  if (cached) {
    // Already known — no re-scan. Only worth telling the page about it if
    // it's not safe (a "safe, carry on" message would just be noise).
    if (cached.verdict !== 'safe') {
      notifyTabOfRetroactiveResult(details.tabId, {
        url: details.url, riskLevel: cached.verdict, reasons: cached.reasons, sources: cached.sources
      });
    }
    return;
  }

  // Not cached — this navigation slipped past the click interceptor. Scan it
  // now as a safety net.
  const result = await scanUrl(details.url, null);
  if (result.riskLevel !== 'safe') {
    notifyTabOfRetroactiveResult(details.tabId, result);
  }
}, { url: [{ schemes: ['http', 'https'] }] });

function notifyTabOfRetroactiveResult(tabId, result) {
  chrome.tabs.sendMessage(tabId, { type: 'SHOW_RETROACTIVE_WARNING', result }).catch(() => {
    notifyManualScanResult(result);
  });
}

// ---------- Message routing ----------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_URL') {
    scanUrl(message.url, message.sourcePageUrl).then(sendResponse);
    return true; // async response
  }
  if (message.type === 'GET_HISTORY') {
    sendResponse({ history: scanHistory });
    return true;
  }
  if (message.type === 'CLEAR_HISTORY') {
    scanHistory = [];
    chrome.storage.local.set({ scanHistory: [] });
    sendResponse({ success: true });
    return true;
  }
  if (message.type === 'FORCE_PHISHTANK_SYNC') {
    syncPhishTankDatabase().then(() => sendResponse({ success: true }));
    return true;
  }
  if (message.type === 'GET_PHISHTANK_STATUS') {
    chrome.storage.local.get(['phishtankLastSync', 'phishtankCount']).then(sendResponse);
    return true;
  }
  if (message.type === 'CLEAR_URL_CACHE') {
    chrome.storage.local.set({ urlCache: {} }).then(() => sendResponse({ success: true }));
    return true;
  }
  if (message.type === 'REQUEST_AI_EXPLANATION') {
    // The ONLY entry point that ever calls Gemini. Fired exclusively by the
    // "Why?" button in content.js — never during scanning.
    getAiExplanation(message.url).then(sendResponse);
    return true;
  }
});

// Keep the toolbar badge reflecting the power switch, and let content scripts
// react instantly (via chrome.storage.onChanged, see content.js) when it flips.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.extensionEnabled) {
    const on = changes.extensionEnabled.newValue !== false;
    chrome.action.setBadgeText({ text: on ? '' : 'OFF' });
    chrome.action.setBadgeBackgroundColor({ color: '#94a3b8' });
  }
});

// ---------- Lifecycle ----------
chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(PHISHTANK_SYNC_ALARM, { periodInMinutes: PHISHTANK_SYNC_PERIOD_MIN });
  syncPhishTankDatabase();
  createContextMenu();
});

chrome.runtime.onStartup.addListener(createContextMenu);

// contextMenus.create throws if an id already exists, which happens whenever
// the MV3 service worker restarts (Chrome unloads it when idle) — removeAll()
// first makes this idempotent no matter how many times it runs.
function createContextMenu() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: 'link-defender-scan',
      title: '🛡️ Scan this link with Link Defender',
      contexts: ['link']
    });
  });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === PHISHTANK_SYNC_ALARM) syncPhishTankDatabase();
});

loadHistory();
console.log('🛡️ Link Defender background worker loaded');
