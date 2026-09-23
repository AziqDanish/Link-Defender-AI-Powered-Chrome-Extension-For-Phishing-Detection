(function () {
  let overlay = null;
  let extensionEnabled = true;
  const currentOrigin = window.location.origin;

  chrome.storage.local.get('extensionEnabled', (s) => {
    extensionEnabled = s.extensionEnabled !== false;
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.extensionEnabled) {
      extensionEnabled = changes.extensionEnabled.newValue !== false;
    }
  });

  function isSameOrigin(url) {
    try { return new URL(url, window.location.href).origin === currentOrigin; } catch { return false; }
  }

  function showOverlay(text) {
    removeOverlay();
    overlay = document.createElement('div');
    overlay.id = 'link-defender-overlay';
    overlay.innerHTML = `
      <div class="ld-box">
        <div class="ld-spinner"></div>
        <div class="ld-text">${text}</div>
      </div>`;
    document.documentElement.appendChild(overlay);
  }

  function removeOverlay() {
    if (overlay) {
      overlay.remove();
      overlay = null;
    }
  }

  // ---------- Safe-scan celebration (lightweight, no image/gif assets) ----------
  
  const SAFE_TOAST_DURATION_MS = 1500;
  const SPARK_COLORS = ['#22c55e', '#facc15', '#38bdf8', '#4ade80', '#fb923c'];

  function buildFireworkHtml() {
    const count = 10;
    let html = '';
    for (let i = 0; i < count; i++) {
      const angle = (360 / count) * i;
      const color = SPARK_COLORS[i % SPARK_COLORS.length];
      const delay = (i % 3) * 45;
      html += `<div class="ld-spark-wrap" style="transform:rotate(${angle}deg);">
        <span class="ld-spark" style="background:${color};animation-delay:${delay}ms;"></span>
      </div>`;
    }
    return html;
  }

  function showSafeCelebration(onDone) {
    removeOverlay();
    const modal = document.createElement('div');
    modal.id = 'link-defender-overlay';
    modal.innerHTML = `
      <div class="ld-box ld-safe">
        <div class="ld-firework">${buildFireworkHtml()}</div>
        <div class="ld-safe-icon">✅</div>
        <div class="ld-safe-title">This link is safe!</div>
        <div class="ld-safe-sub">Enjoy! 🎉</div>
      </div>`;
    document.documentElement.appendChild(modal);
    overlay = modal;

    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      removeOverlay();
      if (onDone) onDone();
    };

    modal.addEventListener('click', finish); 
    setTimeout(finish, SAFE_TOAST_DURATION_MS);
  }

  // ---------- Risk Score + "Why?" button ----------

  function riskExplanationHtml(result) {
    if (result.riskLevel === 'safe') return '';
    const isDangerous = result.riskLevel === 'dangerous';
    const whyLabel = isDangerous ? '🤖 Why is this dangerous?' : '🤖 Why is this suspicious?';
    return `
      <div class="ld-score-box">
        <div class="ld-score-label">Risk Score</div>
        <div class="ld-score-value ${isDangerous ? 'ld-danger' : 'ld-suspicious'}">${result.riskScore ?? '—'}<span>/100</span></div>
      </div>
      <button class="ld-why-btn">${whyLabel}</button>
      <div class="ld-ai-panel" style="display:none;"></div>`;
  }

 
  function wireWhyButton(root, result) {
    const btn = root.querySelector('.ld-why-btn');
    const panel = root.querySelector('.ld-ai-panel');
    if (!btn || !panel) return;

    btn.addEventListener('click', async () => {
      btn.disabled = true;
      panel.style.display = 'block';
      panel.innerHTML = `<div class="ld-ai-loading"><span class="ld-mini-spinner"></span> Analyzing the detected security indicators…</div>`;

      const resp = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'REQUEST_AI_EXPLANATION', url: result.url }, (r) =>
          resolve(r || { ok: false, error: 'No response from extension background' })
        );
      });

      btn.disabled = false;

      if (!resp.ok) {
        panel.innerHTML = `
          <div class="ld-ai-title">🤖 AI Analysis</div>
          <div class="ld-ai-error">AI explanation is currently unavailable.</div>
          <div class="ld-ai-fallback">The existing Link Defender detection information is still valid.<br>
          Risk Score: <b>${result.riskScore ?? '—'}/100</b></div>`;
        return;
      }

      const confPct = Math.round(resp.confidence);
      panel.innerHTML = `
        <div class="ld-ai-title">🤖 AI Analysis ${resp.fromCache ? '<span class="ld-ai-cached">(cached)</span>' : ''}</div>
        <div class="ld-ai-meta">Risk: <b>${escapeHtml(resp.risk_level)}</b> &nbsp;·&nbsp; Confidence: <b>${confPct}%</b></div>
        <div class="ld-ai-explanation">${escapeHtml(resp.explanation)}</div>
        ${resp.advice ? `<div class="ld-ai-advice">💡 ${escapeHtml(resp.advice)}</div>` : ''}`;
    });
  }

  function showWarning(result, proceedCallback) {
    removeOverlay();
    const modal = document.createElement('div');
    modal.id = 'link-defender-overlay';
    const isDangerous = result.riskLevel === 'dangerous';
    const buttonsHtml = isDangerous
      ? `<div class="ld-buttons"><button class="ld-btn ld-cancel" style="flex:1;">🚪 Stay safe &amp; exit</button></div>`
      : `<div class="ld-buttons">
           <button class="ld-btn ld-cancel">Stay safe — cancel</button>
           <button class="ld-btn ld-proceed">Proceed anyway</button>
         </div>`;
    modal.innerHTML = `
      <div class="ld-box ld-warning ${isDangerous ? 'ld-danger' : 'ld-suspicious'}">
        <div class="ld-icon">${isDangerous ? '🚨' : '⚠️'}</div>
        <div class="ld-title">${isDangerous ? 'Dangerous link blocked' : 'Suspicious link'}</div>
        <div class="ld-url">${escapeHtml(result.url)}</div>
        <ul class="ld-reasons">
          ${result.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
        </ul>
        <div class="ld-sources">Checked against: ${result.sources.join(', ')}</div>
        ${riskExplanationHtml(result)}
        ${buttonsHtml}
      </div>`;
    document.documentElement.appendChild(modal);
    overlay = modal;

    modal.querySelector('.ld-cancel').addEventListener('click', () => removeOverlay());
    const proceedBtn = modal.querySelector('.ld-proceed');
    if (proceedBtn) {
      proceedBtn.addEventListener('click', () => {
        removeOverlay();
        proceedCallback();
      });
    }
    wireWhyButton(modal, result);
  }

  // Shows the result of a manual right-click "Scan this link" 
  function showResultToast(result) {
    if (result.riskLevel === 'safe') {
      showSafeCelebration(null);
      return;
    }
    removeOverlay();
    const modal = document.createElement('div');
    modal.id = 'link-defender-overlay';
    const level = result.riskLevel;
    const icon = level === 'dangerous' ? '🚨' : '⚠️';
    const title = level === 'dangerous' ? 'Dangerous link' : 'Suspicious link';
    modal.innerHTML = `
      <div class="ld-box ld-warning ${level === 'dangerous' ? 'ld-danger' : 'ld-suspicious'}">
        <div class="ld-icon">${icon}</div>
        <div class="ld-title">${title}</div>
        <div class="ld-url">${escapeHtml(result.url)}</div>
        <ul class="ld-reasons">${(result.reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>
        <div class="ld-sources">Checked against: ${(result.sources || []).join(', ') || 'n/a'}</div>
        ${riskExplanationHtml(result)}
        <div class="ld-buttons"><button class="ld-btn ld-cancel" style="flex:1;">Close</button></div>
      </div>`;
    document.documentElement.appendChild(modal);
    overlay = modal;
    modal.querySelector('.ld-cancel').addEventListener('click', () => removeOverlay());
    wireWhyButton(modal, result);
  }

  function showRetroactiveBanner(result) {
    removeOverlay();
    const modal = document.createElement('div');
    modal.id = 'link-defender-overlay';
    const isDangerous = result.riskLevel === 'dangerous';
    const buttonsHtml = isDangerous
      ? `<div class="ld-buttons"><button class="ld-btn ld-cancel" style="flex:1;">⬅️ Go back now</button></div>`
      : `<div class="ld-buttons">
           <button class="ld-btn ld-cancel">⬅️ Go back</button>
           <button class="ld-btn ld-proceed">Stay on this page</button>
         </div>`;
    modal.innerHTML = `
      <div class="ld-box ld-warning ${isDangerous ? 'ld-danger' : 'ld-suspicious'}">
        <div class="ld-icon">${isDangerous ? '🚨' : '⚠️'}</div>
        <div class="ld-title">${isDangerous ? 'Dangerous page detected' : 'Suspicious page detected'}</div>
        <div class="ld-url">${escapeHtml(result.url)}</div>
        <ul class="ld-reasons">
          ${(result.reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}
        </ul>
        <div class="ld-sources">Checked against: ${(result.sources || []).join(', ') || 'n/a'}</div>
        ${riskExplanationHtml(result)}
        ${buttonsHtml}
      </div>`;
    document.documentElement.appendChild(modal);
    overlay = modal;

    modal.querySelector('.ld-cancel').addEventListener('click', () => {
      removeOverlay();
      history.back();
    });
    const stayBtn = modal.querySelector('.ld-proceed');
    if (stayBtn) {
      stayBtn.addEventListener('click', () => removeOverlay());
    }
    wireWhyButton(modal, result);
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'SHOW_SCAN_RESULT') {
      showResultToast(message.result);
    }
    if (message.type === 'SHOW_RETROACTIVE_WARNING') {
      showRetroactiveBanner(message.result);
    }
  });

  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function scanUrl(url) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: 'SCAN_URL', url, sourcePageUrl: window.location.href },
        (response) => resolve(response || { riskLevel: 'safe', reasons: [], sources: [] })
      );
    });
  }

  document.addEventListener('click', async (e) => {
    // Power switch off — do absolutely nothing, page behaves as if we're not installed.
    if (!extensionEnabled) return;

    const link = e.target.closest('a[href]');
    if (!link) return;

    const url = link.href;
    if (!url || url.startsWith('javascript:') || url.startsWith('#') || url.startsWith('mailto:')) return;

    if (isSameOrigin(url)) return;

    
    e.preventDefault();
    e.stopPropagation();

    showOverlay('🔍 Checking link safety…');
    const result = await scanUrl(url);

    if (result.riskLevel === 'safe') {
      showSafeCelebration(() => navigateTo(link, url));
    } else {
      showWarning(result, () => navigateTo(link, url));
    }
  }, true); 

  function navigateTo(link, url) {
    if (link.target === '_blank') {
      window.open(url, '_blank');
    } else {
      window.location.href = url;
    }
  }

  // ---------- Scan URLs typed/pasted into search boxes ----------

  const urlLikePattern = /^(https?:\/\/)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(:\d+)?([/?#]\S*)?$/i;

  function isLikelyUrl(text) {
    const t = text.trim();
    if (!t || /\s/.test(t)) return false;
    return urlLikePattern.test(t);
  }

  function normalizeForScan(text) {
    const t = text.trim();
    return /^https?:\/\//i.test(t) ? t : `https://${t}`;
  }

  let ldBypassSubmit = false; 

  async function interceptIfUrl(e, rawValue, onAllow) {
    if (!extensionEnabled) return false;
    if (!isLikelyUrl(rawValue)) return false;

    const url = normalizeForScan(rawValue);
    if (isSameOrigin(url)) return false; 

    e.preventDefault();
    e.stopPropagation();
    showOverlay('🔍 Checking link safety…');
    const result = await scanUrl(url);

    if (result.riskLevel === 'safe') {
      showSafeCelebration(onAllow);
    } else {
      showWarning(result, onAllow);
    }
    return true;
  }

  document.addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter' || ldBypassSubmit) return;
    const el = e.target;
    const isTextField = el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') &&
      (el.type === 'text' || el.type === 'search' || el.tagName === 'TEXTAREA');
    if (!isTextField) return;

    const value = el.value;
    const form = el.form;

    await interceptIfUrl(e, value, () => {
      if (form) {
        ldBypassSubmit = true;
        (form.requestSubmit ? form.requestSubmit() : form.submit());
        ldBypassSubmit = false;
      } else {
        el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
      }
    });
  }, true);

  document.addEventListener('submit', async (e) => {
    if (ldBypassSubmit) return;
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    const field = form.querySelector('input[type="text"], input[type="search"], input:not([type])');
    if (!field || !field.value) return;

    await interceptIfUrl(e, field.value, () => {
      ldBypassSubmit = true;
      (form.requestSubmit ? form.requestSubmit() : form.submit());
      ldBypassSubmit = false;
    });
  }, true);

  console.log('🛡️ Link Defender content script loaded (origin-aware, click-to-scan mode)');
})();
