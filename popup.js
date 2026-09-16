document.addEventListener('DOMContentLoaded', async () => {

  // Initialize buttons FIRST
  initButtons();

  // Initialize other features
  try {
    await refreshAll();
  } catch (error) {
    console.error('Failed to refresh data:', error);
  }

  try {
    await initPowerToggle();
  } catch (error) {
    console.error('Failed to initialize power toggle:', error);
  }

  try {
    initManualScan();
  } catch (error) {
    console.error('Failed to initialize manual scan:', error);
  }

});


/* =========================================================
   BUTTONS
========================================================= */

function initButtons() {

  // Settings
  const settingsBtn = document.getElementById('settingsBtn');

  if (settingsBtn) {
    settingsBtn.addEventListener('click', () => {

      try {
        chrome.runtime.openOptionsPage();
      } catch (error) {
        console.error('Unable to open settings:', error);
      }

    });
  }


  // Dashboard
  const dashboardBtn = document.getElementById('dashboardBtn');

  if (dashboardBtn) {
    dashboardBtn.addEventListener('click', () => {

      try {

        chrome.tabs.create({
          url: chrome.runtime.getURL('dashboard.html')
        });

      } catch (error) {

        console.error('Unable to open dashboard:', error);

      }

    });
  }


  // Sync
  const syncBtn = document.getElementById('syncBtn');

  if (syncBtn) {

    syncBtn.addEventListener('click', async () => {

      const status = document.getElementById('phishtankStatus');

      syncBtn.disabled = true;
      syncBtn.textContent = 'Syncing…';

      if (status) {
        status.textContent = 'Syncing…';
      }

      try {

        await send({
          type: 'FORCE_PHISHTANK_SYNC'
        });

        await refreshPhishTankStatus();

      } catch (error) {

        console.error('PhishTank sync failed:', error);

        if (status) {
          status.textContent = 'Sync failed';
        }

      }

      syncBtn.disabled = false;
      syncBtn.textContent = 'Sync now';

    });

  }

}


/* =========================================================
   SEND MESSAGE
========================================================= */

function send(msg) {

  return new Promise((resolve, reject) => {

    chrome.runtime.sendMessage(msg, (response) => {

      if (chrome.runtime.lastError) {

        console.error(
          'Runtime message error:',
          chrome.runtime.lastError.message
        );

        reject(chrome.runtime.lastError);

        return;
      }

      resolve(response);

    });

  });

}


/* =========================================================
   POWER TOGGLE
========================================================= */

async function initPowerToggle() {

  const result =
    await chrome.storage.local.get('extensionEnabled');

  const enabled =
    result.extensionEnabled !== false;

  const toggle =
    document.getElementById('powerToggle');

  if (!toggle) return;

  toggle.checked = enabled;

  updateStatusText(enabled);

  toggle.addEventListener('change', async () => {

    const state = toggle.checked;

    await chrome.storage.local.set({
      extensionEnabled: state
    });

    updateStatusText(state);

  });

}


/* =========================================================
   STATUS TEXT
========================================================= */

function updateStatusText(enabled) {

  const statusText =
    document.getElementById('statusText');

  if (!statusText) return;

  statusText.textContent = enabled
    ? 'Click-to-scan phishing protection'
    : 'Protection is OFF';

}


/* =========================================================
   MANUAL SCAN
========================================================= */

function initManualScan() {

  const input =
    document.getElementById('manualUrlInput');

  const btn =
    document.getElementById('manualScanBtn');

  const resultBox =
    document.getElementById('manualScanResult');

  if (!input || !btn || !resultBox) return;


  async function runScan() {

    let value = input.value.trim();

    if (!value) return;


    // Add https:// if user doesn't provide protocol
    if (!/^https?:\/\//i.test(value)) {
      value = `https://${value}`;
    }


    btn.disabled = true;
    btn.textContent = '…';


    resultBox.className =
      'manual-scan-result';

    resultBox.style.display =
      'none';


    try {

      const result = await send({
        type: 'SCAN_URL',
        url: value,
        sourcePageUrl: 'manual-scan'
      });


      const riskLevel =
        result?.riskLevel || 'safe';


      const icon =
        riskLevel === 'dangerous'
          ? '🔴'
          : riskLevel === 'suspicious'
            ? '🟡'
            : '🟢';


      resultBox.className =
        `manual-scan-result ${riskLevel}`;


      resultBox.style.display =
        'block';


      const reasons =
        result?.reasons || [];

      const scoreHtml =
        riskLevel !== 'safe' && typeof result?.riskScore === 'number'
          ? ` <span style="opacity:.7;">(Risk Score: ${result.riskScore}/100)</span>`
          : '';

      resultBox.innerHTML =
        `${icon} <b>${riskLevel.toUpperCase()}</b>${scoreHtml} — ${
          reasons.join('; ') || 'No issues detected.'
        }`;


      await refreshHistory();

    } catch (error) {

      console.error(
        'Manual scan failed:',
        error
      );


      resultBox.className =
        'manual-scan-result suspicious';

      resultBox.style.display =
        'block';

      resultBox.textContent =
        '⚠ Unable to scan this URL.';

    }


    btn.disabled = false;
    btn.textContent = 'Scan';

  }


  // Scan button
  btn.addEventListener(
    'click',
    runScan
  );


  // Press Enter
  input.addEventListener(
    'keydown',
    (event) => {

      if (event.key === 'Enter') {
        runScan();
      }

    }
  );

}


/* =========================================================
   REFRESH EVERYTHING
========================================================= */

async function refreshAll() {

  await refreshHistory();

  await refreshPhishTankStatus();

}


/* =========================================================
   PHISHTANK STATUS
========================================================= */

async function refreshPhishTankStatus() {

  const status =
    await send({
      type: 'GET_PHISHTANK_STATUS'
    });


  const element =
    document.getElementById(
      'phishtankStatus'
    );


  if (!element) return;


  if (status && status.phishtankLastSync) {

    const mins =
      Math.round(
        (Date.now() - status.phishtankLastSync)
        / 60000
      );


    element.textContent =
      `PhishTank DB: ${
        status.phishtankCount || 0
      } entries (synced ${mins}m ago)`;

  } else {

    element.textContent =
      'PhishTank DB: not yet synced';

  }

}


/* =========================================================
   HISTORY / STATS
========================================================= */

async function refreshHistory() {

  const response =
    await send({
      type: 'GET_HISTORY'
    });


  const history =
    response?.history || [];


  /* ---------- Statistics ---------- */

  const safe =
    history.filter(
      h => h.riskLevel === 'safe'
    ).length;


  const warn =
    history.filter(
      h => h.riskLevel === 'suspicious'
    ).length;


  const danger =
    history.filter(
      h => h.riskLevel === 'dangerous'
    ).length;


  const safeCount =
    document.getElementById('safeCount');

  const warnCount =
    document.getElementById('warnCount');

  const dangerCount =
    document.getElementById('dangerCount');


  if (safeCount) {
    safeCount.textContent = safe;
  }


  if (warnCount) {
    warnCount.textContent = warn;
  }


  if (dangerCount) {
    dangerCount.textContent = danger;
  }


  /* ---------- History List ---------- */

  const list =
    document.getElementById('list');


  if (!list) return;


  if (history.length === 0) {

    list.innerHTML = `
      <div class="empty">
        No links scanned yet.<br>
        Click any link on a page to scan it.
      </div>
    `;

    return;
  }


  list.innerHTML =
    history
      .slice(0, 10)
      .map(h => {

        const level =
          h.riskLevel || 'safe';


        const timestamp =
          h.timestamp
            ? new Date(
                h.timestamp
              ).toLocaleTimeString()
            : 'Unknown time';


        const sources =
          Array.isArray(h.sources)
            ? h.sources.join(', ')
            : 'n/a';


        const scoreHtml =
          level !== 'safe' && typeof h.riskScore === 'number'
            ? `<div class="item-score">${h.riskScore}/100</div>`
            : '';


        return `
          <div class="item ${level}">

            <div class="item-icon">
              ${icon(level)}
            </div>

            <div class="item-content">

              <div class="u">
                ${escapeHtml(
                  truncate(h.url || '', 45)
                )}
              </div>

              <div class="t">
                ${timestamp} · ${sources}
              </div>

            </div>

            ${scoreHtml}

            <div class="item-status">
              ${level.toUpperCase()}
            </div>

          </div>
        `;

      })
      .join('');

}


/* =========================================================
   ICON
========================================================= */

function icon(level) {

  if (level === 'dangerous') {
    return '🔴';
  }

  if (level === 'suspicious') {
    return '🟡';
  }

  return '🟢';

}


/* =========================================================
   TRUNCATE
========================================================= */

function truncate(str, n) {

  if (!str) return '';

  return str.length > n
    ? str.slice(0, n) + '…'
    : str;

}


/* =========================================================
   BASIC HTML ESCAPE
========================================================= */

function escapeHtml(value) {

  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

}