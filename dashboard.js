let allHistory = [];

document.addEventListener('DOMContentLoaded', async () => {
  await loadHistory();
  render();

  document.getElementById('riskFilter').addEventListener('change', render);
  document.getElementById('searchInput').addEventListener('input', render);
  document.getElementById('csvBtn').addEventListener('click', downloadCsv);
  document.getElementById('clearBtn').addEventListener('click', clearHistory);
});

function send(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
}

async function loadHistory() {
  const { history } = await send({ type: 'GET_HISTORY' });
  allHistory = history || [];
}

function getFiltered() {
  const riskFilter = document.getElementById('riskFilter').value;
  const term = document.getElementById('searchInput').value.toLowerCase();

  return allHistory.filter(h => {
    if (riskFilter !== 'all' && h.riskLevel !== riskFilter) return false;
    if (term && !h.url.toLowerCase().includes(term) && !(h.sourcePageUrl || '').toLowerCase().includes(term)) return false;
    return true;
  });
}

function render() {
  const total = allHistory.length;
  const safe = allHistory.filter(h => h.riskLevel === 'safe').length;
  const warn = allHistory.filter(h => h.riskLevel === 'suspicious').length;
  const danger = allHistory.filter(h => h.riskLevel === 'dangerous').length;
  document.getElementById('totalCount').textContent = total;
  document.getElementById('safeCount').textContent = safe;
  document.getElementById('warnCount').textContent = warn;
  document.getElementById('dangerCount').textContent = danger;

  const filtered = getFiltered();
  const tbody = document.getElementById('tableBody');

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="empty">No scans match this view yet.</div></td></tr>`;
    document.getElementById('countNote').textContent = '';
    return;
  }

  tbody.innerHTML = filtered.map(h => `
    <tr>
      <td><span class="badge ${h.riskLevel}">${h.riskLevel}</span></td>
      <td>${h.riskLevel === 'safe' ? '—' : (h.riskScore ?? '—')}</td>
      <td class="url-cell">${escapeHtml(h.url)}</td>
      <td class="url-cell">${escapeHtml(h.sourcePageUrl || '—')}</td>
      <td>${escapeHtml((h.sources || []).join(', ') || '—')}</td>
      <td>${h.riskLevel === 'safe' ? '—' : (h.hasAiExplanation ? 'Yes' : 'No')}</td>
      <td>${new Date(h.timestamp).toLocaleString()}</td>
    </tr>
  `).join('');

  document.getElementById('countNote').textContent = `Showing ${filtered.length} of ${total} scans`;
}

function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}


function downloadCsv() {
  const rows = getFiltered();
  const headers = ['URL', 'Risk Level', 'Risk Score', 'Found On', 'Sources', 'AI Explanation Available', 'Reasons', 'Timestamp'];
  const csvRows = rows.map(h => [
    h.url,
    h.riskLevel,
    h.riskLevel === 'safe' ? '' : (h.riskScore ?? ''),
    h.sourcePageUrl || '',
    (h.sources || []).join('; '),
    h.riskLevel === 'safe' ? '' : (h.hasAiExplanation ? 'Yes' : 'No'),
    (h.reasons || []).join('; '),
    new Date(h.timestamp).toLocaleString()
  ]);

  const csv = [headers, ...csvRows]
    .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
    .join('\n');

  const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `link-defender-scans-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

async function clearHistory() {
  if (!confirm('Clear all scan history? This cannot be undone.')) return;
  await send({ type: 'CLEAR_HISTORY' });
  await loadHistory();
  render();
}
