document.addEventListener('DOMContentLoaded', async () => {
  const s = await chrome.storage.sync.get([
    'vtApiKey', 'telegramBotToken', 'telegramChatId', 'telegramEnabled', 'geminiApiKey'
  ]);
  document.getElementById('vtApiKey').value = s.vtApiKey || '';
  document.getElementById('tgToken').value = s.telegramBotToken || '';
  document.getElementById('tgChatId').value = s.telegramChatId || '';
  document.getElementById('tgEnabled').checked = s.telegramEnabled !== false;
  document.getElementById('geminiApiKey').value = s.geminiApiKey || '';

  document.getElementById('saveBtn').addEventListener('click', save);
  document.getElementById('testTelegramBtn').addEventListener('click', testTelegram);
  document.getElementById('testGeminiBtn').addEventListener('click', testGemini);
  document.getElementById('clearCacheBtn').addEventListener('click', clearCache);
});

async function save() {
  await chrome.storage.sync.set({
    vtApiKey: document.getElementById('vtApiKey').value.trim(),
    telegramBotToken: document.getElementById('tgToken').value.trim(),
    telegramChatId: document.getElementById('tgChatId').value.trim(),
    telegramEnabled: document.getElementById('tgEnabled').checked,
    geminiApiKey: document.getElementById('geminiApiKey').value.trim()
  });
  const status = document.getElementById('status');
  status.textContent = '✅ Saved';
  setTimeout(() => (status.textContent = ''), 2000);
}


async function testGemini() {
  const key = document.getElementById('geminiApiKey').value.trim();
  const status = document.getElementById('status');

  if (!key) {
    status.textContent = '⚠️ Enter a Gemini API key first';
    status.style.color = '#d97706';
    return;
  }

  status.textContent = '⏳ Testing...';
  status.style.color = '#334155';

  try {
    const resp = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key=${key}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: 'Reply with the single word: OK' }] }] })
      }
    );
    const data = await resp.json();
    if (resp.ok && data?.candidates?.length) {
      status.textContent = '✅ Gemini key works';
      status.style.color = '#16a34a';
    } else {
      status.textContent = `❌ ${data?.error?.message || 'Key test failed'}`;
      status.style.color = '#dc2626';
    }
  } catch (e) {
    status.textContent = `❌ ${e.message}`;
    status.style.color = '#dc2626';
  }
}

async function testTelegram() {
  const token = document.getElementById('tgToken').value.trim();
  const chatId = document.getElementById('tgChatId').value.trim();
  const status = document.getElementById('status');

  if (!token || !chatId) {
    status.textContent = '⚠️ Enter both bot token and chat ID first';
    status.style.color = '#d97706';
    return;
  }

  try {
    const resp = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: '🛡️ Link Defender test message — your Telegram alert setup is working!'
      })
    });
    const data = await resp.json();
    if (data.ok) {
      status.textContent = '✅ Test message sent — check your group';
      status.style.color = '#16a34a';
    } else {
      status.textContent = `❌ ${data.description || 'Failed to send'}`;
      status.style.color = '#dc2626';
    }
  } catch (e) {
    status.textContent = `❌ ${e.message}`;
    status.style.color = '#dc2626';
  }
}

// Clears the persistent URL-level scan cache (chrome.storage.local.urlCache).

function clearCache() {
  chrome.runtime.sendMessage({ type: 'CLEAR_URL_CACHE' }, (res) => {
    const el = document.getElementById('cacheStatus');
    el.textContent = res?.success ? '✅ Cache cleared' : '❌ Failed';
    setTimeout(() => (el.textContent = ''), 2000);
  });
}
