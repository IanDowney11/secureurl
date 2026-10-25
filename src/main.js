import './style.css';
import { Vault, hasVault, MIN_PIN_LENGTH } from './vault.js';

const app = document.getElementById('app');
const IDLE_MS = 2 * 60 * 1000;
const FAIL_KEY = 'secureurl.fails';

let vault = null;
let idleTimer = null;
let toastTimer = null;

const esc = (s) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const $ = (sel) => app.querySelector(sel);

function toast(msg) {
  let t = document.getElementById('toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'toast';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1800);
}

async function copy(text, msg = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
    toast(msg);
  } catch {
    toast('Copy failed');
  }
}

// ---- failed-attempt throttling -------------------------------------------
function failState() {
  try {
    return JSON.parse(localStorage.getItem(FAIL_KEY)) || { n: 0, until: 0 };
  } catch {
    return { n: 0, until: 0 };
  }
}
function recordFail() {
  const s = failState();
  s.n += 1;
  s.until = s.n >= 3 ? Date.now() + Math.min(2 ** (s.n - 3), 600) * 1000 : 0;
  localStorage.setItem(FAIL_KEY, JSON.stringify(s));
  return s;
}
const clearFails = () => localStorage.removeItem(FAIL_KEY);

// ---- auto lock ------------------------------------------------------------
function lock() {
  vault = null;
  clearTimeout(idleTimer);
  render();
}
function bumpIdle() {
  if (!vault) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lock, IDLE_MS);
}
['pointerdown', 'keydown', 'scroll'].forEach((ev) => addEventListener(ev, bumpIdle, { passive: true }));
document.addEventListener('visibilitychange', () => {
  if (document.hidden && vault) lock();
});

// ---- views ----------------------------------------------------------------
function render() {
  if (vault) return renderList();
  return hasVault() ? renderLock() : renderSetup();
}

function shell(inner) {
  app.innerHTML = `<main class="card">${inner}</main>`;
}

function renderSetup() {
  shell(`
    <div class="logo">🔐</div>
    <h1>SecureURL</h1>
    <p class="muted">Choose a PIN. It encrypts everything on this device — there is no way to recover it, so keep a backup.</p>
    <form id="f" autocomplete="off">
      <input id="p1" type="password" inputmode="numeric" placeholder="New PIN (${MIN_PIN_LENGTH}+ digits)" autocomplete="new-password" />
      <input id="p2" type="password" inputmode="numeric" placeholder="Confirm PIN" autocomplete="new-password" />
      <button class="primary" type="submit">Create vault</button>
      <p class="error" id="err"></p>
    </form>
    <button class="link" id="restore">Restore from Nostr</button>
  `);
  $('#f').onsubmit = async (e) => {
    e.preventDefault();
    const p1 = $('#p1').value;
    const p2 = $('#p2').value;
    if (!/^\d+$/.test(p1) || p1.length < MIN_PIN_LENGTH) return ($('#err').textContent = `PIN must be at least ${MIN_PIN_LENGTH} digits.`);
    if (p1 !== p2) return ($('#err').textContent = 'PINs do not match.');
    $('#err').textContent = 'Creating…';
    vault = await Vault.create(p1);
    bumpIdle();
    renderNsec(true);
  };
  $('#restore').onclick = renderRestore;
}

function renderLock() {
  shell(`
    <div class="logo">🔒</div>
    <h1>SecureURL</h1>
    <form id="f" autocomplete="off">
      <input id="pin" type="password" inputmode="numeric" placeholder="Enter PIN" autocomplete="current-password" autofocus />
      <button class="primary" type="submit">Unlock</button>
      <p class="error" id="err"></p>
    </form>
    <button class="link" id="restore">Restore from Nostr</button>
  `);
  $('#f').onsubmit = async (e) => {
    e.preventDefault();
    const wait = failState().until - Date.now();
    if (wait > 0) return ($('#err').textContent = `Too many attempts. Wait ${Math.ceil(wait / 1000)}s.`);
    $('#err').textContent = 'Unlocking…';
    try {
      vault = await Vault.unlock($('#pin').value);
      clearFails();
      bumpIdle();
      render();
    } catch {
      const s = recordFail();
      $('#err').textContent = s.until ? 'Wrong PIN. Please wait before retrying.' : 'Wrong PIN.';
      $('#pin').value = '';
    }
  };
  $('#restore').onclick = renderRestore;
}

function renderRestore() {
  const replacing = hasVault() || vault;
  shell(`
    <h1>Restore from Nostr</h1>
    <p class="muted">Enter your nsec and the PIN you used. The latest encrypted backup is fetched from Nostr relays.${
      replacing ? ' <strong>This replaces the data on this device.</strong>' : ''
    }</p>
    <form id="f" autocomplete="off">
      <input id="nsec" type="password" placeholder="nsec1…" autocomplete="off" autocapitalize="off" spellcheck="false" />
      <input id="pin" type="password" inputmode="numeric" placeholder="PIN" autocomplete="off" />
      <button class="primary" type="submit">Restore</button>
      <p class="error" id="err"></p>
    </form>
    <button class="link" id="back">Cancel</button>
  `);
  $('#back').onclick = render;
  $('#f').onsubmit = async (e) => {
    e.preventDefault();
    $('#err').textContent = 'Contacting relays…';
    try {
      vault = await Vault.restoreFromNostr($('#nsec').value, $('#pin').value);
      clearFails();
      bumpIdle();
      render();
      toast(`Restored ${vault.items.length} URL${vault.items.length === 1 ? '' : 's'}`);
    } catch (err) {
      $('#err').textContent = ['Invalid nsec', 'No backup found for this nsec'].includes(err.message)
        ? err.message
        : 'Wrong PIN, or relays unreachable.';
    }
  };
}

function renderNsec(firstRun = false) {
  shell(`
    <h1>Your nsec</h1>
    <p class="muted">${
      firstRun ? 'Save this now. ' : ''
    }Your nsec plus your PIN is all you need to restore your URLs from a Nostr backup. Anyone with the nsec <em>and</em> PIN can read them.</p>
    <textarea id="nsec" rows="3" readonly>${esc(vault.nsec)}</textarea>
    <button class="primary" id="copy">Copy nsec</button>
    <button class="link" id="done">${firstRun ? "I've saved it — continue" : 'Back'}</button>
  `);
  $('#copy').onclick = () => copy(vault.nsec, 'nsec copied');
  $('#done').onclick = () => (firstRun ? render() : renderBackup());
}

function renderList(filter = '') {
  const q = filter.trim().toLowerCase();
  const items = vault.items.filter((i) => !q || i.url.toLowerCase().includes(q) || (i.note || '').toLowerCase().includes(q));
  app.innerHTML = `
    <main class="wrap">
      <header>
        <h1>SecureURL</h1>
        <div class="row">
          <button class="ghost" id="settings">Backup</button>
          <button class="ghost" id="lock">Lock</button>
        </div>
      </header>
      <form id="add" class="card">
        <textarea id="urls" rows="2" placeholder="Paste one or more URLs…"></textarea>
        <button class="ghost wide" type="button" id="paste">Paste from clipboard</button>
        <input id="note" placeholder="Note (optional)" />
        <button class="primary" type="submit">Save</button>
      </form>
      <input id="search" class="search" type="search" placeholder="Search ${vault.items.length} saved" value="${esc(filter)}" />
      <ul class="list">
        ${
          items.length
            ? items
                .map(
                  (i) => `<li>
            <a href="${esc(i.url)}" target="_blank" rel="noopener noreferrer">${esc(i.url)}</a>
            ${i.note ? `<div class="note">${esc(i.note)}</div>` : ''}
            <div class="meta">${new Date(i.added).toLocaleDateString()}
              <button class="mini danger" data-del="${i.id}">Delete</button>
            </div>
          </li>`
                )
                .join('')
            : `<li class="empty">${vault.items.length ? 'No matches.' : 'Nothing saved yet.'}</li>`
        }
      </ul>
    </main>`;

  $('#lock').onclick = lock;
  $('#settings').onclick = renderBackup;
  $('#search').oninput = (e) => {
    renderList(e.target.value);
    const s = $('#search');
    s.focus();
    s.setSelectionRange(s.value.length, s.value.length);
  };
  // URLs are never copied out; once pasted in, the clipboard is wiped.
  const wipeClipboard = () => navigator.clipboard?.writeText('').catch(() => {});
  $('#urls').addEventListener('paste', () => setTimeout(wipeClipboard, 0));
  $('#paste').onclick = async () => {
    try {
      const text = await navigator.clipboard.readText();
      $('#urls').value += ($('#urls').value ? '\n' : '') + text;
      await navigator.clipboard.writeText('');
      toast('Pasted — clipboard cleared');
    } catch {
      toast('Clipboard unavailable — paste into the box instead');
    }
  };
  $('#add').onsubmit = (e) => {
    e.preventDefault();
    const found = $('#urls').value.split(/\s+/).filter(Boolean);
    const note = $('#note').value.trim();
    let added = 0;
    for (const raw of found) {
      let url;
      try {
        const u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : `https://${raw}`);
        if (!/^https?:$/.test(u.protocol)) continue;
        url = u.href;
      } catch {
        continue;
      }
      if (vault.items.some((i) => i.url === url)) continue;
      vault.items.unshift({ id: crypto.randomUUID(), url, note, added: Date.now() });
      added++;
    }
    if (!added) return toast('No new valid URLs found');
    vault.save();
    renderList(filter);
    toast(`Saved ${added}`);
  };
  app.querySelectorAll('[data-del]').forEach(
    (b) =>
      (b.onclick = () => {
        vault.items = vault.items.filter((i) => i.id !== b.dataset.del);
        vault.save();
        renderList(filter);
      })
  );
}

function renderBackup() {
  shell(`
    <h1>Backup</h1>
    <p class="muted">Publishes your URLs to Nostr relays as one encrypted message, locked with both your nsec and your PIN. To restore anywhere you only need the nsec and PIN. Relays see only your public key and ciphertext.</p>
    <button class="primary" id="push">Back up to Nostr now</button>
    <p class="muted" id="status"></p>
    <button class="ghost wide" id="nsecBtn">Show my nsec</button>
    <button class="ghost wide" id="restore">Restore from Nostr…</button>
    <button class="link" id="back">Back</button>
  `);
  $('#push').onclick = async (e) => {
    e.target.disabled = true;
    $('#status').textContent = 'Publishing…';
    try {
      const { ok, total } = await vault.backupToNostr();
      $('#status').textContent = ok ? `Backed up to ${ok} of ${total} relays.` : 'No relay accepted the backup. Check your connection and retry.';
    } catch {
      $('#status').textContent = 'Backup failed. Check your connection and retry.';
    }
    e.target.disabled = false;
  };
  $('#nsecBtn').onclick = () => renderNsec(false);
  $('#restore').onclick = renderRestore;
  $('#back').onclick = render;
}

render();

if ('serviceWorker' in navigator && import.meta.env.PROD) {
  addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));
}
