// SwiftClip Relay: shows what SwiftClip sent to OneDrive and sends text back.
// Everything is decrypted and encrypted here in the browser; OneDrive only
// stores ciphertext. Message text is only ever inserted with textContent.
import * as auth from './auth.js';
import { GraphError, SignInRequired, download, list, remove, upload } from './graph.js';
import {
  FOLDERS, MAX_TEXT_BYTES, RelayError, deriveKeys, keyIDOf, makeFileName, open, parseFileName, parseKey, seal,
} from './relay-crypto.js';

const KEY_STORAGE = 'swiftclip.relayKey';
const NOTIFY_STORAGE = 'swiftclip.notify';
const NOTIFY_DURATION = 5000;
const SEND_LIFETIME = 5 * 60 * 1000;
/** Written by SwiftClip's "Sign Out Web Pages": pages signed in before it sign out. */
const END_WEB_SESSIONS = /^end-web-sessions-(\d{1,16})\.json$/;
const POLL_VISIBLE = 3000;
const POLL_HIDDEN = 20000;
const SWEEP_INTERVAL = 60000;

const $ = (id) => document.getElementById(id);
const views = ['setup', 'signed-out', 'key-entry', 'relay'];

let keys = null;
/** name → { file, expiresAt, message?, problem? } */
const items = new Map();
const revealed = new Set();
let pollTimer = null;
let lastPoll = 0;
let lastSweep = 0;
let resumeAt = 0;
let polling = false;
let statusError = null;
/** Set after the first listing, so items already waiting don't notify. */
let primed = false;

function show(view) {
  for (const id of views) $(id).hidden = id !== view;
  const signedIn = auth.isSignedIn() && (view === 'relay' || view === 'key-entry');
  $('account').hidden = !signedIn;
  $('change-key').hidden = view !== 'relay';
  $('account-name').textContent = auth.account() || '';
}

let toastTimer = null;
function toast(text) {
  const element = $('message');
  element.textContent = text;
  element.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { element.hidden = true; }, 2600);
}

// MARK: - Key

function storedKey() {
  return localStorage.getItem(KEY_STORAGE) || sessionStorage.getItem(KEY_STORAGE);
}

function forgetKey() {
  localStorage.removeItem(KEY_STORAGE);
  sessionStorage.removeItem(KEY_STORAGE);
  keys = null;
  items.clear();
  primed = false;
}

async function useKey(text, remember) {
  const bytes = await parseKey(text);
  if (!bytes) return false;
  forgetKey();
  (remember ? localStorage : sessionStorage).setItem(KEY_STORAGE, text.trim().toUpperCase());
  keys = await deriveKeys(bytes);
  return true;
}

// MARK: - Polling

function schedulePoll(delay) {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(poll, delay);
}

async function poll() {
  if (polling || !keys) return;
  polling = true;
  const now = Date.now();
  try {
    if (now < resumeAt) return;
    const files = await list(FOLDERS.toBrowser);
    const endedAt = Math.max(0, ...files.map((file) => Number(END_WEB_SESSIONS.exec(file.name)?.[1] || 0)));
    if (endedAt > auth.signedInAt()) {
      endSession('You were signed out from SwiftClip.');
      return;
    }
    auth.touch();
    const present = new Set();
    const arrived = [];
    for (const file of files) {
      const name = parseFileName(file.name);
      if (!name) continue;
      if (name.expiresAt <= now) {
        // Whoever sees an expired item first deletes it.
        remove(file.id).catch(() => {});
        continue;
      }
      present.add(file.name);
      if (!items.has(file.name)) {
        const entry = await readItem(file, name.expiresAt);
        items.set(file.name, entry);
        if (entry.message) arrived.push(entry);
      }
    }
    for (const name of [...items.keys()]) if (!present.has(name)) items.delete(name);
    if (primed) notifyArrival(arrived);
    primed = true;
    if (now - lastSweep > SWEEP_INTERVAL) {
      lastSweep = now;
      for (const file of await list(FOLDERS.fromBrowser)) {
        const name = parseFileName(file.name);
        if (name && name.expiresAt <= now) remove(file.id).catch(() => {});
      }
    }
    lastPoll = Date.now();
    statusError = null;
    render();
  } catch (error) {
    handleError(error);
  } finally {
    polling = false;
    if (keys) schedulePoll(document.visibilityState === 'visible' ? POLL_VISIBLE : POLL_HIDDEN);
  }
}

async function readItem(file, expiresAt) {
  const text = await download(file);
  const entry = { file, expiresAt };
  if (keyIDOf(text) !== keys.keyIDText) {
    entry.problem = 'wrongKey';
    return entry;
  }
  try {
    entry.message = await open(text, keys, file.name);
  } catch (error) {
    entry.problem = error instanceof RelayError ? error.code : 'malformed';
  }
  return entry;
}

function handleError(error) {
  if (error instanceof SignInRequired) {
    show('signed-out');
    return;
  }
  if (error instanceof GraphError && error.retryAfter) resumeAt = Date.now() + error.retryAfter * 1000;
  statusError = error instanceof GraphError ? error.message : 'Can’t reach OneDrive. Retrying…';
  render();
}

// MARK: - Rendering

function mask(text) {
  const characters = [...text];
  const revealedCount = Math.min(3, Math.max(0, characters.length - 5));
  return characters.slice(0, revealedCount).join('') + '*******';
}

function timeLeft(expiresAt) {
  const seconds = Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')} left`;
}

function button(label, onClick, primary = false) {
  const element = document.createElement('button');
  element.type = 'button';
  element.textContent = label;
  if (primary) element.className = 'primary';
  element.addEventListener('click', onClick);
  return element;
}

function render() {
  const list = $('items');
  const now = Date.now();
  const visible = [...items.values()].filter((entry) => entry.expiresAt > now).sort((a, b) => b.expiresAt - a.expiresAt);
  list.replaceChildren(...visible.map(renderItem));
  $('empty').hidden = visible.length > 0;
  if (statusError) {
    $('status').textContent = statusError;
  } else if (lastPoll) {
    const seconds = Math.round((now - lastPoll) / 1000);
    $('status').textContent = seconds < 10 ? 'Up to date' : `Updated ${seconds}s ago`;
  }
}

function renderItem(entry) {
  const li = document.createElement('li');
  li.className = 'item';
  const text = document.createElement('div');
  text.className = 'item-text';
  const meta = document.createElement('div');
  meta.className = 'item-meta';
  const actions = document.createElement('div');
  actions.className = 'item-actions';

  if (entry.message) {
    const { message } = entry;
    const name = entry.file.name;
    if (message.password) {
      li.classList.add('password');
      text.textContent = revealed.has(name) ? message.text : mask(message.text);
      actions.append(button(revealed.has(name) ? 'Hide' : 'Show', () => {
        if (revealed.has(name)) revealed.delete(name); else revealed.add(name);
        render();
      }));
    } else {
      text.textContent = message.text;
    }
    meta.textContent = [message.password ? 'Password' : null, message.from ? `from ${message.from}` : null, timeLeft(entry.expiresAt)]
      .filter(Boolean).join(' · ');
    actions.append(
      button('Copy', () => copy(message.text, message.password), true),
      button('Delete', () => deleteItem(entry)),
    );
  } else {
    li.classList.add('unreadable');
    text.textContent = entry.problem === 'wrongKey'
      ? 'Encrypted with a different key. Choose Change Key and enter the key shown in SwiftClip.'
      : 'This item couldn’t be read.';
    meta.textContent = timeLeft(entry.expiresAt);
    actions.append(button('Delete', () => deleteItem(entry)));
  }
  li.append(text, actions, meta);
  return li;
}

/** Signs out and forgets the key, e.g. when SwiftClip signs out web pages. */
function endSession(message) {
  auth.signOut();
  forgetKey();
  clearTimeout(pollTimer);
  show('signed-out');
  if (message) toast(message);
}

// MARK: - Notifications

const notificationsSupported = () => 'Notification' in window && window.isSecureContext;

/** Notifications are a choice for this browser, kept in localStorage. */
function notificationsOn() {
  return notificationsSupported() && localStorage.getItem(NOTIFY_STORAGE) === 'on' && Notification.permission === 'granted';
}

async function setNotifications(on) {
  if (!on) {
    localStorage.removeItem(NOTIFY_STORAGE);
    return;
  }
  const permission = await Notification.requestPermission();
  if (permission === 'granted') {
    localStorage.setItem(NOTIFY_STORAGE, 'on');
  } else {
    $('notify').checked = false;
    toast('Notifications are blocked for this page. Allow them in your browser’s site settings.');
  }
}

/** Shows the newest arrival for 5 seconds. Clicking it copies the item. */
function notifyArrival(arrived) {
  if (!arrived.length || !notificationsOn()) return;
  const newest = arrived.reduce((a, b) => (b.message.sentAt || 0) > (a.message.sentAt || 0) ? b : a);
  const { message } = newest;
  const from = message.from || 'SwiftClip';
  const title = arrived.length === 1 ? `From ${from}` : `${arrived.length} items from ${from}`;
  const preview = message.password ? mask(message.text) : message.text.slice(0, 140);
  const notification = new Notification(title, {
    body: `${preview}\nClick to copy`,
    tag: 'swiftclip-arrival',
    silent: true,
  });
  const timer = setTimeout(() => notification.close(), NOTIFY_DURATION);
  notification.onclick = () => {
    clearTimeout(timer);
    notification.close();
    window.focus();
    copy(message.text, message.password);
  };
}

// MARK: - Actions

async function copy(text, isPassword) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Older or locked-down browsers: copy through a hidden text field.
    const field = document.createElement('textarea');
    field.value = text;
    field.setAttribute('readonly', '');
    field.style.position = 'fixed';
    field.style.opacity = '0';
    document.body.append(field);
    field.select();
    const copied = document.execCommand('copy');
    field.remove();
    if (!copied) {
      toast('Your browser blocked copying.');
      return;
    }
  }
  toast(isPassword ? 'Password copied' : 'Copied');
}

async function deleteItem(entry) {
  try {
    await remove(entry.file.id);
    items.delete(entry.file.name);
    render();
  } catch (error) {
    handleError(error);
  }
}

async function send(text, password) {
  if (!text.trim()) return;
  if (new TextEncoder().encode(text).length > MAX_TEXT_BYTES) {
    toast('That’s too long to send.');
    return;
  }
  const sendButton = $('send-button');
  sendButton.disabled = true;
  try {
    const name = makeFileName(Date.now() + SEND_LIFETIME);
    const sealed = await seal({ text, password, from: 'Web', sentAt: Date.now() }, keys, name);
    await upload(FOLDERS.fromBrowser, name, sealed);
    $('send-text').value = '';
    $('send-password').checked = false;
    toast('Sent to SwiftClip');
  } catch (error) {
    handleError(error);
    toast(error instanceof SignInRequired ? 'Sign in again to send.' : 'Couldn’t send. Try again.');
  } finally {
    sendButton.disabled = false;
  }
}

// MARK: - Start

async function startRelay() {
  const saved = storedKey();
  if (saved && !keys) {
    const bytes = await parseKey(saved);
    if (bytes) keys = await deriveKeys(bytes); else forgetKey();
  }
  if (!keys) {
    show('key-entry');
    $('key-input').focus();
    return;
  }
  show('relay');
  $('notify-option').hidden = !notificationsSupported();
  $('notify').checked = notificationsOn();
  primed = false;
  render();
  poll();
}

function wireEvents() {
  $('sign-in').addEventListener('click', () => auth.signIn({ remember: $('stay-signed-in').checked }));
  $('sign-out').addEventListener('click', () => {
    auth.signOut();
    clearTimeout(pollTimer);
    items.clear();
    primed = false;
    show('signed-out');
  });
  $('notify').addEventListener('change', (event) => setNotifications(event.target.checked));
  $('change-key').addEventListener('click', () => {
    forgetKey();
    clearTimeout(pollTimer);
    $('key-input').value = '';
    show('key-entry');
    $('key-input').focus();
  });
  $('key-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const ok = await useKey($('key-input').value, $('remember-key').checked);
    $('key-error').hidden = ok;
    if (!ok) {
      $('key-error').textContent = 'That isn’t a valid key. Check for typos.';
      return;
    }
    $('key-input').value = '';
    startRelay();
  });
  $('send-form').addEventListener('submit', (event) => {
    event.preventDefault();
    send($('send-text').value, $('send-password').checked);
  });
  $('send-text').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      send($('send-text').value, $('send-password').checked);
    }
  });
  $('paste-send').addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (!text) {
        toast('The clipboard is empty.');
        return;
      }
      send(text, $('send-password').checked);
    } catch {
      toast('Your browser blocked reading the clipboard. Paste into the box with Ctrl+V.');
    }
  });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && keys) poll();
  });
  // Countdowns.
  setInterval(() => { if (!$('relay').hidden) render(); }, 1000);
}

async function main() {
  wireEvents();
  if (!auth.isConfigured()) {
    show('setup');
    return;
  }
  try {
    await auth.handleRedirect();
  } catch (error) {
    toast(error.message);
  }
  if (!auth.isSignedIn()) {
    show('signed-out');
    return;
  }
  startRelay();
}

main();
