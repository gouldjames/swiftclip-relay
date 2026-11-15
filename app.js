// SwiftClip Relay: shows what SwiftClip sent to OneDrive and sends text back.
// Everything is decrypted and encrypted here in the browser; OneDrive only
// stores ciphertext. Message text is only ever inserted with textContent.
import * as auth from './auth.js?v=c01974a';
import { GraphError, SignInRequired, download, list, remove, upload } from './graph.js?v=c01974a';
import { FocusDeferral, afterSend, problemText, readItem, sessionEnded } from './page-logic.js?v=c01974a';
import {
  FOLDERS, IMAGE_TYPES, MAX_ATTACHMENT_BYTES, MAX_IMAGE_BYTES, MAX_TEXT_BYTES, deriveKeys,
  makeFileName, parseFileName, parseKey, safeFileName, seal,
} from './relay-crypto.js?v=c01974a';

const KEY_STORAGE = 'swiftclip.relayKey';
const NOTIFY_STORAGE = 'swiftclip.notify';
const NOTIFY_DURATION = 5000;
const SEND_LIFETIME = 5 * 60 * 1000;
const POLL_VISIBLE = 3000;
const POLL_HIDDEN = 20000;
const SWEEP_INTERVAL = 60000;

const $ = (id) => document.getElementById(id);
const views = ['setup', 'signed-out', 'key-entry', 'relay'];

let keys = null;
/** name → { file, expiresAt, message?, problem?, view?, imageURL? } */
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

/** Stops polling and drops what was shown, keeping the stored key. */
function stopRelay() {
  keys = null;
  clearTimeout(pollTimer);
  clearItems();
  primed = false;
}

function forgetKey() {
  localStorage.removeItem(KEY_STORAGE);
  sessionStorage.removeItem(KEY_STORAGE);
  stopRelay();
}

function deleteEntry(name) {
  const entry = items.get(name);
  if (!entry) return;
  if (entry.imageURL) URL.revokeObjectURL(entry.imageURL);
  items.delete(name);
}

function clearItems() {
  for (const name of [...items.keys()]) deleteEntry(name);
  revealed.clear();
}

/** Errors that stop a whole poll pass, rather than only the file being read. */
const isFatalReadError = (error) => error instanceof SignInRequired
  || (error instanceof GraphError && (error.status === 429 || error.status === 503));

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
  // Change Key or Sign Out may replace or clear the key while this pass waits
  // on OneDrive: then its results belong to the old key and are dropped.
  const pollKeys = keys;
  const current = () => keys === pollKeys;
  try {
    if (now < resumeAt) return;
    const files = await list(FOLDERS.toBrowser);
    if (!current()) return;
    if (sessionEnded(files, auth.signedInAt())) {
      endSession('You were signed out from SwiftClip.');
      return;
    }
    auth.touch();
    const present = new Set();
    const fresh = [];
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
        // A file that can't be read now is skipped, not allowed to stop the
        // pass: it's tried again next poll.
        const entry = await readItem(file, name.expiresAt, pollKeys, { download, isFatal: isFatalReadError });
        if (!current()) return;
        if (entry) fresh.push(entry);
      }
    }
    // Added only once the pass has read everything, so an error that stops it
    // leaves these to be read, and notified, next time.
    for (const entry of fresh) items.set(entry.file.name, entry);
    for (const name of [...items.keys()]) if (!present.has(name)) deleteEntry(name);
    if (primed) notifyArrival(fresh.filter((entry) => entry.message));
    primed = true;
    if (now - lastSweep > SWEEP_INTERVAL) {
      lastSweep = now;
      for (const file of await list(FOLDERS.fromBrowser)) {
        const name = parseFileName(file.name);
        if (name && name.expiresAt <= now) remove(file.id).catch(() => {});
      }
      if (!current()) return;
    }
    lastPoll = Date.now();
    statusError = null;
    render();
  } catch (error) {
    if (current()) handleError(error);
  } finally {
    polling = false;
    if (keys) schedulePoll(document.visibilityState === 'visible' ? POLL_VISIBLE : POLL_HIDDEN);
  }
}

function handleError(error) {
  if (error instanceof SignInRequired) {
    // Polling stops until the next sign-in; the key stays stored.
    stopRelay();
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

/**
 * Brings the list up to date. Each item's elements are built once, and again
 * only when how it shows changes (Show/Hide); otherwise only its countdown is
 * updated, so selection, focus and screen readers aren't disturbed every second.
 */
function render() {
  const list = $('items');
  const now = Date.now();
  const visible = [...items.values()].filter((entry) => entry.expiresAt > now).sort((a, b) => b.expiresAt - a.expiresAt);
  for (const entry of visible) {
    const viewKey = revealed.has(entry.file.name) ? 'revealed' : 'hidden';
    if (!entry.view || entry.view.key !== viewKey) entry.view = { key: viewKey, ...renderItem(entry) };
    const countdown = timeLeft(entry.expiresAt);
    if (entry.view.countdown.textContent !== countdown) entry.view.countdown.textContent = countdown;
  }
  const wanted = visible.map((entry) => entry.view.element);
  const shown = [...list.children];
  if (wanted.length !== shown.length || wanted.some((element, index) => element !== shown[index])) {
    list.replaceChildren(...wanted);
  }
  $('empty').hidden = visible.length > 0;
  if (statusError) {
    $('status').textContent = statusError;
  } else if (lastPoll) {
    const seconds = Math.round((now - lastPoll) / 1000);
    $('status').textContent = seconds < 10 ? 'Up to date' : `Updated ${seconds}s ago`;
  }
}

/** Builds an item's elements: { element, countdown }. */
function renderItem(entry) {
  const li = document.createElement('li');
  li.className = 'item';
  const text = document.createElement('div');
  text.className = 'item-text';
  const meta = document.createElement('div');
  meta.className = 'item-meta';
  const actions = document.createElement('div');
  actions.className = 'item-actions';

  if (entry.message?.file) {
    const { message } = entry;
    const row = document.createElement('div');
    row.className = 'item-file';
    const icon = document.createElement('span');
    icon.className = 'file-icon';
    icon.setAttribute('aria-hidden', 'true');
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = message.file.name;
    row.append(icon, name);
    text.append(row);
    meta.textContent = [formatSize(message.file.bytes.length), message.from ? `from ${message.from}` : null]
      .filter(Boolean).join(' · ');
    actions.append(
      button('Download', () => downloadFile(message.file), true),
      button('Delete', () => deleteItem(entry)),
    );
  } else if (entry.message?.image) {
    const { message } = entry;
    const name = entry.file.name;
    const hidden = message.password && !revealed.has(name);
    if (hidden) {
      text.textContent = 'Hidden image';
    } else {
      const img = document.createElement('img');
      img.className = 'item-image';
      img.alt = `Image from ${message.from || 'SwiftClip'}`;
      img.src = imageURL(entry);
      text.append(img);
    }
    if (message.password) {
      li.classList.add('password');
      actions.append(button(hidden ? 'Show' : 'Hide', () => {
        if (revealed.has(name)) revealed.delete(name); else revealed.add(name);
        render();
      }));
    }
    meta.textContent = [`Image ${message.image.width} × ${message.image.height}`, message.from ? `from ${message.from}` : null]
      .filter(Boolean).join(' · ');
    actions.append(
      button('Copy', () => copyMessage(message), true),
      button('Delete', () => deleteItem(entry)),
    );
  } else if (entry.message) {
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
    meta.textContent = [message.password ? 'Password' : null, message.from ? `from ${message.from}` : null]
      .filter(Boolean).join(' · ');
    actions.append(
      button('Copy', () => copy(message.text, message.password), true),
      button('Delete', () => deleteItem(entry)),
    );
  } else {
    li.classList.add('unreadable');
    text.textContent = problemText(entry.problem);
    actions.append(button('Delete', () => deleteItem(entry)));
  }
  // The countdown changes every second; the rest of the line doesn't.
  const countdown = document.createElement('span');
  if (meta.textContent) meta.append(' · ');
  meta.append(countdown);
  li.append(text, actions, meta);
  return { element: li, countdown };
}

/** Signs out and forgets the key, e.g. when SwiftClip signs out web pages. */
function endSession(message) {
  auth.signOut();
  forgetKey();
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
  const preview = message.file
    ? `${message.file.name} · ${formatSize(message.file.bytes.length)}`
    : message.image
      ? (message.password ? 'Hidden image' : `Image ${message.image.width} × ${message.image.height}`)
      : (message.password ? mask(message.text) : message.text.slice(0, 140));
  const notification = new Notification(title, {
    body: `${preview}\n${message.file ? 'Click to download' : 'Click to copy'}`,
    tag: 'swiftclip-arrival',
    silent: true,
  });
  const timer = setTimeout(() => notification.close(), NOTIFY_DURATION);
  notification.onclick = () => {
    clearTimeout(timer);
    notification.close();
    // Downloads don't need the page to have focus; copying does.
    if (message.file) downloadFile(message.file); else copyWhenFocused(() => copyMessage(message));
  };
}

/** Resolves true once this page has focus, or false after `timeout`. */
function waitForFocus(timeout) {
  if (document.hasFocus()) return Promise.resolve(true);
  return new Promise((resolve) => {
    const finish = () => {
      clearTimeout(timer);
      window.removeEventListener('focus', finish);
      resolve(document.hasFocus());
    };
    const timer = setTimeout(finish, timeout);
    window.addEventListener('focus', finish);
  });
}

const pendingCopy = new FocusDeferral(window, 60000);

/**
 * Copies after a notification click. Browsers only let a focused page write to
 * the clipboard, and the click arrives while the page is still in the
 * background: ask for focus and wait for it. If the system won't bring the
 * window forward (it may only flash it), copy as soon as the person clicks
 * into the page, within a minute.
 */
async function copyWhenFocused(copyIt) {
  window.focus();
  // A later click replaces any copy still waiting from an earlier one.
  pendingCopy.cancel();
  if (await waitForFocus(1500)) {
    copyIt();
    return;
  }
  pendingCopy.schedule(copyIt);
  toast('Click this page to copy it.');
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

/** Saves a received file through the browser's downloads. */
function downloadFile(file) {
  const url = URL.createObjectURL(new Blob([file.bytes], { type: file.type || 'application/octet-stream' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = safeFileName(file.name);
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  toast(`Downloading ${safeFileName(file.name)}`);
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1048576) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

/** Copies a received message: its image, or its text. */
function copyMessage(message) {
  if (message.image) copyImage(message.image); else copy(message.text, message.password);
}

/** A blob: URL for an item's image, made once and revoked when the item goes. */
function imageURL(entry) {
  entry.imageURL ??= URL.createObjectURL(new Blob([entry.message.image.bytes], { type: entry.message.image.type }));
  return entry.imageURL;
}

function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

/** Browsers only put PNG images on the clipboard, so JPEGs are converted first. */
async function copyImage(image) {
  try {
    const png = image.type === 'image/png'
      ? Promise.resolve(new Blob([image.bytes], { type: 'image/png' }))
      : encodeImage(new Blob([image.bytes], { type: image.type }), 'image/png');
    await navigator.clipboard.write([new ClipboardItem({ 'image/png': png })]);
    toast('Image copied');
  } catch {
    toast('Your browser blocked copying the image.');
  }
}

/** Re-encodes an image blob, optionally scaled so its longer side is at most `maxSide`. */
async function encodeImage(blob, type, maxSide = Infinity, quality = 0.85) {
  const bitmap = await createImageBitmap(blob);
  const scale = Math.min(1, maxSide / Math.max(bitmap.width, bitmap.height));
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(bitmap.width * scale));
  canvas.height = Math.max(1, Math.round(bitmap.height * scale));
  const context = canvas.getContext('2d');
  if (type === 'image/jpeg') {
    // JPEG has no transparency: put transparent areas on white, as SwiftClip does.
    context.fillStyle = '#fff';
    context.fillRect(0, 0, canvas.width, canvas.height);
  }
  context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close();
  return new Promise((resolve, reject) => {
    canvas.toBlob((result) => (result ? resolve(result) : reject(new Error('Couldn’t encode the image'))), type, quality);
  });
}

/**
 * A pasted or chosen image, ready to send: PNG or JPEG, at most 4 MB, scaled
 * down and re-encoded if needed. Returns { type, bytes, width, height }.
 */
async function prepareImage(blob) {
  let candidate = blob;
  if (!IMAGE_TYPES.includes(blob.type) || blob.size > MAX_IMAGE_BYTES) {
    candidate = null;
    for (const [type, maxSide] of [['image/png', Infinity], ['image/jpeg', 3000], ['image/jpeg', 2048], ['image/jpeg', 1600], ['image/jpeg', 1200]]) {
      const encoded = await encodeImage(blob, type, maxSide);
      if (encoded.size <= MAX_IMAGE_BYTES) {
        candidate = encoded;
        break;
      }
    }
    if (!candidate) throw new Error('That image is too large to send.');
  }
  const bitmap = await createImageBitmap(candidate);
  const prepared = { type: candidate.type, bytes: new Uint8Array(await candidate.arrayBuffer()), width: bitmap.width, height: bitmap.height };
  bitmap.close();
  return prepared;
}

// MARK: - Sending images

let pendingImage = null;
let pendingFile = null;
/** Bumped by every attach and Remove, so a slow one that finishes late is dropped. */
let attachGeneration = 0;

/** Attaches a chosen, pasted or dropped file: images as images, anything else as a file. */
function attach(file) {
  if (file.type.startsWith('image/')) attachImage(file); else attachFile(file);
}

/** Resolves true if the image is now attached. */
async function attachImage(blob) {
  const generation = ++attachGeneration;
  let prepared;
  try {
    prepared = await prepareImage(blob);
  } catch (error) {
    if (generation === attachGeneration) toast(error.message || 'That image can’t be sent.');
    return false;
  }
  // Something else was attached, or Remove clicked, while it was prepared.
  if (generation !== attachGeneration) return false;
  pendingImage = prepared;
  pendingFile = null;
  $('send-image-preview').src = `data:${pendingImage.type};base64,${bytesToBase64(pendingImage.bytes)}`;
  $('send-image-preview').hidden = false;
  $('send-file-icon').hidden = true;
  $('send-image-info').textContent = `Image ${pendingImage.width} × ${pendingImage.height} · ${formatSize(pendingImage.bytes.length)}`;
  $('send-image').hidden = false;
  return true;
}

async function attachFile(file) {
  const generation = ++attachGeneration;
  if (file.size > MAX_ATTACHMENT_BYTES) {
    toast('Files up to 5 MB can be sent.');
    return;
  }
  let bytes;
  try {
    bytes = new Uint8Array(await file.arrayBuffer());
  } catch {
    if (generation === attachGeneration) toast('That file couldn’t be read.');
    return;
  }
  if (generation !== attachGeneration) return;
  pendingFile = { name: safeFileName(file.name), type: file.type || 'application/octet-stream', bytes };
  pendingImage = null;
  $('send-image-preview').removeAttribute('src');
  $('send-image-preview').hidden = true;
  $('send-file-icon').hidden = false;
  $('send-image-info').textContent = `${pendingFile.name} · ${formatSize(pendingFile.bytes.length)}`;
  $('send-image').hidden = false;
}

function clearImage() {
  attachGeneration += 1;
  pendingImage = null;
  pendingFile = null;
  $('send-image').hidden = true;
  $('send-image-preview').removeAttribute('src');
  $('send-image-file').value = '';
}

async function deleteItem(entry) {
  try {
    await remove(entry.file.id);
    deleteEntry(entry.file.name);
    render();
  } catch (error) {
    handleError(error);
  }
}

/** Set while a send is uploading: one at a time, so nothing goes twice. */
let sending = false;

/** What's in the send box now. */
function composer() {
  return { text: $('send-text').value, image: pendingImage, file: pendingFile, password: $('send-password').checked };
}

async function send(text, password, image = pendingImage, file = pendingFile) {
  if (sending) return;
  if (!image && !file && !text.trim()) return;
  if (!image && !file && new TextEncoder().encode(text).length > MAX_TEXT_BYTES) {
    toast('That’s too long to send.');
    return;
  }
  sending = true;
  const before = composer();
  const sendButtons = [$('send-button'), $('paste-send')];
  for (const control of sendButtons) control.disabled = true;
  try {
    const name = makeFileName(Date.now() + SEND_LIFETIME);
    const message = file
      ? { text: '', password, from: 'Web', sentAt: Date.now(), file }
      : image
        ? { text: '', password, from: 'Web', sentAt: Date.now(), image }
        : { text, password, from: 'Web', sentAt: Date.now() };
    const sealed = await seal(message, keys, name, FOLDERS.fromBrowser);
    await upload(FOLDERS.fromBrowser, name, sealed);
    // Keep anything typed or attached while it uploaded.
    const clear = afterSend({ text, image, file, password }, before, composer());
    if (clear.clearsAttachment) clearImage();
    if (clear.clearsText) $('send-text').value = '';
    if (clear.clearsPassword) $('send-password').checked = false;
    toast(file ? `${file.name} sent to SwiftClip` : image ? 'Image sent to SwiftClip' : 'Sent to SwiftClip');
  } catch (error) {
    handleError(error);
    toast(error instanceof SignInRequired ? 'Sign in again to send.' : 'Couldn’t send. Try again.');
  } finally {
    sending = false;
    for (const control of sendButtons) control.disabled = false;
  }
}

// MARK: - Start

/**
 * Without a key the page doesn't poll, so a "Sign Out Web Pages" sent from
 * SwiftClip is looked for here too: a sign-in kept for 10 days without a kept
 * key must still end. Returns true when the page signed out. A check that can't
 * reach OneDrive is skipped; it's tried again when the page is next shown.
 */
let checkingSession = false;
async function checkSessionEnded() {
  if (checkingSession || !auth.isSignedIn()) return false;
  checkingSession = true;
  try {
    const files = await list(FOLDERS.toBrowser);
    if (!sessionEnded(files, auth.signedInAt())) return false;
    endSession('You were signed out from SwiftClip.');
    return true;
  } catch (error) {
    if (!(error instanceof SignInRequired)) return false;
    stopRelay();
    show('signed-out');
    return true;
  } finally {
    checkingSession = false;
  }
}

async function startRelay() {
  const saved = storedKey();
  if (saved && !keys) {
    const bytes = await parseKey(saved);
    if (bytes) keys = await deriveKeys(bytes); else forgetKey();
  }
  if (!keys) {
    show('key-entry');
    $('key-input').focus();
    checkSessionEnded();
    return;
  }
  show('relay');
  $('notify-option').hidden = !notificationsSupported();
  $('notify').checked = notificationsOn();
  primed = false;
  // Left from before a key change or sign-out: the next poll says how things are.
  statusError = null;
  render();
  poll();
}

function wireEvents() {
  $('sign-in').addEventListener('click', () => auth.signIn({ remember: $('stay-signed-in').checked }));
  $('sign-out').addEventListener('click', () => {
    auth.signOut();
    // Stops polling; the key stays stored for the next sign-in.
    stopRelay();
    show('signed-out');
  });
  $('notify').addEventListener('change', (event) => setNotifications(event.target.checked));
  $('send-text').addEventListener('paste', (event) => {
    const file = event.clipboardData?.files?.[0];
    if (!file) return;
    event.preventDefault();
    attach(file);
  });
  $('send-text').addEventListener('dragover', (event) => {
    if (event.dataTransfer?.types?.includes('Files')) event.preventDefault();
  });
  $('send-text').addEventListener('drop', (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (!file) return;
    event.preventDefault();
    attach(file);
  });
  $('choose-image').addEventListener('click', () => $('send-image-file').click());
  $('send-image-file').addEventListener('change', (event) => {
    const file = event.target.files?.[0];
    if (file) attach(file);
  });
  $('send-image-remove').addEventListener('click', clearImage);
  $('change-key').addEventListener('click', () => {
    forgetKey();
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
    if (sending) return;
    try {
      if (navigator.clipboard.read) {
        for (const item of await navigator.clipboard.read()) {
          const type = item.types.find((t) => t.startsWith('image/'));
          if (type) {
            if (await attachImage(await item.getType(type))) send('', $('send-password').checked);
            return;
          }
        }
      }
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
    if (document.visibilityState !== 'visible') return;
    if (keys) poll(); else if (!$('key-entry').hidden) checkSessionEnded();
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
