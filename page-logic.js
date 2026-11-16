// Parts of the relay page's logic that don't touch the DOM or the network
// directly, so they can be tested with node --test.
import { FOLDERS, RelayError, open as openRelayFile, revealedCharacters } from './relay-crypto.js?v=ef6b079';

const MASK = '*******';
/** This many characters of a password always stay hidden, as in SecretMasker. */
const MINIMUM_HIDDEN_CHARACTERS = 5;
const WHITESPACE = /^\p{White_Space}/u;
const graphemes = typeof Intl.Segmenter === 'function' ? new Intl.Segmenter(undefined, { granularity: 'grapheme' }) : null;

/** User-perceived characters, as Swift counts them, read lazily so a long secret stays cheap. */
function* characters(text) {
  if (!graphemes) {
    yield* text;
    return;
  }
  for (const { segment } of graphemes.segment(text)) yield segment;
}

/**
 * Masks a password for display exactly as SwiftClip's SecretMasker does: the
 * sender's `reveal` leading characters (clamped to 0…4, 0 when not sent) and a
 * fixed `*******`, so it reads the same on the Mac, the iPhone and here.
 * Leading whitespace is skipped and trailing whitespace doesn't count. All or
 * nothing: a password too short to show every requested character with five
 * still hidden shows none, so the mask never gives away its length.
 */
export function mask(text, reveal = 0) {
  const requested = revealedCharacters(reveal);
  const enough = requested + MINIMUM_HIDDEN_CHARACTERS;
  const shown = [];
  let length = 0;
  let trailingWhitespace = 0;
  for (const character of characters(String(text ?? ''))) {
    const isWhitespace = WHITESPACE.test(character);
    if (isWhitespace && length === 0 && shown.length === 0) continue;
    if (length >= enough) break;
    if (shown.length < requested) shown.push(isWhitespace ? ' ' : character);
    if (isWhitespace) {
      trailingWhitespace += 1;
    } else {
      length += trailingWhitespace + 1;
      trailingWhitespace = 0;
    }
  }
  const visibleCount = length >= enough ? requested : 0;
  return shown.slice(0, visibleCount).join('') + MASK;
}

/** Written by SwiftClip's "Sign Out Web Pages": pages signed in before it sign out. */
const END_WEB_SESSIONS = /^end-web-sessions-(\d{1,16})\.json$/;

/**
 * Whether a ToBrowser listing holds a "Sign Out Web Pages" marker written after
 * this browser signed in (`signedInAt`, in milliseconds), so the page must sign
 * out and forget the key. Checked whether or not a key is entered, so a kept
 * sign-in without a kept key is ended too.
 */
export function sessionEnded(files, signedInAt) {
  const endedAt = Math.max(0, ...files.map((file) => Number(END_WEB_SESSIONS.exec(file?.name ?? '')?.[1] || 0)));
  return endedAt > signedInAt;
}

/**
 * What a "Sign Out Web Pages" marker in a ToBrowser listing means for this page:
 * 'signOut' when it's newer than the sign-in, 'forgetKey' when only the stored
 * key is older than it, otherwise null. A key can outlive the sign-in it was
 * entered with (it's kept when a sign-in lapses, though not through a Sign
 * Out), so a sign-in made after the marker mustn't make an older key usable
 * again. `keySavedAt` is null when no key is stored, and 0 for one stored
 * without a time, which any marker retires.
 */
export function markerAction(files, signedInAt, keySavedAt) {
  if (sessionEnded(files, signedInAt)) return 'signOut';
  if (keySavedAt !== null && sessionEnded(files, keySavedAt)) return 'forgetKey';
  return null;
}

/** Where the relay key is stored, in localStorage when remembered, otherwise sessionStorage. */
export const KEY_STORAGE = 'swiftclip.relayKey';
/** When the key was stored, kept next to it: a later Sign Out Web Pages retires it. */
export const KEY_SAVED_AT = 'swiftclip.relayKeySavedAt';

/**
 * Removes every stored copy of the relay key, and what's stored about it, from
 * each of `storages`: anything named `swiftclip.relayKey…`, so a value kept by
 * an earlier version of the page goes too. Signing out always does this.
 */
export function forgetStoredKey(storages) {
  for (const storage of storages) {
    const names = new Set([KEY_STORAGE, KEY_SAVED_AT]);
    for (let index = 0; index < (storage.length ?? 0); index += 1) {
      const name = storage.key(index);
      if (name?.startsWith(KEY_STORAGE)) names.add(name);
    }
    for (const name of names) storage.removeItem(name);
  }
}

/** Whether the page is shown inside another page's frame, where it could be clickjacked. */
export const isFramed = (window) => window.top !== window.self;

/**
 * Reads one ToBrowser file into an item entry: { file, expiresAt, message? , problem? }.
 *
 * Returns null when the file should be skipped this pass and tried again on the
 * next poll: it vanished between listing and download (another tab or SwiftClip
 * deleted it), or the download failed for a passing reason. Throws only errors
 * `isFatal` accepts (signing in again, OneDrive asking to slow down), which stop
 * the whole poll. A file too large to be a relay item is kept as an entry with a
 * problem, so it isn't downloaded again on every poll.
 */
export async function readItem(file, expiresAt, keys, { download, isFatal, open = openRelayFile }) {
  const entry = { file, expiresAt };
  let text;
  try {
    text = await download(file);
  } catch (error) {
    if (isFatal(error)) throw error;
    if (error?.status === 413) {
      entry.problem = 'tooLarge';
      return entry;
    }
    return null;
  }
  try {
    // open() tells a file sealed with another key ('wrongKey') apart from one
    // that isn't a relay file at all ('malformed').
    entry.message = await open(text, keys, file.name, FOLDERS.toBrowser);
  } catch (error) {
    entry.problem = error instanceof RelayError ? error.code : 'malformed';
  }
  return entry;
}

/**
 * Seconds to wait when OneDrive asks to slow down, from a Retry-After header:
 * whole seconds kept between 5 and 3600, otherwise 30. The same as
 * RelayThrottle.delay in SwiftClip.
 */
export function retryAfterSeconds(header) {
  const text = String(header ?? '').trim();
  if (!/^\d{1,9}$/.test(text)) return 30;
  return Math.min(Math.max(Number(text), 5), 3600);
}

/**
 * A response's text, or null if it's longer than `limit` bytes. Reading stops
 * there: the listed size was checked before downloading, but the file may
 * have been replaced since.
 */
export async function readTextWithin(response, limit) {
  if (Number(response.headers.get('Content-Length')) > limit) {
    await response.body?.cancel().catch(() => {});
    return null;
  }
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(bytes);
}

/** The text shown for an item that can't be shown. */
export function problemText(problem) {
  switch (problem) {
    case 'wrongKey':
      return 'Encrypted with a different key. Choose Change Key and enter the key shown in SwiftClip.';
    case 'tooLarge':
      return 'This item is too large to show here.';
    default:
      return 'This item couldn’t be read.';
  }
}

/**
 * Runs an action the next time `target` gets focus, within `timeout` ms. Only
 * the most recent action is kept: scheduling another cancels the previous
 * one's listener and timer, so an older action can never run or clear a newer one.
 */
export class FocusDeferral {
  constructor(target, timeout = 60000) {
    this.target = target;
    this.timeout = timeout;
    this.pending = null;
  }

  get isPending() {
    return this.pending !== null;
  }

  schedule(action) {
    this.cancel();
    const record = {};
    record.listener = () => {
      if (this.pending !== record) return;
      this.cancel();
      action();
    };
    record.timer = setTimeout(() => {
      if (this.pending === record) this.cancel();
    }, this.timeout);
    this.pending = record;
    this.target.addEventListener('focus', record.listener);
  }

  cancel() {
    const record = this.pending;
    if (!record) return;
    this.pending = null;
    clearTimeout(record.timer);
    this.target.removeEventListener('focus', record.listener);
  }
}

/**
 * Clears a copied password off the clipboard `delay` ms later, as SwiftClip
 * does on the Mac. Browsers only let a focused page (some only one the person
 * is using) write to the clipboard, so `clear` may refuse by returning false:
 * then it's tried again whenever the page gets focus, a click or a key press,
 * for up to `grace` ms. Scheduling again starts over; `cancel` is for a copy
 * that replaced the password.
 */
export class ClipboardExpiry {
  static events = ['focus', 'pointerdown', 'keydown'];

  constructor(target, clear, { delay = 90000, grace = 10 * 60000 } = {}) {
    this.target = target;
    this.clear = clear;
    this.delay = delay;
    this.grace = grace;
    this.pending = null;
  }

  get isPending() {
    return this.pending !== null;
  }

  schedule() {
    this.cancel();
    const record = {};
    record.attempt = async () => {
      if (this.pending !== record) return;
      if (await this.clear() && this.pending === record) this.cancel();
    };
    record.timer = setTimeout(() => {
      if (this.pending !== record) return;
      for (const type of ClipboardExpiry.events) this.target.addEventListener(type, record.attempt);
      record.timer = setTimeout(() => {
        if (this.pending === record) this.cancel();
      }, this.grace);
      record.attempt();
    }, this.delay);
    this.pending = record;
  }

  cancel() {
    const record = this.pending;
    if (!record) return;
    this.pending = null;
    clearTimeout(record.timer);
    for (const type of ClipboardExpiry.events) this.target.removeEventListener(type, record.attempt);
  }
}

/**
 * What to clear once a send finishes. `before` is the composer when the send
 * started and `now` is the composer now: { text, image, file, password }.
 * `sent` is what went out: { text, image, file, password }.
 *
 * Only what was sent is cleared, and only if it's still there: text typed or a
 * file attached while the upload ran is kept. The Password box is reset only if
 * nothing in the composer changed meanwhile.
 */
export function afterSend(sent, before, now) {
  const sentAttachment = Boolean(sent.image || sent.file);
  const clearsAttachment = sentAttachment && (now.image ?? null) === (sent.image ?? null)
    && (now.file ?? null) === (sent.file ?? null);
  const clearsText = !sentAttachment && sent.text === before.text && now.text === sent.text;
  const untouched = now.text === before.text && now.image === before.image && now.file === before.file
    && now.password === before.password;
  return { clearsAttachment, clearsText, clearsPassword: untouched && now.password === sent.password };
}
