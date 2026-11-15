// Parts of the relay page's logic that don't touch the DOM or the network
// directly, so they can be tested with node --test.
import { FOLDERS, RelayError, open as openRelayFile } from './relay-crypto.js?v=c01974a';

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
