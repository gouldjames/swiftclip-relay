// SwiftClip relay format, matching Packages/SwiftClipKit/Sources/SwiftClipCore/Relay.
// Works in browsers and in Node 20+ (Web Crypto). No dependencies.

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const KEY_BYTES = 14;
const SALT = new TextEncoder().encode('SwiftClip Relay');
export const FILE_EXTENSION = 'screlay';
export const ROOT = 'Apps/SwiftClip';
export const FOLDERS = { toBrowser: 'ToBrowser', fromBrowser: 'FromBrowser' };
// Images and attachments travel base64-encoded twice (in the message, then as
// ciphertext), so relay files may be up to 12 MB for a 5 MB attachment.
export const MAX_FILE_BYTES = 12 * 1024 * 1024;
export const MAX_TEXT_BYTES = 1000000;
export const MAX_IMAGE_BYTES = 4000000;
export const MAX_ATTACHMENT_BYTES = 5000000;

/**
 * A file name that can't leave the folder it's saved in, or disguise its
 * extension: path separators, control and format characters (bidi overrides
 * can show "fdp.exe" as "exe.pdf") and line separators become "_". As in
 * SwiftClip (RelayFile.safeName).
 */
export function safeFileName(name) {
  let cleaned = String(name ?? '').replace(/[\/\\:\p{Cc}\p{Cf}\u2028\u2029]/gu, '_').trim().replace(/^\.+/, '');
  if ([...cleaned].length > 200) {
    const dot = cleaned.lastIndexOf('.');
    // Keep a real extension. A very long one is just part of the name.
    const found = dot > 0 ? cleaned.slice(dot + 1) : '';
    const ext = [...found].length <= 20 ? found : '';
    const stem = [...(ext ? cleaned.slice(0, dot) : cleaned)].slice(0, ext ? 199 - [...ext].length : 200).join('');
    cleaned = ext ? `${stem}.${ext}` : stem;
  }
  return cleaned || 'File';
}
export const IMAGE_TYPES = ['image/png', 'image/jpeg'];

/** The most leading characters of a password SwiftClip shows, as SecretMasker.maximumRevealedCharacters. */
export const MAX_REVEALED_CHARACTERS = 4;

/**
 * A sender's "characters to reveal" setting kept within 0…4. Anything that
 * isn't a whole number, including a missing value, is 0. The same as
 * RelayMessage.clampedReveal in SwiftClip.
 */
export function revealedCharacters(value) {
  return Number.isInteger(value) ? Math.min(Math.max(value, 0), MAX_REVEALED_CHARACTERS) : 0;
}

/** Whether bytes start like a PNG or a JPEG file, as SwiftClip checks before decoding. */
export function hasPNGOrJPEGSignature(bytes) {
  const starts = (signature) => signature.every((byte, i) => bytes[i] === byte);
  return starts([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) || starts([0xff, 0xd8, 0xff]);
}

function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

function base64ToBytes(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

const subtle = globalThis.crypto.subtle;

export function base64url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64url(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) return null;
  let base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  try {
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

async function checkSymbol(bytes) {
  const digest = new Uint8Array(await subtle.digest('SHA-256', bytes));
  return digest[0] >> 3;
}

/** Parses a typed key (`XXXX-XXXX-…`). Returns the 14 key bytes, or null. */
export async function parseKey(text) {
  const values = [];
  for (const character of String(text).toUpperCase()) {
    if ('- \t\n'.includes(character)) continue;
    if (character === 'O') values.push(0);
    else if (character === 'I' || character === 'L') values.push(1);
    else {
      const index = ALPHABET.indexOf(character);
      if (index < 0) return null;
      values.push(index);
    }
  }
  if (values.length !== 24) return null;
  const check = values.pop();
  let accumulator = 0;
  let bitCount = 0;
  const bytes = [];
  for (const value of values) {
    accumulator = (accumulator << 5) | value;
    bitCount += 5;
    if (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((accumulator >> bitCount) & 0xff);
      accumulator &= (1 << bitCount) - 1;
    }
  }
  if (bytes.length !== KEY_BYTES || accumulator !== 0) return null;
  const keyBytes = new Uint8Array(bytes);
  if ((await checkSymbol(keyBytes)) !== check) return null;
  return keyBytes;
}

/** Formats key bytes as `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`. */
export async function formatKey(keyBytes) {
  const symbols = [];
  let accumulator = 0;
  let bitCount = 0;
  for (const byte of keyBytes) {
    accumulator = (accumulator << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      symbols.push((accumulator >> bitCount) & 0x1f);
    }
    accumulator &= (1 << bitCount) - 1;
  }
  if (bitCount > 0) symbols.push((accumulator << (5 - bitCount)) & 0x1f);
  symbols.push(await checkSymbol(keyBytes));
  const characters = symbols.map((value) => ALPHABET[value]).join('');
  return characters.match(/.{1,4}/g).join('-');
}

async function hkdf(keyBytes, info, length) {
  const material = await subtle.importKey('raw', keyBytes, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: SALT, info: new TextEncoder().encode(info) },
    material,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** Derives the key ID and AES key from the 14 key bytes. */
export async function deriveKeys(keyBytes) {
  const keyID = await hkdf(keyBytes, 'SwiftClip Relay key id', 8);
  const raw = await hkdf(keyBytes, 'SwiftClip Relay AES-256-GCM', 32);
  const aesKey = await subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { keyID, keyIDText: base64url(keyID), aesKey };
}

/**
 * `<expiry ms>-<UUID>.screlay` → { expiresAt (ms), id }, or null. Only the
 * spelling senders write (no leading zeros, an upper-case UUID), as in
 * SwiftClip: another spelling of a name is a different name.
 */
export function parseFileName(name) {
  const match = /^(0|[1-9]\d{0,15})-([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\.screlay$/.exec(name);
  if (!match) return null;
  return { expiresAt: Number(match[1]), id: match[2] };
}

export function makeFileName(expiresAt, id = globalThis.crypto.randomUUID()) {
  return `${Math.floor(expiresAt)}-${id.toUpperCase()}.${FILE_EXTENSION}`;
}

// Version 2 authenticates the folder a file travels in (ToBrowser or
// FromBrowser), so a file copied into the other folder fails to open. Version 1
// files are refused, as in SwiftClip.
const VERSION = 2;

function associatedData(fileName, folder) {
  if (folder !== FOLDERS.toBrowser && folder !== FOLDERS.fromBrowser) throw new Error('Unknown relay folder');
  return new TextEncoder().encode(`SwiftClip Relay v2\n${folder}\n${fileName}`);
}

/**
 * Encrypts { text, password, from, sentAt, image?, file?, reveal? } for
 * `fileName`, where image is { type, bytes (Uint8Array), width, height }, file
 * is { name, type, bytes } and reveal is how many characters of a password the
 * sender shows (SwiftClip sends it; the page doesn't need to). Returns a JSON
 * string. Keys are in the order SwiftClip writes them (sorted).
 */
export async function seal(message, keys, fileName, folder, nonce = globalThis.crypto.getRandomValues(new Uint8Array(12))) {
  const file = message.file ? {
    data: bytesToBase64(message.file.bytes),
    name: safeFileName(message.file.name),
    type: String(message.file.type || 'application/octet-stream'),
  } : undefined;
  const image = message.image ? {
    data: bytesToBase64(message.image.bytes),
    height: Math.round(message.image.height),
    type: String(message.image.type),
    width: Math.round(message.image.width),
  } : undefined;
  const plaintext = padded(new TextEncoder().encode(JSON.stringify({
    file,
    from: message.from ?? undefined,
    image,
    password: Boolean(message.password),
    reveal: message.reveal === undefined || message.reveal === null ? undefined : revealedCharacters(message.reveal),
    sentAt: Math.round(message.sentAt ?? Date.now()),
    text: String(message.text ?? ''),
  })));
  const sealed = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: associatedData(fileName, folder), tagLength: 128 },
    keys.aesKey,
    plaintext,
  ));
  return JSON.stringify({ c: base64url(sealed), k: keys.keyIDText, n: base64url(nonce), v: VERSION });
}

const PADDING_BLOCK = 256;

/**
 * The encoded JSON object with a "pad" field of zeros added at the end, so
 * its length is a multiple of 256 bytes: OneDrive lists every file's exact
 * size, which would otherwise give away each item's length. Readers ignore
 * the field. The same as RelayEnvelope.padded in SwiftClip.
 */
export function padded(json) {
  const field = ',"pad":""'.length;
  const total = Math.ceil((json.length + field) / PADDING_BLOCK) * PADDING_BLOCK;
  const tail = new TextEncoder().encode(`,"pad":"${'0'.repeat(total - json.length - field)}"}`);
  const result = new Uint8Array(total);
  result.set(json.subarray(0, json.length - 1));
  result.set(tail, json.length - 1);
  return result;
}

/** The longest sender name kept, in code points, as in SwiftClip. */
export const MAX_SENDER_LENGTH = 64;

/**
 * A received sender name fit for display: without control or format
 * characters, at most MAX_SENDER_LENGTH long, or null if nothing is left.
 * The same as RelayMessage.displayableSender in SwiftClip.
 */
export function displayableSender(name) {
  if (typeof name !== 'string') return null;
  const cleaned = [...name.replace(/[\p{Cc}\p{Cf}]/gu, '')].slice(0, MAX_SENDER_LENGTH).join('').trim();
  return cleaned || null;
}

export class RelayError extends Error {
  constructor(code) {
    super(code);
    this.code = code; // 'malformed' | 'wrongKey' | 'decryptionFailed'
  }
}

/** The key ID (base64url) a file was encrypted with. */
export function keyIDOf(json) {
  try {
    const wire = JSON.parse(json);
    return wire && wire.v === VERSION && typeof wire.k === 'string' ? wire.k : null;
  } catch {
    return null;
  }
}

/** Decrypts a relay file. Throws RelayError. */
/** Decrypts a file read from `folder`. Fails if it was sealed for the other folder. */
export async function open(json, keys, fileName, folder) {
  let wire;
  try {
    wire = JSON.parse(json);
  } catch {
    throw new RelayError('malformed');
  }
  if (!wire || wire.v !== VERSION || typeof wire.k !== 'string') throw new RelayError('malformed');
  if (wire.k !== keys.keyIDText) throw new RelayError('wrongKey');
  const nonce = fromBase64url(wire.n);
  const sealed = fromBase64url(wire.c);
  if (!nonce || nonce.length !== 12 || !sealed || sealed.length < 16) throw new RelayError('malformed');
  let plaintext;
  try {
    plaintext = await subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: associatedData(fileName, folder), tagLength: 128 },
      keys.aesKey,
      sealed,
    );
  } catch {
    throw new RelayError('decryptionFailed');
  }
  let message;
  try {
    message = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
  } catch {
    throw new RelayError('malformed');
  }
  if (!message || typeof message.text !== 'string') throw new RelayError('malformed');
  // Senders never send more, as SwiftClip also checks.
  if (new TextEncoder().encode(message.text).length > MAX_TEXT_BYTES) throw new RelayError('malformed');
  let image = null;
  if (message.image !== undefined && message.image !== null) {
    const { type, data, width, height } = message.image;
    if (!IMAGE_TYPES.includes(type) || typeof data !== 'string' || !Number.isInteger(width) || !Number.isInteger(height)) {
      throw new RelayError('malformed');
    }
    try {
      image = { type, bytes: base64ToBytes(data), width, height };
    } catch {
      throw new RelayError('malformed');
    }
    if (!hasPNGOrJPEGSignature(image.bytes)) throw new RelayError('malformed');
  }
  let file = null;
  if (message.file !== undefined && message.file !== null) {
    const { name, type, data } = message.file;
    if (typeof name !== 'string' || typeof data !== 'string') throw new RelayError('malformed');
    try {
      file = { name: safeFileName(name), type: typeof type === 'string' ? type : 'application/octet-stream', bytes: base64ToBytes(data) };
    } catch {
      throw new RelayError('malformed');
    }
  }
  return {
    text: message.text,
    password: message.password === true,
    from: displayableSender(message.from),
    sentAt: typeof message.sentAt === 'number' ? message.sentAt : 0,
    image,
    file,
    // How many characters of a password the sender shows; 0 from senders that
    // don't say, such as older versions of SwiftClip.
    reveal: revealedCharacters(message.reveal),
  };
}
