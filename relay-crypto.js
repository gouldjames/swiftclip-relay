// SwiftClip relay format, matching Packages/SwiftClipKit/Sources/SwiftClipCore/Relay.
// Works in browsers and in Node 20+ (Web Crypto). No dependencies.

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const KEY_BYTES = 14;
const SALT = new TextEncoder().encode('SwiftClip Relay');
export const FILE_EXTENSION = 'screlay';
export const ROOT = 'Apps/SwiftClip';
export const FOLDERS = { toBrowser: 'ToBrowser', fromBrowser: 'FromBrowser' };
export const MAX_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_TEXT_BYTES = 1000000;

const subtle = globalThis.crypto.subtle;

export function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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

/** `<expiry ms>-<UUID>.screlay` → { expiresAt (ms), id }, or null. */
export function parseFileName(name) {
  const match = /^(\d{1,16})-([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\.screlay$/.exec(name);
  if (!match) return null;
  return { expiresAt: Number(match[1]), id: match[2].toUpperCase() };
}

export function makeFileName(expiresAt, id = globalThis.crypto.randomUUID()) {
  return `${Math.floor(expiresAt)}-${id.toUpperCase()}.${FILE_EXTENSION}`;
}

function associatedData(fileName) {
  return new TextEncoder().encode(`SwiftClip Relay v1\n${fileName}`);
}

/** Encrypts { text, password, from, sentAt } for `fileName`. Returns a JSON string. */
export async function seal(message, keys, fileName, nonce = globalThis.crypto.getRandomValues(new Uint8Array(12))) {
  const plaintext = new TextEncoder().encode(JSON.stringify({
    from: message.from ?? undefined,
    password: Boolean(message.password),
    sentAt: Math.round(message.sentAt ?? Date.now()),
    text: String(message.text),
  }));
  const sealed = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: associatedData(fileName), tagLength: 128 },
    keys.aesKey,
    plaintext,
  ));
  return JSON.stringify({ c: base64url(sealed), k: keys.keyIDText, n: base64url(nonce), v: 1 });
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
    return wire && wire.v === 1 && typeof wire.k === 'string' ? wire.k : null;
  } catch {
    return null;
  }
}

/** Decrypts a relay file. Throws RelayError. */
export async function open(json, keys, fileName) {
  let wire;
  try {
    wire = JSON.parse(json);
  } catch {
    throw new RelayError('malformed');
  }
  if (!wire || wire.v !== 1 || typeof wire.k !== 'string') throw new RelayError('malformed');
  if (wire.k !== keys.keyIDText) throw new RelayError('wrongKey');
  const nonce = fromBase64url(wire.n);
  const sealed = fromBase64url(wire.c);
  if (!nonce || nonce.length !== 12 || !sealed || sealed.length < 16) throw new RelayError('malformed');
  let plaintext;
  try {
    plaintext = await subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: associatedData(fileName), tagLength: 128 },
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
  return {
    text: message.text,
    password: message.password === true,
    from: typeof message.from === 'string' ? message.from : null,
    sentAt: typeof message.sentAt === 'number' ? message.sentAt : 0,
  };
}
