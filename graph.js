// The Microsoft Graph calls the relay page needs.
import { accessToken } from './auth.js?v=0ffe00a';
import { MAX_FILE_BYTES, ROOT } from './relay-crypto.js?v=0ffe00a';

const GRAPH = 'https://graph.microsoft.com/v1.0/me/drive/';

export class SignInRequired extends Error {}

export class GraphError extends Error {
  constructor(status, message, retryAfter) {
    super(message || `OneDrive error (${status})`);
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

const pathURL = (path) => `${GRAPH}root:/${path.split('/').map(encodeURIComponent).join('/')}`;

async function send(method, url, { body, contentType, accept = [200, 201, 204] } = {}) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const token = await accessToken({ forceRefresh: attempt > 0 });
    if (!token) throw new SignInRequired();
    const headers = { Authorization: `Bearer ${token}` };
    if (contentType) headers['Content-Type'] = contentType;
    const response = await fetch(url, { method, headers, body, cache: 'no-store' });
    if (response.status === 401 && attempt === 0) continue;
    if (response.status === 429 || response.status === 503) {
      throw new GraphError(response.status, 'OneDrive is busy. Trying again shortly.', Number(response.headers.get('Retry-After')) || 30);
    }
    if (!accept.includes(response.status)) {
      const json = await response.json().catch(() => ({}));
      if (response.status === 403) {
        throw new GraphError(403, 'OneDrive refused access. Your organization may need to approve SwiftClip.');
      }
      throw new GraphError(response.status, json.error?.message);
    }
    return response;
  }
  throw new SignInRequired();
}

async function ensureFolder(path) {
  const existing = await send('GET', pathURL(path), { accept: [200, 404] });
  if (existing.status !== 404) return;
  const segments = path.split('/');
  const name = segments.pop();
  const parent = segments.join('/');
  if (parent) await ensureFolder(parent);
  const url = parent ? `${pathURL(parent)}:/children` : `${GRAPH}root/children`;
  await send('POST', url, {
    body: JSON.stringify({ name, folder: {}, '@microsoft.graph.conflictBehavior': 'fail' }),
    contentType: 'application/json',
    accept: [200, 201, 409],
  });
}

/** Files in Apps/SwiftClip/<folder>: [{ id, name, size, downloadURL }]. */
export async function list(folder) {
  const files = [];
  let url = `${pathURL(`${ROOT}/${folder}`)}:/children?$top=200`;
  while (url) {
    const response = await send('GET', url, { accept: [200, 404] });
    if (response.status === 404) return [];
    const page = await response.json();
    for (const item of page.value || []) {
      if (!item.file) continue;
      files.push({ id: item.id, name: item.name, size: item.size || 0, downloadURL: item['@microsoft.graph.downloadUrl'] || null });
    }
    url = page['@odata.nextLink'] || null;
  }
  return files;
}

/** The file's text. The download address is pre-authenticated, so no token is sent. */
export async function download(file) {
  if (file.size > MAX_FILE_BYTES) throw new GraphError(413, 'File too large');
  const response = file.downloadURL
    ? await fetch(file.downloadURL, { cache: 'no-store' })
    : await send('GET', `${GRAPH}items/${encodeURIComponent(file.id)}/content`);
  if (!response.ok) throw new GraphError(response.status);
  return response.text();
}

export async function upload(folder, name, text) {
  const url = `${pathURL(`${ROOT}/${folder}/${name}`)}:/content`;
  const options = { body: text, contentType: 'application/octet-stream', accept: [200, 201, 404] };
  let response = await send('PUT', url, options);
  if (response.status === 404) {
    await ensureFolder(`${ROOT}/${folder}`);
    response = await send('PUT', url, { ...options, accept: [200, 201] });
  }
  return (await response.json()).id;
}

/** Deletes a file, skipping the recycle bin where OneDrive allows it. */
export async function remove(id) {
  const item = `${GRAPH}items/${encodeURIComponent(id)}`;
  const permanent = await send('POST', `${item}/permanentDelete`, { accept: [200, 204, 400, 403, 404, 405, 501] });
  if ([200, 204, 404].includes(permanent.status)) return;
  await send('DELETE', item, { accept: [200, 204, 404] });
}
