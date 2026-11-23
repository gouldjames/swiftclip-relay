// The relay page's service worker. With the manifest, it lets Edge and Chrome
// install the page as an app, and lets that app open without a connection.
// Requests for the page's own files go to the network first, so it's always
// the latest release while online; only when that fails does the copy cached
// at install answer. Nothing else is cached: requests to Microsoft and
// OneDrive never pass through here, and nothing the page signs in with,
// decrypts or stores is ever in the cache.

// Replaced with the commit by .github/workflows/pages.yml, so each release
// installs afresh, caches its own files and removes the last release's.
const VERSION = '02686a3';
const CACHE_PREFIX = 'swiftclip-relay-';
const CACHE = CACHE_PREFIX + VERSION;

// Everything the page loads. Web/tests/app-install.test.mjs checks that it
// covers everything index.html, its scripts and the manifest refer to.
const FILES = [
  './',
  'style.css',
  'logo.svg',
  'manifest.webmanifest',
  'app.js',
  'auth.js',
  'config.js',
  'graph.js',
  'install.js',
  'page-logic.js',
  'relay-crypto.js',
  'icons/icon-192.png',
  'icons/icon-512.png',
  'icons/maskable-192.png',
  'icons/maskable-512.png',
];

const scoped = (path) => new URL(path, self.registration.scope).href;

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    // From the network, not the HTTP cache, which can still hold the last release.
    await cache.addAll(FILES.map((path) => new Request(scoped(path), { cache: 'reload' })));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const stale = (await caches.keys()).filter((name) => name.startsWith(CACHE_PREFIX) && name !== CACHE);
    await Promise.all(stale.map((name) => caches.delete(name)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET' || !request.url.startsWith(self.registration.scope)) return;
  event.respondWith(fetch(request).catch(async (error) => {
    const cache = await caches.open(CACHE);
    // Every address in scope is the page (Microsoft's sign-in comes back to it
    // with a query), and a script's or stylesheet's ?v= only names its release.
    const cached = request.mode === 'navigate'
      ? await cache.match(scoped('./'), { ignoreVary: true })
      : await cache.match(request, { ignoreSearch: true, ignoreVary: true });
    if (cached) return cached;
    throw error;
  }));
});
