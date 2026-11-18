// Lets Edge and Chrome install the relay page as an app, in its own window
// with its own icon. The manifest (manifest.webmanifest) describes the app,
// and the service worker (sw.js) lets it open without a connection.

/** The installed app's first window, in CSS pixels: the page's column with room around it, and for a few items. */
export const APP_WINDOW = { width: 960, height: 880 };
const PLACED = 'swiftclip.appWindowPlaced';

/**
 * The first time the installed app opens, sizes its window to ``APP_WINDOW``
 * (at most 90% of the screen) and centres it. Edge and Chrome let an app
 * window, though not a browser tab, resize and move itself; afterwards they
 * remember wherever the person puts it, so this happens once. Returns whether
 * it placed the window.
 */
export function placeAppWindow(win = window, storage = win.localStorage) {
  if (!win.matchMedia?.('(display-mode: standalone)').matches) return false;
  try {
    if (storage.getItem(PLACED)) return false;
    storage.setItem(PLACED, '1');
  } catch {
    // Without storage it would be placed on every launch, undoing the person's own size.
    return false;
  }
  const screen = win.screen;
  const width = Math.min(APP_WINDOW.width, Math.round(screen.availWidth * 0.9));
  const height = Math.min(APP_WINDOW.height, Math.round(screen.availHeight * 0.9));
  try {
    win.resizeTo(width, height);
    win.moveTo(
      (screen.availLeft ?? 0) + Math.round((screen.availWidth - width) / 2),
      (screen.availTop ?? 0) + Math.round((screen.availHeight - height) / 2),
    );
  } catch {
    return false;
  }
  return true;
}

/** Registers sw.js. Without it the page works as before; the app just can't open offline. */
export function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

/**
 * Shows `button` while the browser offers to install the page, and asks it to
 * install the page when clicked. Only Edge and Chrome offer, and never once
 * the page is installed; the install icon in their address bar stays too.
 */
export function offerInstall(button) {
  let offer = null;
  window.addEventListener('beforeinstallprompt', (event) => {
    event.preventDefault();
    offer = event;
    button.hidden = false;
  });
  button.addEventListener('click', () => {
    // Each offer can be used once; if it's turned down, the browser makes a new one later.
    offer?.prompt().catch(() => {});
    offer = null;
    button.hidden = true;
  });
  window.addEventListener('appinstalled', () => {
    offer = null;
    button.hidden = true;
  });
}
