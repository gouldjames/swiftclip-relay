// Lets Edge and Chrome install the relay page as an app, in its own window
// with its own icon. The manifest (manifest.webmanifest) describes the app,
// and the service worker (sw.js) lets it open without a connection.

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
