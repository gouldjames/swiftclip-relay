// Microsoft sign-in for the relay page: OAuth authorization code flow with
// PKCE, no client secret and no third-party library. Register this page's
// address as a "Single-page application" redirect URI in Microsoft Entra.
import { config } from './config.js';

const SCOPES = 'openid profile offline_access https://graph.microsoft.com/Files.ReadWrite';
// By default tokens live only as long as this tab, so nothing stays behind on a
// shared or client-managed computer. "Keep me signed in" keeps them in this
// browser for 10 days, a period that starts again each time the page is used.
const REMEMBER_MS = 10 * 24 * 60 * 60 * 1000;
const TOKENS = 'swiftclip.tokens';
const PENDING = 'swiftclip.pendingSignIn';
const SILENT_ATTEMPT = 'swiftclip.silentRenewal';
// The sign-in in progress always lives in the tab.
const store = sessionStorage;

const authority = () => `https://login.microsoftonline.com/${encodeURIComponent(config.tenant || 'common')}/oauth2/v2.0`;
export const redirectURI = () => location.origin + location.pathname;
export const isConfigured = () => Boolean(config.clientId);

function randomString(byteCount = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteCount));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function challengeFor(verifier) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  return btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function readTokens() {
  for (const storage of [sessionStorage, localStorage]) {
    let tokens = null;
    try {
      tokens = JSON.parse(storage.getItem(TOKENS));
    } catch {
      tokens = null;
    }
    if (!tokens) continue;
    if (tokens.remember && !(tokens.rememberUntil > Date.now())) {
      // Unused for 10 days: forget it.
      storage.removeItem(TOKENS);
      continue;
    }
    return tokens;
  }
  return null;
}

function writeTokens(tokens) {
  (tokens.remember ? sessionStorage : localStorage).removeItem(TOKENS);
  (tokens.remember ? localStorage : sessionStorage).setItem(TOKENS, JSON.stringify(tokens));
}

/**
 * `options.remember` keeps the sign-in in this browser. `options.signedInAt`
 * carries the original sign-in time through a silent renewal, so a sign-out
 * sent from SwiftClip still applies.
 */
function saveTokens(response, previous, options = {}) {
  const remember = options.remember ?? previous?.remember ?? false;
  const tokens = {
    accessToken: response.access_token,
    expiresAt: Date.now() + (Number(response.expires_in) || 3600) * 1000,
    refreshToken: response.refresh_token || previous?.refreshToken || null,
    account: (response.id_token && accountName(response.id_token)) || previous?.account || null,
    remember,
    rememberUntil: remember ? (previous?.rememberUntil ?? Date.now() + REMEMBER_MS) : null,
    signedInAt: options.signedInAt ?? previous?.signedInAt ?? Date.now(),
  };
  writeTokens(tokens);
  return tokens;
}

function accountName(idToken) {
  try {
    const payload = idToken.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload), (c) => c.charCodeAt(0))));
    return claims.preferred_username || claims.name || null;
  } catch {
    return null;
  }
}

export function account() {
  return readTokens()?.account || null;
}

export function isSignedIn() {
  return Boolean(readTokens());
}

/** When this browser signed in, in milliseconds; 0 when signed out. */
export function signedInAt() {
  return readTokens()?.signedInAt || 0;
}

/** Whether the sign-in is kept in this browser. */
export function remembers() {
  return Boolean(readTokens()?.remember);
}

/** The page was used: a kept sign-in lasts another 10 days from now. */
export function touch() {
  const tokens = readTokens();
  if (!tokens?.remember) return;
  const until = Date.now() + REMEMBER_MS;
  // Write at most hourly.
  if (until - tokens.rememberUntil < 60 * 60 * 1000) return;
  writeTokens({ ...tokens, rememberUntil: until });
}

/**
 * Goes to Microsoft's sign-in page. `remember` keeps the sign-in in this
 * browser for 10 days. A renewal passes the account and the original
 * `signedInAt`.
 */
export async function signIn({ prompt, remember = false, loginHint, signedInAt: originalSignIn } = {}) {
  const verifier = randomString();
  const state = randomString(16);
  store.setItem(PENDING, JSON.stringify({
    verifier, state, remember, signedInAt: originalSignIn ?? null, renewal: Boolean(originalSignIn),
  }));
  const parameters = new URLSearchParams({
    client_id: config.clientId,
    response_type: 'code',
    redirect_uri: redirectURI(),
    response_mode: 'query',
    scope: SCOPES,
    state,
    code_challenge: await challengeFor(verifier),
    code_challenge_method: 'S256',
  });
  if (prompt) parameters.set('prompt', prompt);
  if (loginHint) parameters.set('login_hint', loginHint);
  location.assign(`${authority()}/authorize?${parameters}`);
}

export function signOut() {
  sessionStorage.removeItem(TOKENS);
  localStorage.removeItem(TOKENS);
  store.removeItem(PENDING);
}

async function requestToken(parameters) {
  const body = new URLSearchParams({ client_id: config.clientId, scope: SCOPES, ...parameters });
  const response = await fetch(`${authority()}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  const json = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = (json.error_description || json.error || `HTTP ${response.status}`).split('\r\n')[0];
    const error = new Error(message);
    error.code = json.error;
    throw error;
  }
  return json;
}

/** Finishes sign-in when Microsoft redirects back. Returns true if it did. */
export async function handleRedirect() {
  const query = new URLSearchParams(location.search);
  if (!query.has('code') && !query.has('error')) return false;
  // Remove the code from the address bar and history straight away.
  history.replaceState(null, '', location.pathname);
  const pending = JSON.parse(store.getItem(PENDING) || 'null');
  store.removeItem(PENDING);
  if (query.has('error')) {
    if (pending?.renewal) {
      // Renewing didn't work out (e.g. the person cancelled Microsoft's page).
      signOut();
      throw new Error('Your sign-in has ended. Sign in again to continue.');
    }
    throw new Error(query.get('error_description') || query.get('error'));
  }
  if (!pending || query.get('state') !== pending.state) {
    throw new Error('Sign-in was interrupted. Please try again.');
  }
  const response = await requestToken({
    grant_type: 'authorization_code',
    code: query.get('code'),
    redirect_uri: redirectURI(),
    code_verifier: pending.verifier,
  });
  saveTokens(response, null, { remember: pending.remember, signedInAt: pending.signedInAt ?? undefined });
  return true;
}

let refreshing = null;

/**
 * A kept sign-in outlives Microsoft's 24-hour refresh token: renew it with a
 * sign-in redirect for the same account. While Microsoft still knows this
 * browser it comes straight back without showing anything; otherwise it asks
 * the person to sign in. (Not `prompt=none`: when Microsoft has no session,
 * that can strand the tab on a Microsoft error page.) At most once every few
 * minutes, so it can't loop.
 */
function renewSilently(tokens) {
  if (!tokens.remember || !tokens.account) return false;
  const lastAttempt = Number(sessionStorage.getItem(SILENT_ATTEMPT)) || 0;
  if (Date.now() - lastAttempt < 5 * 60 * 1000) return false;
  sessionStorage.setItem(SILENT_ATTEMPT, String(Date.now()));
  signIn({ remember: true, loginHint: tokens.account, signedInAt: tokens.signedInAt });
  return true;
}

/** A valid Graph access token, or null when the user must sign in again. */
export async function accessToken({ forceRefresh = false } = {}) {
  const tokens = readTokens();
  if (!tokens) return null;
  if (!forceRefresh && tokens.accessToken && tokens.expiresAt - Date.now() > 120000) return tokens.accessToken;
  if (!tokens.refreshToken) {
    signOut();
    return null;
  }
  refreshing ??= requestToken({ grant_type: 'refresh_token', refresh_token: tokens.refreshToken })
    .then((response) => saveTokens(response, tokens).accessToken)
    .catch((error) => {
      // Refresh tokens for single-page apps last 24 hours; sign in again after that.
      if (error.code === 'invalid_grant' || error.code === 'interaction_required') {
        if (renewSilently(tokens)) return new Promise(() => {}); // Leaving the page.
        signOut();
        return null;
      }
      throw error;
    })
    .finally(() => {
      refreshing = null;
    });
  return refreshing;
}
