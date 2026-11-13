// Microsoft sign-in for the relay page: OAuth authorization code flow with
// PKCE, no client secret and no third-party library. Register this page's
// address as a "Single-page application" redirect URI in Microsoft Entra.
import { config } from './config.js';

const SCOPES = 'openid profile offline_access https://graph.microsoft.com/Files.ReadWrite';
// Tokens live only as long as this tab: nothing stays behind on a shared or
// client-managed computer.
const store = sessionStorage;
const TOKENS = 'swiftclip.tokens';
const PENDING = 'swiftclip.pendingSignIn';

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
  try {
    return JSON.parse(store.getItem(TOKENS)) || null;
  } catch {
    return null;
  }
}

function saveTokens(response, previous) {
  const tokens = {
    accessToken: response.access_token,
    expiresAt: Date.now() + (Number(response.expires_in) || 3600) * 1000,
    refreshToken: response.refresh_token || previous?.refreshToken || null,
    account: (response.id_token && accountName(response.id_token)) || previous?.account || null,
  };
  store.setItem(TOKENS, JSON.stringify(tokens));
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

/** Goes to Microsoft's sign-in page. */
export async function signIn({ prompt } = {}) {
  const verifier = randomString();
  const state = randomString(16);
  store.setItem(PENDING, JSON.stringify({ verifier, state }));
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
  location.assign(`${authority()}/authorize?${parameters}`);
}

export function signOut() {
  store.removeItem(TOKENS);
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
  saveTokens(response, null);
  return true;
}

let refreshing = null;

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
