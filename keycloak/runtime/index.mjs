/**
 * basic/keycloak runtime — SSO provider implementation.
 *
 * Ploinky core imports this module dynamically through the configured
 * workspace SSO provider and calls the exported operations.
 *
 * Core stays provider-neutral and passes `providerSession` blobs opaquely.
 * All Keycloak-specific knowledge — realms,
 * PKCE, JWKS, claim parsing, `realm_access.roles` — lives here.
 *
 * Configuration resolution is injected by core via the `config` parameter so
 * the provider does not read env vars or workspace files directly.
 *
 * Operations (per plan):
 *   sso_begin_login({ redirectUri, prompt })        -> { authorizationUrl, providerState, expiresAt }
 *   sso_handle_callback({ redirectUri, query, providerState }) -> { user, providerSession }
 *   sso_validate_session({ providerSession })        -> { user, providerSession }
 *   sso_refresh_session({ providerSession })         -> { user, providerSession }
 *   sso_logout({ providerSession, postLogoutRedirectUri }) -> { redirectUrl }
 */

import crypto from 'node:crypto';
import { URL } from 'node:url';

const METADATA_TTL_MS = 5 * 60 * 1000;
const JWKS_TTL_MS = 5 * 60 * 1000;
const PENDING_TTL_MS = 5 * 60 * 1000;
const KEYCLOAK_CONFIG_CANDIDATES = {
  baseUrl: ['KEYCLOAK_URL', 'SSO_BASE_URL', 'SSO_URL', 'OIDC_BASE_URL'],
  realm: ['KEYCLOAK_REALM', 'SSO_REALM', 'OIDC_REALM'],
  clientId: ['KEYCLOAK_CLIENT_ID', 'SSO_CLIENT_ID', 'OIDC_CLIENT_ID'],
  clientSecret: ['KEYCLOAK_CLIENT_SECRET', 'SSO_CLIENT_SECRET', 'OIDC_CLIENT_SECRET'],
  scope: ['KEYCLOAK_SCOPE', 'SSO_SCOPE', 'OIDC_SCOPE'],
  redirectUri: ['KEYCLOAK_REDIRECT_URI', 'SSO_REDIRECT_URI', 'OIDC_REDIRECT_URI'],
  postLogoutRedirectUri: ['KEYCLOAK_LOGOUT_REDIRECT_URI', 'SSO_LOGOUT_REDIRECT_URI', 'OIDC_LOGOUT_REDIRECT_URI']
};

// ---------- small helpers ----------

function base64UrlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(segment) {
  const padding = '==='.slice((String(segment).length + 3) % 4);
  return Buffer.from(String(segment).replace(/-/g, '+').replace(/_/g, '/') + padding, 'base64');
}

function ensureTrailingSlash(url) {
  return String(url).endsWith('/') ? url : `${url}/`;
}

function buildRealmBase(baseUrl, realm) {
  return `${ensureTrailingSlash(baseUrl)}realms/${encodeURIComponent(realm)}`;
}

function toFormBody(params) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, String(value));
    }
  }
  return search.toString();
}

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  const text = await res.text();
  if (!res.ok) {
    const detail = text ? `: ${text}` : '';
    throw new Error(`Keycloak request failed (${res.status})${detail}`);
  }
  return text ? JSON.parse(text) : {};
}

function assertConfig(config) {
  if (!config || typeof config !== 'object') {
    throw new Error('sso-provider/basic-keycloak: missing config');
  }
  if (!config.baseUrl) throw new Error('sso-provider/basic-keycloak: baseUrl required');
  if (!config.realm) throw new Error('sso-provider/basic-keycloak: realm required');
  if (!config.clientId) throw new Error('sso-provider/basic-keycloak: clientId required');
}

function readProviderValue(readValue, names, fallback) {
  if (typeof readValue !== 'function') {
    if (fallback === undefined || fallback === null) return '';
    return String(fallback).trim();
  }
  return readValue(names, fallback);
}

export function resolveProviderConfig({ workspaceConfig, providerConfig = {}, readValue } = {}) {
  const sso = workspaceConfig?.sso && typeof workspaceConfig.sso === 'object'
    ? workspaceConfig.sso
    : {};
  const stored = providerConfig && typeof providerConfig === 'object'
    ? providerConfig
    : {};

  const config = {
    baseUrl: readProviderValue(readValue, KEYCLOAK_CONFIG_CANDIDATES.baseUrl, stored.baseUrl || sso.baseUrl || ''),
    realm: readProviderValue(readValue, KEYCLOAK_CONFIG_CANDIDATES.realm, stored.realm || sso.realm || ''),
    clientId: readProviderValue(readValue, KEYCLOAK_CONFIG_CANDIDATES.clientId, stored.clientId || sso.clientId || ''),
    clientSecret: readProviderValue(readValue, KEYCLOAK_CONFIG_CANDIDATES.clientSecret, stored.clientSecret || sso.clientSecret || ''),
    redirectUri: readProviderValue(readValue, KEYCLOAK_CONFIG_CANDIDATES.redirectUri, stored.redirectUri || sso.redirectUri || ''),
    postLogoutRedirectUri: readProviderValue(
      readValue,
      KEYCLOAK_CONFIG_CANDIDATES.postLogoutRedirectUri,
      stored.postLogoutRedirectUri || stored.logoutRedirectUri || sso.postLogoutRedirectUri || sso.logoutRedirectUri || ''
    ),
    scope: readProviderValue(readValue, KEYCLOAK_CONFIG_CANDIDATES.scope, stored.scope || sso.scope || 'openid profile email')
  };

  if (!config.baseUrl || !config.realm || !config.clientId) {
    return null;
  }

  return {
    ...stored,
    ...config,
    clientSecret: config.clientSecret || null,
    redirectUri: config.redirectUri || null,
    postLogoutRedirectUri: config.postLogoutRedirectUri || null,
    scope: config.scope || 'openid profile email'
  };
}

// ---------- metadata + JWKS caches ----------

function createMetadataCache() {
  const cache = new Map();
  return {
    async get(config) {
      const key = `${config.baseUrl}|${config.realm}`;
      const cached = cache.get(key);
      if (cached && Date.now() - cached.fetchedAt < METADATA_TTL_MS) {
        return cached.data;
      }
      const realmBase = buildRealmBase(config.baseUrl, config.realm);
      const url = `${realmBase}/.well-known/openid-configuration`;
      const res = await fetch(url, { method: 'GET' });
      if (!res.ok) {
        throw new Error(`Failed to fetch OpenID configuration (${res.status})`);
      }
      const data = await res.json();
      cache.set(key, { fetchedAt: Date.now(), data });
      return data;
    },
    clear() { cache.clear(); }
  };
}

function createJwksCache() {
  const cache = new Map();
  async function load(jwksUri) {
    const cached = cache.get(jwksUri);
    if (cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS) return cached.keys;
    const res = await fetch(jwksUri, { method: 'GET' });
    if (!res.ok) throw new Error(`Failed to fetch JWKS (${res.status})`);
    const body = await res.json();
    const keys = new Map();
    if (Array.isArray(body?.keys)) {
      for (const jwk of body.keys) {
        if (jwk && jwk.kid) keys.set(jwk.kid, jwk);
      }
    }
    cache.set(jwksUri, { fetchedAt: Date.now(), keys });
    return keys;
  }
  return {
    async getKey(jwksUri, kid) {
      if (!jwksUri || !kid) return null;
      const keys = await load(jwksUri);
      if (!keys.get(kid)) {
        cache.delete(jwksUri);
        const refreshed = await load(jwksUri);
        return refreshed.get(kid) || null;
      }
      return keys.get(kid);
    },
    clear() { cache.clear(); }
  };
}

// ---------- JWT decode + verify ----------

function decodeJwt(token) {
  if (typeof token !== 'string') throw new Error('Missing token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('JWT must have three parts');
  const [rawHeader, rawPayload, signature] = parts;
  const header = JSON.parse(base64UrlDecode(rawHeader).toString('utf8'));
  const payload = JSON.parse(base64UrlDecode(rawPayload).toString('utf8'));
  return { header, payload, signature, rawHeader, rawPayload };
}

function verifySignature({ rawHeader, rawPayload, signature }, jwk) {
  if (!signature) throw new Error('JWT missing signature');
  if (!jwk || !jwk.kty) throw new Error('Missing JWK');
  const sig = base64UrlDecode(signature);
  const data = Buffer.from(`${rawHeader}.${rawPayload}`);
  const keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  return crypto.verify('RSA-SHA256', data, keyObject, sig);
}

function validateClaims(payload, { issuer, clientId, nonce }) {
  if (!payload) throw new Error('Missing JWT payload');
  if (issuer && payload.iss !== issuer) throw new Error('Invalid token issuer');
  if (clientId) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(clientId)) throw new Error('Audience mismatch');
  }
  const now = Math.floor(Date.now() / 1000) - 30;
  if (typeof payload.exp === 'number' && now > payload.exp) throw new Error('Token expired');
  if (typeof payload.nbf === 'number' && now < payload.nbf) throw new Error('Token not yet valid');
  if (nonce && payload.nonce && payload.nonce !== nonce) throw new Error('Nonce mismatch');
}

// ---------- PKCE ----------

function createPkcePair(length = 64) {
  const len = Math.min(Math.max(length, 43), 128);
  const verifier = base64UrlEncode(crypto.randomBytes(len)).slice(0, len);
  const challenge = base64UrlEncode(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge, method: 'S256' };
}

function randomId(bytes = 16) {
  return base64UrlEncode(crypto.randomBytes(bytes));
}

// ---------- token and URL construction ----------

function buildAuthUrl(metadata, config, { state, codeChallenge, redirectUri, scope, nonce, prompt }) {
  const authUrl = new URL(metadata.authorization_endpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', config.clientId);
  authUrl.searchParams.set('scope', scope || config.scope || 'openid');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  if (nonce) authUrl.searchParams.set('nonce', nonce);
  if (prompt) authUrl.searchParams.set('prompt', prompt);
  return authUrl.toString();
}

async function exchangeCodeForTokens(metadata, config, { code, redirectUri, codeVerifier }) {
  const body = toFormBody({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: config.clientId,
    code_verifier: codeVerifier,
    client_secret: config.clientSecret || undefined
  });
  return fetchJson(metadata.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });
}

async function refreshTokensRemote(metadata, config, refreshToken) {
  const body = toFormBody({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: config.clientId,
    client_secret: config.clientSecret || undefined
  });
  return fetchJson(metadata.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });
}

function buildLogoutUrl(metadata, config, { idTokenHint, postLogoutRedirectUri }) {
  if (!metadata.end_session_endpoint) return null;
  const url = new URL(metadata.end_session_endpoint);
  if (idTokenHint) url.searchParams.set('id_token_hint', idTokenHint);
  const redirect = postLogoutRedirectUri || config.postLogoutRedirectUri || config.redirectUri;
  if (redirect) url.searchParams.set('post_logout_redirect_uri', redirect);
  url.searchParams.set('client_id', config.clientId);
  return url.toString();
}

// ---------- claim extraction ----------

function extractRoles(idDecoded, accessDecoded) {
  const src = accessDecoded || idDecoded;
  const realmRoles = Array.isArray(src?.payload?.realm_access?.roles) ? src.payload.realm_access.roles : [];
  const resourceRoles = [];
  if (src?.payload?.resource_access && typeof src.payload.resource_access === 'object') {
    for (const clientData of Object.values(src.payload.resource_access)) {
      if (Array.isArray(clientData?.roles)) resourceRoles.push(...clientData.roles);
    }
  }
  return Array.from(new Set([...realmRoles, ...resourceRoles]));
}

function extractUser(idDecoded, accessDecoded) {
  const idPayload = idDecoded?.payload || {};
  const roles = extractRoles(idDecoded, accessDecoded);
  return {
    id: idPayload.sub || '',
    sub: idPayload.sub || '',
    username: idPayload.preferred_username || idPayload.username || idPayload.email || '',
    name: idPayload.name || idPayload.preferred_username || idPayload.email || '',
    email: idPayload.email || null,
    roles,
    raw: idPayload
  };
}

// ---------- provider-session serialization ----------

function buildProviderSession({ tokens, expiresAt, refreshExpiresAt }) {
  return {
    provider: 'basic/keycloak',
    tokens: {
      accessToken: tokens.access_token || null,
      refreshToken: tokens.refresh_token || null,
      idToken: tokens.id_token || null,
      scope: tokens.scope || null,
      tokenType: tokens.token_type || 'Bearer'
    },
    expiresAt: expiresAt || null,
    refreshExpiresAt: refreshExpiresAt || null
  };
}

// ---------- pending-state (provider-owned) ----------

const pendingStates = new Map();

function createPending(entry) {
  const state = randomId(18);
  pendingStates.set(state, { ...entry, createdAt: Date.now() });
  return state;
}

function consumePending(state) {
  const entry = pendingStates.get(state);
  if (!entry) return null;
  pendingStates.delete(state);
  if (Date.now() - entry.createdAt > PENDING_TTL_MS) return null;
  return entry;
}

// ---------- provider factory (called by core) ----------

export function createProvider({ getConfig } = {}) {
  if (typeof getConfig !== 'function') {
    throw new Error('sso-provider/basic-keycloak: getConfig callback is required');
  }
  const metadataCache = createMetadataCache();
  const jwksCache = createJwksCache();

  async function resolveConfig() {
    const cfg = await getConfig();
    assertConfig(cfg);
    return cfg;
  }

  async function ensureMetadata(cfg) {
    return metadataCache.get(cfg);
  }

  async function sso_begin_login({ redirectUri, prompt } = {}) {
    const cfg = await resolveConfig();
    if (!redirectUri) throw new Error('sso-provider: redirectUri required');
    const metadata = await ensureMetadata(cfg);
    const { verifier, challenge } = createPkcePair();
    const nonce = randomId(12);
    const state = createPending({ codeVerifier: verifier, redirectUri, nonce });
    const authorizationUrl = buildAuthUrl(metadata, cfg, {
      state,
      codeChallenge: challenge,
      redirectUri,
      scope: cfg.scope,
      nonce,
      prompt
    });
    return {
      authorizationUrl,
      providerState: state,
      expiresAt: Date.now() + PENDING_TTL_MS
    };
  }

  async function sso_handle_callback({ redirectUri, query, providerState }) {
    const cfg = await resolveConfig();
    const pending = consumePending(providerState);
    if (!pending) throw new Error('Invalid or expired authorization state');
    if (!query?.code) throw new Error('Authorization response missing code');
    const finalRedirectUri = redirectUri || pending.redirectUri;
    const metadata = await ensureMetadata(cfg);
    const tokens = await exchangeCodeForTokens(metadata, cfg, {
      code: query.code,
      redirectUri: finalRedirectUri,
      codeVerifier: pending.codeVerifier
    });
    if (!tokens?.id_token) throw new Error('Token response missing id_token');
    const idDecoded = decodeJwt(tokens.id_token);
    const jwk = await jwksCache.getKey(metadata.jwks_uri, idDecoded.header.kid);
    if (!jwk) throw new Error('Unable to resolve signing key');
    if (!verifySignature(idDecoded, jwk)) throw new Error('Invalid token signature');
    validateClaims(idDecoded.payload, {
      issuer: metadata.issuer,
      clientId: cfg.clientId,
      nonce: pending.nonce
    });
    const accessDecoded = tokens.access_token ? decodeJwt(tokens.access_token) : null;
    const user = extractUser(idDecoded, accessDecoded);
    const now = Date.now();
    const expiresAt = tokens.expires_in ? now + Number(tokens.expires_in) * 1000 : null;
    const refreshExpiresAt = tokens.refresh_expires_in ? now + Number(tokens.refresh_expires_in) * 1000 : null;
    return {
      user,
      providerSession: buildProviderSession({ tokens, expiresAt, refreshExpiresAt })
    };
  }

  async function sso_validate_session({ providerSession }) {
    const cfg = await resolveConfig();
    if (!providerSession?.tokens?.idToken) throw new Error('Provider session missing id_token');
    const metadata = await ensureMetadata(cfg);
    const idDecoded = decodeJwt(providerSession.tokens.idToken);
    const jwk = await jwksCache.getKey(metadata.jwks_uri, idDecoded.header.kid);
    if (!jwk) throw new Error('Unable to resolve signing key');
    if (!verifySignature(idDecoded, jwk)) throw new Error('Invalid token signature');
    validateClaims(idDecoded.payload, {
      issuer: metadata.issuer,
      clientId: cfg.clientId
    });
    const accessDecoded = providerSession.tokens.accessToken ? decodeJwt(providerSession.tokens.accessToken) : null;
    const user = extractUser(idDecoded, accessDecoded);
    return { user, providerSession };
  }

  async function sso_refresh_session({ providerSession }) {
    const cfg = await resolveConfig();
    if (!providerSession?.tokens?.refreshToken) throw new Error('Provider session missing refresh_token');
    const metadata = await ensureMetadata(cfg);
    const tokens = await refreshTokensRemote(metadata, cfg, providerSession.tokens.refreshToken);
    const now = Date.now();
    const expiresAt = tokens.expires_in ? now + Number(tokens.expires_in) * 1000 : providerSession.expiresAt;
    const refreshExpiresAt = tokens.refresh_expires_in ? now + Number(tokens.refresh_expires_in) * 1000 : providerSession.refreshExpiresAt;
    const updatedTokens = {
      access_token: tokens.access_token || providerSession.tokens.accessToken,
      refresh_token: tokens.refresh_token || providerSession.tokens.refreshToken,
      id_token: tokens.id_token || providerSession.tokens.idToken,
      scope: tokens.scope || providerSession.tokens.scope,
      token_type: tokens.token_type || providerSession.tokens.tokenType
    };
    const idDecoded = decodeJwt(updatedTokens.id_token);
    const accessDecoded = updatedTokens.access_token ? decodeJwt(updatedTokens.access_token) : null;
    const user = extractUser(idDecoded, accessDecoded);
    return {
      user,
      providerSession: buildProviderSession({ tokens: updatedTokens, expiresAt, refreshExpiresAt })
    };
  }

  async function sso_logout({ providerSession, postLogoutRedirectUri } = {}) {
    const cfg = await resolveConfig();
    const metadata = await ensureMetadata(cfg);
    const logoutUrl = buildLogoutUrl(metadata, cfg, {
      idTokenHint: providerSession?.tokens?.idToken,
      postLogoutRedirectUri
    });
    return { redirectUrl: logoutUrl || postLogoutRedirectUri || null };
  }

  function invalidateCaches() {
    metadataCache.clear();
    jwksCache.clear();
  }

  return {
    name: 'basic/keycloak',
    sso_begin_login,
    sso_handle_callback,
    sso_validate_session,
    sso_refresh_session,
    sso_logout,
    invalidateCaches
  };
}

export default { createProvider };
