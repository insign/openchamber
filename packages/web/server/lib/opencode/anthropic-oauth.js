import crypto from 'node:crypto';

import { readAuthFile, writeAuthFile } from './auth.js';

const ANTHROPIC_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const AUTH_URL_CONSOLE = 'https://console.anthropic.com/oauth/authorize';
const TOKEN_URL = 'https://console.anthropic.com/v1/oauth/token';
const REDIRECT_URI = 'https://console.anthropic.com/oauth/code/callback';

const toBase64Url = (buffer) => buffer
  .toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=+$/g, '');

const generateCodeVerifier = () => toBase64Url(crypto.randomBytes(32));

const generateCodeChallenge = (verifier) => toBase64Url(
  crypto.createHash('sha256').update(verifier).digest()
);

export function isAnthropicProvider(providerId) {
  return ['anthropic', 'claude'].includes(String(providerId || '').toLowerCase());
}

export async function startAnthropicOAuth() {
  const verifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(verifier);
  const state = generateCodeVerifier();

  const url = new URL(AUTH_URL_CONSOLE);
  url.searchParams.set('code', 'true');
  url.searchParams.set('client_id', ANTHROPIC_CLIENT_ID);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('scope', 'org:create_api_key user:profile user:inference');
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', state);

  return {
    url: url.toString(),
    verifier,
    state,
  };
}

export async function completeAnthropicOAuth(code, verifier) {
  if (typeof code !== 'string' || code.trim().length === 0) {
    throw new Error('Authorization code is required');
  }
  if (typeof verifier !== 'string' || verifier.trim().length === 0) {
    throw new Error('OAuth verifier is required');
  }

  const response = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      code: code.trim(),
      grant_type: 'authorization_code',
      client_id: ANTHROPIC_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier.trim(),
    }),
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => '');
    throw new Error(`Token exchange failed: ${response.status}${errorText ? ` - ${errorText}` : ''}`);
  }

  const json = await response.json();
  const accessToken = typeof json?.access_token === 'string' ? json.access_token : '';
  const refreshToken = typeof json?.refresh_token === 'string' ? json.refresh_token : '';
  const expiresIn = typeof json?.expires_in === 'number' ? json.expires_in : null;

  if (!accessToken || !refreshToken || !expiresIn) {
    throw new Error('Anthropic OAuth response missing required token fields');
  }

  const auth = readAuthFile();
  auth.anthropic = {
    type: 'oauth',
    access: accessToken,
    refresh: refreshToken,
    expires: Date.now() + expiresIn * 1000,
  };
  writeAuthFile(auth);

  return {
    success: true,
    providerId: 'anthropic',
  };
}
