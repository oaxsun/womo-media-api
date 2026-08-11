const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, Range',
  'Access-Control-Expose-Headers': 'Content-Range, Accept-Ranges, Content-Length, Content-Type, ETag',
  'Cache-Control': 'no-store',
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      ...extraHeaders,
      'Content-Type': 'application/json; charset=utf-8',
    },
  });
}

function getBearerToken(request) {
  const auth = request.headers.get('Authorization') || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

function isValidAesKeyBase64(value) {
  if (typeof value !== 'string' || !value) return false;
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const pad = normalized.length % 4;
    const padded = normalized + (pad ? '='.repeat(4 - pad) : '');
    const bytes = Uint8Array.from(atob(padded), c => c.charCodeAt(0));
    return bytes.length === 32;
  } catch {
    return false;
  }
}

function base64UrlEncodeBytes(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlEncodeString(value) {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

function base64UrlDecodeString(value) {
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
}

async function hmacSign(value, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
  return base64UrlEncodeBytes(new Uint8Array(sig));
}

async function makeMediaToken(uid, secret) {
  const payload = base64UrlEncodeString(JSON.stringify({
    uid,
    exp: Math.floor(Date.now() / 1000) + 7200,
  }));
  const signature = await hmacSign(payload, secret);
  return `wmo2.${payload}.${signature}`;
}

async function verifyMediaToken(token, secret) {
  if (!token || !secret || !token.startsWith('wmo2.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'wmo2') return null;
  const expected = await hmacSign(parts[1], secret);
  if (expected !== parts[2]) return null;
  const raw = base64UrlDecodeString(parts[1]);
  if (!raw) return null;
  try {
    const claims = JSON.parse(raw);
    if (!claims?.uid || Number(claims.exp || 0) < Math.floor(Date.now() / 1000)) return null;
    return claims;
  } catch {
    return null;
  }
}

async function verifyFirebaseIdToken(idToken, apiKey) {
  const response = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(apiKey)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken }),
    }
  );

  if (!response.ok) return null;
  const data = await response.json();
  const user = data?.users?.[0];
  if (!user?.localId) return null;
  return { uid: user.localId, email: user.email || null };
}

function isAllowedArchiveUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:') return false;
    const host = url.hostname.toLowerCase();
    if (!(host === 'archive.org' || host === 'www.archive.org' || host.endsWith('.archive.org'))) return false;
    return /\.wmo$/i.test(url.pathname);
  } catch {
    return false;
  }
}

async function authorizeMediaToken(token, env) {
  const local = await verifyMediaToken(token, env.MEDIA_TOKEN_SECRET || env.REGISTER_TOKEN || '');
  if (local) return local;
  if (!env.FIREBASE_API_KEY) return null;
  return verifyFirebaseIdToken(token, env.FIREBASE_API_KEY);
}

async function fetchArchiveRange(source, start, end) {
  let current = source;
  for (let redirects = 0; redirects <= 5; redirects++) {
    if (!isAllowedArchiveUrl(current)) throw new Error('redirect_host_blocked');
    const response = await fetch(current, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        'Range': `bytes=${start}-${end}`,
        'Accept': 'application/octet-stream,*/*;q=0.8',
        'User-Agent': 'WomoCloudflareMediaBridge/1.0',
      },
    });

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('Location');
      if (!location) throw new Error('invalid_redirect');
      current = new URL(location, current).toString();
      continue;
    }

    if (response.status !== 206 && response.status !== 200) {
      throw new Error(`archive_http_${response.status}`);
    }
    return response;
  }
  throw new Error('too_many_redirects');
}

async function handleRegister(request, env) {
  const token = getBearerToken(request);
  if (!token) return json({ ok: false, error: 'missing_authorization' }, 401);
  if (!env.REGISTER_TOKEN || token !== env.REGISTER_TOKEN) {
    return json({ ok: false, error: 'invalid_authorization' }, 403);
  }

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: 'invalid_json' }, 400); }

  const contentId = String(body?.contentId || '').trim();
  const key = String(body?.key || '').trim();
  if (!contentId || !key) return json({ ok: false, error: 'missing_fields' }, 400);
  if (!isUuid(contentId)) return json({ ok: false, error: 'invalid_content_id' }, 400);
  if (!isValidAesKeyBase64(key)) return json({ ok: false, error: 'invalid_key' }, 400);

  const existing = await env.DB
    .prepare('SELECT content_id FROM media_keys WHERE content_id = ? LIMIT 1')
    .bind(contentId)
    .first();
  if (existing) return json({ ok: false, error: 'content_id_already_exists' }, 409);

  const createdAt = new Date().toISOString();
  await env.DB
    .prepare('INSERT INTO media_keys (content_id, media_key, created_at) VALUES (?, ?, ?)')
    .bind(contentId, key, createdAt)
    .run();

  return json({ ok: true, contentId, registered: true, createdAt });
}

async function handlePlayback(request, env) {
  const firebaseToken = getBearerToken(request);
  if (!firebaseToken) return json({ ok: false, error: 'missing_auth_token' }, 401);
  if (!env.FIREBASE_API_KEY) return json({ ok: false, error: 'firebase_config_missing' }, 500);
  if (!env.REGISTER_TOKEN && !env.MEDIA_TOKEN_SECRET) return json({ ok: false, error: 'media_secret_missing' }, 500);

  const user = await verifyFirebaseIdToken(firebaseToken, env.FIREBASE_API_KEY);
  if (!user) return json({ ok: false, error: 'invalid_auth_token' }, 401);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: 'invalid_json' }, 400); }

  const contentId = String(body?.contentId || '').trim();
  if (!contentId) return json({ ok: false, error: 'missing_content_id' }, 400);
  if (!isUuid(contentId)) return json({ ok: false, error: 'invalid_content_id' }, 400);

  const row = await env.DB
    .prepare('SELECT media_key FROM media_keys WHERE content_id = ? LIMIT 1')
    .bind(contentId)
    .first();
  if (!row?.media_key) return json({ ok: false, error: 'content_not_found' }, 404);

  const mediaToken = await makeMediaToken(user.uid, env.MEDIA_TOKEN_SECRET || env.REGISTER_TOKEN);
  return json({ ok: true, contentId, key: row.media_key, uid: user.uid, mediaToken });
}

async function handleMedia(request, env) {
  if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);

  let body;
  try {
    const raw = await request.text();
    body = JSON.parse(raw);
  } catch {
    return json({ ok: false, error: 'invalid_json' }, 400);
  }

  const source = String(body?.url || '').trim();
  const token = String(body?.token || '').trim();
  const start = Number(body?.start);
  const end = Number(body?.end);

  if (!source) return json({ ok: false, error: 'missing_url' }, 400);
  if (!token) return json({ ok: false, error: 'missing_auth_token' }, 401);
  if (!Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(end) || end < start) {
    return json({ ok: false, error: 'invalid_range' }, 416);
  }
  if (!isAllowedArchiveUrl(source)) return json({ ok: false, error: 'unsupported_media_host' }, 400);

  const authorized = await authorizeMediaToken(token, env);
  if (!authorized) return json({ ok: false, error: 'invalid_auth_token' }, 401);

  let upstream;
  try {
    upstream = await fetchArchiveRange(source, start, end);
  } catch (error) {
    return json({ ok: false, error: String(error?.message || error || 'archive_request_failed') }, 502);
  }

  if (upstream.status !== 206) {
    // A full-file 200 response defeats range streaming and could consume large amounts of memory/bandwidth.
    return json({ ok: false, error: 'archive_range_not_supported' }, 502);
  }

  const headers = new Headers(corsHeaders);
  headers.set('Content-Type', upstream.headers.get('Content-Type') || 'application/octet-stream');
  headers.set('Accept-Ranges', 'bytes');
  headers.set('Cache-Control', 'private, no-store');
  for (const name of ['Content-Range', 'Content-Length', 'ETag']) {
    const value = upstream.headers.get(name);
    if (value) headers.set(name, value);
  }

  return new Response(upstream.body, { status: 206, headers });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/') {
      return json({ ok: true, service: 'womo-media-api', version: 2, mediaBridge: 'cloudflare' });
    }
    if (request.method === 'GET' && url.pathname === '/health') {
      try {
        await env.DB.prepare('SELECT 1 AS ok').first();
        return json({ ok: true, database: 'connected', mediaBridge: 'ready' });
      } catch {
        return json({ ok: false, database: 'unavailable' }, 500);
      }
    }
    if (request.method === 'POST' && url.pathname === '/register') return handleRegister(request, env);
    if (request.method === 'POST' && url.pathname === '/playback') return handlePlayback(request, env);
    if (request.method === 'POST' && url.pathname === '/media') return handleMedia(request, env);
    return json({ ok: false, error: 'not_found' }, 404);
  },
};
