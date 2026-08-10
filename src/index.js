const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Cache-Control': 'no-store',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
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

  return {
    uid: user.localId,
    email: user.email || null,
  };
}

async function handleRegister(request, env) {
  const token = getBearerToken(request);

  if (!token) {
    return json({ ok: false, error: 'missing_authorization' }, 401);
  }

  if (!env.REGISTER_TOKEN || token !== env.REGISTER_TOKEN) {
    return json({ ok: false, error: 'invalid_authorization' }, 403);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'invalid_json' }, 400);
  }

  const contentId = String(body?.contentId || '').trim();
  const key = String(body?.key || '').trim();

  if (!contentId || !key) {
    return json({ ok: false, error: 'missing_fields' }, 400);
  }

  if (!isUuid(contentId)) {
    return json({ ok: false, error: 'invalid_content_id' }, 400);
  }

  if (!isValidAesKeyBase64(key)) {
    return json({ ok: false, error: 'invalid_key' }, 400);
  }

  const existing = await env.DB
    .prepare('SELECT content_id FROM media_keys WHERE content_id = ? LIMIT 1')
    .bind(contentId)
    .first();

  if (existing) {
    return json({ ok: false, error: 'content_id_already_exists' }, 409);
  }

  const createdAt = new Date().toISOString();

  await env.DB
    .prepare('INSERT INTO media_keys (content_id, media_key, created_at) VALUES (?, ?, ?)')
    .bind(contentId, key, createdAt)
    .run();

  return json({
    ok: true,
    contentId,
    registered: true,
    createdAt,
  });
}

async function handlePlayback(request, env) {
  const firebaseToken = getBearerToken(request);

  if (!firebaseToken) {
    return json({ ok: false, error: 'missing_auth_token' }, 401);
  }

  if (!env.FIREBASE_API_KEY) {
    return json({ ok: false, error: 'firebase_config_missing' }, 500);
  }

  const user = await verifyFirebaseIdToken(firebaseToken, env.FIREBASE_API_KEY);

  if (!user) {
    return json({ ok: false, error: 'invalid_auth_token' }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'invalid_json' }, 400);
  }

  const contentId = String(body?.contentId || '').trim();

  if (!contentId) {
    return json({ ok: false, error: 'missing_content_id' }, 400);
  }

  if (!isUuid(contentId)) {
    return json({ ok: false, error: 'invalid_content_id' }, 400);
  }

  const row = await env.DB
    .prepare('SELECT media_key FROM media_keys WHERE content_id = ? LIMIT 1')
    .bind(contentId)
    .first();

  if (!row?.media_key) {
    return json({ ok: false, error: 'content_not_found' }, 404);
  }

  return json({
    ok: true,
    contentId,
    key: row.media_key,
    uid: user.uid,
  });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/') {
      return json({
        ok: true,
        service: 'womo-media-api',
        version: 1,
      });
    }

    if (request.method === 'GET' && url.pathname === '/health') {
      try {
        await env.DB.prepare('SELECT 1 AS ok').first();
        return json({ ok: true, database: 'connected' });
      } catch {
        return json({ ok: false, database: 'unavailable' }, 500);
      }
    }

    if (request.method === 'POST' && url.pathname === '/register') {
      return handleRegister(request, env);
    }

    if (request.method === 'POST' && url.pathname === '/playback') {
      return handlePlayback(request, env);
    }

    return json({ ok: false, error: 'not_found' }, 404);
  },
};
