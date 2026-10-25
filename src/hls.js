const HLS_TOKEN_TTL_SECONDS = 2 * 60 * 60;
const HEADER_SIZE = 256;

const hlsCorsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,HEAD,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, Range',
  'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges, Content-Type',
  'Cache-Control': 'private, no-store',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...hlsCorsHeaders, 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function getBearerToken(request) {
  const match = (request.headers.get('Authorization') || '').match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

function isAllowedArchiveUrl(value) {
  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase();
    return url.protocol === 'https:'
      && (host === 'archive.org' || host === 'www.archive.org' || host.endsWith('.archive.org'))
      && /\.wmo$/i.test(url.pathname);
  } catch {
    return false;
  }
}

function base64UrlEncodeBytes(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
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
    return new TextDecoder().decode(Uint8Array.from(binary, char => char.charCodeAt(0)));
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
  return base64UrlEncodeBytes(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value))));
}

async function makeHlsToken(claims, secret) {
  const payload = base64UrlEncodeString(JSON.stringify({
    ...claims,
    exp: Math.floor(Date.now() / 1000) + HLS_TOKEN_TTL_SECONDS,
  }));
  return `wmo3.${payload}.${await hmacSign(payload, secret)}`;
}

async function verifyHlsToken(token, secret) {
  if (!token || !secret || !token.startsWith('wmo3.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'wmo3') return null;
  if (await hmacSign(parts[1], secret) !== parts[2]) return null;
  try {
    const claims = JSON.parse(base64UrlDecodeString(parts[1]));
    if (!claims?.uid || !claims?.contentId || !claims?.source) return null;
    if (!isUuid(claims.contentId) || !isAllowedArchiveUrl(claims.source)) return null;
    if (Number(claims.exp || 0) < Math.floor(Date.now() / 1000)) return null;
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
  return user?.localId ? { uid: user.localId } : null;
}

async function fetchArchiveRange(source, start, end) {
  let current = source;
  for (let redirects = 0; redirects <= 5; redirects++) {
    if (!isAllowedArchiveUrl(current)) throw new Error('redirect_host_blocked');
    const response = await fetch(current, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        Range: `bytes=${start}-${end}`,
        Accept: 'application/octet-stream,*/*;q=0.8',
        'User-Agent': 'WomoCloudflareHLS/1.0',
      },
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('Location');
      if (!location) throw new Error('invalid_redirect');
      current = new URL(location, current).toString();
      continue;
    }
    if (response.status !== 206) throw new Error(`archive_range_http_${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  }
  throw new Error('too_many_redirects');
}

function readU16LE(bytes, offset) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset, true);
}

function readU32LE(bytes, offset) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
}

function readU64LE(bytes, offset) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const low = view.getUint32(offset, true);
  const high = view.getUint32(offset + 4, true);
  const value = high * 0x100000000 + low;
  if (!Number.isSafeInteger(value)) throw new Error('wmo_integer_out_of_range');
  return value;
}

function readDoubleLE(bytes, offset) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getFloat64(offset, true);
}

function ascii(bytes, start, length) {
  return new TextDecoder().decode(bytes.slice(start, start + length));
}

function uuidFromBytes(bytes) {
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32)].join('-');
}

function parseHeader(bytes) {
  if (bytes.length < HEADER_SIZE || ascii(bytes, 0, 4) !== 'WMO1') throw new Error('invalid_wmo_header');
  const version = bytes[4];
  const flags = bytes[5];
  if (version !== 3 || readU16LE(bytes, 6) !== HEADER_SIZE || (flags & 1) !== 1) {
    throw new Error('unsupported_wmo_version');
  }
  const contentId = uuidFromBytes(bytes.slice(16, 32));
  const header = {
    version,
    contentId,
    chunkCount: readU32LE(bytes, 44),
    indexOffset: readU64LE(bytes, 48),
    indexSize: readU64LE(bytes, 56),
    duration: readDoubleLE(bytes, 64),
  };
  if (!isUuid(contentId) || !header.chunkCount || !header.indexOffset || !header.indexSize) {
    throw new Error('invalid_wmo_header');
  }
  return header;
}

function parseIndex(bytes, header) {
  if (bytes.length < 12 || ascii(bytes, 0, 4) !== 'WIDX') throw new Error('invalid_wmo_index');
  const version = readU32LE(bytes, 4);
  const count = readU32LE(bytes, 8);
  if (version !== 3 || count !== header.chunkCount || bytes.length < 12 + count * 40) {
    throw new Error('invalid_wmo_index');
  }
  const segments = [];
  let cursor = 12;
  for (let index = 0; index < count; index++, cursor += 40) {
    const segment = {
      index,
      chunkIndex: readU32LE(bytes, cursor),
      type: bytes[cursor + 4],
      offset: readU64LE(bytes, cursor + 8),
      totalLength: readU32LE(bytes, cursor + 16),
      plainLength: readU32LE(bytes, cursor + 20),
      startTime: readDoubleLE(bytes, cursor + 24),
      duration: readDoubleLE(bytes, cursor + 32),
    };
    if (!segment.totalLength || segment.type > 3) throw new Error('invalid_wmo_segment');
    segments.push(segment);
  }
  const inferredDuration = segments.reduce((end, item) => Math.max(end, item.startTime + item.duration), 0);
  return {
    version,
    contentId: header.contentId,
    duration: header.duration > 0 ? header.duration : inferredDuration,
    segments,
  };
}

async function manifestCacheKey(contentId, source) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(source)));
  return new Request(`https://womo-hls-cache.invalid/${contentId}/${base64UrlEncodeBytes(digest)}`);
}

async function putManifestCache(manifest, source) {
  try {
    const key = await manifestCacheKey(manifest.contentId, source);
    await caches.default.put(key, new Response(JSON.stringify(manifest), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': `public, max-age=${HLS_TOKEN_TTL_SECONDS}` },
    }));
  } catch {}
}

async function getManifestCache(contentId, source) {
  try {
    const cached = await caches.default.match(await manifestCacheKey(contentId, source));
    return cached ? await cached.json() : null;
  } catch {
    return null;
  }
}

async function loadManifest(source, claims = null) {
  if (claims?.contentId) {
    const cached = await getManifestCache(claims.contentId, source);
    if (cached?.segments?.length) return cached;
  }
  const headerBytes = await fetchArchiveRange(source, 0, HEADER_SIZE - 1);
  const header = parseHeader(headerBytes);
  if (claims?.contentId && claims.contentId !== header.contentId) throw new Error('wmo_content_mismatch');
  const indexBytes = await fetchArchiveRange(source, header.indexOffset, header.indexOffset + header.indexSize - 1);
  const manifest = parseIndex(indexBytes, header);
  await putManifestCache(manifest, source);
  return manifest;
}

function decodeAesKey(value) {
  const clean = String(value || '').trim();
  if (/^[0-9a-f]{64}$/i.test(clean)) {
    return Uint8Array.from(clean.match(/.{2}/g), pair => parseInt(pair, 16));
  }
  try {
    const normalized = clean.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
    const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
    if (bytes.length === 32) return bytes;
  } catch {}
  throw new Error('invalid_wmo_key');
}

async function decryptSegment(encrypted, segment, keyValue) {
  if (encrypted.length < 40) throw new Error('incomplete_wmo_chunk');
  const storedIndex = readU32LE(encrypted, 0);
  const plainLength = readU32LE(encrypted, 4);
  const encryptedLength = readU32LE(encrypted, 8);
  if (storedIndex !== segment.chunkIndex || plainLength !== segment.plainLength || encrypted.length < 40 + encryptedLength) {
    throw new Error('wmo_chunk_metadata_mismatch');
  }
  const nonce = encrypted.slice(12, 24);
  const tag = encrypted.slice(24, 40);
  const cipherText = encrypted.slice(40, 40 + encryptedLength);
  const sealed = new Uint8Array(cipherText.length + tag.length);
  sealed.set(cipherText, 0);
  sealed.set(tag, cipherText.length);
  const aad = new Uint8Array(4);
  new DataView(aad.buffer).setUint32(0, segment.chunkIndex, true);
  const key = await crypto.subtle.importKey('raw', decodeAesKey(keyValue), 'AES-GCM', false, ['decrypt']);
  const plain = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
    key,
    sealed
  ));
  if (plain.length !== plainLength) throw new Error('wmo_plain_size_mismatch');
  return normalizeFragment(plain, segment.type);
}

function readU32BE(bytes, offset) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);
}

function topLevelBoxes(bytes) {
  const boxes = [];
  let offset = 0;
  while (offset + 8 <= bytes.length) {
    let size = readU32BE(bytes, offset);
    const name = ascii(bytes, offset + 4, 4);
    let headerSize = 8;
    if (size === 1) {
      if (offset + 16 > bytes.length) break;
      const high = readU32BE(bytes, offset + 8);
      const low = readU32BE(bytes, offset + 12);
      size = high * 0x100000000 + low;
      headerSize = 16;
    } else if (size === 0) {
      size = bytes.length - offset;
    }
    if (!Number.isSafeInteger(size) || size < headerSize || offset + size > bytes.length) break;
    boxes.push({ name, start: offset, end: offset + size });
    offset += size;
  }
  return boxes;
}

function cmafStypBox() {
  return Uint8Array.from([
    0, 0, 0, 24, 115, 116, 121, 112, 109, 115, 100, 104,
    0, 0, 0, 0, 109, 115, 100, 104, 109, 115, 105, 120,
  ]);
}

function concatBytes(parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function normalizeFragment(bytes, type) {
  if (type !== 1 && type !== 3) return bytes;
  const boxes = topLevelBoxes(bytes);
  if (!boxes.length) return bytes;
  const withoutSidx = boxes.filter(box => box.name !== 'sidx').map(box => bytes.slice(box.start, box.end));
  let normalized = withoutSidx.length === boxes.length ? bytes : concatBytes(withoutSidx);
  const first = topLevelBoxes(normalized)[0]?.name;
  if (first === 'moof') normalized = concatBytes([cmafStypBox(), normalized]);
  return normalized;
}

function mediaPlaylist(manifest, mediaType, initName, prefix) {
  const entries = manifest.segments.filter(item => item.type === mediaType).sort((a, b) => a.startTime - b.startTime);
  const maxDuration = Math.max(1, Math.ceil(entries.reduce((max, item) => Math.max(max, item.duration || 0.1), 0)));
  const lines = [
    '#EXTM3U',
    '#EXT-X-VERSION:7',
    `#EXT-X-TARGETDURATION:${maxDuration}`,
    '#EXT-X-MEDIA-SEQUENCE:0',
    '#EXT-X-PLAYLIST-TYPE:VOD',
    '#EXT-X-INDEPENDENT-SEGMENTS',
    `#EXT-X-MAP:URI="${initName}"`,
  ];
  for (const segment of entries) {
    lines.push(`#EXTINF:${Math.max(0.001, Number(segment.duration || 0)).toFixed(6)},`);
    lines.push(`${prefix}-${segment.index}.m4s`);
  }
  lines.push('#EXT-X-ENDLIST', '');
  return lines.join('\n');
}

function masterPlaylist(manifest) {
  const hasAudio = manifest.segments.some(item => item.type === 2)
    && manifest.segments.some(item => item.type === 3);
  const videoPeak = manifest.segments
    .filter(item => item.type === 1 && item.duration > 0)
    .reduce((peak, item) => Math.max(peak, item.totalLength * 8 / item.duration), 0);
  const audioPeak = manifest.segments
    .filter(item => item.type === 3 && item.duration > 0)
    .reduce((peak, item) => Math.max(peak, item.totalLength * 8 / item.duration), 0);
  const bandwidth = Math.max(1000000, Math.ceil((videoPeak + audioPeak) * 1.2));
  const lines = ['#EXTM3U', '#EXT-X-VERSION:7'];
  if (hasAudio) lines.push('#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",NAME="Main",DEFAULT=YES,AUTOSELECT=YES,URI="audio.m3u8"');
  lines.push(`#EXT-X-STREAM-INF:BANDWIDTH=${bandwidth}${hasAudio ? ',AUDIO="audio"' : ''}`);
  lines.push('video.m3u8', '');
  return lines.join('\n');
}

function textResponse(value, contentType, request) {
  const bytes = new TextEncoder().encode(value);
  return bytesResponse(bytes, contentType, request);
}

function bytesResponse(bytes, contentType, request) {
  const headers = new Headers(hlsCorsHeaders);
  headers.set('Content-Type', contentType);
  headers.set('Accept-Ranges', 'bytes');
  let body = bytes;
  let status = 200;
  const range = request.headers.get('Range') || '';
  const match = range.match(/^bytes=(\d+)-(\d*)$/i);
  if (match) {
    const start = Number(match[1]);
    const end = match[2] ? Math.min(bytes.length - 1, Number(match[2])) : bytes.length - 1;
    if (!Number.isSafeInteger(start) || start < 0 || start >= bytes.length || end < start) {
      headers.set('Content-Range', `bytes */${bytes.length}`);
      return new Response(null, { status: 416, headers });
    }
    body = bytes.slice(start, end + 1);
    status = 206;
    headers.set('Content-Range', `bytes ${start}-${end}/${bytes.length}`);
  }
  headers.set('Content-Length', String(body.length));
  return new Response(request.method === 'HEAD' ? null : body, { status, headers });
}

async function keyForContent(env, contentId) {
  const row = await env.DB
    .prepare('SELECT media_key FROM media_keys WHERE content_id = ? LIMIT 1')
    .bind(contentId)
    .first();
  if (!row?.media_key) throw new Error('content_not_found');
  return row.media_key;
}

export async function handleHlsSession(request, env) {
  if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);
  const firebaseToken = getBearerToken(request);
  if (!firebaseToken) return json({ ok: false, error: 'missing_auth_token' }, 401);
  if (!env.FIREBASE_API_KEY) return json({ ok: false, error: 'firebase_config_missing' }, 500);
  const secret = env.MEDIA_TOKEN_SECRET || env.REGISTER_TOKEN || '';
  if (!secret) return json({ ok: false, error: 'media_secret_missing' }, 500);
  const user = await verifyFirebaseIdToken(firebaseToken, env.FIREBASE_API_KEY);
  if (!user) return json({ ok: false, error: 'invalid_auth_token' }, 401);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: 'invalid_json' }, 400); }
  const source = String(body?.url || '').trim();
  if (!isAllowedArchiveUrl(source)) return json({ ok: false, error: 'unsupported_media_host' }, 400);

  try {
    const manifest = await loadManifest(source);
    await keyForContent(env, manifest.contentId);
    const token = await makeHlsToken({ uid: user.uid, source, contentId: manifest.contentId }, secret);
    const origin = new URL(request.url).origin;
    return json({
      ok: true,
      contentId: manifest.contentId,
      duration: manifest.duration,
      expiresIn: HLS_TOKEN_TTL_SECONDS,
      masterUrl: `${origin}/hls/${token}/master.m3u8`,
    });
  } catch (error) {
    const message = String(error?.message || error || 'hls_session_failed');
    const status = message === 'content_not_found' ? 404 : 502;
    return json({ ok: false, error: message }, status);
  }
}

export async function handleHlsRequest(request, env, url) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return json({ ok: false, error: 'method_not_allowed' }, 405);
  const match = url.pathname.match(/^\/hls\/([^/]+)\/([^/]+)$/);
  if (!match) return json({ ok: false, error: 'not_found' }, 404);
  const secret = env.MEDIA_TOKEN_SECRET || env.REGISTER_TOKEN || '';
  const claims = await verifyHlsToken(match[1], secret);
  if (!claims) return json({ ok: false, error: 'invalid_or_expired_hls_token' }, 401);
  const name = match[2].toLowerCase();

  try {
    const manifest = await loadManifest(claims.source, claims);
    if (name === 'master.m3u8') return textResponse(masterPlaylist(manifest), 'application/vnd.apple.mpegurl', request);
    if (name === 'video.m3u8') return textResponse(mediaPlaylist(manifest, 1, 'video-init.mp4', 'video'), 'application/vnd.apple.mpegurl', request);
    if (name === 'audio.m3u8') return textResponse(mediaPlaylist(manifest, 3, 'audio-init.mp4', 'audio'), 'application/vnd.apple.mpegurl', request);

    let segment = null;
    let contentType = 'application/octet-stream';
    if (name === 'video-init.mp4') {
      segment = manifest.segments.find(item => item.type === 0);
      contentType = 'video/mp4';
    } else if (name === 'audio-init.mp4') {
      segment = manifest.segments.find(item => item.type === 2);
      contentType = 'audio/mp4';
    } else {
      const mediaMatch = name.match(/^(video|audio)-(\d+)\.m4s$/);
      if (mediaMatch) {
        const index = Number(mediaMatch[2]);
        const expectedType = mediaMatch[1] === 'video' ? 1 : 3;
        segment = manifest.segments.find(item => item.index === index && item.type === expectedType);
        contentType = mediaMatch[1] === 'video' ? 'video/iso.segment' : 'audio/iso.segment';
      }
    }
    if (!segment) return json({ ok: false, error: 'segment_not_found' }, 404);
    const encrypted = await fetchArchiveRange(claims.source, segment.offset, segment.offset + segment.totalLength - 1);
    const clear = await decryptSegment(encrypted, segment, await keyForContent(env, claims.contentId));
    return bytesResponse(clear, contentType, request);
  } catch (error) {
    return json({ ok: false, error: String(error?.message || error || 'hls_request_failed') }, 502);
  }
}

export const __test = { parseHeader, parseIndex, normalizeFragment, mediaPlaylist, masterPlaylist };
