/**
 * GitHub Scout — сервер мини-аппки
 * Node 18+, ноль зависимостей. Отдаёт и API, и статику (public/index.html).
 *
 * Переменные окружения:
 *   BOT_TOKEN        токен бота из @BotFather        (обязательно в проде)
 *   CHANNEL          канал для гейта, напр. @codrng  (по умолчанию @codrng)
 *   OWNER_ID         Telegram ID владельца           (для Private Studio)
 *   GITHUB_TOKEN     PAT только с public_repo/без скоупов (поднимает лимит до 30 req/min)
 *   SESSION_SECRET   любая длинная строка            (иначе генерится при старте)
 *   ALLOW_ORIGIN     домен фронта, если он отдельно  (по умолчанию same-origin)
 *   PORT             порт                            (по умолчанию 3000)
 *
 * Если BOT_TOKEN не задан — сервер стартует в DEV-режиме: гейт пропускает всех,
 * права владельца не выдаются. В проде BOT_TOKEN обязателен, иначе доступ закрыт.
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const BOT_TOKEN = process.env.BOT_TOKEN || '';
const CHANNEL = process.env.CHANNEL || '@codrng';
const OWNER_ID = Number(process.env.OWNER_ID || 0);
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || '';
const PORT = Number(process.env.PORT || 3000);
const DEV = !BOT_TOKEN;

const SESSION_TTL = 60 * 60;          // 1 час
const INITDATA_MAX_AGE = 24 * 60 * 60; // Telegram рекомендует не старше суток
const SUB_CACHE_TTL = 60 * 1000;       // не дёргать getChatMember чаще раза в минуту на юзера
const GH_CACHE_TTL = 12 * 60 * 1000;   // кэш выдачи GitHub

if (DEV) {
  console.warn('[scout] BOT_TOKEN не задан — DEV-режим, гейт подписки отключён.');
}

/* ---------------------------------------------------------- helpers */

const b64url = (buf) =>
  Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const fromB64url = (str) =>
  Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');

function signSession(payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = b64url(crypto.createHmac('sha256', SESSION_SECRET).update(body).digest());
  return body + '.' + sig;
}

function verifySession(token) {
  if (!token || typeof token !== 'string' || token.indexOf('.') < 0) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expected = b64url(crypto.createHmac('sha256', SESSION_SECRET).update(body).digest());
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let payload;
  try { payload = JSON.parse(fromB64url(body)); } catch (e) { return null; }
  if (!payload || payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

/**
 * Проверка подписи initData по алгоритму Telegram.
 * Именно это, а не initDataUnsafe, является единственным доказательством личности.
 */
function validateInitData(initData) {
  if (!initData || typeof initData !== 'string') return null;
  let params;
  try { params = new URLSearchParams(initData); } catch (e) { return null; }

  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');
  params.delete('signature');

  const checkString = [...params.entries()]
    .sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0))
    .map(([k, v]) => k + '=' + v)
    .join('\n');

  const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const calc = crypto.createHmac('sha256', secret).update(checkString).digest('hex');

  const a = Buffer.from(calc, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  const authDate = Number(params.get('auth_date') || 0);
  if (!authDate || Math.floor(Date.now() / 1000) - authDate > INITDATA_MAX_AGE) return null;

  try { return JSON.parse(params.get('user') || 'null'); } catch (e) { return null; }
}

/* ------------------------------------------------- subscription check */

const subCache = new Map(); // userId -> { value, at }

async function isSubscribed(userId) {
  const hit = subCache.get(userId);
  if (hit && Date.now() - hit.at < SUB_CACHE_TTL) return hit.value;

  const url = 'https://api.telegram.org/bot' + BOT_TOKEN + '/getChatMember'
    + '?chat_id=' + encodeURIComponent(CHANNEL)
    + '&user_id=' + encodeURIComponent(userId);

  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(6000) });
    const data = await res.json();
    if (!data.ok) {
      // Бот не админ канала или канал не найден — фейлимся закрыто, но громко.
      console.error('[scout] getChatMember:', data.description);
      return false;
    }
    const status = data.result && data.result.status;
    const value = ['creator', 'administrator', 'member'].indexOf(status) > -1;
    subCache.set(userId, { value, at: Date.now() });
    return value;
  } catch (e) {
    console.error('[scout] getChatMember failed:', e.message);
    return false;
  }
}

/* --------------------------------------------------------- rate limit */

const buckets = new Map(); // ip -> { count, reset }

function rateLimited(ip, limit = 60, windowMs = 60000) {
  const now = Date.now();
  const b = buckets.get(ip);
  if (!b || now > b.reset) {
    buckets.set(ip, { count: 1, reset: now + windowMs });
    return false;
  }
  b.count += 1;
  return b.count > limit;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) if (now > v.reset) buckets.delete(k);
  for (const [k, v] of subCache) if (now - v.at > SUB_CACHE_TTL * 5) subCache.delete(k);
}, 60000).unref();

/* ------------------------------------------------------- github proxy */

const ghCache = new Map(); // key -> { at, status, body }

async function githubSearch(query) {
  const key = query;
  const hit = ghCache.get(key);
  if (hit && Date.now() - hit.at < GH_CACHE_TTL) {
    return { status: 200, body: hit.body, cached: true, at: hit.at };
  }

  const headers = {
    accept: 'application/vnd.github+json',
    'user-agent': 'github-scout-miniapp'
  };
  if (GITHUB_TOKEN) headers.authorization = 'Bearer ' + GITHUB_TOKEN;

  const res = await fetch(
    'https://api.github.com/search/repositories?' + query,
    { headers, signal: AbortSignal.timeout(9000) }
  );

  if (res.status === 403 || res.status === 429) {
    // Лимит исчерпан. Если есть протухший кэш — лучше он, чем пустота.
    if (hit) return { status: 200, body: hit.body, cached: true, stale: true, at: hit.at };
    return { status: 429, body: { error: 'rate_limited', message: 'GitHub исчерпал лимит, попробуй через минуту' } };
  }
  if (!res.ok) {
    if (hit) return { status: 200, body: hit.body, cached: true, stale: true, at: hit.at };
    return { status: 502, body: { error: 'upstream', message: 'GitHub ответил ' + res.status } };
  }

  const json = await res.json();
  const body = { items: (json.items || []).slice(0, 30) };
  ghCache.set(key, { at: Date.now(), body });
  if (ghCache.size > 200) ghCache.delete(ghCache.keys().next().value);
  return { status: 200, body, cached: false, at: Date.now() };
}

/* -------------------------------------------------------------- http */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8'
};

function cors(res) {
  if (ALLOW_ORIGIN) {
    res.setHeader('access-control-allow-origin', ALLOW_ORIGIN);
    res.setHeader('access-control-allow-headers', 'content-type,x-scout-session');
    res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS');
    res.setHeader('vary', 'origin');
  }
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(body);
}

function readBody(req, limit = 16 * 1024) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > limit) { reject(new Error('too large')); req.destroy(); }
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  return (fwd ? String(fwd).split(',')[0] : req.socket.remoteAddress || '').trim();
}

/** Общая точка входа: валидируем initData, строим сессию. */
async function buildSession(initData) {
  if (DEV) {
    return {
      dev: true,
      subscribed: true,
      user: null,
      features: { privateStudio: false },
      token: signSession({ uid: 0, dev: true, owner: false, exp: Math.floor(Date.now() / 1000) + SESSION_TTL })
    };
  }

  const user = validateInitData(initData);
  if (!user) return { error: 'bad_init_data' };

  const subscribed = await isSubscribed(user.id);
  const owner = OWNER_ID > 0 && user.id === OWNER_ID;

  return {
    dev: false,
    subscribed,
    user: { id: user.id, first_name: user.first_name, username: user.username },
    features: { privateStudio: subscribed && owner },
    token: subscribed
      ? signSession({ uid: user.id, owner, exp: Math.floor(Date.now() / 1000) + SESSION_TTL })
      : null
  };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
  const route = url.pathname;

  cors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  if (route.startsWith('/api/')) {
    if (rateLimited(clientIp(req))) {
      return send(res, 429, { error: 'rate_limited', message: 'Слишком много запросов' });
    }
  }

  /* ---- health ---- */
  if (route === '/api/health') {
    return send(res, 200, { ok: true, dev: DEV, channel: CHANNEL, github: GITHUB_TOKEN ? 'token' : 'anonymous' });
  }

  /* ---- сессия: подпись initData + проверка подписки одним запросом ---- */
  if (route === '/api/session' && req.method === 'POST') {
    let body;
    try { body = await readBody(req); } catch (e) { return send(res, 400, { error: 'bad_body' }); }
    const session = await buildSession(body.initData);
    if (session.error) return send(res, 401, session);
    return send(res, 200, session);
  }

  /* ---- совместимость со старым клиентом ---- */
  if (route === '/api/check-subscription' && req.method === 'POST') {
    let body;
    try { body = await readBody(req); } catch (e) { return send(res, 400, { error: 'bad_body' }); }
    const session = await buildSession(body.initData);
    if (session.error) return send(res, 401, { subscribed: false });
    return send(res, 200, { subscribed: session.subscribed });
  }

  /* ---- права владельца: решает только сервер ---- */
  if (route === '/api/entitlement' && req.method === 'POST') {
    let body;
    try { body = await readBody(req); } catch (e) { return send(res, 400, { error: 'bad_body' }); }

    if (body.token) {
      const s = verifySession(body.token);
      if (!s) return send(res, 401, { error: 'bad_session' });
      return send(res, 200, { features: { privateStudio: !!s.owner } });
    }
    const session = await buildSession(body.initData);
    if (session.error) return send(res, 401, session);
    return send(res, 200, { features: session.features });
  }

  /* ---- прокси GitHub с кэшем ---- */
  if (route === '/api/github/search' && req.method === 'GET') {
    const s = verifySession(req.headers['x-scout-session']);
    if (!s) return send(res, 401, { error: 'no_session', message: 'Сессия истекла, перезапусти аппку' });

    const q = (url.searchParams.get('q') || '').slice(0, 200);
    if (!q) return send(res, 400, { error: 'no_query' });

    const sort = ['stars', 'forks', 'updated'].indexOf(url.searchParams.get('sort')) > -1
      ? url.searchParams.get('sort') : 'stars';
    const perPage = Math.min(30, Math.max(1, Number(url.searchParams.get('per_page') || 20)));
    const query = 'q=' + encodeURIComponent(q) + '&sort=' + sort + '&order=desc&per_page=' + perPage;

    try {
      const out = await githubSearch(query);
      if (out.status !== 200) return send(res, out.status, out.body);
      return send(res, 200, {
        items: out.body.items,
        cached: !!out.cached,
        stale: !!out.stale,
        fetched_at: out.at
      });
    } catch (e) {
      return send(res, 502, { error: 'upstream', message: 'GitHub недоступен' });
    }
  }

  if (route.startsWith('/api/')) return send(res, 404, { error: 'not_found' });

  /* ---- статика ---- */
  const rel = route === '/' ? 'index.html' : route.replace(/^\/+/, '');
  const file = path.join(__dirname, 'public', path.normalize(rel).replace(/^(\.\.[/\\])+/, ''));

  fs.readFile(file, (err, data) => {
    if (err) {
      fs.readFile(path.join(__dirname, 'public', 'index.html'), (e2, html) => {
        if (e2) { res.writeHead(404); return res.end('not found'); }
        res.writeHead(200, { 'content-type': MIME['.html'] });
        res.end(html);
      });
      return;
    }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, {
      'content-type': MIME[ext] || 'application/octet-stream',
      'cache-control': ext === '.html' ? 'no-cache' : 'public, max-age=3600'
    });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log('[scout] слушаю :' + PORT + (DEV ? ' (DEV)' : ' · канал ' + CHANNEL));
});
