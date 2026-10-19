// Starfall backend - stage 1: signup, login, sessions
// Env vars (set them in Render -> Environment):
//   TURSO_URL    e.g. libsql://your-db.aws-eu-west-1.turso.io   (for local tests: file:local.db)
//   TURSO_TOKEN  a NEW token (rotate the old one - it was public in the HTML files)
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createClient } from '@libsql/client';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
if (!process.env.TURSO_URL) { console.error('TURSO_URL is not set'); process.exit(1); }
// Render values pasted with quotes, spaces or a trailing newline silently break the connection, so clean them first
const cleanEnv = (v) => String(v || '').trim().replace(/^["']+|["']+$/g, '').trim();
const TURSO_URL = cleanEnv(process.env.TURSO_URL), TURSO_TOKEN = cleanEnv(process.env.TURSO_TOKEN);
console.log(`Turso config: url host = ${TURSO_URL.replace(/^[a-z+]+:\/\//i, '').split(/[/?]/)[0] || '(empty)'}, token ${TURSO_TOKEN ? 'present (' + TURSO_TOKEN.length + ' chars)' : 'MISSING'}`);
if (!TURSO_URL.startsWith('file:') && !TURSO_TOKEN) console.error('TURSO_TOKEN is missing - every database call will fail');
const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN || undefined });
// A local database file (development / tests) may be opened by other tools at the same time: wait for their locks instead of failing, and use WAL so readers never block the writer.
if (TURSO_URL.startsWith('file:')) { try { await db.execute('PRAGMA busy_timeout = 8000'); await db.execute('PRAGMA journal_mode = WAL'); } catch (e) { console.warn('could not tune the local database file:', e.message); } }

const app = express();
// Express 4 does not catch errors thrown inside async routes: one failed database call used to crash the whole server
// (Render then answers 502 without CORS headers, which the browser reports as a CORS error). Every handler is wrapped so errors become JSON 500s.
for (const m of ['get', 'post', 'delete']) {
  const orig = app[m].bind(app);
  app[m] = (p, ...handlers) => orig(p, ...handlers.map(h => (typeof h === 'function' && h.length < 4) ? (req, res, next) => Promise.resolve(h(req, res, next)).catch(next) : h));
}
// numeric id from a URL: digits only (max 15), otherwise 0, which matches nothing. Number('abc') = NaN and Number('Infinity') make the database driver throw.
const pid = (req) => { const raw = String((req.params && req.params.id) ?? ''); return /^\d{1,15}$/.test(raw) ? Number(raw) : 0; };
// A process that has hit an uncaught exception / unhandled rejection is in an unknown state (half-finished writes, leaked locks).
// Log it, flush what is safe to flush, and EXIT so the host (Render, systemd, pm2, Docker...) restarts a clean process.
// Route handlers are all wrapped above, so this only fires for real bugs in background jobs or in the runtime itself.
let fatalExiting = false;
function fatal(kind, e) {
  if (fatalExiting) return;
  fatalExiting = true;
  try { console.error(`FATAL ${kind}:`, (e && e.stack) || e); } catch (_) {}
  const hard = setTimeout(() => process.exit(1), 3000);       // never hang while shutting down
  if (hard.unref) hard.unref();
  Promise.resolve().then(() => flushRateHits()).catch(() => {}).finally(() => process.exit(1));
}
process.on('uncaughtException', (e) => fatal('uncaughtException', e));
process.on('unhandledRejection', (e) => fatal('unhandledRejection', e));
app.disable('x-powered-by');
// Configure the exact number of trusted reverse-proxy hops for your deployment.
// Render normally uses one proxy hop; never set this to true (trust every proxy).
const TRUST_PROXY_HOPS = Number.parseInt(process.env.TRUST_PROXY_HOPS || '1', 10);
if (!Number.isInteger(TRUST_PROXY_HOPS) || TRUST_PROXY_HOPS < 0 || TRUST_PROXY_HOPS > 5) throw new Error('TRUST_PROXY_HOPS must be an integer from 0 to 5');
app.set('trust proxy', TRUST_PROXY_HOPS);
// uploads (chat pictures, listing photos, avatars) are ~100-700 KB as base64; everything else stays at 50 KB
const keepRaw = (req, res, buf) => { if (req.originalUrl.startsWith('/api/webhooks/')) req.rawBody = buf; };   // payment webhooks are signed over the exact raw bytes
const bigJson = express.json({ limit: '1mb', verify: keepRaw });
const smallJson = express.json({ limit: '50kb', verify: keepRaw });
const BIG_BODY_PATHS = new Set(['/api/chat/image', '/api/items', '/api/profile']);
app.use((req, res, next) => (BIG_BODY_PATHS.has(req.path) ? bigJson : smallJson)(req, res, next));
app.use(cookieParser());
// If the browser sends several "sid" cookies (an old one from an earlier version next to the new one), cookie-parser keeps only the first,
// which can be the stale one. Use whichever one belongs to a live session.
app.use(async (req, res, next) => {
  try {
    // Fallback for browsers that refuse third-party cookies (the page on GitHub, the API on Render): the page keeps the token itself and sends it as X-Session.
    const xs = String(req.headers['x-session'] || '');
    if (tokenOk(xs)) {
      const r = await db.execute({ sql: 'SELECT 1 FROM sessions WHERE id = ? AND expiresAt > ?', args: [skey(xs), Date.now()] });
      if (r.rows.length) { req.cookies.sid = xs; return next(); }
    }
    const hdr = String(req.headers.cookie || '');
    const all = [...hdr.matchAll(/(?:^|;\s*)sid=([^;]*)/g)].map(m => m[1]);
    if (all.length > 1) {
      for (const v of all) {
        if (!tokenOk(v)) continue;
        const r = await db.execute({ sql: 'SELECT 1 FROM sessions WHERE id = ? AND expiresAt > ?', args: [skey(v), Date.now()] });
        if (r.rows.length) { req.cookies.sid = v; break; }
      }
    }
  } catch (e) { /* fall through to the normal lookup */ }
  next();
});
// CORS: only your own site may call the API from a browser (extra origins: ALLOWED_ORIGINS=https://a.com,https://b.com)
const ALLOWED_ORIGINS = new Set(['https://unique-pdee.onrender.com', 'https://knqwx.github.io', ...String(process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)]);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) res.setHeader('Vary', 'Origin');
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session, X-UT-Page');
    res.setHeader('Access-Control-Max-Age', '600');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(origin && !ALLOWED_ORIGINS.has(origin) ? 403 : 204);
  // The session cookie is SameSite=None in production, so a foreign website could make a visitor's browser send state-changing
  // requests. Browsers always attach an Origin header to those, so refuse any POST/DELETE from an origin that is not ours.
  if (origin && req.method !== 'GET' && req.method !== 'HEAD' && !ALLOWED_ORIGINS.has(origin)) {
    let sameHost = false;
    try { sameHost = new URL(origin).host === req.headers.host; } catch (e) {}
    if (!sameHost) return res.status(403).json({ error: 'Request blocked.' });
  }
  next();
});
// Content-Security-Policy: inline scripts receive a per-response nonce; inline styles remain allowed for legacy style attributes.
// Third-party script execution, framing, plugins, foreign form targets, and script event attributes are blocked.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'nonce-__CSP_NONCE__'",
  "script-src-attr 'none'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: blob:",
  "media-src 'self' blob:",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  "connect-src 'self' https://unique-pdee.onrender.com",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests"
].join('; ');
// In production cookies are SameSite=None; Secure so the page can also be hosted elsewhere (GitHub Pages). Set CROSS_SITE_COOKIES=0 to use Lax instead.
const IS_SECURE = process.env.NODE_ENV === 'production' || process.env.RENDER === 'true';
const CROSS_SITE = IS_SECURE && process.env.CROSS_SITE_COOKIES !== '0';   // on by default in production so a GitHub-hosted page can log in; set CROSS_SITE_COOKIES=0 to force Lax
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(18).toString('base64');
  // HSTS: once a browser has seen the site over HTTPS it refuses plain HTTP for a year (req.secure honours the proxy's X-Forwarded-Proto).
  if (req.secure || IS_SECURE) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');                       // clickjacking: nobody may embed the site in a frame
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', CSP.replace('__CSP_NONCE__', res.locals.cspNonce));
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});

const DAY = 24 * 60 * 60 * 1000;
const SESSION_MS = 30 * DAY;
const ipOf = (req) => {
  // Always use Express's proxy-aware address, never trust X-Forwarded-For directly.
  const ip = String(req.ip || '').trim().replace(/^::ffff:/i, '').toLowerCase();
  return ip && ip.length <= 64 && !/[\s,]/.test(ip) ? ip : '';
};
const ipFingerprint = (ip) => crypto.createHmac('sha256', cleanEnv(process.env.IP_HASH_SECRET || TURSO_TOKEN || 'starfall-ip-guard-change-me')).update(String(ip || '')).digest('hex');

// ---------- small helpers used by the schema/migration code (must exist before init() runs) ----------
// session ids and admin tokens are stored as they are (plain), as in the original version
const skey = (v) => String(v);
const sha256 = (v) => crypto.createHash('sha256').update(String(v)).digest('hex');
const parseJson = (s, fallback) => { try { const v = JSON.parse(s); return v == null ? fallback : v; } catch (e) { return fallback; } };
async function metaGet(k) { const r = await db.execute({ sql: 'SELECT v FROM meta WHERE k = ?', args: [k] }); return r.rows.length ? String(r.rows[0].v) : null; }
async function metaSet(k, v) { await db.execute({ sql: 'INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', args: [k, String(v)] }); }
// monotonically increasing change counters (listing / message revisions), bumped inside the same transaction as the change itself
async function bumpMeta(q, k) {
  await q.execute({ sql: "INSERT INTO meta (k, v) VALUES (?, '1') ON CONFLICT(k) DO UPDATE SET v = CAST(v AS INTEGER) + 1", args: [k] });
  const r = await q.execute({ sql: 'SELECT v FROM meta WHERE k = ?', args: [k] });
  return Number(r.rows[0].v);
}

// ---------- picture safety (avatars, listing photos, chat pictures) ----------
// Pictures arrive as data: URLs, are checked here, and are stored as binary blobs (media table) that are served with their real image type.
// Only real png / jpeg / webp / gif data may be stored or sent out.
const IMG_DATA_RE = /^data:image\/(png|jpe?g|webp|gif);base64,([A-Za-z0-9+/]+={0,2})$/;
function sniffImageType(buf) {            // what the bytes really are, whatever the data: URL claims
  if (buf.length < 12) return '';
  if (buf[0] === 0x89 && buf.toString('latin1', 1, 4) === 'PNG' && buf[4] === 0x0d && buf[5] === 0x0a && buf[6] === 0x1a && buf[7] === 0x0a) return 'png';
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'jpeg';
  const h = buf.toString('latin1', 0, 6);
  if (h === 'GIF87a' || h === 'GIF89a') return 'gif';
  if (buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP') return 'webp';
  return '';
}
// full check for everything that gets STORED: right shape, small enough, and the bytes are really that kind of picture. Returns the clean value or null.
function cleanImageDataUrl(v, maxLen) {
  if (typeof v !== 'string' || v.length > maxLen) return null;
  const m = IMG_DATA_RE.exec(v);
  if (!m || m[2].length % 4 !== 0) return null;
  const real = sniffImageType(Buffer.from(m[2], 'base64'));
  const claimed = m[1] === 'jpg' ? 'jpeg' : m[1];
  if (!real || real !== claimed) return null;
  return 'data:image/' + real + ';base64,' + m[2];
}
// decode a validated data: URL into { mime, buf } (or null)
function decodeImageDataUrl(v, maxLen) {
  const clean = cleanImageDataUrl(v, maxLen);
  if (!clean) return null;
  const m = IMG_DATA_RE.exec(clean);
  return { mime: 'image/' + (m[1] === 'jpg' ? 'jpeg' : m[1]), buf: Buffer.from(m[2], 'base64') };
}
// cheap check for what is SENT OUT (avatars still live as data: URLs on the user row)
const safeImageOut = (v) => (typeof v === 'string' && v.length <= 1000000 && IMG_DATA_RE.test(v)) ? v : null;
const MEDIA_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const mediaUrl = (id) => id ? '/api/media/' + encodeURIComponent(id) : null;
const newMediaId = () => crypto.randomBytes(16).toString('hex');

// ---------- tables ----------
async function init() {
  const run = async (sql) => { try { await db.execute(sql); } catch (e) { /* already exists */ } };
  await run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, customId TEXT, username TEXT UNIQUE, displayName TEXT, email TEXT, password TEXT, avatar TEXT, balance REAL DEFAULT 0.00, lastUsernameChange INTEGER, lastDisplayNameChange INTEGER, items TEXT, lastItemTime INTEGER, messages TEXT, card TEXT)`);
  // an old database may hold a users table with fewer columns than this version expects: add every one that is missing
  for (const col of ['customId TEXT', 'username TEXT', 'displayName TEXT', 'email TEXT', 'password TEXT', 'avatar TEXT', 'lastUsernameChange INTEGER', 'lastDisplayNameChange INTEGER', 'items TEXT']) await run(`ALTER TABLE users ADD COLUMN ${col}`);
  for (const col of ['balance REAL DEFAULT 0.00', 'lastItemTime INTEGER', 'messages TEXT', 'card TEXT', 'isMiddleman INTEGER DEFAULT 0', 'lastSeen INTEGER', 'heldBalance REAL DEFAULT 0', 'bannedUntil INTEGER DEFAULT 0', 'bannedAt INTEGER DEFAULT 0', 'banReason TEXT', 'appeal TEXT', 'appealAt INTEGER DEFAULT 0', 'appealStatus TEXT', 'roblox TEXT']) await run(`ALTER TABLE users ADD COLUMN ${col}`);
  // The very old users table had "id TEXT" (not a real row id). Everything here needs integer ids, so the table is rebuilt once, keeping every row and column.
  try {
    const ti = await db.execute('PRAGMA table_info(users)');
    const idCol = ti.rows.find(r => String(r.name) === 'id');
    if (idCol && String(idCol.type).toUpperCase() !== 'INTEGER') {
      const cols = ti.rows.filter(r => String(r.name) !== 'id');
      const names = cols.map(r => String(r.name));
      const defs = cols.map(r => {
        const n = String(r.name);
        if (n === 'username') return 'username TEXT UNIQUE';
        if (n === 'balanceCents' || n === 'heldBalanceCents') return `${n} INTEGER NOT NULL DEFAULT 0`;
        return `${n} ${String(r.type || '')}${r.dflt_value != null ? ' DEFAULT ' + r.dflt_value : ''}`.trim();
      });
      const sel = names.map(n => (n === 'balanceCents' || n === 'heldBalanceCents') ? `COALESCE(${n}, 0)` : n).join(', ');
      const list = names.join(', ');
      console.warn('Rebuilding users: its id column was ' + (idCol.type || 'untyped') + ', it becomes an integer row id');
      await db.batch([
        'DROP TABLE IF EXISTS users_new',
        `CREATE TABLE users_new (id INTEGER PRIMARY KEY AUTOINCREMENT, ${defs.join(', ')})`,
        // accounts whose old id is a clean whole number keep it; the others get the next free number
        `INSERT OR IGNORE INTO users_new (id, ${list}) SELECT CAST(id AS INTEGER), ${sel} FROM users WHERE CAST(id AS TEXT) GLOB '[0-9]*' AND CAST(id AS TEXT) NOT GLOB '*[^0-9]*' AND CAST(id AS INTEGER) > 0 ORDER BY CAST(id AS INTEGER)`,
        `INSERT OR IGNORE INTO users_new (${list}) SELECT ${sel} FROM users WHERE username NOT IN (SELECT username FROM users_new WHERE username IS NOT NULL)`,
        'DROP TABLE users',
        'ALTER TABLE users_new RENAME TO users',
      ], 'write');
    }
  } catch (e) { console.error('!! users table rebuild failed:', e.message); }
  // Authoritative wallet values are integer cents. Migrate legacy dollar columns exactly once.
  const userCols = await db.execute('PRAGMA table_info(users)');
  const userColNames = new Set(userCols.rows.map(r => String(r.name)));
  if (!userColNames.has('balanceCents')) {
    await run('ALTER TABLE users ADD COLUMN balanceCents INTEGER NOT NULL DEFAULT 0');
    await run('UPDATE users SET balanceCents = CAST(ROUND(COALESCE(balance, 0) * 100) AS INTEGER)');
  }
  if (!userColNames.has('heldBalanceCents')) {
    await run('ALTER TABLE users ADD COLUMN heldBalanceCents INTEGER NOT NULL DEFAULT 0');
    await run('UPDATE users SET heldBalanceCents = CAST(ROUND(COALESCE(heldBalance, 0) * 100) AS INTEGER)');
  }

  await run(`UPDATE users SET joinedAt = 0 WHERE joinedAt = 1`);
  await run(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`);
  // sessions.id is the SHA-256 of the cookie value (never the cookie itself), so a leaked database cannot be replayed as logins.
  await run(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, username TEXT, createdAt INTEGER, expiresAt INTEGER)`);
  await run(`ALTER TABLE sessions ADD COLUMN userId INTEGER`);
  // admin_sessions v2: only hashes are stored. The old table held raw tokens, so it is dropped once (admins simply sign in again).
  if (!(await metaGet('admin_sessions_v2'))) {
    await run('DROP TABLE IF EXISTS admin_sessions');
    await metaSet('admin_sessions_v2', '1');
  }
  await run(`CREATE TABLE IF NOT EXISTS admin_sessions (tokenHash TEXT PRIMARY KEY, userId INTEGER NOT NULL, username TEXT, sessionHash TEXT NOT NULL, createdAt INTEGER NOT NULL, expiresAt INTEGER NOT NULL, maxExpiresAt INTEGER NOT NULL, ipHash TEXT)`);
  await run(`CREATE TABLE IF NOT EXISTS signup_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, createdAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS deals (id INTEGER PRIMARY KEY AUTOINCREMENT, buyer TEXT, seller TEXT, itemName TEXT, amount REAL, sellerAmount REAL, status TEXT, createdAt INTEGER, updatedAt INTEGER, reportedAt INTEGER, chatSnapshot TEXT, reportedBy TEXT, itemId TEXT)`);
  const dealCols = await db.execute('PRAGMA table_info(deals)');
  const dealColNames = new Set(dealCols.rows.map(r => String(r.name)));
  if (!dealColNames.has('amountCents')) {
    await run('ALTER TABLE deals ADD COLUMN amountCents INTEGER NOT NULL DEFAULT 0');
    await run('UPDATE deals SET amountCents = CAST(ROUND(COALESCE(amount, 0) * 100) AS INTEGER)');
  }
  if (!dealColNames.has('sellerAmountCents')) {
    await run('ALTER TABLE deals ADD COLUMN sellerAmountCents INTEGER NOT NULL DEFAULT 0');
    await run('UPDATE deals SET sellerAmountCents = CAST(ROUND(COALESCE(sellerAmount, 0) * 100) AS INTEGER)');
  }

  await run(`CREATE TABLE IF NOT EXISTS chat_clears (user TEXT, other TEXT, clearedAt INTEGER, PRIMARY KEY (user, other))`);
  await run(`CREATE TABLE IF NOT EXISTS typing (user TEXT, other TEXT, ts INTEGER, PRIMARY KEY (user, other))`);
  await run(`CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, creator TEXT, partner TEXT, description TEXT, status TEXT DEFAULT 'open', claimedBy TEXT, createdAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS user_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, target TEXT, reporter TEXT, reason TEXT, details TEXT, createdAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS item_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, itemId TEXT, itemName TEXT, itemGame TEXT, seller TEXT, reporter TEXT, reason TEXT, details TEXT, createdAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS spam_timeouts (username TEXT PRIMARY KEY, level INTEGER DEFAULT 0, until INTEGER DEFAULT 0, lastOffense INTEGER DEFAULT 0)`);
  await run(`CREATE TABLE IF NOT EXISTS chat_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, owner TEXT, members TEXT, createdAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS group_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, groupId INTEGER, sender TEXT, text TEXT, timestamp INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS ratings (rater TEXT, target TEXT, stars INTEGER, createdAt INTEGER, PRIMARY KEY (rater, target))`);
  // One rating/vouch identity per target and network fingerprint. Stores keyed hashes, not raw IPs.
  await run(`CREATE TABLE IF NOT EXISTS social_ip_guard (kind TEXT NOT NULL, target TEXT NOT NULL, ipHash TEXT NOT NULL, actor TEXT NOT NULL, createdAt INTEGER NOT NULL, PRIMARY KEY (kind, target, ipHash))`);
  await run(`CREATE TABLE IF NOT EXISTS vouches (id INTEGER PRIMARY KEY AUTOINCREMENT, middleman TEXT, author TEXT, text TEXT, createdAt INTEGER, UNIQUE (middleman, author))`);
  await run(`CREATE TABLE IF NOT EXISTS ip_bans (ip TEXT PRIMARY KEY, bannedUntil INTEGER, bannedAt INTEGER, reason TEXT, username TEXT)`);
  await run(`ALTER TABLE users ADD COLUMN passwordHash TEXT`);
  await run(`ALTER TABLE users ADD COLUMN lastIp TEXT`);
  await run(`ALTER TABLE users ADD COLUMN joinedAt INTEGER`);
  await run(`ALTER TABLE users ADD COLUMN lastWithdrawAt INTEGER DEFAULT 0`);
  await run(`ALTER TABLE users ADD COLUMN mustChangePassword INTEGER DEFAULT 0`);   // set when the admin resets a password
  try {
    for (const t of ['users', 'sessions']) { const ti = await db.execute(`PRAGMA table_info(${t})`); console.log(`Schema ${t}: ` + ti.rows.map(r => `${r.name} ${r.type}`).join(', ')); }
    try {
      const lc = (await db.execute('SELECT COUNT(*) c FROM listings')).rows[0].c, orph = (await db.execute('SELECT COUNT(*) c FROM listings WHERE ownerId NOT IN (SELECT id FROM users)')).rows[0].c;
      const pend = (await db.execute("SELECT COUNT(*) c FROM users WHERE items IS NOT NULL AND items NOT IN ('', '[]', 'null')")).rows[0].c;
      console.log(`Listings: ${lc} in the listings table, ${orph} without a matching seller, ${pend} users still have old-style items waiting to be moved`);
      if (Number(orph) > 0) {
        const od = (await db.execute('SELECT ownerId, typeof(ownerId) t, COUNT(*) c FROM listings WHERE ownerId NOT IN (SELECT id FROM users) GROUP BY ownerId, typeof(ownerId) LIMIT 15')).rows;
        console.log('Listings without a seller, by ownerId: ' + od.map(r => `${r.ownerId} (${r.t}) x${r.c}`).join('; '));
      }
      console.log('Users: ' + (await db.execute('SELECT id, username FROM users LIMIT 20')).rows.map(r => `${r.id}=${r.username}`).join(', '));
      // Listings whose seller could not be recovered (ownerId 0) can be given to one account: set ORPHAN_LISTINGS_OWNER=<username> on Render, redeploy, then remove it.
      const adopt = String(process.env.ORPHAN_LISTINGS_OWNER || '').trim();
      if (adopt && Number(orph) > 0) {
        const ou = (await db.execute({ sql: 'SELECT id FROM users WHERE lower(username) = lower(?)', args: [adopt] })).rows[0];
        if (!ou) console.error(`ORPHAN_LISTINGS_OWNER: no account named ${adopt}`);
        else {
          await db.batch([
            { sql: 'UPDATE media SET ownerId = ? WHERE kind = \'listing\' AND ownerId NOT IN (SELECT id FROM users)', args: [Number(ou.id)] },
            { sql: 'UPDATE listings SET ownerId = ? WHERE ownerId NOT IN (SELECT id FROM users)', args: [Number(ou.id)] },
          ], 'write');
          await bumpMeta(db, 'listingsRev');
          console.log(`Listings without a seller now belong to ${adopt}`);
        }
      }
    } catch (e) { if (!/no such table/.test(String(e.message))) console.error('listing check failed', e.message); }
    console.log('Sessions in database: ' + (await db.execute('SELECT COUNT(*) c FROM sessions')).rows[0].c + ', users: ' + (await db.execute('SELECT COUNT(*) c FROM users')).rows[0].c);
  } catch (e) { console.error('schema log failed', e.message); }
  await run(`CREATE TABLE IF NOT EXISTS admin_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, admin TEXT, action TEXT, target TEXT, detail TEXT, amount REAL DEFAULT 0, createdAt INTEGER)`);
  // every IP an account has signed up / logged in / browsed from (used for the "same IP" and VPN flags)
  await run(`CREATE TABLE IF NOT EXISTS user_ips (username TEXT, ip TEXT, firstSeen INTEGER, lastSeen INTEGER, PRIMARY KEY (username, ip))`);
  // cached VPN / proxy / datacenter lookup per IP
  await run(`CREATE TABLE IF NOT EXISTS ip_info (ip TEXT PRIMARY KEY, proxy INTEGER DEFAULT 0, hosting INTEGER DEFAULT 0, checkedAt INTEGER)`);
  await run(`INSERT OR IGNORE INTO user_ips (username, ip, firstSeen, lastSeen) SELECT username, lastIp, COALESCE(joinedAt, ${Date.now()}), ${Date.now()} FROM users WHERE lastIp IS NOT NULL AND lastIp != ''`);
  await run(`CREATE TRIGGER IF NOT EXISTS users_set_joined AFTER INSERT ON users WHEN NEW.joinedAt IS NULL BEGIN UPDATE users SET joinedAt = CAST(strftime('%s','now') AS INTEGER) * 1000 WHERE id = NEW.id; END`);
  await run(`UPDATE users SET joinedAt = ${Date.now()} WHERE joinedAt IS NULL`);
  await run(`DELETE FROM sessions WHERE expiresAt < ${Date.now()}`);
  // withdrawal requests are saved here (the admin sees them in Money -> Withdrawal requests)
  await run(`CREATE TABLE IF NOT EXISTS withdrawals (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, amount REAL, method TEXT, status TEXT DEFAULT 'pending', createdAt INTEGER, handledBy TEXT, handledAt INTEGER)`);
  const withdrawalCols = await db.execute('PRAGMA table_info(withdrawals)');
  if (!withdrawalCols.rows.some(r => String(r.name) === 'amountCents')) {
    await run('ALTER TABLE withdrawals ADD COLUMN amountCents INTEGER NOT NULL DEFAULT 0');
    await run('UPDATE withdrawals SET amountCents = CAST(ROUND(COALESCE(amount, 0) * 100) AS INTEGER)');
  }

  await run(`CREATE INDEX IF NOT EXISTS withdrawals_created ON withdrawals (createdAt)`);
  // usernames are unique regardless of capitalization ("Alice" and "alice" are the same name)
  try {
    await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users (lower(username))');
  } catch (e) {
    const dup = await db.execute('SELECT lower(username) AS n, GROUP_CONCAT(username) AS names FROM users GROUP BY lower(username) HAVING COUNT(*) > 1');
    console.error('!! Could not enforce case-insensitive usernames: these accounts differ only by capitalization and one of each pair must be renamed or deleted:', dup.rows.map(r => r.names).join(' | ') || e.message);
  }
  // customId is COUNT(*)+1 again
  await run('DROP INDEX IF EXISTS users_custom_id');   // customId = COUNT(*)+1 can repeat after deletions, so it must not be unique

  // ---- escrow timing / completion bookkeeping on deals ----
  for (const col of ['paidAt INTEGER', 'completedAt INTEGER', 'autoReleased INTEGER DEFAULT 0', 'listingConsumed INTEGER DEFAULT 0']) await run(`ALTER TABLE deals ADD COLUMN ${col}`);
  await run('ALTER TABLE tickets ADD COLUMN closedAt INTEGER');            // when a middleman closed the ticket (closed tickets are the proof needed for a vouch)

  // A table with this name but an unexpected shape can only be left over from an interrupted earlier deploy (the original site never had these tables):
  // drop it so it is rebuilt correctly instead of crashing the start-up on a missing column.
  for (const [t, col] of [['messages', 'senderId'], ['listings', 'ownerId'], ['media', 'kind'], ['group_members', 'userId'], ['login_lockouts', 'lockedUntil'], ['topup_intents', 'userId'], ['payment_events', 'eventId']]) {
    try {
      const info = await db.execute(`PRAGMA table_info(${t})`);
      if (info.rows.length && !info.rows.some(r => String(r.name) === col)) { console.warn(`Rebuilding table ${t}: it had an old layout`); await db.execute(`DROP TABLE ${t}`); }
    } catch (e) { console.error('shape check failed for', t, e.message); }
  }
  // ---- relational chat: one row per message (was: a JSON array copied onto BOTH users' rows) ----
  // Users are referenced by their permanent numeric id, so renaming an account never touches this table.
  await run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, senderId INTEGER NOT NULL, receiverId INTEGER NOT NULL, itemId TEXT NOT NULL DEFAULT '',
    ts INTEGER NOT NULL, text TEXT NOT NULL DEFAULT '', itemRef TEXT, offer TEXT, imageId TEXT, caption TEXT, editedAt INTEGER, rev INTEGER NOT NULL DEFAULT 0)`);
  await run('CREATE UNIQUE INDEX IF NOT EXISTS messages_sender_ts ON messages (senderId, ts)');
  await run('CREATE INDEX IF NOT EXISTS messages_thread ON messages (senderId, receiverId, itemId, ts)');
  await run('CREATE INDEX IF NOT EXISTS messages_inbox ON messages (receiverId, senderId, itemId, ts)');
  await run('CREATE INDEX IF NOT EXISTS messages_recv_ts ON messages (receiverId, ts)');
  await run('CREATE INDEX IF NOT EXISTS messages_item_ts ON messages (itemId, ts)');
  await run('CREATE INDEX IF NOT EXISTS messages_ts ON messages (ts)');

  // ---- relational listings (was: a JSON array on the owner's row) ----
  // id stays "creation time in milliseconds" because the page uses it as the listing's age.
  await run(`CREATE TABLE IF NOT EXISTS listings (
    id INTEGER PRIMARY KEY, ownerId INTEGER NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', tag TEXT NOT NULL,
    price TEXT NOT NULL DEFAULT '', priceCents INTEGER, game TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '',
    items TEXT, wanted TEXT, stock INTEGER NOT NULL DEFAULT 1, photoId TEXT, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL)`);
  await run('CREATE INDEX IF NOT EXISTS listings_owner ON listings (ownerId, id)');
  await run('CREATE INDEX IF NOT EXISTS listings_tag_game ON listings (tag, game, id)');
  await run('CREATE INDEX IF NOT EXISTS listings_updated ON listings (updatedAt)');

  // ---- media: pictures as separate binary blobs served from their own URL (never base64 inside JSON) ----
  await run(`CREATE TABLE IF NOT EXISTS media (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, ownerId INTEGER NOT NULL, peerId INTEGER, refId TEXT, mime TEXT NOT NULL, size INTEGER NOT NULL, data BLOB NOT NULL, createdAt INTEGER NOT NULL)`);
  await run('CREATE INDEX IF NOT EXISTS media_owner_kind ON media (ownerId, kind, createdAt)');
  await run('CREATE INDEX IF NOT EXISTS media_ref ON media (kind, refId)');
  await run('CREATE INDEX IF NOT EXISTS media_created ON media (kind, createdAt)');

  // ---- group members as a real relation (fixes LIKE matching on usernames that contain _ or %) ----
  await run('ALTER TABLE chat_groups ADD COLUMN ownerId INTEGER');
  await run('ALTER TABLE group_messages ADD COLUMN senderId INTEGER');
  await run(`CREATE TABLE IF NOT EXISTS group_members (groupId INTEGER NOT NULL, userId INTEGER NOT NULL, joinedAt INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (groupId, userId))`);
  await run('CREATE INDEX IF NOT EXISTS group_members_user ON group_members (userId, groupId)');

  // ---- login lock-outs, keyed by (IP + account) and stored in the database so a restart does not clear them ----
  await run(`CREATE TABLE IF NOT EXISTS login_lockouts (k TEXT PRIMARY KEY, fails INTEGER NOT NULL DEFAULT 0, level INTEGER NOT NULL DEFAULT 0, lockedUntil INTEGER NOT NULL DEFAULT 0, lastFailAt INTEGER NOT NULL DEFAULT 0)`);
  await run('CREATE INDEX IF NOT EXISTS login_lockouts_last ON login_lockouts (lastFailAt)');

  // ---- wallet top-ups through an external payment gateway (card data never touches this server) ----
  await run(`CREATE TABLE IF NOT EXISTS topup_intents (id TEXT PRIMARY KEY, userId INTEGER NOT NULL, amountCents INTEGER NOT NULL, currency TEXT NOT NULL DEFAULT 'usd', provider TEXT, providerRef TEXT, status TEXT NOT NULL DEFAULT 'pending', createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL, expiresAt INTEGER NOT NULL)`);
  await run('CREATE UNIQUE INDEX IF NOT EXISTS topup_provider_ref ON topup_intents (provider, providerRef) WHERE providerRef IS NOT NULL');
  await run('CREATE INDEX IF NOT EXISTS topup_user ON topup_intents (userId, createdAt)');
  await run('CREATE INDEX IF NOT EXISTS topup_status ON topup_intents (status, expiresAt)');
  await run(`CREATE TABLE IF NOT EXISTS payment_events (eventId TEXT PRIMARY KEY, provider TEXT NOT NULL, type TEXT, intentId TEXT, outcome TEXT, receivedAt INTEGER NOT NULL)`);

  // ---- indexes for the columns the queries actually filter and sort on ----
  for (const ix of [
    'CREATE INDEX IF NOT EXISTS sessions_user ON sessions (userId)', 'CREATE INDEX IF NOT EXISTS sessions_exp ON sessions (expiresAt)',
    'CREATE INDEX IF NOT EXISTS admin_sessions_exp ON admin_sessions (expiresAt)', 'CREATE INDEX IF NOT EXISTS admin_sessions_session ON admin_sessions (sessionHash)',
    'CREATE INDEX IF NOT EXISTS deals_buyer ON deals (buyer, status)', 'CREATE INDEX IF NOT EXISTS deals_seller ON deals (seller, status)',
    'CREATE INDEX IF NOT EXISTS deals_status_updated ON deals (status, updatedAt)', 'CREATE INDEX IF NOT EXISTS deals_status_paid ON deals (status, paidAt)',
    'CREATE INDEX IF NOT EXISTS deals_item ON deals (itemId, status)', 'CREATE INDEX IF NOT EXISTS deals_created ON deals (createdAt)',
    'CREATE INDEX IF NOT EXISTS tickets_creator ON tickets (creator, status)', 'CREATE INDEX IF NOT EXISTS tickets_partner ON tickets (partner, status)',
    'CREATE INDEX IF NOT EXISTS tickets_claimed ON tickets (claimedBy, status)', 'CREATE INDEX IF NOT EXISTS tickets_status_created ON tickets (status, createdAt)',
    'CREATE INDEX IF NOT EXISTS ratings_target ON ratings (target)', 'CREATE INDEX IF NOT EXISTS vouches_mm ON vouches (middleman)',
    'CREATE INDEX IF NOT EXISTS group_messages_group ON group_messages (groupId, timestamp)', 'CREATE INDEX IF NOT EXISTS group_messages_ts ON group_messages (timestamp)',
    'CREATE INDEX IF NOT EXISTS item_reports_item ON item_reports (itemId, reporter)', 'CREATE INDEX IF NOT EXISTS user_reports_target ON user_reports (kind, target, reporter)',
    'CREATE INDEX IF NOT EXISTS withdrawals_user ON withdrawals (username, status)', 'CREATE INDEX IF NOT EXISTS admin_audit_created ON admin_audit (createdAt)',
    'CREATE INDEX IF NOT EXISTS user_ips_ip ON user_ips (ip)', 'CREATE INDEX IF NOT EXISTS typing_ts ON typing (ts)',
    'CREATE INDEX IF NOT EXISTS chat_clears_user ON chat_clears (user)', 'CREATE INDEX IF NOT EXISTS signup_log_ip ON signup_log (ip, createdAt)',
    'CREATE INDEX IF NOT EXISTS users_last_ip ON users (lastIp)', 'CREATE INDEX IF NOT EXISTS users_email_lower ON users (lower(email))'
  ]) await run(ix);
  await run(`INSERT OR IGNORE INTO meta (k, v) VALUES ('listingsRev', '0'), ('msgRev', '0')`);
}
await init();

// ---------- one-time data migrations (each is idempotent and safe to re-run after a crash) ----------
async function migrate() {
  const t0 = Date.now();
  const users = await db.execute('SELECT id, username, joinedAt FROM users');
  const idOf = new Map(users.rows.map(r => [String(r.username), Number(r.id)]));

  // 1) sessions: add the numeric user id
  await db.execute('UPDATE sessions SET userId = (SELECT id FROM users WHERE users.username = sessions.username) WHERE username IS NOT NULL AND (userId IS NULL OR userId NOT IN (SELECT id FROM users))');

  // 2) messages: users.messages (JSON, duplicated on both rows) -> messages table
  if (!(await metaGet('messages_migrated'))) {
    const rows = (await db.execute("SELECT username, messages FROM users WHERE messages IS NOT NULL AND messages NOT IN ('', '[]', 'null')")).rows;
    let inserted = 0, skipped = 0;
    for (const pass of ['sender', 'receiver']) {          // the sender's own copy wins; the receiver's copy only fills in what the sender deleted
      for (const row of rows) {
        const arr = parseJson(row.messages, []);
        if (!Array.isArray(arr)) continue;
        const stmts = [];
        for (const m of arr) {
          if (!m || typeof m !== 'object') { skipped++; continue; }
          if ((pass === 'sender' ? m.sender : m.receiver) !== row.username) continue;
          const s = idOf.get(String(m.sender)), r = idOf.get(String(m.receiver)), ts = Number(m.timestamp);
          if (!s || !r || s === r || !Number.isFinite(ts) || ts <= 0) { skipped++; continue; }
          stmts.push({ sql: 'INSERT OR IGNORE INTO messages (senderId, receiverId, itemId, ts, text, itemRef, offer, imageId, caption, editedAt, rev) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)',
            args: [s, r, m.itemId ? String(m.itemId) : '', Math.floor(ts), String(m.text == null ? '' : m.text).slice(0, 2000), m.itemRef ? JSON.stringify(m.itemRef) : null, m.offer ? JSON.stringify(m.offer) : null,
              m.imageId ? String(m.imageId).slice(0, 64) : null, m.caption ? String(m.caption).slice(0, 500) : null, m.editedAt && Number.isFinite(Number(m.editedAt)) ? Number(m.editedAt) : null] });
        }
        for (let i = 0; i < stmts.length; i += 200) { const rs = await db.batch(stmts.slice(i, i + 200), 'write'); inserted += rs.reduce((a, x) => a + (x.rowsAffected || 0), 0); }
      }
    }
    await db.execute("UPDATE users SET messages = NULL WHERE messages IS NOT NULL");
    await metaSet('messages_migrated', '1');
    if (rows.length) console.log(`Migration: chat history moved to the messages table (${inserted} messages, ${skipped} unusable entries skipped)`);
  }

  // 3) listings: users.items (JSON) -> listings table (+ photos as media blobs). Per user, atomically; the legacy blob is cleared only if the whole batch commits.
  {
    const rows = (await db.execute("SELECT id, username, items, joinedAt FROM users WHERE items IS NOT NULL AND items NOT IN ('', '[]', 'null')")).rows;
    if (rows.length) {
      const used = new Set((await db.execute('SELECT id FROM listings')).rows.map(r => Number(r.id)));
      let moved = 0, dropped = 0;
      for (const row of rows) {
        const arr = parseJson(row.items, []);
        const stmts = [];
        for (const it of Array.isArray(arr) ? arr : []) {
          if (!it || typeof it !== 'object' || !String(it.name || '').trim() || !['selling', 'specific', 'any', 'offers'].includes(String(it.tag))) { dropped++; continue; }
          let id = Number(it.id); if (!Number.isSafeInteger(id) || id <= 0) id = Date.now();
          while (used.has(id)) id++;                      // legacy ids were per-user timestamps, so two sellers could (rarely) collide
          used.add(id);
          const price = it.price == null ? '' : String(it.price).trim();
          const priceNum = parseFloat(price.replace(/,/g, ''));
          const priceCents = it.tag === 'selling' && Number.isFinite(priceNum) && priceNum >= 0 && priceNum <= 1e9 ? Math.round(priceNum * 100) : null;   // absurd legacy prices (1e999, NaN) become 'no price' instead of crashing the start-up
          const created = id > 1e12 ? id : (Number.isFinite(Number(row.joinedAt)) && Number(row.joinedAt) > 0 ? Number(row.joinedAt) : Date.now());
          let photoId = null;
          const img = decodeImageDataUrl(it.photo, 1000000);
          if (img) {
            photoId = newMediaId();
            stmts.push({ sql: "INSERT INTO media (id, kind, ownerId, refId, mime, size, data, createdAt) VALUES (?, 'listing', ?, ?, ?, ?, ?, ?)", args: [photoId, Number(row.id), String(id), img.mime, img.buf.length, img.buf, created] });
          }
          const stock = Number(it.stock);
          stmts.push({ sql: 'INSERT INTO listings (id, ownerId, name, description, tag, price, priceCents, game, category, items, wanted, stock, photoId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            args: [id, Number(row.id), String(it.name).slice(0, 80), String(it.description || '').slice(0, 2000), String(it.tag), price, priceCents, String(it.game || '').slice(0, 60), String(it.category || '').slice(0, 60),
              JSON.stringify(Array.isArray(it.items) ? it.items.slice(0, 60).map(x => String(x).slice(0, 80)) : []), it.wanted && typeof it.wanted === 'object' ? JSON.stringify(it.wanted) : null,
              Number.isInteger(stock) && stock >= 0 ? stock : 1, photoId, created, created] });
          moved++;
        }
        stmts.push({ sql: 'UPDATE users SET items = NULL WHERE id = ?', args: [Number(row.id)] });
        // one user's unusable data must never stop the whole site from starting: log it, keep their old data untouched (nothing was committed) and go on
        try { await db.batch(stmts, 'write'); } catch (e) { console.error(`Migration: listings of user ${row.username} could not be moved (${e.message}); left as they were`); moved -= stmts.filter(x => x.sql.startsWith('INSERT INTO listings')).length; }
      }
      console.log(`Migration: ${moved} listings moved to the listings table (${dropped} invalid entries dropped)`);
      await bumpMeta(db, 'listingsRev');
    }
  }

  // 4) chat pictures: chat_images (base64 text) -> media blobs, same ids so existing messages keep working. The old table is dropped once it is empty.
  if ((await db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chat_images'")).rows.length) {
    let n = 0;
    for (;;) {
      const rows = (await db.execute('SELECT id, sender, receiver, data, createdAt FROM chat_images LIMIT 50')).rows;
      if (!rows.length) break;
      const stmts = [];
      for (const r of rows) {
        const img = decodeImageDataUrl(r.data, 1000000), s = idOf.get(String(r.sender)), p = idOf.get(String(r.receiver));
        if (img && s && p && MEDIA_ID_RE.test(String(r.id))) { stmts.push({ sql: "INSERT OR IGNORE INTO media (id, kind, ownerId, peerId, mime, size, data, createdAt) VALUES (?, 'chat', ?, ?, ?, ?, ?, ?)", args: [String(r.id), s, p, img.mime, img.buf.length, img.buf, (Number.isFinite(Number(r.createdAt)) && Number(r.createdAt) > 0 ? Number(r.createdAt) : Date.now())] }); n++; }
        stmts.push({ sql: 'DELETE FROM chat_images WHERE id = ?', args: [String(r.id)] });
      }
      await db.batch(stmts, 'write');
    }
    if (n) console.log(`Migration: ${n} chat pictures moved to media blobs`);
    await db.execute('DROP TABLE IF EXISTS chat_images');
  }

  // 5) groups: members JSON -> group_members, owner/sender names -> numeric ids
  {
    const gs = (await db.execute('SELECT id, owner, members, createdAt FROM chat_groups WHERE ownerId IS NULL')).rows;
    for (const g of gs) {
      const ownerId = idOf.get(String(g.owner));
      const stmts = [];
      const members = new Set([String(g.owner), ...(Array.isArray(parseJson(g.members, [])) ? parseJson(g.members, []).map(String) : [])]);
      for (const m of members) { const uid = idOf.get(m); if (uid) stmts.push({ sql: 'INSERT OR IGNORE INTO group_members (groupId, userId, joinedAt) VALUES (?, ?, ?)', args: [Number(g.id), uid, Number(g.createdAt) || 0] }); }
      stmts.push({ sql: 'UPDATE chat_groups SET ownerId = ?, members = NULL WHERE id = ?', args: [ownerId || 0, Number(g.id)] });
      await db.batch(stmts, 'write');
    }
    await db.execute('UPDATE group_messages SET senderId = (SELECT id FROM users WHERE users.username = group_messages.sender) WHERE senderId IS NULL');
    if (gs.length) console.log(`Migration: ${gs.length} groups now use the group_members table`);
  }

  // 6) escrow clock for deals that were already paid before paidAt existed (their last update is the best estimate of the payment time)
  await db.execute("UPDATE deals SET paidAt = updatedAt WHERE paidAt IS NULL AND status IN ('paid','not_received','reported','completed','released')");
  if (Date.now() - t0 > 1000) console.log(`Migrations finished in ${Date.now() - t0} ms`);
}
await migrate();

// ---------- rate limiter (memory + database) ----------
// Hits are counted in memory (fast, synchronous) and written to the database in small batches, then reloaded on startup,
// so a restart or redeploy no longer gives everybody a fresh allowance.
await db.execute('CREATE TABLE IF NOT EXISTS rate_hits (k TEXT, t INTEGER)');
await db.execute('CREATE INDEX IF NOT EXISTS rate_hits_k ON rate_hits (k)');
const RATE_KEEP_MS = 2 * 60 * 60 * 1000;          // longest window used anywhere is 1 hour
const buckets = new Map();
try {
  const old = await db.execute({ sql: 'SELECT k, t FROM rate_hits WHERE t > ? ORDER BY t', args: [Date.now() - RATE_KEEP_MS] });
  for (const r of old.rows) { const k = String(r.k); if (!buckets.has(k)) buckets.set(k, []); buckets.get(k).push(Number(r.t)); }
  console.log(`Rate limits restored: ${old.rows.length} recent hits`);
} catch (e) { console.error('rate limit restore failed:', e.message); }
let rateQueue = [];
async function flushRateHits() {
  if (!rateQueue.length) return;
  const batch = rateQueue; rateQueue = [];
  try { await db.batch(batch.map(([k, t]) => ({ sql: 'INSERT INTO rate_hits (k, t) VALUES (?, ?)', args: [k, t] })), 'write'); }
  catch (e) { console.error('rate limit save failed:', e.message); rateQueue = batch.concat(rateQueue).slice(-5000); }
}
setInterval(flushRateHits, 2000);
setInterval(() => db.execute({ sql: 'DELETE FROM rate_hits WHERE t < ?', args: [Date.now() - RATE_KEEP_MS] }).catch(() => {}), 10 * 60 * 1000);
for (const sig of ['SIGTERM', 'SIGINT']) process.once(sig, () => { flushRateHits().finally(() => process.exit(0)); });   // Render sends SIGTERM on every deploy/restart
function limited(key, max, windowMs) {
  const now = Date.now();
  const b = (buckets.get(key) || []).filter(t => now - t < windowMs);
  b.push(now);
  buckets.set(key, b);
  rateQueue.push([key, now]);
  return b.length > max;
}
const failCount = (key, windowMs) => { const now = Date.now(); return (buckets.get(key) || []).filter(t => now - t < windowMs).length; };
setInterval(() => { const now = Date.now(); for (const [k, v] of buckets) if (!v.some(t => now - t < DAY)) buckets.delete(k); }, 10 * 60 * 1000);

// ---------- rules (the same ones the form shows, now enforced on the server) ----------
const BURNER_DOMAINS = new Set('mailinator.com mailinator.net mailinator.org mailnator.com guerrillamail.com guerrillamail.net guerrillamail.org guerrillamail.biz guerrillamail.de guerrillamail.info guerrillamailblock.com sharklasers.com grr.la pokemail.net spam4.me 10minutemail.com 10minutemail.net 10minutemail.org 10mail.org 20minutemail.com temp-mail.org temp-mail.io temp-mail.ru tempmail.com tempmail.net tempmail.dev tempmail.plus tempmailo.com tempmailer.com tempmailaddress.com tempail.com tempr.email tempinbox.com tempsky.com tempm.com tmail.ws tmpmail.org tmpmail.net tmails.net throwawaymail.com throwam.com yopmail.com yopmail.fr yopmail.net cool.fr.nf jetable.fr.nf nospam.ze.tc nomail.xl.cx mega.zik.dj speed.1s.fr courriel.fr.nf moncourrier.fr.nf monemail.fr.nf monmail.fr.nf getnada.com nada.email dispostable.com maildrop.cc fakeinbox.com fakemailgenerator.com emailfake.com crazymailing.com trashmail.com trashmail.net trashmail.org trashmail.de trashmail.me trashmail.io trashmail.ws mailnesia.com mintemail.com mohmal.com emailondeck.com mytemp.email burnermail.io spamgourmet.com spamgourmet.net mailcatch.com mailnull.com anonbox.net discard.email discardmail.com discardmail.de spambox.us spamex.com spamfree24.org spam.la spamobox.com deadaddress.com sogetthis.com getairmail.com trbvm.com nowmymail.com bugmenot.com byom.de dropmail.me mailpoof.com fexbox.org fexpost.com fextemp.com mimimail.me cs.email mail.tm mail.gw chacuo.net mailtothis.com moakt.com moakt.cc inboxkitten.com harakirimail.com mailforspam.com mailsac.com incognitomail.com incognitomail.org mt2015.com armyspy.com cuvox.de dayrep.com einrot.com fleckens.hu gustr.com jourrapide.com rhyta.com superrito.com teleworm.us owlymail.com luxusmail.org bccto.me linshiyouxiang.net 1secmail.com 1secmail.org 1secmail.net esiix.com wwjmp.com xojxe.com yoggm.com vjuum.com laafd.com txcct.com dcctb.com kzccv.com qiott.com wuuvo.com icznn.com ezztt.com cdfaq.com oosln.com vddaz.com emltmp.com emailtemporanea.net temporary-mail.net mvrht.com rmqkr.net getnada.cc tempmailgen.com temp-mail.live tempmailin.com mailtemp.info mailbox92.biz spamdecoy.net 0-mail.com 0815.ru 10minut.xyz fakemail.net fake-mail.net33mail.com guerrillamail.co anonymbox.com dodgeit.com e4ward.com emailsensei.com eyepaste.com fastacura.com filzmail.com get2mail.fr haltospam.com hidemail.de imails.info jetable.org kasmail.com klassmaster.com letthemeatspam.com lookugly.com lroid.com mailexpire.com mailin8r.com mailmoat.com mailzilla.com meltmail.com mintemail.net mt2014.com mytrashmail.com neverbox.com no-spam.ws nobulk.com noclickemail.com nospamfor.us objectmail.com odaymail.com onewaymail.com pjjkp.com proxymail.eu putthisinyourspamdatabase.com quickinbox.com rcpt.at recode.me safetymail.info shieldedmail.com shitmail.me snakemail.com sneakemail.com sofort-mail.de spamavert.com spambog.com spambog.de spambog.ru spamcero.com spamcorptastic.com spamevader.com spamfighter.cf spamhole.com spamify.com spaml.com spammotel.com spamslicer.com spamspot.com spamthis.co.uk spamtroll.net supermailer.jp tempemail.net tempemail.com tempinbox.co.uk temporaryemail.net temporaryforwarding.com thankyou2010.com thisisnotmyrealemail.com tradermail.info trash-mail.com trash-mail.de trashymail.com trashymail.net trillianpro.com twinmail.de tyldd.com uggsrock.com veryrealemail.com wegwerfmail.de wegwerfmail.net wegwerfmail.org yepmail.net zippymail.info zoemail.org'.split(/\s+/).filter(Boolean));
const BURNER_KEYWORDS = ['tempmail', 'temp-mail', 'tmpmail', '10minute', 'minutemail', 'throwaway', 'trashmail', 'trash-mail', 'mailinator', 'guerrilla', 'fakeinbox', 'disposable', 'burner', 'yopmail', 'spamgourmet', 'getnada', 'tempinbox', 'sharklasers', 'dispostable', 'maildrop', 'mohmal', 'fakemail', 'emailfake', 'instantemail', 'anonmail', 'spambox'];
function isBurnerDomain(domain) {
  domain = domain.toLowerCase();
  const parts = domain.split('.');
  for (let i = 0; i < parts.length - 1; i++) if (BURNER_DOMAINS.has(parts.slice(i).join('.'))) return true;
  return BURNER_KEYWORDS.some(k => domain.includes(k));
}
async function checkEmail(email) {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 254) return 'Please enter a valid email address.';
  const domain = email.split('@')[1].toLowerCase();
  if (isBurnerDomain(domain)) return 'Disposable or burner email addresses are not allowed. Please use your real email.';
  if (process.env.SKIP_DNS === '1') return '';
  try {
    const mx = await dns.resolveMx(domain);
    if (mx && mx.length) return '';
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'NXDOMAIN') return 'This email domain does not exist. Please check your email address.';
    if (e.code !== 'ENODATA') return '';          // DNS problem on our side: do not block real users
  }
  try { await dns.resolve4(domain); return ''; }
  catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA' || e.code === 'NXDOMAIN') return 'This email domain cannot receive mail. Please use a real email address.';
    return '';
  }
}
// Names that look like the staff / the service itself. Nobody can register or rename to them (comparison ignores case, . _ - and 0/1/3/4/5/7 look-alikes).
const RESERVED_EXACT = new Set(['admin', 'administrator', 'support', 'staff', 'moderator', 'mod', 'mods', 'middleman', 'middlemen', 'owner', 'system', 'official', 'root', 'help', 'helpdesk', 'service', 'team',
  'security', 'billing', 'verify', 'verified', 'starfall', 'knqw', 'null', 'undefined', 'anonymous', 'sysadmin', 'superuser', 'webmaster', 'contact', 'info', 'abuse', 'postmaster', 'noreply', 'escrow']);
const RESERVED_PREFIX = ['admin', 'administrator', 'moderator', 'middleman', 'middlemen', 'starfall', 'officialsupport'];   // "admin_john", "middleman-bob" ...
const RESERVED_AFFIX = ['the', 'real', 'official', 'im', 'iam', 'mr', 'ms', 'x', 'xx'];                                          // "theadmin", "real_support", "support_official"
const LEET = { 0: 'o', 1: 'i', 3: 'e', 4: 'a', 5: 's', 7: 't' };
const normalizeName = (name) => String(name || '').toLowerCase().replace(/[._-]/g, '').replace(/[013457]/g, (c) => LEET[c]);
function isReservedUsername(name) {
  const n = normalizeName(name), raw = String(name || '').toLowerCase().replace(/[._-]/g, '');
  for (const cand of new Set([n, raw])) {
    if (RESERVED_EXACT.has(cand)) return true;
    if (RESERVED_PREFIX.some(w => cand.startsWith(w) || cand.endsWith(w))) return true;
    for (const w of RESERVED_EXACT) {
      if (w.length < 4) continue;
      if (cand.startsWith(w) && /^\d+$/.test(cand.slice(w.length))) return true;                       // support123
      for (const a of RESERVED_AFFIX) if (cand === a + w || cand === w + a) return true;               // thesupport, support_official
    }
  }
  return false;
}
function checkUsername(name, opts = {}) {
  if (name.length < 3) return 'Username must be at least 3 characters long.';
  if (name.length > 24) return 'Username can be at most 24 characters long.';
  if (!/^[A-Za-z0-9_.-]+$/.test(name)) return 'Username can only contain letters, numbers, dots, dashes and underscores.';
  if (!opts.allowReserved && isReservedUsername(name)) return 'This username is reserved. Please choose another one.';
  return '';
}
// bcrypt only reads the first 72 BYTES of a password, so longer passwords would silently be cut. New passwords are limited to 72 bytes instead.
const MAX_PASSWORD_BYTES = 72;
function passwordProblems(pw) {
  const bad = [];
  if (pw.length < 10) bad.push('at least 10 characters');
  if (Buffer.byteLength(pw, 'utf8') > MAX_PASSWORD_BYTES) bad.push(`at most ${MAX_PASSWORD_BYTES} bytes (symbols and non-English letters take more than one)`);
  if (!/[a-z]/.test(pw)) bad.push('a lowercase letter');
  if (!/[A-Z]/.test(pw)) bad.push('an uppercase letter');
  if (!/[0-9]/.test(pw)) bad.push('a number');
  if (!/[^A-Za-z0-9]/.test(pw)) bad.push('a symbol');
  return bad;
}

// ---------- ip bans (table is created by the main site) ----------
async function activeIpBan(ip) {
  if (!ip) return null;
  try {
    const rs = await db.execute({ sql: 'SELECT * FROM ip_bans WHERE ip = ?', args: [ip] });
    if (!rs.rows.length) return null;
    const r = rs.rows[0];
    const until = Number(r.bannedUntil);
    if (until !== -1 && until <= Date.now()) { await db.execute({ sql: 'DELETE FROM ip_bans WHERE ip = ?', args: [ip] }); return null; }
    return { until, reason: r.reason || '' };
  } catch (e) { return null; }
}
function ipBanText(ban) {
  let when = 'permanently';
  if (ban.until !== -1) {
    const ms = Math.max(0, ban.until - Date.now());
    const d = Math.floor(ms / DAY), h = Math.floor(ms / 3600000) % 24, m = Math.floor(ms / 60000) % 60;
    when = 'for another ' + (d > 0 ? `${d}d ${h}h` : (h > 0 ? `${h}h ${m}m` : `${Math.max(1, m)}m`));
  }
  return `Your IP address is banned ${when}.` + (ban.reason ? ` Reason: ${ban.reason}` : '');
}

// ---------- ip tracking + VPN / proxy lookup ----------
// Every IP an account uses is saved in user_ips. New IPs are looked up once and cached in ip_info for 30 days.
// Lookups ONLY go over HTTPS (an IP address and the API key must never travel in clear text). The free plain-HTTP ip-api.com endpoint is no longer used.
// Env vars: IPAPIIS_KEY (free key from ipapi.is, 1000 lookups/day)  or  IPAPI_KEY (paid ip-api.com key, https://pro.ip-api.com)  -  VPN_CHECK=0 turns the lookup off.
// Without a key no lookup is made and the "VPN / proxy" flag simply stays empty.
const isPrivateIp = (ip) => !ip || ip === '::1' || /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fc|fd|fe80)/i.test(ip);
const ipSeen = new Map(), ipPending = new Set();
function ipLookupProvider() {
  if (process.env.VPN_CHECK === '0') return null;
  const k1 = cleanEnv(process.env.IPAPIIS_KEY), k2 = cleanEnv(process.env.IPAPI_KEY);
  if (k1) return {
    name: 'ipapi.is', perDay: 900,
    url: (ip) => `https://api.ipapi.is/?q=${encodeURIComponent(ip)}&key=${encodeURIComponent(k1)}`,
    parse: (j) => (j && j.ip && !j.error) ? { proxy: !!(j.is_proxy || j.is_vpn || j.is_tor), hosting: !!j.is_datacenter } : null
  };
  if (k2) return {
    name: 'ip-api.com', perDay: 20000,
    url: (ip) => `https://pro.ip-api.com/json/${encodeURIComponent(ip)}?fields=status,proxy,hosting&key=${encodeURIComponent(k2)}`,
    parse: (j) => (j && j.status === 'success') ? { proxy: !!j.proxy, hosting: !!j.hosting } : null
  };
  return null;
}
async function checkIpInfo(ip) {
  const provider = ipLookupProvider();
  if (!provider || isPrivateIp(ip) || ipPending.has(ip)) return;
  const rs = await db.execute({ sql: 'SELECT checkedAt FROM ip_info WHERE ip = ?', args: [ip] });
  if (rs.rows.length && Date.now() - Number(rs.rows[0].checkedAt) < 30 * DAY) return;
  if (limited('ipapi', 40, 60 * 1000) || limited('ipapi-day', provider.perDay, DAY)) return;          // stay inside the provider's quota; retried the next time the IP is seen
  ipPending.add(ip);
  try {
    const url = provider.url(ip);
    if (!url.startsWith('https://')) return;               // belt and braces: never fall back to plain HTTP
    const r = await fetch(url, { signal: AbortSignal.timeout(5000) });
    const out = provider.parse(await r.json());
    if (!out) return;
    await db.execute({ sql: 'INSERT INTO ip_info (ip, proxy, hosting, checkedAt) VALUES (?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET proxy = excluded.proxy, hosting = excluded.hosting, checkedAt = excluded.checkedAt', args: [ip, out.proxy ? 1 : 0, out.hosting ? 1 : 0, Date.now()] });
  } catch (e) { /* lookup failed: try again later */ }
  finally { ipPending.delete(ip); }
}
function trackIp(username, ip) {
  if (!username || !ip) return;
  const key = username + '|' + ip, now = Date.now();
  if (now - (ipSeen.get(key) || 0) < 10 * 60 * 1000) return;     // write at most once per 10 minutes per account+IP
  ipSeen.set(key, now);
  db.execute({ sql: 'INSERT INTO user_ips (username, ip, firstSeen, lastSeen) VALUES (?, ?, ?, ?) ON CONFLICT(username, ip) DO UPDATE SET lastSeen = excluded.lastSeen', args: [username, ip, now, now] }).catch(() => {});
  checkIpInfo(ip).catch(() => {});
}
setInterval(() => { const cut = Date.now() - DAY; for (const [k, t] of ipSeen) if (t < cut) ipSeen.delete(k); }, 60 * 60 * 1000);

// ---------- sessions ----------
// The browser holds a random 256-bit token; the database only ever stores its SHA-256 (sessions.id / admin_sessions.tokenHash),
// so a database leak or backup cannot be replayed as logins. Sessions point at the permanent numeric user id, so renames never break them.
const cookieOpts = (maxAge) => ({ httpOnly: true, secure: CROSS_SITE ? true : IS_SECURE, sameSite: CROSS_SITE ? 'none' : 'lax', maxAge, path: '/' });
const clearOpts = () => ({ ...cookieOpts(0), maxAge: undefined });
const ADMIN_LOGIN_MS = 12 * 60 * 60 * 1000;          // an admin account's login session lasts 12 hours (everyone else: 30 days)
const ADMIN_IDLE_MS = 30 * 60 * 1000;                 // admin powers expire after 30 minutes without admin activity ...
const ADMIN_MAX_MS = 4 * 60 * 60 * 1000;              // ... and never last longer than 4 hours in total, however active
const tokenOk = (t) => /^[a-f0-9]{64}$/.test(String(t || ''));
const isAdminId = (customId) => String(customId || '') === 'knqw';
// Optional network restriction for the admin: ADMIN_IPS=1.2.3.4,5.6.7.8 (empty = any address; password re-entry is still required)
const ADMIN_IPS = new Set(String(process.env.ADMIN_IPS || '').split(',').map(s => s.trim().toLowerCase().replace(/^::ffff:/, '')).filter(Boolean));
const adminIpAllowed = (req) => !ADMIN_IPS.size || ADMIN_IPS.has(ipOf(req));
function readSids(req) {
  return String((req && req.cookies && req.cookies.sids) || '').split(',').filter(tokenOk).slice(0, 10);
}
// Registers a new login for this browser. Admin sessions are NEVER added to the "remembered accounts" cookie, so the admin is not offered in the account switcher.
// opts.makeCurrent = false adds the account to the switcher without leaving the current one.
async function startSession(res, user, opts = {}) {
  const raw = crypto.randomBytes(32).toString('hex'), now = Date.now();
  const ttl = user.isAdmin ? ADMIN_LOGIN_MS : SESSION_MS;
  await db.execute({ sql: 'INSERT INTO sessions (id, username, userId, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)', args: [skey(raw), user.username, user.id, now, now + ttl] });
  const sids = readSids(res.req);
  if (opts.makeCurrent !== false) {
    const prev = String(res.req.cookies.sid || '');
    // a replaced session that is not remembered in the switcher (an admin session, say) would otherwise stay valid in the database with no cookie pointing at it
    if (tokenOk(prev) && !sids.includes(prev)) await dropSession(prev);
    res.cookie('sid', raw, cookieOpts(ttl));
  }
  if (!user.isAdmin) res.cookie('sids', [...sids.filter(x => x !== raw), raw].slice(-10).join(','), cookieOpts(SESSION_MS));
  return raw;
}
async function dropSession(raw) {                    // forget one login completely (including any admin power attached to it)
  const h = skey(raw);
  await db.execute({ sql: 'DELETE FROM admin_sessions WHERE sessionHash = ?', args: [h] });
  await db.execute({ sql: 'DELETE FROM sessions WHERE id = ?', args: [h] });
}
// Finds the user behind a session token. Falls back to the stored username when the numeric user id is missing or stale (old databases).
async function findSession(raw) {
  const k = skey(raw), now = Date.now();
  const sr = await db.execute({ sql: 'SELECT id, username, userId, expiresAt FROM sessions WHERE id = ?', args: [k] });
  if (!sr.rows.length) return { why: 'no sessions row for this cookie value' };
  const row = sr.rows[0];
  if (!(Number(row.expiresAt) > now)) return { why: `session expired (expiresAt=${row.expiresAt}, now=${now})` };
  let ur = row.userId != null ? await db.execute({ sql: 'SELECT id, username, displayName, customId, bannedUntil, mustChangePassword FROM users WHERE id = ?', args: [Number(row.userId)] }) : { rows: [] };
  if (!ur.rows.length && row.username) {
    ur = await db.execute({ sql: 'SELECT id, username, displayName, customId, bannedUntil, mustChangePassword FROM users WHERE username = ?', args: [String(row.username)] });
    if (ur.rows.length) { try { await db.execute({ sql: 'UPDATE sessions SET userId = ? WHERE id = ?', args: [Number(ur.rows[0].id), k] }); } catch (e) {} }
  }
  if (!ur.rows.length) return { why: `session found but its user is missing (userId=${row.userId}, username=${row.username})` };
  return { user: ur.rows[0] };
}
async function sessionInfo(raw) {                    // { id, username, displayName, isAdmin } for a valid raw token, else null
  if (!tokenOk(raw)) return null;
  const f = await findSession(raw);
  if (!f.user) return null;
  const u = f.user;
  return { id: Number(u.id), username: String(u.username), displayName: String(u.displayName || u.username), isAdmin: isAdminId(u.customId) };
}
const BANNED_OK = new Set(['/api/appeal', '/api/logout', '/api/logout-all', '/api/heartbeat']);
const MUST_CHANGE_OK = new Set(['/api/change-password', '/api/logout', '/api/logout-all', '/api/heartbeat']);
let dbg401Count = 0;
function dbg401(req, why) { if (dbg401Count++ < 60) console.warn(`401 ${req.method} ${req.path}: ${why} (origin ${req.headers.origin || '-'}, host ${req.headers.host}, cookies: ${Object.keys(req.cookies || {}).join(',') || 'none'})`); }
export async function requireUser(req, res, next) {      // use this on every future endpoint
  try {
    const raw = String(req.cookies.sid || '');
    if (!tokenOk(raw)) { dbg401(req, 'no valid sid cookie'); return res.status(401).json({ error: 'Please log in.' }); }
    const f = await findSession(raw);
    if (!f.user) { dbg401(req, f.why); return res.status(401).json({ error: 'Please log in.' }); }
    const r = { rows: [f.user] };
    req.user = String(r.rows[0].username);
    req.userId = Number(r.rows[0].id);
    req.isAdminAccount = isAdminId(r.rows[0].customId);
    // a banned account may still read and send its appeal, but cannot do anything else (no chat, pictures, deals, renames...)
    const bannedUntil = Number(r.rows[0].bannedUntil) || 0;
    if ((bannedUntil === -1 || bannedUntil > Date.now()) && req.method !== 'GET' && !BANNED_OK.has(req.path)) return res.status(403).json({ error: 'Your account is banned.', banned: true });
    // after an admin reset the temporary password only works for choosing a new one
    if (Number(r.rows[0].mustChangePassword) === 1 && req.method !== 'GET' && !MUST_CHANGE_OK.has(req.path)) return res.status(403).json({ error: 'Choose a new password first.', mustChangePassword: true });
    trackIp(req.user, ipOf(req));
    next();
  } catch (e) { console.error('requireUser failed:', e); res.status(500).json({ error: 'Server error' }); }
}
const safeEqual = (a, b) => {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
};
// password check shared by login, add-account, change-password and the admin re-confirmation. Old plaintext passwords are upgraded to a hash on first use.
async function verifyPassword(u, password) {
  let ok = false;
  if (u.passwordHash) ok = await bcrypt.compare(password, String(u.passwordHash));
  if (!ok && /^\$2[aby]\$/.test(String(u.password || ''))) { try { ok = await bcrypt.compare(password, String(u.password)); } catch (e) {} if (ok) await db.execute({ sql: "UPDATE users SET passwordHash = ?, password = '' WHERE id = ?", args: [String(u.password), Number(u.id)] }); }   // an old bcrypt hash kept in the plain column
  if (!ok && u.password && safeEqual(u.password, password)) {
    ok = true;
    await db.execute({ sql: "UPDATE users SET passwordHash = ?, password = '' WHERE id = ?", args: [await bcrypt.hash(password, 12), Number(u.id)] });   // plaintext is wiped as soon as the hash exists
  }
  return ok;
}

// ---------- sign-in lock-outs: keyed by IP + ACCOUNT ----------
// 3 wrong passwords from one IP for one account lock that pair out for 3 hours; after the lock ends, 3 more wrong passwords lock it for 24 hours.
// Somebody guessing at your account from their own IP therefore cannot lock YOU out (your IP has its own counter), and the counters survive restarts.
// Names that do not exist are counted exactly like real ones, so the lock-out cannot be used to discover accounts.
const LOCK_AFTER = 3, LOCK_FIRST_MS = 3 * 60 * 60 * 1000, LOCK_NEXT_MS = 24 * 60 * 60 * 1000, LOCK_FORGET_MS = 7 * DAY;
const LOCK_SECRET = cleanEnv(process.env.IP_HASH_SECRET || TURSO_TOKEN || 'starfall-ip-guard-change-me');
const lockKey = (scope, ip, account) => crypto.createHmac('sha256', LOCK_SECRET).update(`${scope}|${ip}|${String(account).toLowerCase()}`).digest('hex');
const lockText = (ms) => { const h = Math.floor(ms / 3600000), m = Math.max(1, Math.ceil((ms % 3600000) / 60000)); return h > 0 ? `${h}h ${m}m` : `${m}m`; };
async function lockoutStatus(key) {                 // { locked, lockedUntil, retryAfterMs }
  const r = await db.execute({ sql: 'SELECT lockedUntil FROM login_lockouts WHERE k = ?', args: [key] });
  const until = r.rows.length ? Number(r.rows[0].lockedUntil) || 0 : 0;
  return until > Date.now() ? { locked: true, lockedUntil: until, retryAfterMs: until - Date.now() } : { locked: false, lockedUntil: 0, retryAfterMs: 0 };
}
function lockoutFail(key) {
  return withWalletLock('lock:' + key, async () => {
    const now = Date.now();
    const r = await db.execute({ sql: 'SELECT fails, level, lastFailAt FROM login_lockouts WHERE k = ?', args: [key] });
    let fails = 0, level = 0;
    if (r.rows.length && now - Number(r.rows[0].lastFailAt) < LOCK_FORGET_MS) { fails = Number(r.rows[0].fails) || 0; level = Number(r.rows[0].level) || 0; }
    fails++;
    let lockedUntil = 0;
    if (fails >= LOCK_AFTER) { level++; lockedUntil = now + (level >= 2 ? LOCK_NEXT_MS : LOCK_FIRST_MS); fails = 0; }
    await db.execute({ sql: 'INSERT INTO login_lockouts (k, fails, level, lockedUntil, lastFailAt) VALUES (?, ?, ?, ?, ?) ON CONFLICT(k) DO UPDATE SET fails = excluded.fails, level = excluded.level, lockedUntil = excluded.lockedUntil, lastFailAt = excluded.lastFailAt', args: [key, fails, level, lockedUntil, now] });
    return { locked: lockedUntil > now, lockedUntil, retryAfterMs: Math.max(0, lockedUntil - now), attemptsLeft: lockedUntil ? 0 : LOCK_AFTER - fails };
  });
}
const lockoutClear = (key) => db.execute({ sql: 'DELETE FROM login_lockouts WHERE k = ?', args: [key] });
const lockedReply = (st) => ({ error: `Too many incorrect attempts. Sign-in is locked for this account from your network. Try again in ${lockText(st.retryAfterMs)}.`, locked: true, lockedUntil: st.lockedUntil, retryAfterMs: st.retryAfterMs });

const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 12);
const BAD_LOGIN = 'Incorrect username/email or password.';
// Checks "username or email" + password. Returns { user } on success or { status, body } to send. Never reveals whether the account exists.
async function authenticate(req, id, password, scope) {
  const ip = ipOf(req);
  if (limited(scope + ':' + ip, 20, 15 * 60 * 1000)) return { status: 429, body: { error: 'Too many attempts. Try again in a few minutes.' } };
  if (!id || !password) return { status: 400, body: { error: 'Please fill in all fields.' } };
  if (id.length > 254 || password.length > 1000) return { status: 400, body: { error: BAD_LOGIN } };
  const rs = await db.execute({ sql: 'SELECT * FROM users WHERE lower(username) = lower(?) OR lower(email) = lower(?) ORDER BY (lower(username) = lower(?)) DESC LIMIT 1', args: [id, id, id] });
  const u = rs.rows.length ? rs.rows[0] : null;
  // the same person typing their e-mail or their username must hit the same counter, so the key uses the account id when there is one
  const key = lockKey('login', ip, u ? 'u' + u.id : 'n:' + id);
  const st = await lockoutStatus(key);
  if (st.locked) { if (!u) await bcrypt.compare(password, DUMMY_HASH); return { status: 429, body: lockedReply(st) }; }
  const ok = u ? await verifyPassword(u, password) : (await bcrypt.compare(password, DUMMY_HASH), false);   // same work either way, so timing gives nothing away
  if (!ok) {
    const f = await lockoutFail(key);
    return { status: f.locked ? 429 : 401, body: f.locked ? lockedReply(f) : { error: BAD_LOGIN, attemptsLeft: f.attemptsLeft } };
  }
  await lockoutClear(key);
  return { user: u };
}

// ---------- admin elevation ----------
// Signing in as the admin account gives ordinary user powers only. Anything under /api/admin needs a separate, short-lived "elevated" token
// that is minted only after the admin password is typed again (POST /api/admin/elevate). It is bound to the login session, optionally to ADMIN_IPS,
// expires after 30 idle minutes / 4 hours total, and only its hash is stored.
async function adminElevation(req) {
  if (req._adminElev !== undefined) return req._adminElev;
  let out = null;
  const token = String(req.cookies.admin_sid || ''), sid = String(req.cookies.sid || '');
  if (req.isAdminAccount && tokenOk(token) && tokenOk(sid) && adminIpAllowed(req)) {
    const now = Date.now();
    const r = await db.execute({
      sql: `SELECT a.tokenHash, a.expiresAt, a.maxExpiresAt FROM admin_sessions a
            JOIN sessions s ON s.id = a.sessionHash AND s.userId = a.userId
            JOIN users u ON u.id = a.userId
            WHERE a.tokenHash = ? AND a.sessionHash = ? AND a.userId = ? AND a.expiresAt > ? AND s.expiresAt > ? AND u.customId = 'knqw'`,
      args: [skey(token), skey(sid), req.userId, now, now]
    });
    if (r.rows.length) {
      const cur = Number(r.rows[0].expiresAt), max = Number(r.rows[0].maxExpiresAt);
      const next = Math.min(now + ADMIN_IDLE_MS, max);
      if (next - cur > 60 * 1000) await db.execute({ sql: 'UPDATE admin_sessions SET expiresAt = ? WHERE tokenHash = ?', args: [next, skey(token)] });   // sliding idle timeout, written at most once a minute
      out = { expiresAt: Math.max(cur, next), maxExpiresAt: max };
    }
  }
  req._adminElev = out;
  return out;
}
async function requireAdmin(req, res, next) {
  try {
    if (!req.isAdminAccount) return res.status(403).json({ error: 'A valid admin session is required.' });
    if (!adminIpAllowed(req)) return res.status(403).json({ error: 'Admin access is not allowed from this network.' });
    if (!(await adminElevation(req))) return res.status(403).json({ error: 'Confirm your admin password to continue.', adminElevationRequired: true });
    next();
  } catch (e) { console.error('admin session validation failed:', e); res.status(500).json({ error: 'Server error' }); }
}
const isElevatedAdmin = async (req) => !!(req.isAdminAccount && await adminElevation(req));

// ---------- API ----------
app.get('/api/health', async (req, res) => {
  if (!req.query.deep) return res.json({ ok: true });
  // /api/health?deep=1 tells you whether the database connection really works (set DEBUG_HEALTH=1 in Render to also see the error text)
  const out = { ok: true, read: false, write: false };
  const show = process.env.DEBUG_HEALTH === '1';
  try { await db.execute('SELECT COUNT(*) FROM users'); out.read = true; } catch (e) { out.ok = false; if (show) out.readError = String(e.message || e).slice(0, 200); }
  try { await db.execute('CREATE TABLE IF NOT EXISTS _healthcheck (t INTEGER)'); await db.execute({ sql: 'INSERT INTO _healthcheck (t) VALUES (?)', args: [Date.now()] }); await db.execute('DELETE FROM _healthcheck'); out.write = true; }
  catch (e) { out.ok = false; if (show) out.writeError = String(e.message || e).slice(0, 200); }
  res.status(out.ok ? 200 : 500).json(out);
});

app.get('/api/ip-status', async (req, res) => {
  const ban = await activeIpBan(ipOf(req));
  res.json(ban ? { banned: true, message: ipBanText(ban) } : { banned: false });
});

app.get('/api/me', requireUser, async (req, res) => {
  const r = await db.execute({ sql: 'SELECT username, displayName, customId FROM users WHERE id = ?', args: [req.userId] });
  if (!r.rows.length) return res.status(401).json({ error: 'Please log in.' });
  const isAdmin = isAdminId(r.rows[0].customId);
  const el = isAdmin ? await adminElevation(req) : null;
  res.json({ username: r.rows[0].username, displayName: r.rows[0].displayName || r.rows[0].username, isAdmin, adminElevated: !!el, adminExpiresAt: el ? el.expiresAt : 0 });
});

app.get('/api/check-username', async (req, res) => {
  if (limited('chk:' + ipOf(req), 120, 60 * 1000)) return res.status(429).json({ error: 'Too many requests' });
  const name = String(req.query.name || '').trim();
  const err = checkUsername(name);
  if (err) return res.json({ ok: false, message: err });
  const r = await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(username) = lower(?) LIMIT 1', args: [name] });
  res.json(r.rows.length ? { ok: false, message: 'This username is already taken.' } : { ok: true, message: 'Username is available.' });
});

app.get('/api/check-email', async (req, res) => {
  if (limited('chk:' + ipOf(req), 120, 60 * 1000)) return res.status(429).json({ error: 'Too many requests' });
  const email = String(req.query.email || '').trim().toLowerCase();
  const err = await checkEmail(email);
  if (err) return res.json({ ok: false, message: err });
  // only the format / domain is checked here: whether an email already has an account is never revealed
  res.json({ ok: true, message: 'Email looks good.' });
});

app.post('/api/signup', async (req, res) => {
  const fail = (message, code = 400) => res.status(code).json({ error: message });
  try {
    const ip = ipOf(req);
    if (limited('signup:' + ip, 15, 60 * 60 * 1000)) return fail('Too many attempts. Try again later.', 429);
    const username = String(req.body.username || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!username || !email || !password) return fail('Please fill in all fields.');

    const ban = await activeIpBan(ip);
    if (ban) return fail(ipBanText(ban), 403);

    const uErr = checkUsername(username); if (uErr) return fail(uErr);
    const eErr = await checkEmail(email); if (eErr) return fail(eErr);
    const pBad = passwordProblems(password);
    if (pBad.length) return fail('Your password is too weak. It needs: ' + pBad.join(', ') + '.');
    if (req.body.ageConfirmed !== true) return fail('You must confirm that you are at least 13 years old.');

    // one account per day: per IP (signup_log + accounts last seen on this IP) and per device cookie
    const now = Date.now();
    let wait = 0;
    const devLast = Number(req.cookies.ut_su) || 0;
    if (devLast && now - devLast < DAY) wait = Math.max(wait, DAY - (now - devLast));
    if (ip) {
      const a = await db.execute({ sql: 'SELECT MAX(createdAt) AS t FROM signup_log WHERE ip = ?', args: [ip] });
      const t1 = Number(a.rows[0] && a.rows[0].t) || 0;
      if (t1 && now - t1 < DAY) wait = Math.max(wait, DAY - (now - t1));
      const b = await db.execute({ sql: 'SELECT MAX(joinedAt) AS t FROM users WHERE lastIp = ?', args: [ip] });
      const t2 = Number(b.rows[0] && b.rows[0].t) || 0;
      if (t2 && now - t2 < DAY) wait = Math.max(wait, DAY - (now - t2));
    }
    if (wait > 0) {
      const h = Math.floor(wait / 3600000), m = Math.max(1, Math.ceil((wait % 3600000) / 60000));
      return fail(`Only one account can be created per day. Please try again in ${h > 0 ? h + 'h ' : ''}${m}m.`, 429);
    }

    if ((await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(username) = lower(?) LIMIT 1', args: [username] })).rows.length) return fail('This username is already taken.');
    // neutral message: does not confirm that an account with this email exists
    if ((await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(email) = ? LIMIT 1', args: [email] })).rows.length) return fail('We could not create an account with these details. Check them and try again, or log in if you already have an account.');

    const hash = await bcrypt.hash(password, 12);
    // customId = COUNT(*)+1, as in the original version
    let newId = 0;
    const tx = await db.transaction('write');
    try {
      const ins = await tx.execute({
        sql: 'INSERT INTO users (customId, username, displayName, email, password, passwordHash, lastIp, joinedAt, balanceCents, heldBalanceCents) VALUES (CAST((SELECT COUNT(*) + 1 FROM users) AS TEXT), ?, ?, ?, ?, ?, ?, ?, 0, 0)',
        args: [username, username, email, '', hash, ip || null, now]
      });
      newId = Number(ins.lastInsertRowid);
      await tx.commit();
    } catch (e) {
      try { await tx.rollback(); } catch (_) {}
      if (String(e.message || e).toUpperCase().includes('UNIQUE')) return fail('This username is already taken.');
      throw e;
    } finally { tx.close(); }
    if (ip) await db.execute({ sql: 'INSERT INTO signup_log (ip, createdAt) VALUES (?, ?)', args: [ip, now] });
    trackIp(username, ip);
    res.cookie('ut_su', String(now), cookieOpts(DAY));
    await startSession(res, { id: newId, username, isAdmin: false });
    res.json({ username });
  } catch (e) {
    console.error('signup error:', e);
    fail('Server error during registration. Try again.', 500);
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const id = String(req.body.id || '').trim(), password = String(req.body.password || '');
    const r = await authenticate(req, id, password, 'login');
    if (!r.user) return res.status(r.status).json(r.body);
    const u = r.user, ip = ipOf(req), isAdmin = isAdminId(u.customId);
    if (!isAdmin) {
      const ban = await activeIpBan(ip);
      if (ban) return res.status(403).json({ error: ipBanText(ban) });
    }
    if (ip) { try { await db.execute({ sql: 'UPDATE users SET lastIp = ? WHERE id = ?', args: [ip, Number(u.id)] }); } catch (e) {} }
    trackIp(String(u.username), ip);
    const newSid = await startSession(res, { id: Number(u.id), username: String(u.username), isAdmin });
    res.clearCookie('admin_sid', clearOpts());          // a fresh sign-in never inherits admin powers: they are granted separately, after the password is typed again
    console.log(`login ok for ${u.username}: origin ${req.headers.origin || '-'}, cookie flags ${CROSS_SITE ? 'SameSite=None; Secure (cross-site)' : (IS_SECURE ? 'SameSite=Lax; Secure' : 'SameSite=Lax')}`);
    // only for a page hosted on another site: it needs the token because its cookie may be blocked
    const crossPage = req.headers.origin && req.headers.origin !== `${req.protocol}://${req.headers.host}`;
    res.json({ username: String(u.username), isAdmin, ...(crossPage && !isAdmin ? { token: newSid } : {}) });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ error: 'Server error. Try again later.' });
  }
});

// ---------- the accounts this browser is signed into ("Manage Accounts") ----------
// Each remembered login is a secret session token in this browser's own httpOnly "sids" cookie. The admin account is never in that list.
app.get('/api/accounts', requireUser, async (req, res) => {
  const cur = String(req.cookies.sid || '');
  const infos = [];
  const seen = new Set();
  for (const raw of readSids(req)) {
    const info = await sessionInfo(raw);
    if (!info || info.isAdmin || seen.has(info.id)) continue;
    seen.add(info.id);
    infos.push({ ...info, current: raw === cur });
  }
  if (!req.isAdminAccount && !seen.has(req.userId)) infos.unshift({ id: req.userId, username: req.user, displayName: req.user, isAdmin: false, current: true });
  let withAvatar = new Set();
  if (infos.length) {
    const rs = await db.execute({ sql: `SELECT id, displayName, (CASE WHEN avatar IS NOT NULL AND avatar != '' THEN 1 ELSE 0 END) AS hasAvatar FROM users WHERE id IN (${infos.map(() => '?').join(',')})`, args: infos.map(i => i.id) });
    withAvatar = new Set(rs.rows.filter(r => Number(r.hasAvatar)).map(r => Number(r.id)));
    const names = new Map(rs.rows.map(r => [Number(r.id), String(r.displayName || '')]));
    infos.forEach(i => { if (names.get(i.id)) i.displayName = names.get(i.id); });
  }
  res.json({
    current: req.user, currentIsAdmin: req.isAdminAccount,
    accounts: infos.map(i => ({ username: i.username, displayName: i.displayName, avatar: withAvatar.has(i.id) ? '/api/avatar/' + encodeURIComponent(i.username) : null, current: i.current }))
  });
});

// Switch between accounts this browser is ALREADY logged into. The username in the body is only a choice among them:
// it works only if one of the secret session tokens in this browser's own httpOnly "sids" cookie belongs to that account
// and is still valid, so it cannot be used to become someone this browser never logged in as. The admin can never be switched to.
app.post('/api/switch', async (req, res) => {
  try {
    if (limited('switch:' + ipOf(req), 30, 60 * 1000)) return res.status(429).json({ error: 'Too many attempts. Try again in a minute.' });
    const username = String(req.body.username || '');
    const sids = readSids(req);
    if (!username || username.length > 100 || !sids.length) return res.status(401).json({ error: 'Please log in.' });
    for (const raw of sids) {
      const info = await sessionInfo(raw);
      if (!info || info.isAdmin || info.username !== username) continue;
      const prev = String(req.cookies.sid || '');
      if (tokenOk(prev) && prev !== raw && !sids.includes(prev)) await dropSession(prev);       // do not leave an orphaned (admin) session behind
      res.cookie('sid', raw, cookieOpts(SESSION_MS));
      res.clearCookie('admin_sid', clearOpts());
      return res.json({ username });
    }
    res.status(401).json({ error: 'Please log in.' });
  } catch (e) { console.error('switch error:', e); res.status(500).json({ error: 'Server error' }); }
});

// "Add account": signs ANOTHER existing account in (it is not registration) without leaving the current one. The new account appears in Manage Accounts.
app.post('/api/accounts/add', requireUser, async (req, res) => {
  try {
    const id = String((req.body && req.body.id) || '').trim(), password = String((req.body && req.body.password) || '');
    const r = await authenticate(req, id, password, 'addacct');
    if (!r.user) return res.status(r.status).json(r.body);
    const u = r.user;
    if (isAdminId(u.customId)) return res.status(403).json({ error: 'This account cannot be added here. Sign in on the login page instead.' });
    if (Number(u.id) === req.userId) return res.status(409).json({ error: 'You are already signed in to this account.' });
    const ban = await activeIpBan(ipOf(req));
    if (ban) return res.status(403).json({ error: ipBanText(ban) });
    // an older remembered login of the same account is replaced, so the list never shows one account twice
    const keep = [];
    for (const raw of readSids(req)) {
      const info = await sessionInfo(raw);
      if (info && info.id === Number(u.id)) { await dropSession(raw); continue; }
      keep.push(raw);
    }
    req.cookies.sids = keep.join(',');
    await startSession(res, { id: Number(u.id), username: String(u.username), isAdmin: false }, { makeCurrent: false });
    res.json({ ok: true, username: String(u.username) });
  } catch (e) { console.error('add account error:', e); res.status(500).json({ error: 'Server error. Try again later.' }); }
});

// Remove ONE account from this browser (signs that account out here). If it was the account in use, another remembered account takes over, if any.
app.post('/api/accounts/remove', requireUser, async (req, res) => {
  try {
    const target = String((req.body && req.body.username) || '');
    const cur = String(req.cookies.sid || '');
    const sids = readSids(req);
    let victim = null;
    for (const raw of sids.concat(tokenOk(cur) && !sids.includes(cur) ? [cur] : [])) {
      const info = await sessionInfo(raw);
      if (info && info.username === target) { victim = raw; break; }
    }
    if (!victim) return res.status(404).json({ error: 'That account is not signed in on this browser.' });
    await dropSession(victim);
    const left = sids.filter(x => x !== victim);
    res.cookie('sids', left.join(','), cookieOpts(SESSION_MS));
    if (victim !== cur) return res.json({ ok: true, wasCurrent: false, next: null });
    res.clearCookie('admin_sid', clearOpts());
    for (const raw of left.slice().reverse()) {
      const info = await sessionInfo(raw);
      if (info && !info.isAdmin) { res.cookie('sid', raw, cookieOpts(SESSION_MS)); return res.json({ ok: true, wasCurrent: true, next: info.username }); }
    }
    res.clearCookie('sid', clearOpts());
    res.json({ ok: true, wasCurrent: true, next: null });
  } catch (e) { console.error('remove account error:', e); res.status(500).json({ error: 'Server error' }); }
});

// Log out of the account in use (single-account case).
app.post('/api/logout', async (req, res) => {
  const cur = String(req.cookies.sid || '');
  try { if (tokenOk(cur)) await dropSession(cur); } catch (e) { console.error('logout error:', e); }
  res.cookie('sids', readSids(req).filter(x => x !== cur).join(','), cookieOpts(SESSION_MS));
  res.clearCookie('admin_sid', clearOpts());
  res.clearCookie('sid', clearOpts());
  res.json({ ok: true });
});
// Log out of EVERY account remembered in this browser (and the one in use).
app.post('/api/logout-all', async (req, res) => {
  const cur = String(req.cookies.sid || '');
  try { for (const raw of new Set([...readSids(req), ...(tokenOk(cur) ? [cur] : [])])) await dropSession(raw); } catch (e) { console.error('logout-all error:', e); }
  res.clearCookie('sids', clearOpts());
  res.clearCookie('admin_sid', clearOpts());
  res.clearCookie('sid', clearOpts());
  res.json({ ok: true });
});

// ======================================================================
// Stage 2: password change, wallet, deals, admin money tools
// Every route below needs a logged-in session; money logic runs ONLY here.
// ======================================================================
const ADMIN_MAX_ADJUST = Number(process.env.ADMIN_MAX_ADJUST) || 10000, ADMIN_DAILY_CAP = Number(process.env.ADMIN_DAILY_CAP) || 100000;   // set these in Render to change the limits
const SELLER_SHARE = 0.9;
const MIN_DEAL = 0.01, MAX_DEAL = 1000000;
const MIN_TOPUP = 1, MAX_TOPUP = 10000;
const round2 = (n) => Math.round(Number(n) * 100) / 100;
const toCents = (v) => Math.round(Number(v) * 100);
const fromCents = (v) => (Number(v) || 0) / 100;
const parseMoney = (v) => { if (typeof v !== 'number' && (typeof v !== 'string' || !/^\d{1,9}(?:\.\d{1,2})?$/.test(v.trim()))) return NaN; const n = Number(v); return Number.isFinite(n) ? toCents(n) : NaN; };

// ---- admin audit trail ----
// auditRaw writes one row. auditReq also marks the request as "already audited" so the catch-all below does not add a second, generic row.
const auditRaw = (admin, action, target, detail, amount) => db.execute({ sql: 'INSERT INTO admin_audit (admin, action, target, detail, amount, createdAt) VALUES (?, ?, ?, ?, ?, ?)', args: [admin, action, String(target || '').slice(0, 200), String(detail || '').slice(0, 300), Number(amount) || 0, Date.now()] }).catch(e => console.error('audit failed:', e.message));
const auditReq = (req, res, action, target, detail, amount) => { if (res && res.locals) res.locals.audited = true; return auditRaw(req.user, action, target, detail, amount); };
const SECRET_KEYS = new Set(['password', 'currentpassword', 'newpassword', 'token', 'secret']);
const auditBody = (b) => { try { return JSON.stringify(Object.fromEntries(Object.entries(b && typeof b === 'object' ? b : {}).filter(([k]) => !SECRET_KEYS.has(k.toLowerCase())).map(([k, v]) => [k, typeof v === 'string' ? v.slice(0, 60) : v]))).slice(0, 300); } catch (e) { return ''; } };

// Admin power must be earned again with the admin password (and expires quickly): these two routes sit BEFORE the /api/admin guard on purpose.
app.post('/api/admin/elevate', requireUser, async (req, res) => {
  try {
    if (!req.isAdminAccount) return res.status(403).json({ error: 'A valid admin session is required.' });
    const ip = ipOf(req);
    if (!adminIpAllowed(req)) { auditRaw(req.user, 'elevate-denied', '', `address ${ip} is not in ADMIN_IPS`, 0); return res.status(403).json({ error: 'Admin access is not allowed from this network.' }); }
    const password = String((req.body && req.body.password) || '');
    if (!password || password.length > 1000) return res.status(400).json({ error: 'Enter your admin password.' });
    const key = lockKey('admin', ip, req.userId);
    const st = await lockoutStatus(key);
    if (st.locked) return res.status(429).json(lockedReply(st));
    const me = (await db.execute({ sql: 'SELECT id, password, passwordHash FROM users WHERE id = ?', args: [req.userId] })).rows[0];
    if (!me || !(await verifyPassword(me, password))) {
      const f = await lockoutFail(key);
      auditRaw(req.user, 'elevate-failed', '', `wrong password from ${ip}`, 0);
      return res.status(f.locked ? 429 : 403).json(f.locked ? lockedReply(f) : { error: 'Incorrect password.', attemptsLeft: f.attemptsLeft });
    }
    await lockoutClear(key);
    const token = crypto.randomBytes(32).toString('hex'), sidHash = skey(String(req.cookies.sid || '')), now = Date.now();
    await db.execute({ sql: 'DELETE FROM admin_sessions WHERE sessionHash = ?', args: [sidHash] });
    await db.execute({ sql: 'INSERT INTO admin_sessions (tokenHash, userId, username, sessionHash, createdAt, expiresAt, maxExpiresAt, ipHash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', args: [skey(token), req.userId, req.user, sidHash, now, now + ADMIN_IDLE_MS, now + ADMIN_MAX_MS, ipFingerprint(ip)] });
    res.cookie('admin_sid', token, cookieOpts(ADMIN_MAX_MS));
    auditRaw(req.user, 'elevate', '', `admin session started from ${ip}`, 0);
    res.json({ ok: true, expiresAt: now + ADMIN_IDLE_MS });
  } catch (e) { console.error('elevate error:', e); res.status(500).json({ error: 'Server error. Try again.' }); }
});
app.post('/api/admin/elevate/end', requireUser, async (req, res) => {
  try { await db.execute({ sql: 'DELETE FROM admin_sessions WHERE sessionHash = ?', args: [skey(String(req.cookies.sid || ''))] }); } catch (e) { console.error(e); }
  res.clearCookie('admin_sid', clearOpts());
  if (req.isAdminAccount) auditRaw(req.user, 'elevate-end', '', 'admin session ended', 0);
  res.json({ ok: true });
});
// Defense in depth: every other /api/admin/* route is protected here even if a route is added later without explicitly attaching the authorization middleware.
// Every state-changing admin request that does not write its own, more detailed audit row gets a generic one, so nothing an admin does is unrecorded.
app.use('/api/admin', requireUser, requireAdmin, (req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.on('finish', () => { if (!res.locals.audited && res.statusCode < 400) auditRaw(req.user, 'admin-op', `${req.method} ${req.originalUrl.split('?')[0]}`, auditBody(req.body), 0); });
  }
  next();
});
class Abort extends Error { constructor(msg, code = 409) { super(msg); this.code = code; } }
// run fn(tx) in a write transaction; throw Abort(...) to roll back and answer with that message
async function inTx(res, fn) {
  const tx = await db.transaction('write');
  try {
    const out = await fn(tx);
    await tx.commit();
    return out;
  } catch (e) {
    try { await tx.rollback(); } catch (_) {}
    if (e instanceof Abort) { res.status(e.code).json({ error: e.message }); return undefined; }
    console.error('tx error:', e);
    res.status(500).json({ error: 'Server error. Nothing was changed.' });
    return undefined;
  } finally { tx.close(); }
}
const walletLocks = new Map();
async function withWalletLock(key, fn) {
  const k = String(key);
  const prior = walletLocks.get(k) || Promise.resolve();
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const tail = prior.then(() => gate);
  walletLocks.set(k, tail);
  await prior;
  try { return await fn(); }
  finally { release(); if (walletLocks.get(k) === tail) walletLocks.delete(k); }
}
const moneyLimit = (req, res, key, max, ms) => {
  if (limited(key + ':' + req.user, max, ms)) { res.status(429).json({ error: 'Too many requests. Slow down.' }); return true; }
  return false;
};

// ---------- password ----------
app.post('/api/change-password', requireUser, async (req, res) => {
  try {
    if (moneyLimit(req, res, 'pw', 8, 15 * 60 * 1000)) return;
    const cur = String(req.body.currentPassword || '');
    const next = String(req.body.newPassword || '');
    if (!cur || !next) return res.status(400).json({ error: 'Please fill in all fields.' });
    const rs = await db.execute({ sql: 'SELECT id, username, email, password, passwordHash FROM users WHERE id = ?', args: [req.userId] });
    if (!rs.rows.length) return res.status(401).json({ error: 'Please log in.' });
    const u = rs.rows[0];
    if (!(await verifyPassword(u, cur))) return res.status(403).json({ error: 'Current password is incorrect.' });
    const bad = passwordProblems(next);
    if (bad.length) return res.status(400).json({ error: 'Your new password is too weak. It needs: ' + bad.join(', ') + '.' });
    if (next === cur) return res.status(400).json({ error: 'Choose a password different from the current one.' });
    const hash = await bcrypt.hash(next, 12);
    // the legacy plaintext column is wiped; every other device is logged out (and loses any admin power); a reset-password flag is cleared
    const mine = skey(String(req.cookies.sid || ''));
    await db.execute({ sql: "UPDATE users SET passwordHash = ?, password = '', mustChangePassword = 0 WHERE id = ?", args: [hash, req.userId] });
    await db.execute({ sql: 'DELETE FROM sessions WHERE userId = ? AND id != ?', args: [req.userId, mine] });
    await db.execute({ sql: 'DELETE FROM admin_sessions WHERE userId = ? AND sessionHash != ?', args: [req.userId, mine] });
    res.json({ ok: true });
  } catch (e) { console.error('change-password error:', e); res.status(500).json({ error: 'Server error. Try again.' }); }
});

// ---------- wallet ----------
// Escrow overview: money I have PAID that is still held (to whom, for which item) and money held for me as a seller.
// Nothing here sits forever: a 'paid' deal is released to the seller automatically ESCROW_TIMEOUT_MS after payment (see the escrow job below).
const ESCROW_TIMEOUT_MS = (Number(process.env.ESCROW_TIMEOUT_DAYS) || 7) * DAY;
async function escrowFor(username) {
  const rs = await db.execute({
    sql: "SELECT id, buyer, seller, itemName, itemId, amountCents, sellerAmountCents, status, paidAt, updatedAt FROM deals WHERE (buyer = ? OR seller = ?) AND status IN ('paid','not_received','reported') ORDER BY COALESCE(paidAt, updatedAt) DESC LIMIT 200",
    args: [username, username]
  });
  const paid = [], incoming = [];
  for (const r of rs.rows) {
    const paidAt = Number(r.paidAt) || Number(r.updatedAt) || 0;
    // paid: released automatically on the date shown; not_received: sent to the admin on that date; reported: waiting for the admin (no date)
    const releaseAt = r.status === 'paid' ? paidAt + ESCROW_TIMEOUT_MS : r.status === 'not_received' ? (Number(r.updatedAt) || paidAt) + ESCROW_TIMEOUT_MS : 0;
    const base = { dealId: Number(r.id), itemName: r.itemName || '', itemId: r.itemId ? String(r.itemId) : '', status: r.status, paidAt, releaseAt };
    if (r.buyer === username) paid.push({ ...base, to: r.seller, amount: fromCents(r.amountCents) });
    if (r.seller === username) incoming.push({ ...base, from: r.buyer, amount: fromCents(r.sellerAmountCents) });
  }
  return {
    paid, incoming,
    totalPaid: paid.reduce((a, x) => a + Math.round(x.amount * 100), 0) / 100,
    totalIncoming: incoming.reduce((a, x) => a + Math.round(x.amount * 100), 0) / 100,
    timeoutDays: ESCROW_TIMEOUT_MS / DAY
  };
}
app.get('/api/wallet', requireUser, async (req, res) => {
  const r = await db.execute({ sql: 'SELECT balanceCents, heldBalanceCents, lastWithdrawAt FROM users WHERE id = ?', args: [req.userId] });
  if (!r.rows.length) return res.status(401).json({ error: 'Please log in.' });
  const last = Number(r.rows[0].lastWithdrawAt) || 0;
  res.json({ balance: fromCents(r.rows[0].balanceCents), held: fromCents(r.rows[0].heldBalanceCents), nextWithdrawAt: last ? last + WITHDRAW_COOLDOWN : 0, escrow: await escrowFor(req.user), topupAvailable: paymentsEnabled() });
});

// Withdrawals: one per hour per account, enforced here (not in the page). The request is saved in the withdrawals table; no money is moved or deducted yet.
const WITHDRAW_COOLDOWN = 60 * 60 * 1000;
app.post('/api/wallet/withdraw', requireUser, async (req, res) => {
  try {
    if (moneyLimit(req, res, 'withdraw', 20, 60 * 60 * 1000)) return;
    const amountCents = parseMoney(req.body.amount);
    if (!(amountCents > 0) || amountCents > 100000000) return res.status(400).json({ error: 'Please enter a valid withdrawal amount.' });
    const method = String(req.body.method || 'card');
    if (!['card', 'crypto'].includes(method)) return res.status(400).json({ error: 'Please choose a payout method.' });
    const rs = await db.execute({ sql: 'SELECT balanceCents, lastWithdrawAt, bannedUntil FROM users WHERE username = ?', args: [req.user] });
    if (!rs.rows.length) return res.status(401).json({ error: 'Please log in.' });
    const u = rs.rows[0];
    const until = Number(u.bannedUntil) || 0;
    if (until === -1 || until > Date.now()) return res.status(403).json({ error: 'Your account is banned.' });
    if (amountCents > (Number(u.balanceCents) || 0)) return res.status(400).json({ error: 'You do not have enough balance for this withdrawal.' });
    const now = Date.now();
    // atomic: only one request can claim the hourly slot
    const upd = await db.execute({ sql: 'UPDATE users SET lastWithdrawAt = ? WHERE username = ? AND COALESCE(lastWithdrawAt, 0) <= ?', args: [now, req.user, now - WITHDRAW_COOLDOWN] });
    if (!upd.rowsAffected) {
      const wait = (Number(u.lastWithdrawAt) || 0) + WITHDRAW_COOLDOWN - now;
      return res.status(429).json({ error: `You can only withdraw once per hour. Try again in ${Math.max(1, Math.ceil(wait / 60000))} min.`, nextWithdrawAt: now + Math.max(0, wait) });
    }
    try {
      await db.execute({ sql: "INSERT INTO withdrawals (username, amount, amountCents, method, status, createdAt) VALUES (?, ?, ?, ?, 'pending', ?)", args: [req.user, fromCents(amountCents), amountCents, method, now] });
    } catch (e) {
      // the request could not be saved: give the hourly slot back so the user can simply try again
      await db.execute({ sql: 'UPDATE users SET lastWithdrawAt = ? WHERE username = ?', args: [Number(u.lastWithdrawAt) || 0, req.user] }).catch(() => {});
      throw e;
    }
    console.log(`WITHDRAW request ${req.user} ${fromCents(amountCents)} ${method}`);
    res.json({ ok: true, nextWithdrawAt: now + WITHDRAW_COOLDOWN });
  } catch (e) { console.error('withdraw error:', e); res.status(500).json({ error: 'Withdrawal failed. Try again.' }); }
});

// admin only: saved withdrawal requests (newest first) and marking them paid / rejected
app.get('/api/admin/withdrawals', async (req, res) => {
  const rs = await db.execute('SELECT w.id, w.username, w.amountCents, w.method, w.status, w.createdAt, w.handledBy, w.handledAt, u.balanceCents FROM withdrawals w LEFT JOIN users u ON u.username = w.username ORDER BY w.id DESC LIMIT 200');
  res.json({ rows: rs.rows.map(r => ({ id: Number(r.id), username: r.username, amount: fromCents(r.amountCents), method: r.method || '', status: r.status || 'pending', createdAt: Number(r.createdAt) || 0, handledBy: r.handledBy || '', handledAt: Number(r.handledAt) || 0, balance: fromCents(r.balanceCents) })) });
});
app.post('/api/admin/withdrawals/:id/status', async (req, res) => {
  const status = String(req.body.status || '');
  if (!['paid', 'rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });
  const upd = await db.execute({ sql: "UPDATE withdrawals SET status = ?, handledBy = ?, handledAt = ? WHERE id = ? AND status = 'pending'", args: [status, req.user, Date.now(), pid(req)] });
  if (!upd.rowsAffected) return res.status(409).json({ error: 'This request was already handled.' });
  auditReq(req, res, 'withdrawal-' + status, '#' + req.params.id, '', 0);
  res.json({ ok: true });
});

// ---------- wallet top-ups through a payment gateway (hosted checkout + signed webhook) ----------
// This site and this server NEVER see card numbers or CVVs: the old in-page card form is gone. A top-up works like this:
//   1. POST /api/wallet/topup {amount}  stores a pending "intent" (amount decided HERE) and asks the gateway for a hosted checkout page.
//      The browser is redirected to that page and the customer types the card into the GATEWAY's site.
//   2. The gateway calls POST /api/webhooks/payments. The call is signed (HMAC-SHA256 over the raw body, Stripe-style "Stripe-Signature: t=...,v1=...").
//      Only a verified event credits the wallet, once per event id, for the amount stored in OUR intent (never an amount that came from the browser).
// Reference adapter: Stripe Checkout. Set STRIPE_SECRET_KEY, PAYMENT_WEBHOOK_SECRET (the endpoint's signing secret) and PUBLIC_URL (https://your-site) to switch it on.
// Another gateway only needs its own createCheckout() and signature check; the intent / idempotency / crediting logic below stays the same.
const stripeKey = () => cleanEnv(process.env.STRIPE_SECRET_KEY);
const webhookSecret = () => cleanEnv(process.env.PAYMENT_WEBHOOK_SECRET);
const publicUrl = () => cleanEnv(process.env.PUBLIC_URL).replace(/\/+$/, '');
const paymentsEnabled = () => !!(stripeKey() && webhookSecret() && /^https:\/\//.test(publicUrl()));
const WEBHOOK_TOLERANCE_S = 5 * 60;
async function createCheckout(intent) {                    // returns { ref, url } from the gateway
  const form = new URLSearchParams({
    mode: 'payment', client_reference_id: intent.id, 'metadata[intentId]': intent.id,
    success_url: `${publicUrl()}/starfall.html?topup=success`, cancel_url: `${publicUrl()}/starfall.html?topup=cancelled`,
    'line_items[0][quantity]': '1', 'line_items[0][price_data][currency]': intent.currency,
    'line_items[0][price_data][unit_amount]': String(intent.amountCents), 'line_items[0][price_data][product_data][name]': 'Starfall wallet top-up'
  });
  const r = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST', headers: { Authorization: 'Bearer ' + stripeKey(), 'Content-Type': 'application/x-www-form-urlencoded', 'Idempotency-Key': 'topup-' + intent.id },
    body: form, signal: AbortSignal.timeout(10000)
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.id || !/^https:\/\//.test(String(j.url || ''))) throw new Error('gateway refused the checkout: ' + ((j.error && j.error.message) || r.status));
  return { ref: String(j.id), url: String(j.url) };
}
// Stripe-style signature: header "t=<unix seconds>,v1=<hex hmac>[,v1=...]", hmac = HMAC_SHA256(secret, t + "." + rawBody)
function verifyWebhookSignature(rawBody, header, secret, nowMs = Date.now()) {
  if (!rawBody || !header || !secret) return false;
  const parts = String(header).split(',').map(x => x.trim().split('='));
  const t = Number((parts.find(p => p[0] === 't') || [])[1]);
  const sigs = parts.filter(p => p[0] === 'v1' && /^[a-f0-9]{64}$/.test(p[1] || '')).map(p => p[1]);
  if (!Number.isFinite(t) || !sigs.length || Math.abs(nowMs / 1000 - t) > WEBHOOK_TOLERANCE_S) return false;
  const want = crypto.createHmac('sha256', secret).update(t + '.').update(rawBody).digest();
  return sigs.some(h => { const got = Buffer.from(h, 'hex'); return got.length === want.length && crypto.timingSafeEqual(got, want); });
}
app.post('/api/wallet/topup', requireUser, async (req, res) => {
  try {
    if (!paymentsEnabled()) return res.status(503).json({ error: 'Wallet top-ups are not available yet. Payments are being set up.', topupAvailable: false });
    if (moneyLimit(req, res, 'topup', 10, 60 * 60 * 1000)) return;
    const amountCents = parseMoney(req.body && req.body.amount);
    if (!(amountCents >= MIN_TOPUP * 100)) return res.status(400).json({ error: `Minimum top-up is $${MIN_TOPUP}.` });
    if (amountCents > MAX_TOPUP * 100) return res.status(400).json({ error: `Maximum top-up is $${MAX_TOPUP}.` });
    const open = await db.execute({ sql: "SELECT COUNT(*) AS c FROM topup_intents WHERE userId = ? AND status = 'pending' AND expiresAt > ?", args: [req.userId, Date.now()] });
    if (Number(open.rows[0].c) >= 5) return res.status(429).json({ error: 'You have several unfinished top-ups. Finish or wait for them to expire.' });
    const now = Date.now(), intent = { id: 'ti_' + crypto.randomBytes(12).toString('hex'), userId: req.userId, amountCents, currency: 'usd' };
    await db.execute({ sql: "INSERT INTO topup_intents (id, userId, amountCents, currency, provider, status, createdAt, updatedAt, expiresAt) VALUES (?, ?, ?, 'usd', 'stripe', 'pending', ?, ?, ?)", args: [intent.id, req.userId, amountCents, now, now, now + 2 * 60 * 60 * 1000] });
    let co;
    try { co = await createCheckout(intent); }
    catch (e) {
      console.error('checkout creation failed:', e.message);
      await db.execute({ sql: "UPDATE topup_intents SET status = 'failed', updatedAt = ? WHERE id = ?", args: [Date.now(), intent.id] });
      return res.status(502).json({ error: 'The payment provider is not reachable right now. Try again later.' });
    }
    await db.execute({ sql: 'UPDATE topup_intents SET providerRef = ?, updatedAt = ? WHERE id = ?', args: [co.ref, Date.now(), intent.id] });
    res.json({ checkoutUrl: co.url, intentId: intent.id });
  } catch (e) { console.error('topup error:', e); res.status(500).json({ error: 'Top-up failed. Try again.' }); }
});
app.post('/api/webhooks/payments', async (req, res) => {
  const secret = webhookSecret();
  if (!secret) return res.status(503).json({ error: 'Payments are not configured.' });
  if (!verifyWebhookSignature(req.rawBody, req.headers['stripe-signature'], secret)) return res.status(400).json({ error: 'Invalid signature.' });
  const ev = req.body && typeof req.body === 'object' ? req.body : {};
  const eventId = String(ev.id || '');
  if (!/^[A-Za-z0-9_.:-]{3,100}$/.test(eventId)) return res.status(400).json({ error: 'Bad event.' });
  const type = String(ev.type || '');
  const obj = (ev.data && ev.data.object) || {};
  const credits = type === 'checkout.session.completed' || type === 'checkout.session.async_payment_succeeded';
  const tx = await db.transaction('write');
  try {
    const dup = await tx.execute({ sql: 'SELECT 1 FROM payment_events WHERE eventId = ?', args: [eventId] });
    if (dup.rows.length) { await tx.rollback(); return res.json({ received: true, duplicate: true }); }     // already processed: acknowledge, do nothing
    let outcome = credits ? 'ignored' : 'not-a-payment-event', intentId = String(obj.client_reference_id || '');
    if (credits) {
      const it = (await tx.execute({ sql: 'SELECT * FROM topup_intents WHERE id = ?', args: [intentId] })).rows[0];
      if (!it) outcome = 'unknown-intent';
      else if (it.status === 'completed') outcome = 'already-credited';
      else if (obj.payment_status !== 'paid') outcome = 'not-paid-yet';
      else if (String(it.providerRef || '') !== String(obj.id || '') || Number(obj.amount_total) !== Number(it.amountCents) || String(obj.currency || '').toLowerCase() !== String(it.currency)) {
        outcome = 'mismatch'; console.error(`PAYMENT MISMATCH for intent ${intentId}: expected ${it.amountCents} ${it.currency} / ${it.providerRef}, got ${obj.amount_total} ${obj.currency} / ${obj.id}`);
      } else {
        const up = await tx.execute({ sql: "UPDATE topup_intents SET status = 'completed', updatedAt = ? WHERE id = ? AND status IN ('pending', 'failed')", args: [Date.now(), intentId] });
        if (up.rowsAffected) {
          await tx.execute({ sql: 'UPDATE users SET balanceCents = COALESCE(balanceCents, 0) + ?, balance = (COALESCE(balanceCents, 0) + ?) / 100.0 WHERE id = ?', args: [Number(it.amountCents), Number(it.amountCents), Number(it.userId)] });
          outcome = 'credited';
        } else outcome = 'already-credited';
      }
    }
    await tx.execute({ sql: 'INSERT INTO payment_events (eventId, provider, type, intentId, outcome, receivedAt) VALUES (?, ?, ?, ?, ?, ?)', args: [eventId, 'stripe', type.slice(0, 80), intentId.slice(0, 80), outcome, Date.now()] });
    await tx.commit();
    if (outcome === 'credited') console.log(`TOPUP credited intent ${intentId}`);
    res.json({ received: true, outcome });
  } catch (e) {
    try { await tx.rollback(); } catch (_) {}
    console.error('webhook error:', e);
    res.status(500).json({ error: 'Webhook processing failed.' });      // the gateway retries; nothing was recorded
  } finally { tx.close(); }
});

// admin only: add or subtract balance for any user (never goes below $0)
app.post('/api/admin/adjust', async (req, res) => {
  try {
    const target = String(req.body.username || '');
    const deltaCents = parseMoney(req.body.delta);
    const delta = fromCents(deltaCents);
    if (!target) return res.status(400).json({ error: 'Select a user first.' });
    if (!Number.isFinite(deltaCents) || deltaCents === 0 || Math.abs(deltaCents) > ADMIN_MAX_ADJUST * 100) return res.status(400).json({ error: `Enter a valid amount (at most $${ADMIN_MAX_ADJUST} at a time).` });
    // money changes need the admin password typed AGAIN, on top of the elevated admin session, so a stolen session alone cannot create money
    if (limited('adminpw:' + req.user, 10, 15 * 60 * 1000)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
    const me = await db.execute({ sql: 'SELECT id, password, passwordHash FROM users WHERE id = ?', args: [req.userId] });
    const pw = String(req.body.password || '');
    const pwOk = !!pw && me.rows.length > 0 && await verifyPassword(me.rows[0], pw);
    if (!pwOk) return res.status(403).json({ error: 'Enter your admin password to change a balance.' });
    const today = await db.execute({ sql: "SELECT COALESCE(SUM(ABS(amount)), 0) AS t FROM admin_audit WHERE action = 'adjust' AND createdAt > ?", args: [Date.now() - DAY] });
    if (Number(today.rows[0].t) + Math.abs(delta) > ADMIN_DAILY_CAP) return res.status(429).json({ error: `Daily admin balance limit reached ($${ADMIN_DAILY_CAP}).` });
    const rs = await db.execute({ sql: 'UPDATE users SET balanceCents = MAX(0, COALESCE(balanceCents, 0) + ?), balance = MAX(0, COALESCE(balanceCents, 0) + ?) / 100.0 WHERE username = ?', args: [deltaCents, deltaCents, target] });
    if (!rs.rowsAffected) return res.status(404).json({ error: 'User not found.' });
    const r = await db.execute({ sql: 'SELECT balanceCents FROM users WHERE username = ?', args: [target] });
    console.log(`ADMIN ${req.user} adjusted ${target} by ${delta}`);
    auditReq(req, res, 'adjust', target, `balance ${delta > 0 ? '+' : ''}${delta}`, delta);
    res.json({ balance: fromCents(r.rows[0].balanceCents) });
  } catch (e) { console.error('adjust error:', e); res.status(500).json({ error: 'Failed to update balance.' }); }
});

// admin only: reset someone's password. A random temporary password is returned ONCE (only its hash is stored);
// the user is logged out everywhere and must choose a new password before doing anything else.
function makeTempPassword() {
  const pick = (set) => set[crypto.randomInt(set.length)];
  const U = 'ABCDEFGHJKLMNPQRSTUVWXYZ', L = 'abcdefghijkmnopqrstuvwxyz', N = '23456789', S = '!@#$%*?';
  for (let tries = 0; tries < 50; tries++) {
    const chars = [pick(U), pick(U), pick(L), pick(L), pick(L), pick(L), pick(L), pick(N), pick(N), pick(S), pick(L), pick(U), pick(N), pick(L)];
    for (let i = chars.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
    const pw = chars.join('');
    if (!passwordProblems(pw).length) return pw;
  }
  throw new Error('could not generate a temporary password');
}
app.post('/api/admin/reset-password', async (req, res) => {
  try {
    const target = String(req.body.username || '');
    if (!target) return res.status(400).json({ error: 'Select a user first.' });
    if (limited('adminreset:' + req.user, 10, 15 * 60 * 1000)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
    // same rule as balance changes: the admin password is needed again, so a stolen session alone cannot take over accounts
    const me = await db.execute({ sql: 'SELECT id, password, passwordHash FROM users WHERE id = ?', args: [req.userId] });
    const pw = String(req.body.password || '');
    const pwOk = !!pw && me.rows.length > 0 && await verifyPassword(me.rows[0], pw);
    if (!pwOk) return res.status(403).json({ error: 'Enter your admin password to reset a password.' });
    const t = await db.execute({ sql: 'SELECT username, email, customId FROM users WHERE username = ?', args: [target] });
    if (!t.rows.length) return res.status(404).json({ error: 'User not found.' });
    const name = String(t.rows[0].username);
    if (name === req.user || String(t.rows[0].customId || '') === 'knqw') return res.status(400).json({ error: 'Change your own password in Account settings.' });
    const temp = makeTempPassword();
    const hash = await bcrypt.hash(temp, 12);
    await db.execute({ sql: "UPDATE users SET passwordHash = ?, password = '', mustChangePassword = 1 WHERE username = ?", args: [hash, name] });
    await db.execute({ sql: 'DELETE FROM sessions WHERE userId = (SELECT id FROM users WHERE username = ?)', args: [name] });
    console.log(`ADMIN ${req.user} reset the password of ${name}`);
    auditReq(req, res, 'reset-password', name, 'password reset (temporary password issued)', 0);
    res.json({ ok: true, tempPassword: temp });
  } catch (e) { console.error('reset-password error:', e); res.status(500).json({ error: 'Could not reset the password.' }); }
});

// (GET /api/admin/audit lives in the admin section below, with paging)
app.get('/api/admin/users', async (req, res) => {
  const rs = await db.execute('SELECT customId, username, displayName, balanceCents, heldBalanceCents, bannedUntil FROM users ORDER BY username');
  res.json({ users: rs.rows.map(r => ({
    customId: r.customId, username: r.username, displayName: r.displayName,
    balance: fromCents(r.balanceCents), held: fromCents(r.heldBalanceCents), bannedUntil: Number(r.bannedUntil) || 0
  })) });
});

// ---------- listings: small helpers shared by deals and chat ----------
const listingIdOk = (v) => /^\d{1,16}$/.test(String(v == null ? '' : v)) && Number.isSafeInteger(Number(v)) && Number(v) > 0;
async function getListing(q, id) {            // the listing row plus its owner's username, or null
  if (!listingIdOk(id)) return null;
  const r = await q.execute({ sql: 'SELECT l.*, u.username AS owner FROM listings l JOIN users u ON u.id = l.ownerId WHERE l.id = ?', args: [Number(id)] });
  return r.rows.length ? r.rows[0] : null;
}
// units that are really still for sale: stock minus the units already promised to deals whose money is in escrow
async function listingFree(q, listing) {
  const r = await q.execute({ sql: "SELECT COUNT(*) AS c FROM deals WHERE itemId = ? AND status IN ('paid','not_received','reported')", args: [String(listing.id)] });
  return Number(listing.stock) - Number(r.rows[0].c);
}
// A deal for a listing is "entirely completed": one unit is sold. The listing loses one unit of stock and is deleted when none are left (with its picture).
async function consumeListing(tx, d) {
  if (!d.itemId || !listingIdOk(d.itemId)) return false;
  const l = await getListing(tx, d.itemId);
  if (!l || l.owner !== d.seller) return false;                // never touch a listing that is not the seller's
  const left = Number(l.stock) - 1;
  if (left <= 0) {
    await tx.execute({ sql: 'DELETE FROM listings WHERE id = ?', args: [l.id] });
    await tx.execute({ sql: "DELETE FROM media WHERE kind = 'listing' AND refId = ?", args: [String(l.id)] });
  } else {
    await tx.execute({ sql: 'UPDATE listings SET stock = ?, updatedAt = ? WHERE id = ?', args: [left, Date.now(), l.id] });
  }
  await tx.execute({ sql: 'UPDATE deals SET listingConsumed = 1 WHERE id = ?', args: [d.id] });
  await bumpMeta(tx, 'listingsRev');
  return true;
}

// ---------- deals ----------
const mapDeal = (r) => {
  const paidAt = Number(r.paidAt) || 0, updatedAt = Number(r.updatedAt) || 0;
  return {
    id: Number(r.id), buyer: r.buyer, seller: r.seller, itemName: r.itemName || '',
    amount: fromCents(r.amountCents), sellerAmount: fromCents(r.sellerAmountCents), amountCents: Number(r.amountCents) || 0, sellerAmountCents: Number(r.sellerAmountCents) || 0, status: r.status,
    createdAt: Number(r.createdAt) || 0, updatedAt, paidAt, completedAt: Number(r.completedAt) || 0, autoReleased: Number(r.autoReleased) === 1,
    // when escrow releases on its own: a paid deal is released to the seller, a "not received" deal is handed to the admin
    releaseAt: r.status === 'paid' ? (paidAt || updatedAt) + ESCROW_TIMEOUT_MS : r.status === 'not_received' ? updatedAt + ESCROW_TIMEOUT_MS : 0,
    reportedAt: Number(r.reportedAt) || 0, chatSnapshot: r.chatSnapshot || null, reportedBy: r.reportedBy || '',
    itemId: r.itemId ? String(r.itemId) : ''
  };
};
const dealId = (req) => { const raw = String(req.params.id || ''); const n = Number(raw); return /^\d{1,16}$/.test(raw) && Number.isSafeInteger(n) && n > 0 ? n : 0; };
async function loadDeal(q, id) {
  const rs = await q.execute({ sql: 'SELECT * FROM deals WHERE id = ?', args: [id] });
  return rs.rows.length ? mapDeal(rs.rows[0]) : null;
}
const dealAmountsValid = (d) => Number.isSafeInteger(d.amountCents) && d.amountCents >= MIN_DEAL * 100 && d.amountCents <= MAX_DEAL * 100 && Number.isSafeInteger(d.sellerAmountCents) && Math.abs(d.sellerAmountCents - Math.round(d.amountCents * SELLER_SHARE)) <= 1;
// the chat evidence for a dispute is rebuilt from the stored messages (whatever the browser sends as "snapshot" is ignored, so it cannot be forged)
async function chatSnapshotFor(q, dl) {
  const ids = await q.execute({ sql: 'SELECT username, id FROM users WHERE username IN (?, ?)', args: [dl.buyer, dl.seller] });
  const idOf = new Map(ids.rows.map(r => [String(r.username), Number(r.id)]));
  const b = idOf.get(dl.buyer), s = idOf.get(dl.seller);
  if (!b || !s) return [];
  const rs = await q.execute({
    sql: 'SELECT senderId, text, ts FROM messages WHERE ((senderId = ? AND receiverId = ?) OR (senderId = ? AND receiverId = ?)) AND itemId = ? ORDER BY ts DESC LIMIT 500',
    args: [b, s, s, b, dl.itemId || '']
  });
  return rs.rows.reverse().map(m => ({ sender: Number(m.senderId) === b ? dl.buyer : dl.seller, receiver: Number(m.senderId) === b ? dl.seller : dl.buyer, text: String(m.text || '').slice(0, 2000), timestamp: Number(m.ts) || 0 }));
}
// held money -> the seller's balance, deal -> finalStatus, and the sold unit leaves the listing. One transaction; throws Abort when anything is off.
async function finishDeal(tx, d, finalStatus, opts = {}) {
  if (!dealAmountsValid(d) || d.sellerAmountCents < 0) throw new Abort('This deal failed validation and cannot be completed.', 409);
  const now = Date.now();
  const claim = await tx.execute({ sql: 'UPDATE deals SET status = ?, updatedAt = ?, completedAt = ?, autoReleased = ? WHERE id = ? AND status = ?', args: [finalStatus, now, now, opts.auto ? 1 : 0, d.id, d.status] });
  if (!claim.rowsAffected) throw new Abort('This deal was already updated.');
  const rel = await tx.execute({
    sql: 'UPDATE users SET heldBalanceCents = MAX(0, COALESCE(heldBalanceCents, 0) - ?), heldBalance = MAX(0, COALESCE(heldBalanceCents, 0) - ?) / 100.0, balanceCents = COALESCE(balanceCents, 0) + ?, balance = (COALESCE(balanceCents, 0) + ?) / 100.0 WHERE username = ?',
    args: [d.sellerAmountCents, d.sellerAmountCents, d.sellerAmountCents, d.sellerAmountCents, d.seller]
  });
  if (!rel.rowsAffected) throw new Abort("The seller's account no longer exists. Nothing was changed - ask the admin to resolve this deal.");   // rolled back: the money is never destroyed
  await consumeListing(tx, d);
}

// deals between me and one other user (chat view). Reported-deal chat snapshots are not sent here.
app.get('/api/deals', requireUser, async (req, res) => {
  const other = String(req.query.with || '');
  if (!other) return res.status(400).json({ error: 'Missing user.' });
  const rs = await db.execute({
    sql: 'SELECT * FROM deals WHERE (buyer = ? AND seller = ?) OR (buyer = ? AND seller = ?) ORDER BY createdAt ASC',
    args: [req.user, other, other, req.user]
  });
  res.json({ deals: rs.rows.map(r => { const d = mapDeal(r); d.chatSnapshot = null; return d; }) });
});

// cheap change signal for polling
async function dealsSig(username) {
  const rs = await db.execute({ sql: 'SELECT COUNT(*) AS c, COALESCE(SUM(updatedAt), 0) AS s FROM deals WHERE buyer = ? OR seller = ?', args: [username, username] });
  return `${Number(rs.rows[0].c)}:${Number(rs.rows[0].s)}`;
}
app.get('/api/deals/sig', requireUser, async (req, res) => res.json({ sig: await dealsSig(req.user) }));

// one deal (participants or elevated admin). Only the elevated admin receives the chat snapshot.
app.get('/api/deals/:id', requireUser, async (req, res) => {
  const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
  const d = await loadDeal(db, id);
  if (!d) return res.status(404).json({ error: 'Deal not found.' });
  const isAdmin = await isElevatedAdmin(req);
  if (!isAdmin && d.buyer !== req.user && d.seller !== req.user) return res.status(404).json({ error: 'Deal not found.' });
  if (!isAdmin) d.chatSnapshot = null;
  res.json({ deal: d });
});

// seller asks the buyer for payment
app.post('/api/deals', requireUser, async (req, res) => {
  try {
    if (moneyLimit(req, res, 'deal-new', 30, 60 * 60 * 1000)) return;
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) return res.status(400).json({ error: 'Bad request.' });
    const buyer = typeof req.body.buyer === 'string' ? req.body.buyer.trim() : '';
    const amountCents = parseMoney(req.body.amount);
    const amount = fromCents(amountCents);
    let itemName = typeof req.body.itemName === 'string' ? req.body.itemName.trim() : '';
    const itemId = req.body.itemId == null || req.body.itemId === '' ? '' : String(req.body.itemId);
    if (itemId && !listingIdOk(itemId)) return res.status(400).json({ error: 'Invalid item ID.' });
    if (!buyer || buyer.length > 40 || buyer === req.user) return res.status(400).json({ error: 'Choose another user.' });
    if (!(amount >= MIN_DEAL) || amount > MAX_DEAL || !Number.isFinite(amount)) return res.status(400).json({ error: 'Enter a valid amount.' });
    if (!itemName || itemName.length > 200) return res.status(400).json({ error: 'Enter a valid item name.' });
    if (itemId) {
      const listing = await getListing(db, itemId);
      if (!listing || listing.owner !== req.user) return res.status(400).json({ error: 'That listing no longer exists. Refresh the page and try again.' });
      // The server owns the item name; client-provided titles cannot misrepresent the listing.
      itemName = String(listing.name || itemName).slice(0, 200);
      if (listing.tag === 'selling') {
        // Deal integrity: a payment request for a listing that is for sale must be for exactly the listed price, nothing more and nothing less.
        if (listing.priceCents == null) return res.status(400).json({ error: 'This listing has no valid price. Edit the listing first.' });
        if (amountCents !== Number(listing.priceCents)) return res.status(400).json({ error: `For this listing the amount must be exactly the listed price ($${fromCents(listing.priceCents).toFixed(2)}).`, listingPrice: fromCents(listing.priceCents) });
        if ((await listingFree(db, listing)) < 1) return res.status(409).json({ error: 'This item is out of stock.' });
      }
    }
    const b = await db.execute({ sql: 'SELECT id FROM users WHERE username = ?', args: [buyer] });
    if (!b.rows.length) return res.status(404).json({ error: 'User not found.' });
    // a payment request is only allowed inside an existing chat: the buyer must already have written to this seller
    // (about the same item, when the request is for a specific item). Senders are set by the server, so this cannot be faked.
    const chatted = await db.execute({ sql: "SELECT 1 FROM messages WHERE senderId = ? AND receiverId = ? AND (? = '' OR itemId = ?) LIMIT 1", args: [Number(b.rows[0].id), req.userId, itemId, itemId] });
    if (!chatted.rows.length) return res.status(403).json({ error: 'You can only ask for payment in a chat where this buyer has written to you.' });
    const dup = await db.execute({
      sql: "SELECT id FROM deals WHERE seller = ? AND buyer = ? AND COALESCE(itemId, '') = ? AND status = 'requested'",
      args: [req.user, buyer, itemId]
    });
    if (dup.rows.length) return res.status(409).json({ error: 'You already have a pending payment request in this chat.' });
    const now = Date.now();
    await db.execute({
      sql: "INSERT INTO deals (buyer, seller, itemName, amount, sellerAmount, amountCents, sellerAmountCents, status, createdAt, updatedAt, itemId) VALUES (?, ?, ?, ?, ?, ?, ?, 'requested', ?, ?, ?)",
      args: [buyer, req.user, itemName, amount, round2(amount * SELLER_SHARE), amountCents, Math.round(amountCents * SELLER_SHARE), now, now, itemId || null]
    });
    res.json({ ok: true });
  } catch (e) { console.error('deal create error:', e); res.status(500).json({ error: 'Server error. Try again.' }); }
});

// buyer pays: money leaves the buyer and sits on hold for the seller (escrow clock starts: paidAt)
app.post('/api/deals/:id/pay', requireUser, async (req, res) => {
  const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
  if (moneyLimit(req, res, 'deal-act', 60, 60 * 1000)) return;
  const out = await withWalletLock(req.user, () => inTx(res, async (tx) => {
    const d = await loadDeal(tx, id);
    if (!d || d.buyer !== req.user) throw new Abort('This request is no longer available.');
    if (d.status !== 'requested' || !dealAmountsValid(d)) throw new Abort('This request failed validation and cannot be paid.', 409);
    if (d.itemId) {
      // the listing must still exist, still be the seller's, still cost exactly this much, and still have a unit left
      const l = await getListing(tx, d.itemId);
      if (!l || l.owner !== d.seller) throw new Abort('This listing is no longer available. Ask the seller to send a new request.', 409);
      if (l.tag === 'selling') {
        if (l.priceCents == null || Number(l.priceCents) !== d.amountCents) throw new Abort('The listing price changed after this request was made. Ask the seller to send a new request.', 409);
        if ((await listingFree(tx, l)) < 1) throw new Abort('This item is out of stock.', 409);
      }
    }
    const now = Date.now();
    const claim = await tx.execute({ sql: "UPDATE deals SET status = 'paid', updatedAt = ?, paidAt = ? WHERE id = ? AND status = 'requested'", args: [now, now, id] });
    if (!claim.rowsAffected) throw new Abort('This request is no longer available.');
    const debit = await tx.execute({ sql: 'UPDATE users SET balanceCents = balanceCents - ?, balance = (balanceCents - ?) / 100.0 WHERE username = ? AND COALESCE(balanceCents, 0) >= ?', args: [d.amountCents, d.amountCents, req.user, d.amountCents] });
    if (!debit.rowsAffected) throw new Abort('Not enough balance.');
    const credit = await tx.execute({ sql: 'UPDATE users SET heldBalanceCents = COALESCE(heldBalanceCents, 0) + ?, heldBalance = (COALESCE(heldBalanceCents, 0) + ?) / 100.0 WHERE username = ?', args: [d.sellerAmountCents, d.sellerAmountCents, d.seller] });
    if (!credit.rowsAffected) throw new Abort('Seller account not found. You were not charged.');
    const r = await tx.execute({ sql: 'SELECT balanceCents FROM users WHERE username = ?', args: [req.user] });
    return fromCents(r.rows[0].balanceCents);
  }));
  if (out !== undefined) res.json({ balance: out });
});

// buyer confirms delivery: held money goes to the seller's balance and the sold unit leaves the listing (the listing is deleted when it was the last one)
app.post('/api/deals/:id/complete', requireUser, async (req, res) => {
  const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
  if (moneyLimit(req, res, 'deal-act', 60, 60 * 1000)) return;
  const out = await inTx(res, async (tx) => {
    const d = await loadDeal(tx, id);
    if (!d || d.buyer !== req.user || !['paid', 'not_received'].includes(d.status)) throw new Abort('This deal can no longer be confirmed.');
    await finishDeal(tx, d, 'completed');
    return true;
  });
  if (out) res.json({ ok: true });
});

// simple state changes without money movement
async function simpleStatus(req, res, from, to, who) {
  const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
  if (moneyLimit(req, res, 'deal-act', 60, 60 * 1000)) return;
  const col = who === 'buyer' ? 'buyer = ?' : who === 'seller' ? 'seller = ?' : '(buyer = ? OR seller = ?)';
  const args = [to, Date.now(), id, from, req.user];
  if (who === 'either') args.push(req.user);
  const rs = await db.execute({ sql: `UPDATE deals SET status = ?, updatedAt = ? WHERE id = ? AND status = ? AND ${col}`, args });
  if (!rs.rowsAffected) return res.status(409).json({ error: 'This deal was already updated.' });
  res.json({ ok: true });
}
app.post('/api/deals/:id/not-received', requireUser, (req, res) => simpleStatus(req, res, 'paid', 'not_received', 'buyer'));
app.post('/api/deals/:id/cancel', requireUser, (req, res) => simpleStatus(req, res, 'requested', 'cancelled', 'either'));

// either side reports a deal marked "not received"; the chat snapshot is shown to the admin only
app.post('/api/deals/:id/report', requireUser, async (req, res) => {
  try {
    const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
    if (moneyLimit(req, res, 'deal-act', 60, 60 * 1000)) return;
    const dl = await loadDeal(db, id);
    if (!dl || dl.status !== 'not_received' || (dl.buyer !== req.user && dl.seller !== req.user)) return res.status(409).json({ error: 'This deal was already updated.' });
    const snap = await chatSnapshotFor(db, dl);
    const now = Date.now();
    const rs = await db.execute({
      sql: "UPDATE deals SET status = 'reported', reportedAt = ?, updatedAt = ?, chatSnapshot = ?, reportedBy = ? WHERE id = ? AND status = 'not_received' AND (buyer = ? OR seller = ?)",
      args: [now, now, JSON.stringify(snap), req.user, id, req.user, req.user]
    });
    if (!rs.rowsAffected) return res.status(409).json({ error: 'This deal was already updated.' });
    res.json({ ok: true });
  } catch (e) { console.error('report error:', e); res.status(500).json({ error: 'Server error. Try again.' }); }
});

// ---------- escrow timeout: held money never sits forever ----------
// * 'paid' for ESCROW_TIMEOUT_MS (7 days) with no confirmation and no complaint -> released to the seller automatically (status 'completed', autoReleased = 1).
// * 'not_received' (the buyer complained but never filed the report) for as long -> escalated to 'reported' so the admin decides. It is NOT released
//   to the seller (the buyer said the item never came) and NOT refunded (the seller has not been heard), so a dispute can still be resolved fairly.
async function txRun(fn) {
  const tx = await db.transaction('write');
  try { const out = await fn(tx); await tx.commit(); return out; }
  catch (e) { try { await tx.rollback(); } catch (_) {} throw e; }
  finally { tx.close(); }
}
let escrowRunning = false;
async function runEscrowJob() {
  if (escrowRunning) return { released: 0, escalated: 0 };
  escrowRunning = true;
  let released = 0, escalated = 0;
  try {
    const cutoff = Date.now() - ESCROW_TIMEOUT_MS;
    const due = await db.execute({ sql: "SELECT id FROM deals WHERE status = 'paid' AND COALESCE(paidAt, updatedAt) <= ? ORDER BY id LIMIT 200", args: [cutoff] });
    for (const row of due.rows) {
      try {
        await txRun(async (tx) => {
          const d = await loadDeal(tx, Number(row.id));
          if (!d || d.status !== 'paid') return;
          await finishDeal(tx, d, 'completed', { auto: true });
        });
        released++;
        console.log(`ESCROW auto-released deal ${row.id}`);
      } catch (e) { console.error(`escrow release of deal ${row.id} failed:`, e.message); }
    }
    const stale = await db.execute({ sql: "SELECT id FROM deals WHERE status = 'not_received' AND updatedAt <= ? ORDER BY id LIMIT 200", args: [cutoff] });
    for (const row of stale.rows) {
      try {
        await txRun(async (tx) => {
          const d = await loadDeal(tx, Number(row.id));
          if (!d || d.status !== 'not_received') return;
          const snap = await chatSnapshotFor(tx, d), now = Date.now();
          await tx.execute({ sql: "UPDATE deals SET status = 'reported', reportedAt = ?, updatedAt = ?, chatSnapshot = ?, reportedBy = 'system' WHERE id = ? AND status = 'not_received'", args: [now, now, JSON.stringify(snap), d.id] });
        });
        escalated++;
        console.log(`ESCROW escalated deal ${row.id} to the admin`);
      } catch (e) { console.error(`escrow escalation of deal ${row.id} failed:`, e.message); }
    }
  } catch (e) { console.error('escrow job failed:', e.message); }
  finally { escrowRunning = false; }
  return { released, escalated };
}
setInterval(() => { runEscrowJob().catch(() => {}); }, 5 * 60 * 1000);
setTimeout(() => { runEscrowJob().catch(() => {}); }, 20 * 1000);

// ---------- admin: money overview + resolving held deals ----------
app.get('/api/admin/deals', async (req, res) => {
  const status = String(req.query.status || '');
  const rs = status === 'reported'
    ? await db.execute("SELECT * FROM deals WHERE status = 'reported' ORDER BY reportedAt DESC")
    : status === 'held'
      ? await db.execute("SELECT * FROM deals WHERE status IN ('paid','not_received','reported') ORDER BY updatedAt DESC")
      : await db.execute("SELECT * FROM deals ORDER BY createdAt DESC LIMIT 500");
  if (status === 'reported') auditReq(req, res, 'view-reported-deals', '', `${rs.rows.length} reported deals with chat evidence`, 0);      // the reported list carries chat evidence
  res.json({ deals: rs.rows.map(mapDeal) });
});

app.get('/api/admin/deals/:id', async (req, res) => {
  const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
  const d = await loadDeal(db, id);
  if (!d) return res.status(404).json({ error: 'Deal not found.' });
  auditReq(req, res, 'view-deal', d.buyer + ' / ' + d.seller, `deal ${id}${d.chatSnapshot ? ' (with chat evidence)' : ''}`, 0);
  res.json({ deal: d });
});

app.post('/api/admin/deals/:id/resolve', async (req, res) => {
  const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
  const mode = String(req.body.mode || '');
  if (mode !== 'refund' && mode !== 'pay') return res.status(400).json({ error: 'Bad request.' });
  const out = await inTx(res, async (tx) => {
    const d = await loadDeal(tx, id);
    if (!d || !['paid', 'not_received', 'reported'].includes(d.status)) throw new Abort('This transaction was already handled.');
    if (!dealAmountsValid(d)) throw new Abort('Deal amounts failed integrity validation. Escalate this deal for manual review.', 409);
    const finalStatus = mode === 'refund' ? 'refunded' : 'released';
    if (mode === 'refund') {
      const claim = await tx.execute({ sql: 'UPDATE deals SET status = ?, updatedAt = ?, completedAt = ? WHERE id = ? AND status = ?', args: [finalStatus, Date.now(), Date.now(), id, d.status] });
      if (!claim.rowsAffected) throw new Abort('This transaction was already handled.');
      const credit = await tx.execute({ sql: 'UPDATE users SET balanceCents = COALESCE(balanceCents, 0) + ?, balance = (COALESCE(balanceCents, 0) + ?) / 100.0 WHERE username = ?', args: [d.amountCents, d.amountCents, d.buyer] });
      if (!credit.rowsAffected) throw new Abort('The buyer account no longer exists.');
      await tx.execute({ sql: 'UPDATE users SET heldBalanceCents = MAX(0, COALESCE(heldBalanceCents, 0) - ?), heldBalance = MAX(0, COALESCE(heldBalanceCents, 0) - ?) / 100.0 WHERE username = ?', args: [d.sellerAmountCents, d.sellerAmountCents, d.seller] });
    } else {
      await finishDeal(tx, d, finalStatus);          // pays the seller; the sold unit leaves the listing like any completed deal
    }
    console.log(`ADMIN ${req.user} resolved deal ${id} as ${finalStatus}`);
    auditReq(req, res, 'resolve', d.buyer + ' / ' + d.seller, `deal ${id} ${finalStatus}`, d.amount);
    return { status: finalStatus, amount: d.amount, sellerAmount: d.sellerAmount, buyer: d.buyer, seller: d.seller };
  });
  if (out) res.json(out);
});

// ======================================================================
// Stage 3: users directory, profile, listings, pictures, chat
// The browser never reads other people's private data or rewrites whole user rows.
// Listings, chat messages and pictures live in their own indexed tables and reference users by their permanent numeric id.
// ======================================================================
const THREAD_SEP = '~i~';
const isAdminName = async (name) => {
  const r = await db.execute({ sql: 'SELECT customId FROM users WHERE username = ?', args: [name] });
  return !!r.rows.length && isAdminId(r.rows[0].customId);
};
const clampInt = (v, lo, hi, dflt) => { const n = Math.floor(Number(v)); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt; };
const inList = (arr) => arr.map(() => '?').join(',');

// ---------- listings ----------
const mapListing = (r) => ({
  id: Number(r.id), name: r.name, description: r.description || '', tag: r.tag, price: r.price || '', game: r.game || '', category: r.category || '',
  items: parseJson(r.items, []), wanted: parseJson(r.wanted, null), stock: Number(r.stock), photo: r.photoId ? mediaUrl(r.photoId) : null,
  createdAt: Number(r.createdAt) || Number(r.id), updatedAt: Number(r.updatedAt) || 0,
  sellerUsername: r.owner, owner: r.owner
});
async function listingsOfOwners(ownerIds) {     // Map(ownerId -> [listing, ...]) newest first
  const out = new Map();
  if (!ownerIds.length) return out;
  const rs = await db.execute({ sql: `SELECT l.*, u.username AS owner FROM listings l JOIN users u ON u.id = l.ownerId WHERE l.ownerId IN (${inList(ownerIds)}) ORDER BY l.id DESC`, args: ownerIds });
  for (const r of rs.rows) { const k = Number(r.ownerId); if (!out.has(k)) out.set(k, []); out.get(k).push(mapListing(r)); }
  return out;
}
const banPart = (r) => ({
  bannedUntil: Number(r.bannedUntil) || 0, bannedAt: Number(r.bannedAt) || 0, banReason: r.banReason || '',
  appeal: r.appeal || '', appealAt: Number(r.appealAt) || 0, appealStatus: r.appealStatus || ''
});
// what everybody may see about everybody. Ban reason, appeal text and ban dates are NOT here: only the owner (privateUser) and the admin see them.
const publicUser = (r, items = []) => ({
  customId: r.customId, username: r.username, displayName: r.displayName || r.username, avatar: safeImageOut(r.avatar),
  items, roblox: r.roblox || '', isMiddleman: Number(r.isMiddleman) === 1,
  lastSeen: Number(r.lastSeen) || 0, joinedAt: Number(r.joinedAt) || 0, bannedUntil: Number(r.bannedUntil) || 0
});
// Username / display-name change cooldowns (the same ones the Edit Profile screen announces). Enforced HERE, not in the page.
const USERNAME_COOLDOWN_MS = 14 * DAY, DISPLAYNAME_COOLDOWN_MS = 7 * DAY;
const nextChangeAt = (last, cooldown) => { const t = Number(last) || 0; return t ? t + cooldown : 0; };
// what only the owner sees (never the password or its hash). Messages are NOT part of it any more: they come from /api/chat/sync, paginated.
const privateUser = (r, items = []) => ({
  ...publicUser(r, items), ...banPart(r), email: r.email || '', card: null, balance: fromCents(r.balanceCents),
  heldBalance: fromCents(r.heldBalanceCents), lastUsernameChange: r.lastUsernameChange || null,
  lastDisplayNameChange: r.lastDisplayNameChange || null, lastItemTime: Number(r.lastItemTime) || 0,
  nextUsernameChangeAt: nextChangeAt(r.lastUsernameChange, USERNAME_COOLDOWN_MS), nextDisplayNameChangeAt: nextChangeAt(r.lastDisplayNameChange, DISPLAYNAME_COOLDOWN_MS),
  mustChangePassword: Number(r.mustChangePassword) === 1
});
// extra columns for the admin panel (no password, no hash)
const adminUser = (r, items = []) => ({
  ...publicUser(r, items), ...banPart(r), email: r.email || '', balance: fromCents(r.balanceCents), heldBalance: fromCents(r.heldBalanceCents),
  lastIp: r.lastIp || '', lastItemTime: Number(r.lastItemTime) || 0
});

// /api/users is the long list every page load fetches, so it carries only light fields: no listings (items) and no pictures.
// Pictures are a small URL (served by /api/avatar/:name, cacheable); listings come from /api/listings, only for screens that need them.
const USER_LIST_COLS = "id, customId, username, displayName, roblox, isMiddleman, lastSeen, joinedAt, bannedUntil, (CASE WHEN avatar IS NOT NULL AND avatar != '' THEN 1 ELSE 0 END) AS hasAvatar";
const ADMIN_USER_LIST_COLS = "customId, username, displayName, roblox, isMiddleman, lastSeen, joinedAt, bannedUntil, bannedAt, banReason, appeal, appealAt, appealStatus, email, balanceCents, heldBalanceCents, lastIp, lastItemTime, (CASE WHEN avatar IS NOT NULL AND avatar != '' THEN 1 ELSE 0 END) AS hasAvatar";
const lightUser = (r) => ({
  customId: r.customId, username: r.username, displayName: r.displayName || r.username,
  avatar: Number(r.hasAvatar) ? '/api/avatar/' + encodeURIComponent(r.username) : null,
  roblox: r.roblox || '', isMiddleman: Number(r.isMiddleman) === 1,
  lastSeen: Number(r.lastSeen) || 0, joinedAt: Number(r.joinedAt) || 0, bannedUntil: Number(r.bannedUntil) || 0
});
const lightAdminUser = (r) => ({
  ...lightUser(r), ...banPart(r), email: r.email || '', balance: fromCents(r.balanceCents), heldBalance: fromCents(r.heldBalanceCents),
  lastIp: r.lastIp || '', lastItemTime: Number(r.lastItemTime) || 0
});
app.get('/api/users', requireUser, async (req, res) => {
  const rs = await db.execute(`SELECT ${USER_LIST_COLS} FROM users`);
  // This is a public directory for any signed-in account: never include emails, balances, or IP addresses.
  // An older copy of the page (without the X-UT-Page header) still expects each user's listings inside this list, so they are added for it.
  if (!req.headers['x-ut-page']) {
    const byOwner = await listingsOfOwners(rs.rows.map(r => Number(r.id)).filter(n => Number.isFinite(n)));
    return res.json({ users: rs.rows.map(r => ({ ...lightUser(r), items: byOwner.get(Number(r.id)) || [] })) });
  }
  res.json({ users: rs.rows.map(lightUser) });
});

app.get('/api/admin/directory', async (req, res) => {
  const rs = await db.execute(`SELECT ${ADMIN_USER_LIST_COLS} FROM users`);
  res.setHeader('Cache-Control', 'no-store');
  res.json({ users: rs.rows.map(lightAdminUser) });
});

// Listings of everybody (the marketplace), kept out of /api/users on purpose. Newest first, paginated with a cursor:
//   GET /api/listings?limit=100&cursor=<id of the last listing you already have>[&owner=name][&tag=selling][&game=...][&q=text]
// -> { items: [...flat page...], listings: [{ username, items }] (the same page grouped by seller), nextCursor: id | null }
app.get('/api/listings', requireUser, async (req, res) => {
  const limit = clampInt(req.query.limit, 1, 500, 200), cursor = clampInt(req.query.cursor, 0, Number.MAX_SAFE_INTEGER, 0);
  const where = [], args = [];
  if (cursor) { where.push('l.id < ?'); args.push(cursor); }
  if (req.query.owner) { where.push('u.username = ?'); args.push(String(req.query.owner).slice(0, 40)); }
  if (req.query.tag && LISTING_TAGS.includes(String(req.query.tag))) { where.push('l.tag = ?'); args.push(String(req.query.tag)); }
  if (req.query.game) { where.push('l.game = ?'); args.push(String(req.query.game).slice(0, 60)); }
  if (req.query.q) { where.push("l.name LIKE ? ESCAPE '\\'"); args.push('%' + String(req.query.q).slice(0, 60).replace(/[\\%_]/g, '\\$&') + '%'); }
  const rs = await db.execute({ sql: `SELECT l.*, u.username AS owner FROM listings l JOIN users u ON u.id = l.ownerId ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY l.id DESC LIMIT ?`, args: [...args, limit + 1] });
  const more = rs.rows.length > limit;
  const items = rs.rows.slice(0, limit).map(mapListing);
  const grouped = new Map();
  for (const it of items) { if (!grouped.has(it.owner)) grouped.set(it.owner, []); grouped.get(it.owner).push(it); }
  res.json({ items, listings: [...grouped].map(([username, list]) => ({ username, items: list })), nextCursor: more && items.length ? items[items.length - 1].id : null });
});

// cheap change signal for polling: a counter bumped by EVERY listing change (create, edit of price / stock / text / picture, sale, delete) plus the ban state
app.get('/api/listings/sig', requireUser, async (req, res) => {
  const rev = await metaGet('listingsRev');
  const c = await db.execute('SELECT COUNT(*) AS c, COALESCE(MAX(updatedAt), 0) AS m FROM listings');
  const b = await db.execute('SELECT COALESCE(SUM(bannedUntil), 0) AS s, COUNT(*) AS c FROM users WHERE COALESCE(bannedUntil, 0) != 0');
  res.json({ sig: `${rev || 0}:${Number(c.rows[0].c)}:${Number(c.rows[0].m)}:${Number(b.rows[0].s)}:${Number(b.rows[0].c)}` });
});

// "Is somebody messaging the seller about this item right now?" Counts DIFFERENT people who wrote to / were answered by the seller about this listing in the last 10 minutes.
// Only a number is returned (never who), and the viewer is not counted as "somebody else".
const ACTIVITY_WINDOW_MS = 10 * 60 * 1000;
app.get('/api/listings/:id/activity', requireUser, async (req, res) => {
  if (!listingIdOk(req.params.id)) return res.status(400).json({ error: 'Invalid listing ID.' });
  const l = await getListing(db, req.params.id);
  if (!l) return res.status(404).json({ error: 'Listing not found.' });
  const rs = await db.execute({
    sql: 'SELECT DISTINCT CASE WHEN senderId = ? THEN receiverId ELSE senderId END AS other FROM messages WHERE itemId = ? AND ts > ? AND (senderId = ? OR receiverId = ?)',
    args: [l.ownerId, String(l.id), Date.now() - ACTIVITY_WINDOW_MS, l.ownerId, l.ownerId]
  });
  const people = rs.rows.map(r => Number(r.other));
  const others = people.filter(x => x !== req.userId).length;
  res.json({ active: others > 0, count: others, you: people.includes(req.userId), windowMinutes: ACTIVITY_WINDOW_MS / 60000 });
});

// profile picture as a real image, so it is cached by the browser instead of being repeated inside every JSON list
app.get('/api/avatar/:name', requireUser, async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT avatar FROM users WHERE username = ?', args: [String(req.params.name)] });
  const m = rs.rows.length && IMG_DATA_RE.exec(String(rs.rows[0].avatar || ''));
  if (!m || m[2].length % 4 !== 0) return res.status(404).end();
  const buf = Buffer.from(m[2], 'base64');
  const kind = sniffImageType(buf);
  if (!kind) return res.status(404).end();
  const etag = '"' + crypto.createHash('sha1').update(buf).digest('hex') + '"';
  res.setHeader('ETag', etag);
  res.setHeader('Cache-Control', 'private, no-cache');       // always revalidate (cheap 304), so a new picture shows up at once
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  if (req.headers['if-none-match'] === etag) return res.status(304).end();
  res.setHeader('Content-Type', 'image/' + kind);
  res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");   // even if opened directly, nothing in it can run
  res.send(buf);
});

// Listing photos and chat pictures: binary blobs with their own URL (not base64 inside JSON). The id is random and never reused for different bytes, so the
// browser may keep the picture for a year. Listing photos may be seen by any signed-in user; chat pictures only by the two people in that chat (and the elevated admin).
app.get('/api/media/:id', requireUser, async (req, res) => {
  const id = String(req.params.id);
  if (!MEDIA_ID_RE.test(id)) return res.status(404).end();
  const rs = await db.execute({ sql: 'SELECT kind, ownerId, peerId, mime, data FROM media WHERE id = ?', args: [id] });
  if (!rs.rows.length) return res.status(404).end();
  const r = rs.rows[0];
  if (r.kind === 'chat' && Number(r.ownerId) !== req.userId && Number(r.peerId) !== req.userId && !(await isElevatedAdmin(req))) return res.status(404).end();
  const buf = Buffer.from(r.data);
  const real = sniffImageType(buf);
  if (!real || 'image/' + real !== String(r.mime)) return res.status(404).end();
  const etag = '"' + id + '"';
  res.setHeader('ETag', etag);
  res.setHeader('Cache-Control', 'private, max-age=31536000, immutable');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  if (req.headers['if-none-match'] === etag) return res.status(304).end();
  res.setHeader('Content-Type', String(r.mime));
  res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
  res.send(buf);
});

app.get('/api/users/presence', requireUser, async (req, res) => {
  const rs = await db.execute('SELECT username, lastSeen FROM users');
  res.json({ users: rs.rows.map(r => ({ username: r.username, lastSeen: Number(r.lastSeen) || 0 })) });
});

app.get('/api/user/:name', requireUser, async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT * FROM users WHERE username = ?', args: [String(req.params.name)] });
  if (!rs.rows.length) return res.status(404).json({ error: 'Account not found.' });
  const row = rs.rows[0];
  const items = (await listingsOfOwners([Number(row.id)])).get(Number(row.id)) || [];
  // email / IP / balance are only shown to an admin who has re-entered the admin password (an elevated session)
  res.json({ user: (await isElevatedAdmin(req)) ? adminUser(row, items) : publicUser(row, items) });
});

app.get('/api/profile', requireUser, async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [req.userId] });
  if (!rs.rows.length) return res.status(401).json({ error: 'Please log in.' });
  const items = (await listingsOfOwners([req.userId])).get(req.userId) || [];
  res.json({ user: privateUser(rs.rows[0], items) });
});

app.post('/api/heartbeat', requireUser, async (req, res) => {
  await db.execute({ sql: 'UPDATE users SET lastSeen = ? WHERE id = ?', args: [Date.now(), req.userId] });
  res.json({ ok: true });
});

const waitText = (ms) => { const d = Math.floor(ms / DAY), h = Math.floor(ms / 3600000) % 24, m = Math.max(1, Math.ceil(ms / 60000) % 60); return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`; };
// partial update of my own profile: only the fields that are sent are touched
app.post('/api/profile', requireUser, async (req, res) => {
  try {
    if (limited('prof:' + req.user, 30, 60 * 1000)) return res.status(429).json({ error: 'Too many requests.' });
    const b = req.body || {};
    const sets = [], args = [];
    if ('displayName' in b) {
      const v = String(b.displayName || '').trim().slice(0, 40) || req.user;
      const cur = (await db.execute({ sql: 'SELECT displayName, lastDisplayNameChange FROM users WHERE id = ?', args: [req.userId] })).rows[0];
      if (v !== String(cur.displayName || '')) {                  // saving the same name again is not a change and does not start a cooldown
        if (!req.isAdminAccount) {
          if (v !== req.user && isReservedUsername(v.replace(/\s+/g, ''))) return res.status(400).json({ error: 'This display name is reserved. Please choose another one.' });
          const next = nextChangeAt(cur.lastDisplayNameChange, DISPLAYNAME_COOLDOWN_MS);
          if (next > Date.now()) return res.status(429).json({ error: `You can change your display name again in ${waitText(next - Date.now())}.`, nextChangeAt: next });
        }
        sets.push('displayName = ?'); args.push(v);
        sets.push('lastDisplayNameChange = ?'); args.push(Date.now());
      }
    }
    if ('avatar' in b) {
      const v = (b.avatar == null || b.avatar === '') ? null : cleanImageDataUrl(b.avatar, 700000);
      if (v === null && b.avatar != null && b.avatar !== '') return res.status(400).json({ error: 'Invalid picture. Use a real PNG, JPEG, WebP or GIF image.' });
      sets.push('avatar = ?'); args.push(v);
    }
    if ('email' in b) {
      const v = String(b.email || '').trim().toLowerCase();
      const cur = await db.execute({ sql: 'SELECT email FROM users WHERE id = ?', args: [req.userId] });
      if (v !== String(cur.rows[0].email || '').toLowerCase()) {
        const err = await checkEmail(v); if (err) return res.status(400).json({ error: err });
        if ((await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(email) = ? AND id != ?', args: [v, req.userId] })).rows.length) return res.status(400).json({ error: 'This email is already registered.' });
      }
      sets.push('email = ?'); args.push(v);
    }
    // 'card' is deliberately ignored: this site never stores or accepts card details (old pages may still send the field)
    if ('roblox' in b) {
      const v = b.roblox == null || b.roblox === '' ? null : String(b.roblox).trim().slice(0, 40);
      sets.push('roblox = ?'); args.push(v);
    }
    if (!sets.length) return res.json({ ok: true });
    args.push(req.userId);
    await db.execute({ sql: `UPDATE users SET ${sets.join(', ')} WHERE id = ?`, args });
    res.json({ ok: true });
  } catch (e) { console.error('profile error:', e); res.status(500).json({ error: 'Server error. Try again.' }); }
});

// ---------- renaming an account ----------
// Messages, listings, pictures, group membership and sessions point at the permanent numeric user id, so they follow a rename by themselves.
// Everything that still stores the NAME as text is listed here and rewritten in the same transaction. (The test-suite walks the live schema and fails
// if a table with a user-name column is missing from this list, so a newly added table cannot be forgotten.)
const USERNAME_COLUMNS = [
  ['sessions', 'username'], ['admin_sessions', 'username'],
  ['deals', 'buyer'], ['deals', 'seller'], ['deals', 'reportedBy'],
  ['chat_clears', 'user'], ['typing', 'user'], ['typing', 'other'],
  ['tickets', 'creator'], ['tickets', 'partner'], ['tickets', 'claimedBy'],
  ['user_reports', 'target'], ['user_reports', 'reporter'], ['item_reports', 'seller'], ['item_reports', 'reporter'],
  ['spam_timeouts', 'username'],
  ['chat_groups', 'owner'], ['group_messages', 'sender'],
  ['ratings', 'rater'], ['ratings', 'target'], ['vouches', 'middleman'], ['vouches', 'author'],
  ['social_ip_guard', 'target'], ['social_ip_guard', 'actor'],
  ['ip_bans', 'username'], ['user_ips', 'username'], ['withdrawals', 'username'], ['withdrawals', 'handledBy'],
  ['admin_audit', 'admin'], ['admin_audit', 'target']
];
// tables whose PRIMARY KEY contains a user-name column: leftovers of a deleted account with the new name would collide, so they are cleared first
const USERNAME_KEYED = new Set(['chat_clears:user', 'typing:user', 'typing:other', 'spam_timeouts:username', 'ratings:rater', 'ratings:target', 'vouches:middleman', 'vouches:author', 'social_ip_guard:target', 'social_ip_guard:actor', 'user_ips:username']);
async function renameUserEverywhere(tx, oldName, newName) {
  for (const [t, c] of USERNAME_COLUMNS) {
    if (USERNAME_KEYED.has(t + ':' + c)) await tx.execute({ sql: `DELETE FROM ${t} WHERE ${c} = ?`, args: [newName] });          // orphans of an account that was deleted earlier
    await tx.execute({ sql: `UPDATE ${t} SET ${c} = ? WHERE ${c} = ?`, args: [newName, oldName] });
  }
  // chat_clears.other is "<other user>" or "<other user>~i~<item id>": the other person's name is the prefix
  await tx.execute({ sql: "DELETE FROM chat_clears WHERE other = ? OR substr(other, 1, ?) = ?", args: [newName, newName.length + THREAD_SEP.length, newName + THREAD_SEP] });
  await tx.execute({ sql: "UPDATE chat_clears SET other = ? || substr(other, ?) WHERE other = ? OR substr(other, 1, ?) = ?", args: [newName, oldName.length + 1, oldName, oldName.length + THREAD_SEP.length, oldName + THREAD_SEP] });
  // the frozen chat evidence stored on reported deals names the two people as well
  const snaps = await tx.execute({ sql: 'SELECT id, chatSnapshot FROM deals WHERE (buyer = ? OR seller = ?) AND chatSnapshot IS NOT NULL', args: [newName, newName] });
  for (const r of snaps.rows) {
    const arr = parseJson(r.chatSnapshot, null);
    if (!Array.isArray(arr)) continue;
    let changed = false;
    for (const m of arr) { if (m && m.sender === oldName) { m.sender = newName; changed = true; } if (m && m.receiver === oldName) { m.receiver = newName; changed = true; } }
    if (changed) await tx.execute({ sql: 'UPDATE deals SET chatSnapshot = ? WHERE id = ?', args: [JSON.stringify(arr), Number(r.id)] });
  }
}
// a name that old deals still mention (an account that was deleted) cannot be taken again: the new owner would inherit that deal history
async function nameHasHistory(q, name) {
  const r = await q.execute({ sql: 'SELECT 1 FROM deals WHERE buyer = ? COLLATE NOCASE OR seller = ? COLLATE NOCASE LIMIT 1', args: [name, name] });
  return r.rows.length > 0;
}
// change my username; the row (balance, hash, listings, messages...) stays, everything pointing at the name follows
app.post('/api/profile/rename', requireUser, async (req, res) => {
  try {
    if (limited('rename:' + req.user, 10, 60 * 60 * 1000)) return res.status(429).json({ error: 'Too many requests.' });
    const nu = String((req.body && req.body.username) || '').trim();
    const err = checkUsername(nu, { allowReserved: req.isAdminAccount }); if (err) return res.status(400).json({ error: err });
    if (nu === req.user) return res.json({ username: nu });
    const out = await inTx(res, async (tx) => {
      const me = (await tx.execute({ sql: 'SELECT lastUsernameChange FROM users WHERE id = ?', args: [req.userId] })).rows[0];
      if (!me) throw new Abort('Please log in.', 401);
      if (!req.isAdminAccount) {
        const next = nextChangeAt(me.lastUsernameChange, USERNAME_COOLDOWN_MS);
        if (next > Date.now()) throw new Abort(`You can change your username again in ${waitText(next - Date.now())}.`, 429);
      }
      if ((await tx.execute({ sql: 'SELECT 1 FROM users WHERE lower(username) = lower(?) AND id != ?', args: [nu, req.userId] })).rows.length) throw new Abort('Username is already taken');
      if (nu.toLowerCase() !== req.user.toLowerCase() && await nameHasHistory(tx, nu)) throw new Abort('This username is not available.');
      await tx.execute({ sql: 'UPDATE users SET username = ?, lastUsernameChange = ? WHERE id = ?', args: [nu, Date.now(), req.userId] });
      await renameUserEverywhere(tx, req.user, nu);
      return nu;
    });
    if (out) res.json({ username: out });
  } catch (e) { console.error('rename error:', e); res.status(500).json({ error: 'Server error. Try again.' }); }
});

// ---------- items (listings) ----------
const LISTING_COOLDOWN = 10 * 60 * 1000;
const LISTING_TAGS = ['selling', 'specific', 'any', 'offers'];
// Validates the form and returns clean values. `current` is the stored listing row when editing (so its own picture can be kept).
function cleanItem(b, current) {
  const tag = LISTING_TAGS.includes(String(b.tag)) ? String(b.tag) : null;
  const stock = Number(b.stock);
  // picture: empty = no picture; a data: URL = a new picture; this listing's own /api/media/<id> URL = keep what is stored
  let photo = { mode: 'none' };
  if (b.photo != null && b.photo !== '') {
    if (typeof b.photo !== 'string') throw new Abort('Invalid picture. Use a real PNG, JPEG, WebP or GIF image.', 400);
    if (b.photo.startsWith('data:')) {
      const img = decodeImageDataUrl(b.photo, 900000);
      if (!img) throw new Abort('Invalid picture. Use a real PNG, JPEG, WebP or GIF image.', 400);
      photo = { mode: 'new', img };
    } else {
      const m = /\/api\/media\/([A-Za-z0-9_-]{8,64})(?:[?#].*)?$/.exec(b.photo);
      if (!m || !current || String(current.photoId || '') !== m[1]) throw new Abort('Invalid picture. Use a real PNG, JPEG, WebP or GIF image.', 400);
      photo = { mode: 'keep', id: m[1] };
    }
  }
  const rawPrice = b.price == null ? '' : String(b.price).trim();
  const price = rawPrice;
  const list = (arr) => (Array.isArray(arr) ? arr.slice(0, 60).map(x => String(x).slice(0, 80)) : []);
  const wanted = b.wanted && typeof b.wanted === 'object' ? { game: String(b.wanted.game || '').slice(0, 60), items: list(b.wanted.items) } : null;
  const name = String(b.name || '').trim().slice(0, 80);
  if (!name) throw new Abort('Please enter a name.', 400);
  if (!tag) throw new Abort('Invalid listing type.', 400);
  if (tag === 'selling' && (!/^\d{1,8}(?:\.\d{1,2})?$/.test(price) || !Number.isFinite(Number(price)) || Number(price) <= 0 || Number(price) > 1000000)) throw new Abort('Enter a valid price between 0.01 and 1,000,000 with at most two decimals.', 400);
  if (tag !== 'selling' && price !== '' && (!/^\d{1,8}(?:\.\d{1,2})?$/.test(price) || Number(price) < 0 || Number(price) > 1000000)) throw new Abort('Invalid price.', 400);
  if (typeof b.name !== 'string' || b.name.length > 160) throw new Abort('Invalid item name.', 400);
  if (b.description != null && (typeof b.description !== 'string' || b.description.length > 2000)) throw new Abort('Invalid description.', 400);
  if (b.items != null && !Array.isArray(b.items)) throw new Abort('Invalid item list.', 400);
  if (b.wanted != null && (typeof b.wanted !== 'object' || Array.isArray(b.wanted) || (b.wanted.items != null && !Array.isArray(b.wanted.items)))) throw new Abort('Invalid wanted items.', 400);
  if (!Number.isInteger(stock) || stock < 0 || stock > 99999) throw new Abort('Stock must be a whole number from 0 to 99999.', 400);
  return {
    name, description: String(b.description || '').slice(0, 2000), tag, price, priceCents: price === '' ? null : Math.round(Number(price) * 100), photo,
    game: String(b.game || '').slice(0, 60), category: String(b.category || '').slice(0, 60),
    items: list(b.items), wanted, stock
  };
}
app.post('/api/items', requireUser, async (req, res) => {
  const out = await inTx(res, async (tx) => {
    const rs = await tx.execute({ sql: 'SELECT customId, lastItemTime, bannedUntil FROM users WHERE id = ?', args: [req.userId] });
    if (!rs.rows.length) throw new Abort('Please log in.', 401);
    const u = rs.rows[0];
    const until = Number(u.bannedUntil) || 0;
    if (until === -1 || until > Date.now()) throw new Abort('Your account is banned.', 403);
    const body = req.body || {};
    const editId = body.id != null ? Number(body.id) : null;
    if (body.id != null && (!Number.isSafeInteger(editId) || editId <= 0)) throw new Abort('Invalid listing ID.', 400);
    const now = Date.now();
    if (editId != null) {
      const cur = await getListing(tx, editId);
      if (!cur || Number(cur.ownerId) !== req.userId) throw new Abort('Item not found.', 404);
      const data = cleanItem(body, cur);
      let photoId = cur.photoId || null;
      if (data.photo.mode === 'none') photoId = null;
      else if (data.photo.mode === 'new') {
        photoId = newMediaId();
        await tx.execute({ sql: "INSERT INTO media (id, kind, ownerId, refId, mime, size, data, createdAt) VALUES (?, 'listing', ?, ?, ?, ?, ?, ?)", args: [photoId, req.userId, String(editId), data.photo.img.mime, data.photo.img.buf.length, data.photo.img.buf, now] });
      }
      if (cur.photoId && cur.photoId !== photoId) await tx.execute({ sql: "DELETE FROM media WHERE id = ? AND kind = 'listing'", args: [cur.photoId] });
      await tx.execute({
        sql: 'UPDATE listings SET name = ?, description = ?, tag = ?, price = ?, priceCents = ?, game = ?, category = ?, items = ?, wanted = ?, stock = ?, photoId = ?, updatedAt = ? WHERE id = ?',
        args: [data.name, data.description, data.tag, data.price, data.priceCents, data.game, data.category, JSON.stringify(data.items), data.wanted ? JSON.stringify(data.wanted) : null, data.stock, photoId, now, editId]
      });
      await bumpMeta(tx, 'listingsRev');
      return { id: editId };
    }
    const data = cleanItem(body, null);
    if (!isAdminId(u.customId)) {
      const wait = (Number(u.lastItemTime) || 0) + LISTING_COOLDOWN - now;
      if (wait > 0) throw new Abort(`You can list another item in ${Math.ceil(wait / 60000)} min.`, 429);
      const cnt = await tx.execute({ sql: 'SELECT COUNT(*) AS c FROM listings WHERE ownerId = ?', args: [req.userId] });
      if (Number(cnt.rows[0].c) >= 200) throw new Abort('You have too many listings.', 400);
    }
    let id = now; while ((await tx.execute({ sql: 'SELECT 1 FROM listings WHERE id = ?', args: [id] })).rows.length) id++;
    let photoId = null;
    if (data.photo.mode === 'new') {
      photoId = newMediaId();
      await tx.execute({ sql: "INSERT INTO media (id, kind, ownerId, refId, mime, size, data, createdAt) VALUES (?, 'listing', ?, ?, ?, ?, ?, ?)", args: [photoId, req.userId, String(id), data.photo.img.mime, data.photo.img.buf.length, data.photo.img.buf, now] });
    }
    await tx.execute({
      sql: 'INSERT INTO listings (id, ownerId, name, description, tag, price, priceCents, game, category, items, wanted, stock, photoId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      args: [id, req.userId, data.name, data.description, data.tag, data.price, data.priceCents, data.game, data.category, JSON.stringify(data.items), data.wanted ? JSON.stringify(data.wanted) : null, data.stock, photoId, now, now]
    });
    await tx.execute({ sql: 'UPDATE users SET lastItemTime = ? WHERE id = ?', args: [now, req.userId] });
    await bumpMeta(tx, 'listingsRev');
    return { id };
  });
  if (out) res.json(out);
});
// delete several of my own listings at once: { ids: [..up to 200..] } -> { ok, deleted }
app.post('/api/items/delete-many', requireUser, async (req, res) => {
  const ids = [...new Set((Array.isArray(req.body && req.body.ids) ? req.body.ids : []).map(Number).filter(n => Number.isSafeInteger(n) && n > 0))].slice(0, 200);
  if (!ids.length) return res.status(400).json({ error: 'Pick at least one item.' });
  const out = await inTx(res, async (tx) => {
    const mine = (await tx.execute({ sql: `SELECT id FROM listings WHERE ownerId = ? AND id IN (${ids.map(() => '?').join(',')})`, args: [req.userId, ...ids] })).rows.map(r => Number(r.id));
    for (const id of mine) {
      await tx.execute({ sql: 'DELETE FROM listings WHERE id = ?', args: [id] });
      await tx.execute({ sql: "DELETE FROM media WHERE kind = 'listing' AND refId = ?", args: [String(id)] });
      await tx.execute({ sql: "UPDATE deals SET status = 'cancelled', updatedAt = ? WHERE itemId = ? AND seller = ? AND status = 'requested'", args: [Date.now(), String(id), req.user] });
    }
    if (mine.length) await bumpMeta(tx, 'listingsRev');
    return mine.length;
  });
  if (out !== undefined) res.json({ ok: true, deleted: out });
});

app.delete('/api/items/:id', requireUser, async (req, res) => {
  const deleteId = Number(req.params.id); /* validated just below */ if (!listingIdOk(req.params.id)) return res.status(400).json({ error: 'Invalid listing ID.' });
  const out = await inTx(res, async (tx) => {
    const cur = await getListing(tx, deleteId);
    if (!cur || Number(cur.ownerId) !== req.userId) throw new Abort('Item not found.', 404);
    await tx.execute({ sql: 'DELETE FROM listings WHERE id = ?', args: [deleteId] });
    await tx.execute({ sql: "DELETE FROM media WHERE kind = 'listing' AND refId = ?", args: [String(deleteId)] });
    // payment requests that were still waiting for this listing can no longer be paid
    await tx.execute({ sql: "UPDATE deals SET status = 'cancelled', updatedAt = ? WHERE itemId = ? AND seller = ? AND status = 'requested'", args: [Date.now(), String(deleteId), req.user] });
    await bumpMeta(tx, 'listingsRev');
    return true;
  });
  if (out) res.json({ ok: true });
});

// ---------- chat ----------
// One row per message in the `messages` table (sender/receiver are numeric user ids). A person "deleting a chat" only moves their own
// watermark (chat_clears); the rows disappear for good once BOTH people have deleted it.
const mapMessage = (r) => {
  const m = { sender: r.sender, receiver: r.receiver, text: r.text || '', timestamp: Number(r.ts), itemRef: parseJson(r.itemRef, null), itemId: r.itemId || null };
  if (r.imageId) { m.imageId = r.imageId; m.imageUrl = mediaUrl(r.imageId); m.caption = r.caption || ''; }
  if (r.offer) m.offer = parseJson(r.offer, null);
  if (r.editedAt) m.editedAt = Number(r.editedAt);
  return m;
};
const MSG_SELECT = 'SELECT m.*, s.username AS sender, r.username AS receiver FROM messages m JOIN users s ON s.id = m.senderId JOIN users r ON r.id = m.receiverId';
const threadKeyOf = (other, itemId) => other + (itemId ? THREAD_SEP + String(itemId) : '');
async function myClears(userName) {
  const rs = await db.execute({ sql: 'SELECT other, clearedAt FROM chat_clears WHERE user = ?', args: [userName] });
  const clears = {}; rs.rows.forEach(r => { clears[r.other] = Number(r.clearedAt) || 0; });
  return clears;
}
async function userIdByName(q, name) {
  const r = await q.execute({ sql: 'SELECT id FROM users WHERE username = ?', args: [name] });
  return r.rows.length ? Number(r.rows[0].id) : 0;
}
function cleanItemRef(r) {
  if (!r || typeof r !== 'object') return null;
  return { name: String(r.name || '').slice(0, 80), price: String(r.price || '').slice(0, 30), game: String(r.game || '').slice(0, 60), seller: String(r.seller || '').slice(0, 40) };
}
function cleanOffer(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o) || !Array.isArray(o.items) || !o.items.length || o.items.length > 60) return null;
  if (o.items.some(x => typeof x !== 'string' || !x.trim() || x.trim().length > 80)) return null;
  if (typeof o.game !== 'string' || !o.game.trim() || o.game.length > 60) return null;
  if (o.listingGame != null && (typeof o.listingGame !== 'string' || o.listingGame.length > 60)) return null;
  const items = o.items.map(x => x.trim());
  return { game: o.game.trim(), items, mm: o.mm === true, listingGame: String(o.listingGame || '').trim(), status: 'pending' };
}

// All my conversations in one call, paginated per conversation: the newest `perThread` messages of each, plus the true size of each conversation.
//   GET /api/chat/sync?perThread=40&threads=100  ->  { messages: [...oldest first], threads: [{ other, itemId, count, lastTs }], sig, clears, now }
// Older messages of one conversation: GET /api/chat/messages?other=NAME[&itemId=ID]&before=<timestamp>&limit=50
app.get('/api/chat/sync', requireUser, async (req, res) => {
  const perThread = clampInt(req.query.perThread, 1, 200, 40), maxThreads = clampInt(req.query.threads, 1, 200, 100);
  const clears = await myClears(req.user);
  const rs = await db.execute({
    sql: `SELECT * FROM (
            SELECT m.*, s.username AS sender, r.username AS receiver,
                   ROW_NUMBER() OVER (PARTITION BY CASE WHEN m.senderId = ?1 THEN m.receiverId ELSE m.senderId END, m.itemId ORDER BY m.ts DESC) AS rn,
                   COUNT(*) OVER (PARTITION BY CASE WHEN m.senderId = ?1 THEN m.receiverId ELSE m.senderId END, m.itemId) AS total
            FROM messages m JOIN users s ON s.id = m.senderId JOIN users r ON r.id = m.receiverId
            WHERE m.senderId = ?1 OR m.receiverId = ?1
          ) WHERE rn <= ?2 ORDER BY ts ASC`,
    args: [req.userId, perThread]
  });
  const threads = new Map(), messages = [];
  for (const r of rs.rows) {
    const other = r.sender === req.user ? r.receiver : r.sender, key = threadKeyOf(other, r.itemId);
    if (Number(r.ts) <= (clears[key] || 0)) continue;                                   // hidden by my own "delete chat"
    messages.push({ r, key });
    const t = threads.get(key) || { other, itemId: r.itemId || '', count: 0, lastTs: 0, total: Number(r.total) };
    t.count++; t.lastTs = Math.max(t.lastTs, Number(r.ts)); threads.set(key, t);
  }
  const keep = new Set([...threads.values()].sort((a, b) => b.lastTs - a.lastTs).slice(0, maxThreads).map(t => threadKeyOf(t.other, t.itemId)));
  const out = messages.filter(x => keep.has(x.key)).map(x => mapMessage(x.r));
  res.json({
    messages: out, now: Date.now(), clears,
    threads: [...threads.values()].filter(t => keep.has(threadKeyOf(t.other, t.itemId))).map(t => ({ other: t.other, itemId: t.itemId, loaded: t.count, total: t.total, lastTs: t.lastTs })),
    sig: await messageSig(req.userId)
  });
});
app.get('/api/chat/messages', requireUser, async (req, res) => {
  const other = String(req.query.other || ''), itemId = req.query.itemId ? String(req.query.itemId) : '';
  if (!other || other.length > 40) return res.status(400).json({ error: 'Bad request.' });
  if (itemId && !listingIdOk(itemId)) return res.status(400).json({ error: 'Invalid item ID.' });
  const otherId = await userIdByName(db, other);
  if (!otherId) return res.json({ messages: [], hasMore: false });
  const limit = clampInt(req.query.limit, 1, 200, 50), before = clampInt(req.query.before, 0, Number.MAX_SAFE_INTEGER, 0) || Number.MAX_SAFE_INTEGER;
  const cleared = (await myClears(req.user))[threadKeyOf(other, itemId)] || 0;
  const rs = await db.execute({
    sql: `${MSG_SELECT} WHERE ((m.senderId = ? AND m.receiverId = ?) OR (m.senderId = ? AND m.receiverId = ?)) AND m.itemId = ? AND m.ts < ? AND m.ts > ? ORDER BY m.ts DESC LIMIT ?`,
    args: [req.userId, otherId, otherId, req.userId, itemId, before, cleared, limit + 1]
  });
  res.json({ messages: rs.rows.slice(0, limit).reverse().map(mapMessage), hasMore: rs.rows.length > limit });
});
// change signal for my messages: count + newest and total revision, so edits, deletes, new messages and offer answers are ALL noticed
async function messageSig(userId) {
  const r = await db.execute({ sql: 'SELECT COUNT(*) AS c, COALESCE(MAX(rev), 0) AS m, COALESCE(SUM(rev), 0) AS s FROM messages WHERE senderId = ? OR receiverId = ?', args: [userId, userId] });
  return `${Number(r.rows[0].c)}:${Number(r.rows[0].m)}:${Number(r.rows[0].s)}`;
}
// Lightweight poll that replaces fetching the whole profile every few seconds:
//   GET /api/unread?since=<ms>  ->  incoming 1:1 messages newer than `since` (sender, item, time only), group activity, the change signals the page compares
//   (messages / deals / groups) and the live balance. The page refetches a conversation only when its signal changed.
app.get('/api/unread', requireUser, async (req, res) => {
  const since = clampInt(req.query.since, 0, Number.MAX_SAFE_INTEGER, 0);
  const [dm, clears, groups, msgSig, dSig, gSig, bal] = await Promise.all([
    db.execute({ sql: 'SELECT s.username AS sender, m.itemId, m.ts FROM messages m JOIN users s ON s.id = m.senderId WHERE m.receiverId = ? AND m.ts > ? ORDER BY m.ts DESC LIMIT 1000', args: [req.userId, since] }),
    myClears(req.user),
    db.execute({ sql: 'SELECT gmsg.groupId, gmsg.sender, gmsg.timestamp FROM group_messages gmsg JOIN group_members gm ON gm.groupId = gmsg.groupId AND gm.userId = ? WHERE gmsg.timestamp > ? AND (gmsg.senderId IS NULL OR gmsg.senderId != ?) ORDER BY gmsg.timestamp DESC LIMIT 1000', args: [req.userId, since, req.userId] }),
    messageSig(req.userId), dealsSig(req.user), groupsSig(req.userId),
    db.execute({ sql: 'SELECT balanceCents, heldBalanceCents FROM users WHERE id = ?', args: [req.userId] })
  ]);
  res.json({
    now: Date.now(), msgSig, dealsSig: dSig, groupsSig: gSig, clears,
    dm: dm.rows.map(r => ({ sender: r.sender, itemId: r.itemId || '', timestamp: Number(r.ts) })).filter(m => m.timestamp > (clears[threadKeyOf(m.sender, m.itemId)] || 0)),
    groups: groups.rows.map(r => ({ groupId: Number(r.groupId), sender: r.sender, timestamp: Number(r.timestamp) })),
    balance: bal.rows.length ? fromCents(bal.rows[0].balanceCents) : 0, held: bal.rows.length ? fromCents(bal.rows[0].heldBalanceCents) : 0
  });
});

app.post('/api/chat/send', requireUser, async (req, res) => {
  if (limited('chat:' + req.user, 20, 10 * 1000)) return res.status(429).json({ error: 'You are sending messages too fast.' });
  const b = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  const to = typeof b.receiver === 'string' ? b.receiver.trim() : '';
  const text = typeof b.text === 'string' ? b.text.slice(0, 2000) : '';
  const itemId = b.itemId == null || b.itemId === '' ? '' : String(b.itemId);
  if (!to || to.length > 40 || to === req.user) return res.status(400).json({ error: 'Choose another user.' });
  if (!text.trim() && !b.offer && !b.imageId) return res.status(400).json({ error: 'Message is empty.' });
  if (itemId && !listingIdOk(itemId)) return res.status(400).json({ error: 'Invalid item ID.' });
  try { const blocked = await spamBlocked(req.user); if (blocked) return res.status(429).json({ error: blocked }); } catch (e) { console.error('spam check error:', e); }
  const out = await inTx(res, async (tx) => {
    const ex = await tx.execute({ sql: 'SELECT bannedUntil FROM users WHERE id = ?', args: [req.userId] });
    const until = Number(ex.rows[0] && ex.rows[0].bannedUntil) || 0;
    if (until === -1 || until > Date.now()) throw new Abort('Your account is banned.', 403);
    const toId = await userIdByName(tx, to);
    if (!toId) throw new Abort('Account not found.', 404);
    if (itemId) {
      // a NEW conversation about an item needs a listing that exists; an existing conversation (for instance about an item that has just been sold) may continue
      const listing = await getListing(tx, itemId);
      const known = await tx.execute({ sql: 'SELECT 1 FROM messages WHERE itemId = ? AND ((senderId = ? AND receiverId = ?) OR (senderId = ? AND receiverId = ?)) LIMIT 1', args: [itemId, req.userId, toId, toId, req.userId] });
      if (!listing && !known.rows.length) throw new Abort('This listing no longer exists. Refresh the page before messaging.', 400);
    }
    let imageId = null;
    if (b.imageId) {
      if (typeof b.imageId !== 'string' || !MEDIA_ID_RE.test(b.imageId)) throw new Abort('Invalid picture ID.', 400);
      imageId = b.imageId;
      const im = await tx.execute({ sql: "SELECT 1 FROM media WHERE id = ? AND kind = 'chat' AND ownerId = ? AND peerId = ?", args: [imageId, req.userId, toId] });
      if (!im.rows.length) throw new Abort('Picture not found.', 400);
    }
    const offer = cleanOffer(b.offer); if (b.offer && !offer) throw new Abort('Invalid offer details.', 400);
    let ts = Date.now();
    while ((await tx.execute({ sql: 'SELECT 1 FROM messages WHERE senderId = ? AND ts = ?', args: [req.userId, ts] })).rows.length) ts++;      // the timestamp is the message id
    const rev = await bumpMeta(tx, 'msgRev');
    const itemRef = cleanItemRef(b.itemRef);
    await tx.execute({
      sql: 'INSERT INTO messages (senderId, receiverId, itemId, ts, text, itemRef, offer, imageId, caption, rev) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      args: [req.userId, toId, itemId, ts, text, itemRef ? JSON.stringify(itemRef) : null, offer ? JSON.stringify(offer) : null, imageId, imageId ? (typeof b.caption === 'string' ? b.caption.slice(0, 500) : '') : null, rev]
    });
    const msg = { sender: req.user, receiver: to, text, timestamp: ts, itemRef, itemId: itemId || null };
    if (imageId) { msg.imageId = imageId; msg.imageUrl = mediaUrl(imageId); msg.caption = typeof b.caption === 'string' ? b.caption.slice(0, 500) : ''; }
    if (offer) msg.offer = offer;
    return msg;
  });
  if (out) res.json({ message: out });
});
app.post('/api/chat/edit', requireUser, async (req, res) => {
  const to = String(req.body.receiver || ''), ts = Number(req.body.timestamp);
  const text = String(req.body.text || '').slice(0, 2000);
  if (!to || !ts || !text.trim()) return res.status(400).json({ error: 'Bad request.' });
  const out = await inTx(res, async (tx) => {
    const toId = await userIdByName(tx, to);
    if (!toId) return true;
    const rev = await bumpMeta(tx, 'msgRev');
    await tx.execute({ sql: 'UPDATE messages SET text = ?, editedAt = ?, rev = ? WHERE senderId = ? AND receiverId = ? AND ts = ? AND offer IS NULL AND imageId IS NULL AND text != ?', args: [text, Date.now(), rev, req.userId, toId, ts, text] });
    return true;
  });
  if (out) res.json({ ok: true });
});
app.post('/api/chat/delete', requireUser, async (req, res) => {
  const to = String(req.body.receiver || ''), ts = Number(req.body.timestamp);
  if (!to || !ts) return res.status(400).json({ error: 'Bad request.' });
  const out = await inTx(res, async (tx) => {
    const toId = await userIdByName(tx, to);
    if (!toId) return true;
    const m = await tx.execute({ sql: 'SELECT imageId FROM messages WHERE senderId = ? AND receiverId = ? AND ts = ?', args: [req.userId, toId, ts] });
    if (m.rows.length && m.rows[0].imageId) await tx.execute({ sql: "DELETE FROM media WHERE id = ? AND kind = 'chat' AND ownerId = ?", args: [m.rows[0].imageId, req.userId] });
    await tx.execute({ sql: 'DELETE FROM messages WHERE senderId = ? AND receiverId = ? AND ts = ?', args: [req.userId, toId, ts] });
    await bumpMeta(tx, 'msgRev');
    return true;
  });
  if (out) res.json({ ok: true });
});
// offers: the receiver accepts / declines / asks for more items; the sender updates the items after being asked
app.post('/api/chat/offer', requireUser, async (req, res) => {
  const b = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  const sender = typeof b.sender === 'string' ? b.sender : '', receiver = typeof b.receiver === 'string' ? b.receiver : '';
  const ts = Number(b.timestamp), action = typeof b.action === 'string' ? b.action : '';
  if (!sender || !receiver || sender === receiver || ![sender, receiver].includes(req.user) || !Number.isSafeInteger(ts) || ts <= 0 || !['accept', 'decline', 'add', 'update'].includes(action)) return res.status(400).json({ error: 'Bad request.' });
  const out = await inTx(res, async (tx) => {
    const sId = await userIdByName(tx, sender), rId = await userIdByName(tx, receiver);
    const row = sId && rId ? (await tx.execute({ sql: 'SELECT id, text, offer FROM messages WHERE senderId = ? AND receiverId = ? AND ts = ? AND offer IS NOT NULL', args: [sId, rId, ts] })).rows[0] : null;
    if (!row) throw new Abort('Offer not found.', 404);
    const offer = parseJson(row.offer, null);
    let text = row.text;
    if (!offer || !Array.isArray(offer.items) || !offer.items.length || offer.items.length > 60 || !['pending', 'accepted', 'declined', 'add'].includes(offer.status)) throw new Abort('This offer failed validation.', 409);
    let next = offer;
    if (action === 'accept' || action === 'decline' || action === 'add') {
      if (req.user !== receiver) throw new Abort('Only the other person can respond to this offer.', 403);
      if (offer.status !== 'pending') throw new Abort('This offer was already answered.', 409);
      next = { ...offer, status: action === 'accept' ? 'accepted' : action === 'decline' ? 'declined' : 'add', by: req.user };
    } else if (action === 'update') {
      if (req.user !== sender) throw new Abort('Only the sender can change the offer.', 403);
      if (offer.status !== 'add') throw new Abort('Items can only be changed after the other person asks for additions.', 409);
      if (!Array.isArray(b.items) || !b.items.length || b.items.length > 60 || b.items.some(x => typeof x !== 'string' || !x.trim() || x.length > 80)) throw new Abort('Invalid offer items.', 400);
      // Keep game, listing context, and middleman flag from the original server-stored offer.
      next = cleanOffer({ game: offer.game, listingGame: offer.listingGame, mm: offer.mm, items: b.items });
      if (!next) throw new Abort('Pick at least one item.', 400);
      text = typeof b.text === 'string' ? b.text.trim().slice(0, 2000) : String(row.text || '').slice(0, 2000);
    }
    const rev = await bumpMeta(tx, 'msgRev');
    await tx.execute({ sql: 'UPDATE messages SET offer = ?, text = ?, rev = ? WHERE id = ?', args: [JSON.stringify(next), text, rev, Number(row.id)] });
    return true;
  });
  if (out) res.json({ ok: true });
});

// delete a chat only for me (moves my watermark); also forgets it forever when the other side already deleted theirs
app.post('/api/chat/clear', requireUser, async (req, res) => {
  const other = String(req.body.other || ''), itemId = req.body.itemId ? String(req.body.itemId) : '';
  if (!other) return res.status(400).json({ error: 'Bad request.' });
  const key = threadKeyOf(other, itemId), theirKey = threadKeyOf(req.user, itemId);
  const out = await inTx(res, async (tx) => {
    const open = await tx.execute({
      sql: "SELECT id FROM deals WHERE ((buyer = ? AND seller = ?) OR (buyer = ? AND seller = ?)) AND COALESCE(itemId, '') = ? AND status IN ('requested','paid','not_received','reported') LIMIT 1",
      args: [req.user, other, other, req.user, itemId]
    });
    if (open.rows.length) throw new Abort('Finish or resolve the deal in this chat before deleting it.');
    const otherId = await userIdByName(tx, other);
    const pair = [req.userId, otherId, otherId, req.userId, itemId];
    const PAIR_SQL = '((senderId = ? AND receiverId = ?) OR (senderId = ? AND receiverId = ?)) AND itemId = ?';
    const mx = otherId ? await tx.execute({ sql: `SELECT COALESCE(MAX(ts), 0) AS t FROM messages WHERE ${PAIR_SQL}`, args: pair }) : null;
    const mark = Math.max(Date.now(), mx ? Number(mx.rows[0].t) : 0);
    await tx.execute({ sql: 'INSERT INTO chat_clears (user, other, clearedAt) VALUES (?, ?, ?) ON CONFLICT(user, other) DO UPDATE SET clearedAt = excluded.clearedAt', args: [req.user, key, mark] });
    const th = await tx.execute({ sql: 'SELECT clearedAt FROM chat_clears WHERE user = ? AND other = ?', args: [other, theirKey] });
    const theirMark = th.rows.length ? Number(th.rows[0].clearedAt) || 0 : -1;
    // the other side sees nothing either (they deleted it too, or the account is gone): nothing is left to keep
    const theirVisible = otherId && theirMark >= 0 ? Number((await tx.execute({ sql: `SELECT COUNT(*) AS c FROM messages WHERE ${PAIR_SQL} AND ts > ?`, args: [...pair, theirMark] })).rows[0].c) : (otherId ? 1 : 0);
    if (theirVisible === 0) {
      if (otherId) {
        await tx.execute({ sql: `DELETE FROM media WHERE kind = 'chat' AND id IN (SELECT imageId FROM messages WHERE ${PAIR_SQL} AND imageId IS NOT NULL)`, args: pair });
        await tx.execute({ sql: `DELETE FROM messages WHERE ${PAIR_SQL}`, args: pair });
        await bumpMeta(tx, 'msgRev');
      }
      await tx.execute({
        sql: "DELETE FROM deals WHERE status IN ('completed','cancelled','refunded','released') AND COALESCE(itemId, '') = ? AND ((buyer = ? AND seller = ?) OR (buyer = ? AND seller = ?))",
        args: [itemId, req.user, other, other, req.user]
      });
      await tx.execute({ sql: 'DELETE FROM chat_clears WHERE (user = ? AND other = ?) OR (user = ? AND other = ?)', args: [req.user, key, other, theirKey] });
    }
    return true;
  });
  if (out) res.json({ ok: true });
});
app.get('/api/chat/clears', requireUser, async (req, res) => {
  res.json({ clears: await myClears(req.user) });
});

// pictures: uploaded once as binary (kept as a media blob), then referenced by id from a message and shown through /api/media/<id>
const CHAT_IMG_PER_DAY = 40, CHAT_IMG_STORED_BYTES = 25 * 1024 * 1024;
app.post('/api/chat/image', requireUser, async (req, res) => {
  if (limited('img:' + req.user, 10, 60 * 1000)) return res.status(429).json({ error: 'Too many pictures. Slow down.' });
  const to = String(req.body.receiver || '');
  const img = decodeImageDataUrl(req.body.data, 700000);
  if (!to || !img) return res.status(400).json({ error: 'Invalid picture. Use a real PNG, JPEG, WebP or GIF image.' });
  const toId = await userIdByName(db, to);
  if (!toId || toId === req.userId) return res.status(404).json({ error: 'Account not found.' });
  // per-user quota: how many pictures a day, and how much picture data may sit on the server at once (old pictures are purged with their chats)
  const q = await db.execute({ sql: "SELECT COALESCE(SUM(CASE WHEN createdAt > ? THEN 1 ELSE 0 END), 0) AS today, COALESCE(SUM(size), 0) AS bytes FROM media WHERE kind = 'chat' AND ownerId = ?", args: [Date.now() - DAY, req.userId] });
  if (Number(q.rows[0].today) >= CHAT_IMG_PER_DAY) return res.status(429).json({ error: `You can send at most ${CHAT_IMG_PER_DAY} pictures per day.` });
  if (Number(q.rows[0].bytes) + img.buf.length > CHAT_IMG_STORED_BYTES) return res.status(413).json({ error: 'Your picture storage is full. Old pictures are removed automatically after two weeks, or delete some chats.' });
  const id = newMediaId();
  await db.execute({ sql: "INSERT INTO media (id, kind, ownerId, peerId, mime, size, data, createdAt) VALUES (?, 'chat', ?, ?, ?, ?, ?, ?)", args: [id, req.userId, toId, img.mime, img.buf.length, img.buf, Date.now()] });
  res.json({ id, url: mediaUrl(id) });
});

// typing dots
app.post('/api/chat/typing', requireUser, async (req, res) => {
  const other = String(req.body.other || '');
  if (!other) return res.status(400).json({ error: 'Bad request.' });
  if (req.body.stop) await db.execute({ sql: 'DELETE FROM typing WHERE user = ? AND other = ?', args: [req.user, other] });
  else await db.execute({ sql: 'INSERT INTO typing (user, other, ts) VALUES (?, ?, ?) ON CONFLICT(user, other) DO UPDATE SET ts = excluded.ts', args: [req.user, other, Date.now()] });
  res.json({ ok: true });
});
app.get('/api/chat/typing', requireUser, async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT ts FROM typing WHERE user = ? AND other = ?', args: [String(req.query.other || ''), req.user] });
  res.json({ ts: rs.rows.length ? Number(rs.rows[0].ts) || 0 : 0 });
});

// admin: read the chat between two people (used by the reports page). Every read is written to the audit log.
app.get('/api/admin/chat', async (req, res) => {
  const a = String(req.query.a || ''), b = String(req.query.b || '');
  const aId = await userIdByName(db, a), bId = await userIdByName(db, b);
  auditReq(req, res, 'view-chat', `${a} / ${b}`, 'read the private chat between these two accounts', 0);
  if (!aId || !bId) return res.json({ messages: [] });
  const rs = await db.execute({ sql: `${MSG_SELECT} WHERE (m.senderId = ? AND m.receiverId = ?) OR (m.senderId = ? AND m.receiverId = ?) ORDER BY m.ts ASC LIMIT 2000`, args: [aId, bId, bId, aId] });
  res.json({ messages: rs.rows.map(mapMessage) });
});

// admin: delete an account (never the admin itself)
app.post('/api/admin/delete-user', async (req, res) => {
  const name = String(req.body.username || '');
  if (!name) return res.status(400).json({ error: 'Bad request.' });
  // never delete an account while money is held for it or from it: the admin has to resolve those deals first
  const held = await db.execute({ sql: "SELECT COUNT(*) AS c FROM deals WHERE (buyer = ? OR seller = ?) AND status IN ('paid','not_received','reported')", args: [name, name] });
  if (Number(held.rows[0].c)) return res.status(409).json({ error: 'This account has money held in unfinished deals. Resolve them in Money first.' });
  const victim = await db.execute({ sql: "SELECT id FROM users WHERE username = ? AND COALESCE(customId, '') != 'knqw'", args: [name] });
  if (!victim.rows.length) return res.status(404).json({ error: 'Account not found.' });
  const uid = Number(victim.rows[0].id);
  await deleteUserData(uid, name);
  console.log(`ADMIN ${req.user} deleted account ${name}`);
  auditReq(req, res, 'delete-user', name, '', 0);
  res.json({ ok: true });
});
// removes the account and everything that belongs to it. Finished deals stay (financial history); unfinished payment requests are cancelled.
async function deleteUserData(uid, name) {
  const stmts = [
    ["UPDATE deals SET status = 'cancelled', updatedAt = ? WHERE (buyer = ? OR seller = ?) AND status = 'requested'", [Date.now(), name, name]],
    ["DELETE FROM media WHERE ownerId = ? OR peerId = ?", [uid, uid]],
    ["DELETE FROM messages WHERE senderId = ? OR receiverId = ?", [uid, uid]],
    ["DELETE FROM listings WHERE ownerId = ?", [uid]],
    ["DELETE FROM group_messages WHERE groupId IN (SELECT id FROM chat_groups WHERE ownerId = ?)", [uid]],
    ["DELETE FROM group_members WHERE groupId IN (SELECT id FROM chat_groups WHERE ownerId = ?)", [uid]],
    ["DELETE FROM chat_groups WHERE ownerId = ?", [uid]],
    ["DELETE FROM group_members WHERE userId = ?", [uid]],
    ["DELETE FROM admin_sessions WHERE userId = ?", [uid]],
    ["DELETE FROM sessions WHERE userId = ?", [uid]],
    ["DELETE FROM topup_intents WHERE userId = ? AND status != 'completed'", [uid]],
    ["DELETE FROM tickets WHERE creator = ? OR partner = ?", [name, name]],
    ["DELETE FROM user_ips WHERE username = ?", [name]],
    ["DELETE FROM chat_clears WHERE user = ? OR other = ? OR substr(other, 1, ?) = ?", [name, name, name.length + THREAD_SEP.length, name + THREAD_SEP]],
    ["DELETE FROM typing WHERE user = ? OR other = ?", [name, name]],
    ["DELETE FROM spam_timeouts WHERE username = ?", [name]],
    ["DELETE FROM ratings WHERE rater = ? OR target = ?", [name, name]],
    ["DELETE FROM vouches WHERE author = ? OR middleman = ?", [name, name]],
    ["DELETE FROM social_ip_guard WHERE actor = ? OR target = ?", [name, name]],
    ["DELETE FROM users WHERE id = ? AND COALESCE(customId, '') != 'knqw'", [uid]]
  ];
  await db.batch(stmts.map(([sql, args]) => ({ sql, args })), 'write');
  await bumpMeta(db, 'listingsRev'); await bumpMeta(db, 'msgRev');
}

// ---------- housekeeping ----------
// Old chats are cleaned up by the server (every 10 minutes), not by whoever opens the page.
const CHAT_TTL_MS = 14 * DAY;
async function purgeOldChats() {
  try {
    const cutoff = Date.now() - CHAT_TTL_MS;
    // messages older than the retention period go, except between two people who still have an unfinished deal
    await db.execute({
      sql: `DELETE FROM messages WHERE ts < ? AND NOT EXISTS (
              SELECT 1 FROM deals d JOIN users b ON b.username = d.buyer JOIN users s ON s.username = d.seller
              WHERE d.status IN ('requested','paid','not_received','reported')
                AND ((b.id = messages.senderId AND s.id = messages.receiverId) OR (b.id = messages.receiverId AND s.id = messages.senderId)))`,
      args: [cutoff]
    });
    for (const sql of ["DELETE FROM group_messages WHERE timestamp < ?", "DELETE FROM deals WHERE status IN ('completed','cancelled','refunded','released') AND updatedAt < ?", "DELETE FROM chat_clears WHERE clearedAt < ?", "DELETE FROM media WHERE kind = 'chat' AND createdAt < ?"]) {
      try { await db.execute({ sql, args: [cutoff] }); } catch (e) { console.error('purge step failed:', e.message); }
    }
    // pictures that were uploaded but never sent (or whose message was deleted) free their space after an hour
    await db.execute({ sql: "DELETE FROM media WHERE kind = 'chat' AND createdAt < ? AND id NOT IN (SELECT imageId FROM messages WHERE imageId IS NOT NULL)", args: [Date.now() - 60 * 60 * 1000] });
    await db.execute({ sql: 'DELETE FROM typing WHERE ts < ?', args: [Date.now() - 60000] });
  } catch (e) { console.error('purge error:', e); }
}
// (purgeOldChats runs from runCleanup() below)

// ======================================================================
// Stage 4: ratings, vouches, tickets, reports, groups, bans, appeals, IP bans, spam timeouts, flags
// Everything an admin does here is written to the audit log (admin_audit), including reading private chats.
// ======================================================================
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const isMiddlemanName = async (name) => {
  const r = await db.execute({ sql: 'SELECT isMiddleman FROM users WHERE username = ?', args: [name] });
  return !!r.rows.length && Number(r.rows[0].isMiddleman) === 1;
};
const userExists = async (name) => !!name && (await db.execute({ sql: 'SELECT 1 FROM users WHERE username = ?', args: [name] })).rows.length > 0;
const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { console.error(req.path, e); if (!res.headersSent) res.status(500).json({ error: 'Server error. Try again.' }); } };
const envNum = (name, dflt) => { const raw = process.env[name]; if (raw == null || String(raw).trim() === '') return dflt; const n = Number(raw); return Number.isFinite(n) && n >= 0 ? n : dflt; };

// Rate/vouch anti-farming: at most one account per target from the same observed IP.
// Only a keyed fingerprint is stored here; raw IPs remain restricted to moderation tables.
async function claimSocialIp(kind, target, actor, req) {
  const ip = ipOf(req);
  if (!ip) return { ok: true, skipped: true };
  const ipHash = ipFingerprint(ip);
  const existing = await db.execute({ sql: 'SELECT actor FROM social_ip_guard WHERE kind = ? AND target = ? AND ipHash = ?', args: [kind, target, ipHash] });
  if (existing.rows.length && String(existing.rows[0].actor) !== actor) return { ok: false };
  await db.execute({ sql: 'INSERT OR IGNORE INTO social_ip_guard (kind, target, ipHash, actor, createdAt) VALUES (?, ?, ?, ?, ?)', args: [kind, target, ipHash, actor, Date.now()] });
  const check = await db.execute({ sql: 'SELECT actor FROM social_ip_guard WHERE kind = ? AND target = ? AND ipHash = ?', args: [kind, target, ipHash] });
  return { ok: !!check.rows.length && String(check.rows[0].actor) === actor };
}

// Review-farming rules (all adjustable with environment variables):
//  * a rating needs a COMPLETED deal with that person worth at least MIN_RATING_DEAL (default $5);
//  * a vouch needs a middleman ticket that this middleman claimed and closed for you;
//  * both need an account at least MIN_SOCIAL_ACCOUNT_AGE_HOURS old (default 24);
//  * plus the existing "one account per target per network" guard and the per-hour limits.
const MIN_RATING_DEAL_CENTS = Math.round(envNum('MIN_RATING_DEAL', 5) * 100);
const MIN_SOCIAL_AGE_MS = envNum('MIN_SOCIAL_ACCOUNT_AGE_HOURS', 24) * 3600 * 1000;
const dollars = (cents) => '$' + (cents / 100).toFixed(2).replace(/\.00$/, '');
async function socialAgeError(userId, what) {
  const r = await db.execute({ sql: 'SELECT joinedAt FROM users WHERE id = ?', args: [userId] });
  const joined = r.rows.length ? Number(r.rows[0].joinedAt) || 0 : 0;
  if (joined && Date.now() - joined < MIN_SOCIAL_AGE_MS) {
    const left = joined + MIN_SOCIAL_AGE_MS - Date.now();
    return `Your account is too new to ${what}. Try again in ${waitText(left)}.`;
  }
  return '';
}
async function ratingBlock(userId, userName, target) {      // '' when allowed, else the reason
  const age = await socialAgeError(userId, 'leave ratings'); if (age) return age;
  const d = await db.execute({ sql: "SELECT 1 FROM deals WHERE status IN ('completed','released') AND amountCents >= ? AND ((buyer = ? AND seller = ?) OR (buyer = ? AND seller = ?)) LIMIT 1", args: [MIN_RATING_DEAL_CENTS, userName, target, target, userName] });
  if (!d.rows.length) return `You can rate someone after a completed deal of at least ${dollars(MIN_RATING_DEAL_CENTS)} with them.`;
  return '';
}

// ---------- ratings ----------
app.get('/api/ratings/meta', requireUser, wrap(async (req, res) => {
  const meta = {};
  (await db.execute('SELECT target, AVG(stars) AS a, COUNT(*) AS c FROM ratings GROUP BY target')).rows
    .forEach(x => { meta[x.target] = { avg: Number(x.a) || 0, count: Number(x.c) || 0, vouches: 0 }; });
  (await db.execute('SELECT middleman, COUNT(*) AS c FROM vouches GROUP BY middleman')).rows.forEach(x => {
    if (!meta[x.middleman]) meta[x.middleman] = { avg: 0, count: 0, vouches: 0 };
    meta[x.middleman].vouches = Number(x.c) || 0;
  });
  res.json({ meta });
}));
app.get('/api/ratings/:user', requireUser, wrap(async (req, res) => {
  const t = String(req.params.user);
  const r = await db.execute({ sql: 'SELECT AVG(stars) AS a, COUNT(*) AS c FROM ratings WHERE target = ?', args: [t] });
  const m = await db.execute({ sql: 'SELECT stars FROM ratings WHERE target = ? AND rater = ?', args: [t, req.user] });
  const mine = m.rows.length ? Number(m.rows[0].stars) || 0 : 0;
  const reason = t === req.user ? 'You cannot rate yourself.' : (mine ? '' : await ratingBlock(req.userId, req.user, t));
  res.json({ avg: Number(r.rows[0].a) || 0, count: Number(r.rows[0].c) || 0, mine, canRate: !reason, reason });
}));
app.post('/api/ratings', requireUser, wrap(async (req, res) => {
  if (limited('rate:' + req.user, 30, 60 * 60 * 1000)) return bad(res, 'Too many requests.', 429);
  const target = String(req.body.target || ''), stars = Number(req.body.stars);
  if (!target || target === req.user || !Number.isInteger(stars) || stars < 1 || stars > 5) return bad(res, 'Bad request.');
  if (!(await userExists(target))) return bad(res, 'Account not found.', 404);
  const had = (await db.execute({ sql: 'SELECT 1 FROM ratings WHERE rater = ? AND target = ?', args: [req.user, target] })).rows.length > 0;
  // changing a rating you already gave is always fine (the deal behind it may be gone by now); a first rating has to be earned
  const reason = had ? await socialAgeError(req.userId, 'leave ratings') : await ratingBlock(req.userId, req.user, target);
  if (reason) return bad(res, reason, 403);
  const socialClaim = await claimSocialIp('rating', target, req.user, req);
  if (!socialClaim.ok) return bad(res, 'A rating for this user has already been submitted from this network.', 403);
  await db.execute({ sql: 'INSERT INTO ratings (rater, target, stars, createdAt) VALUES (?, ?, ?, ?) ON CONFLICT(rater, target) DO UPDATE SET stars = excluded.stars, createdAt = excluded.createdAt', args: [req.user, target, stars, Date.now()] });
  res.json({ ok: true });
}));
app.post('/api/ratings/remove', requireUser, wrap(async (req, res) => {
  await db.execute({ sql: 'DELETE FROM ratings WHERE rater = ? AND target = ?', args: [req.user, String(req.body.target || '')] });
  res.json({ ok: true });
}));
app.get('/api/admin/ratings/:user', wrap(async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT rater, stars, createdAt FROM ratings WHERE target = ? ORDER BY createdAt DESC', args: [String(req.params.user)] });
  res.json({ rows: rs.rows.map(r => ({ rater: r.rater, stars: Number(r.stars), createdAt: Number(r.createdAt) })) });
}));
app.post('/api/admin/ratings/add', wrap(async (req, res) => {
  const target = String(req.body.target || ''), stars = Number(req.body.stars);
  if (!(await userExists(target)) || !Number.isInteger(stars) || stars < 1 || stars > 5) return bad(res, 'Bad request.');
  await db.execute({ sql: 'INSERT INTO ratings (rater, target, stars, createdAt) VALUES (?, ?, ?, ?)', args: ['admin:' + Date.now() + crypto.randomInt(1000), target, stars, Date.now()] });
  auditReq(req, res, 'rating-add', target, `added a ${stars}-star rating`, 0);
  res.json({ ok: true });
}));
app.post('/api/admin/ratings/remove', wrap(async (req, res) => {
  const rater = String(req.body.rater || ''), target = String(req.body.target || '');
  const rs = await db.execute({ sql: 'SELECT stars FROM ratings WHERE rater = ? AND target = ?', args: [rater, target] });
  await db.execute({ sql: 'DELETE FROM ratings WHERE rater = ? AND target = ?', args: [rater, target] });
  auditReq(req, res, 'rating-remove', target, `removed the rating from ${rater}${rs.rows.length ? ' (' + Number(rs.rows[0].stars) + ' stars)' : ''}`, 0);
  res.json({ ok: true });
}));
app.post('/api/admin/ratings/clear', wrap(async (req, res) => {
  const target = String(req.body.target || '');
  const rs = await db.execute({ sql: 'DELETE FROM ratings WHERE target = ?', args: [target] });
  auditReq(req, res, 'rating-clear', target, `cleared all ratings (${rs.rowsAffected || 0})`, 0);
  res.json({ ok: true });
}));

// ---------- middleman tickets ----------
// Open tickets disappear after a day, claimed ones after a week, and CLOSED ones are kept for 90 days: a closed ticket is the proof that allows a vouch.
const TICKET_OPEN_TTL_MS = DAY, TICKET_CLAIMED_TTL_MS = 7 * DAY, TICKET_CLOSED_KEEP_MS = 90 * DAY;
async function purgeTickets() {
  const now = Date.now();
  await db.execute({ sql: "DELETE FROM tickets WHERE (status = 'open' AND createdAt < ?) OR (status = 'claimed' AND createdAt < ?) OR (status = 'closed' AND COALESCE(closedAt, createdAt) < ?)", args: [now - TICKET_OPEN_TTL_MS, now - TICKET_CLAIMED_TTL_MS, now - TICKET_CLOSED_KEEP_MS] });
}
const mapTicket = (r) => ({ id: Number(r.id), creator: r.creator, partner: r.partner || '', description: r.description, status: r.status, claimedBy: r.claimedBy || '', createdAt: Number(r.createdAt) });
app.get('/api/tickets', requireUser, wrap(async (req, res) => {
  await purgeTickets();
  const isMM = await isMiddlemanName(req.user);
  const rs = isMM
    ? await db.execute({ sql: "SELECT id, creator, partner, description, status, claimedBy, createdAt FROM tickets WHERE status = 'open' OR (status = 'claimed' AND (claimedBy = ? OR creator = ? OR partner = ?)) ORDER BY createdAt DESC LIMIT 100", args: [req.user, req.user, req.user] })
    : await db.execute({ sql: "SELECT id, creator, partner, description, status, claimedBy, createdAt FROM tickets WHERE status IN ('open', 'claimed') AND (creator = ? OR partner = ?) ORDER BY createdAt DESC LIMIT 100", args: [req.user, req.user] });
  res.json({ isMiddleman: isMM, tickets: rs.rows.map(mapTicket) });
}));
app.post('/api/tickets', requireUser, wrap(async (req, res) => {
  if (limited('ticket:' + req.user, 5, 60 * 60 * 1000)) return bad(res, 'Too many tickets. Try again later.', 429);
  const partner = String(req.body.partner || '').trim().slice(0, 64);
  if (!partner) return bad(res, 'Select who you are trading with.', 400);
  if (partner.toLowerCase() === String(req.user).toLowerCase()) return bad(res, 'You cannot create a ticket to trade with yourself.', 400);
  const partnerRow = await db.execute({ sql: 'SELECT username FROM users WHERE lower(username) = lower(?) LIMIT 1', args: [partner] });
  if (!partnerRow.rows.length) return bad(res, 'The selected trading partner was not found.', 400);
  const actualPartner = String(partnerRow.rows[0].username);
  const desc = String(req.body.description || '').trim().slice(0, 1000) || 'No description';
  await db.execute({ sql: "INSERT INTO tickets (creator, partner, description, status, createdAt) VALUES (?, ?, ?, 'open', ?)", args: [req.user, actualPartner, desc, Date.now()] });
  res.json({ ok: true });
}));
app.post('/api/tickets/:id/claim', requireUser, wrap(async (req, res) => {
  if (!(await isMiddlemanName(req.user))) return bad(res, 'Only middlemen can claim tickets.', 403);
  const rs = await db.execute({ sql: "UPDATE tickets SET status = 'claimed', claimedBy = ? WHERE id = ? AND status = 'open' AND creator != ? AND COALESCE(partner, '') != ?", args: [req.user, pid(req), req.user, req.user] });
  if (!rs.rowsAffected) return bad(res, 'This ticket is no longer available.', 409);
  res.json({ ok: true });
}));
app.post('/api/tickets/:id/cancel', requireUser, wrap(async (req, res) => {
  const rs = await db.execute({ sql: "DELETE FROM tickets WHERE id = ? AND creator = ? AND status IN ('open', 'claimed')", args: [pid(req), req.user] });
  if (!rs.rowsAffected) return bad(res, 'This ticket is already gone.', 409);
  res.json({ ok: true });
}));
app.post('/api/tickets/:id/close', requireUser, wrap(async (req, res) => {
  await db.execute({ sql: "UPDATE tickets SET status = 'closed', closedAt = ? WHERE id = ? AND claimedBy = ? AND status = 'claimed'", args: [Date.now(), pid(req), req.user] });
  res.json({ ok: true });
}));
app.get('/api/tickets/middlemen', requireUser, wrap(async (req, res) => {
  const rs = await db.execute({ sql: "SELECT DISTINCT claimedBy FROM tickets WHERE (creator = ? OR partner = ?) AND claimedBy IS NOT NULL AND claimedBy != '' AND status IN ('claimed', 'closed')", args: [req.user, req.user] });
  res.json({ names: rs.rows.map(r => r.claimedBy).filter(n => n && n !== req.user) });
}));

// ---------- vouches (for middlemen) ----------
async function vouchBlock(userId, userName, mm) {         // '' when allowed, else the reason
  const age = await socialAgeError(userId, 'vouch'); if (age) return age;
  const t = await db.execute({ sql: "SELECT 1 FROM tickets WHERE claimedBy = ? AND status = 'closed' AND (creator = ? OR partner = ?) LIMIT 1", args: [mm, userName, userName] });
  if (!t.rows.length) return 'You can vouch for a middleman after they have completed a ticket for you.';
  return '';
}
app.get('/api/vouches/:mm', requireUser, wrap(async (req, res) => {
  const mm = String(req.params.mm);
  const rs = await db.execute({ sql: 'SELECT id, author, text, createdAt FROM vouches WHERE middleman = ? ORDER BY createdAt DESC', args: [mm] });
  const mineRow = rs.rows.find(r => r.author === req.user);
  let reason = '';
  if (mm === req.user) reason = 'You cannot vouch for yourself.';
  else if (!mineRow) reason = await vouchBlock(req.userId, req.user, mm);
  res.json({ vouches: rs.rows.map(r => ({ id: Number(r.id), author: r.author, text: r.text, createdAt: Number(r.createdAt) })), canVouch: !reason, reason });
}));
app.post('/api/vouches', requireUser, wrap(async (req, res) => {
  if (limited('vouch:' + req.user, 20, 60 * 60 * 1000)) return bad(res, 'Too many requests.', 429);
  const mm = String(req.body.middleman || ''), text = String(req.body.text || '').trim();
  if (!mm || mm === req.user || !(await isMiddlemanName(mm))) return bad(res, 'You can only vouch for another middleman.');
  if (text.length < 3) return bad(res, 'Write at least 3 characters.');
  const had = (await db.execute({ sql: 'SELECT 1 FROM vouches WHERE middleman = ? AND author = ?', args: [mm, req.user] })).rows.length > 0;
  const reason = had ? await socialAgeError(req.userId, 'vouch') : await vouchBlock(req.userId, req.user, mm);
  if (reason) return bad(res, reason, 403);
  const socialClaim = await claimSocialIp('vouch', mm, req.user, req);
  if (!socialClaim.ok) return bad(res, 'A vouch for this middleman has already been submitted from this network.', 403);
  await db.execute({ sql: 'INSERT INTO vouches (middleman, author, text, createdAt) VALUES (?, ?, ?, ?) ON CONFLICT(middleman, author) DO UPDATE SET text = excluded.text, createdAt = excluded.createdAt', args: [mm, req.user, text.slice(0, 300), Date.now()] });
  res.json({ ok: true });
}));
app.post('/api/vouches/delete', requireUser, wrap(async (req, res) => {
  const id = Number(req.body.id);
  if (!Number.isSafeInteger(id) || id <= 0) return bad(res, 'Bad request.');
  const row = (await db.execute({ sql: 'SELECT middleman, author FROM vouches WHERE id = ?', args: [id] })).rows[0];
  if (!row) return res.json({ ok: true });
  if (row.author !== req.user) {
    // removing somebody else's vouch is an admin power: it needs the re-confirmed admin session and is audited
    if (!(await isElevatedAdmin(req))) return bad(res, 'You can only remove your own vouch.', 403);
    auditReq(req, res, 'vouch-remove', String(row.middleman), `removed the vouch written by ${row.author}`, 0);
  }
  await db.execute({ sql: 'DELETE FROM vouches WHERE id = ?', args: [id] });
  res.json({ ok: true });
}));

// ---------- reports ----------
const cleanReason = (v, n) => String(v || '').slice(0, n);
app.post('/api/reports/item', requireUser, wrap(async (req, res) => {
  if (limited('rep:' + req.user, 20, 60 * 60 * 1000)) return bad(res, 'Too many reports.', 429);
  const b = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  const itemId = String(b.itemId || ''), reason = typeof b.reason === 'string' ? cleanReason(b.reason.trim(), 100) : '';
  if (!listingIdOk(itemId) || !reason) return bad(res, 'Bad request.');
  const listing = await getListing(db, itemId);
  if (!listing) return bad(res, 'This listing no longer exists.', 404);
  if (listing.owner === req.user) return bad(res, 'You cannot report your own listing.', 403);
  if ((await db.execute({ sql: 'SELECT id FROM item_reports WHERE itemId = ? AND reporter = ? LIMIT 1', args: [itemId, req.user] })).rows.length) return res.json({ duplicate: true });
  await db.execute({ sql: 'INSERT INTO item_reports (itemId, itemName, itemGame, seller, reporter, reason, details, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', args: [itemId, cleanReason(listing.name, 100), cleanReason(listing.game, 60), cleanReason(listing.owner, 40), req.user, reason, typeof b.details === 'string' ? cleanReason(b.details.trim(), 1000) : '', Date.now()] });
  res.json({ ok: true });
}));
app.post('/api/reports/user', requireUser, wrap(async (req, res) => {
  if (limited('rep:' + req.user, 20, 60 * 60 * 1000)) return bad(res, 'Too many reports.', 429);
  const b = req.body, kind = b.kind === 'middleman' ? 'middleman' : 'user', target = String(b.target || ''), reason = cleanReason(b.reason, 100);
  if (!target || target === req.user || !reason) return bad(res, 'Bad request.');
  if ((await db.execute({ sql: 'SELECT id FROM user_reports WHERE kind = ? AND target = ? AND reporter = ? LIMIT 1', args: [kind, target, req.user] })).rows.length) return res.json({ duplicate: true });
  await db.execute({ sql: 'INSERT INTO user_reports (kind, target, reporter, reason, details, createdAt) VALUES (?, ?, ?, ?, ?, ?)', args: [kind, target, req.user, reason, cleanReason(b.details, 1000), Date.now()] });
  res.json({ ok: true });
}));
app.get('/api/admin/reports/items', wrap(async (req, res) => {
  res.json({ rows: (await db.execute('SELECT * FROM item_reports ORDER BY createdAt DESC')).rows.map(r => ({ ...r, id: Number(r.id), createdAt: Number(r.createdAt) })) });
}));
app.get('/api/admin/reports/users', wrap(async (req, res) => {
  res.json({ rows: (await db.execute('SELECT * FROM user_reports ORDER BY createdAt DESC')).rows.map(r => ({ ...r, id: Number(r.id), createdAt: Number(r.createdAt) })) });
}));
app.post('/api/admin/reports/item/dismiss', wrap(async (req, res) => {
  const id = Number(req.body && req.body.id); if (!Number.isSafeInteger(id) || id <= 0) return bad(res, 'Invalid report ID.');
  const row = (await db.execute({ sql: 'SELECT seller, reporter, itemName FROM item_reports WHERE id = ?', args: [id] })).rows[0];
  const r = await db.execute({ sql: 'DELETE FROM item_reports WHERE id = ?', args: [id] }); if (!r.rowsAffected) return bad(res, 'Report not found.', 404);
  auditReq(req, res, 'report-dismiss', row ? String(row.seller) : '', `dismissed item report #${id} by ${row ? row.reporter : '?'} (${row ? row.itemName : ''})`, 0);
  res.json({ ok: true });
}));
app.post('/api/admin/reports/user/dismiss', wrap(async (req, res) => {
  const id = Number(req.body && req.body.id); if (!Number.isSafeInteger(id) || id <= 0) return bad(res, 'Invalid report ID.');
  const row = (await db.execute({ sql: 'SELECT target, reporter, kind FROM user_reports WHERE id = ?', args: [id] })).rows[0];
  const r = await db.execute({ sql: 'DELETE FROM user_reports WHERE id = ?', args: [id] }); if (!r.rowsAffected) return bad(res, 'Report not found.', 404);
  auditReq(req, res, 'report-dismiss', row ? String(row.target) : '', `dismissed ${row ? row.kind : 'user'} report #${id} by ${row ? row.reporter : '?'}`, 0);
  res.json({ ok: true });
}));
app.post('/api/admin/deals/:id/cancel-report', wrap(async (req, res) => {
  const id = dealId(req); if (!id) return bad(res, 'Invalid deal ID.');
  const rs = await db.execute({ sql: "UPDATE deals SET status = 'not_received', reportedAt = 0, reportedBy = NULL, chatSnapshot = NULL, updatedAt = ? WHERE id = ? AND status = 'reported'", args: [Date.now(), id] });
  if (!rs.rowsAffected) return bad(res, 'This report was already handled.', 409);
  auditReq(req, res, 'cancel-report', `deal ${id}`, 'sent the reported deal back to "not received"', 0);
  res.json({ ok: true });
}));

// ---------- group chats ----------
// Members live in the group_members table (group id + permanent user id), so names with "_" or "%" can never match the wrong group
// and renaming a member changes nothing here.
const GROUP_MAX_MEMBERS = 100;
async function groupMembers(q, groupId) {
  const rs = await q.execute({ sql: 'SELECT u.username FROM group_members gm JOIN users u ON u.id = gm.userId WHERE gm.groupId = ? ORDER BY gm.joinedAt ASC, u.id ASC', args: [groupId] });
  return rs.rows.map(r => String(r.username));
}
async function loadGroup(q, id) {
  const rs = await q.execute({ sql: 'SELECT g.id, g.name, g.createdAt, g.ownerId, u.username AS owner FROM chat_groups g LEFT JOIN users u ON u.id = g.ownerId WHERE g.id = ?', args: [id] });
  if (!rs.rows.length) return null;
  const r = rs.rows[0];
  return { id: Number(r.id), name: r.name || 'Group', owner: r.owner || '', ownerId: Number(r.ownerId) || 0, createdAt: Number(r.createdAt) || 0, members: await groupMembers(q, Number(r.id)) };
}
async function memberGroup(id, userId, q = db) {        // the group, only if I am in it
  if (!Number.isSafeInteger(id) || id <= 0) return null;
  const m = await q.execute({ sql: 'SELECT 1 FROM group_members WHERE groupId = ? AND userId = ?', args: [id, userId] });
  if (!m.rows.length) return null;
  const g = await loadGroup(q, id);
  return g && g.members.length ? g : null;
}
async function myGroups(userId) {
  const rs = await db.execute({
    sql: `SELECT g.id, g.name, g.createdAt, u.username AS owner,
                 (SELECT COALESCE(MAX(timestamp), 0) FROM group_messages x WHERE x.groupId = g.id) AS lastMsg
          FROM chat_groups g JOIN group_members me ON me.groupId = g.id AND me.userId = ? LEFT JOIN users u ON u.id = g.ownerId`,
    args: [userId]
  });
  if (!rs.rows.length) return [];
  const ids = rs.rows.map(r => Number(r.id));
  const mem = await db.execute({ sql: `SELECT gm.groupId, u.username FROM group_members gm JOIN users u ON u.id = gm.userId WHERE gm.groupId IN (${inList(ids)}) ORDER BY gm.joinedAt ASC, u.id ASC`, args: ids });
  const byGroup = new Map();
  for (const r of mem.rows) { const k = Number(r.groupId); if (!byGroup.has(k)) byGroup.set(k, []); byGroup.get(k).push(String(r.username)); }
  return rs.rows.map(r => ({ id: Number(r.id), name: r.name || 'Group', owner: r.owner || '', members: byGroup.get(Number(r.id)) || [], createdAt: Number(r.createdAt) || 0, lastTime: Number(r.lastMsg) || Number(r.createdAt) || 0 }))
    .sort((a, b) => b.lastTime - a.lastTime);
}
// change signal: group list (ids, names, member counts) + message count / newest message
async function groupsSig(userId) {
  const rs = await db.execute({
    sql: `SELECT g.id, g.name, (SELECT COUNT(*) FROM group_members x WHERE x.groupId = g.id) AS mc,
                 (SELECT COUNT(*) FROM group_messages m WHERE m.groupId = g.id) AS c, (SELECT COALESCE(MAX(timestamp), 0) FROM group_messages m WHERE m.groupId = g.id) AS t
          FROM chat_groups g JOIN group_members me ON me.groupId = g.id AND me.userId = ? ORDER BY g.id`,
    args: [userId]
  });
  return rs.rows.map(r => `${Number(r.id)}:${Number(r.mc)}:${r.name}:${Number(r.c)}:${Number(r.t)}`).join('|');
}
app.get('/api/groups', requireUser, wrap(async (req, res) => res.json({ groups: await myGroups(req.userId) })));
app.get('/api/groups/sig', requireUser, wrap(async (req, res) => res.json({ sig: await groupsSig(req.userId) })));
app.get('/api/groups/unread', requireUser, wrap(async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT gmsg.groupId, gmsg.sender, gmsg.timestamp FROM group_messages gmsg JOIN group_members gm ON gm.groupId = gmsg.groupId AND gm.userId = ? WHERE gmsg.timestamp > ? AND (gmsg.senderId IS NULL OR gmsg.senderId != ?) ORDER BY gmsg.timestamp DESC LIMIT 1000', args: [req.userId, clampInt(req.query.since, 0, Number.MAX_SAFE_INTEGER, 0), req.userId] });
  res.json({ rows: rs.rows.map(r => ({ groupId: Number(r.groupId), sender: r.sender, timestamp: Number(r.timestamp) })) });
}));
app.get('/api/groups/:id', requireUser, wrap(async (req, res) => {
  const g = await memberGroup(pid(req), req.userId);
  if (!g) return bad(res, 'Group not found.', 404);
  res.json({ group: { id: g.id, name: g.name, owner: g.owner, members: g.members, createdAt: g.createdAt } });
}));
// newest `limit` messages (oldest first); pass before=<timestamp> for the page before them
app.get('/api/groups/:id/messages', requireUser, wrap(async (req, res) => {
  const id = pid(req);
  if (!(await memberGroup(id, req.userId))) return bad(res, 'Group not found.', 404);
  const limit = clampInt(req.query.limit, 1, 500, 300), before = clampInt(req.query.before, 0, Number.MAX_SAFE_INTEGER, 0) || Number.MAX_SAFE_INTEGER;
  const rs = await db.execute({ sql: 'SELECT sender, text, timestamp FROM group_messages WHERE groupId = ? AND timestamp < ? ORDER BY timestamp DESC, id DESC LIMIT ?', args: [id, before, limit + 1] });
  res.json({ messages: rs.rows.slice(0, limit).reverse().map(r => ({ sender: r.sender, text: r.text, timestamp: Number(r.timestamp) })), hasMore: rs.rows.length > limit });
}));
// people I may add: anyone I have a chat with, or a middleman who took one of my tickets
async function groupCandidates(userId, userName) {
  const set = new Set();
  const rs = await db.execute({
    sql: `SELECT DISTINCT u.username FROM (
            SELECT receiverId AS other FROM messages WHERE senderId = ?1 UNION SELECT senderId AS other FROM messages WHERE receiverId = ?1
          ) c JOIN users u ON u.id = c.other WHERE u.id != ?1`,
    args: [userId]
  });
  rs.rows.forEach(r => set.add(String(r.username)));
  (await db.execute({ sql: "SELECT DISTINCT claimedBy FROM tickets WHERE (creator = ? OR partner = ?) AND claimedBy IS NOT NULL AND claimedBy != '' AND status IN ('claimed','closed')", args: [userName, userName] })).rows.forEach(r => { if (r.claimedBy !== userName) set.add(String(r.claimedBy)); });
  return set;
}
app.post('/api/groups', requireUser, wrap(async (req, res) => {
  if (limited('grp:' + req.user, 10, 60 * 60 * 1000)) return bad(res, 'Too many requests.', 429);
  const name = String(req.body.name || '').trim().slice(0, 40);
  const picked = [...new Set((Array.isArray(req.body.members) ? req.body.members : []).map(String))].filter(n => n !== req.user).slice(0, 50);
  if (!name || !picked.length) return bad(res, 'Pick a name and at least one person.');
  const allowed = await groupCandidates(req.userId, req.user);
  if (picked.some(p => !allowed.has(p))) return bad(res, 'You can only add people you have chats with.', 403);
  const out = await inTx(res, async (tx) => {
    const ids = [];
    for (const p of picked) { const uid = await userIdByName(tx, p); if (!uid) throw new Abort('Account not found.', 404); ids.push(uid); }
    const now = Date.now();
    const rs = await tx.execute({ sql: 'INSERT INTO chat_groups (name, owner, ownerId, createdAt) VALUES (?, ?, ?, ?)', args: [name, req.user, req.userId, now] });
    const gid = Number(rs.lastInsertRowid);
    await tx.execute({ sql: 'INSERT INTO group_members (groupId, userId, joinedAt) VALUES (?, ?, ?)', args: [gid, req.userId, now] });
    for (const uid of ids) await tx.execute({ sql: 'INSERT OR IGNORE INTO group_members (groupId, userId, joinedAt) VALUES (?, ?, ?)', args: [gid, uid, now] });
    return gid;
  });
  if (out) res.json({ id: out });
}));
app.get('/api/groups/:id/candidates', requireUser, wrap(async (req, res) => {
  const g = await memberGroup(pid(req), req.userId);
  if (!g || g.ownerId !== req.userId) return bad(res, 'Only the owner can add people.', 403);
  res.json({ names: [...(await groupCandidates(req.userId, req.user))].filter(n => !g.members.includes(n)) });
}));
app.post('/api/groups/:id/members', requireUser, wrap(async (req, res) => {
  const gid = pid(req);
  const action = String(req.body.action || ''), who = String(req.body.username || '');
  const allowed = action === 'add' ? await groupCandidates(req.userId, req.user) : null;
  const out = await inTx(res, async (tx) => {
    const g = await memberGroup(gid, req.userId, tx);
    if (!g) throw new Abort('Group not found.', 404);
    if (action === 'add') {
      if (g.ownerId !== req.userId) throw new Abort('Only the owner can add people.', 403);
      const want = (Array.isArray(req.body.usernames) ? req.body.usernames : [who]).map(String).filter(n => allowed.has(n) && !g.members.includes(n));
      for (const n of want) {
        if (g.members.length >= GROUP_MAX_MEMBERS) break;
        const uid = await userIdByName(tx, n); if (!uid) continue;
        await tx.execute({ sql: 'INSERT OR IGNORE INTO group_members (groupId, userId, joinedAt) VALUES (?, ?, ?)', args: [gid, uid, Date.now()] });
        g.members.push(n);
      }
    } else if (action === 'remove') {
      if (g.ownerId !== req.userId || who === g.owner) throw new Abort('Only the owner can remove people.', 403);
      const uid = await userIdByName(tx, who);
      if (uid) await tx.execute({ sql: 'DELETE FROM group_members WHERE groupId = ? AND userId = ?', args: [gid, uid] });
    } else if (action === 'leave') {
      if (g.ownerId === req.userId) throw new Abort('The owner cannot leave. Delete the group instead.');
      await tx.execute({ sql: 'DELETE FROM group_members WHERE groupId = ? AND userId = ?', args: [gid, req.userId] });
    } else throw new Abort('Bad request.', 400);
    return true;
  });
  if (out) res.json({ ok: true });
}));
app.post('/api/groups/:id/delete', requireUser, wrap(async (req, res) => {
  const id = pid(req);
  if (!Number.isSafeInteger(id) || id <= 0) return bad(res, 'Bad request.');
  const out = await inTx(res, async (tx) => {
    const rs = await tx.execute({ sql: 'DELETE FROM chat_groups WHERE id = ? AND ownerId = ?', args: [id, req.userId] });
    if (!rs.rowsAffected) throw new Abort('Only the owner can delete the group.', 403);
    await tx.execute({ sql: 'DELETE FROM group_members WHERE groupId = ?', args: [id] });
    await tx.execute({ sql: 'DELETE FROM group_messages WHERE groupId = ?', args: [id] });
    return true;
  });
  if (out) res.json({ ok: true });
}));

// ---------- spam timeouts (enforced here, for 1:1 and group messages) ----------
const SPAM_STEPS = [15 * 1000, 3 * 60 * 1000, 60 * 60 * 1000, DAY];
const SPAM_MAX_MSGS = 5, SPAM_WINDOW_MS = 5000, SPAM_RESET_MS = DAY;
const spamStamps = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of spamStamps) if (!v.some(t => now - t < SPAM_WINDOW_MS)) spamStamps.delete(k); }, 60 * 1000);
async function spamBlocked(user) {           // returns an error text, or '' when the message may go through
  if (await isAdminName(user)) return '';
  const now = Date.now();
  const r = await db.execute({ sql: 'SELECT * FROM spam_timeouts WHERE username = ?', args: [user] });
  const row = r.rows[0];
  if (row && Number(row.until) > now) return `You are timed out for spamming. Try again in ${Math.ceil((Number(row.until) - now) / 1000)}s.`;
  const st = (spamStamps.get(user) || []).filter(t => now - t < SPAM_WINDOW_MS); st.push(now); spamStamps.set(user, st);
  if (st.length >= SPAM_MAX_MSGS) {
    spamStamps.set(user, []);
    let level = row ? Number(row.level) || 0 : 0;
    if (row && now - Number(row.until) > SPAM_RESET_MS) level = 0;
    const dur = SPAM_STEPS[Math.min(level, SPAM_STEPS.length - 1)];
    await db.execute({ sql: 'INSERT INTO spam_timeouts (username, level, until, lastOffense) VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET level = excluded.level, until = excluded.until, lastOffense = excluded.lastOffense', args: [user, level + 1, now + dur, now] });
    return `You are sending messages too fast. Timed out for ${Math.ceil(dur / 1000)}s.`;
  }
  return '';
}
app.post('/api/groups/:id/send', requireUser, wrap(async (req, res) => {
  const g = await memberGroup(pid(req), req.userId);
  if (!g) return bad(res, 'You are no longer in this group.', 403);
  const text = String(req.body.text || '').trim().slice(0, 2000);
  if (!text) return bad(res, 'Message is empty.');
  const blocked = await spamBlocked(req.user); if (blocked) return bad(res, blocked, 429);
  await db.execute({ sql: 'INSERT INTO group_messages (groupId, sender, senderId, text, timestamp) VALUES (?, ?, ?, ?, ?)', args: [g.id, req.user, req.userId, text, Date.now()] });
  res.json({ ok: true });
}));
app.get('/api/admin/timeouts', wrap(async (req, res) => {
  res.json({ rows: (await db.execute('SELECT * FROM spam_timeouts ORDER BY until DESC')).rows.map(r => ({ username: r.username, level: Number(r.level), until: Number(r.until), lastOffense: Number(r.lastOffense) })) });
}));
app.post('/api/admin/timeouts/remove', wrap(async (req, res) => {
  const name = String(req.body.username || '');
  await db.execute({ sql: 'DELETE FROM spam_timeouts WHERE username = ?', args: [name] });
  auditReq(req, res, 'timeout-remove', name, 'removed the chat timeout', 0);
  res.json({ ok: true });
}));
app.post('/api/admin/timeouts/add', wrap(async (req, res) => {
  const name = String(req.body.username || ''), mins = Math.floor(Number(req.body.minutes));
  if (!name || !(mins > 0) || mins > 525600) return bad(res, 'Enter the minutes to add.');
  if (!(await userExists(name))) return bad(res, 'Account not found.', 404);
  const cur = (await db.execute({ sql: 'SELECT until FROM spam_timeouts WHERE username = ?', args: [name] })).rows[0];
  const base = Math.max(Date.now(), cur ? Number(cur.until) || 0 : 0);
  await db.execute({ sql: 'INSERT INTO spam_timeouts (username, level, until, lastOffense) VALUES (?, 0, ?, ?) ON CONFLICT(username) DO UPDATE SET until = excluded.until, lastOffense = excluded.lastOffense', args: [name, base + mins * 60000, Date.now()] });
  auditReq(req, res, 'timeout-add', name, `added ${mins} minute(s) of chat timeout`, 0);
  res.json({ ok: true });
}));

// ---------- bans, appeals, middleman role, IP bans ----------
app.get('/api/me/ban', requireUser, wrap(async (req, res) => {
  const r = await db.execute({ sql: 'SELECT username, customId, bannedUntil, bannedAt, banReason, appeal, appealAt, appealStatus FROM users WHERE id = ?', args: [req.userId] });
  if (!r.rows.length) return res.json({ deleted: true });
  res.json({ user: { username: r.rows[0].username, customId: r.rows[0].customId, ...banPart(r.rows[0]) } });
}));
app.post('/api/appeal', requireUser, wrap(async (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 1000);
  if (text.length < 5) return bad(res, 'Please explain why the ban should be lifted.');
  const rs = await db.execute({ sql: "UPDATE users SET appeal = ?, appealAt = ?, appealStatus = 'pending' WHERE id = ? AND (bannedUntil = -1 OR bannedUntil > ?) AND (appealStatus IS NULL OR appealStatus = '')", args: [text, Date.now(), req.userId, Date.now()] });
  if (!rs.rowsAffected) return bad(res, 'You cannot send an appeal right now.', 409);
  res.json({ ok: true });
}));
app.post('/api/admin/ban', wrap(async (req, res) => {
  const name = String(req.body.username || ''), until = Number(req.body.until), reason = String(req.body.reason || '').slice(0, 300);
  if (!Number.isFinite(until) || (until !== -1 && until <= Date.now())) return bad(res, 'Bad ban length.');
  const victim = (await db.execute({ sql: "SELECT id, lastIp FROM users WHERE username = ? AND COALESCE(customId, '') != 'knqw'", args: [name] })).rows[0];
  if (!victim) return bad(res, 'Account not found.', 404);
  await db.execute({ sql: "UPDATE users SET bannedUntil = ?, bannedAt = ?, banReason = ?, appeal = NULL, appealAt = 0, appealStatus = NULL WHERE id = ?", args: [until, Date.now(), reason, Number(victim.id)] });
  let ipBanned = false;
  if (req.body.banIp && victim.lastIp) {
    await db.execute({ sql: 'INSERT INTO ip_bans (ip, bannedUntil, bannedAt, reason, username) VALUES (?, ?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET bannedUntil = excluded.bannedUntil, bannedAt = excluded.bannedAt, reason = excluded.reason, username = excluded.username', args: [victim.lastIp, until, Date.now(), reason, name] });
    ipBanned = true;
  }
  await db.execute({ sql: 'DELETE FROM sessions WHERE userId = ?', args: [Number(victim.id)] });     // banned people are logged out everywhere
  console.log(`ADMIN ${req.user} banned ${name} until ${until}`);
  auditReq(req, res, 'ban', name, `${until === -1 ? 'permanent' : 'until ' + new Date(until).toISOString()}${ipBanned ? ' + IP ban' : ''}: ${reason}`, 0);
  res.json({ ok: true });
}));
app.post('/api/admin/unban', wrap(async (req, res) => {
  const name = String(req.body.username || '');
  await db.execute({ sql: 'UPDATE users SET bannedUntil = 0, bannedAt = 0, banReason = NULL, appeal = NULL, appealAt = 0, appealStatus = NULL WHERE username = ?', args: [name] });
  const ips = await db.execute({ sql: 'DELETE FROM ip_bans WHERE username = ?', args: [name] });
  auditReq(req, res, 'unban', name, ips.rowsAffected ? 'also lifted the IP ban' : '', 0);
  res.json({ ok: true });
}));
app.get('/api/admin/appeals', wrap(async (req, res) => {
  const rs = await db.execute("SELECT username, displayName, bannedUntil, bannedAt, banReason, appeal, appealAt, appealStatus FROM users WHERE appealStatus IN ('pending','denied') AND appeal IS NOT NULL");
  res.json({ rows: rs.rows.map(r => ({ username: r.username, displayName: r.displayName, ...banPart(r) })) });
}));
app.post('/api/admin/appeal-status', wrap(async (req, res) => {
  const st = String(req.body.status || ''), name = String(req.body.username || '');
  if (!['pending', 'denied', ''].includes(st)) return bad(res, 'Bad request.');
  await db.execute({ sql: 'UPDATE users SET appealStatus = ? WHERE username = ?', args: [st || null, name] });
  auditReq(req, res, 'appeal-status', name, `appeal marked "${st || 'cleared'}"`, 0);
  res.json({ ok: true });
}));
app.post('/api/admin/middleman', wrap(async (req, res) => {
  const name = String(req.body.username || ''), on = !!req.body.value;
  const rs = await db.execute({ sql: 'UPDATE users SET isMiddleman = ? WHERE username = ?', args: [on ? 1 : 0, name] });
  if (!rs.rowsAffected) return bad(res, 'Account not found.', 404);
  auditReq(req, res, on ? 'middleman-grant' : 'middleman-revoke', name, on ? 'granted the middleman role' : 'removed the middleman role', 0);
  res.json({ ok: true });
}));
app.get('/api/admin/ip-banned', wrap(async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT username FROM ip_bans WHERE bannedUntil = -1 OR bannedUntil > ?', args: [Date.now()] });
  res.json({ names: rs.rows.map(r => r.username).filter(Boolean) });
}));
// the audit trail itself, newest first (read-only; there is deliberately no way to edit or delete rows)
app.get('/api/admin/audit', wrap(async (req, res) => {
  const limit = clampInt(req.query.limit, 1, 500, 200), before = clampInt(req.query.before, 0, Number.MAX_SAFE_INTEGER, 0) || Number.MAX_SAFE_INTEGER;
  const rs = await db.execute({ sql: 'SELECT id, admin, action, target, detail, amount, createdAt FROM admin_audit WHERE id < ? ORDER BY id DESC LIMIT ?', args: [before, limit] });
  res.json({ rows: rs.rows.map(r => ({ id: Number(r.id), admin: r.admin, action: r.action, target: r.target, detail: r.detail, amount: Number(r.amount) || 0, createdAt: Number(r.createdAt) })) });
}));

// ---------- admin: flags (same IP, VPN / proxy, duplicate listings) ----------
const normTxt = (v) => String(v == null ? '' : v).trim().toLowerCase().replace(/\s+/g, ' ');
app.get('/api/admin/flags', wrap(async (req, res) => {
  const now = Date.now();
  const urs = await db.execute('SELECT id, customId, username, displayName, joinedAt, bannedUntil FROM users');
  const byName = new Map(urs.rows.map(r => [String(r.username), r]));
  const skip = (n) => { const u = byName.get(n); return !u || isAdminId(u.customId); };      // deleted accounts and the admin are never flagged
  const brief = (n) => { const u = byName.get(n); const bu = Number(u.bannedUntil) || 0; return { username: n, displayName: u.displayName || n, joinedAt: Number(u.joinedAt) || 0, banned: bu === -1 || bu > now }; };

  const info = new Map((await db.execute('SELECT ip, proxy, hosting FROM ip_info')).rows.map(r => [String(r.ip), { proxy: Number(r.proxy) === 1, hosting: Number(r.hosting) === 1 }]));
  const perIp = new Map(), perUser = new Map(), unchecked = new Set();
  for (const r of (await db.execute('SELECT username, ip, lastSeen FROM user_ips ORDER BY lastSeen DESC')).rows) {
    const name = String(r.username), ip = String(r.ip);
    if (skip(name)) continue;
    if (!perIp.has(ip)) perIp.set(ip, []);
    if (!perIp.get(ip).includes(name)) perIp.get(ip).push(name);
    if (!perUser.has(name)) perUser.set(name, []);
    perUser.get(name).push({ ip, lastSeen: Number(r.lastSeen) || 0 });
    if (!isPrivateIp(ip) && !info.has(ip)) unchecked.add(ip);
  }
  const sameIp = [...perIp].filter(([ip, names]) => !isPrivateIp(ip) && names.length >= 2)
    .map(([ip, names]) => { const i = info.get(ip) || {}; return { ip, vpn: !!(i.proxy || i.hosting), users: names.map(brief) }; })
    .sort((a, b) => b.users.length - a.users.length);
  const vpn = [];
  for (const [name, list] of perUser) {
    const flagged = list.filter(x => { const i = info.get(x.ip); return i && (i.proxy || i.hosting); })
      .map(x => ({ ip: x.ip, kind: info.get(x.ip).proxy ? 'VPN / proxy' : 'Hosting / datacenter', lastSeen: x.lastSeen }));
    if (flagged.length) vpn.push({ ...brief(name), ips: flagged });
  }

  // the same seller listing the same thing more than once (name, game, type, price and items are equal)
  const nameOfId = new Map(urs.rows.map(r => [Number(r.id), String(r.username)]));
  const lrs = await db.execute('SELECT id, ownerId, name, game, tag, price, items, wanted FROM listings ORDER BY ownerId, id');
  const groups = new Map();
  for (const l of lrs.rows) {
    const owner = nameOfId.get(Number(l.ownerId));
    if (!owner || skip(owner)) continue;
    const items = parseJson(l.items, []), wanted = parseJson(l.wanted, null);
    const key = [Number(l.ownerId), normTxt(l.game), normTxt(l.tag), normTxt(l.name), String(l.price == null ? '' : l.price).replace(/,/g, '').trim(),
      JSON.stringify((Array.isArray(items) ? items : []).map(normTxt).sort()),
      wanted ? normTxt(wanted.game) + JSON.stringify((Array.isArray(wanted.items) ? wanted.items : []).map(normTxt).sort()) : ''].join('|');
    if (!groups.has(key)) groups.set(key, { owner, rows: [] });
    groups.get(key).rows.push(l);
  }
  const duplicates = [];
  for (const { owner, rows } of groups.values()) {
    if (rows.length < 2) continue;
    duplicates.push({ ...brief(owner), name: String(rows[0].name || ''), game: String(rows[0].game || ''), tag: String(rows[0].tag || ''), price: String(rows[0].price == null ? '' : rows[0].price), count: rows.length, ids: rows.map(x => Number(x.id)) });
  }
  duplicates.sort((a, b) => b.count - a.count);
  res.json({ sameIp, vpn, duplicates, ipsUnchecked: unchecked.size, vpnCheck: process.env.VPN_CHECK !== '0' });
}));

// permanently banned accounts disappear 30 days later (with everything that belongs to them), unless money is still held for them
const PERM_DELETE_MS = 30 * DAY;
async function purgePermanentlyBanned() {
  const rs = await db.execute({
    sql: `SELECT id, username FROM users WHERE bannedUntil = -1 AND bannedAt > 0 AND bannedAt <= ? AND COALESCE(customId, '') != 'knqw' AND COALESCE(heldBalanceCents, 0) = 0
          AND NOT EXISTS (SELECT 1 FROM deals WHERE (buyer = users.username OR seller = users.username) AND status IN ('paid','not_received','reported'))`,
    args: [Date.now() - PERM_DELETE_MS]
  });
  for (const r of rs.rows) {
    await deleteUserData(Number(r.id), String(r.username));
    auditRaw('system', 'purge-banned', String(r.username), 'permanently banned account removed after 30 days', 0);
  }
}

// ---------- periodic cleanup (every 15 minutes, and once shortly after start-up) ----------
// Expired logins, spent rate-limit rows, old lock-out counters, stale payment intents and other temporary rows would otherwise grow without limit.
async function runCleanup() {
  const now = Date.now();
  const steps = [
    ['sessions', () => db.execute({ sql: 'DELETE FROM sessions WHERE expiresAt < ?', args: [now] })],
    ['admin_sessions', () => db.execute({ sql: 'DELETE FROM admin_sessions WHERE expiresAt < ? OR maxExpiresAt < ?', args: [now, now] })],
    ['admin_sessions (orphans)', () => db.execute('DELETE FROM admin_sessions WHERE sessionHash NOT IN (SELECT id FROM sessions)')],
    ['rate_hits', () => db.execute({ sql: 'DELETE FROM rate_hits WHERE t < ?', args: [now - RATE_KEEP_MS] })],
    ['login_lockouts', () => db.execute({ sql: 'DELETE FROM login_lockouts WHERE lockedUntil < ? AND lastFailAt < ?', args: [now, now - LOCK_FORGET_MS] })],
    ['topup_intents', () => db.execute({ sql: "DELETE FROM topup_intents WHERE status != 'completed' AND createdAt < ?", args: [now - 30 * DAY] })],
    ['payment_events', () => db.execute({ sql: 'DELETE FROM payment_events WHERE receivedAt < ?', args: [now - 180 * DAY] })],
    ['signup_log', () => db.execute({ sql: 'DELETE FROM signup_log WHERE createdAt < ?', args: [now - 30 * DAY] })],
    ['ip_info', () => db.execute({ sql: 'DELETE FROM ip_info WHERE checkedAt < ?', args: [now - 30 * DAY] })],
    ['typing', () => db.execute({ sql: 'DELETE FROM typing WHERE ts < ?', args: [now - 60 * 1000] })],
    ['tickets', () => purgeTickets()],
    ['chats', () => purgeOldChats()],
    ['banned accounts', () => purgePermanentlyBanned()],
    ['spam_timeouts', () => db.execute({ sql: 'DELETE FROM spam_timeouts WHERE until < ? AND lastOffense < ?', args: [now, now - 2 * DAY] })]
  ];
  for (const [name, fn] of steps) {
    try { await fn(); } catch (e) { console.error(`cleanup step "${name}" failed:`, e.message); }
  }
}
setTimeout(() => { runCleanup().catch(() => {}); }, 20 * 1000).unref();
setInterval(() => { runCleanup().catch(() => {}); }, 15 * 60 * 1000);

// ---------- the site itself ----------
// The pages are read from disk ONCE, at start-up, and served from memory. Every inline <script> gets the CSP nonce of the response it is sent in
// (the markers are put in at start-up; the real nonce is swapped in per request), so no 'unsafe-inline' is needed for scripts and login.html works too.
const NONCE_MARK = '@@CSP_NONCE@@';
async function loadPage(file) {
  let html;
  try { html = await fs.readFile(path.join(__dirname, file), 'utf8'); } catch (e) { console.warn(`Page ${file} not found next to server.js - it will not be served from here (API-only deployment?)`); return null; }
  return html.replace(/<script(?![^>]*\bsrc\s*=)(?![^>]*\bnonce\s*=)([^>]*)>/gi, (tag, attrs) => `<script${attrs} nonce="${NONCE_MARK}">`);
}
const PAGE_MAIN = await loadPage('starfall.html');
const PAGE_LOGIN = await loadPage('login.html');
const servePage = (html) => (req, res, next) => {
  if (html == null) return next();
  res.setHeader('Cache-Control', 'no-store');
  res.type('html').send(html.split(NONCE_MARK).join(res.locals.cspNonce));
};
app.get('/', servePage(PAGE_MAIN));
app.get('/starfall.html', servePage(PAGE_MAIN));
app.get(['/login', '/login.html'], servePage(PAGE_LOGIN));
app.use(express.static(path.join(__dirname, 'public')));

// unknown API paths answer with JSON, never with an HTML page
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

// last resort: any error that reaches here becomes a clean JSON error (and is written to the log)
app.use((err, req, res, next) => {
  if (err && (err.type === 'entity.too.large' || err.status === 413)) return res.status(413).json({ error: 'That upload is too large.' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Bad request.' });
  console.error('ERROR on', req.method, req.path, '->', err && (err.stack || err.message || err));
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Server error. Try again.' });
});
(async () => {                       // one line in the log that says whether the database works
  try { await db.execute('SELECT COUNT(*) FROM users'); console.log('DB check: read OK'); } catch (e) { console.error('DB check: READ FAILED ->', e.message); }
  try { await db.execute('CREATE TABLE IF NOT EXISTS _healthcheck (t INTEGER)'); await db.execute('DELETE FROM _healthcheck'); console.log('DB check: write OK'); } catch (e) { console.error('DB check: WRITE FAILED ->', e.message, '(is TURSO_TOKEN a read-write token?)'); }
})();
const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Starfall backend listening on ' + port));
