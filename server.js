// Unique Trading backend - stage 1: signup, login, sessions
// Env vars (set them in Render -> Environment):
//   TURSO_URL    e.g. libsql://your-db.aws-eu-west-1.turso.io   (for local tests: file:local.db)
//   TURSO_TOKEN  a NEW token (rotate the old one - it was public in the HTML files)
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import path from 'node:path';
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

const app = express();
// Express 4 does not catch errors thrown inside async routes: one failed database call used to crash the whole server
// (Render then answers 502 without CORS headers, which the browser reports as a CORS error). Every handler is wrapped so errors become JSON 500s.
for (const m of ['get', 'post', 'delete']) {
  const orig = app[m].bind(app);
  app[m] = (p, ...handlers) => orig(p, ...handlers.map(h => (typeof h === 'function' && h.length < 4) ? (req, res, next) => Promise.resolve(h(req, res, next)).catch(next) : h));
}
process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e));
process.on('uncaughtException', (e) => console.error('uncaughtException:', e));
app.disable('x-powered-by');
app.set('trust proxy', 1);                 // Render sits behind a proxy: req.ip is the real visitor IP
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
// CORS: only your own site may call the API from a browser (extra origins: ALLOWED_ORIGINS=https://a.com,https://b.com)
const ALLOWED_ORIGINS = new Set(['https://unique-pdee.onrender.com', 'https://knqwx.github.io', ...String(process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)]);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) res.setHeader('Vary', 'Origin');
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '600');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(origin && !ALLOWED_ORIGINS.has(origin) ? 403 : 204);
  next();
});
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});

const DAY = 24 * 60 * 60 * 1000;
const SESSION_MS = 30 * DAY;
const ipOf = (req) => String(req.ip || '').replace(/^::ffff:/, '');

// ---------- tables ----------
async function init() {
  const run = async (sql) => { try { await db.execute(sql); } catch (e) { /* already exists */ } };
  await run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, customId TEXT, username TEXT UNIQUE, displayName TEXT, email TEXT, password TEXT, avatar TEXT, balance REAL DEFAULT 0.00, lastUsernameChange INTEGER, lastDisplayNameChange INTEGER, items TEXT, lastItemTime INTEGER, messages TEXT, card TEXT)`);
  for (const col of ['balance REAL DEFAULT 0.00', 'lastItemTime INTEGER', 'messages TEXT', 'card TEXT', 'isMiddleman INTEGER DEFAULT 0', 'lastSeen INTEGER', 'heldBalance REAL DEFAULT 0', 'bannedUntil INTEGER DEFAULT 0', 'bannedAt INTEGER DEFAULT 0', 'banReason TEXT', 'appeal TEXT', 'appealAt INTEGER DEFAULT 0', 'appealStatus TEXT', 'roblox TEXT']) await run(`ALTER TABLE users ADD COLUMN ${col}`);
  await run(`UPDATE users SET joinedAt = 0 WHERE joinedAt = 1`);
  await run(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, username TEXT, createdAt INTEGER, expiresAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS signup_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, createdAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS deals (id INTEGER PRIMARY KEY AUTOINCREMENT, buyer TEXT, seller TEXT, itemName TEXT, amount REAL, sellerAmount REAL, status TEXT, createdAt INTEGER, updatedAt INTEGER, reportedAt INTEGER, chatSnapshot TEXT, reportedBy TEXT, itemId TEXT)`);
  await run(`CREATE TABLE IF NOT EXISTS chat_clears (user TEXT, other TEXT, clearedAt INTEGER, PRIMARY KEY (user, other))`);
  await run(`CREATE TABLE IF NOT EXISTS typing (user TEXT, other TEXT, ts INTEGER, PRIMARY KEY (user, other))`);
  await run(`CREATE TABLE IF NOT EXISTS chat_images (id TEXT PRIMARY KEY, sender TEXT, receiver TEXT, data TEXT, createdAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, creator TEXT, partner TEXT, description TEXT, status TEXT DEFAULT 'open', claimedBy TEXT, createdAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS user_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, target TEXT, reporter TEXT, reason TEXT, details TEXT, createdAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS item_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, itemId TEXT, itemName TEXT, itemGame TEXT, seller TEXT, reporter TEXT, reason TEXT, details TEXT, createdAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS spam_timeouts (username TEXT PRIMARY KEY, level INTEGER DEFAULT 0, until INTEGER DEFAULT 0, lastOffense INTEGER DEFAULT 0)`);
  await run(`CREATE TABLE IF NOT EXISTS chat_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, owner TEXT, members TEXT, createdAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS group_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, groupId INTEGER, sender TEXT, text TEXT, timestamp INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS ratings (rater TEXT, target TEXT, stars INTEGER, createdAt INTEGER, PRIMARY KEY (rater, target))`);
  await run(`CREATE TABLE IF NOT EXISTS vouches (id INTEGER PRIMARY KEY AUTOINCREMENT, middleman TEXT, author TEXT, text TEXT, createdAt INTEGER, UNIQUE (middleman, author))`);
  await run(`CREATE TABLE IF NOT EXISTS ip_bans (ip TEXT PRIMARY KEY, bannedUntil INTEGER, bannedAt INTEGER, reason TEXT, username TEXT)`);
  await run(`ALTER TABLE users ADD COLUMN passwordHash TEXT`);
  await run(`ALTER TABLE users ADD COLUMN lastIp TEXT`);
  await run(`ALTER TABLE users ADD COLUMN joinedAt INTEGER`);
  await run(`CREATE TRIGGER IF NOT EXISTS users_set_joined AFTER INSERT ON users WHEN NEW.joinedAt IS NULL BEGIN UPDATE users SET joinedAt = CAST(strftime('%s','now') AS INTEGER) * 1000 WHERE id = NEW.id; END`);
  await run(`UPDATE users SET joinedAt = ${Date.now()} WHERE joinedAt IS NULL`);
  await run(`DELETE FROM sessions WHERE expiresAt < ${Date.now()}`);
}
await init();
setInterval(() => db.execute({ sql: 'DELETE FROM sessions WHERE expiresAt < ?', args: [Date.now()] }).catch(() => {}), 60 * 60 * 1000);

// ---------- tiny in-memory rate limiter ----------
const buckets = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const b = (buckets.get(key) || []).filter(t => now - t < windowMs);
  b.push(now);
  buckets.set(key, b);
  return b.length > max;
}
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
function checkUsername(name) {
  if (name.length < 3) return 'Username must be at least 3 characters long.';
  if (name.length > 24) return 'Username can be at most 24 characters long.';
  if (!/^[A-Za-z0-9_.-]+$/.test(name)) return 'Username can only contain letters, numbers, dots, dashes and underscores.';
  return '';
}
function passwordProblems(pw, username, email) {
  const l = pw.toLowerCase();
  const u = (username || '').toLowerCase();
  const local = ((email || '').split('@')[0] || '').toLowerCase();
  const bad = [];
  if (pw.length < 10) bad.push('at least 10 characters');
  if (pw.length > 200) bad.push('at most 200 characters');
  if (!/[a-z]/.test(pw)) bad.push('a lowercase letter');
  if (!/[A-Z]/.test(pw)) bad.push('an uppercase letter');
  if (!/[0-9]/.test(pw)) bad.push('a number');
  if (!/[^A-Za-z0-9]/.test(pw)) bad.push('a symbol');
  if ((u.length >= 3 && l.includes(u)) || (local.length >= 3 && l.includes(local))) bad.push('no part of your name or email');
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

// ---------- sessions ----------
// Cookies are SameSite=None; Secure on Render, which browsers need when the pages are on another site (github.io).
const IS_SECURE = process.env.NODE_ENV === 'production' || process.env.RENDER === 'true';
const CROSS_SITE = IS_SECURE && process.env.CROSS_SITE_COOKIES !== '0';   // on Render: on by default because the pages live on github.io; set CROSS_SITE_COOKIES=0 to turn off
const cookieOpts = (maxAge) => ({ httpOnly: true, secure: CROSS_SITE ? true : IS_SECURE, sameSite: CROSS_SITE ? 'none' : 'lax', maxAge, path: '/' });
async function startSession(res, username) {
  const sid = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  await db.execute({ sql: 'INSERT INTO sessions (id, username, createdAt, expiresAt) VALUES (?, ?, ?, ?)', args: [sid, username, now, now + SESSION_MS] });
  res.cookie('sid', sid, cookieOpts(SESSION_MS));
}
export async function requireUser(req, res, next) {      // use this on every future endpoint
  try {
    const r = await db.execute({ sql: 'SELECT username FROM sessions WHERE id = ? AND expiresAt > ?', args: [String(req.cookies.sid || ''), Date.now()] });
    if (!r.rows.length) return res.status(401).json({ error: 'Please log in.' });
    req.user = String(r.rows[0].username);
    next();
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
}
const safeEqual = (a, b) => {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
};

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
  const r = await db.execute({ sql: 'SELECT username, customId FROM users WHERE username = ?', args: [req.user] });
  if (!r.rows.length) return res.status(401).json({ error: 'Please log in.' });
  res.json({ username: r.rows[0].username, isAdmin: String(r.rows[0].customId || '') === 'knqw' });
});

app.get('/api/check-username', async (req, res) => {

  if (limited('chk:' + ipOf(req), 120, 60 * 1000)) return res.status(429).json({ error: 'Too many requests' });

  const name = String(req.query.name || '').trim();

  const err = checkUsername(name);

  if (err) return res.json({ ok: false, message: err });

  const r = await db.execute({ sql: 'SELECT 1 FROM users WHERE username = ? LIMIT 1', args: [name] });

  res.json(r.rows.length ? { ok: false, message: 'This username is already taken.' } : { ok: true, message: 'Username is available.' });

});



app.get('/api/check-email', async (req, res) => {
  if (limited('chk:' + ipOf(req), 120, 60 * 1000)) return res.status(429).json({ error: 'Too many requests' });
  const email = String(req.query.email || '').trim().toLowerCase();
  const err = await checkEmail(email);
  if (err) return res.json({ ok: false, message: err });
  const r = await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(email) = ? LIMIT 1', args: [email] });
  res.json(r.rows.length ? { ok: false, message: 'This email is already registered.' } : { ok: true, message: 'Email is available.' });
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
    const pBad = passwordProblems(password, username, email);
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

    if ((await db.execute({ sql: 'SELECT 1 FROM users WHERE username = ? LIMIT 1', args: [username] })).rows.length) return fail('This username is already taken.');
    if ((await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(email) = ? LIMIT 1', args: [email] })).rows.length) return fail('This email is already registered.');

    const cnt = await db.execute('SELECT COUNT(*) AS cnt FROM users');
    const customId = String(Number(cnt.rows[0].cnt || 0) + 1);
    const hash = await bcrypt.hash(password, 12);
    try {
      // NOTE: the old "password" column is left empty for new accounts. The main site still reads it until it is moved to the backend too.
      await db.execute({
        sql: 'INSERT INTO users (customId, username, displayName, email, password, passwordHash, items, lastIp, joinedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        args: [customId, username, username, email, '', hash, JSON.stringify([]), ip || null, now]
      });
    } catch (e) {
      if (String(e.message || e).toUpperCase().includes('UNIQUE')) return fail('This username is already taken.');
      throw e;
    }
    if (ip) await db.execute({ sql: 'INSERT INTO signup_log (ip, createdAt) VALUES (?, ?)', args: [ip, now] });
    res.cookie('ut_su', String(now), cookieOpts(DAY));
    await startSession(res, username);
    res.json({ username });
  } catch (e) {
    console.error('signup error:', e);
    fail('Server error during registration. Try again.', 500);
  }
});

app.post('/api/login', async (req, res) => {
  const fail = (message, code = 401) => res.status(code).json({ error: message });
  try {
    const ip = ipOf(req);
    if (limited('login:' + ip, 20, 15 * 60 * 1000)) return fail('Too many attempts. Try again in a few minutes.', 429);
    const id = String(req.body.id || '').trim();
    const password = String(req.body.password || '');
    if (!id || !password) return fail('Please fill in all fields.', 400);

    const rs = await db.execute({ sql: 'SELECT * FROM users WHERE username = ? OR lower(email) = lower(?)', args: [id, id] });
    if (!rs.rows.length) return fail('Account with this username or email does not exist.');
    const u = rs.rows[0];

    let ok = false;
    if (u.passwordHash) ok = await bcrypt.compare(password, String(u.passwordHash));
    // transition: the main site still stores/changes the old plain "password" column, so accept it too and keep the hash in sync
    if (!ok && u.password && safeEqual(u.password, password)) {
      ok = true;
      await db.execute({ sql: "UPDATE users SET passwordHash = ?, password = '' WHERE username = ?", args: [await bcrypt.hash(password, 12), u.username] });   // plaintext is wiped as soon as the hash exists
    }
    if (!ok) return fail('Incorrect password. Please try again.');

    if (String(u.customId || '') !== 'knqw') {
      const ban = await activeIpBan(ip);
      if (ban) return fail(ipBanText(ban), 403);
    }
    if (ip) { try { await db.execute({ sql: 'UPDATE users SET lastIp = ? WHERE username = ?', args: [ip, u.username] }); } catch (e) {} }
    await startSession(res, String(u.username));
    res.json({ username: String(u.username) });
  } catch (e) {
    console.error('login error:', e);
    fail('Server error. Try again later.', 500);
  }
});

app.post('/api/logout', async (req, res) => {
  try { await db.execute({ sql: 'DELETE FROM sessions WHERE id = ?', args: [String(req.cookies.sid || '')] }); } catch (e) {}
  res.clearCookie('sid', { ...cookieOpts(0), maxAge: undefined });
  res.json({ ok: true });
});

// ======================================================================
// Stage 2: password change, wallet, deals, admin money tools
// Every route below needs a logged-in session; money logic runs ONLY here.
// ======================================================================
const SELLER_SHARE = 0.9;
const MIN_DEAL = 0.01, MAX_DEAL = 1000000;
const MIN_TOPUP = 1, MAX_TOPUP = 10000;
const round2 = (n) => Math.round(Number(n) * 100) / 100;
const parseMoney = (v) => { const n = typeof v === 'number' ? v : parseFloat(String(v)); return Number.isFinite(n) ? round2(n) : NaN; };

async function requireAdmin(req, res, next) {
  try {
    const r = await db.execute({ sql: 'SELECT customId FROM users WHERE username = ?', args: [req.user] });
    if (!r.rows.length || String(r.rows[0].customId || '') !== 'knqw') return res.status(403).json({ error: 'Only the admin can do this.' });
    next();
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
}
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
    const rs = await db.execute({ sql: 'SELECT username, email, password, passwordHash FROM users WHERE username = ?', args: [req.user] });
    if (!rs.rows.length) return res.status(401).json({ error: 'Please log in.' });
    const u = rs.rows[0];
    let ok = false;
    if (u.passwordHash) ok = await bcrypt.compare(cur, String(u.passwordHash));
    if (!ok && u.password && safeEqual(u.password, cur)) ok = true;
    if (!ok) return res.status(403).json({ error: 'Current password is incorrect.' });
    const bad = passwordProblems(next, String(u.username), String(u.email || ''));
    if (bad.length) return res.status(400).json({ error: 'Your new password is too weak. It needs: ' + bad.join(', ') + '.' });
    const hash = await bcrypt.hash(next, 12);
    // the legacy plaintext column is wiped; every other device is logged out
    await db.execute({ sql: "UPDATE users SET passwordHash = ?, password = '' WHERE username = ?", args: [hash, req.user] });
    await db.execute({ sql: 'DELETE FROM sessions WHERE username = ? AND id != ?', args: [req.user, String(req.cookies.sid || '')] });
    res.json({ ok: true });
  } catch (e) { console.error('change-password error:', e); res.status(500).json({ error: 'Server error. Try again.' }); }
});

// ---------- wallet ----------
app.get('/api/wallet', requireUser, async (req, res) => {
  const r = await db.execute({ sql: 'SELECT balance, heldBalance FROM users WHERE username = ?', args: [req.user] });
  if (!r.rows.length) return res.status(401).json({ error: 'Please log in.' });
  res.json({ balance: Number(r.rows[0].balance) || 0, held: Number(r.rows[0].heldBalance) || 0 });
});

// Top-up is a DEMO (free money). It only works while PAYMENT_DEMO_MODE=1 is set in Render. Remove that variable before real launch.
app.post('/api/wallet/topup', requireUser, async (req, res) => {
  try {
    if (process.env.PAYMENT_DEMO_MODE !== '1') return res.status(403).json({ error: 'Payment provider is not connected.' });
    if (moneyLimit(req, res, 'topup', 20, 60 * 60 * 1000)) return;
    const amount = parseMoney(req.body.amount);
    if (!(amount >= MIN_TOPUP)) return res.status(400).json({ error: `Minimum purchase is $${MIN_TOPUP}.` });
    if (amount > MAX_TOPUP) return res.status(400).json({ error: `Maximum purchase is $${MAX_TOPUP}.` });
    const me = await db.execute({ sql: 'SELECT card FROM users WHERE username = ?', args: [req.user] });
    if (!me.rows.length) return res.status(401).json({ error: 'Please log in.' });
    if (!me.rows[0].card) return res.status(400).json({ error: 'Link a bank card in Settings first.' });
    await db.execute({ sql: 'UPDATE users SET balance = COALESCE(balance, 0) + ? WHERE username = ?', args: [amount, req.user] });
    const r = await db.execute({ sql: 'SELECT balance FROM users WHERE username = ?', args: [req.user] });
    res.json({ balance: Number(r.rows[0].balance) || 0 });
  } catch (e) { console.error('topup error:', e); res.status(500).json({ error: 'Purchase failed. Try again.' }); }
});

// admin only: add or subtract balance for any user (never goes below $0)
app.post('/api/admin/adjust', requireUser, requireAdmin, async (req, res) => {
  try {
    const target = String(req.body.username || '');
    const delta = parseMoney(req.body.delta);
    if (!target) return res.status(400).json({ error: 'Select a user first.' });
    if (!Number.isFinite(delta) || delta === 0 || Math.abs(delta) > 1000000) return res.status(400).json({ error: 'Enter a valid amount.' });
    const rs = await db.execute({ sql: 'UPDATE users SET balance = MAX(0, COALESCE(balance, 0) + ?) WHERE username = ?', args: [delta, target] });
    if (!rs.rowsAffected) return res.status(404).json({ error: 'User not found.' });
    const r = await db.execute({ sql: 'SELECT balance FROM users WHERE username = ?', args: [target] });
    console.log(`ADMIN ${req.user} adjusted ${target} by ${delta}`);
    res.json({ balance: Number(r.rows[0].balance) || 0 });
  } catch (e) { console.error('adjust error:', e); res.status(500).json({ error: 'Failed to update balance.' }); }
});

app.get('/api/admin/users', requireUser, requireAdmin, async (req, res) => {
  const rs = await db.execute('SELECT customId, username, displayName, balance, heldBalance, bannedUntil FROM users ORDER BY username');
  res.json({ users: rs.rows.map(r => ({
    customId: r.customId, username: r.username, displayName: r.displayName,
    balance: Number(r.balance) || 0, held: Number(r.heldBalance) || 0, bannedUntil: Number(r.bannedUntil) || 0
  })) });
});

// ---------- deals ----------
const mapDeal = (r) => ({
  id: Number(r.id), buyer: r.buyer, seller: r.seller, itemName: r.itemName || '',
  amount: Number(r.amount) || 0, sellerAmount: Number(r.sellerAmount) || 0, status: r.status,
  createdAt: Number(r.createdAt) || 0, updatedAt: Number(r.updatedAt) || 0,
  reportedAt: Number(r.reportedAt) || 0, chatSnapshot: r.chatSnapshot || null, reportedBy: r.reportedBy || '',
  itemId: r.itemId ? String(r.itemId) : ''
});
const dealId = (req) => { const n = Number(req.params.id); return Number.isInteger(n) && n > 0 ? n : 0; };
async function loadDeal(q, id) {
  const rs = await q.execute({ sql: 'SELECT * FROM deals WHERE id = ?', args: [id] });
  return rs.rows.length ? mapDeal(rs.rows[0]) : null;
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
app.get('/api/deals/sig', requireUser, async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT COUNT(*) AS c, COALESCE(SUM(updatedAt), 0) AS s FROM deals WHERE buyer = ? OR seller = ?', args: [req.user, req.user] });
  res.json({ sig: `${Number(rs.rows[0].c)}:${Number(rs.rows[0].s)}` });
});

// one deal (participants or admin). Only the admin receives the chat snapshot.
app.get('/api/deals/:id', requireUser, async (req, res) => {
  const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
  const d = await loadDeal(db, id);
  if (!d) return res.status(404).json({ error: 'Deal not found.' });
  const a = await db.execute({ sql: 'SELECT customId FROM users WHERE username = ?', args: [req.user] });
  const isAdmin = a.rows.length && String(a.rows[0].customId || '') === 'knqw';
  if (!isAdmin && d.buyer !== req.user && d.seller !== req.user) return res.status(404).json({ error: 'Deal not found.' });
  if (!isAdmin) d.chatSnapshot = null;
  res.json({ deal: d });
});

// seller asks the buyer for payment
app.post('/api/deals', requireUser, async (req, res) => {
  try {
    if (moneyLimit(req, res, 'deal-new', 30, 60 * 60 * 1000)) return;
    const buyer = String(req.body.buyer || '');
    const amount = parseMoney(req.body.amount);
    const itemName = String(req.body.itemName || '').slice(0, 200);
    const itemId = req.body.itemId ? String(req.body.itemId).slice(0, 64) : '';
    if (!buyer || buyer === req.user) return res.status(400).json({ error: 'Choose another user.' });
    if (!(amount >= MIN_DEAL) || amount > MAX_DEAL) return res.status(400).json({ error: 'Enter a valid amount.' });
    if (!(await db.execute({ sql: 'SELECT 1 FROM users WHERE username = ?', args: [buyer] })).rows.length) return res.status(404).json({ error: 'User not found.' });
    const dup = await db.execute({
      sql: "SELECT id FROM deals WHERE seller = ? AND buyer = ? AND COALESCE(itemId, '') = ? AND status = 'requested'",
      args: [req.user, buyer, itemId]
    });
    if (dup.rows.length) return res.status(409).json({ error: 'You already have a pending payment request in this chat.' });
    const now = Date.now();
    await db.execute({
      sql: "INSERT INTO deals (buyer, seller, itemName, amount, sellerAmount, status, createdAt, updatedAt, itemId) VALUES (?, ?, ?, ?, ?, 'requested', ?, ?, ?)",
      args: [buyer, req.user, itemName, amount, round2(amount * SELLER_SHARE), now, now, itemId || null]
    });
    res.json({ ok: true });
  } catch (e) { console.error('deal create error:', e); res.status(500).json({ error: 'Server error. Try again.' }); }
});

// buyer pays: money leaves the buyer and sits on hold for the seller
app.post('/api/deals/:id/pay', requireUser, async (req, res) => {
  const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
  if (moneyLimit(req, res, 'deal-act', 60, 60 * 1000)) return;
  const out = await inTx(res, async (tx) => {
    const d = await loadDeal(tx, id);
    if (!d || d.buyer !== req.user) throw new Abort('This request is no longer available.');
    const claim = await tx.execute({ sql: "UPDATE deals SET status = 'paid', updatedAt = ? WHERE id = ? AND status = 'requested'", args: [Date.now(), id] });
    if (!claim.rowsAffected) throw new Abort('This request is no longer available.');
    const debit = await tx.execute({ sql: 'UPDATE users SET balance = balance - ? WHERE username = ? AND COALESCE(balance, 0) >= ?', args: [d.amount, req.user, d.amount] });
    if (!debit.rowsAffected) throw new Abort('Not enough balance.');
    const credit = await tx.execute({ sql: 'UPDATE users SET heldBalance = COALESCE(heldBalance, 0) + ? WHERE username = ?', args: [d.sellerAmount, d.seller] });
    if (!credit.rowsAffected) throw new Abort('Seller account not found. You were not charged.');
    const r = await tx.execute({ sql: 'SELECT balance FROM users WHERE username = ?', args: [req.user] });
    return Number(r.rows[0].balance) || 0;
  });
  if (out !== undefined) res.json({ balance: out });
});

// buyer confirms delivery: held money goes to the seller's balance
app.post('/api/deals/:id/complete', requireUser, async (req, res) => {
  const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
  if (moneyLimit(req, res, 'deal-act', 60, 60 * 1000)) return;
  const out = await inTx(res, async (tx) => {
    const d = await loadDeal(tx, id);
    if (!d || d.buyer !== req.user) throw new Abort('This deal can no longer be confirmed.');
    const claim = await tx.execute({ sql: "UPDATE deals SET status = 'completed', updatedAt = ? WHERE id = ? AND status IN ('paid', 'not_received')", args: [Date.now(), id] });
    if (!claim.rowsAffected) throw new Abort('This deal can no longer be confirmed.');
    await tx.execute({
      sql: 'UPDATE users SET heldBalance = MAX(0, COALESCE(heldBalance, 0) - ?), balance = COALESCE(balance, 0) + ? WHERE username = ?',
      args: [d.sellerAmount, d.sellerAmount, d.seller]
    });
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
    let snap = Array.isArray(req.body.snapshot) ? req.body.snapshot.slice(-500) : [];
    snap = snap.map(m => ({
      sender: String(m && m.sender || '').slice(0, 64), receiver: String(m && m.receiver || '').slice(0, 64),
      text: String(m && m.text || '').slice(0, 2000), timestamp: Number(m && m.timestamp) || 0
    }));
    const now = Date.now();
    const rs = await db.execute({
      sql: "UPDATE deals SET status = 'reported', reportedAt = ?, updatedAt = ?, chatSnapshot = ?, reportedBy = ? WHERE id = ? AND status = 'not_received' AND (buyer = ? OR seller = ?)",
      args: [now, now, JSON.stringify(snap), req.user, id, req.user, req.user]
    });
    if (!rs.rowsAffected) return res.status(409).json({ error: 'This deal was already updated.' });
    res.json({ ok: true });
  } catch (e) { console.error('report error:', e); res.status(500).json({ error: 'Server error. Try again.' }); }
});

// ---------- admin: money overview + resolving held deals ----------
app.get('/api/admin/deals', requireUser, requireAdmin, async (req, res) => {
  const status = String(req.query.status || '');
  const rs = status === 'reported'
    ? await db.execute("SELECT * FROM deals WHERE status = 'reported' ORDER BY reportedAt DESC")
    : status === 'held'
      ? await db.execute("SELECT * FROM deals WHERE status IN ('paid','not_received','reported') ORDER BY updatedAt DESC")
      : await db.execute("SELECT * FROM deals ORDER BY createdAt DESC LIMIT 500");
  res.json({ deals: rs.rows.map(mapDeal) });
});

app.get('/api/admin/deals/:id', requireUser, requireAdmin, async (req, res) => {
  const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
  const d = await loadDeal(db, id);
  if (!d) return res.status(404).json({ error: 'Deal not found.' });
  res.json({ deal: d });
});

app.post('/api/admin/deals/:id/resolve', requireUser, requireAdmin, async (req, res) => {
  const id = dealId(req); if (!id) return res.status(400).json({ error: 'Bad request.' });
  const mode = String(req.body.mode || '');
  if (mode !== 'refund' && mode !== 'pay') return res.status(400).json({ error: 'Bad request.' });
  const out = await inTx(res, async (tx) => {
    const d = await loadDeal(tx, id);
    if (!d || !['paid', 'not_received', 'reported'].includes(d.status)) throw new Abort('This transaction was already handled.');
    const finalStatus = mode === 'refund' ? 'refunded' : 'released';
    const claim = await tx.execute({ sql: 'UPDATE deals SET status = ?, updatedAt = ? WHERE id = ? AND status = ?', args: [finalStatus, Date.now(), id, d.status] });
    if (!claim.rowsAffected) throw new Abort('This transaction was already handled.');
    if (mode === 'refund') {
      const credit = await tx.execute({ sql: 'UPDATE users SET balance = COALESCE(balance, 0) + ? WHERE username = ?', args: [d.amount, d.buyer] });
      if (!credit.rowsAffected) throw new Abort('The buyer account no longer exists.');
      await tx.execute({ sql: 'UPDATE users SET heldBalance = MAX(0, COALESCE(heldBalance, 0) - ?) WHERE username = ?', args: [d.sellerAmount, d.seller] });
    } else {
      const rel = await tx.execute({
        sql: 'UPDATE users SET heldBalance = MAX(0, COALESCE(heldBalance, 0) - ?), balance = COALESCE(balance, 0) + ? WHERE username = ?',
        args: [d.sellerAmount, d.sellerAmount, d.seller]
      });
      if (!rel.rowsAffected) throw new Abort('The seller account no longer exists.');
    }
    console.log(`ADMIN ${req.user} resolved deal ${id} as ${finalStatus}`);
    return { status: finalStatus, amount: d.amount, sellerAmount: d.sellerAmount, buyer: d.buyer, seller: d.seller };
  });
  if (out) res.json(out);
});

// ======================================================================
// Stage 3: users directory, profile, items, chat
// The browser never reads other people's private data or rewrites whole user rows any more.
// ======================================================================
const THREAD_SEP = '~i~';
const isAdminName = async (name) => {
  const r = await db.execute({ sql: 'SELECT customId FROM users WHERE username = ?', args: [name] });
  return !!r.rows.length && String(r.rows[0].customId || '') === 'knqw';
};
const parseJson = (s, fallback) => { try { const v = JSON.parse(s); return v == null ? fallback : v; } catch (e) { return fallback; } };
const banPart = (r) => ({
  bannedUntil: Number(r.bannedUntil) || 0, bannedAt: Number(r.bannedAt) || 0, banReason: r.banReason || '',
  appeal: r.appeal || '', appealAt: Number(r.appealAt) || 0, appealStatus: r.appealStatus || ''
});
// what everybody may see about everybody
const publicUser = (r) => ({
  customId: r.customId, username: r.username, displayName: r.displayName || r.username, avatar: r.avatar || null,
  items: parseJson(r.items, []), roblox: r.roblox || '', isMiddleman: Number(r.isMiddleman) === 1,
  lastSeen: Number(r.lastSeen) || 0, joinedAt: Number(r.joinedAt) || 0, ...banPart(r)
});
// what only the owner sees (never the password or its hash)
const privateUser = (r) => ({
  ...publicUser(r), email: r.email || '', card: r.card || null, balance: Number(r.balance) || 0,
  heldBalance: Number(r.heldBalance) || 0, lastUsernameChange: r.lastUsernameChange || null,
  lastDisplayNameChange: r.lastDisplayNameChange || null, lastItemTime: Number(r.lastItemTime) || 0,
  messages: parseJson(r.messages, [])
});
// extra columns for the admin panel (no password, no hash)
const adminUser = (r) => ({
  ...publicUser(r), email: r.email || '', balance: Number(r.balance) || 0, heldBalance: Number(r.heldBalance) || 0,
  lastIp: r.lastIp || '', lastItemTime: Number(r.lastItemTime) || 0
});

app.get('/api/users', requireUser, async (req, res) => {
  const admin = await isAdminName(req.user);
  const rs = await db.execute('SELECT * FROM users');
  res.json({ users: rs.rows.map(admin ? adminUser : publicUser) });
});

app.get('/api/users/presence', requireUser, async (req, res) => {
  const rs = await db.execute('SELECT username, lastSeen FROM users');
  res.json({ users: rs.rows.map(r => ({ username: r.username, lastSeen: Number(r.lastSeen) || 0 })) });
});

app.get('/api/user/:name', requireUser, async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT * FROM users WHERE username = ?', args: [String(req.params.name)] });
  if (!rs.rows.length) return res.status(404).json({ error: 'Account not found.' });
  res.json({ user: (await isAdminName(req.user)) ? adminUser(rs.rows[0]) : publicUser(rs.rows[0]) });
});

app.get('/api/profile', requireUser, async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT * FROM users WHERE username = ?', args: [req.user] });
  if (!rs.rows.length) return res.status(401).json({ error: 'Please log in.' });
  res.json({ user: privateUser(rs.rows[0]) });
});

app.post('/api/heartbeat', requireUser, async (req, res) => {
  await db.execute({ sql: 'UPDATE users SET lastSeen = ? WHERE username = ?', args: [Date.now(), req.user] });
  res.json({ ok: true });
});

// partial update of my own profile: only the fields that are sent are touched
app.post('/api/profile', requireUser, async (req, res) => {
  try {
    if (limited('prof:' + req.user, 30, 60 * 1000)) return res.status(429).json({ error: 'Too many requests.' });
    const b = req.body || {};
    const sets = [], args = [];
    if ('displayName' in b) {
      const v = String(b.displayName || '').trim().slice(0, 40);
      sets.push('displayName = ?'); args.push(v || req.user);
      sets.push('lastDisplayNameChange = ?'); args.push(Date.now());
    }
    if ('avatar' in b) {
      const v = b.avatar == null ? null : String(b.avatar);
      if (v !== null && (!/^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(v) || v.length > 700000)) return res.status(400).json({ error: 'Invalid picture.' });
      sets.push('avatar = ?'); args.push(v);
    }
    if ('email' in b) {
      const v = String(b.email || '').trim().toLowerCase();
      const cur = await db.execute({ sql: 'SELECT email FROM users WHERE username = ?', args: [req.user] });
      if (v !== String(cur.rows[0].email || '').toLowerCase()) {
        const err = await checkEmail(v); if (err) return res.status(400).json({ error: err });
        if ((await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(email) = ? AND username != ?', args: [v, req.user] })).rows.length) return res.status(400).json({ error: 'This email is already registered.' });
      }
      sets.push('email = ?'); args.push(v);
    }
    if ('card' in b) {
      const v = b.card == null ? null : String(b.card).slice(0, 40);
      if (v !== null && !/^[•*\d\s-]+$/.test(v)) return res.status(400).json({ error: 'Invalid card label.' });   // only the masked label is kept, never real card data
      sets.push('card = ?'); args.push(v);
    }
    if ('roblox' in b) {
      const v = b.roblox == null || b.roblox === '' ? null : String(b.roblox).trim().slice(0, 40);
      sets.push('roblox = ?'); args.push(v);
    }
    if (!sets.length) return res.json({ ok: true });
    args.push(req.user);
    await db.execute({ sql: `UPDATE users SET ${sets.join(', ')} WHERE username = ?`, args });
    res.json({ ok: true });
  } catch (e) { console.error('profile error:', e); res.status(500).json({ error: 'Server error. Try again.' }); }
});

// change my username; the row (balance, hash, items, messages...) stays, everything pointing at the name follows
app.post('/api/profile/rename', requireUser, async (req, res) => {
  try {
    if (limited('rename:' + req.user, 5, 60 * 60 * 1000)) return res.status(429).json({ error: 'Too many requests.' });
    const nu = String(req.body.username || '').trim();
    const err = checkUsername(nu); if (err) return res.status(400).json({ error: err });
    if (nu === req.user) return res.json({ username: nu });
    const out = await inTx(res, async (tx) => {
      if ((await tx.execute({ sql: 'SELECT 1 FROM users WHERE username = ?', args: [nu] })).rows.length) throw new Abort('Username is already taken');
      await tx.execute({ sql: 'UPDATE users SET username = ?, lastUsernameChange = ? WHERE username = ?', args: [nu, Date.now(), req.user] });
      await tx.execute({ sql: 'UPDATE sessions SET username = ? WHERE username = ?', args: [nu, req.user] });
      await tx.execute({ sql: 'UPDATE deals SET buyer = ? WHERE buyer = ?', args: [nu, req.user] });
      await tx.execute({ sql: 'UPDATE deals SET seller = ? WHERE seller = ?', args: [nu, req.user] });
      // messages of other people that mention me, and my own item/message copies
      const rows = await tx.execute({ sql: 'SELECT username, messages, items FROM users WHERE (messages IS NOT NULL AND messages LIKE ?) OR username = ?', args: [`%${req.user}%`, nu] });
      for (const r of rows.rows) {
        let changed = false;
        const msgs = parseJson(r.messages, []);
        msgs.forEach(m => { if (m.sender === req.user) { m.sender = nu; changed = true; } if (m.receiver === req.user) { m.receiver = nu; changed = true; } });
        let items = parseJson(r.items, []);
        if (r.username === nu) items.forEach(i => { if (i.sellerUsername) { i.sellerUsername = nu; changed = true; } if (i.owner) { i.owner = nu; changed = true; } });
        if (changed) await tx.execute({ sql: 'UPDATE users SET messages = ?, items = ? WHERE username = ?', args: [JSON.stringify(msgs), JSON.stringify(items), r.username] });
      }
      for (const [t, cols] of [['chat_clears', ['user']], ['ratings', ['rater', 'target']], ['vouches', ['author', 'middleman']], ['tickets', ['creator', 'partner']], ['chat_images', ['sender', 'receiver']]]) {
        for (const c of cols) { try { await tx.execute({ sql: `UPDATE ${t} SET ${c} = ? WHERE ${c} = ?`, args: [nu, req.user] }); } catch (e) { /* table may not exist yet */ } }
      }
      return nu;
    });
    if (out) res.json({ username: out });
  } catch (e) { console.error('rename error:', e); res.status(500).json({ error: 'Server error. Try again.' }); }
});

// ---------- items (stored on the owner's row) ----------
const LISTING_COOLDOWN = 10 * 60 * 1000;
function cleanItem(b) {
  const tag = ['selling', 'specific', 'any'].includes(String(b.tag)) ? String(b.tag) : null;
  const stock = Number(b.stock);
  const photo = b.photo == null || b.photo === '' ? null : String(b.photo);
  if (photo && (!/^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(photo) || photo.length > 900000)) throw new Abort('Invalid picture.', 400);
  const price = b.price == null ? '' : String(b.price).slice(0, 20);
  const list = (arr) => (Array.isArray(arr) ? arr.slice(0, 60).map(x => String(x).slice(0, 80)) : []);
  const wanted = b.wanted && typeof b.wanted === 'object' ? { game: String(b.wanted.game || '').slice(0, 60), items: list(b.wanted.items) } : null;
  const name = String(b.name || '').trim().slice(0, 80);
  if (!name) throw new Abort('Please enter a name.', 400);
  if (!tag) throw new Abort('Invalid listing type.', 400);
  if (tag === 'selling' && !(parseFloat(price) > 0)) throw new Abort('Please enter a price.', 400);
  if (!Number.isInteger(stock) || stock < 0 || stock > 99999) throw new Abort('Stock must be a whole number from 0 to 99999.', 400);
  return {
    name, description: String(b.description || '').slice(0, 2000), tag, price, photo,
    game: String(b.game || '').slice(0, 60), category: String(b.category || '').slice(0, 60),
    items: list(b.items), wanted, stock
  };
}
app.post('/api/items', requireUser, async (req, res) => {
  const out = await inTx(res, async (tx) => {
    const rs = await tx.execute({ sql: 'SELECT customId, items, lastItemTime, bannedUntil FROM users WHERE username = ?', args: [req.user] });
    if (!rs.rows.length) throw new Abort('Please log in.', 401);
    const u = rs.rows[0];
    const until = Number(u.bannedUntil) || 0;
    if (until === -1 || until > Date.now()) throw new Abort('Your account is banned.', 403);
    const data = cleanItem(req.body || {});
    const items = parseJson(u.items, []);
    const editId = req.body.id != null ? Number(req.body.id) : null;
    if (editId) {
      const i = items.findIndex(x => Number(x.id) === editId);
      if (i < 0) throw new Abort('Item not found.', 404);
      items[i] = { ...items[i], ...data };
      await tx.execute({ sql: 'UPDATE users SET items = ? WHERE username = ?', args: [JSON.stringify(items), req.user] });
      return { id: editId };
    }
    if (String(u.customId || '') !== 'knqw') {
      const wait = (Number(u.lastItemTime) || 0) + LISTING_COOLDOWN - Date.now();
      if (wait > 0) throw new Abort(`You can list another item in ${Math.ceil(wait / 60000)} min.`, 429);
      if (items.length >= 200) throw new Abort('You have too many listings.', 400);
    }
    let id = Date.now(); while (items.some(x => Number(x.id) === id)) id++;
    items.push({ id, ...data });
    await tx.execute({ sql: 'UPDATE users SET items = ?, lastItemTime = ? WHERE username = ?', args: [JSON.stringify(items), Date.now(), req.user] });
    return { id };
  });
  if (out) res.json(out);
});
app.delete('/api/items/:id', requireUser, async (req, res) => {
  const out = await inTx(res, async (tx) => {
    const rs = await tx.execute({ sql: 'SELECT items FROM users WHERE username = ?', args: [req.user] });
    const items = parseJson(rs.rows[0] && rs.rows[0].items, []);
    const left = items.filter(x => Number(x.id) !== Number(req.params.id));
    if (left.length === items.length) throw new Abort('Item not found.', 404);
    await tx.execute({ sql: 'UPDATE users SET items = ? WHERE username = ?', args: [JSON.stringify(left), req.user] });
    return true;
  });
  if (out) res.json({ ok: true });
});

// ---------- chat ----------
// messages live on both people's rows; every change runs in one transaction on the server
const threadKeyOf = (m, me) => { const other = m.sender === me ? m.receiver : m.sender; return other + (m.itemId ? THREAD_SEP + String(m.itemId) : ''); };
async function withBothRows(tx, a, b, fn) {          // fn(msgsA, msgsB) mutates the arrays; both rows are saved
  const names = a === b ? [a] : [a, b];
  const rows = {};
  for (const n of names) {
    const r = await tx.execute({ sql: 'SELECT messages FROM users WHERE username = ?', args: [n] });
    rows[n] = r.rows.length ? parseJson(r.rows[0].messages, []) : null;
  }
  if (rows[a] === null) throw new Abort('Account not found.', 404);
  fn(rows);
  for (const n of names) if (rows[n] !== null) await tx.execute({ sql: 'UPDATE users SET messages = ? WHERE username = ?', args: [JSON.stringify(rows[n]), n] });
}
function cleanItemRef(r) {
  if (!r || typeof r !== 'object') return null;
  return { name: String(r.name || '').slice(0, 80), price: String(r.price || '').slice(0, 30), game: String(r.game || '').slice(0, 60), seller: String(r.seller || '').slice(0, 40) };
}
function cleanOffer(o) {
  if (!o || typeof o !== 'object') return null;
  const items = Array.isArray(o.items) ? o.items.slice(0, 60).map(x => String(x).slice(0, 80)) : [];
  if (!items.length) return null;
  return { game: String(o.game || '').slice(0, 60), items, mm: !!o.mm, listingGame: String(o.listingGame || '').slice(0, 60), status: 'pending' };
}
app.post('/api/chat/send', requireUser, async (req, res) => {
  if (limited('chat:' + req.user, 20, 10 * 1000)) return res.status(429).json({ error: 'You are sending messages too fast.' });
  const to = String(req.body.receiver || '');
  const text = String(req.body.text || '').slice(0, 2000);
  if (!to) return res.status(400).json({ error: 'Choose who to message.' });
  if (!text.trim()) return res.status(400).json({ error: 'Message is empty.' });
  try { const blocked = await spamBlocked(req.user); if (blocked) return res.status(429).json({ error: blocked }); } catch (e) { console.error('spam check error:', e); }
  const out = await inTx(res, async (tx) => {
    const ex = await tx.execute({ sql: 'SELECT bannedUntil FROM users WHERE username = ?', args: [req.user] });
    const until = Number(ex.rows[0] && ex.rows[0].bannedUntil) || 0;
    if (until === -1 || until > Date.now()) throw new Abort('Your account is banned.', 403);
    if (!(await tx.execute({ sql: 'SELECT 1 FROM users WHERE username = ?', args: [to] })).rows.length) throw new Abort('Account not found.', 404);
    let imageId = null;
    if (req.body.imageId) {
      imageId = String(req.body.imageId).slice(0, 64);
      const im = await tx.execute({ sql: 'SELECT 1 FROM chat_images WHERE id = ? AND sender = ?', args: [imageId, req.user] });
      if (!im.rows.length) throw new Abort('Picture not found.', 400);
    }
    const msg = { sender: req.user, receiver: to, text, timestamp: Date.now(), itemRef: cleanItemRef(req.body.itemRef), itemId: req.body.itemId ? String(req.body.itemId).slice(0, 64) : null };
    if (imageId) { msg.imageId = imageId; msg.caption = String(req.body.caption || '').slice(0, 500); }
    const offer = cleanOffer(req.body.offer); if (offer) msg.offer = offer;
    await withBothRows(tx, req.user, to, (rows) => {
      while (rows[req.user].some(m => m.sender === req.user && m.timestamp === msg.timestamp)) msg.timestamp++;   // timestamp is the id
      rows[req.user].push(msg);
      if (to !== req.user && rows[to] !== null) rows[to].push(msg);
    });
    return msg;
  });
  if (out) res.json({ message: out });
});
app.post('/api/chat/edit', requireUser, async (req, res) => {
  const to = String(req.body.receiver || ''), ts = Number(req.body.timestamp);
  const text = String(req.body.text || '').slice(0, 2000);
  if (!to || !ts || !text.trim()) return res.status(400).json({ error: 'Bad request.' });
  const out = await inTx(res, async (tx) => {
    await withBothRows(tx, req.user, to, (rows) => {
      for (const n of Object.keys(rows)) if (rows[n]) rows[n].forEach(m => { if (m.sender === req.user && m.timestamp === ts && !m.offer) m.text = text; });
    });
    return true;
  });
  if (out) res.json({ ok: true });
});
app.post('/api/chat/delete', requireUser, async (req, res) => {
  const to = String(req.body.receiver || ''), ts = Number(req.body.timestamp);
  if (!to || !ts) return res.status(400).json({ error: 'Bad request.' });
  const out = await inTx(res, async (tx) => {
    await withBothRows(tx, req.user, to, (rows) => {
      for (const n of Object.keys(rows)) if (rows[n]) rows[n] = rows[n].filter(m => !(m.sender === req.user && m.timestamp === ts));
    });
    return true;
  });
  if (out) res.json({ ok: true });
});
// offers: the receiver accepts / declines / asks for more items; the sender updates the items after being asked
app.post('/api/chat/offer', requireUser, async (req, res) => {
  const sender = String(req.body.sender || ''), receiver = String(req.body.receiver || ''), ts = Number(req.body.timestamp);
  const action = String(req.body.action || '');
  if (![sender, receiver].includes(req.user) || !ts) return res.status(400).json({ error: 'Bad request.' });
  const out = await inTx(res, async (tx) => {
    let found = false;
    await withBothRows(tx, sender, receiver, (rows) => {
      for (const n of Object.keys(rows)) if (rows[n]) rows[n].forEach(m => {
        if (m.sender !== sender || m.timestamp !== ts || !m.offer) return;
        found = true;
        if (action === 'accept' || action === 'decline' || action === 'add') {
          if (req.user !== receiver) throw new Abort('Only the other person can respond to this offer.', 403);
          if (m.offer.status !== 'pending') throw new Abort('This offer was already answered.');
          m.offer.status = action === 'accept' ? 'accepted' : action === 'decline' ? 'declined' : 'add';
          m.offer.by = req.user;
        } else if (action === 'update') {
          if (req.user !== sender) throw new Abort('Only the sender can change the offer.', 403);
          const o = cleanOffer({ ...m.offer, items: req.body.items, mm: req.body.mm });
          if (!o) throw new Abort('Pick at least one item.', 400);
          m.offer = o;
          m.text = String(req.body.text || m.text).slice(0, 2000);
        } else throw new Abort('Bad request.', 400);
      });
    });
    if (!found) throw new Abort('Offer not found.', 404);
    return true;
  });
  if (out) res.json({ ok: true });
});

// delete a chat only for me; also forgets it forever when the other side already deleted theirs
app.post('/api/chat/clear', requireUser, async (req, res) => {
  const other = String(req.body.other || ''), itemId = req.body.itemId ? String(req.body.itemId) : '';
  if (!other) return res.status(400).json({ error: 'Bad request.' });
  const key = other + (itemId ? THREAD_SEP + itemId : '');
  const theirKey = req.user + (itemId ? THREAD_SEP + itemId : '');
  const out = await inTx(res, async (tx) => {
    const open = await tx.execute({
      sql: "SELECT id FROM deals WHERE ((buyer = ? AND seller = ?) OR (buyer = ? AND seller = ?)) AND COALESCE(itemId, '') = ? AND status IN ('requested','paid','not_received','reported') LIMIT 1",
      args: [req.user, other, other, req.user, itemId]
    });
    if (open.rows.length) throw new Abort('Finish or resolve the deal in this chat before deleting it.');
    const me = await tx.execute({ sql: 'SELECT messages FROM users WHERE username = ?', args: [req.user] });
    const mine = parseJson(me.rows[0] && me.rows[0].messages, []).filter(m => threadKeyOf(m, req.user) !== key);
    await tx.execute({ sql: 'UPDATE users SET messages = ? WHERE username = ?', args: [JSON.stringify(mine), req.user] });
    await tx.execute({ sql: 'INSERT INTO chat_clears (user, other, clearedAt) VALUES (?, ?, ?) ON CONFLICT(user, other) DO UPDATE SET clearedAt = excluded.clearedAt', args: [req.user, key, Date.now()] });
    const th = await tx.execute({ sql: 'SELECT clearedAt FROM chat_clears WHERE user = ? AND other = ?', args: [other, theirKey] });
    const ot = await tx.execute({ sql: 'SELECT messages FROM users WHERE username = ?', args: [other] });
    const theirLeft = ot.rows.length ? parseJson(ot.rows[0].messages, []).some(m => threadKeyOf(m, other) === theirKey) : false;
    if (th.rows.length && Number(th.rows[0].clearedAt) && !theirLeft) {
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
  const rs = await db.execute({ sql: 'SELECT other, clearedAt FROM chat_clears WHERE user = ?', args: [req.user] });
  const clears = {}; rs.rows.forEach(r => { clears[r.other] = Number(r.clearedAt) || 0; });
  res.json({ clears });
});

// pictures
app.post('/api/chat/image', requireUser, async (req, res) => {
  if (limited('img:' + req.user, 10, 60 * 1000)) return res.status(429).json({ error: 'Too many pictures. Slow down.' });
  const to = String(req.body.receiver || ''), data = String(req.body.data || '');
  if (!to || !/^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(data) || data.length > 700000) return res.status(400).json({ error: 'Invalid picture.' });
  if (!(await db.execute({ sql: 'SELECT 1 FROM users WHERE username = ?', args: [to] })).rows.length) return res.status(404).json({ error: 'Account not found.' });
  const ts = Date.now(), id = ts + '-' + crypto.randomBytes(4).toString('hex');
  await db.execute({ sql: 'INSERT INTO chat_images (id, sender, receiver, data, createdAt) VALUES (?, ?, ?, ?, ?)', args: [id, req.user, to, data, ts] });
  res.json({ id });
});
app.get('/api/chat/image/:id', requireUser, async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT sender, receiver, data FROM chat_images WHERE id = ?', args: [String(req.params.id)] });
  if (!rs.rows.length) return res.status(404).json({ error: 'Not found' });
  const r = rs.rows[0];
  if (r.sender !== req.user && r.receiver !== req.user && !(await isAdminName(req.user))) return res.status(404).json({ error: 'Not found' });
  res.json({ data: r.data });
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

// admin: read the chat between two people (used by the reports page)
app.get('/api/admin/chat', requireUser, requireAdmin, async (req, res) => {
  const a = String(req.query.a || ''), b = String(req.query.b || '');
  const out = [];
  for (const n of [a, b]) {
    const r = await db.execute({ sql: 'SELECT messages FROM users WHERE username = ?', args: [n] });
    if (r.rows.length) parseJson(r.rows[0].messages, []).forEach(m => { if ((m.sender === a && m.receiver === b) || (m.sender === b && m.receiver === a)) out.push(m); });
  }
  res.json({ messages: out });
});

// admin: delete an account (never the admin itself)
app.post('/api/admin/delete-user', requireUser, requireAdmin, async (req, res) => {
  const name = String(req.body.username || '');
  if (!name) return res.status(400).json({ error: 'Bad request.' });
  const r = await db.execute({ sql: "DELETE FROM users WHERE username = ? AND COALESCE(customId, '') != 'knqw'", args: [name] });
  if (!r.rowsAffected) return res.status(404).json({ error: 'Account not found.' });
  await db.execute({ sql: 'DELETE FROM sessions WHERE username = ?', args: [name] });
  try { await db.execute({ sql: 'DELETE FROM tickets WHERE creator = ? OR partner = ?', args: [name, name] }); } catch (e) {}
  console.log(`ADMIN ${req.user} deleted account ${name}`);
  res.json({ ok: true });
});

// old chats are cleaned up by the server now (every 10 minutes), not by whoever opens the page
const CHAT_TTL_MS = 14 * DAY;
async function purgeOldChats() {
  try {
    const cutoff = Date.now() - CHAT_TTL_MS;
    const open = await db.execute("SELECT buyer, seller FROM deals WHERE status IN ('requested','paid','not_received','reported')");
    const keep = new Set(); open.rows.forEach(r => { keep.add(r.buyer + '|' + r.seller); keep.add(r.seller + '|' + r.buyer); });
    const rs = await db.execute("SELECT username, messages FROM users WHERE messages IS NOT NULL AND messages != '[]'");
    for (const row of rs.rows) {
      const msgs = parseJson(row.messages, []);
      const kept = msgs.filter(m => !(Number(m.timestamp) < cutoff) || keep.has(row.username + '|' + (m.sender === row.username ? m.receiver : m.sender)));
      if (kept.length !== msgs.length) await db.execute({ sql: 'UPDATE users SET messages = ? WHERE username = ?', args: [JSON.stringify(kept), row.username] });
    }
    for (const sql of ["DELETE FROM group_messages WHERE timestamp < ?", "DELETE FROM deals WHERE status IN ('completed','cancelled','refunded','released') AND updatedAt < ?", "DELETE FROM chat_clears WHERE clearedAt < ?", "DELETE FROM chat_images WHERE createdAt < ?"]) {
      try { await db.execute({ sql, args: [cutoff] }); } catch (e) {}
    }
    try { await db.execute({ sql: 'DELETE FROM typing WHERE ts < ?', args: [Date.now() - 60000] }); } catch (e) {}
  } catch (e) { console.error('purge error:', e); }
}
setInterval(purgeOldChats, 10 * 60 * 1000);

// ======================================================================
// Stage 4: ratings, vouches, tickets, reports, groups, bans, appeals, IP bans, spam timeouts
// ======================================================================
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const isMiddlemanName = async (name) => {
  const r = await db.execute({ sql: 'SELECT isMiddleman FROM users WHERE username = ?', args: [name] });
  return !!r.rows.length && Number(r.rows[0].isMiddleman) === 1;
};
const userExists = async (name) => !!name && (await db.execute({ sql: 'SELECT 1 FROM users WHERE username = ?', args: [name] })).rows.length > 0;
const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { console.error(req.path, e); if (!res.headersSent) res.status(500).json({ error: 'Server error. Try again.' }); } };

// ---------- ratings: only after a completed deal ----------
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
  res.json({ avg: Number(r.rows[0].a) || 0, count: Number(r.rows[0].c) || 0, mine: m.rows.length ? Number(m.rows[0].stars) || 0 : 0 });
}));
app.post('/api/ratings', requireUser, wrap(async (req, res) => {
  if (limited('rate:' + req.user, 30, 60 * 60 * 1000)) return bad(res, 'Too many requests.', 429);
  const target = String(req.body.target || ''), stars = Number(req.body.stars);
  if (!target || target === req.user || !Number.isInteger(stars) || stars < 1 || stars > 5) return bad(res, 'Bad request.');
  const d = await db.execute({ sql: "SELECT 1 FROM deals WHERE status IN ('completed','released') AND ((buyer = ? AND seller = ?) OR (buyer = ? AND seller = ?)) LIMIT 1", args: [req.user, target, target, req.user] });
  if (!d.rows.length) return bad(res, 'You can rate someone after a completed deal with them.', 403);
  await db.execute({ sql: 'INSERT INTO ratings (rater, target, stars, createdAt) VALUES (?, ?, ?, ?) ON CONFLICT(rater, target) DO UPDATE SET stars = excluded.stars, createdAt = excluded.createdAt', args: [req.user, target, stars, Date.now()] });
  res.json({ ok: true });
}));
app.post('/api/ratings/remove', requireUser, wrap(async (req, res) => {
  await db.execute({ sql: 'DELETE FROM ratings WHERE rater = ? AND target = ?', args: [req.user, String(req.body.target || '')] });
  res.json({ ok: true });
}));
app.get('/api/admin/ratings/:user', requireUser, requireAdmin, wrap(async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT rater, stars, createdAt FROM ratings WHERE target = ? ORDER BY createdAt DESC', args: [String(req.params.user)] });
  res.json({ rows: rs.rows.map(r => ({ rater: r.rater, stars: Number(r.stars), createdAt: Number(r.createdAt) })) });
}));
app.post('/api/admin/ratings/add', requireUser, requireAdmin, wrap(async (req, res) => {
  const target = String(req.body.target || ''), stars = Number(req.body.stars);
  if (!(await userExists(target)) || !Number.isInteger(stars) || stars < 1 || stars > 5) return bad(res, 'Bad request.');
  await db.execute({ sql: 'INSERT INTO ratings (rater, target, stars, createdAt) VALUES (?, ?, ?, ?)', args: ['admin:' + Date.now() + crypto.randomInt(1000), target, stars, Date.now()] });
  res.json({ ok: true });
}));
app.post('/api/admin/ratings/remove', requireUser, requireAdmin, wrap(async (req, res) => {
  await db.execute({ sql: 'DELETE FROM ratings WHERE rater = ? AND target = ?', args: [String(req.body.rater || ''), String(req.body.target || '')] });
  res.json({ ok: true });
}));
app.post('/api/admin/ratings/clear', requireUser, requireAdmin, wrap(async (req, res) => {
  await db.execute({ sql: 'DELETE FROM ratings WHERE target = ?', args: [String(req.body.target || '')] });
  res.json({ ok: true });
}));

// ---------- vouches (for middlemen) ----------
app.get('/api/vouches/:mm', requireUser, wrap(async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT id, author, text, createdAt FROM vouches WHERE middleman = ? ORDER BY createdAt DESC', args: [String(req.params.mm)] });
  res.json({ vouches: rs.rows.map(r => ({ id: Number(r.id), author: r.author, text: r.text, createdAt: Number(r.createdAt) })) });
}));
app.post('/api/vouches', requireUser, wrap(async (req, res) => {
  if (limited('vouch:' + req.user, 20, 60 * 60 * 1000)) return bad(res, 'Too many requests.', 429);
  const mm = String(req.body.middleman || ''), text = String(req.body.text || '').trim();
  if (!mm || mm === req.user || !(await isMiddlemanName(mm))) return bad(res, 'You can only vouch for another middleman.');
  if (text.length < 3) return bad(res, 'Write at least 3 characters.');
  await db.execute({ sql: 'INSERT INTO vouches (middleman, author, text, createdAt) VALUES (?, ?, ?, ?) ON CONFLICT(middleman, author) DO UPDATE SET text = excluded.text, createdAt = excluded.createdAt', args: [mm, req.user, text.slice(0, 300), Date.now()] });
  res.json({ ok: true });
}));
app.post('/api/vouches/delete', requireUser, wrap(async (req, res) => {
  const admin = await isAdminName(req.user);
  await db.execute({ sql: 'DELETE FROM vouches WHERE id = ? AND (author = ? OR ?)', args: [Number(req.body.id), req.user, admin ? 1 : 0] });
  res.json({ ok: true });
}));

// ---------- middleman tickets ----------
const TICKET_TTL_MS = DAY;
app.get('/api/tickets', requireUser, wrap(async (req, res) => {
  const cutoff = Date.now() - TICKET_TTL_MS;
  await db.execute({ sql: 'DELETE FROM tickets WHERE createdAt < ?', args: [cutoff] });
  const isMM = await isMiddlemanName(req.user);
  const rs = isMM
    ? await db.execute({ sql: "SELECT id, creator, partner, description, status, claimedBy, createdAt FROM tickets WHERE createdAt > ? AND (status = 'open' OR (status = 'claimed' AND (claimedBy = ? OR creator = ? OR partner = ?))) ORDER BY createdAt DESC LIMIT 100", args: [cutoff, req.user, req.user, req.user] })
    : await db.execute({ sql: "SELECT id, creator, partner, description, status, claimedBy, createdAt FROM tickets WHERE createdAt > ? AND status IN ('open', 'claimed') AND (creator = ? OR partner = ?) ORDER BY createdAt DESC LIMIT 100", args: [cutoff, req.user, req.user] });
  res.json({ isMiddleman: isMM, tickets: rs.rows.map(r => ({ id: Number(r.id), creator: r.creator, partner: r.partner || '', description: r.description, status: r.status, claimedBy: r.claimedBy || '', createdAt: Number(r.createdAt) })) });
}));
app.post('/api/tickets', requireUser, wrap(async (req, res) => {
  if (limited('ticket:' + req.user, 5, 60 * 60 * 1000)) return bad(res, 'Too many tickets. Try again later.', 429);
  const desc = String(req.body.description || '').trim().slice(0, 1000) || 'No description';
  await db.execute({ sql: "INSERT INTO tickets (creator, partner, description, status, createdAt) VALUES (?, '', ?, 'open', ?)", args: [req.user, desc, Date.now()] });
  res.json({ ok: true });
}));
app.post('/api/tickets/:id/claim', requireUser, wrap(async (req, res) => {
  if (!(await isMiddlemanName(req.user))) return bad(res, 'Only middlemen can claim tickets.', 403);
  const rs = await db.execute({ sql: "UPDATE tickets SET status = 'claimed', claimedBy = ? WHERE id = ? AND status = 'open' AND creator != ? AND COALESCE(partner, '') != ?", args: [req.user, Number(req.params.id), req.user, req.user] });
  if (!rs.rowsAffected) return bad(res, 'This ticket is no longer available.', 409);
  res.json({ ok: true });
}));
app.post('/api/tickets/:id/cancel', requireUser, wrap(async (req, res) => {
  const rs = await db.execute({ sql: "DELETE FROM tickets WHERE id = ? AND creator = ? AND status IN ('open', 'claimed')", args: [Number(req.params.id), req.user] });
  if (!rs.rowsAffected) return bad(res, 'This ticket is already gone.', 409);
  res.json({ ok: true });
}));
app.post('/api/tickets/:id/close', requireUser, wrap(async (req, res) => {
  await db.execute({ sql: "UPDATE tickets SET status = 'closed' WHERE id = ? AND claimedBy = ?", args: [Number(req.params.id), req.user] });
  res.json({ ok: true });
}));
app.get('/api/tickets/middlemen', requireUser, wrap(async (req, res) => {
  const rs = await db.execute({ sql: "SELECT DISTINCT claimedBy FROM tickets WHERE (creator = ? OR partner = ?) AND claimedBy IS NOT NULL AND claimedBy != '' AND status IN ('claimed', 'closed')", args: [req.user, req.user] });
  res.json({ names: rs.rows.map(r => r.claimedBy).filter(n => n && n !== req.user) });
}));

// ---------- reports ----------
const cleanReason = (v, n) => String(v || '').slice(0, n);
app.post('/api/reports/item', requireUser, wrap(async (req, res) => {
  if (limited('rep:' + req.user, 20, 60 * 60 * 1000)) return bad(res, 'Too many reports.', 429);
  const b = req.body, itemId = String(b.itemId || '').slice(0, 64), reason = cleanReason(b.reason, 100);
  if (!itemId || !reason) return bad(res, 'Bad request.');
  if ((await db.execute({ sql: 'SELECT id FROM item_reports WHERE itemId = ? AND reporter = ? LIMIT 1', args: [itemId, req.user] })).rows.length) return res.json({ duplicate: true });
  await db.execute({ sql: 'INSERT INTO item_reports (itemId, itemName, itemGame, seller, reporter, reason, details, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', args: [itemId, cleanReason(b.itemName, 100), cleanReason(b.itemGame, 60), cleanReason(b.seller, 40), req.user, reason, cleanReason(b.details, 1000), Date.now()] });
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
app.get('/api/admin/reports/items', requireUser, requireAdmin, wrap(async (req, res) => {
  res.json({ rows: (await db.execute('SELECT * FROM item_reports ORDER BY createdAt DESC')).rows.map(r => ({ ...r, id: Number(r.id), createdAt: Number(r.createdAt) })) });
}));
app.get('/api/admin/reports/users', requireUser, requireAdmin, wrap(async (req, res) => {
  res.json({ rows: (await db.execute('SELECT * FROM user_reports ORDER BY createdAt DESC')).rows.map(r => ({ ...r, id: Number(r.id), createdAt: Number(r.createdAt) })) });
}));
app.post('/api/admin/reports/item/dismiss', requireUser, requireAdmin, wrap(async (req, res) => {
  await db.execute({ sql: 'DELETE FROM item_reports WHERE id = ?', args: [Number(req.body.id)] }); res.json({ ok: true });
}));
app.post('/api/admin/reports/user/dismiss', requireUser, requireAdmin, wrap(async (req, res) => {
  await db.execute({ sql: 'DELETE FROM user_reports WHERE id = ?', args: [Number(req.body.id)] }); res.json({ ok: true });
}));
app.post('/api/admin/deals/:id/cancel-report', requireUser, requireAdmin, wrap(async (req, res) => {
  const rs = await db.execute({ sql: "UPDATE deals SET status = 'not_received', reportedAt = 0, reportedBy = NULL, chatSnapshot = NULL, updatedAt = ? WHERE id = ? AND status = 'reported'", args: [Date.now(), Number(req.params.id)] });
  if (!rs.rowsAffected) return bad(res, 'This report was already handled.', 409);
  res.json({ ok: true });
}));

// ---------- group chats ----------
const mapGroup = (r) => ({ id: Number(r.id), name: r.name || 'Group', owner: r.owner, members: parseJson(r.members, []), createdAt: Number(r.createdAt) || 0 });
async function memberGroup(id, user) {
  const rs = await db.execute({ sql: 'SELECT * FROM chat_groups WHERE id = ?', args: [id] });
  if (!rs.rows.length) return null;
  const g = mapGroup(rs.rows[0]);
  return g.members.includes(user) ? g : null;
}
async function myGroups(user) {
  const rs = await db.execute({ sql: 'SELECT * FROM chat_groups WHERE members LIKE ?', args: [`%"${user.replace(/[%_"\\]/g, '')}"%`] });
  const groups = rs.rows.map(mapGroup).filter(g => g.members.includes(user));
  if (groups.length) {
    const last = await db.execute({ sql: `SELECT groupId, MAX(timestamp) AS t FROM group_messages WHERE groupId IN (${groups.map(() => '?').join(',')}) GROUP BY groupId`, args: groups.map(g => g.id) });
    const lt = {}; last.rows.forEach(r => { lt[Number(r.groupId)] = Number(r.t) || 0; });
    groups.forEach(g => { g.lastTime = lt[g.id] || g.createdAt; });
  }
  return groups.sort((a, b) => (b.lastTime || 0) - (a.lastTime || 0));
}
app.get('/api/groups', requireUser, wrap(async (req, res) => res.json({ groups: await myGroups(req.user) })));
app.get('/api/groups/sig', requireUser, wrap(async (req, res) => {
  const groups = await myGroups(req.user);
  if (!groups.length) return res.json({ sig: '' });
  const rs = await db.execute({ sql: `SELECT COUNT(*) AS c, COALESCE(MAX(timestamp), 0) AS t FROM group_messages WHERE groupId IN (${groups.map(() => '?').join(',')})`, args: groups.map(g => g.id) });
  res.json({ sig: groups.map(g => g.id + ':' + g.members.length + ':' + g.name).join(',') + '|' + Number(rs.rows[0].c) + ':' + Number(rs.rows[0].t) });
}));
app.get('/api/groups/unread', requireUser, wrap(async (req, res) => {
  const groups = await myGroups(req.user);
  if (!groups.length) return res.json({ rows: [] });
  const rs = await db.execute({ sql: `SELECT groupId, sender, timestamp FROM group_messages WHERE groupId IN (${groups.map(() => '?').join(',')}) AND sender != ? AND timestamp > ?`, args: [...groups.map(g => g.id), req.user, Number(req.query.since) || 0] });
  res.json({ rows: rs.rows.map(r => ({ groupId: Number(r.groupId), sender: r.sender, timestamp: Number(r.timestamp) })) });
}));
app.get('/api/groups/:id', requireUser, wrap(async (req, res) => {
  const g = await memberGroup(Number(req.params.id), req.user);
  if (!g) return bad(res, 'Group not found.', 404);
  res.json({ group: g });
}));
app.get('/api/groups/:id/messages', requireUser, wrap(async (req, res) => {
  if (!(await memberGroup(Number(req.params.id), req.user))) return bad(res, 'Group not found.', 404);
  const rs = await db.execute({ sql: 'SELECT sender, text, timestamp FROM group_messages WHERE groupId = ? ORDER BY timestamp ASC, id ASC LIMIT 500', args: [Number(req.params.id)] });
  res.json({ messages: rs.rows.map(r => ({ sender: r.sender, text: r.text, timestamp: Number(r.timestamp) })) });
}));
// people I may add: anyone I have a chat with, or a middleman who took one of my tickets
async function groupCandidates(user) {
  const set = new Set();
  const me = await db.execute({ sql: 'SELECT messages FROM users WHERE username = ?', args: [user] });
  parseJson(me.rows[0] && me.rows[0].messages, []).forEach(m => { const o = m.sender === user ? m.receiver : m.sender; if (o && o !== user) set.add(o); });
  (await db.execute({ sql: "SELECT DISTINCT claimedBy FROM tickets WHERE (creator = ? OR partner = ?) AND claimedBy IS NOT NULL AND claimedBy != '' AND status IN ('claimed','closed')", args: [user, user] })).rows.forEach(r => { if (r.claimedBy !== user) set.add(r.claimedBy); });
  return set;
}
app.post('/api/groups', requireUser, wrap(async (req, res) => {
  if (limited('grp:' + req.user, 10, 60 * 60 * 1000)) return bad(res, 'Too many requests.', 429);
  const name = String(req.body.name || '').trim().slice(0, 40);
  const picked = [...new Set((Array.isArray(req.body.members) ? req.body.members : []).map(String))].filter(n => n !== req.user).slice(0, 50);
  if (!name || !picked.length) return bad(res, 'Pick a name and at least one person.');
  const allowed = await groupCandidates(req.user);
  if (picked.some(p => !allowed.has(p))) return bad(res, 'You can only add people you have chats with.', 403);
  const rs = await db.execute({ sql: 'INSERT INTO chat_groups (name, owner, members, createdAt) VALUES (?, ?, ?, ?)', args: [name, req.user, JSON.stringify([req.user, ...picked]), Date.now()] });
  res.json({ id: Number(rs.lastInsertRowid) });
}));
app.get('/api/groups/:id/candidates', requireUser, wrap(async (req, res) => {
  const g = await memberGroup(Number(req.params.id), req.user);
  if (!g || g.owner !== req.user) return bad(res, 'Only the owner can add people.', 403);
  res.json({ names: [...(await groupCandidates(req.user))].filter(n => !g.members.includes(n)) });
}));
app.post('/api/groups/:id/members', requireUser, wrap(async (req, res) => {
  const out = await inTx(res, async (tx) => {
    const rs = await tx.execute({ sql: 'SELECT * FROM chat_groups WHERE id = ?', args: [Number(req.params.id)] });
    if (!rs.rows.length) throw new Abort('Group not found.', 404);
    const g = mapGroup(rs.rows[0]);
    if (!g.members.includes(req.user)) throw new Abort('Group not found.', 404);
    const action = String(req.body.action || ''), who = String(req.body.username || '');
    let members = g.members;
    if (action === 'add') {
      if (g.owner !== req.user) throw new Abort('Only the owner can add people.', 403);
      const allowed = await groupCandidates(req.user);
      const add = (Array.isArray(req.body.usernames) ? req.body.usernames : [who]).map(String).filter(n => allowed.has(n) && !members.includes(n));
      members = [...members, ...add].slice(0, 100);
    } else if (action === 'remove') {
      if (g.owner !== req.user || who === g.owner) throw new Abort('Only the owner can remove people.', 403);
      members = members.filter(m => m !== who);
    } else if (action === 'leave') {
      if (g.owner === req.user) throw new Abort('The owner cannot leave. Delete the group instead.');
      members = members.filter(m => m !== req.user);
    } else throw new Abort('Bad request.', 400);
    await tx.execute({ sql: 'UPDATE chat_groups SET members = ? WHERE id = ?', args: [JSON.stringify(members), g.id] });
    return true;
  });
  if (out) res.json({ ok: true });
}));
app.post('/api/groups/:id/delete', requireUser, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const rs = await db.execute({ sql: 'DELETE FROM chat_groups WHERE id = ? AND owner = ?', args: [id, req.user] });
  if (!rs.rowsAffected) return bad(res, 'Only the owner can delete the group.', 403);
  await db.execute({ sql: 'DELETE FROM group_messages WHERE groupId = ?', args: [id] });
  res.json({ ok: true });
}));

// ---------- spam timeouts (enforced here, for 1:1 and group messages) ----------
const SPAM_STEPS = [15 * 1000, 3 * 60 * 1000, 60 * 60 * 1000, DAY];
const SPAM_MAX_MSGS = 5, SPAM_WINDOW_MS = 5000, SPAM_RESET_MS = DAY;
const spamStamps = new Map();
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
  const g = await memberGroup(Number(req.params.id), req.user);
  if (!g) return bad(res, 'You are no longer in this group.', 403);
  const text = String(req.body.text || '').trim().slice(0, 2000);
  if (!text) return bad(res, 'Message is empty.');
  const blocked = await spamBlocked(req.user); if (blocked) return bad(res, blocked, 429);
  await db.execute({ sql: 'INSERT INTO group_messages (groupId, sender, text, timestamp) VALUES (?, ?, ?, ?)', args: [g.id, req.user, text, Date.now()] });
  res.json({ ok: true });
}));
app.get('/api/admin/timeouts', requireUser, requireAdmin, wrap(async (req, res) => {
  res.json({ rows: (await db.execute('SELECT * FROM spam_timeouts ORDER BY until DESC')).rows.map(r => ({ username: r.username, level: Number(r.level), until: Number(r.until), lastOffense: Number(r.lastOffense) })) });
}));
app.post('/api/admin/timeouts/remove', requireUser, requireAdmin, wrap(async (req, res) => {
  await db.execute({ sql: 'DELETE FROM spam_timeouts WHERE username = ?', args: [String(req.body.username || '')] }); res.json({ ok: true });
}));
app.post('/api/admin/timeouts/add', requireUser, requireAdmin, wrap(async (req, res) => {
  const name = String(req.body.username || ''), mins = Math.floor(Number(req.body.minutes));
  if (!name || !(mins > 0) || mins > 525600) return bad(res, 'Enter the minutes to add.');
  const cur = (await db.execute({ sql: 'SELECT until FROM spam_timeouts WHERE username = ?', args: [name] })).rows[0];
  const base = Math.max(Date.now(), cur ? Number(cur.until) || 0 : 0);
  await db.execute({ sql: 'UPDATE spam_timeouts SET until = ?, lastOffense = ? WHERE username = ?', args: [base + mins * 60000, Date.now(), name] });
  res.json({ ok: true });
}));

// ---------- bans, appeals, middleman role, IP bans ----------
app.get('/api/me/ban', requireUser, wrap(async (req, res) => {
  const r = await db.execute({ sql: 'SELECT username, customId, bannedUntil, bannedAt, banReason, appeal, appealAt, appealStatus FROM users WHERE username = ?', args: [req.user] });
  if (!r.rows.length) return res.json({ deleted: true });
  res.json({ user: { username: r.rows[0].username, customId: r.rows[0].customId, ...banPart(r.rows[0]) } });
}));
app.post('/api/appeal', requireUser, wrap(async (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 1000);
  if (text.length < 5) return bad(res, 'Please explain why the ban should be lifted.');
  const rs = await db.execute({ sql: "UPDATE users SET appeal = ?, appealAt = ?, appealStatus = 'pending' WHERE username = ? AND (bannedUntil = -1 OR bannedUntil > ?) AND (appealStatus IS NULL OR appealStatus = '')", args: [text, Date.now(), req.user, Date.now()] });
  if (!rs.rowsAffected) return bad(res, 'You cannot send an appeal right now.', 409);
  res.json({ ok: true });
}));
app.post('/api/admin/ban', requireUser, requireAdmin, wrap(async (req, res) => {
  const name = String(req.body.username || ''), until = Number(req.body.until), reason = String(req.body.reason || '').slice(0, 300);
  if (!Number.isFinite(until) || (until !== -1 && until <= Date.now())) return bad(res, 'Bad ban length.');
  const rs = await db.execute({ sql: "UPDATE users SET bannedUntil = ?, bannedAt = ?, banReason = ?, appeal = NULL, appealAt = 0, appealStatus = NULL WHERE username = ? AND COALESCE(customId, '') != 'knqw'", args: [until, Date.now(), reason, name] });
  if (!rs.rowsAffected) return bad(res, 'Account not found.', 404);
  if (req.body.banIp) {
    const u = await db.execute({ sql: 'SELECT lastIp FROM users WHERE username = ?', args: [name] });
    const ip = u.rows[0] && u.rows[0].lastIp;
    if (ip) await db.execute({ sql: 'INSERT INTO ip_bans (ip, bannedUntil, bannedAt, reason, username) VALUES (?, ?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET bannedUntil = excluded.bannedUntil, bannedAt = excluded.bannedAt, reason = excluded.reason, username = excluded.username', args: [ip, until, Date.now(), reason, name] });
  }
  await db.execute({ sql: 'DELETE FROM sessions WHERE username = ?', args: [name] });     // banned people are logged out everywhere
  console.log(`ADMIN ${req.user} banned ${name} until ${until}`);
  res.json({ ok: true });
}));
app.post('/api/admin/unban', requireUser, requireAdmin, wrap(async (req, res) => {
  const name = String(req.body.username || '');
  await db.execute({ sql: 'UPDATE users SET bannedUntil = 0, bannedAt = 0, banReason = NULL, appeal = NULL, appealAt = 0, appealStatus = NULL WHERE username = ?', args: [name] });
  await db.execute({ sql: 'DELETE FROM ip_bans WHERE username = ?', args: [name] });
  res.json({ ok: true });
}));
app.get('/api/admin/appeals', requireUser, requireAdmin, wrap(async (req, res) => {
  const rs = await db.execute("SELECT username, displayName, bannedUntil, bannedAt, banReason, appeal, appealAt, appealStatus FROM users WHERE appealStatus IN ('pending','denied') AND appeal IS NOT NULL");
  res.json({ rows: rs.rows.map(r => ({ username: r.username, displayName: r.displayName, ...banPart(r) })) });
}));
app.post('/api/admin/appeal-status', requireUser, requireAdmin, wrap(async (req, res) => {
  const st = String(req.body.status || '');
  if (!['pending', 'denied', ''].includes(st)) return bad(res, 'Bad request.');
  await db.execute({ sql: 'UPDATE users SET appealStatus = ? WHERE username = ?', args: [st || null, String(req.body.username || '')] });
  res.json({ ok: true });
}));
app.post('/api/admin/middleman', requireUser, requireAdmin, wrap(async (req, res) => {
  const rs = await db.execute({ sql: 'UPDATE users SET isMiddleman = ? WHERE username = ?', args: [req.body.value ? 1 : 0, String(req.body.username || '')] });
  if (!rs.rowsAffected) return bad(res, 'Account not found.', 404);
  res.json({ ok: true });
}));
app.get('/api/admin/ip-banned', requireUser, requireAdmin, wrap(async (req, res) => {
  const rs = await db.execute({ sql: 'SELECT username FROM ip_bans WHERE bannedUntil = -1 OR bannedUntil > ?', args: [Date.now()] });
  res.json({ names: rs.rows.map(r => r.username).filter(Boolean) });
}));

// ---------- misc ----------
app.get('/api/listings/sig', requireUser, wrap(async (req, res) => {
  const rs = await db.execute('SELECT username, COALESCE(length(items), 0) AS l, COALESCE(lastItemTime, 0) AS t, COALESCE(bannedUntil, 0) AS b FROM users');
  res.json({ sig: rs.rows.map(r => `${r.username}:${r.l}:${r.t}:${r.b}`).join('|') });
}));
const PERM_DELETE_MS = 30 * DAY;      // permanently banned accounts disappear 30 days later
setInterval(() => db.execute({ sql: "DELETE FROM users WHERE bannedUntil = -1 AND bannedAt > 0 AND bannedAt <= ? AND COALESCE(customId, '') != 'knqw'", args: [Date.now() - PERM_DELETE_MS] }).catch(() => {}), 60 * 60 * 1000);

// ---------- the site itself ----------
app.get('/', (req, res) => res.redirect('/uniquetrading.html'));
app.use(express.static(path.join(__dirname, 'public')));

// last resort: any error that reaches here becomes a clean JSON 500 (and is written to the Render log)
app.use((err, req, res, next) => {
  console.error('ERROR on', req.method, req.path, '->', err && (err.stack || err.message || err));
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Server error. Try again.' });
});
(async () => {                       // one line in the Render log that says whether the database works
  try { await db.execute('SELECT COUNT(*) FROM users'); console.log('DB check: read OK'); } catch (e) { console.error('DB check: READ FAILED ->', e.message); }
  try { await db.execute('CREATE TABLE IF NOT EXISTS _healthcheck (t INTEGER)'); await db.execute('DELETE FROM _healthcheck'); console.log('DB check: write OK'); } catch (e) { console.error('DB check: WRITE FAILED ->', e.message, '(is TURSO_TOKEN a read-write token?)'); }
})();
const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Unique Trading backend listening on ' + port));
