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
const db = createClient({ url: process.env.TURSO_URL, authToken: process.env.TURSO_TOKEN });

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);                 // Render sits behind a proxy: req.ip is the real visitor IP
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
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
  await run(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, username TEXT, createdAt INTEGER, expiresAt INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS signup_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, createdAt INTEGER)`);
  await run(`ALTER TABLE users ADD COLUMN passwordHash TEXT`);
  await run(`ALTER TABLE users ADD COLUMN lastIp TEXT`);
  await run(`ALTER TABLE users ADD COLUMN joinedAt INTEGER`);
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
async function startSession(res, username) {
  const sid = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  await db.execute({ sql: 'INSERT INTO sessions (id, username, createdAt, expiresAt) VALUES (?, ?, ?, ?)', args: [sid, username, now, now + SESSION_MS] });
  res.cookie('sid', sid, { httpOnly: true, secure: process.env.NODE_ENV === 'production' || process.env.RENDER === 'true', sameSite: 'lax', maxAge: SESSION_MS, path: '/' });
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
app.get('/api/health', (req, res) => res.json({ ok: true }));

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
    res.cookie('ut_su', String(now), { httpOnly: true, sameSite: 'lax', maxAge: DAY, path: '/', secure: process.env.NODE_ENV === 'production' || process.env.RENDER === 'true' });
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
      await db.execute({ sql: 'UPDATE users SET passwordHash = ? WHERE username = ?', args: [await bcrypt.hash(password, 12), u.username] });
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
  res.clearCookie('sid', { path: '/' });
  res.json({ ok: true });
});

// ---------- the site itself ----------
app.get('/', (req, res) => res.redirect('/uniquetrading.html'));
app.use(express.static(path.join(__dirname, 'public')));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Unique Trading backend listening on ' + port));
