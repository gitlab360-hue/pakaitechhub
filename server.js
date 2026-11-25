'use strict';
/* PAK AI TechHub — tiny zero-dependency server.
   Serves the site, stores admin changes (data/site.json), accepts image/audio uploads,
   stores contact-form leads and (optionally) emails them. Needs Node 18+. */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = +process.env.PORT || 3000, HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname, PUB = path.join(ROOT, 'public');
const DATA = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));
const UP = path.join(DATA, 'uploads'), BK = path.join(DATA, 'backups');
[DATA, UP, BK].forEach(d => fs.mkdirSync(d, { recursive: true }));
const F = { site: path.join(DATA, 'site.json'), secrets: path.join(DATA, 'secrets.json'), leads: path.join(DATA, 'leads.json') };

/* ---------- small helpers ---------- */
const readJSON = (f, def) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { return def; } };
const writeJSON = (f, o) => { const t = f + '.' + process.pid + '.tmp'; fs.writeFileSync(t, JSON.stringify(o, null, 2)); fs.renameSync(t, f); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const str = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
const escAttr = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const clientIp = req => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

const hashPw = p => { const s = crypto.randomBytes(16); return s.toString('hex') + ':' + crypto.scryptSync(p, s, 32).toString('hex'); };
const checkPw = (p, st) => {
  try { const [s, h] = st.split(':'); const x = crypto.scryptSync(p, Buffer.from(s, 'hex'), 32); return crypto.timingSafeEqual(x, Buffer.from(h, 'hex')); }
  catch (e) { return false; }
};

/* ---------- secrets (admin password hash, session key, SMTP) ---------- */
let secrets = readJSON(F.secrets, null);
if (!secrets) {
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  secrets = { sessionKey: crypto.randomBytes(32).toString('hex'), pw: hashPw(pw), smtp: {}, web3key: '' };
  writeJSON(F.secrets, secrets);
  console.log('\n  First run — admin password: ' + pw + '\n  (change it from Admin → Settings)\n');
} else if (process.env.ADMIN_PASSWORD && !checkPw(process.env.ADMIN_PASSWORD, secrets.pw)) {
  secrets.pw = hashPw(process.env.ADMIN_PASSWORD); writeJSON(F.secrets, secrets);
  console.log('  Admin password reset from ADMIN_PASSWORD environment variable.');
}
const saveSecrets = () => { writeJSON(F.secrets, secrets); try { fs.chmodSync(F.secrets, 0o600); } catch (e) {} };
try { fs.chmodSync(F.secrets, 0o600); } catch (e) {}

/* ---------- sessions (signed cookie, no server state) ---------- */
const sign = p => crypto.createHmac('sha256', secrets.sessionKey).update(p).digest('base64url');
function mkToken() { const p = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 3600e3 })).toString('base64url'); return p + '.' + sign(p); }
function authed(req) {
  const c = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith('sess='));
  if (!c) return false;
  const [p, s] = c.slice(5).split('.');
  if (!p || !s) return false;
  const e = sign(p);
  if (e.length !== s.length || !crypto.timingSafeEqual(Buffer.from(e), Buffer.from(s))) return false;
  try { return JSON.parse(Buffer.from(p, 'base64url').toString()).exp > Date.now(); } catch (x) { return false; }
}
const isHttps = req => !!req.socket.encrypted || String(req.headers['x-forwarded-proto'] || '').split(',')[0] === 'https';

/* ---------- tiny rate limiter ---------- */
const hits = new Map();
function limited(key, max, winMs) {
  const now = Date.now(), a = (hits.get(key) || []).filter(t => now - t < winMs);
  a.push(now); hits.set(key, a);
  if (hits.size > 5000) for (const [k, v] of hits) if (!v.some(t => now - t < winMs)) hits.delete(k);
  return a.length > max;
}

/* ---------- request / response ---------- */
function body(req, max) {
  return new Promise((resolve, reject) => {
    let n = 0, over = false; const b = [];
    req.on('data', c => { n += c.length; if (n > max) { over = true; b.length = 0; return; } if (!over) b.push(c); });
    req.on('end', () => over ? reject(Object.assign(new Error('too large'), { code: 413 })) : resolve(Buffer.concat(b)));
    req.on('error', reject);
  });
}
async function jsonBody(req, max) { try { const o = JSON.parse((await body(req, max)).toString('utf8')); return o && typeof o === 'object' ? o : null; } catch (e) { if (e.code === 413) throw e; return null; } }
function json(res, code, o, extra) {
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, extra || {}));
  res.end(JSON.stringify(o));
}

/* ---------- uploads: only real images / audio (checked by file signature) ---------- */
function sniff(b) {
  if (b.length < 12) return null;
  const s = (a, z) => b.toString('latin1', a, z);
  if (b[0] === 0x89 && s(1, 4) === 'PNG') return ['png', 'image/png'];
  if (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return ['jpg', 'image/jpeg'];
  if (s(0, 4) === 'GIF8') return ['gif', 'image/gif'];
  if (s(0, 4) === 'RIFF' && s(8, 12) === 'WEBP') return ['webp', 'image/webp'];
  if (b[0] === 0 && b[1] === 0 && b[2] === 1 && b[3] === 0) return ['ico', 'image/x-icon'];
  if (s(0, 4) === 'RIFF' && s(8, 12) === 'WAVE') return ['wav', 'audio/wav'];
  if (s(0, 3) === 'ID3' || (b[0] === 0xFF && (b[1] & 0xE0) === 0xE0)) return ['mp3', 'audio/mpeg'];
  if (s(0, 4) === 'OggS') return ['ogg', 'audio/ogg'];
  if (s(4, 8) === 'ftyp') return ['m4a', 'audio/mp4'];
  if (b[0] === 0x1A && b[1] === 0x45 && b[2] === 0xDF && b[3] === 0xA3) return ['webm', 'audio/webm'];
  return null;
}
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8',
  '.mp3': 'audio/mpeg', '.ogg': 'audio/ogg', '.wav': 'audio/wav', '.m4a': 'audio/mp4', '.webm': 'audio/webm', '.svg': 'image/svg+xml'
};

/* ---------- email (optional) ---------- */
async function notify(lead) {
  const site = readJSON(F.site, {}), brand = site.brand || 'PAK AI TechHub';
  const to = (secrets.smtp && secrets.smtp.to) || site.email;
  const subject = 'New inquiry — ' + brand;
  const text = ['New inquiry — ' + brand, '',
    'Name: ' + lead.first + ' ' + lead.last, 'Job title: ' + (lead.job || '-'), 'Country: ' + (lead.country || '-'),
    'Email: ' + lead.email, 'Phone: ' + (lead.phone || '-'), 'Industry: ' + (lead.industry || '-'),
    'Reaching out about: ' + (lead.reach || '-'), 'Product: ' + (lead.product || '-'), 'Via: ' + (lead.via || '-'), '', 'Message:', lead.msg || '-'].join('\n');
  try {
    if (secrets.web3key) {
      const r = await fetch('https://api.web3forms.com/submit', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, signal: AbortSignal.timeout(10000),
        body: JSON.stringify({ access_key: secrets.web3key, subject, from_name: lead.first + ' ' + lead.last, email: lead.email, message: text })
      });
      return r.ok ? { sent: true } : { sent: false, err: 'Web3Forms HTTP ' + r.status };
    }
    const s = secrets.smtp || {};
    if (s.host) {
      let nm; try { nm = require('nodemailer'); } catch (e) { return { sent: false, err: 'nodemailer install nahi hai — folder mein "npm install" chalayein' }; }
      const tr = nm.createTransport({ host: s.host, port: +s.port || 587, secure: !!s.secure, auth: s.user ? { user: s.user, pass: s.pass } : undefined, connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000 });
      await tr.sendMail({ from: s.from || s.user || to, to, replyTo: lead.email, subject, text });
      return { sent: true };
    }
    return { sent: false, err: 'Email delivery configured nahi (Admin → Settings)' };
  } catch (e) { return { sent: false, err: String(e.message || e).slice(0, 200) }; }
}

/* ---------- pages ---------- */
function seoTags(site, origin) {
  const brand = site.brand || 'PAK AI TechHub', title = brand + ' — ' + (site.tagline || 'AI for every business, everywhere.');
  const desc = str(site.heroSub || 'Browse AI products, try before you buy, and put them to work.', 200);
  let img = site.heroImage || site.logoUrl || '';
  if (img.startsWith('/') && !img.startsWith('//')) img = origin + img; else if (!/^https?:\/\//i.test(img)) img = '';
  return '<!--SEO-->\n<title>' + escAttr(title) + '</title>\n<meta name="description" content="' + escAttr(desc) + '">\n' +
    '<meta property="og:type" content="website">\n<meta property="og:title" content="' + escAttr(title) + '">\n<meta property="og:description" content="' + escAttr(desc) + '">\n' +
    (img ? '<meta property="og:image" content="' + escAttr(img) + '">\n<meta name="twitter:card" content="summary_large_image">\n' : '<meta name="twitter:card" content="summary">\n') + '<!--/SEO-->';
}
function servePage(req, res) {
  let html;
  try { html = fs.readFileSync(path.join(PUB, 'index.html'), 'utf8'); } catch (e) { res.writeHead(500); return res.end('public/index.html missing'); }
  const site = readJSON(F.site, {});
  const origin = (String(req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http')).split(',')[0]) + '://' + (req.headers.host || 'localhost');
  const boot = '<script>window.__CFG=' + JSON.stringify(site).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029') + '</script>';
  html = html.replace('<!--BOOT-->', () => boot).replace(/<!--SEO-->[\s\S]*?<!--\/SEO-->/, () => seoTags(site, origin));
  res.writeHead(200, {
    'Content-Type': MIME['.html'], 'Cache-Control': 'no-cache',
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data: blob: https:; media-src 'self' data: blob: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' mailto:"
  });
  res.end(html);
}
function serveFile(res, dir, rel, immutable) {
  const f = path.normalize(path.join(dir, rel));
  const ext = path.extname(f).toLowerCase();
  if (!f.startsWith(dir + path.sep) || rel.split(/[\\/]/).some(s => s.startsWith('.')) || !MIME[ext] || ext === '.html') { res.writeHead(404); return res.end('Not found'); }
  fs.stat(f, (e, st) => {
    if (e || !st.isFile()) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[ext], 'Content-Length': st.size, 'Cache-Control': immutable ? 'public, max-age=31536000, immutable' : 'no-cache' });
    fs.createReadStream(f).pipe(res);
  });
}

/* ---------- API ---------- */
async function api(req, res, p) {
  const m = req.method, ip = clientIp(req);
  if (m !== 'GET' && p !== '/api/contact' && req.headers['x-requested-with'] !== 'admin') return json(res, 403, { error: 'Forbidden' });
  const need = () => { if (!authed(req)) { json(res, 401, { error: 'Login required' }); return false; } return true; };

  if (p === '/api/ping' && m === 'GET') return json(res, 200, { server: true, authed: authed(req) });
  if (p === '/api/config' && m === 'GET') return json(res, 200, readJSON(F.site, {}));

  if (p === '/api/login' && m === 'POST') {
    if (limited('login:' + ip, 8, 10 * 60e3)) return json(res, 429, { error: 'Too many attempts' });
    const o = await jsonBody(req, 4000);
    if (!o || typeof o.password !== 'string' || !checkPw(o.password, secrets.pw)) { await sleep(500); return json(res, 401, { error: 'Wrong password' }); }
    return json(res, 200, { ok: true }, { 'Set-Cookie': 'sess=' + mkToken() + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200' + (isHttps(req) ? '; Secure' : '') });
  }
  if (p === '/api/logout' && m === 'POST') return json(res, 200, { ok: true }, { 'Set-Cookie': 'sess=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });

  if (p === '/api/config' && m === 'PUT') {
    if (!need()) return;
    const o = await jsonBody(req, 3 * 1024 * 1024);
    if (!o || Array.isArray(o)) return json(res, 400, { error: 'Invalid JSON' });
    try {
      if (fs.existsSync(F.site)) fs.copyFileSync(F.site, path.join(BK, 'site-' + Date.now() + '.json'));
      const old = fs.readdirSync(BK).filter(n => n.startsWith('site-')).sort();
      old.slice(0, Math.max(0, old.length - 30)).forEach(n => { try { fs.unlinkSync(path.join(BK, n)); } catch (e) {} });
    } catch (e) { /* backup is best-effort */ }
    o.updatedAt = new Date().toISOString();
    writeJSON(F.site, o);
    return json(res, 200, { ok: true });
  }

  if (p === '/api/upload' && m === 'POST') {
    if (!need()) return;
    const b = await body(req, 8 * 1024 * 1024), t = sniff(b);
    if (!t) return json(res, 415, { error: 'Sirf PNG, JPG, GIF, WEBP, ICO ya MP3/WAV/OGG/M4A audio allowed hai' });
    const name = crypto.randomBytes(10).toString('hex') + '.' + t[0];
    fs.writeFileSync(path.join(UP, name), b);
    return json(res, 200, { ok: true, url: '/uploads/' + name, type: t[1] });
  }

  if (p === '/api/leads') {
    if (!need()) return;
    if (m === 'GET') return json(res, 200, readJSON(F.leads, []));
    if (m === 'DELETE') { writeJSON(F.leads, []); return json(res, 200, { ok: true }); }
  }

  if (p === '/api/settings') {
    if (!need()) return;
    if (m === 'GET') { const s = secrets.smtp || {}; return json(res, 200, { smtp: { host: s.host || '', port: s.port || 587, secure: !!s.secure, user: s.user || '', from: s.from || '', to: s.to || '', passSet: !!s.pass }, web3keySet: !!secrets.web3key }); }
    if (m === 'PUT') {
      const o = await jsonBody(req, 8000); if (!o) return json(res, 400, { error: 'Invalid JSON' });
      const s = o.smtp || {}, cur = secrets.smtp || {};
      secrets.smtp = { host: str(s.host, 200), port: +s.port || 587, secure: !!s.secure, user: str(s.user, 200), pass: s.pass ? str(s.pass, 200) : (cur.pass || ''), from: str(s.from, 200), to: str(s.to, 200) };
      if (o.clearWeb3) secrets.web3key = ''; else if (typeof o.web3key === 'string' && o.web3key.trim()) secrets.web3key = str(o.web3key, 100);
      saveSecrets(); return json(res, 200, { ok: true });
    }
  }
  if (p === '/api/password' && m === 'PUT') {
    if (!need()) return;
    const o = await jsonBody(req, 2000);
    if (!o || !checkPw(String(o.current || ''), secrets.pw)) { await sleep(400); return json(res, 400, { error: 'Current password galat hai' }); }
    if (typeof o.next !== 'string' || o.next.length < 8) return json(res, 400, { error: 'Naya password kam az kam 8 characters ka ho' });
    secrets.pw = hashPw(o.next); saveSecrets(); return json(res, 200, { ok: true });
  }
  if (p === '/api/test-email' && m === 'POST') {
    if (!need()) return;
    const r = await notify({ first: 'Test', last: 'Message', email: (secrets.smtp && secrets.smtp.to) || 'test@example.com', msg: 'This is a test email from your admin panel.', via: 'admin-test' });
    return json(res, 200, r);
  }

  if (p === '/api/contact' && m === 'POST') {
    if (limited('contact:' + ip, 5, 10 * 60e3)) return json(res, 429, { error: 'Bohat zyada requests — thori der baad try karein' });
    const o = await jsonBody(req, 20000);
    if (!o) return json(res, 400, { error: 'Invalid request' });
    if (o.website) return json(res, 200, { ok: true }); // honeypot
    const lead = { id: crypto.randomUUID(), at: new Date().toISOString(), via: str(o.via, 20) || 'email' };
    ['first', 'last', 'job', 'country', 'email', 'phone', 'industry', 'reach', 'product'].forEach(k => lead[k] = str(o[k], 200));
    lead.msg = str(o.msg, 3000);
    if (!lead.first || !lead.last || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(lead.email)) return json(res, 400, { error: 'Naam aur sahi email zaroori hai' });
    const L = readJSON(F.leads, []); L.unshift(lead); writeJSON(F.leads, L.slice(0, 2000));
    const r = await notify(lead);
    return json(res, 200, { ok: true, emailed: r.sent });
  }
  return json(res, 404, { error: 'Not found' });
}

/* ---------- server ---------- */
const server = http.createServer(async (req, res) => {
  try {
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    let p; try { p = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch (e) { res.writeHead(400); return res.end('Bad request'); }
    if (p.startsWith('/api/')) return await api(req, res, p);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    if (p.startsWith('/uploads/')) return serveFile(res, UP, p.slice(9), true);
    if (p === '/' || p === '/index.html') return servePage(req, res);
    return serveFile(res, PUB, p.slice(1), false);
  } catch (e) {
    if (e && e.code !== 413) console.error(e);
    if (!res.headersSent) json(res, e && e.code === 413 ? 413 : 500, { error: e && e.code === 413 ? 'File bohat bari hai' : 'Server error' }); else res.end();
  }
});
server.listen(PORT, HOST, () => console.log('PAK AI TechHub running → http://localhost:' + PORT + '   (data folder: ' + DATA + ')'));
