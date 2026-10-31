// MedTrack backend: Node.js + Express + SQLite (better-sqlite3)
const express = require('express'), Database = require('better-sqlite3'), crypto = require('crypto'), path = require('path');
try { // optional settings file: copy .env.example to .env and edit it
  require('fs').readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => {
    const m = l.match(/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
} catch { /* no .env file, that is fine */ }
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'medtrack.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, salt TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER);
CREATE TABLE IF NOT EXISTS medicines(id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, disease TEXT, qty REAL, unit TEXT,
  times TEXT, start_date TEXT, end_date TEXT, instructions TEXT, stock INTEGER);
CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY, med_id INTEGER, user_id INTEGER, date TEXT, time TEXT, status TEXT,
  UNIQUE(med_id, date, time));
`);

const app = express();
app.use((q, r, next) => express.json({ limit: q.path === '/api/bill/scan' ? '8mb' : '50kb' })(q, r, next)); // bigger limit only for bill uploads
// ---- Security: headers, HTTPS redirect, rate limiting ----
app.set('trust proxy', process.env.TRUST_PROXY ? 1 : false); // TRUST_PROXY=1 when behind Render, nginx, Cloudflare...
app.use((q, r, next) => {
  if (process.env.FORCE_HTTPS && !q.secure) return r.redirect(301, 'https://' + q.headers.host + q.url);
  r.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' });
  if (q.secure) r.set('Strict-Transport-Security', 'max-age=31536000');
  next();
});
const hits = new Map();
const limit = (max, ms) => (q, r, next) => {
  const k = q.ip + '|' + max, now = Date.now(), h = (hits.get(k) || []).filter(t => now - t < ms);
  if (h.length >= max) return r.status(429).json({ error: 'Too many attempts. Please wait a few minutes and try again.' });
  h.push(now); hits.set(k, h); next();
};
setInterval(() => hits.clear(), 3600000).unref();
app.use('/api', limit(300, 60000)); // general limit per IP
app.use(['/api/login', '/api/register', '/api/forgot', '/api/reset'], limit(10, 15 * 60000)); // strict limit on sign-in routes
app.use(express.static(path.join(__dirname, 'public')));

const T = /^([01]\d|2[0-3]):[0-5]\d$/, D = /^\d{4}-\d{2}-\d{2}$/;
const GRACE = 60; // minutes after the scheduled time before a dose counts as missed
const mins = t => +t.slice(0, 2) * 60 + +t.slice(3);
const addDays = (d, n) => { const t = new Date(d + 'T00:00:00Z'); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); };
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const session = uid => { const t = crypto.randomBytes(24).toString('hex'); db.prepare('INSERT INTO sessions VALUES(?,?)').run(t, uid); return t; };

// ---- Password rules and "confirm it's you" check for sensitive actions ----
const STRONG = /^(?=.*[A-Za-z])(?=.*\d).{8,}$/; // 8+ characters, at least one letter and one number
const WEAK_MSG = 'Password must have 8+ characters with at least one letter and one number.';
const pwOk = (uid, pw) => {
  const u = db.prepare('SELECT salt,hash FROM users WHERE id=?').get(uid);
  return !!u && typeof pw === 'string' && crypto.timingSafeEqual(Buffer.from(hash(pw, u.salt)), Buffer.from(u.hash));
};
const fails = new Map();
function need(q, r) { // true only if the request carries the signed-in user's correct password
  const f = (fails.get(q.uid) || []).filter(t => Date.now() - t < 15 * 60000);
  if (f.length >= 5) { r.status(429).json({ error: 'Too many wrong passwords. Please wait 15 minutes.' }); return false; }
  if (pwOk(q.uid, q.body.password)) return true;
  f.push(Date.now()); fails.set(q.uid, f);
  r.status(403).json({ error: 'Your password is wrong. Please try again.' }); return false;
}

// ---- Auth ----
app.post('/api/register', (q, r) => {
  const { name, email, password } = q.body;
  if (!name?.trim() || !/^\S+@\S+$/.test(email || '') || !STRONG.test(password || ''))
    return r.status(400).json({ error: 'Enter your name and a valid email. ' + WEAK_MSG });
  const salt = crypto.randomBytes(16).toString('hex');
  try {
    const id = db.prepare('INSERT INTO users(name,email,salt,hash) VALUES(?,?,?,?)').run(name.trim(), email.toLowerCase(), salt, hash(password, salt)).lastInsertRowid;
    r.json({ token: session(id), name: name.trim() });
  } catch { r.status(409).json({ error: 'That email is already registered. Sign in instead.' }); }
});
app.post('/api/login', (q, r) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((q.body.email || '').toLowerCase());
  const ok = u && crypto.timingSafeEqual(Buffer.from(hash(q.body.password || '', u.salt)), Buffer.from(u.hash));
  if (!ok) return r.status(400).json({ error: 'Email or password is wrong.' });
  r.json({ token: session(u.id), name: u.name });
});
// ---- Email (optional): password reset and caregiver alerts ----
const mailer = process.env.SMTP_URL && process.env.MAIL_FROM ? require('nodemailer').createTransport(process.env.SMTP_URL) : null;
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
db.exec('CREATE TABLE IF NOT EXISTS resets(hash TEXT PRIMARY KEY, user_id INTEGER, expires INTEGER)');

// ---- Password reset: one-time link, valid 30 minutes, only its hash is stored ----
app.post('/api/forgot', (q, r) => {
  const u = db.prepare('SELECT id,name,email FROM users WHERE email=?').get((q.body.email || '').toLowerCase());
  if (u) {
    const token = crypto.randomBytes(24).toString('hex');
    db.prepare('INSERT INTO resets VALUES(?,?,?)').run(sha(token), u.id, Date.now() + 30 * 60000);
    const link = `${process.env.BASE_URL || q.protocol + '://' + q.headers.host}/?reset=${token}`; // set BASE_URL in production
    if (mailer) mailer.sendMail({ from: process.env.MAIL_FROM, to: u.email, subject: 'Reset your MedTrack password',
      text: `Hi ${u.name}, open this link within 30 minutes to choose a new password:\n${link}\nIf you did not ask for this, ignore this email.` })
      .catch(e => console.error('Email failed:', e.message));
    else console.log('Password reset link (email is not set up):', link);
  }
  r.json({ ok: true }); // same answer whether or not the email exists
});
app.post('/api/reset', (q, r) => {
  const { token, password } = q.body;
  const row = db.prepare('SELECT * FROM resets WHERE hash=? AND expires>?').get(sha(token || ''), Date.now());
  if (!row || !STRONG.test(password || '')) return r.status(400).json({ error: row ? WEAK_MSG : 'This reset link is invalid or expired.' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET salt=?,hash=? WHERE id=?').run(salt, hash(password, salt), row.user_id);
  db.prepare('DELETE FROM resets WHERE user_id=?').run(row.user_id);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(row.user_id); // signs out every device
  r.json({ ok: true });
});

app.use('/api', (q, r, next) => {
  const s = db.prepare('SELECT user_id FROM sessions WHERE token=?').get((q.headers.authorization || '').slice(7));
  if (!s) return r.status(401).json({ error: 'Please sign in.' });
  q.uid = s.user_id; next();
});

// ---- Schedule engine: every dose of a day with its live status ----
// taken | skipped (user action) | upcoming | due (15 min before to GRACE after) | missed (auto-detected)
function dayDoses(uid, date, today, now) {
  const meds = db.prepare('SELECT * FROM medicines WHERE user_id=? AND start_date<=? AND (end_date IS NULL OR end_date>=?)').all(uid, date, date);
  const logs = db.prepare('SELECT med_id,time,status FROM logs WHERE user_id=? AND date=?').all(uid, date);
  return meds.flatMap(m => JSON.parse(m.times).map(time => {
    const l = logs.find(x => x.med_id === m.id && x.time === time);
    if (l?.status === 'na') return null; // dose time had already passed when the medicine was added
    const status = l ? l.status : date < today ? 'missed' : date > today ? 'upcoming'
      : (d => d > 15 ? 'upcoming' : d >= -GRACE ? 'due' : 'missed')(mins(time) - now);
    return { med_id: m.id, name: m.name, disease: m.disease, qty: m.qty, unit: m.unit, instructions: m.instructions, time, status };
  })).filter(Boolean).sort((a, b) => a.time.localeCompare(b.time));
}

app.get('/api/today', (q, r) => {
  const { date, now } = q.query; // the browser sends its local date/time, so time zones just work
  if (!D.test(date) || !T.test(now)) return r.status(400).json({ error: 'Bad date or time.' });
  const doses = dayDoses(q.uid, date, date, mins(now)), week = [];
  for (let i = 6; i >= 0; i--) {
    const d = addDays(date, -i), x = dayDoses(q.uid, d, date, mins(now)).filter(y => ['taken', 'missed', 'skipped'].includes(y.status));
    week.push({ date: d, taken: x.filter(y => y.status === 'taken').length, total: x.length });
  }
  const low = db.prepare('SELECT name,stock FROM medicines WHERE user_id=? AND stock IS NOT NULL AND stock<=5').all(q.uid);
  r.json({ date, doses, week, low });
});

// ---- Medicines ----
app.get('/api/medicines', (q, r) =>
  r.json(db.prepare('SELECT * FROM medicines WHERE user_id=? ORDER BY name').all(q.uid).map(m => ({ ...m, times: JSON.parse(m.times) }))));

app.post('/api/medicines', (q, r) => {
  const b = q.body, times = [...new Set(b.times || [])].filter(t => T.test(t)).sort();
  if (!b.name?.trim() || !(b.qty > 0) || !times.length || !D.test(b.start_date))
    return r.status(400).json({ error: 'Add a name, a quantity above 0, at least one time and a start date.' });
  const id = db.prepare('INSERT INTO medicines(user_id,name,disease,qty,unit,times,start_date,end_date,instructions,stock,info) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
    .run(q.uid, b.name.trim(), (b.disease || '').trim(), +b.qty, b.unit || 'tablet(s)', JSON.stringify(times), b.start_date,
      D.test(b.end_date || '') ? b.end_date : null, b.instructions || 'Any time', b.stock > 0 ? +b.stock : null, b.info ? String(b.info).slice(0, 1500) : null).lastInsertRowid;
  // Doses earlier today than "now" are not counted as missed for a brand-new medicine
  if (b.start_date === b.today && T.test(b.now || ''))
    times.filter(t => mins(t) < mins(b.now) - GRACE).forEach(t =>
      db.prepare("INSERT OR IGNORE INTO logs(med_id,user_id,date,time,status) VALUES(?,?,?,?,'na')").run(id, q.uid, b.start_date, t));
  r.json({ id });
});

app.delete('/api/medicines/:id', (q, r) => {
  if (!need(q, r)) return; // password needed to delete a medicine
  db.prepare('DELETE FROM logs WHERE med_id=? AND user_id=?').run(q.params.id, q.uid);
  db.prepare('DELETE FROM medicines WHERE id=? AND user_id=?').run(q.params.id, q.uid);
  r.json({ ok: true });
});

// ---- Log a dose as taken / skipped (also reduces stock) ----
app.post('/api/doses', (q, r) => {
  const { med_id, date, time, status } = q.body;
  const m = db.prepare('SELECT * FROM medicines WHERE id=? AND user_id=?').get(med_id, q.uid);
  if (!m || !D.test(date) || !JSON.parse(m.times).includes(time) || !['taken', 'skipped'].includes(status))
    return r.status(400).json({ error: 'Invalid dose.' });
  const prev = db.prepare('SELECT status FROM logs WHERE med_id=? AND date=? AND time=?').get(med_id, date, time);
  db.prepare('INSERT INTO logs(med_id,user_id,date,time,status) VALUES(?,?,?,?,?) ON CONFLICT(med_id,date,time) DO UPDATE SET status=excluded.status')
    .run(med_id, q.uid, date, time, status);
  if (status === 'taken' && prev?.status !== 'taken' && m.stock > 0) db.prepare('UPDATE medicines SET stock=stock-1 WHERE id=?').run(med_id);
  r.json({ ok: true });
});

// ---- Refill: add doses to stock ----
app.post('/api/medicines/:id/refill', (q, r) => {
  const n = Math.floor(+q.body.amount);
  if (!(n > 0 && n < 10000)) return r.status(400).json({ error: 'Enter a number of doses above 0.' });
  db.prepare('UPDATE medicines SET stock=COALESCE(stock,0)+? WHERE id=? AND user_id=?').run(n, q.params.id, q.uid);
  r.json({ ok: true });
});

// ---- Background alerts (Web Push): reach the patient even when MedTrack is closed ----
const webpush = require('web-push');
db.exec(`CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS pushes(endpoint TEXT PRIMARY KEY, user_id INTEGER, sub TEXT, tz TEXT);
CREATE TABLE IF NOT EXISTS sent(key TEXT PRIMARY KEY, date TEXT);`);
let kv = db.prepare("SELECT v FROM kv WHERE k='vapid'").get();
if (!kv) { kv = { v: JSON.stringify(webpush.generateVAPIDKeys()) }; db.prepare("INSERT INTO kv VALUES('vapid',?)").run(kv.v); }
const VAPID = JSON.parse(kv.v); // generated once, kept in the database
webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@example.com', VAPID.publicKey, VAPID.privateKey);

app.get('/api/push-key', (q, r) => r.json({ key: VAPID.publicKey }));
app.post('/api/push', (q, r) => {
  const { sub, tz } = q.body;
  try { if (!sub?.endpoint || typeof tz !== 'string') throw 0; new Intl.DateTimeFormat('en', { timeZone: tz }); }
  catch { return r.status(400).json({ error: 'Invalid alert subscription.' }); }
  db.prepare('INSERT OR REPLACE INTO pushes VALUES(?,?,?,?)').run(sub.endpoint, q.uid, JSON.stringify(sub), tz);
  r.json({ ok: true });
});
app.delete('/api/push', (q, r) => {
  db.prepare('DELETE FROM pushes WHERE endpoint=? AND user_id=?').run(q.body.endpoint, q.uid);
  r.json({ ok: true });
});

function localNow(tz) { // the patient's own date and time, from the time zone their browser reported
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-CA', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit',
    day: '2-digit', hour: '2-digit', minute: '2-digit' }).formatToParts(new Date()).map(x => [x.type, x.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, now: `${p.hour}:${p.minute}` };
}
setInterval(() => { // every minute: push each newly due or missed dose once per device
  for (const p of db.prepare('SELECT * FROM pushes').all()) {
    let t; try { t = localNow(p.tz); } catch { continue; }
    db.prepare('DELETE FROM sent WHERE date<?').run(addDays(t.date, -2));
    for (const x of dayDoses(p.user_id, t.date, t.date, mins(t.now)).filter(y => ['due', 'missed'].includes(y.status))) {
      const key = [p.endpoint, t.date, x.med_id, x.time, x.status].join('|');
      if (db.prepare('SELECT 1 FROM sent WHERE key=?').get(key)) continue;
      db.prepare('INSERT INTO sent VALUES(?,?)').run(key, t.date);
      webpush.sendNotification(JSON.parse(p.sub), JSON.stringify({
        title: x.status === 'due' ? 'Time for ' + x.name : 'Missed dose: ' + x.name,
        body: `${x.qty} ${x.unit} · scheduled ${x.time}`
      })).catch(e => { if ([404, 410].includes(e.statusCode)) db.prepare('DELETE FROM pushes WHERE endpoint=?').run(p.endpoint); });
    }
  }
}, 60000);

// ---- Caregiver: read-only link, plus email and SMS when a dose is missed ----
db.exec('CREATE TABLE IF NOT EXISTS shares(user_id INTEGER PRIMARY KEY, token TEXT UNIQUE, email TEXT, phone TEXT, tz TEXT)');
const sms = (to, body) => process.env.TWILIO_SID && process.env.TWILIO_TOKEN && process.env.TWILIO_FROM &&
  fetch(`https://api.twilio.com/2010-04-01/Accounts/${process.env.TWILIO_SID}/Messages.json`, { method: 'POST',
    headers: { Authorization: 'Basic ' + Buffer.from(process.env.TWILIO_SID + ':' + process.env.TWILIO_TOKEN).toString('base64') },
    body: new URLSearchParams({ To: to, From: process.env.TWILIO_FROM, Body: body }) }).catch(e => console.error('SMS failed:', e.message));

app.get('/api/share', (q, r) => r.json(db.prepare('SELECT token,email,phone FROM shares WHERE user_id=?').get(q.uid) || {}));
app.post('/api/share', (q, r) => {
  if (!need(q, r)) return; // password needed to share health data
  const email = (q.body.email || '').trim(), phone = (q.body.phone || '').replace(/[\s-]/g, ''), tz = q.body.tz;
  if (email && !/^\S+@\S+$/.test(email)) return r.status(400).json({ error: 'Enter a valid caregiver email, or leave it empty.' });
  if (phone && !/^\+\d{8,15}$/.test(phone)) return r.status(400).json({ error: 'Phone must include the country code, like +14155550123.' });
  try { new Intl.DateTimeFormat('en', { timeZone: tz }); } catch { return r.status(400).json({ error: 'Invalid time zone.' }); }
  const old = db.prepare('SELECT token FROM shares WHERE user_id=?').get(q.uid);
  const token = old && !q.body.renew ? old.token : crypto.randomBytes(18).toString('hex'); // "New link" kills the old one
  db.prepare('INSERT OR REPLACE INTO shares VALUES(?,?,?,?,?)').run(q.uid, token, email || null, phone || null, tz);
  r.json({ token, email, phone });
});
app.delete('/api/share', (q, r) => { if (!need(q, r)) return; db.prepare('DELETE FROM shares WHERE user_id=?').run(q.uid); r.json({ ok: true }); });

app.get('/shared/:token', (q, r) => { // public, but only reachable with the secret token
  const s = db.prepare('SELECT s.user_id, s.tz, u.name FROM shares s JOIN users u ON u.id=s.user_id WHERE s.token=?').get(q.params.token);
  if (!s) return r.status(404).json({ error: 'This link is no longer active.' });
  const t = localNow(s.tz);
  r.json({ name: s.name, ...t, doses: dayDoses(s.user_id, t.date, t.date, mins(t.now)).map(({ disease, ...x }) => x) });
});

setInterval(() => { // every minute: tell the caregiver once about each newly missed dose
  for (const s of db.prepare('SELECT s.*, u.name FROM shares s JOIN users u ON u.id=s.user_id WHERE s.email IS NOT NULL OR s.phone IS NOT NULL').all()) {
    let t; try { t = localNow(s.tz); } catch { continue; }
    db.prepare('DELETE FROM sent WHERE date<?').run(addDays(t.date, -2));
    for (const x of dayDoses(s.user_id, t.date, t.date, mins(t.now)).filter(y => y.status === 'missed')) {
      const key = ['care', s.user_id, t.date, x.med_id, x.time].join('|');
      if (db.prepare('SELECT 1 FROM sent WHERE key=?').get(key)) continue;
      db.prepare('INSERT INTO sent VALUES(?,?)').run(key, t.date);
      const text = `MedTrack: ${s.name} has not logged ${x.name} (${x.qty} ${x.unit}) scheduled for ${x.time}. Please check in with them.`;
      if (s.email && mailer) mailer.sendMail({ from: process.env.MAIL_FROM, to: s.email, subject: `${s.name} missed a dose`, text })
        .catch(e => console.error('Email failed:', e.message));
      if (s.phone) sms(s.phone, text);
    }
  }
}, 60000);

// ---- Medicine bill scan: photo or PDF in, list of medicines plus plain-language info out ----
try { db.exec('ALTER TABLE medicines ADD COLUMN info TEXT'); } catch { /* column already exists */ }
const SCAN_PROMPT = `This is a pharmacy bill or prescription. List every medicine on it. Return ONLY a JSON array. Each item has:
name (as printed), strength (like "500 mg" or null), form (one of "tablet(s)","capsule(s)","ml","drop(s)","puff(s)","unit(s)", or null),
qty_per_dose (number or null), times_per_day (number or null), instructions (like "After food" or null),
purpose (what this medicine is generally used for, plain words, max 20 words), why (one simple sentence on why a doctor may prescribe it),
caution (one short general tip, or null).
Copy dose and frequency ONLY if they are printed on the document. Never guess them. If nothing is readable return [].`;
app.post('/api/bill/scan', async (q, r) => {
  const { data, mime } = q.body;
  if (!data || !['image/jpeg', 'image/png', 'image/webp', 'application/pdf'].includes(mime))
    return r.status(400).json({ error: 'Upload a photo (JPG, PNG, WebP) or a PDF of the bill.' });
  if (!process.env.ANTHROPIC_API_KEY)
    return r.status(503).json({ error: 'Bill scanning is not set up on this server (ANTHROPIC_API_KEY). You can add the medicines by hand.' });
  try {
    const block = { type: mime === 'application/pdf' ? 'document' : 'image', source: { type: 'base64', media_type: mime, data } };
    const res = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST',
      headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: process.env.CLAUDE_MODEL || 'claude-sonnet-5-5', max_tokens: 3000, messages: [{ role: 'user', content: [block, { type: 'text', text: SCAN_PROMPT }] }] }) });
    if (!res.ok) throw new Error('scanner');
    const txt = (await res.json()).content.map(c => c.text || '').join('');
    const items = JSON.parse(txt.slice(txt.indexOf('['), txt.lastIndexOf(']') + 1));
    r.json({ items: items.filter(i => i && i.name).slice(0, 30) });
  } catch { r.status(502).json({ error: 'Could not read the bill. Try a clearer, well-lit photo, or add the medicines by hand.' }); }
});

// ---- Account security: change password, sign out everywhere, delete account ----
app.post('/api/password', (q, r) => {
  if (!need(q, r)) return;
  if (!STRONG.test(q.body.newPassword || '')) return r.status(400).json({ error: WEAK_MSG });
  const salt = crypto.randomBytes(16).toString('hex'), me = (q.headers.authorization || '').slice(7);
  db.prepare('UPDATE users SET salt=?,hash=? WHERE id=?').run(salt, hash(q.body.newPassword, salt), q.uid);
  db.prepare('DELETE FROM sessions WHERE user_id=? AND token<>?').run(q.uid, me); // other devices must sign in again
  r.json({ ok: true });
});
app.post('/api/logout-all', (q, r) => { db.prepare('DELETE FROM sessions WHERE user_id=?').run(q.uid); r.json({ ok: true }); });
app.post('/api/account/delete', (q, r) => {
  if (!need(q, r)) return;
  for (const t of ['logs', 'medicines', 'shares', 'pushes', 'sessions', 'resets']) db.prepare(`DELETE FROM ${t} WHERE user_id=?`).run(q.uid);
  db.prepare('DELETE FROM users WHERE id=?').run(q.uid);
  r.json({ ok: true });
});

// ---- Start: HTTPS when a certificate is provided, otherwise HTTP ----
const PORT = process.env.PORT || 3000;
if (process.env.HTTPS_KEY && process.env.HTTPS_CERT) {
  const fs = require('fs');
  require('https').createServer({ key: fs.readFileSync(process.env.HTTPS_KEY), cert: fs.readFileSync(process.env.HTTPS_CERT) }, app)
    .listen(PORT, () => console.log('MedTrack running at https://localhost:' + PORT));
} else app.listen(PORT, () => console.log('MedTrack running at http://localhost:' + PORT + ' (set HTTPS_KEY and HTTPS_CERT to use HTTPS)'));
