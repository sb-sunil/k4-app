// Mobile Pass K4 v2 – free serverless API. Stores all data in ONE file of a PRIVATE GitHub repo.
// Runs on Cloudflare Workers (free).
// Secrets:   GITHUB_TOKEN (required), RECOVERY_KEY (optional – lets the owner reset an admin PIN if every admin is locked out)
// Variables: GH_REPO ("owner/repo", required), GH_PATH (default data.json), ALLOWED_ORIGIN (your site URL, recommended),
//            ITER (optional PBKDF2 rounds 10000-100000; default 10000 = safe for the free plan's 10 ms CPU limit)
const DAY = 864e5, HR = 36e5, enc = new TextEncoder();
const bad = m => { const e = new Error(m); e.user = true; throw e; };
const clean = s => String(s == null ? '' : s).trim();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const same = (a, b) => { a = String(a); b = String(b); let r = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) r |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return r === 0; };

export default {
  async fetch(req, env) {
    const cors = { 'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*', 'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type', 'Vary': 'Origin' };
    const out = (o) => new Response(JSON.stringify(o), { headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    if (req.method !== 'POST') return new Response('Mobile Pass K4 API is running.', { headers: cors });
    try {
      const { fn, a } = await req.json();
      if (!Object.prototype.hasOwnProperty.call(F, fn)) bad('Unknown request.');
      return out({ ok: true, data: await run(env, fn, a || {}) });
    } catch (e) {
      if (!e.user) console.error(e);
      return out({ ok: false, error: e.user ? e.message : 'Server busy or misconfigured. Try again.' });
    }
  }
};

// ---------- GitHub storage (optimistic locking with the file sha + ETag cache) ----------
const gh = (env, path, init = {}) => fetch(`https://api.github.com/repos/${env.GH_REPO}/contents/${path}`, { ...init, headers: {
  Authorization: 'Bearer ' + env.GITHUB_TOKEN, Accept: 'application/vnd.github+json', 'User-Agent': 'k4-pass',
  'X-GitHub-Api-Version': '2022-11-28', 'Cache-Control': 'no-cache', ...(init.headers || {}) } });
const b64d = s => new TextDecoder().decode(Uint8Array.from(atob(s.replace(/\n/g, '')), c => c.charCodeAt(0)));
const b64e = s => { let t = ''; for (const b of enc.encode(s)) t += String.fromCharCode(b); return btoa(t); };

let CACHE = null; // { path, etag, json, sha } – a 304 reply from GitHub does not count against the API rate limit
async function load(env) {
  const path = env.GH_PATH || 'data.json';
  const r = await gh(env, path, CACHE && CACHE.path === path ? { headers: { 'If-None-Match': CACHE.etag } } : {});
  if (r.status === 304 && CACHE) return { d: JSON.parse(CACHE.json), sha: CACHE.sha };
  if (r.status === 404) { CACHE = null; return { d: { users: {}, sessions: {} }, sha: undefined }; }
  if (!r.ok) throw new Error('GitHub read failed ' + r.status);
  const j = await r.json(), json = b64d(j.content), etag = r.headers.get('etag');
  CACHE = etag ? { path, etag, json, sha: j.sha } : null;
  return { d: JSON.parse(json), sha: j.sha };
}
async function store(env, d, sha, msg) {
  CACHE = null;
  const r = await gh(env, env.GH_PATH || 'data.json', { method: 'PUT', body: JSON.stringify({
    message: 'k4: ' + msg, content: b64e(JSON.stringify(d)), ...(sha ? { sha } : {}) }) });
  if (r.status === 409 || r.status === 422) { const e = new Error('conflict'); e.conflict = true; throw e; }
  if (!r.ok) throw new Error('GitHub write failed ' + r.status);
}
async function run(env, fn, a) {
  for (let i = 0; i < 5; i++) {
    const { d, sha } = await load(env), before = JSON.stringify(d);
    purge(d);
    const res = await F[fn](d, a, env);
    if (JSON.stringify(d) === before) return res;       // nothing changed: no commit
    try { await store(env, d, sha, fn); return res; }
    catch (e) { if (!e.conflict) throw e; }              // someone else wrote first: redo on fresh data
  }
  bad('Server busy. Please try again.');
}

// ---------- wrong-attempt lockout (kept in memory so failed tries never create GitHub commits) ----------
const TRY = new Map();
function tryCheck(key) { const t = TRY.get(key); if (t && t.until > Date.now()) bad('Too many wrong tries. Try again after 15 minutes.'); }
function tryFail(key) { const now = Date.now(); let t = TRY.get(key);
  if (!t || (t.until && t.until <= now)) t = { n: 0, until: 0 };
  if (++t.n >= 5) { t.until = now + 15 * 60000; t.n = 0; }
  TRY.set(key, t); if (TRY.size > 5000) TRY.delete(TRY.keys().next().value); }
const tryOk = key => TRY.delete(key);

// ---------- security helpers ----------
const iters = env => Math.min(100000, Math.max(10000, parseInt(env && env.ITER, 10) || 10000));
async function hash(pin, salt, it) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: it || 10000 }, k, 256));
}
async function secret(pin, env) { const salt = crypto.randomUUID(), it = iters(env); return { salt, hash: await hash(pin, salt, it), it }; }
function session(d, uid) {
  const now = Date.now();
  for (const t in d.sessions) if (now - d.sessions[t].t > 30 * DAY) delete d.sessions[t];
  const t = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, '');
  d.sessions[t] = { u: uid, t: now };
  const mine = Object.entries(d.sessions).filter(([, s]) => s.u === uid).sort((x, y) => y[1].t - x[1].t);
  for (const [tk] of mine.slice(5)) delete d.sessions[tk];       // max 5 logged-in devices per ID
  return t;
}
function me(d, token) {
  const tk = String(token), s = d.sessions[tk], u = s && d.users[s.u];
  if (!s || !u) { if (d.gone && d.gone[tk]) bad('Your temporary pass has expired and the account was removed. Contact your admin.'); bad('Session expired. Please log in again.'); }
  if (Date.now() - s.t > 30 * DAY) bad('Session expired. Please log in again.');
  return { id: s.u, u };
}
function admin(d, t) { const m = me(d, t); if (m.u.role !== 'admin') bad('Admin only.'); return m; }
const up = s => clean(s).toUpperCase();
const proper = s => clean(s).toLowerCase().replace(/(^|[\s.'-])(\p{L})/gu, (m, a, b) => a + b.toUpperCase()).slice(0, 60);
const okId = id => /^[A-Z0-9_.-]{3,20}$/.test(id);
const luhn = s => { let n = 0; for (let i = 0; i < 15; i++) { let x = +s[14 - i]; if (i % 2) { x *= 2; if (x > 9) x -= 9; } n += x; } return n % 10 === 0; };
const canSet = u => !u.hash || (!!u.resetOk && Date.now() - (u.resetOkAt || 0) < HR);   // reset approval is valid for 1 hour
const blank = (name, role) => ({ name, salt: null, hash: null, it: null, role, passType: 'none', count: 0, expiry: null, approvedBy: null,
  approvedAt: null, devices: [], devReq: {}, vc: null, resetReq: null, resetOk: false, resetOkAt: null });
function log(d, by, act, to) { (d.log = d.log || []).unshift({ t: Date.now(), by, act, to: to || '' }); d.log.length = Math.min(d.log.length, 300); }
function dropSessions(d, id) { for (const t in d.sessions) if (d.sessions[t].u === id) delete d.sessions[t]; }
function purge(d) { // keep IDs UPPERCASE and auto-remove expired temporary users (after the optional grace period)
  d.settings = d.settings || { grace: 0 }; d.gone = d.gone || {};
  for (const id of Object.keys(d.users)) { const U = id.toUpperCase(); if (U !== id) { d.users[U] = d.users[id]; delete d.users[id];
    for (const t in d.sessions) if (d.sessions[t].u === id) d.sessions[t].u = U; } }
  const now = Date.now(), grace = Math.max(0, Number(d.settings.grace) || 0) * HR;
  for (const id of Object.keys(d.users)) { const u = d.users[id];
    if (u.role === 'guard') u.role = 'user';
    if (u.role === 'user' && u.passType === 'temp' && u.expiry && u.expiry + grace <= now) {
      for (const t in d.sessions) if (d.sessions[t].u === id) d.gone[t] = now;
      delete d.users[id]; dropSessions(d, id); log(d, 'System', 'Temporary user removed (pass expired)', id + ' ' + u.name); } }
  for (const t in d.gone) if (now - d.gone[t] > 7 * DAY) delete d.gone[t];
}
const pub = (u, full) => { const { name, role, passType, count, expiry, approvedBy, approvedAt, devices, devReq } = u;
  return { name, role, passType, count, expiry, approvedBy, approvedAt, devices, devReq: devReq || {}, pinSet: !!u.hash,
    ...(full ? { resetReq: u.resetReq, resetOk: !!u.resetOk && canSet(u), resetOkAt: u.resetOkAt, hasCode: !!u.vc } : {}) }; };

// ---------- API ----------
const F = {
  async k4_state(d) { return Object.keys(d.users).length > 0; },

  async k4_setup(d, a, env) {
    if (Object.keys(d.users).length) bad('Setup already done.');
    const id = up(a.p_id), name = proper(a.p_name), pin = String(a.p_pin || '');
    if (!okId(id) || !name || pin.length < 4) bad('Fill all fields. ID: 3-20 letters/numbers. PIN: min 4.');
    d.users[id] = Object.assign(blank(name, 'admin'), await secret(pin, env)); log(d, name, 'First admin created', id); return session(d, id);
  },

  // tells the login screen what to ask: 'set' = choose a new PIN, 'login' = enter PIN
  async k4_check(d, a) { const u = d.users[up(a.p_id)];
    if (!u) return { s: 'login', waiting: false, needsCode: false };
    const set = canSet(u);
    return { s: set ? 'set' : 'login', waiting: !!u.resetReq && !set, needsCode: set && !!u.vc }; },

  async k4_login(d, a, env) {
    const id = up(a.p_id), key = 'in:' + id, u = d.users[id], pin = String(a.p_pin || '');
    tryCheck(key);
    if (!u || !u.hash) { tryFail(key); return null; }
    if (await hash(pin, u.salt, u.it) !== u.hash) { tryFail(key); return null; }
    tryOk(key);
    if ((u.it || 10000) < iters(env)) Object.assign(u, await secret(pin, env));   // silently upgrade old hashes
    return session(d, id);
  },

  async k4_set_pin(d, a, env) {
    const id = up(a.p_id), u = d.users[id], pin = String(a.p_pin || ''), key = 'set:' + id;
    tryCheck(key);
    if (!u || !canSet(u)) bad('PIN change is not allowed. Ask your admin to approve a reset.');
    if (pin.length < 4) bad('PIN must be at least 4 characters.');
    if (u.vc && clean(a.p_code) !== u.vc) { tryFail(key); bad('Verification code is wrong.'); }
    tryOk(key);
    Object.assign(u, await secret(pin, env), { resetOk: false, resetOkAt: null, resetReq: null });
    dropSessions(d, id); log(d, u.name, 'PIN set', id); return session(d, id);
  },

  async k4_forgot(d, a) { const id = up(a.p_id), u = d.users[id];
    if (u && u.hash && !canSet(u)) { u.resetOk = false; if (!u.resetReq) { u.resetReq = Date.now(); log(d, u.name, 'Requested PIN reset', id); } }
    return true; },

  // owner-only emergency reset of an ADMIN PIN with the RECOVERY_KEY secret (for the case where no admin can log in)
  async k4_recover(d, a, env) {
    const id = up(a.p_id), key = 'rec:' + id, pin = String(a.p_pin || '');
    tryCheck(key);
    const u = d.users[id];
    if (!env.RECOVERY_KEY || !u || u.role !== 'admin' || !same(clean(a.p_key), env.RECOVERY_KEY)) { tryFail(key); bad('Recovery failed.'); }
    if (pin.length < 4) bad('PIN must be at least 4 characters.');
    tryOk(key);
    Object.assign(u, await secret(pin, env), { resetOk: false, resetOkAt: null, resetReq: null });
    dropSessions(d, id); log(d, u.name, 'Admin PIN recovered with owner key', id); return session(d, id);
  },

  async k4_logout(d, a) { delete d.sessions[String(a.p_token)]; return null; },

  async k4_get(d, a) {
    const m = me(d, a.p_token), isA = m.u.role === 'admin', users = {};
    for (const id in d.users) if (isA || id === m.id) users[id] = pub(d.users[id], isA);
    return { me: m.id, now: Date.now(), users, log: isA ? (d.log || []).slice(0, 150) : [], settings: isA ? d.settings : null };
  },

  async k4_add_user(d, a) {
    const m = admin(d, a.p_token), id = up(a.p_id), name = proper(a.p_name), code = clean(a.p_code);
    if (!okId(id) || !name) bad('Enter a name and an ID (3-20 letters/numbers).');
    if (!/^[0-9]{4}$/.test(code)) bad("Enter the 4-digit verification code (last 4 digits of the user's mobile number).");
    if (d.users[id]) bad('ID already exists.');
    d.users[id] = Object.assign(blank(name, 'user'), { vc: code }); log(d, m.u.name, 'Added user', id + ' ' + name); return null;
  },

  // each line:  ID, Name, 4-digit code(optional)   (comma, tab or space separated)
  async k4_bulk_add(d, a) {
    const m = admin(d, a.p_token); let added = 0; const skipped = [];
    for (const line of String(a.p_text || '').split(/\r?\n/).slice(0, 200)) {
      const s = line.trim(); if (!s) continue;
      let p = s.split(/[,\t]/).map(x => x.trim()).filter(Boolean);
      if (p.length < 2) { const mm = s.match(/^(\S+)\s+(.+)$/); p = mm ? [mm[1], mm[2]] : [s]; }
      const id = up(p[0]), name = proper(p[1]), code = clean(p[2]);
      if (!okId(id) || !name || d.users[id] || (code && !/^[0-9]{4}$/.test(code))) { skipped.push(s.slice(0, 30)); continue; }
      d.users[id] = Object.assign(blank(name, 'user'), { vc: code || null }); added++;
    }
    if (added) log(d, m.u.name, 'Bulk added ' + added + ' users'); return { added, skipped };
  },

  async k4_approve(d, a) {
    const adm = admin(d, a.p_token), id = up(a.p_id), t = d.users[id], cnt = Number(a.p_count), hrs = Number(a.p_hours);
    if (!t || t.role !== 'user') bad('User not found.');
    if (!['temp', 'perm'].includes(a.p_type) || !(cnt >= 1 && cnt <= 5)) bad('Invalid pass settings.');
    if (a.p_type === 'temp' && !(hrs > 0 && hrs <= 8760)) bad('Enter validity for a temporary pass.');
    Object.assign(t, { passType: a.p_type, count: cnt, approvedBy: adm.u.name, approvedAt: Date.now(),
      expiry: a.p_type === 'temp' ? Date.now() + hrs * HR : null, devices: t.devices.slice(0, cnt) });
    for (const k of Object.keys(t.devReq || {})) if (+k >= cnt) delete t.devReq[k];
    log(d, adm.u.name, (a.p_type === 'temp' ? 'Approved temporary pass' : 'Approved permanent pass') + ' x' + cnt, id); return null;
  },

  async k4_extend(d, a) {
    const m = admin(d, a.p_token), id = up(a.p_id), t = d.users[id], hrs = Math.min(Number(a.p_hours) || 24, 720);
    if (!t || t.passType !== 'temp') bad('Not a temporary pass.');
    t.expiry = Math.max(t.expiry, Date.now()) + hrs * HR; log(d, m.u.name, 'Extended pass by ' + hrs + 'h', id); return null;
  },

  async k4_revoke(d, a) {
    const m = admin(d, a.p_token), t = d.users[up(a.p_id)];
    if (t && t.role === 'user') { Object.assign(t, { passType: 'none', count: 0, expiry: null, devices: [], devReq: {} }); log(d, m.u.name, 'Revoked pass', up(a.p_id)); } return null;
  },

  async k4_promote(d, a) {
    const m = admin(d, a.p_token), t = d.users[up(a.p_id)];
    if (t) { Object.assign(t, { role: 'admin', passType: 'none', count: 0, expiry: null, devices: [], devReq: {} }); log(d, m.u.name, 'Made admin', up(a.p_id)); } return null;
  },

  async k4_demote(d, a) {
    const m = admin(d, a.p_token);
    if (Object.values(d.users).filter(u => u.role === 'admin').length < 2) bad('You are the only admin. Make another admin first.');
    m.u.role = 'user'; log(d, m.u.name, 'Demoted self to user', m.id); return null;
  },

  async k4_delete(d, a) {
    const m = admin(d, a.p_token), id = up(a.p_id);
    if (m.id === id) bad('You cannot delete yourself.');
    const t = d.users[id]; if (t) { delete d.users[id]; dropSessions(d, id); log(d, m.u.name, 'Deleted user', id + ' ' + t.name); } return null;
  },

  async k4_reset_ok(d, a) {
    const m = admin(d, a.p_token), id = up(a.p_id), t = d.users[id]; if (!t) bad('User not found.');
    Object.assign(t, { resetOk: true, resetOkAt: Date.now(), resetReq: null }); log(d, m.u.name, 'Approved PIN reset (valid 1 hour)', id); return null;
  },

  async k4_reset_deny(d, a) {
    const m = admin(d, a.p_token), id = up(a.p_id), t = d.users[id];
    if (t) { Object.assign(t, { resetReq: null, resetOk: false, resetOkAt: null }); log(d, m.u.name, 'Denied PIN reset', id); } return null;
  },

  async k4_settings(d, a) {
    const m = admin(d, a.p_token), g = Math.round(Number(a.p_grace));
    if (!(g >= 0 && g <= 720)) bad('Invalid grace period.');
    d.settings.grace = g; log(d, m.u.name, 'Grace period set to ' + g + 'h'); return null;
  },

  async k4_add_device(d, a) {
    const m = me(d, a.p_token), u = m.u, idx = Number(a.p_idx), imei = String(a.p_imei || ''), model = clean(a.p_model), num = clean(a.p_num);
    if (u.role !== 'user' || u.passType === 'none' || !(idx >= 0 && idx < u.count)) bad('No such pass.');
    if (u.passType === 'temp' && u.expiry <= Date.now()) bad('Pass expired.');
    if (!/^[0-9]{15}$/.test(imei) || !luhn(imei)) bad('Invalid IMEI. Check the 15 digits (dial *#06#).');
    if (!model) bad('Enter phone model.');
    if (num && !/^[0-9+\- ]{7,20}$/.test(num)) bad('Mobile number looks wrong.');
    if (Object.values(d.users).some(x => x.devices.some(v => v && v.imei === imei))) bad('This IMEI is already registered.');
    while (u.devices.length <= idx) u.devices.push(null);
    if (u.devices[idx]) bad('This pass already has a device.');
    u.devices[idx] = { model: model.slice(0, 60), imei, num: num.slice(0, 20), os: clean(a.p_os).slice(0, 30) };
    log(d, u.name, 'Registered device on pass ' + (idx + 1), m.id); return null;
  },

  // user: "lost / changed phone" -> asks the admin to clear that device
  async k4_report_lost(d, a) {
    const m = me(d, a.p_token), u = m.u, idx = Number(a.p_idx);
    if (u.role !== 'user' || !u.devices[idx]) bad('No device on this pass.');
    u.devReq = u.devReq || {};
    if (!u.devReq[idx]) { u.devReq[idx] = Date.now(); log(d, u.name, 'Asked to change device on pass ' + (idx + 1), m.id); }
    return null;
  },

  async k4_remove_device(d, a) {
    const m = admin(d, a.p_token), id = up(a.p_id), t = d.users[id], idx = Number(a.p_idx);
    if (!t || !t.devices[idx]) bad('No device there.');
    const old = t.devices[idx]; t.devices[idx] = null;
    while (t.devices.length && !t.devices[t.devices.length - 1]) t.devices.pop();
    if (t.devReq) delete t.devReq[idx];
    log(d, m.u.name, 'Removed device (' + old.model + ') from pass ' + (idx + 1), id); return null;
  },

  async k4_dismiss_dev(d, a) {
    admin(d, a.p_token); const t = d.users[up(a.p_id)];
    if (t && t.devReq) delete t.devReq[Number(a.p_idx)]; return null;
  }
};
