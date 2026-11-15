/* server.js -- Abandoned but Not Forgotten: accounts + progress stored in SQLite.
 * Zero dependencies (Node 22+: node:http, node:sqlite, node:crypto).
 * Run:  node server.js        (PORT=3000, DB_PATH=./data/abnf.db, COOKIE_SECURE=1 behind HTTPS)
 */
"use strict";
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

const PORT = +process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "abnf.db");
const SECURE = process.env.COOKIE_SECURE === "1";
const SESSION_DAYS = 30;
const NAME_RE = /^[A-Za-z0-9_-]{3,16}$/;

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, name_lc TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, created INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS progress (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, level INTEGER NOT NULL,
    best_time REAL NOT NULL, score INTEGER NOT NULL, PRIMARY KEY (user_id, level));
  CREATE TABLE IF NOT EXISTS files (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, file_id TEXT NOT NULL,
    key TEXT NOT NULL, PRIMARY KEY (user_id, file_id));
`);
const q = {
  userByName: db.prepare("SELECT * FROM users WHERE name_lc = ?"),
  userById: db.prepare("SELECT id, name FROM users WHERE id = ?"),
  addUser: db.prepare("INSERT INTO users (name, name_lc, salt, hash, created) VALUES (?,?,?,?,?)"),
  addSession: db.prepare("INSERT INTO sessions (sid, user_id, created) VALUES (?,?,?)"),
  session: db.prepare("SELECT sid, user_id, created FROM sessions WHERE sid = ?"),
  delSession: db.prepare("DELETE FROM sessions WHERE sid = ?"),
  purge: db.prepare("DELETE FROM sessions WHERE created < ?"),
  getProg: db.prepare("SELECT level, best_time, score FROM progress WHERE user_id = ?"),
  putProg: db.prepare("INSERT INTO progress (user_id, level, best_time, score) VALUES (?,?,?,?) " +
    "ON CONFLICT(user_id, level) DO UPDATE SET best_time = excluded.best_time, score = excluded.score"),
  getFiles: db.prepare("SELECT file_id, key FROM files WHERE user_id = ?"),
  putFile: db.prepare("INSERT OR IGNORE INTO files (user_id, file_id, key) VALUES (?,?,?)"),
  board: db.prepare("SELECT u.name AS name, SUM(p.score) AS score, COUNT(*) AS levels FROM progress p " +
    "JOIN users u ON u.id = p.user_id GROUP BY u.id ORDER BY score DESC, levels DESC, u.name LIMIT 100"),
};

/* ---- page template: the game file, with per-request user, progress and CSRF token injected ---- */
const PAGE = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
const GD = '<script type="application/json" id="game-data">';
const gdAt = PAGE.indexOf(GD);
if (gdAt < 0 || !PAGE.includes('<meta name="csrf-token" content="local">')) throw new Error("index.html is missing expected markers");
const gdEnd = PAGE.indexOf("</script>", gdAt);
const GAME = JSON.parse(PAGE.slice(gdAt + GD.length, gdEnd));
const FILE_LEVEL = {}; (GAME.config.facts || []).forEach(f => { FILE_LEVEL[f.id] = f.level; });
const MAX_LEVEL = (GAME.config.levels || []).length || 4;

const secret = crypto.randomBytes(32);   // CSRF tokens are tied to the session id; they reset if the server restarts (page reload fixes it)
const csrfFor = sid => crypto.createHmac("sha256", secret).update(sid).digest("hex");
const safeEq = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };

/* ---- passwords: scrypt + per-user salt ---- */
const hashPw = (pw, saltHex) => crypto.scryptSync(pw, Buffer.from(saltHex, "hex"), 64, { N: 16384, r: 8, p: 1 }).toString("hex");
const DUMMY_SALT = crypto.randomBytes(16).toString("hex"), DUMMY_HASH = hashPw("dummy", DUMMY_SALT);

/* ---- helpers ---- */
const progressFor = uid => {
  const completed = {}; q.getProg.all(uid).forEach(r => { completed[r.level] = { best_time: r.best_time, score: r.score }; });
  const files = [], keys = {}; q.getFiles.all(uid).forEach(r => { files.push(r.file_id); keys[r.file_id] = r.key; });
  return { completed, files, keys };
};
const maxUnlocked = uid => { const c = progressFor(uid).completed; let n = 1; while (n < MAX_LEVEL && c[n]) n++; return n; };
const num = (v, lo, hi) => (typeof v === "number" && Number.isFinite(v) && v >= lo && v <= hi) ? v : null;
const better = (score, time, prev) => !prev || score > prev.score || (score === prev.score && time < prev.best_time);

function recordLevel(uid, level, time, score) {
  const prev = q.getProg.all(uid).find(r => r.level === level);
  if (better(score, time, prev)) q.putProg.run(uid, level, time, score);
}
function recordFile(uid, id, key) {
  if (typeof id !== "string" || FILE_LEVEL[id] == null || typeof key !== "string" || !/^[\w.+/=-]{1,200}$/.test(key)) return false;
  if (FILE_LEVEL[id] > maxUnlocked(uid)) return false;
  q.putFile.run(uid, id, key); return true;
}

const cookies = req => Object.fromEntries((req.headers.cookie || "").split(";").map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(a => a[0]));
const setCookie = (res, sid) => res.setHeader("Set-Cookie",
  `sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}${SECURE ? "; Secure" : ""}`);
const send = (res, code, body, type = "application/json; charset=utf-8", extra = {}) => {
  res.writeHead(code, Object.assign({ "Content-Type": type, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY" }, extra));
  res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
};
const readBody = req => new Promise((resolve, reject) => {
  let n = 0; const parts = [];
  req.on("data", c => { n += c.length; if (n > 64 * 1024) { reject(Object.assign(new Error("too large"), { code: 413 })); req.destroy(); } else parts.push(c); });
  req.on("end", () => resolve(Buffer.concat(parts).toString("utf8")));
  req.on("error", reject);
});

/* simple per-IP throttle on login/register */
const hits = new Map();
const throttled = ip => { const now = Date.now(), a = (hits.get(ip) || []).filter(t => now - t < 60000); a.push(now); hits.set(ip, a); return a.length > 10; };
setInterval(() => { const now = Date.now(); for (const [k, a] of hits) if (!a.some(t => now - t < 60000)) hits.delete(k); q.purge.run(Date.now() - SESSION_DAYS * 864e5); }, 60000).unref();

function sessionOf(req, res) {
  let sid = cookies(req).sid, row = sid && /^[0-9a-f]{48}$/.test(sid) ? q.session.get(sid) : null;
  if (row && row.created < Date.now() - SESSION_DAYS * 864e5) { q.delSession.run(sid); row = null; }
  if (!row) { sid = crypto.randomBytes(24).toString("hex"); q.addSession.run(sid, null, Date.now()); setCookie(res, sid); row = { sid, user_id: null }; }
  return row;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x"), route = req.method + " " + url.pathname;
    const sess = sessionOf(req, res), token = csrfFor(sess.sid);

    if (route === "GET /" || route === "GET /index.html") {
      const user = sess.user_id ? q.userById.get(sess.user_id) : null;
      const data = Object.assign({}, GAME);
      if (user) { data.user = { name: user.name }; data.progress = progressFor(user.id); }
      const json = JSON.stringify(data).replace(/</g, "\\u003c");
      const html = PAGE.slice(0, gdAt).replace('<meta name="csrf-token" content="local">',
        `<meta name="csrf-token" content="${token}"><meta name="abnf-server" content="1">`) + GD + json + PAGE.slice(gdEnd);
      return send(res, 200, html, "text/html; charset=utf-8");
    }
    if (route === "GET /api/leaderboard") return send(res, 200, q.board.all().map((r, i) => ({ rank: i + 1, name: r.name, score: r.score, levels: r.levels })));
    if (route === "GET /healthz") return send(res, 200, { ok: true });

    if (req.method !== "POST") return send(res, 404, { error: "Not found" });

    /* every POST needs the CSRF token (header for fetch, form field for the logout button) */
    const raw = await readBody(req);
    let body = {}, formTok = null;
    if ((req.headers["content-type"] || "").startsWith("application/json")) { try { body = JSON.parse(raw || "{}"); } catch (e) { return send(res, 400, { error: "Bad JSON" }); } }
    else formTok = new URLSearchParams(raw).get("csrf_token");
    if (!safeEq(req.headers["x-csrftoken"] || formTok || "", token)) return send(res, 403, { error: "Session expired. Reload the page." });
    if (!body || typeof body !== "object") body = {};
    const ip = req.socket.remoteAddress;

    if (route === "POST /api/register") {
      if (throttled(ip)) return send(res, 429, { error: "Too many attempts. Wait a minute." });
      const name = typeof body.username === "string" ? body.username.trim() : "", pw = typeof body.password === "string" ? body.password : "";
      if (!NAME_RE.test(name)) return send(res, 400, { error: "Username: 3-16 letters, numbers, _ or -." });
      if (pw.length < 6 || pw.length > 64) return send(res, 400, { error: "Password must be 6-64 characters." });
      if (q.userByName.get(name.toLowerCase())) return send(res, 409, { error: "That username is taken." });
      const salt = crypto.randomBytes(16).toString("hex");
      let uid; try { uid = Number(q.addUser.run(name, name.toLowerCase(), salt, hashPw(pw, salt), Date.now()).lastInsertRowid); }
      catch (e) { return send(res, 409, { error: "That username is taken." }); }
      q.delSession.run(sess.sid);                                   // new session id on login (prevents fixation)
      const sid = crypto.randomBytes(24).toString("hex"); q.addSession.run(sid, uid, Date.now()); setCookie(res, sid);
      return send(res, 200, { ok: true });
    }
    if (route === "POST /api/login") {
      if (throttled(ip)) return send(res, 429, { error: "Too many attempts. Wait a minute." });
      const name = typeof body.username === "string" ? body.username.trim().toLowerCase() : "", pw = typeof body.password === "string" ? body.password.slice(0, 64) : "";
      const u = q.userByName.get(name);
      const h = hashPw(pw, u ? u.salt : DUMMY_SALT);                // same work whether or not the user exists
      if (!u || !safeEq(h, u.hash)) return send(res, 401, { error: "Wrong username or password." });
      q.delSession.run(sess.sid);
      const sid = crypto.randomBytes(24).toString("hex"); q.addSession.run(sid, u.id, Date.now()); setCookie(res, sid);
      return send(res, 200, { ok: true });
    }
    if (route === "POST /logout") {
      q.delSession.run(sess.sid);
      res.setHeader("Set-Cookie", `sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${SECURE ? "; Secure" : ""}`);
      return formTok != null ? send(res, 303, "", "text/plain", { Location: "/" }) : send(res, 200, { ok: true });
    }

    /* everything below needs a logged-in user */
    if (!sess.user_id) return send(res, 401, { error: "Not logged in." });
    const uid = sess.user_id;

    if (route === "POST /api/complete") {
      const level = body.level, time = num(body.elapsed, 0, 86400), score = num(body.score, 0, 1e6);
      if (!Number.isInteger(level) || level < 1 || level > MAX_LEVEL || time == null || score == null || !Number.isInteger(score)) return send(res, 400, { error: "Bad data" });
      if (level > maxUnlocked(uid)) return send(res, 403, { error: "Level locked" });
      recordLevel(uid, level, time, score);
      const p = progressFor(uid); return send(res, 200, { saved: true, completed: p.completed, files: p.files, keys: p.keys });
    }
    if (route === "POST /api/unlock_file") { recordFile(uid, body.file_id, body.key); return send(res, 200, { saved: true }); }
    if (route === "POST /api/sync") {                                // merge guest progress made before logging in
      const c = body.completed && typeof body.completed === "object" ? body.completed : {};
      for (const k of Object.keys(c).sort()) {
        const level = Number(k), time = num(c[k] && c[k].best_time, 0, 86400), score = num(c[k] && c[k].score, 0, 1e6);
        if (Number.isInteger(level) && level >= 1 && level <= maxUnlocked(uid) && time != null && Number.isInteger(score)) recordLevel(uid, level, time, score);
      }
      const keys = body.keys && typeof body.keys === "object" ? body.keys : {};
      (Array.isArray(body.files) ? body.files : []).slice(0, 200).forEach(id => recordFile(uid, id, keys[id]));
      const p = progressFor(uid); return send(res, 200, { saved: true, completed: p.completed, files: p.files, keys: p.keys });
    }
    return send(res, 404, { error: "Not found" });
  } catch (e) {
    if (e && e.code === 413) return send(res, 413, { error: "Too large" });
    console.error(e); if (!res.headersSent) send(res, 500, { error: "Server error" });
  }
});
server.listen(PORT, () => console.log(`Abandoned but Not Forgotten running on http://localhost:${PORT}  (db: ${DB_PATH})`));
