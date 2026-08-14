const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = process.env.STORAGE_ROOT || path.join(__dirname, "storage");
const DB_FILE = path.join(ROOT, "db.json");
const SESSION_TTL = 1000 * 60 * 60 * 24 * 7;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

fs.mkdirSync(ROOT, { recursive: true });
function readDb() {
  if (!fs.existsSync(DB_FILE)) return { users: [], weddings: [], files: [], uploads: [], sessions: [] };
  try { return JSON.parse(fs.readFileSync(DB_FILE, "utf8")); } catch { return { users: [], weddings: [], files: [], uploads: [], sessions: [] }; }
}
function writeDb(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
let db = readDb();

function id(prefix) { return `${prefix}_${crypto.randomBytes(12).toString("hex")}`; }
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  try {
    const [salt, expected] = stored.split(":");
    const actual = crypto.scryptSync(String(password), salt, 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
  } catch { return false; }
}
function safeName(name) { return String(name || "file").replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 180); }
function seedAdmin() {
  const username = process.env.ADMIN_USERNAME || "admin";
  const password = process.env.ADMIN_PASSWORD;
  if (!password) {
    if (!db.users.some(u => u.role === "admin")) console.warn("ADMIN_PASSWORD is not set. Set it before deploying.");
    return;
  }
  let admin = db.users.find(u => u.role === "admin" && u.username === username);
  if (!admin) {
    db.users.push({ id: id("usr"), username, name: "Administrator", passwordHash: hashPassword(password), role: "admin", active: true, createdAt: new Date().toISOString() });
    writeDb(db);
  }
}
seedAdmin();

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.static(__dirname));

function cookieToken(req) {
  const m = String(req.headers.cookie || "").match(/(?:^|; )nandani_session=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}
function auth(req, res, next) {
  const token = cookieToken(req);
  const session = db.sessions.find(s => s.token === token && s.expiresAt > Date.now());
  if (!session) return res.status(401).json({ error: "Login required" });
  const user = db.users.find(u => u.id === session.userId && u.active !== false);
  if (!user) return res.status(401).json({ error: "Account unavailable" });
  req.user = user;
  next();
}
function adminOnly(req, res, next) { if (req.user.role !== "admin") return res.status(403).json({ error: "Admin access required" }); next(); }
function customerOrAdmin(req, res, next) { if (req.user.role === "admin" || req.user.id === req.params.customerId) return next(); return res.status(403).json({ error: "Access denied" }); }
function visibleWedding(w, user) { return user.role === "admin" || w.customerId === user.id; }
function visibleFile(f, user) { const w = db.weddings.find(x => x.id === f.weddingId); return w && visibleWedding(w, user); }

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  const user = db.users.find(u => u.username === String(username || "").trim() && u.active !== false);
  if (!user || !verifyPassword(password || "", user.passwordHash)) return res.status(401).json({ error: "Invalid username or password" });
  const token = crypto.randomBytes(32).toString("hex");
  db.sessions = db.sessions.filter(s => s.expiresAt > Date.now());
  db.sessions.push({ token, userId: user.id, expiresAt: Date.now() + SESSION_TTL });
  writeDb(db);
  res.setHeader("Set-Cookie", `nandani_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_TTL / 1000}`);
  res.json({ user: { id: user.id, username: user.username, name: user.name, role: user.role } });
});
app.post("/api/auth/logout", auth, (req, res) => {
  const token = cookieToken(req); db.sessions = db.sessions.filter(s => s.token !== token); writeDb(db);
  res.setHeader("Set-Cookie", "nandani_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"); res.json({ ok: true });
});
app.get("/api/auth/me", auth, (req, res) => res.json({ id: req.user.id, username: req.user.username, name: req.user.name, role: req.user.role }));

app.get("/api/customers", auth, adminOnly, (req, res) => res.json(db.users.filter(u => u.role === "customer").map(({ passwordHash, ...u }) => u)));
app.post("/api/customers", auth, adminOnly, (req, res) => {
  const { name, username, password, mobile } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({ error: "Name, username and password are required" });
  if (db.users.some(u => u.username === username)) return res.status(409).json({ error: "Username already exists" });
  const user = { id: id("usr"), username: String(username).trim(), name: String(name).trim(), mobile: String(mobile || "").trim(), passwordHash: hashPassword(password), role: "customer", active: true, createdAt: new Date().toISOString() };
  db.users.push(user); writeDb(db); res.status(201).json({ id: user.id, username: user.username, name: user.name, mobile: user.mobile, role: user.role });
});
app.delete("/api/customers/:customerId", auth, adminOnly, (req, res) => {
  const customer = db.users.find(u => u.id === req.params.customerId && u.role === "customer");
  if (!customer) return res.status(404).json({ error: "Customer not found" });
  customer.active = false; db.sessions = db.sessions.filter(s => s.userId !== customer.id); writeDb(db); res.json({ ok: true });
});

app.get("/api/weddings", auth, (req, res) => {
  const list = db.weddings.filter(w => visibleWedding(w, req.user)).map(w => ({ ...w, files: db.files.filter(f => f.weddingId === w.id).map(f => ({ id: f.id, name: f.name, size: f.size, mime: f.mime, url: `/api/files/${f.id}` })) }));
  res.json(list);
});
app.post("/api/weddings", auth, (req, res) => {
  const { name, customerId } = req.body || {};
  const owner = req.user.role === "admin" ? db.users.find(u => u.id === customerId && u.role === "customer") : req.user;
  if (!name) return res.status(400).json({ error: "Wedding name required" });
  if (!owner) return res.status(400).json({ error: "Valid customer required" });
  const wedding = { id: id("wed"), name: String(name).trim(), customerId: owner.id, createdAt: new Date().toISOString() };
  db.weddings.push(wedding); writeDb(db); res.status(201).json(wedding);
});
app.delete("/api/weddings/:id", auth, (req, res) => {
  const wedding = db.weddings.find(w => w.id === req.params.id);
  if (!wedding || !visibleWedding(wedding, req.user)) return res.status(404).json({ error: "Album not found" });
  const files = db.files.filter(f => f.weddingId === wedding.id);
  for (const f of files) try { fs.rmSync(f.path, { force: true }); } catch {}
  db.files = db.files.filter(f => f.weddingId !== wedding.id); db.weddings = db.weddings.filter(w => w.id !== wedding.id); writeDb(db); res.json({ ok: true });
});
app.get("/api/weddings/:id/files", auth, (req, res) => {
  const w = db.weddings.find(x => x.id === req.params.id);
  if (!w || !visibleWedding(w, req.user)) return res.status(404).json({ error: "Album not found" });
  res.json(db.files.filter(f => f.weddingId === w.id).map(f => ({ id: f.id, name: f.name, size: f.size, mime: f.mime, url: `/api/files/${f.id}` })));
});

app.get("/api/files/:id", auth, (req, res) => {
  const f = db.files.find(x => x.id === req.params.id);
  if (!f || !visibleFile(f, req.user)) return res.status(404).end();
  if (!fs.existsSync(f.path)) return res.status(404).end();
  res.sendFile(path.resolve(f.path), { headers: { "Content-Type": f.mime || "application/octet-stream", "Content-Disposition": `inline; filename="${safeName(f.name)}"` } });
});
app.delete("/api/weddings/:weddingId/files/:id", auth, (req, res) => {
  const f = db.files.find(x => x.id === req.params.id && x.weddingId === req.params.weddingId);
  if (!f || !visibleFile(f, req.user)) return res.status(404).json({ error: "File not found" });
  try { fs.rmSync(f.path, { force: true }); } catch {}
  db.files = db.files.filter(x => x.id !== f.id); writeDb(db); res.json({ ok: true });
});

app.post("/api/upload/start", auth, (req, res) => {
  const { weddingId, fileName, size, mime } = req.body || {};
  const wedding = db.weddings.find(w => w.id === weddingId);
  if (!wedding || !visibleWedding(wedding, req.user)) return res.status(404).json({ error: "Album not found" });
  if (!fileName || !Number.isFinite(size) || size <= 0 || size > 20 * 1024 * 1024 * 1024) return res.status(400).json({ error: "Invalid file or file exceeds 20 GB" });
  const uploadId = id("upl"); const dir = path.join(ROOT, "uploads"); fs.mkdirSync(dir, { recursive: true });
  const temp = path.join(dir, `${uploadId}.part`); fs.writeFileSync(temp, "");
  db.uploads.push({ id: uploadId, userId: req.user.id, weddingId, fileName: safeName(fileName), size, mime: mime || "application/octet-stream", received: 0, path: temp }); writeDb(db);
  res.json({ uploadId, chunkBytes: 8 * 1024 * 1024 });
});
app.post("/api/upload/:uploadId/chunk", auth, upload.single("chunk"), (req, res) => {
  const u = db.uploads.find(x => x.id === req.params.uploadId && x.userId === req.user.id);
  if (!u || !req.file) return res.status(404).json({ error: "Upload not found" });
  const start = Number(req.headers["x-chunk-start"] || 0);
  if (start !== u.received) return res.status(409).json({ error: "Invalid chunk offset", received: u.received });
  fs.appendFileSync(u.path, req.file.buffer); u.received += req.file.size; writeDb(db); res.json({ received: u.received });
});
app.post("/api/upload/:uploadId/finish", auth, (req, res) => {
  const u = db.uploads.find(x => x.id === req.params.uploadId && x.userId === req.user.id);
  if (!u) return res.status(404).json({ error: "Upload not found" });
  if (u.received !== u.size) return res.status(400).json({ error: `Upload incomplete: ${u.received}/${u.size}` });
  const weddingDir = path.join(ROOT, "weddings", u.weddingId); fs.mkdirSync(weddingDir, { recursive: true });
  const finalPath = path.join(weddingDir, `${id("file")}_${u.fileName}`); fs.renameSync(u.path, finalPath);
  const file = { id: id("file"), weddingId: u.weddingId, name: u.fileName, size: u.size, mime: u.mime, path: finalPath, createdAt: new Date().toISOString() };
  db.files.push(file); db.uploads = db.uploads.filter(x => x.id !== u.id); writeDb(db); res.json({ id: file.id });
});

app.get("/api/admin/stats", auth, adminOnly, (req, res) => res.json({ customers: db.users.filter(u => u.role === "customer" && u.active !== false).length, weddings: db.weddings.length, files: db.files.length, storageBytes: db.files.reduce((n, f) => n + Number(f.size || 0), 0) }));

// Admin URL भी main login page पर जाएगा
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// बाकी सभी frontend routes भी index.html पर जाएंगे
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/api/admin/stats", auth, adminOnly, (req, res) => {
  res.json({
    customers: db.users.filter(u => u.role === "customer" && u.active !== false).length,
    weddings: db.weddings.length,
    files: db.files.length,
    storageBytes: db.files.reduce((n, f) => n + Number(f.size || 0), 0)
  });
});

// Admin URL
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Frontend routes
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Nandani Wedding Cloud running on port ${PORT}`);
});
