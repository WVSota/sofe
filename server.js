const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

// .env ファイルが存在する場合は読み込む
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const [key, ...rest] = line.split('=');
    if (key && rest.length) process.env[key.trim()] = rest.join('=').trim();
  });
}

const INITIAL_PASSWORD = process.env.INITIAL_PASSWORD || INITIAL_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET || 'sofe-secret-2024';

const app = express();
const PORT = 3000;
const DATA_FILE = path.join(__dirname, 'data', 'db.json');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

function loadDB() {
  if (!fs.existsSync(DATA_FILE)) return initDB();
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { return initDB(); }
}

function saveDB(db) {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), 'utf8');
}

function initDB() {
  const db = {
    members: {
      'admin': {
        id: 'admin', name: 'admin', role: 'admin',
        passwordHash: bcrypt.hashSync(INITIAL_PASSWORD, 10),
        mustChangePassword: false, createdAt: Date.now()
      }
    },
    shifts: {}, attendance: {}
  };
  saveDB(db);
  return db;
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'ログインしてください' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'ログインしてください' });
  const db = loadDB();
  const user = db.members[req.session.userId];
  if (!user || user.role !== 'admin') return res.status(403).json({ error: '管理者権限が必要です' });
  next();
}

app.post('/api/verify-initial-pw', (req, res) => {
  if (req.body.password === INITIAL_PASSWORD) res.json({ ok: true });
  else res.status(401).json({ error: '初期パスワードが違います' });
});

app.post('/api/register', (req, res) => {
  const { name, password, initialPw } = req.body;
  if (!initialPw || initialPw !== INITIAL_PASSWORD) return res.status(401).json({ error: '初期パスワードが違います' });
  if (!name || !password) return res.status(400).json({ error: '名前とパスワードは必須です' });
  if (password.length < 4) return res.status(400).json({ error: 'パスワードは4文字以上にしてください' });
  const db = loadDB();
  if (Object.values(db.members).find(m => m.name === name)) return res.status(400).json({ error: 'その名前はすでに使われています' });
  const id = 'u' + Date.now();
  db.members[id] = { id, name, role: 'member', passwordHash: bcrypt.hashSync(password, 10), mustChangePassword: false, createdAt: Date.now() };
  saveDB(db);
  req.session.userId = id;
  res.json({ ok: true, user: { id, name, role: 'member' } });
});

app.post('/api/login', (req, res) => {
  const { name, password } = req.body;
  const db = loadDB();
  const user = Object.values(db.members).find(m => m.name === name);
  if (!user) return res.status(401).json({ error: 'ユーザーが見つかりません' });
  if (!bcrypt.compareSync(password, user.passwordHash)) return res.status(401).json({ error: 'パスワードが違います' });
  req.session.userId = user.id;
  res.json({ ok: true, user: { id: user.id, name: user.name, role: user.role, mustChangePassword: user.mustChangePassword || false } });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'not logged in' });
  const db = loadDB();
  const user = db.members[req.session.userId];
  if (!user) return res.status(401).json({ error: 'not found' });
  res.json({ id: user.id, name: user.name, role: user.role, mustChangePassword: user.mustChangePassword || false });
});

app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'パスワードは4文字以上にしてください' });
  const db = loadDB();
  const user = db.members[req.session.userId];
  if (!bcrypt.compareSync(currentPassword, user.passwordHash)) return res.status(401).json({ error: '現在のパスワードが違います' });
  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  user.mustChangePassword = false;
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/members', requireAuth, (req, res) => {
  const db = loadDB();
  res.json(Object.values(db.members).map(m => ({ id: m.id, name: m.name, role: m.role, createdAt: m.createdAt })));
});

app.put('/api/members/:id/role', requireAdmin, (req, res) => {
  const { role } = req.body;
  if (!['member', 'leader', 'admin'].includes(role)) return res.status(400).json({ error: '無効なロールです' });
  const db = loadDB();
  if (!db.members[req.params.id]) return res.status(404).json({ error: 'メンバーが見つかりません' });
  db.members[req.params.id].role = role;
  saveDB(db);
  res.json({ ok: true });
});

app.delete('/api/members/:id', requireAdmin, (req, res) => {
  if (req.params.id === 'admin') return res.status(400).json({ error: 'adminは削除できません' });
  const db = loadDB();
  delete db.members[req.params.id];
  saveDB(db);
  res.json({ ok: true });
});

app.post('/api/members/:id/reset-password', requireAdmin, (req, res) => {
  const db = loadDB();
  if (!db.members[req.params.id]) return res.status(404).json({ error: 'メンバーが見つかりません' });
  db.members[req.params.id].passwordHash = bcrypt.hashSync(INITIAL_PASSWORD, 10);
  db.members[req.params.id].mustChangePassword = true;
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/shifts', requireAuth, (req, res) => { const db = loadDB(); res.json(db.shifts); });

app.post('/api/shifts', requireAuth, (req, res) => {
  const { date, start, end, note } = req.body;
  if (!date || !start || !end) return res.status(400).json({ error: '日付・開始・終了は必須です' });
  const db = loadDB();
  const uid = req.session.userId;
  if (!db.shifts[uid]) db.shifts[uid] = {};
  db.shifts[uid][date] = { start, end, note: note || '', status: 'requested', updatedAt: Date.now() };
  saveDB(db);
  res.json({ ok: true });
});

app.delete('/api/shifts/:date', requireAuth, (req, res) => {
  const db = loadDB();
  const uid = req.session.userId;
  if (db.shifts[uid]) delete db.shifts[uid][req.params.date];
  saveDB(db);
  res.json({ ok: true });
});

app.put('/api/shifts/:userId/:date/confirm', requireAdmin, (req, res) => {
  const db = loadDB();
  const { userId, date } = req.params;
  if (!db.shifts[userId] || !db.shifts[userId][date]) return res.status(404).json({ error: 'シフトが見つかりません' });
  db.shifts[userId][date].status = 'confirmed';
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/attendance', requireAuth, (req, res) => { const db = loadDB(); res.json(db.attendance); });

app.post('/api/attendance/stamp', requireAuth, (req, res) => {
  const { type, date } = req.body;
  if (!type || !date) return res.status(400).json({ error: 'type, date は必須です' });
  const db = loadDB();
  const uid = req.session.userId;
  if (!db.attendance[uid]) db.attendance[uid] = {};
  if (!db.attendance[uid][date]) db.attendance[uid][date] = { stamps: [] };
  const now = new Date();
  const time = String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0');
  db.attendance[uid][date].stamps.push({ type, time });
  saveDB(db);
  res.json({ ok: true, time });
});


// 打刻修正申請一覧
app.get('/api/stamp-corrections', requireAuth, (req, res) => {
  const db = loadDB();
  if (!db.stampCorrections) db.stampCorrections = [];
  const user = db.members[req.session.userId];
  if (user.role === 'admin') return res.json(db.stampCorrections);
  res.json(db.stampCorrections.filter(c => c.uid === req.session.userId));
});

app.post('/api/stamp-corrections', requireAuth, (req, res) => {
  const { date, type, requestedTime, reason } = req.body;
  if (!date || !type || !requestedTime) return res.status(400).json({ error: '必須項目が不足しています' });
  const db = loadDB();
  if (!db.stampCorrections) db.stampCorrections = [];
  const user = db.members[req.session.userId];
  db.stampCorrections.push({ id: 'sc'+Date.now(), uid: req.session.userId, name: user.name, date, type, requestedTime, reason: reason||'', status: 'pending', createdAt: Date.now() });
  saveDB(db);
  res.json({ ok: true });
});

app.put('/api/stamp-corrections/:id/approve', requireAdmin, (req, res) => {
  const db = loadDB();
  if (!db.stampCorrections) return res.status(404).json({ error: '見つかりません' });
  const c = db.stampCorrections.find(x => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: '見つかりません' });
  if (!db.attendance[c.uid]) db.attendance[c.uid] = {};
  if (!db.attendance[c.uid][c.date]) db.attendance[c.uid][c.date] = { stamps: [] };
  db.attendance[c.uid][c.date].stamps.push({ type: c.type, time: c.requestedTime, corrected: true });
  db.attendance[c.uid][c.date].stamps.sort((a,b) => a.time.localeCompare(b.time));
  c.status = 'approved';
  saveDB(db);
  res.json({ ok: true });
});

app.put('/api/stamp-corrections/:id/reject', requireAdmin, (req, res) => {
  const db = loadDB();
  if (!db.stampCorrections) return res.status(404).json({ error: '見つかりません' });
  const c = db.stampCorrections.find(x => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: '見つかりません' });
  c.status = 'rejected';
  saveDB(db);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log('\n  ✅ sunabaco sofe が起動しました');
  console.log('  🌐 http://localhost:' + PORT + ' をブラウザで開いてください\n');
  console.log('  管理者: admin / sofe0333');
  console.log('  新規登録の初期パスワード: sofe0333\n');
});
