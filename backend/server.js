
// server.js
const express = require('express');
const bodyParser = require('body-parser');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// JWT secret (change in production)
const JWT_SECRET = "change_this_for_production_very_secret";

// setup sqlite
const db = new Database('demo-bet.db');

// create tables
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT,
  is_admin INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS wallets (
  user_id INTEGER PRIMARY KEY,
  balance TEXT DEFAULT '0',
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS bets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  stake TEXT,
  outcome TEXT,
  win INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

// helpers
function createUser(username, password, isAdmin=0) {
  const hash = bcrypt.hashSync(password, 10);
  try {
    const res = db.prepare('INSERT INTO users(username, password_hash, is_admin) VALUES (?, ?, ?)').run(username, hash, isAdmin);
    const userId = res.lastInsertRowid;
    db.prepare('INSERT INTO wallets(user_id, balance) VALUES (?, ?)').run(userId, '0');
    return userId;
  } catch (e) {
    return null;
  }
}
function getUserByUsername(username) {
  return db.prepare('SELECT id, username, password_hash, is_admin FROM users WHERE username = ?').get(username);
}
function authMiddleware(req, res, next){
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if(!token) return res.status(401).json({error: 'Unauthorized'});
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch(e) {
    return res.status(401).json({error:'Invalid token'});
  }
}

// create default admin-demo with huge balance if missing
if(!getUserByUsername('admin-demo')) {
  const adminId = createUser('admin-demo', 'admin123', 1);
  const initial = BigInt("100000000000");
  db.prepare('UPDATE wallets SET balance = ? WHERE user_id = ?').run(initial.toString(), adminId);
  console.log('Created admin-demo with 100000000000 دينار. username: admin-demo password: admin123');
}

app.post('/register', (req, res) => {
  const {username, password} = req.body;
  if(!username || !password) return res.status(400).json({error: 'username and password required'});
  const id = createUser(username, password, 0);
  if(!id) return res.status(400).json({error:'username exists'});
  res.json({ok:true, userId: id});
});

app.post('/login', (req, res) => {
  const {username, password} = req.body;
  const user = getUserByUsername(username);
  if(!user) return res.status(401).json({error:'invalid'});
  if(!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({error:'invalid'});
  const token = jwt.sign({userId: user.id, username: user.username, is_admin: user.is_admin}, JWT_SECRET, {expiresIn: '8h'});
  res.json({token});
});

app.get('/me', authMiddleware, (req, res) => {
  const uid = req.user.userId;
  const user = db.prepare('SELECT id, username, is_admin FROM users WHERE id = ?').get(uid);
  const w = db.prepare('SELECT balance FROM wallets WHERE user_id = ?').get(uid);
  res.json({user, balance: w.balance});
});

// list bets (user)
app.get('/bets', authMiddleware, (req, res) => {
  const uid = req.user.userId;
  const bets = db.prepare('SELECT id, stake, outcome, win, created_at FROM bets WHERE user_id = ? ORDER BY created_at DESC').all(uid);
  res.json({bets});
});

// admin: list users and balances
app.get('/admin/users', authMiddleware, (req, res) => {
  if(!req.user.is_admin) return res.status(403).json({error:'forbidden'});
  const rows = db.prepare('SELECT u.id, u.username, u.is_admin, w.balance FROM users u JOIN wallets w ON u.id = w.user_id ORDER BY u.id').all();
  res.json({users: rows});
});

// admin: mint
app.post('/admin/mint', authMiddleware, (req, res) => {
  if(!req.user.is_admin) return res.status(403).json({error:'forbidden'});
  const {username, amount} = req.body;
  if(!username || !amount) return res.status(400).json({error:'username and amount required'});
  const target = getUserByUsername(username);
  if(!target) return res.status(404).json({error:'user not found'});
  const current = BigInt(db.prepare('SELECT balance FROM wallets WHERE user_id = ?').get(target.id).balance || '0');
  const add = BigInt(amount);
  const updated = current + add;
  db.prepare('UPDATE wallets SET balance = ? WHERE user_id = ?').run(updated.toString(), target.id);
  res.json({ok:true, newBalance: updated.toString()});
});

// deposit (fake)
app.post('/wallet/deposit', authMiddleware, (req, res) => {
  const uid = req.user.userId;
  const {amount} = req.body;
  if(!amount) return res.status(400).json({error:'amount required'});
  const current = BigInt(db.prepare('SELECT balance FROM wallets WHERE user_id = ?').get(uid).balance || '0');
  const add = BigInt(amount);
  const updated = current + add;
  db.prepare('UPDATE wallets SET balance = ? WHERE user_id = ?').run(updated.toString(), uid);
  res.json({ok:true, newBalance: updated.toString()});
});

// withdraw (fake)
app.post('/wallet/withdraw', authMiddleware, (req, res) => {
  const uid = req.user.userId;
  const {amount} = req.body;
  if(!amount) return res.status(400).json({error:'amount required'});
  const current = BigInt(db.prepare('SELECT balance FROM wallets WHERE user_id = ?').get(uid).balance || '0');
  const sub = BigInt(amount);
  if(sub > current) return res.status(400).json({error:'insufficient funds'});
  const updated = current - sub;
  db.prepare('UPDATE wallets SET balance = ? WHERE user_id = ?').run(updated.toString(), uid);
  res.json({ok:true, newBalance: updated.toString()});
});

// place bet 50/50
app.post('/bet/place', authMiddleware, (req, res) => {
  const uid = req.user.userId;
  const {stake, choice} = req.body;
  if(!stake) return res.status(400).json({error:'stake required'});
  const stakeBig = BigInt(stake);
  const current = BigInt(db.prepare('SELECT balance FROM wallets WHERE user_id = ?').get(uid).balance || '0');
  if(stakeBig > current) return res.status(400).json({error:'insufficient'});
  const rnd = Math.random() < 0.5;
  let win = 0;
  let newBalance = current - stakeBig;
  if(rnd) {
    const payout = stakeBig * BigInt(2);
    newBalance = current - stakeBig + payout;
    win = 1;
  }
  db.prepare('UPDATE wallets SET balance = ? WHERE user_id = ?').run(newBalance.toString(), uid);
  db.prepare('INSERT INTO bets(user_id, stake, outcome, win) VALUES (?, ?, ?, ?)').run(uid, stakeBig.toString(), rnd ? 'win' : 'lose', win);
  res.json({ok:true, win: win===1, newBalance: newBalance.toString(), outcome: rnd ? 'win' : 'lose'});
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
