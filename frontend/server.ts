import express from 'express';
import { createServer as createViteServer } from 'vite';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'phishguard-secret-key';

// Initialize Database
const db = new Database('phishguard.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT
  );
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    url TEXT,
    result TEXT,
    confidence REAL,
    reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Auth Middleware
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- API Routes ---

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)');
    stmt.run(email, hashedPassword);
    res.status(201).json({ message: 'User created' });
  } catch (err: any) {
    if (err.code === 'SQLITE_CONSTRAINT') {
      res.status(400).json({ detail: 'Email already registered' });
    } else {
      res.status(500).json({ detail: 'Internal server error' });
    }
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body; // FastAPI standard uses 'username'
  const user: any = db.prepare('SELECT * FROM users WHERE email = ?').get(username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ detail: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
  res.json({ access_token: token, token_type: 'bearer' });
});

// Predict
app.post('/api/predict/', authenticateToken, (req: any, res) => {
  const { url } = req.body;
  
  // Simple heuristic for demo purposes
  const isSuspicious = url.includes('login') || url.includes('verify') || url.includes('secure') || url.length > 50;
  const result = isSuspicious ? 'phishing' : 'safe';
  const confidence = 75 + Math.random() * 20;
  const reason = isSuspicious 
    ? "Suspicious keywords and unusual URL structure detected." 
    : "URL appears to follow standard patterns and has no immediate red flags.";

  const stmt = db.prepare('INSERT INTO scans (user_id, url, result, confidence, reason) VALUES (?, ?, ?, ?, ?)');
  const info = stmt.run(req.user.id, url, result, confidence, reason);

  res.json({
    id: info.lastInsertRowid,
    url,
    result,
    confidence,
    reason,
    created_at: new Date().toISOString()
  });
});

// History
app.get('/api/history/', authenticateToken, (req: any, res) => {
  const scans = db.prepare('SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json(scans);
});

// --- Vite Integration ---
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
    app.get('*', (req, res) => res.sendFile('dist/index.html', { root: '.' }));
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`Server running at http://0.0.0.0:${port}`);
  });
}

startServer();
