import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';

app.use(express.json());

// In-memory database for demo/preview purposes
// The Go version uses SQLite (app.db)
const users: any[] = [];

// API Routes
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 6) {
    return res.status(400).json({ error: 'Invalid email or password' });
  }

  const existingUser = users.find(u => u.email === email.toLowerCase());
  if (existingUser) {
    return res.status(409).json({ error: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now(), email: email.toLowerCase(), password: hashedPassword };
  users.push(newUser);

  res.status(201).json({ status: 'ok', user: { id: newUser.id, email: newUser.email } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email.toLowerCase());

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ user_id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
  res.status(200).json({ status: 'ok', token });
});

app.get('/api/profile', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded: any = jwt.verify(token, JWT_SECRET);
    const user = users.find(u => u.id === decoded.user_id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.status(200).json({ status: 'ok', user: { id: user.id, email: user.email } });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Static routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'static', 'auth', 'index.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'static', 'auth', 'register.html'));
});

app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'static', 'auth', 'profile.html'));
});

// Serve static files
app.use('/imgs', express.static(path.join(__dirname, 'static', 'imgs')));
app.use('/css', express.static(path.join(__dirname, 'static', 'auth', 'css')));
app.use('/js', express.static(path.join(__dirname, 'static', 'auth', 'js')));
app.use('/static', express.static(path.join(__dirname, 'static')));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Node.js Preview Server running on http://localhost:${PORT}`);
});
