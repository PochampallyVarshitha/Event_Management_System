// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const DATA_FILE = path.join(__dirname, 'data.json');
const OTP_TTL_MS = 5 * 60 * 1000; // 5 minutes
const VERIFIED_TTL_MS = 3 * 60 * 1000; // 3 minutes after verify-otp to complete registration

// Admin emails from env (comma-separated). Normalize lower-case.
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

// Nodemailer transport (Gmail SMTP recommended)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT || 587),
  secure: (process.env.SMTP_SECURE === 'true') || false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// In-memory OTP & verified maps (short lived). Good enough for demo.
const pendingOtps = {};   // { email: { code, expiresAt, type } }
const justVerified = {};  // { email: expiresAt }  (after successful OTP verification)

// --- Helpers for data file ---
async function loadData() {
  try {
    const raw = await fs.readFile(DATA_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    const initial = { users: [], events: [], registrations: [] };
    await fs.writeFile(DATA_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
}
async function saveData(data) {
  await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// --- Helpers ---
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
function isSruUserEmail(email) {
  return String(email || '').toLowerCase().endsWith('@sru.edu.in');
}
async function sendOtpEmail(to, code, purpose = 'Login/Verification') {
  const html = `
    <div style="font-family:Arial,sans-serif;color:#111">
      <p>Your one-time code for <strong>College Event System</strong> (${purpose}) is:</p>
      <h2 style="letter-spacing:4px">${code}</h2>
      <p>This code is valid for 5 minutes.</p>
      <hr/>
      <small>If you didn't request this, ignore this email.</small>
    </div>
  `;
  return transporter.sendMail({
    from: process.env.FROM_EMAIL || process.env.SMTP_USER,
    to,
    subject: `Your OTP for College Event System`,
    html,
  });
}

// Clean expired entries periodically
setInterval(() => {
  const now = Date.now();
  for (const k of Object.keys(pendingOtps)) {
    if (pendingOtps[k].expiresAt <= now) delete pendingOtps[k];
  }
  for (const k of Object.keys(justVerified)) {
    if (justVerified[k] <= now) delete justVerified[k];
  }
}, 60 * 1000);

// ---------- Routes ----------

// GET admin emails (info)
app.get('/admin-emails', (req, res) => res.json({ admins: ADMIN_EMAILS }));

// Request OTP (type: 'register' or 'login')
// body: { email, type }
app.post('/request-otp', async (req, res) => {
  const { email, type = 'login' } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });

  const key = String(email).toLowerCase();

  // Allow admin emails always, otherwise enforce SRU domain
  if (!ADMIN_EMAILS.includes(key) && !isSruUserEmail(key)) {
    return res.status(400).json({ error: 'Only @sru.edu.in emails can register/login.' });
  }

  const code = generateOtp();
  const expiresAt = Date.now() + OTP_TTL_MS;
  pendingOtps[key] = { code, expiresAt, type };

  try {
    await sendOtpEmail(key, code, type === 'register' ? 'Registration' : 'Login');
    return res.json({ ok: true, message: 'OTP sent (check your email).' });
  } catch (err) {
    console.error('sendOtp error', err && err.message);
    return res.status(500).json({ error: 'Failed to send OTP email (server error).' });
  }
});

// Verify OTP
// body: { email, otp }
app.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'email and otp required' });

  const key = String(email).toLowerCase();
  const record = pendingOtps[key];
  if (!record) return res.status(400).json({ error: 'No OTP requested for this email' });
  if (Date.now() > record.expiresAt) { delete pendingOtps[key]; return res.status(400).json({ error: 'OTP expired' }); }
  if (String(record.code) !== String(otp)) return res.status(400).json({ error: 'Invalid OTP' });

  // success -> mark short-lived verified flag
  justVerified[key] = Date.now() + VERIFIED_TTL_MS;
  delete pendingOtps[key];

  const isAdmin = ADMIN_EMAILS.includes(key);
  return res.json({ ok: true, admin: isAdmin, message: 'OTP verified' });
});

// Complete registration (after OTP verified)
// body: { name, email, password }
app.post('/complete-registration', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'name, email, password required' });

  const key = String(email).toLowerCase();
  if (!ADMIN_EMAILS.includes(key) && !isSruUserEmail(key)) {
    return res.status(400).json({ error: 'Only @sru.edu.in users can register.' });
  }
  if (!justVerified[key]) return res.status(400).json({ error: 'Email not recently verified (request OTP first).' });

  const data = await loadData();
  if (data.users.find(u => u.email === key)) return res.status(400).json({ error: 'User already exists' });

  const hash = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now(), name, email: key, passwordHash: hash, role: ADMIN_EMAILS.includes(key) ? 'admin' : 'user', createdAt: new Date().toISOString() };
  data.users.push(newUser);
  await saveData(data);
  delete justVerified[key];

  return res.json({ ok: true, user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role } });
});

// Login-check (validate password first) client should call before requesting login OTP
// body: { email, password }
app.post('/login-check', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email & password required' });

  const key = String(email).toLowerCase();
  if (!ADMIN_EMAILS.includes(key) && !isSruUserEmail(key)) {
    return res.status(400).json({ error: 'Only @sru.edu.in users can login.' });
  }

  const data = await loadData();
  const user = data.users.find(u => u.email === key);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash || '');
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

  return res.json({ ok: true, message: 'Password verified. Request OTP to continue.' });
});

// Create event (admin)
// body: { adminEmail, title, date, venue, description, category }
app.post('/events', async (req, res) => {
  const { adminEmail, title, date, venue, description, category } = req.body;
  if (!adminEmail || !title || !date || !venue) return res.status(400).json({ error: 'adminEmail, title, date, venue required' });

  const emailKey = String(adminEmail).toLowerCase();
  const data = await loadData();
  const isAdmin = ADMIN_EMAILS.includes(emailKey) || (data.users.find(u => u.email === emailKey && u.role === 'admin'));
  if (!isAdmin) return res.status(403).json({ error: 'Only admins may create events' });

  const ev = { id: Date.now(), title, date: new Date(date).toISOString(), venue, description: description || '', category: category || '', createdBy: emailKey };
  data.events.push(ev);
  await saveData(data);
  return res.json({ ok: true, event: ev });
});

// Edit event (admin)
app.put('/events/:id', async (req, res) => {
  const id = String(req.params.id);
  const { adminEmail, title, date, venue, description, category } = req.body;
  if (!adminEmail) return res.status(400).json({ error: 'adminEmail required' });

  const data = await loadData();
  const emailKey = String(adminEmail).toLowerCase();
  const isAdmin = ADMIN_EMAILS.includes(emailKey) || (data.users.find(u => u.email === emailKey && u.role === 'admin'));
  if (!isAdmin) return res.status(403).json({ error: 'Only admins may edit events' });

  const ev = data.events.find(e => String(e.id) === id);
  if (!ev) return res.status(404).json({ error: 'Event not found' });

  ev.title = title || ev.title;
  ev.date = date ? new Date(date).toISOString() : ev.date;
  ev.venue = venue || ev.venue;
  ev.description = description !== undefined ? description : ev.description;
  ev.category = category !== undefined ? category : ev.category;
  await saveData(data);
  return res.json({ ok: true, event: ev });
});

// Delete event (admin)
app.delete('/events/:id', async (req, res) => {
  const id = String(req.params.id);
  const { adminEmail } = req.body;
  if (!adminEmail) return res.status(400).json({ error: 'adminEmail required' });

  const data = await loadData();
  const emailKey = String(adminEmail).toLowerCase();
  const isAdmin = ADMIN_EMAILS.includes(emailKey) || (data.users.find(u => u.email === emailKey && u.role === 'admin'));
  if (!isAdmin) return res.status(403).json({ error: 'Only admins may delete events' });

  const before = data.events.length;
  data.events = data.events.filter(e => String(e.id) !== id);
  data.registrations = data.registrations.filter(r => String(r.eventId) !== id);
  await saveData(data);
  return res.json({ ok: true, deleted: before - data.events.length });
});

// List events (public)
app.get('/events', async (req, res) => {
  const data = await loadData();
  return res.json({ ok: true, events: data.events });
});

// Register for event (user)
// body: { name, email }
app.post('/events/:id/register', async (req, res) => {
  const eventId = String(req.params.id);
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'name & email required' });

  const data = await loadData();
  const ev = data.events.find(e => String(e.id) === eventId);
  if (!ev) return res.status(404).json({ error: 'Event not found' });

  if (data.registrations.find(r => String(r.eventId) === eventId && r.email === String(email).toLowerCase())) {
    return res.status(400).json({ error: 'Already registered' });
  }

  const reg = { id: Date.now(), eventId, name, email: String(email).toLowerCase(), registeredAt: new Date().toISOString() };
  data.registrations.push(reg);
  await saveData(data);
  return res.json({ ok: true, registration: reg });
});

// Get registrations for an event (admin)
app.get('/events/:id/registrations', async (req, res) => {
  const eventId = String(req.params.id);
  const adminEmail = String(req.query.adminEmail || '').toLowerCase();
  if (!adminEmail) return res.status(400).json({ error: 'adminEmail required' });

  const data = await loadData();
  const isAdmin = ADMIN_EMAILS.includes(adminEmail) || (data.users.find(u => u.email === adminEmail && u.role === 'admin'));
  if (!isAdmin) return res.status(403).json({ error: 'Only admins may view registrations' });

  const regs = data.registrations.filter(r => String(r.eventId) === eventId);
  return res.json({ ok: true, registrations: regs });
});

// Get all registrations (admin)
app.get('/registrations', async (req, res) => {
  const adminEmail = String(req.query.adminEmail || '').toLowerCase();
  if (!adminEmail) return res.status(400).json({ error: 'adminEmail required' });
  const data = await loadData();
  const isAdmin = ADMIN_EMAILS.includes(adminEmail) || (data.users.find(u => u.email === adminEmail && u.role === 'admin'));
  if (!isAdmin) return res.status(403).json({ error: 'Only admins may view registrations' });
  return res.json({ ok: true, registrations: data.registrations });
});

// Get users or a specific user
app.get('/users', async (req, res) => {
  const email = String(req.query.email || '').toLowerCase();
  const data = await loadData();
  if (email) {
    const u = data.users.find(x => x.email === email);
    if (!u) return res.status(404).json({ error: 'User not found' });
    return res.json({ ok: true, user: { id: u.id, name: u.name, email: u.email, role: u.role }});
  }
  return res.json({ ok: true, users: data.users.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role }))});
});

app.listen(PORT, () => console.log(`OTP & data server running on port ${PORT}`));
