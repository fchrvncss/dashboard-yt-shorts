const express = require('express');
const session = require('express-session');
const fetch = require('node-fetch');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 10000;

// Configurações do Render / Environment
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL;
const REDIRECT_URI = `${BASE_URL}/callback`;
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || 'admin123';
const MONGODB_URI = process.env.MONGODB_URI;

// --- CONEXÃO COM O BANCO DE DADOS ---
let db;
async function connectDB() {
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db('automata_db');
    console.log('MongoDB Conectado!');
  } catch (err) {
    console.error('ERRO CRÍTICO NO MONGODB:', err.message);
  }
}
connectDB();

app.use(session({
  secret: process.env.SESSION_SECRET || 'automata-secure-session',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 dias de sessão no navegador
}));

app.use(express.json());
app.use(express.static('public'));

// --- SEGURANÇA ---
function checkAuth(req, res, next) {
  if (req.session.isAuthenticated) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

app.post('/api/login', (req, res) => {
  if (req.body.password === DASHBOARD_PASSWORD) {
    req.session.isAuthenticated = true;
    res.json({ ok: true });
  } else {
    res.status(401).json({ ok: false });
  }
});

app.get('/api/status', (req, res) => {
  res.json({ authenticated: !!req.session.isAuthenticated });
});

// --- AUTH GOOGLE ---
app.get('/auth/:slot', checkAuth, (req, res) => {
  const slot = req.params.slot;
  const scopes = [
    'https://www.googleapis.com/auth/youtube.readonly',
    'https://www.googleapis.com/auth/yt-analytics.readonly',
    'https://www.googleapis.com/auth/yt-analytics-monetary.readonly',
    'https://www.googleapis.com/auth/userinfo.email'
  ].join(' ');

  const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=${encodeURIComponent(scopes)}&access_type=offline&prompt=consent&state=${slot}`;
  res.redirect(url);
});

app.get('/callback', async (req, res) => {
  const { code, state: slot } = req.query;
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code, client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI, grant_type: 'authorization_code'
      })
    });
    const tokens = await tokenRes.json();

    const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const userInfo = await userRes.json();

    // SALVA NO MONGODB (Se já existir, atualiza. Se não, cria.)
    await db.collection('accounts').updateOne(
      { slot: slot },
      { 
        $set: { 
          email: userInfo.email,
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
          expiresAt: Date.now() + (tokens.expires_in * 1000)
        } 
      },
      { upsert: true }
    );

    res.redirect('/?connected=' + slot);
  } catch (err) {
    res.redirect('/?error=auth_failed');
  }
});

// --- API DATA ---

async function getValidToken(slot) {
  const acc = await db.collection('accounts').findOne({ slot: slot });
  if (!acc) return null;

  // Se o token ainda é válido (com margem de 5 min)
  if (acc.accessToken && acc.expiresAt > Date.now() + 300000) {
    return acc.accessToken;
  }

  // Se expirou, usa o Refresh Token
  if (!acc.refreshToken) return null;
  try {
    const res = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
        refresh_token: acc.refreshToken, grant_type: 'refresh_token'
      })
    });
    const data = await res.json();
    
    await db.collection('accounts').updateOne(
      { slot: slot },
      { 
        $set: { 
          accessToken: data.access_token, 
          expiresAt: Date.now() + (data.expires_in * 1000) 
        } 
      }
    );
    return data.access_token
