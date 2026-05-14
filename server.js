const express = require('express');
const session = require('express-session');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL;
const REDIRECT_URI = `${BASE_URL}/callback`;

// ── AQUI ESTÁ A CHAVE DE SEGURANÇA ──
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || 'admin123';

const SCOPES = [
  'https://www.googleapis.com/auth/youtube.readonly',
  'https://www.googleapis.com/auth/yt-analytics.readonly',
  'https://www.googleapis.com/auth/yt-analytics-monetary.readonly',
  'https://www.googleapis.com/auth/userinfo.email'
].join(' ');

app.use(session({
  secret: process.env.SESSION_SECRET || 'dashboard-yt-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

app.use(express.json());
app.use(express.static('public'));

let storedAccounts = {};

// ── MIDDLEWARE DE SEGURANÇA (O GUARDA-COSTAS) ──
function checkAuth(req, res, next) {
  if (req.session.isAuthenticated) return next();
  res.status(401).json({ error: 'Acesso negado' });
}

// ── ROTAS DE LOGIN DO SITE ──
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

// ── ROTAS PROTEGIDAS ──
app.get('/auth/:slot', checkAuth, (req, res) => {
  const slot = req.params.slot;
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', SCOPES);
  url.searchParams.set('access_type', 'offline');
  url.searchParams.set('prompt', 'select_account consent');
  url.searchParams.set('state', slot);
  res.redirect(url.toString());
});

app.get('/callback', async (req, res) => {
  const { code, state: slot, error } = req.query;
  if (error) return res.redirect(`/?error=${error}`);

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

    storedAccounts[slot] = {
      email: userInfo.email,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Date.now() + (tokens.expires_in * 1000)
    };

    res.redirect('/?connected=' + slot);
  } catch (err) {
    res.redirect('/?error=callback_failed');
  }
});

app.get('/api/accounts', checkAuth, (req, res) => {
  const accounts = {};
  for (const [slot, acc] of Object.entries(storedAccounts)) {
    accounts[slot] = { email: acc.email, connected: true };
  }
  res.json(accounts);
});

async function getValidToken(slot) {
  const acc = storedAccounts[slot];
  if (!acc) return null;
  if (acc.accessToken && acc.expiresAt > Date.now() + 300000) return acc.accessToken;
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
    storedAccounts[slot].accessToken = data.access_token;
    storedAccounts[slot].expiresAt = Date.now() + (data.expires_in * 1000);
    return data.access_token;
  } catch { return null; }
}

app.get('/api/analytics', checkAuth, async (req, res) => {
  const { channelId, startDate, endDate } = req.query;
  
  for (const slot of Object.keys(storedAccounts)) {
    const token = await getValidToken(slot);
    if (!token) continue;

    try {
      const url = new URL('https://youtubeanalytics.googleapis.com/v2/reports');
      url.searchParams.set('ids', `channel==${channelId}`);
      url.searchParams.set('startDate', startDate);
      url.searchParams.set('endDate', endDate);
      url.searchParams.set('metrics', 'estimatedRevenue,views');
      url.searchParams.set('dimensions', 'day');

      const r = await fetch(url.toString(), {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (!r.ok) continue;
      const data = await r.json();
      return res.json({ ok: true, rows: data.rows || [] });
    } catch { continue; }
  }
  res.json({ ok: false });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Rodando na porta ${PORT}`));
