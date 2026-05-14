const express = require('express');
const session = require('express-session');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

// ── CONFIG ────────────────────────────────────────────────
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL; // ex: https://seu-app.run.app
const REDIRECT_URI = `${BASE_URL}/callback`;

const SCOPES = [
  'https://www.googleapis.com/auth/youtube.readonly',
  'https://www.googleapis.com/auth/yt-analytics.readonly',
  'https://www.googleapis.com/auth/yt-analytics-monetary.readonly',
  'https://www.googleapis.com/auth/userinfo.email'
].join(' ');

// ── SESSÃO ────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET || 'dashboard-yt-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 dias
}));

app.use(express.json());
app.use(express.static('public'));

// ── STORAGE em memória (persiste enquanto o servidor roda) ─
// Para persistência real, usaríamos um banco, mas isso funciona bem
let storedAccounts = {}; // { slotId: { email, refreshToken, accessToken, expiresAt } }

// ── ROTAS OAuth ───────────────────────────────────────────

// Inicia login para um slot específico
app.get('/auth/:slot', (req, res) => {
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

// Callback do Google
app.get('/callback', async (req, res) => {
  const { code, state: slot, error } = req.query;

  if (error) {
    return res.redirect(`/?error=${error}`);
  }

  try {
    // Troca code por tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });

    const tokens = await tokenRes.json();
    if (!tokens.access_token) throw new Error('Sem access token');

    // Busca email
    const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const userInfo = await userRes.json();

    // Salva conta
    storedAccounts[slot] = {
      email: userInfo.email || `Conta ${slot}`,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Date.now() + (tokens.expires_in * 1000)
    };

    res.redirect('/?connected=' + slot);
  } catch (err) {
    console.error('Erro no callback:', err);
    res.redirect('/?error=callback_failed');
  }
});

// ── API: status das contas ────────────────────────────────
app.get('/api/accounts', (req, res) => {
  const accounts = {};
  for (const [slot, acc] of Object.entries(storedAccounts)) {
    accounts[slot] = { email: acc.email, connected: true };
  }
  res.json(accounts);
});

// ── API: desconectar conta ────────────────────────────────
app.delete('/api/accounts/:slot', (req, res) => {
  delete storedAccounts[req.params.slot];
  res.json({ ok: true });
});

// ── HELPER: garante token válido ──────────────────────────
async function getValidToken(slot) {
  const acc = storedAccounts[slot];
  if (!acc) return null;

  // Se token ainda é válido (com 5min de margem)
  if (acc.accessToken && acc.expiresAt > Date.now() + 300000) {
    return acc.accessToken;
  }

  // Renova com refresh token
  if (!acc.refreshToken) return null;

  try {
    const res = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: acc.refreshToken,
        grant_type: 'refresh_token'
      })
    });

    const data = await res.json();
    if (!data.access_token) return null;

    storedAccounts[slot].accessToken = data.access_token;
    storedAccounts[slot].expiresAt = Date.now() + (data.expires_in * 1000);
    return data.access_token;
  } catch {
    return null;
  }
}

// ── API: buscar analytics de um canal ────────────────────
app.get('/api/analytics', async (req, res) => {
  const { channelId, startDate, endDate } = req.query;

  if (!channelId || !startDate || !endDate) {
    return res.status(400).json({ error: 'Parâmetros faltando' });
  }

  // Tenta cada slot até um funcionar
  for (const slot of Object.keys(storedAccounts)) {
    const token = await getValidToken(slot);
    if (!token) continue;

    try {
      const url = new URL('https://youtubeanalytics.googleapis.com/v2/reports');
      url.searchParams.set('ids', `channel==${channelId}`);
      url.searchParams.set('startDate', startDate);
      url.searchParams.set('endDate', endDate);
      url.searchParams.set('metrics', 'estimatedRevenue,views');

      const r = await fetch(url.toString(), {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (!r.ok) continue;

      const data = await r.json();
      if (!data.rows?.length) {
        return res.json({ ok: true, receita: 0, views: 0 });
      }

      return res.json({
        ok: true,
        receita: parseFloat(data.rows[0][0]) || 0,
        views: parseInt(data.rows[0][1]) || 0
      });
    } catch { continue; }
  }

  res.json({ ok: false });
});

// ── SERVE INDEX ───────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
