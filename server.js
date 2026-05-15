const express = require('express');
const session = require('express-session');
const fetch = require('node-fetch');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 10000;

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL;
const REDIRECT_URI = `${BASE_URL}/callback`;
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || 'admin123';
const MONGODB_URI = process.env.MONGODB_URI;

// --- CORREÇÃO 1: MongoDB com retry automático ---
let db;
let mongoClient;

async function connectDB() {
  try {
    mongoClient = new MongoClient(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
    });
    await mongoClient.connect();
    db = mongoClient.db('automata_db');
    console.log('MongoDB Conectado!');

    mongoClient.on('close', () => {
      console.warn('MongoDB desconectado. Reconectando em 5s...');
      setTimeout(connectDB, 5000);
    });
  } catch (err) {
    console.error('ERRO NO MONGODB:', err.message, '— Tentando novamente em 5s...');
    setTimeout(connectDB, 5000);
  }
}
connectDB();

app.use(session({
  secret: process.env.SESSION_SECRET || 'automata-secure-session',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
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

// --- CORREÇÃO 2: Callback com validação do token ---
app.get('/callback', async (req, res) => {
  const { code, state: slot, error } = req.query;

  if (error) {
    console.error('Erro retornado pelo Google:', error);
    return res.redirect('/?error=' + error);
  }

  if (!code || !slot) {
    return res.redirect('/?error=missing_params');
  }

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

    // Valida se o Google retornou um token válido
    if (!tokens.access_token) {
      console.error('Google não retornou access_token:', tokens);
      return res.redirect('/?error=token_failed');
    }

    const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const userInfo = await userRes.json();

    await db.collection('accounts').updateOne(
      { slot: slot },
      {
        $set: {
          email: userInfo.email || 'desconhecido',
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
          expiresAt: Date.now() + (tokens.expires_in * 1000)
        }
      },
      { upsert: true }
    );

    res.redirect('/?connected=' + slot);
  } catch (err) {
    console.error('Erro no callback:', err.message);
    res.redirect('/?error=auth_failed');
  }
});

// --- API DATA ---
async function getValidToken(slot) {
  const acc = await db.collection('accounts').findOne({ slot: slot });
  if (!acc) return null;

  if (acc.accessToken && acc.expiresAt > Date.now() + 300000) {
    return acc.accessToken;
  }

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

    if (!data.access_token) return null;

    await db.collection('accounts').updateOne(
      { slot: slot },
      { $set: { accessToken: data.access_token, expiresAt: Date.now() + (data.expires_in * 1000) } }
    );
    return data.access_token;
  } catch (e) { return null; }
}

app.get('/api/accounts', checkAuth, async (req, res) => {
  try {
    const docs = await db.collection('accounts').find().toArray();
    const accounts = {};
    docs.forEach(doc => {
      accounts[doc.slot] = { email: doc.email, connected: true };
    });
    res.json(accounts);
  } catch (e) { res.json({}); }
});

app.get('/api/channel-thumbs', checkAuth, async (req, res) => {
  const accounts = await db.collection('accounts').find().toArray();
  for (const acc of accounts) {
    const token = await getValidToken(acc.slot);
    if (!token) continue;
    try {
      const r = await fetch(`https://www.googleapis.com/youtube/v3/channels?part=snippet&id=${req.query.ids}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await r.json();
      if (data.items) {
        const thumbs = {};
        data.items.forEach(i => thumbs[i.id] = i.snippet.thumbnails.default.url);
        return res.json({ ok: true, thumbs });
      }
    } catch (e) {}
  }
  res.json({ ok: false });
});

app.get('/api/analytics', checkAuth, async (req, res) => {
  const { channelId, startDate, endDate } = req.query;
  const accounts = await db.collection('accounts').find().toArray();
  for (const acc of accounts) {
    const token = await getValidToken(acc.slot);
    if (!token) continue;
    try {
      const url = `https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==${channelId}&startDate=${startDate}&endDate=${endDate}&metrics=estimatedRevenue,views&dimensions=day`;
      const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!r.ok) continue;
      const data = await r.json();
      return res.json({ ok: true, rows: data.rows || [] });
    } catch (e) {}
  }
  res.json({ ok: false });
});

// --- ÚLTIMOS VÍDEOS DO CANAL ---
app.get('/api/recent-videos', checkAuth, async (req, res) => {
  const { channelId } = req.query;
  const accounts = await db.collection('accounts').find().toArray();
  for (const acc of accounts) {
    const token = await getValidToken(acc.slot);
    if (!token) continue;
    try {
      const r = await fetch(
        `https://www.googleapis.com/youtube/v3/search?part=snippet&channelId=${channelId}&order=date&maxResults=10&type=video`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!r.ok) continue;
      const data = await r.json();
      if (!data.items?.length) continue;
      const videos = data.items.map(v => ({
        id: v.id.videoId,
        title: v.snippet.title,
        thumb: v.snippet.thumbnails.medium?.url || v.snippet.thumbnails.default?.url,
        publishedAt: v.snippet.publishedAt
      }));
      return res.json({ ok: true, videos });
    } catch (e) {}
  }
  res.json({ ok: false, videos: [] });
});

// --- TOP VÍDEOS POR VIEWS NO PERÍODO ---
app.get('/api/top-videos', checkAuth, async (req, res) => {
  const { channelId, startDate, endDate } = req.query;
  const accounts = await db.collection('accounts').find().toArray();
  for (const acc of accounts) {
    const token = await getValidToken(acc.slot);
    if (!token) continue;
    try {
      const url = `https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==${channelId}&startDate=${startDate}&endDate=${endDate}&metrics=views,estimatedRevenue&dimensions=video&sort=-views&maxResults=10`;
      const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!r.ok) continue;
      const data = await r.json();
      if (!data.rows?.length) return res.json({ ok: true, videos: [] });

      // Busca títulos e thumbs dos vídeos
      const videoIds = data.rows.map(row => row[0]).join(',');
      const detailRes = await fetch(
        `https://www.googleapis.com/youtube/v3/videos?part=snippet&id=${videoIds}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const detailData = await detailRes.json();
      const details = {};
      (detailData.items || []).forEach(v => {
        details[v.id] = {
          title: v.snippet.title,
          thumb: v.snippet.thumbnails.medium?.url || v.snippet.thumbnails.default?.url
        };
      });

      const videos = data.rows.map(row => ({
        id: row[0],
        views: row[1],
        revenue: row[2],
        title: details[row[0]]?.title || 'Sem título',
        thumb: details[row[0]]?.thumb || ''
      }));
      return res.json({ ok: true, videos });
    } catch (e) {}
  }
  res.json({ ok: false, videos: [] });
});

// --- ANALYTICS DETALHADO DO CANAL (views, minutos, receita por dia) ---
app.get('/api/analytics-detail', checkAuth, async (req, res) => {
  const { channelId, startDate, endDate } = req.query;
  const accounts = await db.collection('accounts').find().toArray();
  for (const acc of accounts) {
    const token = await getValidToken(acc.slot);
    if (!token) continue;
    try {
      const url = `https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==${channelId}&startDate=${startDate}&endDate=${endDate}&metrics=views,estimatedMinutesWatched,estimatedRevenue&dimensions=day`;
      const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!r.ok) continue;
      const data = await r.json();
      return res.json({ ok: true, rows: data.rows || [] });
    } catch (e) {}
  }
  res.json({ ok: false, rows: [] });
});

app.listen(PORT, () => console.log(`Server ON: ${PORT}`));
