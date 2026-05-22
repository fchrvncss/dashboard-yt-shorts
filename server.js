const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const fetch = require('node-fetch');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 10000;

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL;
const REDIRECT_URI = `${BASE_URL}/callback`;
const REDIRECT_URI_LOGIN = `${BASE_URL}/callback-login`;
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || 'admin123';
const MONGODB_URI = process.env.MONGODB_URI;
// ADMIN_EMAIL: e-mail Google autorizado a fazer login no dashboard.
// Configure em: Render → Environment → ADMIN_EMAIL=seu@email.com
// Também adicione BASE_URL/callback-login nas URIs autorizadas no Google Cloud Console.

// FIX: db começa como null, não undefined — evita crash em rotas antes da conexão
let db = null;

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

// FIX: middleware que bloqueia rotas se o banco não estiver disponível
function checkDB(req, res, next) {
  if (!db) return res.status(503).json({ error: 'Database unavailable' });
  next();
}

// Sessão persistida no MongoDB — sobrevive a restarts do servidor
app.use(session({
  secret: process.env.SESSION_SECRET || 'automata-secure-session',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: MONGODB_URI }),
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // padrão: 30 dias
}));

app.use(express.json());
app.use(express.static('public'));

function checkAuth(req, res, next) {
  if (req.session.isAuthenticated) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

app.post('/api/login', (req, res) => {
  if (req.body.password === DASHBOARD_PASSWORD) {
    req.session.isAuthenticated = true;
    // Se "manter conectado" NÃO marcado: sessão expira ao fechar o browser
    if (!req.body.remember) {
      req.session.cookie.expires = false;
      req.session.cookie.maxAge = undefined;
    }
    res.json({ ok: true });
  } else {
    res.status(401).json({ ok: false });
  }
});

// FIX: rota de logout que destrói a sessão no servidor
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/status', (req, res) => {
  res.json({ authenticated: !!req.session.isAuthenticated });
});

// --- LOGIN COM GOOGLE (autenticação do dashboard) ---
// Diferente do /auth/:slot (que conecta canais), este fluxo autentica o dono do dashboard.
app.get('/auth/google-login', (req, res) => {
  const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI_LOGIN)}&response_type=code&scope=${encodeURIComponent('https://www.googleapis.com/auth/userinfo.email')}&access_type=online&prompt=select_account`;
  res.redirect(url);
});

app.get('/callback-login', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/?error=login_cancelled');
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code, client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI_LOGIN, grant_type: 'authorization_code'
      })
    });
    const tokens = await tokenRes.json();
    const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const userInfo = await userRes.json();
    const adminEmail = process.env.ADMIN_EMAIL;
    if (!adminEmail) return res.redirect('/?error=admin_email_not_configured');
    if (userInfo.email === adminEmail) {
      req.session.isAuthenticated = true;
      req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 dias
      return res.redirect('/');
    }
    return res.redirect('/?error=unauthorized_email');
  } catch (err) {
    return res.redirect('/?error=login_failed');
  }
});

// --- AUTH GOOGLE ---
app.get('/auth/new', checkAuth, (req, res) => {
  const scopes = [
    'https://www.googleapis.com/auth/youtube.readonly',
    'https://www.googleapis.com/auth/yt-analytics.readonly',
    'https://www.googleapis.com/auth/yt-analytics-monetary.readonly',
    'https://www.googleapis.com/auth/userinfo.email'
  ].join(' ');

  const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=${encodeURIComponent(scopes)}&access_type=offline&prompt=consent`;
  res.redirect(url);
});

app.get('/callback', async (req, res) => {
  const { code } = req.query;
  console.log(`🔐 OAuth callback recebido`);
  if (!db) return res.redirect('/?error=db_unavailable');
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
    console.log(`📝 Tokens recebidos:`, { hasAccessToken: !!tokens.access_token, hasRefreshToken: !!tokens.refresh_token, expiresIn: tokens.expires_in });

    if (!tokens.access_token) {
      console.error('❌ Nenhum access_token recebido:', tokens);
      return res.redirect('/?error=no_access_token');
    }

    // Obter informações do usuário
    const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const userInfo = await userRes.json();

    // Obter informações do canal YouTube do usuário
    const channelRes = await fetch('https://www.googleapis.com/youtube/v3/channels?part=snippet,statistics&mine=true', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const channelData = await channelRes.json();
    
    if (!channelData.items || channelData.items.length === 0) {
      console.error('❌ Nenhum canal encontrado');
      return res.redirect('/?error=no_channel');
    }

    const channel = channelData.items[0];
    const channelId = channel.id;
    const channelName = channel.snippet.title;
    const channelThumb = channel.snippet.thumbnails?.default?.url || '';
    const subscriberCount = channel.statistics.subscriberCount || '0';

    console.log(`✅ Canal encontrado: ${channelName} (${channelId})`);

    // Usar EMAIL como userId permanente (não muda entre sessões)
    const userId = userInfo.email;
    
    // Salvar no MongoDB com userId (email) para rastrear qual usuário conectou
    await db.collection('accounts').updateOne(
      { channelId },  // Usar channelId como identificador único do canal
      {
        $set: {
          channelId,
          channelName,
          channelThumb,
          subscriberCount,
          email: userInfo.email,
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token || undefined,
          expiresAt: Date.now() + (tokens.expires_in * 1000),
          userId,  // Agora é o EMAIL (permanente)
          connectedAt: new Date().toISOString()
        }
      },
      { upsert: true }
    );
    console.log(`✅ Conta salva: ${channelName} (${channelId}), userId=${userId}`);

    // Salvar email na sessão para fins de autenticação
    req.session.userEmail = userInfo.email;
    await new Promise((resolve, reject) => {
      req.session.save(err => err ? reject(err) : resolve());
    });

    res.redirect('/?connected=' + channelId);
  } catch (err) {
    console.error('❌ Erro no callback:', err);
    res.redirect('/?error=auth_failed');
  }
});

// --- TOKEN HELPERS ---
async function getValidToken(channelId, userId) {
  if (!db || !channelId) return null;
  const acc = await db.collection('accounts').findOne({ channelId, userId });
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
      { channelId, userId },
      { $set: { accessToken: data.access_token, expiresAt: Date.now() + (data.expires_in * 1000) } }
    );
    return data.access_token;
  } catch (e) {
    return null;
  }
}

// Para chamadas à Data API (thumbnails, metadados): qualquer token serve DO USUÁRIO
async function getAnyToken(userId) {
  if (!db || !userId) return null;
  const accounts = await db.collection('accounts').find({ userId }).toArray();
  for (const acc of accounts) {
    const token = await getValidToken(acc.channelId, userId);
    if (token) return token;
  }
  return null;
}

// Para Analytics API: tenta cada conta do usuário até uma retornar dados válidos.
// apiCallFn(token) retorna null para "tente a próxima", qualquer outro valor para "sucesso".
async function tryAllTokens(apiCallFn, userId) {
  if (!db) return null;
  const accounts = await db.collection('accounts').find({ userId }).toArray();
  console.log(`🔄 tryAllTokens: tentando ${accounts.length} conta(s) do usuário ${userId}`);
  for (const acc of accounts) {
    console.log(`  ├─ Tentando channelId=${acc.channelId}, name=${acc.channelName}`);
    const token = await getValidToken(acc.channelId, userId);
    if (!token) {
      console.log(`  │  ⚠️ Token inválido/expirado`);
      continue;
    }
    try {
      const result = await apiCallFn(token);
      if (result !== null) {
        console.log(`  └─ ✅ Sucesso com ${acc.channelName}`);
        return result;
      }
      console.log(`  │  ⚠️ Retornou null`);
    } catch (e) {
      console.log(`  │  ❌ Erro: ${e.message}`);
    }
  }
  console.log(`❌ Nenhum token funcionou`);
  return null;
}

// --- API DATA ---
app.get('/api/accounts', checkAuth, checkDB, async (req, res) => {
  try {
    // Obter userId (email) da sessão
    const userId = req.session.userEmail;
    
    if (!userId) {
      console.warn('⚠️ Nenhum userEmail na sessão');
      return res.json({});
    }
    
    // Retornar apenas os canais conectados POR ESTE USUÁRIO (baseado no email)
    const docs = await db.collection('accounts').find({ userId }).toArray();
    console.log(`📊 Canais do usuário ${userId}: ${docs.length} canal(is)`, docs.map(d=>({name:d.channelName, id:d.channelId})));
    
    const accounts = {};
    docs.forEach(doc => {
      accounts[doc.channelId] = { 
        name: doc.channelName, 
        thumb: doc.channelThumb,
        email: doc.email,
        connected: true 
      };
    });
    res.json(accounts);
  } catch (e) {
    console.error('❌ Erro ao buscar accounts:', e);
    res.json({});
  }
});

// FIX: usa getAnyToken, adiciona encodeURIComponent nos IDs, trata thumbnail ausente
app.get('/api/channel-thumbs', checkAuth, checkDB, async (req, res) => {
  if (!req.query.ids) return res.json({ ok: false });
  const userId = req.session.userEmail;
  const token = await getAnyToken(userId);
  if (!token) return res.json({ ok: false });
  try {
    const r = await fetch(
      `https://www.googleapis.com/youtube/v3/channels?part=snippet&id=${encodeURIComponent(req.query.ids)}&maxResults=50`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = await r.json();
    if (!data.items) return res.json({ ok: false });
    const thumbs = {};
    data.items.forEach(i => {
      thumbs[i.id] = i.snippet.thumbnails?.default?.url || '';
    });
    return res.json({ ok: true, thumbs });
  } catch (e) {
    return res.json({ ok: false });
  }
});

// tryAllTokens: a Analytics API exige token do dono do canal
app.get('/api/analytics', checkAuth, checkDB, async (req, res) => {
  const { channelId, startDate, endDate } = req.query;
  const userId = req.session.userEmail;  // Email permanente, não sessionID
  console.log(`📊 /api/analytics: channelId=${channelId}, período=${startDate} até ${endDate}, userId=${userId}`);
  if (!channelId || !startDate || !endDate) {
    console.log('⚠️ Parâmetros inválidos');
    return res.json({ ok: false });
  }

  // Usar tryAllTokens para encontrar um token que tenha acesso a este canal
  const rows = await tryAllTokens(async (token) => {
    const url = `https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==${channelId}&startDate=${startDate}&endDate=${endDate}&metrics=estimatedRevenue,views&dimensions=day&sort=day`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) {
      console.log(`⚠️ Token falhou, tentando próximo (status ${r.status})`);
      return null;
    }
    const data = await r.json();
    if (data.error) {
      console.log(`⚠️ API retornou erro: ${data.error.message}`);
      return null;
    }
    console.log(`✅ Sucesso! ${data.rows?.length || 0} linhas`);
    return data.rows || [];
  }, userId);
  if (rows === null) {
    console.log('❌ Nenhum token funcionou');
    return res.json({ ok: false });
  }
  return res.json({ ok: true, rows });
});

app.get('/api/analytics-detail', checkAuth, checkDB, async (req, res) => {
  const { channelId, startDate, endDate } = req.query;
  const userId = req.session.userEmail;
  if (!channelId || !startDate || !endDate) return res.json({ ok: false });
  const rows = await tryAllTokens(async (token) => {
    const url = `https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==${channelId}&startDate=${startDate}&endDate=${endDate}&metrics=views,estimatedMinutesWatched,estimatedRevenue&dimensions=day&sort=day`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) return null;
    const data = await r.json();
    if (data.error) return null;
    return data.rows || [];
  }, userId);
  if (rows === null) return res.json({ ok: false });
  return res.json({ ok: true, rows });
});

app.get('/api/top-videos', checkAuth, checkDB, async (req, res) => {
  const { channelId, startDate, endDate } = req.query;
  const userId = req.session.userEmail;
  if (!channelId || !startDate || !endDate) return res.json({ ok: false, videos: [] });

  // Analytics: precisa do token do dono do canal
  const analyticsRows = await tryAllTokens(async (token) => {
    const url = `https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==${channelId}&startDate=${startDate}&endDate=${endDate}&metrics=views,estimatedRevenue&dimensions=video&sort=-estimatedRevenue&maxResults=10`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) return null;
    const data = await r.json();
    if (data.error) return null;
    return data.rows || [];
  }, userId);

  if (analyticsRows === null) return res.json({ ok: false, videos: [] });
  if (!analyticsRows.length) return res.json({ ok: true, videos: [] });

  // Metadados: qualquer token serve (Data API)
  const token = await getAnyToken(userId);
  if (!token) return res.json({ ok: false, videos: [] });
  try {
    const videoIds = analyticsRows.map(r => r[0]).join(',');
    const dr = await fetch(
      `https://www.googleapis.com/youtube/v3/videos?part=snippet,statistics&id=${encodeURIComponent(videoIds)}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (!dr.ok) return res.json({ ok: false, videos: [] });
    const dData = await dr.json();

    const metaMap = {};
    (dData.items || []).forEach(v => {
      metaMap[v.id] = {
        title: v.snippet.title,
        thumb: v.snippet.thumbnails?.medium?.url || v.snippet.thumbnails?.default?.url || '',
        likes: parseInt(v.statistics.likeCount || 0),
        comments: parseInt(v.statistics.commentCount || 0)
      };
    });

    const videos = analyticsRows.map(r => ({
      id: r[0],
      views: r[1],
      revenue: r[2],
      title: metaMap[r[0]]?.title || '',
      thumb: metaMap[r[0]]?.thumb || '',
      likes: metaMap[r[0]]?.likes || 0,
      comments: metaMap[r[0]]?.comments || 0
    }));

    return res.json({ ok: true, videos });
  } catch (e) {
    return res.json({ ok: false, videos: [] });
  }
});

// NOVO: vídeos recentes paginados, com estatísticas (views, likes, comentários)
app.get('/api/recent-videos', checkAuth, checkDB, async (req, res) => {
  const { channelId, pageToken } = req.query;
  const userId = req.session.userEmail;
  if (!channelId) return res.json({ ok: false, videos: [] });
  const token = await getAnyToken(userId);
  if (!token) return res.json({ ok: false, videos: [] });
  try {
    // Passo 1: lista de vídeos recentes via Search API
    let searchUrl = `https://www.googleapis.com/youtube/v3/search?channelId=${channelId}&type=video&order=date&part=snippet&maxResults=20`;
    if (pageToken) searchUrl += `&pageToken=${encodeURIComponent(pageToken)}`;
    const sr = await fetch(searchUrl, { headers: { Authorization: `Bearer ${token}` } });
    if (!sr.ok) return res.json({ ok: false, videos: [] });
    const sData = await sr.json();
    const items = sData.items || [];
    if (!items.length) return res.json({ ok: true, videos: [], nextPageToken: null, totalResults: 0 });

    // Passo 2: estatísticas dos vídeos via Data API
    const videoIds = items.map(v => v.id.videoId).join(',');
    const statsRes = await fetch(
      `https://www.googleapis.com/youtube/v3/videos?part=statistics&id=${encodeURIComponent(videoIds)}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const statsData = statsRes.ok ? await statsRes.json() : { items: [] };
    const statsMap = {};
    (statsData.items || []).forEach(v => {
      statsMap[v.id] = {
        views: parseInt(v.statistics.viewCount || 0),
        likes: parseInt(v.statistics.likeCount || 0),
        comments: parseInt(v.statistics.commentCount || 0)
      };
    });

    const videos = items.map(v => ({
      id: v.id.videoId,
      title: v.snippet.title,
      thumb: v.snippet.thumbnails?.medium?.url || v.snippet.thumbnails?.default?.url || '',
      publishedAt: v.snippet.publishedAt,
      views: statsMap[v.id.videoId]?.views || 0,
      likes: statsMap[v.id.videoId]?.likes || 0,
      comments: statsMap[v.id.videoId]?.comments || 0
    }));

    return res.json({
      ok: true,
      videos,
      nextPageToken: sData.nextPageToken || null,
      totalResults: sData.pageInfo?.totalResults || 0
    });
  } catch (e) {
    return res.json({ ok: false, videos: [] });
  }
});

app.get('/api/video-metrics', checkAuth, checkDB, async (req, res) => {
  const { videoId, channelId, startDate, endDate } = req.query;
  const userId = req.session.userEmail;
  if (!videoId || !channelId || !startDate || !endDate) return res.json({ ok: false });

  // Analytics do vídeo: precisa do token do dono do canal
  const analyticsRow = await tryAllTokens(async (token) => {
    const url = `https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==${channelId}&startDate=${startDate}&endDate=${endDate}&metrics=views,estimatedRevenue,estimatedMinutesWatched,averageViewPercentage&dimensions=video&filters=video==${videoId}`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) return null;
    const data = await r.json();
    if (data.error) return null;
    // rows[0] ou array vazio — ambos são "sucesso" (canal respondeu)
    return data.rows || [];
  }, userId);

  // Estatísticas do vídeo: qualquer token serve (Data API)
  const token = await getAnyToken(userId);
  let likeCount = 0, commentCount = 0;
  if (token) {
    try {
      const dr = await fetch(
        `https://www.googleapis.com/youtube/v3/videos?part=statistics&id=${encodeURIComponent(videoId)}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const dData = dr.ok ? await dr.json() : { items: [] };
      const stats = dData.items?.[0]?.statistics || {};
      likeCount = parseInt(stats.likeCount || 0);
      commentCount = parseInt(stats.commentCount || 0);
    } catch (e) {}
  }

  if (!analyticsRow || !analyticsRow.length) {
    return res.json({ ok: true, views: 0, revenue: null, minutes: 0, retention: null, likeRate: '—', comments: commentCount });
  }

  const row = analyticsRow[0];
  const views = row[1] || 0;
  const revenue = row[2];
  const minutes = row[3] || 0;
  const avgViewPct = row[4];
  const likeRate = views > 0 ? ((likeCount / views) * 1000).toFixed(1) : '—';

  return res.json({ ok: true, views, revenue, minutes, retention: avgViewPct != null ? avgViewPct.toFixed(1) + '%' : null, likeRate, comments: commentCount });
});

app.listen(PORT, () => console.log(`Server ON: ${PORT}`));
