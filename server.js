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

    // Usar EMAIL como userId permanente
    const userId = userInfo.email;
    
    // Se há apenas 1 canal, conectar direto
    if (channelData.items.length === 1) {
      const channel = channelData.items[0];
      const channelId = channel.id;
      const channelName = channel.snippet.title;
      const channelThumb = channel.snippet.thumbnails?.default?.url || '';
      const subscriberCount = channel.statistics.subscriberCount || '0';

      console.log(`✅ Canal encontrado: ${channelName} (${channelId})`);

      // Gerar ou usar dashboardUserId existente (persiste entre emails)
      let dashboardUserId = req.session.dashboardUserId;
      if (!dashboardUserId) {
        // Primeira autenticação: gerar ID único
        dashboardUserId = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        req.session.dashboardUserId = dashboardUserId;
        console.log(`🆔 Novo usuário da dashboard: ${dashboardUserId}`);
      }

      const docId = `${dashboardUserId}::${channelId}`;
      console.log(`🔍 Tentando salvar: docId=${docId}`);
      
      const result = await db.collection('accounts').updateOne(
        { _id: docId },
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
            dashboardUserId,  // ID permanente da dashboard
            oauthEmail: userInfo.email,  // Email específico do OAuth
            connectedAt: new Date().toISOString()
          }
        },
        { upsert: true }
      );
      console.log(`📊 updateOne resultado:`, { matched: result.matchedCount, modified: result.modifiedCount, upserted: result.upsertedId });
      
      const allChannels = await db.collection('accounts').find({ dashboardUserId }).toArray();
      console.log(`✅ Dashboard ${dashboardUserId} agora tem ${allChannels.length} canal(is):`, allChannels.map(c => c.channelName).join(', '));

      // Salvar email na sessão para fins de autenticação
      req.session.user = true;
      req.session.userEmail = userInfo.email;
      req.session.dashboardUserId = dashboardUserId;
      
      await new Promise((resolve, reject) => {
        req.session.save(err => err ? reject(err) : resolve());
      });

      return res.redirect('/?connected=' + channelId);
    }
    
    // Se há múltiplos canais, salvar na sessão e mostrar seletor
    console.log(`⚠️ ${channelData.items.length} canal(is) encontrado(s), mostrando seletor`);
    
    // Gerar ou usar dashboardUserId existente
    let dashboardUserId = req.session.dashboardUserId;
    if (!dashboardUserId) {
      dashboardUserId = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
      req.session.dashboardUserId = dashboardUserId;
      console.log(`🆔 Novo usuário da dashboard: ${dashboardUserId}`);
    }
    
    // Salvar tokens e canais na sessão temporária
    req.session.pendingAuth = {
      dashboardUserId,
      oauthEmail: userInfo.email,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || undefined,
      expiresIn: tokens.expires_in,
      channels: channelData.items.map(ch => ({
        id: ch.id,
        name: ch.snippet.title,
        thumb: ch.snippet.thumbnails?.default?.url || '',
        subscribers: ch.statistics.subscriberCount || '0'
      }))
    };
    
    await new Promise((resolve, reject) => {
      req.session.save(err => err ? reject(err) : resolve());
    });

    // Redirecionar para página de seleção
    res.redirect('/?select-channel=true');
  } catch (err) {
    console.error('❌ Erro no callback:', err);
    res.redirect('/?error=auth_failed');
  }
});

// Endpoint para o usuário selecionar qual canal conectar (quando há múltiplos)
app.post('/api/select-channel', async (req, res) => {
  const { channelId } = req.body;
  const pending = req.session.pendingAuth;
  
  if (!pending || !channelId) {
    return res.json({ ok: false, error: 'Dados inválidos' });
  }
  
  try {
    const dashboardUserId = pending.dashboardUserId;
    const oauthEmail = pending.oauthEmail;
    const selectedChannel = pending.channels.find(c => c.id === channelId);
    
    if (!selectedChannel) {
      return res.json({ ok: false, error: 'Canal não encontrado' });
    }
    
    console.log(`✅ Dashboard ${dashboardUserId} selecionou canal: ${selectedChannel.name} (${channelId})`);
    
    const docId = `${dashboardUserId}::${channelId}`;
    
    // Salvar o canal selecionado no MongoDB
    const result = await db.collection('accounts').updateOne(
      { _id: docId },
      {
        $set: {
          channelId,
          channelName: selectedChannel.name,
          channelThumb: selectedChannel.thumb,
          subscriberCount: selectedChannel.subscribers,
          email: oauthEmail,
          accessToken: pending.accessToken,
          refreshToken: pending.refreshToken || undefined,
          expiresAt: Date.now() + (pending.expiresIn * 1000),
          dashboardUserId,
          oauthEmail,
          connectedAt: new Date().toISOString()
        }
      },
      { upsert: true }
    );
    
    console.log(`📊 updateOne resultado:`, { matched: result.matchedCount, modified: result.modifiedCount, upserted: result.upsertedId });
    
    // Marcar como autenticado
    req.session.user = true;
    req.session.userEmail = oauthEmail;
    delete req.session.pendingAuth;  // Limpar dados temporários
    
    await new Promise((resolve, reject) => {
      req.session.save(err => err ? reject(err) : resolve());
    });
    
    res.json({ ok: true, channelId });
  } catch (err) {
    console.error('❌ Erro ao selecionar canal:', err);
    res.json({ ok: false, error: 'Erro ao salvar' });
  }
});

// Endpoint para retornar os canais pendentes
app.get('/api/pending-channels', async (req, res) => {
  const pending = req.session.pendingAuth;
  
  if (!pending || !pending.channels) {
    return res.json({ ok: false, channels: [] });
  }
  
  res.json({ ok: true, channels: pending.channels });
});

// --- TOKEN HELPERS ---
async function getValidToken(channelId, userId) {
  if (!db || !channelId) return null;
  // userId agora é dashboardUserId
  const acc = await db.collection('accounts').findOne({ channelId, dashboardUserId: userId });
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
      { channelId, dashboardUserId: userId },
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
  // userId agora é dashboardUserId
  const accounts = await db.collection('accounts').find({ dashboardUserId: userId }).toArray();
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
  // userId agora é o dashboardUserId
  const accounts = await db.collection('accounts').find({ dashboardUserId: userId }).toArray();
  console.log(`🔄 tryAllTokens: tentando ${accounts.length} conta(s) do dashboard ${userId}`);
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
    // Obter dashboardUserId da sessão (persiste no MongoDB)
    let dashboardUserId = req.session.dashboardUserId;
    
    if (!dashboardUserId) {
      console.warn('⚠️ Nenhum dashboardUserId na sessão');
      return res.json({});
    }
    
    console.log(`📊 Dashboard ${dashboardUserId}: buscando canais...`);
    
    // Retornar apenas os canais conectados POR ESTE DASHBOARD USER
    const docs = await db.collection('accounts').find({ dashboardUserId }).toArray();
    console.log(`✅ Dashboard ${dashboardUserId}: ${docs.length} canal(is)`, docs.map(d=>({name:d.channelName, id:d.channelId})));
    
    const accounts = {};
    docs.forEach(doc => {
      accounts[doc.channelId] = { 
        name: doc.channelName, 
        thumb: doc.channelThumb,
        email: doc.oauthEmail,
        connected: true 
      };
    });
    res.json(accounts);
  } catch (e) {
    console.error('❌ Erro ao buscar accounts:', e);
    res.json({});
  }
});

// Endpoint para desconectar/deletar um canal
app.post('/api/disconnect-channel', checkAuth, checkDB, async (req, res) => {
  const { channelId } = req.body;
  const dashboardUserId = req.session.dashboardUserId;
  
  if (!channelId || !dashboardUserId) {
    return res.json({ ok: false, error: 'Dados inválidos' });
  }
  
  try {
    const docId = `${dashboardUserId}::${channelId}`;
    const result = await db.collection('accounts').deleteOne({ _id: docId });
    
    if (result.deletedCount > 0) {
      console.log(`🗑️ Canal deletado: ${channelId} do usuário ${dashboardUserId}`);
      
      // Listar canais restantes
      const remaining = await db.collection('accounts').find({ dashboardUserId }).toArray();
      console.log(`📊 Canais restantes: ${remaining.length}`, remaining.map(d=>d.channelName).join(', '));
      
      return res.json({ ok: true, message: 'Canal desconectado com sucesso' });
    } else {
      return res.json({ ok: false, error: 'Canal não encontrado' });
    }
  } catch (err) {
    console.error('❌ Erro ao desconectar canal:', err);
    res.json({ ok: false, error: 'Erro ao deletar' });
  }
});

// FIX: usa getAnyToken, adiciona encodeURIComponent nos IDs, trata thumbnail ausente
app.get('/api/channel-thumbs', checkAuth, checkDB, async (req, res) => {
  if (!req.query.ids) return res.json({ ok: false });
  const dashboardUserId = req.session.dashboardUserId;
  const token = await getAnyToken(dashboardUserId);
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
  const dashboardUserId = req.session.dashboardUserId;
  console.log(`📊 /api/analytics: channelId=${channelId}, período=${startDate} até ${endDate}, dashboardUserId=${dashboardUserId}`);
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
  }, dashboardUserId);
  if (rows === null) {
    console.log('❌ Nenhum token funcionou');
    return res.json({ ok: false });
  }
  return res.json({ ok: true, rows });
});

app.get('/api/analytics-detail', checkAuth, checkDB, async (req, res) => {
  const { channelId, startDate, endDate } = req.query;
  const dashboardUserId = req.session.dashboardUserId;
  if (!channelId || !startDate || !endDate) return res.json({ ok: false });
  const rows = await tryAllTokens(async (token) => {
    const url = `https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==${channelId}&startDate=${startDate}&endDate=${endDate}&metrics=views,estimatedMinutesWatched,estimatedRevenue&dimensions=day&sort=day`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) return null;
    const data = await r.json();
    if (data.error) return null;
    return data.rows || [];
  }, dashboardUserId);
  if (rows === null) return res.json({ ok: false });
  return res.json({ ok: true, rows });
});

app.get('/api/top-videos', checkAuth, checkDB, async (req, res) => {
  const { channelId, startDate, endDate } = req.query;
  const dashboardUserId = req.session.dashboardUserId;
  if (!channelId || !startDate || !endDate) return res.json({ ok: false, videos: [] });

  // Analytics: precisa do token do dono do canal
  const analyticsRows = await tryAllTokens(async (token) => {
    const url = `https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==${channelId}&startDate=${startDate}&endDate=${endDate}&metrics=views,estimatedRevenue&dimensions=video&sort=-estimatedRevenue&maxResults=10`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) return null;
    const data = await r.json();
    if (data.error) return null;
    return data.rows || [];
  }, dashboardUserId);

  if (analyticsRows === null) return res.json({ ok: false, videos: [] });
  if (!analyticsRows.length) return res.json({ ok: true, videos: [] });

  // Metadados: qualquer token serve (Data API)
  const token = await getAnyToken(dashboardUserId);
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
  const dashboardUserId = req.session.dashboardUserId;
  if (!channelId) return res.json({ ok: false, videos: [] });
  const token = await getAnyToken(dashboardUserId);
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

// NOVO: TODOS os vídeos do canal, ordenados por views (maior → menor)
// Usa a playlist de uploads (eficiente em quota) e pagina por todos os vídeos
app.get('/api/all-videos', checkAuth, checkDB, async (req, res) => {
  const { channelId } = req.query;
  const dashboardUserId = req.session.dashboardUserId;
  if (!channelId) return res.json({ ok: false, videos: [] });
  const token = await getAnyToken(dashboardUserId);
  if (!token) return res.json({ ok: false, videos: [] });
  try {
    // Passo 1: obter a playlist de uploads do canal
    const chRes = await fetch(
      `https://www.googleapis.com/youtube/v3/channels?part=contentDetails&id=${encodeURIComponent(channelId)}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const chData = await chRes.json();
    const uploadsPlaylist = chData.items?.[0]?.contentDetails?.relatedPlaylists?.uploads;
    if (!uploadsPlaylist) return res.json({ ok: false, videos: [] });

    // Passo 2: paginar por TODOS os vídeos da playlist (50 por página)
    const videoMeta = {};
    const allVideoIds = [];
    let pageToken = null, pages = 0;
    do {
      let url = `https://www.googleapis.com/youtube/v3/playlistItems?part=snippet,contentDetails&playlistId=${uploadsPlaylist}&maxResults=50`;
      if (pageToken) url += `&pageToken=${encodeURIComponent(pageToken)}`;
      const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!r.ok) break;
      const data = await r.json();
      (data.items || []).forEach(item => {
        const vid = item.contentDetails?.videoId;
        if (!vid) return;
        allVideoIds.push(vid);
        videoMeta[vid] = {
          id: vid,
          title: item.snippet.title,
          thumb: item.snippet.thumbnails?.medium?.url || item.snippet.thumbnails?.default?.url || '',
          publishedAt: item.contentDetails.videoPublishedAt || item.snippet.publishedAt,
          views: 0, likes: 0, comments: 0
        };
      });
      pageToken = data.nextPageToken || null;
      pages++;
    } while (pageToken && pages < 60);  // limite: 60 páginas = 3000 vídeos

    // Passo 3: buscar estatísticas (views) em lotes de 50
    for (let i = 0; i < allVideoIds.length; i += 50) {
      const batch = allVideoIds.slice(i, i + 50).join(',');
      const sr = await fetch(
        `https://www.googleapis.com/youtube/v3/videos?part=statistics&id=${encodeURIComponent(batch)}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!sr.ok) continue;
      const sd = await sr.json();
      (sd.items || []).forEach(v => {
        if (videoMeta[v.id]) {
          videoMeta[v.id].views = parseInt(v.statistics.viewCount || 0);
          videoMeta[v.id].likes = parseInt(v.statistics.likeCount || 0);
          videoMeta[v.id].comments = parseInt(v.statistics.commentCount || 0);
        }
      });
    }

    // Passo 4: ordenar por views (maior → menor)
    const videos = Object.values(videoMeta).sort((a, b) => (b.views || 0) - (a.views || 0));
    console.log(`📹 all-videos: ${videos.length} vídeos do canal ${channelId}`);

    return res.json({ ok: true, videos, totalResults: videos.length });
  } catch (e) {
    console.error('❌ Erro all-videos:', e);
    return res.json({ ok: false, videos: [] });
  }
});

app.get('/api/video-metrics', checkAuth, checkDB, async (req, res) => {
  const { videoId, channelId, startDate, endDate } = req.query;
  const dashboardUserId = req.session.dashboardUserId;
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
  }, dashboardUserId);

  // Estatísticas do vídeo: qualquer token serve (Data API)
  const token = await getAnyToken(dashboardUserId);
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

// DEBUG: Listar todos os canais do usuário
app.get('/api/debug-channels', checkAuth, checkDB, async (req, res) => {
  const dashboardUserId = req.session.dashboardUserId;
  const allChannels = await db.collection('accounts').find({ dashboardUserId }).toArray();
  console.log(`🔍 DEBUG: Dashboard ${dashboardUserId} tem ${allChannels.length} canal(is)`);
  res.json({
    dashboardUserId,
    totalChannels: allChannels.length,
    channels: allChannels.map(c => ({
      channelId: c.channelId,
      channelName: c.channelName,
      connectedAt: c.connectedAt
    }))
  });
});

app.listen(PORT, () => console.log(`Server ON: ${PORT}`));
