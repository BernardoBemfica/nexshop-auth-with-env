// AuthSDK_Backend.js — Signup(Login) + MFA SMS + KBA + anti-brute-force + sessão
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// Twilio (opcional)
const twilioSid = process.env.TWILIO_ACCOUNT_SID || null;
const twilioAuth = process.env.TWILIO_AUTH_TOKEN || null;
const twilioFrom = process.env.TWILIO_FROM_NUMBER || null;
const twilioClient = (twilioSid && twilioAuth) ? require('twilio')(twilioSid, twilioAuth) : null;

const app = express();
const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(cors());
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'AuthSDK_Frontend.html'));
});

// -------------------------
// "Banco" em memória (demo)
// -------------------------
// users[email] = { passwordHash, phoneE164, favoriteColor, birthYear, devices:Set }
const users = Object.create(null);

// desafios por fingerprint:
// { otp, otpExpires, attempts, lockedUntil, smsTo, resendCount, lastSentAt, forUserEmail }
const challenges = Object.create(null);

// sessões simples por token
// sessions[token] = { email, createdAt }
const sessions = Object.create(null);

// antifraude “histórico”
const mockDB = {
  knownDevices: new Set(['c9c17381a40c25641217f3c389ee7c19']),
  knownUserAgentsByDevice: new Map([
    ['c9c17381a40c25641217f3c389ee7c19', new Set(['ua_hash_exemplo'])]
  ]),
  knownIpCidrs: ['201.0.0.0/8', '187.0.0.0/8'],
  firstAccesses: new Set(['new_device_id_123']),
};

// -------------------------
// Utils
// -------------------------
function ipInCidr(ip, cidr) {
  try {
    const [range, bits] = cidr.split('/');
    const toLong = s => s.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0;
    const mask = ~((1 << (32 - parseInt(bits, 10))) - 1) >>> 0;
    return (toLong(ip) & mask) === (toLong(range) & mask);
  } catch { return false; }
}
function ipMatchesKnownRanges(ip, ranges) { return ranges.some(r => ipInCidr(ip, r)); }
const hash = s => crypto.createHash('sha256').update(String(s)).digest('hex');

function normalizePhoneBR(raw) {
  if (!raw) return null;
  const digits = String(raw).replace(/\D/g, '').replace(/^0+/, '');
  if (digits.length === 10 || digits.length === 11) return '+55' + digits;
  if ((digits.length === 12 || digits.length === 13) && digits.startsWith('55')) return '+' + digits;
  if (/^\+/.test(raw)) return raw;
  return null;
}

function makeOtp() { return '' + Math.floor(100000 + Math.random() * 900000); }

async function sendSms(to, body) {
  if (twilioClient && twilioFrom) {
    try {
      await twilioClient.messages.create({ from: twilioFrom, to, body });
      console.log(`[SMS] Enviado para ${to}`);
      return true;
    } catch (e) {
      console.warn('[SMS] Falha ao enviar via Twilio:', e.message);
      return false;
    }
  } else {
    console.log(`[DEBUG] Twilio não configurado. SMS para ${to}: ${body}`);
    return true;
  }
}

function newSession(email) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions[token] = { email, createdAt: Date.now() };
  return token;
}

// -------------------------
// Score antifraude
// -------------------------
function calculateRiskScore({ fingerprint, behavior, env }, req) {
  let score = 0;

  const clientUA = req.get('user-agent') || '';
  const fwdHeader = req.headers['x-forwarded-for'];
  const clientIP = (Array.isArray(fwdHeader) ? fwdHeader[0] : (fwdHeader || '')).split(',')[0].trim()
                 || req.socket.remoteAddress || '';

  const isUnknownDevice = !mockDB.knownDevices.has(fingerprint);
  if (isUnknownDevice) score += 20;

  const ipLooksOk = clientIP && ipMatchesKnownRanges(clientIP, mockDB.knownIpCidrs);
  if (!ipLooksOk) score += 15;

  if (env?.webdriver || env?.headlessHints) score += 15;

  const userHour = env?.localHour;
  if (typeof userHour === 'number' && (userHour >= 23 || userHour < 6)) score += 10;

  const uaHash = hash(clientUA);
  const past = mockDB.knownUserAgentsByDevice.get(fingerprint);
  const uaChanged = past && !past.has(uaHash);
  if (uaChanged) score += 5;

  if (behavior?.timeOnPage < 5 || behavior?.timeOnPage > 600) score += 10;
  if ((behavior?.mouseMovements ?? 0) < 50) score += 10;
  if ((behavior?.hiddenCount ?? 0) >= 2) score += 5;
  if (behavior?.avgKeystrokeMs && behavior.avgKeystrokeMs < 60) score += 10;
  if (behavior?.pastedPassword) score += 10;

  if (mockDB.firstAccesses.has(fingerprint)) score += 5;

  if (score > 100) score = 100;

  let action = 'allow';
  if (score >= 75) action = 'deny';
  else if (score >= 50) action = 'review';
  else if (score >= 20) action = 'mfa';

  // aprendizado simples de UA p/ devices conhecidos
  if (!isUnknownDevice) {
    if (!mockDB.knownUserAgentsByDevice.has(fingerprint)) {
      mockDB.knownUserAgentsByDevice.set(fingerprint, new Set([uaHash]));
    } else {
      mockDB.knownUserAgentsByDevice.get(fingerprint).add(uaHash);
    }
  } else if (action === 'allow' || action === 'mfa') {
    mockDB.knownDevices.add(fingerprint);
    mockDB.knownUserAgentsByDevice.set(fingerprint, new Set([uaHash]));
  }

  return { score, action, server: { ip: clientIP, uaHash } };
}

// -------------------------
// AUTH: Signup / Login / Sessão
// -------------------------
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, phone, favoriteColor, birthYear } = req.body || {};
  if (!email || !password || !phone || !favoriteColor || !birthYear) {
    return res.status(400).json({ ok: false, error: 'email, password, phone, favoriteColor, birthYear são obrigatórios' });
  }
  if (users[email]) return res.status(409).json({ ok: false, error: 'email já cadastrado' });

  const phoneE164 = normalizePhoneBR(phone);
  if (!phoneE164) return res.status(400).json({ ok: false, error: 'telefone inválido (digite só números; ex.: 11991234567)' });

  const yearNum = parseInt(String(birthYear).replace(/\D/g,''), 10);
  if (!yearNum || yearNum < 1900 || yearNum > new Date().getFullYear()) {
    return res.status(400).json({ ok: false, error: 'birthYear inválido' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users[email] = { passwordHash, phoneE164, favoriteColor: String(favoriteColor).trim().toLowerCase(), birthYear: String(yearNum), devices: new Set() };
  return res.json({ ok: true, phoneE164 });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const u = users[email];
  if (!u) return res.status(401).json({ ok: false, error: 'credenciais inválidas' });
  const ok = await bcrypt.compare(password || '', u.passwordHash);
  if (!ok) return res.status(401).json({ ok: false, error: 'credenciais inválidas' });
  return res.json({ ok: true });
});

// emitir sessão quando risco = allow
app.post('/api/auth/session/issue', (req, res) => {
  const { user } = req.body || {};
  if (!user || !users[user]) return res.status(400).json({ ok: false, error: 'usuário inválido' });
  const token = newSession(user);
  res.json({ ok: true, sessionToken: token });
});

// -------------------------
// Antifraude: verificação
// -------------------------
app.post('/api/identity/verify', (req, res) => {
  const sessionData = req.body || {};
  const result = calculateRiskScore(sessionData, req);
  res.json({
    action: result.action,
    score: result.score,
    metadata: { server_ip: result.server.ip, ua_hash: result.server.uaHash }
  });
});

// -------------------------
// MFA por SMS + KBA (com anti-brute-force)
// -------------------------
function ensureChallenge(fingerprint, userEmail, phoneE164) {
  const now = Date.now();
  let c = challenges[fingerprint];
  if (!c) {
    c = challenges[fingerprint] = {
      otp: makeOtp(),
      otpExpires: now + 2 * 60 * 1000,
      attempts: 0,
      lockedUntil: 0,
      smsTo: phoneE164,
      resendCount: 0,
      lastSentAt: 0,
      forUserEmail: userEmail
    };
  } else {
    // NÃO zera attempts num start; mantém o estado do desafio
    c.smsTo = phoneE164;
    c.forUserEmail = userEmail;
  }
  return c;
}

app.post('/api/identity/challenge/start', async (req, res) => {
  const { fingerprint, user } = req.body || {};
  if (!fingerprint || !user) return res.status(400).json({ error: 'fingerprint e user são obrigatórios' });

  const account = users[user];
  if (!account) return res.status(404).json({ error: 'usuário não encontrado' });

  const now = Date.now();
  const c = ensureChallenge(fingerprint, user, account.phoneE164);

  if (c.lockedUntil && c.lockedUntil > now) return res.status(429).json({ error: 'temporarily locked' });

  // cooldown de 30s entre envios
  const COOLDOWN_MS = 30 * 1000;
  if (now - c.lastSentAt < COOLDOWN_MS) {
    const wait = Math.ceil((COOLDOWN_MS - (now - c.lastSentAt))/1000);
    return res.status(429).json({ error: 'cooldown', waitSec: wait });
  }

  // limite de reenvios: 3 por 10 minutos
  c.resendCount = (c.resendCount || 0) + 1;
  if (c.resendCount > 3) {
    c.lockedUntil = now + 5 * 60 * 1000; // 5min lock se abusar
    return res.status(429).json({ error: 'too-many-resends', lockMs: 5*60*1000 });
  }

  c.lastSentAt = now;
  // NÃO cria OTP novo a cada reenvio (evita “chutar” infinito). Mantém o mesmo.
  // Apenas estende validade máx. pra +2min (opcional):
  c.otpExpires = now + 2 * 60 * 1000;

  const sent = await sendSms(c.smsTo, `Seu código Nexshop: ${c.otp} (expira em 2 min)`);
  if (!sent) console.log(`[DEBUG] OTP = ${c.otp}`);

  res.json({ challenge: { type: 'mfa', otpExpiresInSec: Math.floor((c.otpExpires - now)/1000) }, cooldownSec: 30 });
});

app.post('/api/identity/challenge/resend', async (req, res) => {
  const { fingerprint } = req.body || {};
  if (!fingerprint) return res.status(400).json({ error: 'fingerprint obrigatório' });
  const c = challenges[fingerprint];
  const now = Date.now();
  if (!c) return res.status(404).json({ error: 'no-challenge' });
  if (c.lockedUntil && c.lockedUntil > now) return res.status(429).json({ error: 'locked' });

  // reaproveita a mesma lógica de cooldown/limite do /start
  req.body.user = c.forUserEmail;
  return app._router.handle(req, res, require('finalhandler')(req, res)); // repassa pra mesma rota
});

app.post('/api/identity/challenge/verify-otp', (req, res) => {
  const { fingerprint, code } = req.body || {};
  if (!fingerprint || !code) return res.status(400).json({ ok: false, reason: 'bad-request' });

  const c = challenges[fingerprint];
  const now = Date.now();
  if (!c) return res.status(404).json({ ok: false, reason: 'no-challenge' });
  if (c.lockedUntil && c.lockedUntil > now) return res.status(429).json({ ok: false, reason: 'locked' });
  if (now > c.otpExpires) return res.json({ ok: false, reason: 'expired' });

  if (code === c.otp) {
    const token = newSession(c.forUserEmail);
    delete challenges[fingerprint];
    return res.json({ ok: true, sessionToken: token });
  }

  c.attempts = (c.attempts || 0) + 1;
  if (c.attempts >= 5) {
    c.lockedUntil = now + 2 * 60 * 1000; // 2min de lock após 5 erros
    return res.json({ ok: false, reason: 'too-many-attempts', lockMs: 120000 });
  }
  return res.json({ ok: false, reason: 'invalid' });
});

app.post('/api/identity/challenge/verify-kba', (req, res) => {
  const { fingerprint, answer1, answer2 } = req.body || {};
  if (!fingerprint) return res.status(400).json({ ok: false, reason: 'bad-request' });
  const c = challenges[fingerprint];
  if (!c) return res.status(404).json({ ok: false, reason: 'no-challenge' });

  const u = users[c.forUserEmail];
  if (!u) return res.status(404).json({ ok: false, reason: 'user-not-found' });

  const a1 = String(answer1 || '').trim().toLowerCase();
  const a2 = String(answer2 || '').trim();
  const ok = a1 === u.favoriteColor && a2 === u.birthYear;

  if (ok) {
    const token = newSession(c.forUserEmail);
    delete challenges[fingerprint];
    return res.json({ ok: true, sessionToken: token });
  }
  return res.json({ ok: false, reason: 'kba-invalid' });
});

app.listen(port, () => {
  console.log(`SDK backend na porta ${port} -> http://localhost:${port}`);
});
