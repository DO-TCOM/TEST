require('dotenv').config();
const express = require('express');
const http = require('http');
const https = require('https');
const socketIo = require('socket.io');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { createClient } = require('redis');
const { createAdapter } = require('@socket.io/redis-adapter');

const fsp = fs.promises;

const IPHUB_API_KEY  = process.env.IPHUB_API_KEY  || null; // set in Render env
const STATS_PASSWORD = process.env.STATS_PASSWORD || null; // set in Render env
if (!STATS_PASSWORD) console.error('[WARN] STATS_PASSWORD not set — admin dashboard disabled!');

// ── Porte d'entrée : /general ───────────────────────────────────────────────
// /general est toujours accessible directement (hub central).
// Toute autre room exige un token de room valide (?rt=...), obtenu en tapant
// "/nomderoom" dans le chat de la room où l'on se trouve actuellement. Le lien
// généré est posté dans le chat pour toute la room : le token reste valide
// (5 min) tant que quelqu'un peut cliquer dessus — pas à usage unique, sinon
// une seule personne du salon pourrait suivre le lien. Pour aller de test à
// test2, il faut repasser par une nouvelle commande /test2 depuis test (ou
// repasser par /general).
const FORCE_ROOM = 'general';
const VISITED_COOKIE_NAME = 'chaltet_visited';
const ROOM_LINK_SECRET = process.env.ROOM_LINK_SECRET || crypto.randomBytes(32).toString('hex');
const roomLinkTokensMemory = new Map(); // fallback si pas de Redis : token -> { room, exp }

// Lecture d'un cookie sans dépendance externe (cookie-parser non installé).
function getCookieValue(req, name) {
    const raw = req.headers.cookie;
    if (!raw) return null;
    for (const part of raw.split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1) continue;
        if (part.slice(0, idx).trim() === name) {
            return decodeURIComponent(part.slice(idx + 1).trim());
        }
    }
    return null;
}

// Historique des rooms déjà visitées depuis le dernier passage par /general.
// Sert à interdire le retour en arrière : une fois une room quittée, on ne
// peut plus y retourner tant qu'on n'est pas repassé par /general (qui reset).
function getVisitedRooms(req) {
    const raw = getCookieValue(req, VISITED_COOKIE_NAME);
    if (!raw) return [];
    try {
        const arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr.filter(r => typeof r === 'string').slice(-50) : [];
    } catch (e) { return []; }
}

function setVisitedRooms(res, rooms) {
    res.cookie(VISITED_COOKIE_NAME, JSON.stringify(rooms.slice(-50)), {
        httpOnly: true,
        sameSite: 'lax',
        secure: isProduction,
        maxAge: 6 * 60 * 60 * 1000 // 6h
    });
}

async function createRoomToken(room) {
    const token = crypto.randomBytes(16).toString('hex');
    if (redisStore) {
        await redisStore.set('roomtok:' + token, room, { EX: 300 }); // 5 min
    } else {
        roomLinkTokensMemory.set(token, { room, exp: Date.now() + 5 * 60 * 1000 });
    }
    return token;
}

async function consumeRoomToken(token, room) {
    if (!token || typeof token !== 'string' || token.length > 64) return false;
    // Le lien est partagé avec toute la room (voir /api/room-link + chat-message
    // \u0001ROOMLINK\u0001) : plusieurs personnes doivent pouvoir cliquer le même
    // lien. On ne supprime donc plus le token à la première utilisation — il
    // reste valide jusqu'à expiration (TTL), pas juste pour un seul clic.
    if (redisStore) {
        const val = await redisStore.get('roomtok:' + token);
        return val === room;
    }
    const entry = roomLinkTokensMemory.get(token);
    return !!(entry && entry.room === room && Date.now() <= entry.exp);
}

// Nettoyage périodique du fallback mémoire (si pas de Redis)
setInterval(() => {
    const now = Date.now();
    for (const [token, entry] of roomLinkTokensMemory.entries()) {
        if (now > entry.exp) roomLinkTokensMemory.delete(token);
    }
}, 60 * 1000);

// Conditional logging for production
const isProduction = process.env.NODE_ENV === 'production';
const log = isProduction ?
    (msg, ...args) => console.error(`[${new Date().toISOString()}] ${msg}`, ...args) :
    (msg, ...args) => console.log(msg, ...args);

// File paths (fallback when Redis unavailable)
const EXTRAS_FILE = path.join(__dirname, 'extras.json');
const LOG_FILE    = path.join(__dirname, 'display.txt');

// Redis storage client (separate from Socket.io adapter)
let redisStore = null;
if (process.env.REDIS_URL) {
    redisStore = createClient({ url: process.env.REDIS_URL });
    redisStore.connect()
        .then(() => log('[Redis] Storage client connected'))
        .catch(err => { console.error('[Redis] Storage connection error:', err); redisStore = null; });
}

// Redis-backed helpers
async function redisGet(key, defaultVal) {
    try {
        if (redisStore) {
            const val = await redisStore.get(key);
            return val ? JSON.parse(val) : defaultVal;
        }
    } catch(e) {
        console.error('[Redis] Get error for key', key, ':', e.message);
    }
    return defaultVal;
}

async function redisSet(key, val) {
    try {
        if (redisStore) await redisStore.set(key, JSON.stringify(val));
    } catch(e) {
        console.error('[Redis] Set error for key', key, ':', e.message);
    }
}

async function redisAppendLog(line) {
    try {
        if (redisStore) {
            await redisStore.rPush('logs', line);
            await redisStore.lTrim('logs', -5000, -1); // Keep last 5000 lines
            return;
        }
    } catch(e) {
        console.error('[Redis] Log append error:', e.message);
    }
    // Fallback to file
    await fsp.appendFile(LOG_FILE, line + '\n', 'utf8');
}

async function redisGetLogs(maxLines = 5000) {
    try {
        if (redisStore) {
            const lines = await redisStore.lRange('logs', -maxLines, -1);
            return lines.join('\n');
        }
    } catch(e) {
        console.error('[Redis] Get logs error:', e.message);
    }
    return getTailLogs(LOG_FILE, maxLines);
}

// Atomic Extras Helpers (Redis Hash based)
async function getIPExtras(ip) {
    try {
        if (redisStore) {
            const val = await redisStore.hGet('extras_hash', ip);
            return val ? JSON.parse(val) : {};
        }
    } catch(e) { console.error('[Extras] getIPExtras error:', e.message); }
    return {};
}

async function setIPExtras(ip, data) {
    try {
        if (redisStore) {
            await redisStore.hSet('extras_hash', ip, JSON.stringify(data));
        }
    } catch(e) { console.error('[Extras] setIPExtras error:', e.message); }
}

async function getAllExtras() {
    try {
        if (redisStore) {
            const all = await redisStore.hGetAll('extras_hash');
            const parsed = {};
            for (const ip in all) {
                try { parsed[ip] = JSON.parse(all[ip]); } catch(e) {}
            }
            return parsed;
        }
    } catch(e) { console.error('[Extras] getAllExtras error:', e.message); }
    return {};
}

// Admin Sessions (Transient memory)
const authTokens = new Map();
const authModule = require('./auth');
const { validatePseudo, normalizePseudo, validateDisplayName } = require('./pseudoRules');

// Helper to read JSON (Async)
async function readJson(file, defaultVal = {}) {
    try {
        await fsp.access(file);
        const data = await fsp.readFile(file, 'utf8');
        return JSON.parse(data);
    } catch (e) { return defaultVal; }
}

// Helper to write JSON (Async)
async function writeJson(file, data) {
    try {
        await fsp.writeFile(file, JSON.stringify(data, null, 2), 'utf8');
    } catch (e) { console.error(`Error writing to ${file}:`, e); }
}


// Fetch helper with timeout
function fetchJson(url, headers = {}) {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Timeout')), 5000);
        const protocol = url.startsWith('https') ? https : http;
        protocol.get(url, { headers }, (res) => {
            clearTimeout(timeout);
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch (e) { reject(e); }
            });
        }).on('error', (e) => {
            clearTimeout(timeout);
            reject(e);
        });
    });
}

// VPN Detection Fallback — basic CIDR check when IPHub is unavailable
function isLikelyVPNFallback(ip) {
    const ranges = [
        [0x2D4C0000, 16], // 45.76.0.0/16
        [0x68140000, 16], // 104.20.0.0/16
        [0xB9DC6500, 24], // 185.220.101.0/24
        [0x33510000, 16], // 51.81.0.0/16
        [0xA7630000, 16], // 167.99.0.0/16
        [0x9FCB0000, 16], // 159.203.0.0/16
    ];
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return false;
    const num = (parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]) >>> 0;
    return ranges.some(([base, bits]) => {
        const mask = bits === 32 ? 0xFFFFFFFF : (~(0xFFFFFFFF >>> bits)) >>> 0;
        return (num & mask) === (base & mask);
    });
}

async function isVPNviaIPHub(ip) {
    // Check Redis cache first (Fix 19: no more disk file in production)
    if (redisStore) {
        try {
            const cached = await redisStore.hGet('vpn_cache', ip);
            if (cached) {
                const { is_vpn, time } = JSON.parse(cached);
                if (Date.now() - time < 86400000) return is_vpn;
            }
        } catch(e) {}
    }
    if (!IPHUB_API_KEY) return isLikelyVPNFallback(ip);
    try {
        const data = await fetchJson(`https://v2.api.iphub.info/ip/${ip}`, { 'X-Key': IPHUB_API_KEY });
        const is_vpn = data.block === 1;
        if (redisStore) {
            try {
                await redisStore.hSet('vpn_cache', ip, JSON.stringify({ is_vpn, time: Date.now() }));
                await redisStore.expire('vpn_cache', 86400 * 7); // 7-day TTL on the whole hash
            } catch(e) {}
        }
        return is_vpn;
    } catch (e) {
        return isLikelyVPNFallback(ip);
    }
}


async function getLocation(ip) {
    try {
        if (redisStore) {
            const cached = await redisStore.hGet('location_cache', ip);
            if (cached) return JSON.parse(cached);
        }
        const data = await fetchJson(`http://ip-api.com/json/${ip}?fields=status,message,country,city`);
        const loc = { city: data.city || 'N/A', country: data.country || 'N/A' };
        if (redisStore && data.status === 'success') {
            await redisStore.hSet('location_cache', ip, JSON.stringify(loc));
            await redisStore.expire('location_cache', 86400 * 7); // Fix 20: 7-day TTL
        }
        return loc;
    } catch (e) {
        return { city: 'N/A', country: 'N/A' };
    }
}

function parseUserAgent(agent) {
    if (!agent) return 'UNKNOWN';
    const a = agent.toLowerCase();
    if (a.includes('mobile') || a.includes('android') || a.includes('iphone')) return 'Mobile';
    if (a.includes('chrome')) return 'Chrome';
    if (a.includes('firefox')) return 'Firefox';
    if (a.includes('safari')) return 'Safari';
    return 'Other';
}

// Helper to read ONLY the last N lines of a file (Async)
async function getTailLogs(file, maxLines = 5000) {
    try {
        await fsp.access(file);
        const data = await fsp.readFile(file, 'utf8');
        const lines = data.trim().split('\n');
        return lines.slice(-maxLines).join('\n');
    } catch (e) { return ''; }
}



const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

function indexToLetter(idx) {
    if (idx < 26) return alphabet[idx];
    return alphabet[Math.floor(idx / 26) - 1] + alphabet[idx % 26];
}

async function getLetterForIP(ip) {
    if (!redisStore) return 'A';
    // Check if already assigned
    const existing = await redisStore.hGet('ip_letters', ip);
    if (existing) return existing;
    // Atomically claim next counter slot
    const counter = await redisStore.incr('letter_counter');
    const candidate = indexToLetter(counter - 1);
    // HSETNX: atomic set-if-not-exists — prevents duplicate letters if two
    // requests race between the hGet above and this hSet
    await redisStore.hSetNX('ip_letters', ip, candidate);
    return await redisStore.hGet('ip_letters', ip);
}




// Domaine officiel : chaltet.com (ne pas confondre avec chatlet.com)
const ALLOWED_ORIGINS = [
    'https://chaltet.com',
    'http://chaltet.com',
    'https://www.chaltet.com',
    'http://www.chaltet.com'
];

const app = express();
app.set('trust proxy', 1); // Render sits behind a proxy
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: (origin, callback) => {
            if (!origin || ALLOWED_ORIGINS.includes(origin)) {
                callback(null, true);
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        },
        methods: ['GET', 'POST']
    },
    pingTimeout: 10000,   // 10s sans réponse → déconnecté
    pingInterval: 5000,   // ping toutes les 5s
});

const PORT = process.env.PORT || 3000;
const MOD_PASSWORD = process.env.MOD_PASSWORD || null;
if (!MOD_PASSWORD) {
    console.error('[WARN] MOD_PASSWORD non défini en variable d\'environnement — modération désactivée!');
}
// MOD_PASSWORD is for the mod script, STATS_PASSWORD is for the stats dashboard.
const bannedIps = new Set();

// ── Anti-spam par IP ──────────────────────────────────────────────────────────
// Stocke l'état anti-spam par IP : { timestamps[], longTimestamps[], violations, muteUntil }
const spamState = new Map();

const SPAM_RULES = {
    maxMessages:      3,          // max messages par fenêtre courte (3/5sec)
    windowMs:         5000,       // fenêtre courte (ms)
    maxLongMessages:  3,          // max messages > 150 chars
    longWindowMs:     30000,      // fenêtre longue (ms)
    maxChars:         500,        // limite caractères par message
    cooldownMs:       5000,       // cooldown après dépassement débit
    // Paliers de mute selon violations cumulées (par tranche de 3)
    muteLevels: [
        15 * 1000,          // 3  violations → 15 sec
        60 * 1000,          // 6  violations → 1 min
        10 * 60 * 1000,     // 9  violations → 10 min
        60 * 60 * 1000,     // 12 violations → 1 heure
        24 * 60 * 60 * 1000 // 15 violations → 1 jour
    ]
};

function getSpamState(ip) {
    if (!spamState.has(ip)) {
        spamState.set(ip, {
            timestamps:     [],   // horodatages des messages récents
            longTimestamps: [],   // horodatages des messages > 150 chars
            violations:     0,   // compteur de violations cumulées
            muteUntil:      0    // timestamp fin de mute (0 = pas muté)
        });
    }
    return spamState.get(ip);
}

// Retourne null si OK, sinon { muted: bool, message: string }
function checkSpam(ip, message) {
    const now   = Date.now();
    const state = getSpamState(ip);

    // Déjà muté ?
    if (state.muteUntil > now) {
        const remaining = Math.ceil((state.muteUntil - now) / 1000);
        return { muted: true, message: `Tu es muté encore ${remaining} secondes.` };
    }

    // Nettoyer les timestamps expirés
    state.timestamps     = state.timestamps.filter(t => now - t < SPAM_RULES.windowMs);
    state.longTimestamps = state.longTimestamps.filter(t => now - t < SPAM_RULES.longWindowMs);

    let violation = false;
    let reason    = '';

    // Règle 1 : limite de caractères
    if (message.length > SPAM_RULES.maxChars) {
        violation = true;
        reason    = `Message trop long (max ${SPAM_RULES.maxChars} caractères).`;
    }
    // Règle 2 : débit trop élevé
    else if (state.timestamps.length >= SPAM_RULES.maxMessages) {
        violation = true;
        reason    = 'Tu envoies des messages trop vite.';
    }
    // Règle 3 : trop de longs messages
    else if (message.length > 150 && state.longTimestamps.length >= SPAM_RULES.maxLongMessages) {
        violation = true;
        reason    = 'Trop de longs messages en peu de temps.';
    }

    if (violation) {
        state.violations++;
        const level     = Math.min(Math.floor((state.violations - 1) / 3), SPAM_RULES.muteLevels.length - 1);
        const threshold = (level + 1) * 3; // palier atteint tous les 3 violations

        if (state.violations % 3 === 0) {
            // Appliquer le mute
            const duration    = SPAM_RULES.muteLevels[level];
            state.muteUntil   = now + duration;
            const durationStr = duration >= 3600000
                ? (duration >= 86400000 ? '1 jour' : `${duration/3600000}h`)
                : (duration >= 60000 ? `${duration/60000} min` : `${duration/1000} sec`);
            return { muted: true, muteUntil: state.muteUntil, message: `Tu es muté pour ${durationStr} (spam).` };
        } else {
            // Avertissement
            const remaining = 3 - (state.violations % 3);
            return { muted: false, warning: true, message: `⚠️ ${reason} Encore ${remaining} infraction(s) avant mute.` };
        }
    }

    // Pas de violation : enregistrer le message
    state.timestamps.push(now);
    if (message.length > 150) state.longTimestamps.push(now);
    return null;
}

// Nettoyage périodique de la Map (évite les fuites mémoire)
setInterval(() => {
    const now = Date.now();
    for (const [ip, state] of spamState.entries()) {
        // Supprimer les entrées inactives depuis > 1 heure et non mutées
        const lastSeen = Math.max(...state.timestamps, ...state.longTimestamps, 0);
        if (state.muteUntil <= now && now - lastSeen > 3600000) {
            spamState.delete(ip);
        }
    }
}, 5 * 60 * 1000); // toutes les 5 minutes

if (process.env.REDIS_URL) {
    const pubClient = createClient({ url: process.env.REDIS_URL });
    const subClient = pubClient.duplicate();

    Promise.all([pubClient.connect(), subClient.connect()]).then(() => {
        io.adapter(createAdapter(pubClient, subClient));
        log('[Socket] Redis Adapter attached successfully: ready to scale!');
    }).catch(err => {
        console.error('[Socket] Redis Adapter connection error:', err);
    });
}

// ── Unicité des pseudos (comptes + invités connectés, multi-worker) ──────────
// Un pseudo est pris s'il correspond à un compte enregistré OU au pseudo
// actuellement affiché par un autre socket connecté (n'importe quel worker).
async function isPseudoTaken(normalized, exemptSocketId) {
    if (!redisStore) {
        log('[Security] isPseudoTaken: Redis indisponible — vérification d\'unicité des pseudos désactivée (risque de collision/usurpation).');
        return false;
    }

    const isAccount = await redisStore.hExists('accounts:index', normalized);
    if (isAccount) return true;

    const profiles = await redisStore.hGetAll('socket_profiles');
    for (const [sid, raw] of Object.entries(profiles)) {
        if (sid === exemptSocketId) continue;
        try {
            const profile = JSON.parse(raw);
            if (profile.displayName && normalizePseudo(profile.displayName) === normalized) {
                return true;
            }
        } catch (e) { /* entrée corrompue, on ignore */ }
    }
    return false;
}

// Libère le pseudo d'un invité local (ce worker) qui le porte actuellement,
// sauf exemptSocketId. Ne choisit pas de nouveau nom lui-même : le client
// génère son propre pseudo + avatar aléatoires (mêmes générateurs que pour
// un nouvel arrivant) puis renvoie profile-update pour se resynchroniser.
async function localReclaimPseudo(normalized, exemptSocketId) {
    for (const [id, s] of io.sockets.sockets) {
        if (id === exemptSocketId) continue;
        if (s.data.hasAccount) continue;
        const currentName = s.data.profile?.displayName;
        if (!currentName) continue;
        if (normalizePseudo(currentName) !== normalized) continue;

        if (s.data.profile) s.data.profile.displayName = null;

        if (redisStore) {
            redisStore.hDel('socket_profiles', id).catch(() => {});
        }

        s.emit('pseudo-reclaimed', {
            reason: "Un compte vient d'être créé avec ce pseudo. / An account was just created with this nickname."
        });

        if (s.data.roomId) {
            s.to(s.data.roomId).emit('profile-update', {
                id,
                displayName: 'Guest',
                profileColor: s.data.profile?.profileColor || '#4A90E2',
                avatarIndex: null
            });
        }
    }
}

// Écoute cross-worker (redis adapter) : chaque worker traite ses sockets locaux.
io.on('force-rename-pseudo', ({ normalized, exemptSocketId }) => {
    localReclaimPseudo(normalized, exemptSocketId).catch(err => log('[Pseudo] reclaim error:', err.message));
});

// Point d'entrée : à appeler après création de compte ou account-login réussi.
async function reclaimPseudo(normalized, exemptSocketId) {
    await localReclaimPseudo(normalized, exemptSocketId); // ce worker-ci
    io.serverSideEmit('force-rename-pseudo', { normalized, exemptSocketId }); // les autres workers
}

// Forcer HTTPS en production (Render passe x-forwarded-proto)
if (process.env.NODE_ENV === 'production') {
    app.use((req, res, next) => {
        if (req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect(301, 'https://' + req.headers.host + req.url);
        }
        next();
    });
}

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://www.youtube.com", "https://s.ytimg.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.gstatic.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "https://images.unsplash.com", "https://api.dicebear.com", "https://i.ytimg.com", "data:"],
            connectSrc: ["'self'", "wss://chaltet.com", "wss://www.chaltet.com", "turn:", "turns:"],
            mediaSrc: ["'self'", "data:"],
            frameSrc: ["'self'", "https://www.youtube.com", "https://www.youtube-nocookie.com"],
        }
    },
    // HSTS : forcer HTTPS pour 1 an
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));


const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { ok: false, message: "Trop de tentatives de connexion, réessayez plus tard." }
});

// Rate limiter pour mod-auth (event Socket.IO — express-rate-limit ne couvre pas les sockets)
const modAuthAttempts = new Map(); // ip -> { count, firstAttempt }
const MOD_AUTH_WINDOW_MS = 15 * 60 * 1000;
const MOD_AUTH_MAX_ATTEMPTS = 10;
function isModAuthRateLimited(ip) {
    const now = Date.now();
    const entry = modAuthAttempts.get(ip);
    if (!entry || now - entry.firstAttempt > MOD_AUTH_WINDOW_MS) {
        modAuthAttempts.set(ip, { count: 1, firstAttempt: now });
        return false;
    }
    entry.count++;
    return entry.count > MOD_AUTH_MAX_ATTEMPTS;
}
setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of modAuthAttempts.entries()) {
        if (now - entry.firstAttempt > MOD_AUTH_WINDOW_MS) modAuthAttempts.delete(ip);
    }
}, MOD_AUTH_WINDOW_MS);

// Rate limiter pour les endpoints publics (anti-spam/flood)
const publicApiLimiter = rateLimit({
    windowMs: 60 * 1000,     // 1 minute
    max: 30,                  // 30 requêtes par IP par minute
    standardHeaders: true,
    legacyHeaders: false,
    message: { ok: false, message: "Trop de requêtes, réessayez dans un moment." }
});

app.use(express.json({ limit: '50kb' })); // limite la taille des requêtes JSON

// Route de santé pour Render Health Check
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', uptime: Math.floor(process.uptime()) });
});

// CORS strict : uniquement les origines de ALLOWED_ORIGINS (pas de wildcard)
function setCorsHeaders(req, res) {
    const origin = req.headers.origin;
    if (origin && ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

app.use((req, res, next) => {
    if (req.method === 'OPTIONS') {
        setCorsHeaders(req, res);
        return res.status(204).end();
    }
    next();
});

app.use(async (req, res, next) => {
    // Skip static assets filters to avoid overhead
    const ext = path.extname(req.path);
    if (ext && ext !== '.html') return next();
    if (req.path.startsWith('/socket.io') || req.path.startsWith('/api/ice-servers')) return next();

    const ip = req.ip;
    const config = await redisGet('config', { whitelist_mode: false, redirect_url: '' });
    const blacklist = await redisGet('blacklist', []);

    const rule = blacklist.find(r => r.ip === ip);
    const isBlocked = rule ? rule.blocked : false;
    const isWhitelisted = rule ? rule.whitelist : false;

    // Sécurité : valider que redirect_url est bien une URL https:// (open redirect prevention)
    const rawRedirect = config.redirect_url || '';
    const redirectTarget = /^https:\/\/[a-zA-Z0-9\-.]+(:\d+)?(\/.*)?$/.test(rawRedirect)
        ? rawRedirect
        : 'https://google.com';

    // Filter
    if (!req.path.startsWith('/admin')) {
        if (config.whitelist_mode) {
            if (!isWhitelisted) return res.redirect(redirectTarget);
        } else if (isBlocked) {
            return res.redirect(redirectTarget);
        }
    }

    // Auto-ban des scanners malveillants
    const SCANNER_PATHS = ['.git', '.env', 'phpinfo', '.aws', 'wp-admin', 'wp-login',
        'config/.env', '/.aws', '/etc/passwd', 'shell', 'webshell', 'eval(', 'base64'];
    const reqPath = req.path.toLowerCase();
    const isScanner = SCANNER_PATHS.some(p => reqPath.includes(p));
    if (isScanner) {
        const scanIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || ip;
        (async () => {
            try {
                const blacklist = await redisGet('blacklist', []);
                if (!blacklist.find(r => r.ip === scanIp)) {
                    blacklist.push({ ip: scanIp, blocked: true, whitelist: false });
                    await redisSet('blacklist', blacklist);
                    log(`[AutoBan] Scanner banni: ${scanIp} → ${req.path}`);
                }
            } catch(e) {}
        })();
        return res.status(404).end();
    }

    // Logging (similaire à index.php)
    const ignoreLogging = ['/api/', '/admin/', '/favicon'];
    if (!ignoreLogging.some(p => req.path.startsWith(p))) {
        const date = new Date().toISOString().replace('T', ' ').split('.')[0];
        // Use real public IP from x-forwarded-for for geolocation
        const realIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || ip;
        const urlObj = new URL(req.originalUrl, 'http://localhost');
        const room = urlObj.pathname.replace(/^\//, '').split('/')[0] || '/';
        const urlPseudo = urlObj.searchParams.get('pseudo') || '';
        const urlColor = urlObj.searchParams.get('color') ? '#' + urlObj.searchParams.get('color') : '';

        // Exécution background
        (async () => {
            try {
                const letter = await getLetterForIP(realIp);
                const [loc, isVPN] = await Promise.all([getLocation(realIp), isVPNviaIPHub(realIp)]);
                const vpnFlag = isVPN ? '[VPN]' : '';
                const browser = parseUserAgent(req.headers['user-agent']);
                // Sanitize : retirer les caractères de contrôle pour éviter le log injection
                const sanitize = s => String(s || '').replace(/[\r\n\t\x00-\x1f\x7f]/g, ' ').substring(0, 100);

                const logLine = `[${date}] IP: ${sanitize(realIp)} | ${sanitize(letter)} | ${sanitize(loc.city)}(${sanitize(loc.country)}) | ${vpnFlag} |  | ${sanitize(browser)} | ${sanitize(room)}`;
                await redisAppendLog(logLine);

                // If pseudo or color in URL, save to extras immediately
                if (urlPseudo || urlColor) {
                    const extras = await getIPExtras(realIp);
                    if (urlPseudo && !validateDisplayName(urlPseudo)) {
                        const existing = extras.pseudos ? extras.pseudos.split(', ') : [];
                        if (!existing.includes(urlPseudo)) existing.push(urlPseudo);
                        extras.pseudos = existing.join(', ');
                        extras.url_pseudo = urlPseudo;
                    }
                    if (urlColor && /^#[0-9a-fA-F]{6}$/.test(urlColor)) extras.url_color = urlColor;
                    await setIPExtras(realIp, extras);
                }
            } catch (err) { log('Logging error:', err); }
        })();
    }

    next();
});

// Admin dashboard route moved to /admin/stats for consistency

app.use(express.static(path.join(__dirname, 'public')));


app.get(/^\/favicon/, (req, res) => res.status(204).end());

app.post('/api/collect', publicApiLimiter, async (req, res) => {
    const data = req.body;
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip;
    if (!ip) return res.status(400).json({ ok: false });

    const existing = await getIPExtras(ip);
    const updated = {
        ...existing,
        screen: data.screen || existing.screen || 'N/A',
        lang: data.lang || existing.lang || 'N/A',
        timezone: data.timezone || existing.timezone || 'N/A',
        cores: data.cores || existing.cores || 'N/A',
        ram: data.ram ? data.ram + ' GB' : (existing.ram || 'N/A'),
        touch: data.touch !== undefined ? (data.touch ? 'Oui' : 'Non') : (existing.touch || 'N/A'),
        platform: data.platform || existing.platform || 'N/A',
        darkmode: data.darkmode !== undefined ? (data.darkmode ? '🌙 Dark' : '☀️ Light') : (existing.darkmode || 'N/A'),
        battery_level: data.battery_level !== null && data.battery_level !== undefined ? data.battery_level + '%' : (existing.battery_level || 'N/A'),
        battery_charging: data.battery_charging !== null && data.battery_charging !== undefined ? (data.battery_charging ? '⚡ Oui' : 'Non') : (existing.battery_charging || 'N/A'),
        connection: data.connection || existing.connection || 'N/A',
        localstorage: data.localstorage || existing.localstorage || 'N/A',
        adblock: data.adblock || existing.adblock || 'N/A',
        time: Math.floor(Date.now() / 1000).toString()
    };
    await setIPExtras(ip, updated);
    res.json({ ok: true });
});



app.get('/api/ice-servers', (req, res) => {
    res.set('Cache-Control', 'no-store');
    const turnUrl  = process.env.TURN_URL;
    const turnUser = process.env.TURN_USERNAME;
    const turnCred = process.env.TURN_CREDENTIAL;

    const staticFallback = [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
    ];

    if (!turnUrl || !turnUser || !turnCred) return res.json(staticFallback);

    res.json([
        { urls: `stun:${turnUrl}:3478` },
        { urls: `turn:${turnUrl}:3478`, username: turnUser, credential: turnCred },
        { urls: `turn:${turnUrl}:3478?transport=tcp`, username: turnUser, credential: turnCred },
    ]);
});

// API to get profile by UUID — searches all extras for a matching uuid field
app.post('/api/get-profile-by-uuid', publicApiLimiter, async (req, res) => {
    const { uuid } = req.body;
    if (!uuid) return res.json({ ok: false });
    try {
        // UUID is stored as a field inside the IP's extras hash, not as the key itself
        const all = await getAllExtras();
        const entry = Object.values(all).find(e => e.uuid === uuid);
        if (entry && (entry.url_pseudo || entry.url_color)) {
            res.json({ ok: true, profile: { pseudo: entry.url_pseudo, color: entry.url_color } });
        } else {
            res.json({ ok: false });
        }
    } catch (error) {
        console.error('Error getting profile by UUID:', error);
        res.json({ ok: false });
    }
});

// API to get user profile by IP (for cross-domain requests)
app.get('/api/get-user-profile', publicApiLimiter, async (req, res) => {
    const requestedIp = req.headers['x-forwarded-for']
        ? req.headers['x-forwarded-for'].split(',')[0].trim()
        : req.ip;

    if (!requestedIp) return res.json({ ok: false });

    setCorsHeaders(req, res);

    try {
        const userProfile = await getIPExtras(requestedIp);
        if (userProfile && (userProfile.url_pseudo || userProfile.url_color)) {
            res.json({
                ok: true,
                profile: {
                    pseudo: userProfile.url_pseudo,
                    color: userProfile.url_color
                }
            });
        } else {
            res.json({ ok: false });
        }
    } catch (error) {
        console.error('Error getting user profile:', error);
        res.json({ ok: false });
    }
});

app.post('/api/save-transferred-profile', publicApiLimiter, async (req, res) => {
    setCorsHeaders(req, res);

    const { pseudo, color } = req.body;
    if (!pseudo && !color) return res.json({ ok: false });

    const realIp = req.headers['x-forwarded-for']
        ? req.headers['x-forwarded-for'].split(',')[0].trim()
        : req.ip;

    try {
        const extras = await getIPExtras(realIp);
        if (pseudo) extras.url_pseudo = pseudo;
        if (color) extras.url_color = color;
        await setIPExtras(realIp, extras);

        log(`[Profile] Saved transferred profile for ${realIp}: ${pseudo}`);
        res.json({ ok: true });
    } catch (error) {
        console.error('Error saving transferred profile:', error);
        res.status(500).json({ ok: false });
    }
});

// Room profile system - store profile data for room links
app.post('/api/room-profile', async (req, res) => {
    const { room, pseudo, color } = req.body;
    if (!room || typeof room !== 'string') return res.status(400).json({ ok: false });

    // Sanitize room name into a new variable
    const sanitizedRoom = room.replace(/[^a-z0-9\-_]/gi, '').toLowerCase();
    if (!sanitizedRoom) return res.status(400).json({ ok: false });

    try {
        const roomProfiles = await redisGet('roomProfiles', {});
        if (!roomProfiles[sanitizedRoom]) roomProfiles[sanitizedRoom] = {};

        // Add profile data if provided
        if (pseudo || color) {
            roomProfiles[sanitizedRoom].profile = {
                pseudo: pseudo || null,
                color: color || null
            };
            roomProfiles[sanitizedRoom].timestamp = Date.now(); // nécessaire pour l'expiration 30min
        }

        await redisSet('roomProfiles', roomProfiles);
        res.json({ ok: true, url: 'https://chaltet.com/' + sanitizedRoom });
    } catch (error) {
        console.error('Error saving room profile:', error);
        res.status(500).json({ ok: false });
    }
});

// API pour récupérer un profil par token (lien personnalisé ?t=TOKEN)
app.get('/api/profile-by-token/:token', async (req, res) => {
    setCorsHeaders(req, res);
    const token = req.params.token;
    if (!token || token.length > 64) return res.json({ ok: false });
    try {
        const tokens = await redisGet('profileTokens', {});
        const profile = tokens[token];
        if (!profile || Date.now() - profile.timestamp > 24 * 60 * 60 * 1000) {
            return res.json({ ok: false });
        }
        res.json({ ok: true, pseudo: profile.pseudo, color: profile.color });
    } catch (e) {
        res.json({ ok: false });
    }
});

// API pour stocker les tokens de profils (appelé par le script Tampermonkey)
app.post('/api/store-profile-tokens', publicApiLimiter, async (req, res) => {
    setCorsHeaders(req, res);
    const { tokens } = req.body; // [{ token, pseudo, color }]
    if (!tokens || !Array.isArray(tokens)) return res.json({ ok: false });
    try {
        const stored = await redisGet('profileTokens', {});
        const now = Date.now();
        for (const t of tokens) {
            if (!t.token || !t.pseudo || !t.color) continue;
            stored[t.token] = { pseudo: t.pseudo, color: t.color, timestamp: now };
        }
        // Nettoyer les tokens expirés (> 24h)
        for (const k in stored) {
            if (now - stored[k].timestamp > 24 * 60 * 60 * 1000) delete stored[k];
        }
        await redisSet('profileTokens', stored);
        log(`[Tokens] ${tokens.length} tokens stockés`);
        res.json({ ok: true });
    } catch (e) {
        res.json({ ok: false });
    }
});

// URL shortener simple (pour le panel admin)
app.post('/api/shorten', async (req, res) => {
    if (!authTokens.has(req.body?.token)) return res.status(401).json({ ok: false });
    const { url } = req.body;
    if (!url || typeof url !== 'string') return res.json({ ok: false });
    // Sécurité : n'accepter que les URLs http(s) pour éviter javascript: / data: etc.
    if (!/^https?:\/\/[a-zA-Z0-9\-.]+/.test(url)) {
        return res.status(400).json({ ok: false, message: 'URL invalide' });
    }
    try {
        const token = crypto.randomBytes(4).toString('hex'); // plus aléatoire que Math.random
        if (redisStore) {
            await redisStore.hSet('short_urls', token, JSON.stringify({ url, created: Date.now() }));
        }
        res.json({ ok: true, short: 'https://chaltet.com/s/' + token });
    } catch(e) {
        res.json({ ok: false });
    }
});

// Redirect short URLs
app.get('/s/:token', async (req, res) => {
    try {
        if (redisStore) {
            const data = await redisStore.hGet('short_urls', req.params.token);
            if (!data) return res.status(404).end();
            const entry = JSON.parse(data);
            return res.redirect(302, entry.url);
        }
        res.status(404).end();
    } catch(e) {
        res.status(500).end();
    }
});

// API to get all profiles for a room (called by client on arrival)
app.get('/api/room-profiles/:room', async (req, res) => {
    setCorsHeaders(req, res);
    const room = req.params.room.replace(/[^a-z0-9\-_]/gi, '').toLowerCase();
    if (!room) return res.json({ ok: false });

    try {
        const roomProfiles = await redisGet('roomProfiles', {});
        const entry = roomProfiles[room];

        // Expire after 30 minutes
        if (!entry || Date.now() - entry.timestamp > 30 * 60 * 1000) {
            return res.json({ ok: false, profiles: [] });
        }

        res.json({ ok: true, profiles: entry.profiles || [] });
    } catch (e) {
        res.json({ ok: false, profiles: [] });
    }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

// ── API Auth ─────────────────────────────────────────────────────────────────

app.post('/api/auth/register', publicApiLimiter, async (req, res) => {
    setCorsHeaders(req, res);
    const { pseudo, pin, avatarIndex } = req.body;
    if (!pseudo || !pin) return res.json({ success: false, error: 'Pseudo et NIP requis.' });
    try {
        const result = await authModule.register(redisStore, pseudo, String(pin), avatarIndex);
        if (result.success) {
            reclaimPseudo(normalizePseudo(pseudo), null).catch(err => log('[Pseudo] reclaim error:', err.message));
        }
        res.json(result);
    } catch (e) {
        log(`[Auth] Register error: ${e.message}`);
        res.json({ success: false, error: 'Erreur serveur.' });
    }
});

app.post('/api/auth/login', publicApiLimiter, async (req, res) => {
    setCorsHeaders(req, res);
    const { pseudo, pin } = req.body;
    if (!pseudo || !pin) return res.json({ success: false, error: 'Pseudo et NIP requis.' });
    try {
        const result = await authModule.login(redisStore, pseudo, String(pin));
        res.json(result);
    } catch (e) {
        log(`[Auth] Login error: ${e.message}`);
        res.json({ success: false, error: 'Erreur serveur.' });
    }
});

app.post('/api/auth/verify', publicApiLimiter, async (req, res) => {
    setCorsHeaders(req, res);
    const { token } = req.body;
    try {
        const result = await authModule.verifySession(redisStore, token);
        if (!result) return res.json({ success: false });
        res.json({ success: true, ...result });
    } catch (e) {
        res.json({ success: false });
    }
});

app.post('/api/auth/check-pseudo', publicApiLimiter, async (req, res) => {
    setCorsHeaders(req, res);
    const { pseudo } = req.body;
    try {
        const result = await authModule.checkPseudo(redisStore, pseudo);
        res.json(result);
    } catch (e) {
        res.json({ available: false, error: 'Erreur serveur.' });
    }
});

app.post('/api/auth/update-avatar', publicApiLimiter, async (req, res) => {
    setCorsHeaders(req, res);
    const { token, avatarIndex, avatarUrl } = req.body;
    try {
        const result = await authModule.updateAvatar(redisStore, token, avatarIndex, avatarUrl);
        res.json(result);
    } catch (e) {
        res.json({ success: false, error: 'Erreur serveur.' });
    }
});

// Génère un lien à usage unique vers une autre room, depuis la room actuelle.
// Utilisé par la commande "/room" tapée dans le chat (voir client.js).
app.post('/api/room-link', publicApiLimiter, async (req, res) => {
    const { target } = req.body;
    if (!target || typeof target !== 'string') {
        return res.json({ ok: false, message: 'Nom de room invalide.' });
    }
    const clean = target.toLowerCase().replace(/[^a-z0-9\-_]/g, '').substring(0, 100);
    if (!clean) {
        return res.json({ ok: false, message: 'Nom de room invalide.' });
    }
    // Interdit de retourner dans une room déjà visitée depuis le dernier /general
    if (clean !== FORCE_ROOM) {
        const visited = getVisitedRooms(req);
        if (visited.includes(clean)) {
            return res.json({ ok: false, message: 'Impossible de retourner dans cette room — repasse par /general.' });
        }
    }
    try {
        const url = clean === FORCE_ROOM
            ? '/' + clean // /general toujours accessible directement, pas besoin de token
            : '/' + clean + '?rt=' + await createRoomToken(clean);
        res.json({ ok: true, room: clean, url });
    } catch (e) {
        console.error('[room-link] error:', e.message);
        res.json({ ok: false, message: 'Erreur serveur.' });
    }
});

app.get('/:room', async (req, res) => {
  const room = req.params.room;
  if (room === 'random') {
      const randomName = crypto.randomBytes(4).toString('hex');
      return res.redirect('/' + randomName);
  }
  // Validation : uniquement lettres, chiffres, tirets, underscores, max 100 chars
  if (!/^[a-zA-Z0-9\-_]{1,100}$/.test(room)) {
      return res.status(400).sendFile(path.join(__dirname, 'public', '404.html'), err => {
          if (err) res.status(400).send('Room invalide');
      });
  }
  if (room !== room.toLowerCase()) {
      return res.redirect('/' + room.toLowerCase());
  }

  // ── Porte d'entrée : toute room ≠ /general exige un token valide ──────────
  // Le token (?rt=...) est obtenu en tapant "/room" dans le chat de la room
  // actuelle, puis posté dans le chat pour toute la room. Valable 5 minutes,
  // utilisable par plusieurs personnes (pas à usage unique).
  if (room !== FORCE_ROOM) {
      const granted = await consumeRoomToken(req.query.rt, room);
      if (!granted) {
          return res.redirect(302, '/' + FORCE_ROOM);
      }
  }

  // ── Historique de navigation : /general reset le parcours, sinon on empile ──
  if (room === FORCE_ROOM) {
      setVisitedRooms(res, []);
  } else {
      const visited = getVisitedRooms(req);
      if (!visited.includes(room)) visited.push(room);
      setVisitedRooms(res, visited);
  }

  const realIp = req.headers['x-forwarded-for']
      ? req.headers['x-forwarded-for'].split(',')[0].trim()
      : req.ip;

  try {
      const extras = await getIPExtras(realIp);
      if (extras.url_pseudo || extras.url_color) {
          log(`[Profile] Stored profile found for ${realIp}: ${extras.url_pseudo}`);
      }
      // Fix 4: read-only — no setIPExtras write needed here
  } catch (error) {
      console.error('Error reading profile:', error);
  }

  res.sendFile(path.join(__dirname, 'public', 'room.html'));
});

// Admin Routes - accessible with Tampermonkey script detection
app.get('/admin/check-token', (req, res) => {
    const adminToken = req.headers['x-admin-token'] || req.query.admin_token;
    const expectedToken = process.env.ADMIN_TOKEN;
    if (!expectedToken) return res.json({ hasToken: false });
    res.json({ hasToken: adminToken === expectedToken });
});

app.get('/admin/stats', (req, res) => {
    // Serve the dashboard shell. Data is protected via /admin/api/data session token.
    res.sendFile(path.join(__dirname, 'public', 'admin-stats.html'));
});

// Protect the static manifest and direct access
// Redirect direct file access to the official route
app.get('/admin-stats.html', (req, res) => {
    res.redirect('/admin/stats');
});


app.post('/admin/api/login', adminLoginLimiter, (req, res) => {
    if (!req.body || typeof req.body.password !== 'string' || req.body.password.length === 0) {
        return res.status(400).json({ ok: false, message: 'Invalid password format' });
    }
    if (req.body.password === STATS_PASSWORD) {
        const token = crypto.randomBytes(32).toString('hex');
        authTokens.set(token, Date.now());
        // Clean old tokens
        for (const [t, time] of authTokens.entries()) {
            if (Date.now() - time > 24 * 60 * 60 * 1000) authTokens.delete(t);
        }
        return res.json({ ok: true, token });
    }
    res.status(401).json({ ok: false });
});

app.post('/admin/api/data', async (req, res) => {
    if (!req.body || typeof req.body.token !== 'string' || req.body.token.length === 0) {
        return res.status(400).json({ ok: false, message: 'Invalid token format' });
    }
    if (!authTokens.has(req.body.token)) return res.status(401).json({ ok: false });

    const [logs, config, blacklist, extras, notes] = await Promise.all([
        redisGetLogs(5000),
        redisGet('config', { whitelist_mode: false, redirect_url: '' }),
        redisGet('blacklist', []),
        getAllExtras(),
        redisGet('notes', {})
    ]);

    res.json({ ok: true, logs, config, blacklist, extras, notes });
});


app.post('/admin/api/toggle', async (req, res) => {
    if (!authTokens.has(req.body.token)) return res.status(401).json({ ok: false });
    const { ip, field, value } = req.body;

    let blacklist = await redisGet('blacklist', []);
    let rule = blacklist.find(r => r.ip === ip);
    if (!rule) {
        rule = { ip, blocked: false, whitelist: false };
        blacklist.push(rule);
    }
    rule[field] = value;
    if (value) rule[field === 'blocked' ? 'whitelist' : 'blocked'] = false;

    blacklist = blacklist.filter(r => r.blocked || r.whitelist);
    await redisSet('blacklist', blacklist);
    res.json({ ok: true });
});

app.post('/admin/api/config', async (req, res) => {
    if (!authTokens.has(req.body.token)) return res.status(401).json({ ok: false });
    const { whitelist_mode, redirect_url } = req.body;

    let config = await redisGet('config', { whitelist_mode: false, redirect_url: '' });
    if (whitelist_mode !== undefined) config.whitelist_mode = !!whitelist_mode;
    if (redirect_url !== undefined) {
        // Sécurité : n'accepter que les URLs https:// valides (open redirect prevention)
        if (redirect_url === '' || /^https:\/\/[a-zA-Z0-9\-.]+(:\d+)?(\/.*)?$/.test(redirect_url)) {
            config.redirect_url = redirect_url;
        } else {
            return res.status(400).json({ ok: false, message: 'URL de redirection invalide (doit commencer par https://)' });
        }
    }

    await redisSet('config', config);
    res.json({ ok: true });
});

app.post('/admin/api/delete', async (req, res) => {
    if (!authTokens.has(req.body.token)) return res.status(401).json({ ok: false });
    if (req.body.all) {
        if (redisStore) await redisStore.del('logs');
        else await fsp.writeFile(LOG_FILE, '', 'utf8');
    }
    res.json({ ok: true });
});

app.post('/admin/api/delete-selected', async (req, res) => {
    if (!authTokens.has(req.body.token)) return res.status(401).json({ ok: false });
    const { indices } = req.body;
    if (!Array.isArray(indices)) return res.status(400).json({ ok: false });

    try {
        const setIndices = new Set(indices.map(Number));
        if (redisStore) {
            // Fix 1: use lRange(-5000,-1) — same window as redisGetLogs — so indices match
            const lines = await redisStore.lRange('logs', -5000, -1);
            const kept = lines.filter((_, i) => !setIndices.has(i));

            if (kept.length === 0 && lines.length > setIndices.size) {
                log('[Admin] Delete aborted — would delete all logs unexpectedly');
                return res.json({ ok: false, message: 'Opération annulée — vérifiez la sélection' });
            }

            const pipeline = redisStore.multi();
            pipeline.del('logs');
            if (kept.length > 0) {
                for (let i = 0; i < kept.length; i += 1000) {
                    pipeline.rPush('logs', ...kept.slice(i, i + 1000));
                }
            }
            await pipeline.exec();
        } else {
            const data = await fsp.readFile(LOG_FILE, 'utf8');
            let lines = data.trim().split('\n');
            const tail = lines.slice(-5000); // same window
            const kept = tail.filter((_, i) => !setIndices.has(i));
            const newContent = kept.join('\n') + (kept.length ? '\n' : '');
            await fsp.writeFile(LOG_FILE, newContent, 'utf8');
        }
        res.json({ ok: true });
    } catch (e) {
        log('Error in delete-selected:', e.message);
        res.json({ ok: false, message: e.message });
    }
});

app.post('/admin/api/rooms', async (req, res) => {
    if (!req.body || typeof req.body.token !== 'string' || !authTokens.has(req.body.token)) {
        return res.status(401).json({ ok: false });
    }
    try {
        const allSockets = await io.fetchSockets();
        const roomMap = {};
        for (const s of allSockets) {
            if (!s.data.roomId || s.data.isGhost) continue;
            if (!roomMap[s.data.roomId]) roomMap[s.data.roomId] = [];
            roomMap[s.data.roomId].push({
                id: s.id,
                name: s.data.profile?.displayName || 'Guest',
                cam: s.data.camEnabled || false
            });
        }
        const rooms = Object.entries(roomMap).map(([room, peers]) => ({ room, count: peers.length, peers }));
        res.json({ ok: true, rooms });
    } catch(e) {
        res.status(500).json({ ok: false });
    }
});

app.post('/admin/api/save-notes', async (req, res) => {
    if (!authTokens.has(req.body.token)) return res.status(401).json({ ok: false });
    const { notes } = req.body; // Map IP -> Note
    if (!notes) return res.status(400).json({ ok: false });

    let current = await redisGet('notes', {});
    Object.assign(current, notes);
    await redisSet('notes', current);
    res.json({ ok: true });
});



// 404 catch-all
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});


// ── YouTube Queue (par room, max 5 vidéos) ─────────────────────────────────
const ytbQueues = {}; // roomId -> { queue: [{videoId, addedBy}], startedAt: ms|null }
const YTB_MAX_QUEUE = 5;

function extractYoutubeId(url) {
    if (typeof url !== 'string') return null;
    const m = url.match(/(?:youtube\.com\/(?:watch\?v=|shorts\/|embed\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
    return m ? m[1] : null;
}
function getYtbState(roomId) {
    if (!ytbQueues[roomId]) ytbQueues[roomId] = { queue: [], startedAt: null };
    return ytbQueues[roomId];
}
function ytbAdvance(roomId) {
    const state = getYtbState(roomId);
    state.queue.shift();
    state.startedAt = state.queue.length ? Date.now() : null;
    io.to(roomId).emit('ytb-sync', { queue: state.queue, startedAt: state.startedAt });
}

io.on('connection', async (socket) => {
  const clientIp = socket.handshake.headers['x-forwarded-for']
    ? socket.handshake.headers['x-forwarded-for'].split(',')[0].trim()
    : socket.handshake.address;

  // Check bannedIps (temp kick 30s)
  if (bannedIps.has(clientIp)) {
    socket.emit('mod-action', { type: 'kicked-temp', by: 'Serveur' });
    socket.disconnect(true);
    return;
  }

  // Check blacklist (ban permanent) - Synchronous block to prevent unauthorized data access
  try {
    const blacklist = await redisGet('blacklist', []);
    if (blacklist.find(r => r.ip === clientIp && r.blocked)) {
      socket.emit('mod-action', { type: 'banned', by: 'Serveur' });
      socket.disconnect(true);
      return;
    }
  } catch (e) { log('Blacklist check error:', e.message); }

  log(`[Socket] New connection: ${socket.id}`);


  socket.on('join-room', async (roomId) => {
    if (typeof roomId !== 'string' || roomId.length === 0 || roomId.length > 100) return;
    roomId = roomId.replace(/[^a-z0-9\-_]/gi, '').toLowerCase();
    if (!roomId) return;

    if (socket.data.roomId === roomId) return;

    if (socket.data.roomId) {
        socket.leave(socket.data.roomId);
        socket.to(socket.data.roomId).emit('user-disconnected', socket.id);
    }

    socket.join(roomId);
    socket.data.roomId = roomId;
    log(`[Socket] User ${socket.id} joined room: ${roomId}`);

    // Fix A: broadcast user-connected + profile in ONE shot BEFORE any await
    // This way existing peers never create a "Guest" avatar — they get the real
    // profile in the same tick, before their JS even processes user-connected.
    // Ghost sockets are invisible — don't broadcast their presence
    if (socket.data.isGhost) return;
    socket.to(roomId).emit('user-connected', socket.id);
    if (socket.data.profile) {
        socket.to(roomId).emit('profile-update', {
            id: socket.id,
            displayName:  socket.data.profile.displayName,
            profileColor: socket.data.profile.profileColor,
            avatarIndex:  socket.data.profile.avatarIndex ?? null
        });
    }

    // Notify new joiner of any existing mods in room
    try {
        const allSockets = await io.in(roomId).fetchSockets();
        for (const s of allSockets) {
            if (s.id !== socket.id && s.data.isMod) {
                socket.emit('mod-badge', { id: s.id });
            }
        }
    } catch(e) {}

    // Fix B: build sync-profiles from Redis hash (cross-node safe) instead of
    // socket.data.profile which may be empty for sockets on other Render instances
    try {
        const sockets = await io.in(roomId).fetchSockets();
        const roomProfiles = {};
        for (const remoteSocket of sockets) {
            if (remoteSocket.id === socket.id) continue;
            // Try Redis first (always available cross-node), fall back to socket.data
            let profile = remoteSocket.data.profile || null;
            if (!profile && redisStore) {
                try {
                    const raw = await redisStore.hGet('socket_profiles', remoteSocket.id);
                    if (raw) profile = JSON.parse(raw);
                } catch(e) {}
            }
            roomProfiles[remoteSocket.id] = profile || { displayName: 'Guest', profileColor: '#4A90E2', avatarIndex: null };
        }
        socket.emit('sync-profiles', roomProfiles);
    } catch (err) {
        log('Error fetching sockets:', err);
    }

    // Envoyer l'état de la file YouTube au nouvel arrivant
    if (roomId === 'general') {
        const ytbState = getYtbState(roomId);
        socket.emit('ytb-sync', { queue: ytbState.queue, startedAt: ytbState.startedAt });
    }

    // Apply URL-based profile from extras (background, non-blocking for room announce)
    const realIp = socket.handshake.headers['x-forwarded-for']
        ? socket.handshake.headers['x-forwarded-for'].split(',')[0].trim()
        : socket.handshake.address;
    try {
        const extras = await getIPExtras(realIp);
        if (extras.url_pseudo || extras.url_color) {
            const profile = socket.data.profile || {};
            if (extras.url_pseudo && !socket.data.hasAccount) profile.displayName  = extras.url_pseudo;
            if (extras.url_color)  profile.profileColor = extras.url_color;
            socket.data.profile = profile;
            // Only emit to room — joining user already got their profile via profile-update before join-room
            socket.to(roomId).emit('profile-update', {
                id: socket.id,
                displayName:  profile.displayName,
                profileColor: profile.profileColor
            });
            log(`[Socket] Applied URL profile for ${socket.id}: ${profile.displayName}`);
        }
    } catch (err) {
        log('Error applying URL profile:', err);
    }
  });

  socket.on('account-login', (data) => {
    if (!data || typeof data.pseudo !== 'string') return;
    const pseudo = data.pseudo.trim().substring(0, 20);
    if (!pseudo) return;
    if (validatePseudo(pseudo)) return;
    socket.data.hasAccount = true;
    if (socket.data.profile) {
        socket.data.profile.displayName = pseudo;
    } else {
        socket.data.profile = { displayName: pseudo, profileColor: '#4A90E2', avatarIndex: null };
    }
    if (redisStore) {
        redisStore.hSet('socket_profiles', socket.id,
            JSON.stringify(socket.data.profile)).catch(() => {});
    }
    reclaimPseudo(normalizePseudo(pseudo), socket.id).catch(err => log('[Pseudo] reclaim error:', err.message));
    const actualRoom = socket.data.roomId;
    if (actualRoom) {
        socket.to(actualRoom).emit('profile-update', {
            id: socket.id,
            displayName: pseudo,
            profileColor: socket.data.profile.profileColor,
            avatarIndex: socket.data.profile.avatarIndex ?? null
        });
    }
  });

  socket.on('profile-update', async (data) => {
    if (!data || typeof data.displayName !== 'string' || typeof data.profileColor !== 'string') return;

    data.displayName = data.displayName.trim().substring(0, 20);

    // Validation nom (allégée — autorise emojis pour les profils sans compte)
    const pseudoErr = validateDisplayName(data.displayName);
    if (pseudoErr) return;

    // Unicité du pseudo (compte enregistré OU autre invité connecté) —
    // ne s'applique pas à un socket déjà authentifié sur son propre pseudo.
    if (!socket.data.hasAccount) {
        const normalized = normalizePseudo(data.displayName);
        const taken = await isPseudoTaken(normalized, socket.id);
        if (taken) {
            socket.emit('profile-update-error', { error: 'Ce pseudo est déjà pris. / This nickname is already taken.' });
            return;
        }
    }

    if (!/^#[0-9a-fA-F]{6}$/.test(data.profileColor)) return;

    const avatarIndex = (typeof data.avatarIndex === 'number' && data.avatarIndex >= 0) ? data.avatarIndex : null;

    socket.data.profile = {
        displayName: data.displayName,
        profileColor: data.profileColor,
        avatarIndex
    };

    // Fix B: persist to Redis so other Render nodes can read it via fetchSockets
    if (redisStore) {
        redisStore.hSet('socket_profiles', socket.id,
            JSON.stringify(socket.data.profile)).catch(() => {});
    }

    const actualRoom = socket.data.roomId;
    if (!actualRoom) return;

    log(`[Socket] Profile update for ${socket.id} in ${actualRoom}`);
    socket.to(actualRoom).emit('profile-update', {
        id: socket.id,
        displayName: data.displayName,
        profileColor: data.profileColor,
        avatarIndex
    });

    // Update pseudo in logs and extras
    const realIp = socket.handshake.headers['x-forwarded-for']
        ? socket.handshake.headers['x-forwarded-for'].split(',')[0].trim()
        : socket.handshake.address;

    // Save profile per-IP in a Redis hash
    if (socket._pseudoSaveTimer) clearTimeout(socket._pseudoSaveTimer);
    socket._pseudoSaveTimer = setTimeout(async () => {
        if (!data.displayName || data.displayName.length < 2) return;
        try {
            const extras = await getIPExtras(realIp);
            const pseudos = extras.pseudos ? extras.pseudos.split(', ').filter(Boolean) : [];
            if (!pseudos.includes(data.displayName)) pseudos.push(data.displayName);

            extras.url_pseudo = data.displayName;
            extras.url_color = data.profileColor;
            extras.current_pseudo = data.displayName;
            extras.current_color = data.profileColor;
            extras.pseudos = pseudos.join(', ');

            await setIPExtras(realIp, extras);
            log(`[Profile] Saved: ${data.displayName} (${realIp})`);
        } catch(e) { log('Error saving profile extras:', e.message); }
    }, 1500);
    // Update pseudo in logs (Redis OR file fallback)
    // Removed pseudo log update block – frontend does not rely on log pseudo data.
  });

  socket.on('peer-speaking', (data) => {
    if (!data || typeof data.status !== 'boolean') return;
    const actualRoom = socket.data.roomId;
    if (!actualRoom) return;
    socket.to(actualRoom).emit('peer-speaking', {
        id: socket.id,
        status: data.status
    });
  });

  // FIX: relay video-status to room peers
  socket.on('video-status', (data) => {
    if (!data || typeof data.enabled !== 'boolean') return;
    const actualRoom = socket.data.roomId;
    if (!actualRoom) return;
    socket.data.camEnabled = data.enabled;
    socket.to(actualRoom).emit('video-status', {
      id: socket.id,
      enabled: data.enabled
    });
    // Notify ghost admin watchers of webcam state change
    io.to('__ghost_admin__').emit('ghost-video-status', {
      roomId: actualRoom,
      peerId: socket.id,
      enabled: data.enabled,
      displayName: socket.data.profile?.displayName || 'Guest'
    });
  });

  // Ghost join: admin joins a room silently (no user-connected broadcast)
  socket.on('ghost-join', async (data) => {
    if (!data || typeof data.token !== 'string') return;
    if (!authTokens.has(data.token)) return;
    const roomId = typeof data.roomId === 'string' ? data.roomId.replace(/[^a-z0-9\-_]/gi, '').toLowerCase() : null;
    if (!roomId) return;

    // Leave previous ghost room
    if (socket.data.ghostRoom) socket.leave(socket.data.ghostRoom);

    socket.data.isGhost = true;
    socket.data.ghostRoom = roomId;
    socket.join(roomId);
    socket.join('__ghost_admin__');
    socket.data.roomId = roomId;

    // Send ghost the list of current peers in room (for WebRTC)
    try {
      const sockets = await io.in(roomId).fetchSockets();
      const peers = sockets
        .filter(s => s.id !== socket.id && !s.data.isGhost)
        .map(s => ({
          id: s.id,
          displayName: s.data.profile?.displayName || 'Guest',
          profileColor: s.data.profile?.profileColor || '#4A90E2'
        }));
      socket.emit('ghost-peers', peers);
    } catch(e) {}
    log(`[Ghost] Admin ghost joined room: ${roomId}`);
  });

  socket.on('chat-message', (data) => {
    if (!data || typeof data.message !== 'string' || typeof data.userName !== 'string') return;
    if (socket.data.isMuted) return;
    const actualRoom = socket.data.roomId;
    if (!actualRoom) return;

    // Tronquer à 200 chars avant vérification spam
    const message = data.message.substring(0, SPAM_RULES.maxChars);

    // Vérification anti-spam par IP
    const spamResult = checkSpam(clientIp, message);
    if (spamResult) {
        if (spamResult.muted) {
            // Appliquer le mute côté serveur
            socket.data.isMuted = true;
            // Planifier le démute automatique
            const remaining = spamResult.muteUntil - Date.now();
            setTimeout(() => {
                socket.data.isMuted = false;
                socket.emit('spam-unmuted');
                log(`[AntiSpam] ${clientIp} démuté automatiquement`);
            }, remaining);
            socket.emit('spam-warning', { muted: true, message: spamResult.message });
            log(`[AntiSpam] ${clientIp} muté : ${spamResult.message}`);
        } else {
            // Simple avertissement
            socket.emit('spam-warning', { muted: false, message: spamResult.message });
        }
        return;
    }

    const safeColor = /^#[0-9a-fA-F]{6}$/.test(data.color) ? data.color : '#4A90E2';
    io.to(actualRoom).emit('chat-message', {
      id: socket.id,
      userName: (socket.data.profile?.displayName || 'Guest').substring(0, 50),
      message: message,
      color: safeColor
    });
  });

  // ── File YouTube (room "general" uniquement) ──────────────────────────────
  socket.on('ytb-add', (data) => {
    const actualRoom = socket.data.roomId;
    if (!actualRoom || actualRoom !== 'general') return;
    if (!data || typeof data.url !== 'string') return;
    const videoId = extractYoutubeId(data.url);
    if (!videoId) { socket.emit('ytb-error', { message: 'Lien YouTube invalide.' }); return; }

    const state = getYtbState(actualRoom);
    if (state.queue.length >= YTB_MAX_QUEUE) {
        socket.emit('ytb-error', { message: 'File pleine (max 5). Attends qu\'une vidéo se termine.' });
        return;
    }
    const addedBy = (socket.data.profile?.displayName || 'Guest').substring(0, 30);
    state.queue.push({ videoId, addedBy, ownerId: socket.id });
    if (state.queue.length === 1) state.startedAt = Date.now();

    io.to(actualRoom).emit('ytb-sync', { queue: state.queue, startedAt: state.startedAt });
    log(`[YTB] ${addedBy} added ${videoId} to queue (room ${actualRoom})`);
  });

  // Le client qui joue la vidéo (le premier arrivé fait référence) signale la fin
  socket.on('ytb-ended', (data) => {
    const actualRoom = socket.data.roomId;
    if (!actualRoom || actualRoom !== 'general') return;
    const state = getYtbState(actualRoom);
    if (!state.queue.length) return;
    if (data && data.videoId && state.queue[0].videoId !== data.videoId) return; // évite double-avance
    ytbAdvance(actualRoom);
  });

  socket.on('ytb-skip', () => {
    const actualRoom = socket.data.roomId;
    if (!actualRoom || actualRoom !== 'general') return;
    const state = getYtbState(actualRoom);
    if (!state.queue.length) return;
    ytbAdvance(actualRoom);
    log(`[YTB] Skip in room ${actualRoom}`);
  });

  // Seul le propriétaire de la vidéo en cours peut piloter play/pause pour tout le monde
  socket.on('ytb-control', (data) => {
    const actualRoom = socket.data.roomId;
    if (!actualRoom || actualRoom !== 'general') return;
    const state = getYtbState(actualRoom);
    const current = state.queue[0];
    if (!current || current.ownerId !== socket.id) return;
    if (!data || (data.action !== 'play' && data.action !== 'pause')) return;
    socket.to(actualRoom).emit('ytb-control', { action: data.action, currentTime: data.currentTime || 0 });
  });

  socket.on('url-identity', (data) => {
    if (!data || typeof data.pseudo !== 'string') return;
    const pseudo = data.pseudo.trim().substring(0, 20);
    if (!pseudo || validateDisplayName(pseudo)) return;
    const color = data.color || '';
    if (!socket.data.profile) socket.data.profile = {};
    if (!socket.data.profile.displayName) socket.data.profile.displayName = pseudo;
    if (!socket.data.profile.profileColor && /^#[0-9a-fA-F]{6}$/.test(color)) socket.data.profile.profileColor = color;
  });

  socket.on('signal', async (data) => {
    if (!data || typeof data.to !== 'string' || !data.signal) return;
    const senderRoom = socket.data.roomId;
    if (!senderRoom) return;

    // Sécurité : vérifier que le destinataire est bien dans la même room
    // évite l'injection de signal vers des peers d'autres rooms
    try {
        const roomSockets = await io.in(senderRoom).fetchSockets();
        const targetInRoom = roomSockets.some(s => s.id === data.to);
        if (!targetInRoom) return;
    } catch(e) { return; }

    io.to(data.to).emit('signal', { from: socket.id, signal: data.signal });
    // Log uniquement les offres/réponses SDP, pas chaque candidate ICE (trop verbeux en prod)
    if (data.signal.type) {
        log(`[Socket] Signal ${data.signal.type} from ${socket.id} to ${data.to}`);
    }
  });

  socket.on('mod-badge', (data) => {
    const roomId = socket.data.roomId;
    if (!roomId || !socket.data.isMod) return;
    socket.to(roomId).emit('mod-badge', { id: socket.id });
  });

  socket.on('mod-auth', (data) => {
    const realIp = socket.handshake.headers['x-forwarded-for']
        ? socket.handshake.headers['x-forwarded-for'].split(',')[0].trim()
        : socket.handshake.address;
    if (isModAuthRateLimited(realIp)) {
      socket.emit('mod-status', false);
      log(`[Security] mod-auth rate-limited: ${realIp}`);
      return;
    }
    // Support both old string format and new object format
    const password = typeof data === 'object' ? data.password : data;
    const displayName = typeof data === 'object' ? data.displayName : null;
    if (!MOD_PASSWORD || !password || password.length === 0) {
      socket.emit('mod-status', false);
      return;
    }
    if (password === MOD_PASSWORD) {
      socket.data.isMod = true;
      // Store mod display name directly in case profile isn't set yet
      if (displayName) socket.data.modName = displayName;
      socket.emit('mod-status', true);
      log(`[Socket] User ${socket.id} authenticated as Moderator`);

      // Sync existing users in the room for moderation
      const roomId = socket.data.roomId;
      if (roomId) {
        setTimeout(async () => {
          try {
            const sockets = await io.in(roomId).fetchSockets();
            sockets.forEach(s => {
              if (s.id !== socket.id) {
                socket.emit('user-connected', s.id);
                if (s.data.profile) {
                  socket.emit('profile-update', {
                    id: s.id,
                    displayName: s.data.profile.displayName,
                    profileColor: s.data.profile.profileColor
                  });
                }
              }
            });
          } catch (err) {
            log('Error syncing existing users for moderator:', err);
          }
        }, 100);
      }
    } else {
      socket.emit('mod-status', false);
    }
  });

  socket.on('mod-kick', (targetId) => {
    if (!socket.data.isMod) return;
    if (typeof targetId !== 'string' || targetId.length === 0) return;
    const modName = socket.data.modName || socket.data.profile?.displayName || 'Mod';
    io.to(targetId).emit('mod-action', { type: 'kicked', by: modName });
    setTimeout(() => io.in(targetId).disconnectSockets(true), 500);
    log(`[Socket] Moderator ${socket.id} kicked ${targetId}`);
  });

  socket.on('mod-kick-temp', (targetId) => {
    if (!socket.data.isMod) return;
    if (typeof targetId !== 'string' || targetId.length === 0) return;
    const modName = socket.data.modName || socket.data.profile?.displayName || 'Mod';
    const targetSocket = io.sockets.sockets.get(targetId);
    if (targetSocket) {
      const targetIp = targetSocket.handshake.headers['x-forwarded-for']
        ? targetSocket.handshake.headers['x-forwarded-for'].split(',')[0].trim()
        : targetSocket.handshake.address;
      bannedIps.add(targetIp);
      setTimeout(() => bannedIps.delete(targetIp), 30000);
    }
    io.to(targetId).emit('mod-action', { type: 'kicked-temp', by: modName });
    setTimeout(() => io.in(targetId).disconnectSockets(true), 500);
    log(`[Socket] Moderator ${socket.id} temp-kicked ${targetId} for 30s`);
  });

  socket.on('mod-ban', async (targetId) => {
    if (!socket.data.isMod) return;
    const modName = socket.data.modName || socket.data.profile?.displayName || 'Mod';
    const targetSocket = io.sockets.sockets.get(targetId);
    if (targetSocket) {
      const targetIp = targetSocket.handshake.headers['x-forwarded-for']
        ? targetSocket.handshake.headers['x-forwarded-for'].split(',')[0].trim()
        : targetSocket.handshake.address;

      const blacklist = await redisGet('blacklist', []);
      if (!blacklist.find(r => r.ip === targetIp)) {
          blacklist.push({ ip: targetIp, blocked: true, whitelist: false });
          await redisSet('blacklist', blacklist);
      }
      log(`[Socket] Moderator ${socket.id} banned IP ${targetIp} (User ${targetId})`);
    }
    io.to(targetId).emit('mod-action', { type: 'banned', by: modName });
    setTimeout(() => io.in(targetId).disconnectSockets(true), 500);
  });



  socket.on('mod-mute', (targetId) => {
    if (!socket.data.isMod) return;
    if (typeof targetId !== 'string' || targetId.length === 0) return;
    const targetSocket = io.sockets.sockets.get(targetId);
    if (targetSocket) targetSocket.data.isMuted = true;
    io.to(targetId).emit('mod-action', { type: 'muted', by: socket.data.modName || socket.data.profile?.displayName || 'Mod' });
    // Notifier le mod que le mute a été appliqué → sync boutons
    socket.emit('mod-mute-ack', { targetId, muted: true });
    log(`[Socket] Moderator ${socket.id} muted ${targetId}`);
  });

  socket.on('mod-unmute', (targetId) => {
    if (!socket.data.isMod) return;
    if (typeof targetId !== 'string' || targetId.length === 0) return;
    const targetSocket = io.sockets.sockets.get(targetId);
    if (targetSocket) targetSocket.data.isMuted = false;
    io.to(targetId).emit('mod-action', { type: 'unmuted', by: socket.data.modName || socket.data.profile?.displayName || 'Mod' });
    // Notifier le mod que le unmute a été appliqué → sync boutons
    socket.emit('mod-mute-ack', { targetId, muted: false });
    log(`[Socket] Moderator ${socket.id} unmuted ${targetId}`);
  });

  // ── Déconnexion (fermeture onglet, timeout, kick) ─────────────────────────
  socket.on('disconnect', (reason) => {
    const roomId = socket.data.roomId;
    if (roomId) {
      if (!socket.data.isGhost) socket.to(roomId).emit('user-disconnected', socket.id);
      log(`[Socket] ${socket.data.isGhost ? '[Ghost]' : 'User'} ${socket.id} disconnected from room ${roomId} (${reason})`);
      // Si le propriétaire de la vidéo en cours quitte, on annule toute la file
      const ytbState = ytbQueues[roomId];
      if (ytbState && ytbState.queue.length && ytbState.queue[0].ownerId === socket.id) {
        ytbState.queue = [];
        ytbState.startedAt = null;
        io.to(roomId).emit('ytb-sync', { queue: [], startedAt: null });
        log(`[YTB] Queue annulée (room ${roomId}) — le propriétaire a quitté`);
      }
    }
    // Fix B: clean up cross-node profile cache
    if (redisStore) redisStore.hDel('socket_profiles', socket.id).catch(() => {});
  });
});

server.listen(PORT, () => {
  log(`Server ready at http://localhost:${PORT}`);
});
