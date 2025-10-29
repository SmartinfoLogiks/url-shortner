// server.js
// Single-file URL shortener with:
// - cutt.ly-style API endpoint
// - MySQL + Redis
// - Multi-ready accounts + strict API key validation
// - Admin endpoints to create/delete API keys (protected by ADMIN_KEY envvar)
// - Click analytics (full): timestamp, ip, user-agent, referer (MySQL)
// - Rate limiting using sliding token-bucket stored in Redis (per-account & per-url)
// - IP-based exponential backoff throttling (Redis)
// - Uses dotenv for configuration
//
// npm install express mysql redis axios lodash dotenv crypto

const express = require('express');
const mysql = require('mysql2/promise');
const { createClient } = require('redis');
const axios = require('axios');
const _ = require('lodash');
const util = require('util');
const crypto = require('crypto');
const path = require("path");
const { Reader } = require("@maxmind/geoip2-node");
let geoReader = null;

require('dotenv').config();

const app = express();
app.use(express.json());

app.use(express.static(path.join(__dirname, "public")));

// -------------------- CONFIG --------------------
const PORT = process.env.PORT || 3000;
const BASE_HOST = process.env.BASE_HOST || `http://localhost:${PORT}`;

const ADMIN_KEY = process.env.ADMIN_KEY || 'admin_local_default';

// MySQL config
const pool = mysql.createPool({
  connectionLimit: Number(process.env.MYSQL_CONN_LIMIT || 10),
  host: process.env.MYSQL_HOST || 'localhost',
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DB || 'urlshortener',
  timezone: 'Z', // prevent auto-TZ offset
  dateStrings: true, // return DATETIME as string instead of JS date
});
const query = (...args) => pool.query(...args);

// Redis client
const redis = createClient({
  url: `redis://${process.env.REDIS_HOST || '127.0.0.1'}:${process.env.REDIS_PORT || 6379}`,
  password: process.env.REDIS_PASSWORD || undefined,
});
redis.on('error', (err) => console.error('Redis Client Error', err));

// token-bucket Lua script (atomic):
// KEYS[1] = bucketKey
// ARGV[1] = capacity (integer)
// ARGV[2] = refill_per_sec (float as string)
// ARGV[3] = now_ts (seconds since epoch, integer)
// ARGV[4] = tokens_to_take (integer)
const tokenBucketLua = `
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_sec = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local take = tonumber(ARGV[4])

local meta = redis.call('HMGET', key, 'tokens', 'last')
local tokens = tonumber(meta[1]) or capacity
local last = tonumber(meta[2]) or now

-- refill tokens
local delta = math.max(0, now - last)
local refill = delta * refill_per_sec
tokens = math.min(capacity, tokens + refill)

local allowed = 0
if tokens >= take then
  tokens = tokens - take
  allowed = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'last', now)
-- set TTL to 48 hours to avoid stale keys
redis.call('EXPIRE', key, 60*60*48)
return { allowed, tokens }
`;

// We'll load the script into Redis on startup for faster evalsha usage
let tokenBucketScriptSha = null;

// -------------------- DB INIT --------------------
async function initDb() {
  // Create tables (idempotent)
  await query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100),
      default_expiry_days INT DEFAULT ?,
      account_max_clicks_per_day INT DEFAULT ?,
      url_max_clicks_per_day INT DEFAULT ?,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB;
  `, [
    Number(process.env.DEFAULT_EXPIRY_DAYS || 3650),
    Number(process.env.DEFAULT_ACCOUNT_MAX_CLICKS_PER_DAY || 10000),
    Number(process.env.DEFAULT_URL_MAX_CLICKS_PER_DAY || 1000)
  ]);

  await query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INT AUTO_INCREMENT PRIMARY KEY,
      account_id INT NOT NULL,
      api_key VARCHAR(128) NOT NULL UNIQUE,
      subpath VARCHAR(25) NOT NULL DEFAULT '',
      name VARCHAR(100),
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
    ) ENGINE=InnoDB;
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS urls (
      id INT AUTO_INCREMENT PRIMARY KEY,
      account_id INT NOT NULL,
      shortId VARCHAR(100) NOT NULL UNIQUE,
      originalUrl TEXT NOT NULL,
      customName VARCHAR(100),
      onetime_use int default 0,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expiryAt DATETIME NULL,
      deleted int default 0,
      clickCount INT DEFAULT 0,
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
    ) ENGINE=InnoDB;
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS url_clicks (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      account_id INT NOT NULL,
      url_id INT NOT NULL,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ip VARCHAR(64),
      user_agent VARCHAR(512),
      country VARCHAR(4) DEFAULT '',
      region VARCHAR(128) DEFAULT '',
      city VARCHAR(128) DEFAULT '',
      latitude DECIMAL(10,6) DEFAULT '',
      longitude DECIMAL(10,6) DEFAULT '',
      referer TEXT,
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
      FOREIGN KEY (url_id) REFERENCES urls(id) ON DELETE CASCADE,
      INDEX idx_createdAt (createdAt)
    ) ENGINE=InnoDB;
  `);
}

// ensure at least one account + api key exists for convenience
async function ensureSampleAccount() {
  const [rows] = await query(`SELECT id FROM accounts LIMIT 1`);
  if (rows.length === 0) {
    const [res] = await query(
      `INSERT INTO accounts (name) VALUES (?)`,
      ['default-account']
    );
    const accountId = res.insertId;
    const apiKey = 'demo_' + crypto.randomBytes(8).toString('hex');
    await query(`INSERT INTO api_keys (account_id, api_key, name) VALUES (?, ?, ?)`, [accountId, apiKey, 'default-key']);
    console.log('Created sample account');
    console.log('    Account ID:', accountId);
    console.log('    Sample API Key:', apiKey);
  }
}

// Helper to initialize GeoIP DB (call on startup)
async function initGeoIP(dbPath = process.env.GEOLITE_DB_PATH || './geo/GeoLite2-City.mmdb') {
  try {
    geoReader = await Reader.open(dbPath);
    console.log('GeoIP DB loaded:', dbPath);
  } catch (e) {
    geoReader = null;
    console.warn('Could not load GeoIP DB:', dbPath, e.message || e);
  }
}

// -------------------- UTIL --------------------
function generateShortId(length = 7) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  return _.sampleSize(chars, length).join('');
}

function randKey(len = 24) {
  return crypto.randomBytes(Math.ceil(len / 2)).toString('hex').slice(0, len);
}

function getClientIp(req) {
  //const ip = (req.headers["x-forwarded-for"]?.split(",")[0] || req.ip || "").trim();
  const xf = req.headers['x-forwarded-for'];
  if (xf) return xf.split(',')[0].trim();
  return (req.ip || (req.socket && req.socket.remoteAddress)) || 'unknown';
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

// Redis geo cache key helper (namespaced v1)
function geoCacheKey(ip) {
  return `geo:v1:${ip}`;
}

/**
 * lookupGeoForIp(ip)
 * - checks Redis cache first
 * - if missing, queries MaxMind (geoReader.city) and caches the result (JSON)
 * - returns object: { country, region, city, latitude, longitude }
 * - returns null if lookup not possible
 */
async function lookupGeoForIp(ip) {
  if (!ip) return null;

  // check redis cache
  try {
    const key = geoCacheKey(ip);
    const cached = await redis.get(key);
    if (cached) {
      return JSON.parse(cached);
    }
  } catch (e) {
    console.warn('Redis geo cache error (get):', e && e.message);
    // continue to lookup
  }

  // if no geoReader or ip is local/private, return null
  if (!geoReader) return null;

  try {
    // perform lookup (city-level)
    const res = geoReader.city(ip);

    const country = res?.country?.isoCode || null;
    const region = res?.mostSpecificSubdivision?.names?.en || null;
    const city = res?.city?.names?.en || null;
    const latitude = (res?.location && typeof res.location.latitude === 'number') ? Number(res.location.latitude) : null;
    const longitude = (res?.location && typeof res.location.longitude === 'number') ? Number(res.location.longitude) : null;

    const out = {
      country: country || null,
      region: region || null,
      city: city || null,
      latitude,
      longitude
    };

    // cache in Redis (no TTL)
    try {
      await redis.set(geoCacheKey(ip), JSON.stringify(out));
    } catch (e) {
      console.warn('Redis geo cache error (set):', e && e.message);
    }

    return out;
  } catch (e) {
    // lookup may throw for local/private IPs or invalid addresses
    // we swallow and return null
    // console.warn('GeoIP lookup error for', ip, e && e.message);
    return null;
  }
}

// -------------------- REDIS TOKEN BUCKET --------------------
async function loadTokenBucketScript() {
  try {
    tokenBucketScriptSha = await redis.scriptLoad(tokenBucketLua);
  } catch (e) {
    console.error('Failed to load token bucket script', e);
    tokenBucketScriptSha = null;
  }
}

/**
 * consumeTokenRedis
 * Attempts to take 1 token from bucketKey (atomic via Lua)
 * @param {string} bucketKey
 * @param {number} capacity
 * @param {number} refillPerSec
 * @returns {Promise<{allowed:number, tokens:number}>}
 */
async function consumeTokenRedis(bucketKey, capacity, refillPerSec) {
  const now = nowSec();
  try {
    if (tokenBucketScriptSha) {
      const ret = await redis.evalSha(tokenBucketScriptSha, {
        keys: [bucketKey],
        arguments: [String(capacity), String(refillPerSec), String(now), '1'],
      });
      // ret = [allowed (0/1), tokens]
      return { allowed: Number(ret[0]) === 1, tokens: Number(ret[1]) };
    } else {
      // fallback to EVAL
      const ret = await redis.eval(tokenBucketLua, {
        keys: [bucketKey],
        arguments: [String(capacity), String(refillPerSec), String(now), '1'],
      });
      return { allowed: Number(ret[0]) === 1, tokens: Number(ret[1]) };
    }
  } catch (e) {
    console.error('consumeTokenRedis error', e);
    // on Redis error, be conservative: deny to avoid abuse
    return { allowed: false, tokens: 0, error: e };
  }
}

// -------------------- ACCOUNT / API KEY helpers --------------------
async function getAccountByApiKey(apiKey) {
  if (!apiKey) return null;
  const [rows] = await query(
    `SELECT a.*,k.* FROM api_keys k JOIN accounts a ON k.account_id = a.id WHERE k.api_key = ? LIMIT 1`,
    [apiKey]
  );
  return rows[0] || null;
}

// Create short url in MySQL
async function createShortUrl(accountId, originalUrl, customName, expiryDays, onetimeUse, subpath) {
  let shortId = customName || generateShortId(7);

  // uniqueness checks
  const [exists] = await query(`SELECT * FROM urls WHERE shortId = ? LIMIT 1`, [shortId]);
  if (exists.length > 0) {
    if (customName) throw new Error('alias_taken');
    // generate random until unique
    for (let i = 0; i < 5; i++) {
      shortId = generateShortId(7);
      const [e] = await query(`SELECT id FROM urls WHERE shortId = ? LIMIT 1`, [shortId]);
      if (e.length === 0) break;
    }
    const [final] = await query(`SELECT id FROM urls WHERE shortId = ? LIMIT 1`, [shortId]);
    if (final.length > 0) throw new Error('could_not_generate_unique_id');
  }

  let expiryAt = null;
  if (expiryDays && Number(expiryDays) > 0) {
    const d = new Date();
    d.setDate(d.getDate() + Number(expiryDays));
    expiryAt = d.toISOString().slice(0, 19).replace('T', ' ');
  }

  if(subpath && subpath.length > 0){
    shortId = `${subpath}/${shortId}`;
  }

  const [res] = await query(
    `INSERT INTO urls (account_id, shortId, originalUrl, customName, expiryAt, onetime_use) VALUES (?, ?, ?, ?, ?, ?)`,
    [accountId, shortId, originalUrl, customName || null, expiryAt, onetimeUse || 0]
  );
  const id = res.insertId;
  const [rows] = await query(`SELECT * FROM urls WHERE id = ? LIMIT 1`, [id]);
  return rows[0];
}

async function recordClick(accountId, urlId, ip, ua, referer) {
  let geo = null;
  try {
    geo = await lookupGeoForIp(ip);
  } catch (e) {
    geo = null;
  }

  // If no geo -> store "UNKNOWN" strings per your choice; lat/lon remain null
  const country = geo && geo.country ? geo.country : '-';
  const region = geo && geo.region ? geo.region : '-';
  const city = geo && geo.city ? geo.city : '-';
  const latitude = geo && (typeof geo.latitude === 'number') ? geo.latitude : 0;
  const longitude = geo && (typeof geo.longitude === 'number') ? geo.longitude : 0;

  // console.log(ip, country,region,city,latitude,longitude);
  await query(
    `INSERT INTO url_clicks (account_id, url_id, ip, user_agent, referer, country,region,city,latitude,longitude) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [accountId, urlId, ip || null, ua || null, referer || null, country,region,city,latitude,longitude]
  );
  await query(`UPDATE urls SET clickCount = clickCount + 1 WHERE id = ?`, [urlId]);
}

// -------------------- IP exponential backoff --------------------
/*
Strategy:
- Each time an IP triggers a rate-limit (i.e., token bucket denies), increment a counter "ip:backoff:{ip}"
- Backoff level N => block time = baseSeconds * (2^(N-1)) (exponential)
- We record last backoff increment time and set key TTL to exceed block time.
- When IP is blocked, respond 429 with Retry-After = remaining block seconds
*/

const IP_BACKOFF_BASE = 5; // seconds base (small initial block)
const IP_BACKOFF_KEY = (ip) => `backoff:ip:${ip}`;

async function ipBackoffRegister(ip) {
  if (!ip) return;
  const key = IP_BACKOFF_KEY(ip);
  // increment level atomically
  const level = await redis.incr(key);
  // compute block duration (seconds)
  const block = IP_BACKOFF_BASE * Math.pow(2, Math.max(0, level - 1));
  // set TTL to block (or extend) so key expires after block seconds
  await redis.expire(key, Math.min(block, 60 * 60 * 24)); // cap TTL to 24h
  return { level, block };
}

async function ipBackoffGetRemaining(ip) {
  const key = IP_BACKOFF_KEY(ip);
  const ttl = await redis.ttl(key);
  if (ttl <= 0) return 0;
  return ttl;
}

async function redirectToURI(shortId, req, res) {
  try {
    // find url + account limits
    const [rows] = await query(`SELECT u.*, a.account_max_clicks_per_day, a.url_max_clicks_per_day, u.onetime_use FROM urls u JOIN accounts a ON u.account_id = a.id WHERE u.shortId = ? AND deleted = 0 LIMIT 1`, [shortId]);
    if (!rows || rows.length === 0) return res.status(404).send('Not found');
    const urlRow = rows[0];

    // check expiry
    if (urlRow.expiryAt) {
      const expiry = new Date(urlRow.expiryAt);
      if (expiry < new Date()) {
        return res.status(404).send('Link expired');
      }
    }

    if(urlRow.onetime_use == 1){
      //delete the url after one use
      await query(`UPDATE urls SET deleted = 1 WHERE id = ?`, [urlRow.id]);
    }

    // get client IP

    const ip = getClientIp(req);
    // check if IP currently in backoff / blocked
    const ipRemaining = await ipBackoffGetRemaining(ip);
    if (ipRemaining > 0) {
      res.set('Retry-After', String(ipRemaining));
      return res.status(429).send(`Too many requests from IP. Retry after ${ipRemaining} seconds`);
    }

    // Build bucket keys
    const accountBucket = `bucket:account:${urlRow.account_id}`;
    const urlBucket = `bucket:url:${urlRow.id}`;

    // capacity and refill per second (sliding window approximated as token-bucket)
    const accCap = Number(urlRow.account_max_clicks_per_day) || Number(process.env.DEFAULT_ACCOUNT_MAX_CLICKS_PER_DAY || 10000);
    const urlCap = Number(urlRow.url_max_clicks_per_day) || Number(process.env.DEFAULT_URL_MAX_CLICKS_PER_DAY || 1000);

    const secsInDay = 86400;
    const accRefillPerSec = accCap / secsInDay;
    const urlRefillPerSec = urlCap / secsInDay;

    // attempt to consume from account bucket
    const accRes = await consumeTokenRedis(accountBucket, accCap, accRefillPerSec);
    if (!accRes.allowed) {
      // register IP backoff
      const back = await ipBackoffRegister(ip);
      res.set('Retry-After', String(back.block));
      return res.status(429).send('Account rate limit exceeded (try later)');
    }

    // attempt url bucket
    const urlRes = await consumeTokenRedis(urlBucket, urlCap, urlRefillPerSec);
    if (!urlRes.allowed) {
      // rollback account token? We cannot rollback the previous atomic token-consume easily; it's acceptable to treat the account token as used.
      const back = await ipBackoffRegister(ip);
      res.set('Retry-After', String(back.block));
      return res.status(429).send('URL rate limit exceeded (try later)');
    }

    // Passed both buckets: record click and redirect
    const ua = req.headers['user-agent'] || null;
    const referer = req.headers['referer'] || req.headers['referrer'] || null;
    // do not await non-blocking tasks in high throughput; but we'll await to keep counts correct for demo
    await recordClick(urlRow.account_id, urlRow.id, ip, ua, referer);

    return res.redirect(302, urlRow.originalUrl);
  } catch (err) {
    console.error('redirect error', err);
    return res.status(500).send('Internal server error');
  }
}

// -------------------- ROUTES --------------------

// 1) API endpoint to create new short URL
// GET /api/generate?key={{key}}&source={{source_url}}&userDomain=1&name={{name}}
app.get('/api/generate', async (req, res) => {
  try {
    const apiKey = req.query.key;
    const original = req.query.source;
    const name = req.query.name;
    var useHeader = req.query.useHeader;
    var onetimeUse = req.query.onetimeUse;
    //noTitle
    //tag

    if (!apiKey) return res.status(401).json({ status: 'error', message: 'API key required (key)' });
    if (!original) return res.status(400).json({ status: 'error', message: 'short (original URL) required' });
    if (typeof useHeader === 'undefined') useHeader = 0;
    if (typeof onetimeUse === 'undefined') onetimeUse = 0;

    // strict API key validation
    const account = await getAccountByApiKey(apiKey);
    if (!account) return res.status(401).json({ status: 'error', message: 'Invalid API key' });

    // basic URL format validation
    try {
      new URL(original);
    } catch (e) {
      try {
        new URL(decodeURIComponent(original));
        original = decodeURIComponent(original);
      } catch (e2) {
        return res.status(400).json({ status: 'error', message: 'Invalid URL format' });
      }
    }

    // expiry from account default
    const expiryDays = account.default_expiry_days || null;

    // create short URL
    let created;
    try {
      created = await createShortUrl(account.id, original, name, expiryDays, onetimeUse, useHeader?account.subpath:null);
    } catch (e) {
      if (e.message === 'alias_taken') {
        return res.status(409).json({ status: 'error', message: 'Custom alias already taken' });
      }
      console.error('createShortUrl error', e);
      return res.status(500).json({ status: 'error', message: 'Failed to create short url' });
    }

    const shortUrl = `${BASE_HOST}/${created.shortId}`;
    return res.json({
      status: 'ok',
      shortUrl,
      originalUrl: created.originalUrl,
      shortId: created.shortId,
      expiryAt: created.expiryAt
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

// -------------------- ADMIN ENDPOINTS --------------------
// Protected by header X-ADMIN-KEY or query adminKey
function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-key'] || req.query.adminKey || '';
  if (secret !== ADMIN_KEY) return res.status(401).json({ error: 'invalid admin key' });
  next();
}

// Create API key: POST /admin/api-keys  { accountId, name(optional) }
// returns created api key
app.post('/admin/api-keys', adminAuth, async (req, res) => {
  try {
    const { accountId, name } = req.body;
    if (!accountId) return res.status(400).json({ error: 'accountId required' });
    // ensure account exists
    const acc = await query(`SELECT * FROM accounts WHERE id = ? LIMIT 1`, [accountId]);
    if (!acc.length) return res.status(404).json({ error: 'account not found' });
    const apiKey = randKey(40);
    await query(`INSERT INTO api_keys (account_id, api_key, name) VALUES (?, ?, ?)`, [accountId, apiKey, name || null]);
    return res.json({ status: 'ok', apiKey });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Delete API key: DELETE /admin/api-keys/:apiKey
app.delete('/admin/api-keys/:apiKey', adminAuth, async (req, res) => {
  try {
    const apiKey = req.params.apiKey;
    const r = await query(`DELETE FROM api_keys WHERE api_key = ?`, [apiKey]);
    return res.json({ status: 'ok', deleted: r.affectedRows });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Admin: create account (for multi-ready usage) POST /admin/accounts {name, default_expiry_days, account_max_clicks_per_day, url_max_clicks_per_day}
app.post('/admin/accounts', adminAuth, async (req, res) => {
  try {
    const body = req.body || {};
    const name = body.name || 'account_' + Date.now();
    const defaultExpiry = Number(body.default_expiry_days || process.env.DEFAULT_EXPIRY_DAYS || 3650);
    const accountMax = Number(body.account_max_clicks_per_day || process.env.DEFAULT_ACCOUNT_MAX_CLICKS_PER_DAY || 10000);
    const urlMax = Number(body.url_max_clicks_per_day || process.env.DEFAULT_URL_MAX_CLICKS_PER_DAY || 1000);
    const r = await query(`INSERT INTO accounts (name, default_expiry_days, account_max_clicks_per_day, url_max_clicks_per_day) VALUES (?, ?, ?, ?)`, [name, defaultExpiry, accountMax, urlMax]);
    return res.json({ status: 'ok', accountId: r.insertId });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Admin: list accounts (brief)
app.get('/admin/accounts', adminAuth, async (req, res) => {
  try {
    const [rows] = await query(`SELECT id, name, createdAt, default_expiry_days, account_max_clicks_per_day, url_max_clicks_per_day FROM accounts ORDER BY id DESC LIMIT 100`);
    return res.json({ status: 'ok', accounts: rows });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Admin: list API keys
app.get('/admin/api-keys', adminAuth, async (req, res) => {
  try {
    const [rows] = await query(`SELECT id, account_id, api_key, name, createdAt FROM api_keys ORDER BY id DESC LIMIT 200`);
    return res.json({ status: 'ok', keys: rows });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Admin: delete account (and cascade) DELETE /admin/accounts/:id
app.delete('/admin/accounts/:id', adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await query(`DELETE FROM accounts WHERE id = ?`, [id]);
    return res.json({ status: 'ok', deleted: r.affectedRows });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'internal error' });
  }
});

// UPDATED /admin/urls (with pagination + filters)
app.get("/admin/urls", adminAuth, async (req, res) => {
  try {
    const accountId = req.query.account;
    if (!accountId) return res.status(400).json({ status: "error", message: "missing_account_id" });

    const page = parseInt(req.query.page || "1", 10);
    const limit = parseInt(req.query.limit || "25", 10);
    const offset = (page - 1) * limit;

    const from = req.query.from || null;
    const to = req.query.to || null;

    // dynamic filter for time-range
    let timeFilter = "";
    const params = [];

    if (from) {
      timeFilter += " AND c.createdAt >= ?";
      params.push(from);
    }
    if (to) {
      timeFilter += " AND c.createdAt <= ?";
      params.push(to);
    }
    params.push(accountId);

    // fetch paginated results
    const [urls] = await query(
      `
      SELECT 
        u.id,
        u.customName as alias,
        u.originalUrl as destination,
        u.shortId,
        COUNT(c.id) AS total_clicks,
        MAX(c.createdAt) AS last_click_at
      FROM urls u
      LEFT JOIN url_clicks c
        ON c.url_id = u.id
        ${timeFilter}
      WHERE u.account_id = ?
      GROUP BY u.id
      ORDER BY u.id DESC
      LIMIT ? OFFSET ?
      `,
      [...params, limit, offset]
    );

    // fetch total count for pagination
    const [[countRow]] = await query(
      `
      SELECT COUNT(*) AS total
      FROM urls
      WHERE account_id = ?
      `,
      [accountId]
    );

    res.json({
      status: "ok",
      page,
      limit,
      total: countRow.total,
      urls
    });
  } catch (err) {
    console.error("Error /admin/urls:", err);
    res.status(500).json({ status: "error", message: "server_error" });
  }
});

// CSV export for a single URL
app.get("/admin/urls/:shortid/csv", async (req, res) => {
  try {
    const shortid = req.params.shortid;
    const [[url]] = await query(
      `SELECT id, customName, shortId FROM urls WHERE shortid = ? LIMIT 1`,
      [shortid]
    );
    if (!url) return res.status(404).json({ status: "error", message: "not_found" });

    const [clicks] = await query(
      `SELECT * FROM url_clicks WHERE url_id = ? ORDER BY createdAt DESC`,
      [url.id]
    );

    const alias = url.customName || url.shortId || `url_${url.id}`;
    let csv = "createdAt,ip,country,region,city,latitude,longitude\n" + clicks.map(c => `${c.createdAt},${c.ip},${c.country},${c.region},${c.city},${c.latitude},${c.longitude}`).join("\n");

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename=\"${alias}.csv\"`);
    res.send(csv);
  } catch (err) {
    console.error("Error /admin/urls/:alias/csv:", err);
    res.status(500).json({ status: "error", message: "server_error" });
  }
});

// 2) Redirect route with Redis token-bucket enforcement & IP backoff
app.get('/:subpath/:shortId', async (req, res) => {
  const shortId_1 = req.params.subpath;
  if (!shortId_1) return res.status(400).send('Bad request');

  const shortId_2 = req.params.shortId;
  if (!shortId_2) return res.status(400).send('Bad request');

  const shortId = `${shortId_1}/${shortId_2}`;

  redirectToURI(shortId, req, res);
});

app.get('/:shortId', async (req, res) => {
  const shortId = req.params.shortId;
  if (!shortId) return res.status(400).send('Bad request');

  redirectToURI(shortId, req, res);
});

// -------------------- STARTUP --------------------
(async () => {
  try {
    await redis.connect();
    console.log('Redis connected');
    await loadTokenBucketScript();

    // load geo ip db
    await initGeoIP(process.env.GEOLITE_DB_PATH || './geo/GeoLite2-City.mmdb');

    await initDb();
    await ensureSampleAccount();

    app.listen(PORT, () => {
      console.log(`Server listening on ${BASE_HOST}`);
      console.log(`API endpoint: ${BASE_HOST}/api/generate?key={{key}}&source={{source_url}}&userDomain=1&name={{name}}`);
      console.log(`Admin endpoints require X-ADMIN-KEY header or ?adminKey=... (set ADMIN_KEY in .env)`);
    });
  } catch (e) {
    console.error('Startup failure', e);
    process.exit(1);
  }
})();
