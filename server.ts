import 'dotenv/config';
import express, { type Request, type Response, type NextFunction } from 'express';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import JSZip from 'jszip';
import { createServer as createViteServer } from 'vite';
import { db, initLocalDatabase, verifyPassword, hashPassword } from './server/localDb.ts';

initLocalDatabase();

const app = express();
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT) || 3000;

const rawSessionSecret = (process.env.ADMIN_SESSION_SECRET || '').trim();
const isWeakSecret = !rawSessionSecret || rawSessionSecret.includes('CHANGE_THIS') || rawSessionSecret.length < 16;
const SESSION_SECRET =
  process.env.NODE_ENV === 'production'
    ? isWeakSecret
      ? crypto.randomBytes(32).toString('hex')
      : rawSessionSecret
    : isWeakSecret
    ? 'kushiara-express-local-dev-session-secret-2026'
    : rawSessionSecret;

function validateStrongPassword(password: string): string | null {
  if (!password || password.length < 8) {
    return 'নিরাপত্তার জন্য পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের হতে হবে।';
  }
  const lower = password.toLowerCase();
  const weakList = new Set(['12345678', '123456789', 'password', 'password123', 'admin123', 'qwerty123']);
  if (weakList.has(lower) || (process.env.NODE_ENV === 'production' && password === 'Kushiara@2026!')) {
    return 'অনুগ্রহ করে আরও শক্তিশালী ও নিরাপদ পাসওয়ার্ড ব্যবহার করুন।';
  }
  if (!/[a-zA-Z]/.test(password) || !/[0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
    return 'পাসওয়ার্ডে অন্তত একটি ইংরেজি অক্ষর এবং একটি সংখ্যা বা বিশেষ চিহ্ন থাকতে হবে।';
  }
  return null;
}

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Ensure uploads directory exists
const UPLOADS_DIR = path.resolve(process.cwd(), 'public', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Serve generated editorial images, public OG assets, & user uploads with public caching and zero cookies
app.use('/src/assets/images', express.static(path.resolve(process.cwd(), 'src', 'assets', 'images'), { maxAge: '1d' }));
app.use('/uploads', express.static(UPLOADS_DIR, { maxAge: '1d' }));
app.use(express.static(path.resolve(process.cwd(), 'public'), { index: false, maxAge: '1d' }));

// Rate Limiter for auth & public write endpoints
const rateBuckets = new Map<string, { count: number; resetAt: number }>();
function rateLimit(maxHits: number, windowMs: number) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const key = `${req.path}:${ip}`;
    const now = Date.now();
    const bucket = rateBuckets.get(key);
    if (!bucket || bucket.resetAt < now) {
      rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    bucket.count += 1;
    if (bucket.count > maxHits) {
      return res.status(429).json({ error: 'অনুরোধের সীমা অতিক্রম করেছে। কিছুক্ষণ পর আবার চেষ্টা করুন।' });
    }
    return next();
  };
}

// HMAC Token Helpers
function createToken(payload: Record<string, unknown>, ttlMs = 1000 * 60 * 60 * 24 * 7): string {
  const data = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + ttlMs })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token: string): Record<string, unknown> | null {
  try {
    const [data, sig] = token.split('.');
    if (!data || !sig) return null;
    const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) return null;
    const parsed = JSON.parse(Buffer.from(data, 'base64url').toString('utf-8'));
    if (!parsed.exp || Number(parsed.exp) < Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}

const ALL_PERMISSION_KEYS = [
  'manage_news',
  'manage_breaking',
  'manage_taxonomy',
  'manage_media',
  'manage_ads',
  'manage_layout',
  'manage_settings',
  'manage_users',
  'manage_roles',
  'view_logs',
  'manage_backup',
] as const;

interface AuthedRequest extends Request {
  admin?: {
    id: string;
    email: string;
    username: string | null;
    full_name: string;
    role: string;
    permissions: string[];
  };
}

function getRolesMap() {
  const rows = db.prepare('SELECT * FROM roles').all() as Array<Record<string, unknown>>;
  const map = new Map<string, { id: string; name: string; slug: string; permissions: string[]; is_system: boolean }>();
  for (const r of rows) {
    map.set(String(r.slug), {
      id: String(r.id),
      name: String(r.name),
      slug: String(r.slug),
      permissions: safeJsonParse<string[]>(r.permissions as string, []),
      is_system: Boolean(r.is_system),
    });
  }
  return map;
}

function hydrateUserProfile(row: Record<string, any>, rolesMap = getRolesMap()) {
  const { password_hash: _, ...safe } = row;
  const roleSlug = String(row.role || 'member');
  const roleDef = rolesMap.get(roleSlug);
  const customPermissions = safeJsonParse<string[]>(row.custom_permissions as string, []);
  const rolePermissions = roleDef?.permissions || [];
  const effectivePermissions =
    roleSlug === 'super_admin'
      ? [...ALL_PERMISSION_KEYS]
      : Array.from(new Set([...rolePermissions, ...customPermissions]));

  return {
    ...safe,
    id: String(row.id || ''),
    email: String(row.email || ''),
    full_name: String(row.full_name || ''),
    role: roleSlug,
    username: row.username ? String(row.username) : '',
    is_active: row.is_active === undefined ? true : Boolean(row.is_active),
    custom_permissions: customPermissions,
    role_name: roleDef?.name || roleSlug,
    permissions: effectivePermissions,
  };
}

function requireAdmin(req: AuthedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  const payload = token ? verifyToken(token) : null;
  if (!payload || !payload.adminId) {
    return res.status(401).json({ error: 'অননুমোদিত প্রবেশ। অনুগ্রহ করে অ্যাডমিন প্যানেলে লগইন করুন।' });
  }
  const row = db
    .prepare('SELECT id, user_id, username, full_name, email, role, custom_permissions, is_active, avatar_url, bio, phone, last_login_at, created_at, updated_at FROM admin_profiles WHERE id = ?')
    .get(String(payload.adminId)) as Record<string, unknown> | undefined;

  if (!row) {
    return res.status(401).json({ error: 'অ্যাডমিন সেশন পাওয়া যায়নি।' });
  }
  if (!row.is_active) {
    return res.status(403).json({ error: 'আপনার অ্যাকাউন্টটি নিষ্ক্রিয় করা হয়েছে।' });
  }

  const hydrated = hydrateUserProfile(row);
  if (hydrated.role !== 'super_admin' && hydrated.permissions.length === 0) {
    return res.status(403).json({ error: 'এই অ্যাকাউন্টটির অ্যাডমিন প্যানেলে প্রবেশের অনুমতি নেই।' });
  }

  req.admin = {
    id: String(hydrated.id),
    email: String(hydrated.email),
    username: hydrated.username || null,
    full_name: String(hydrated.full_name),
    role: String(hydrated.role),
    permissions: hydrated.permissions,
  };
  return next();
}

function requirePermission(permission: string) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    if (!req.admin) {
      return res.status(401).json({ error: 'অননুমোদিত প্রবেশ।' });
    }
    if (req.admin.role === 'super_admin' || req.admin.permissions.includes(permission)) {
      return next();
    }
    return res.status(403).json({ error: 'এই কাজটি করার জন্য আপনার পর্যাপ্ত অনুমতি (Permission) নেই।' });
  };
}

function logActivity(adminEmail: string, action: string, entityType: string, entityId: string | null, details: Record<string, unknown>, ip?: string) {
  try {
    db.prepare(`
      INSERT INTO activity_logs (id, admin_email, action, entity_type, entity_id, details, ip_address, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(crypto.randomUUID(), adminEmail, action, entityType, entityId, JSON.stringify(details), ip || '127.0.0.1', new Date().toISOString());
  } catch {
    // Non-blocking audit log
  }
}

function promoteScheduledNews() {
  const now = new Date().toISOString();
  db.prepare(`
    UPDATE news
    SET status = 'published', published_at = COALESCE(published_at, scheduled_at, ?), updated_at = ?
    WHERE status = 'scheduled' AND scheduled_at IS NOT NULL AND scheduled_at <= ?
  `).run(now, now, now);
}

function hydrateNewsRow(row: Record<string, unknown>) {
  const cat = db.prepare('SELECT * FROM categories WHERE id = ?').get(String(row.category_id)) as Record<string, unknown> | undefined;
  const sub = row.subcategory_id
    ? (db.prepare('SELECT * FROM subcategories WHERE id = ?').get(String(row.subcategory_id)) as Record<string, unknown> | undefined)
    : undefined;
  return {
    ...row,
    gallery_images: safeJsonParse(row.gallery_images as string, []),
    tags: safeJsonParse(row.tags as string, []),
    is_featured: Boolean(row.is_featured),
    is_pinned: Boolean(row.is_pinned),
    is_editors_choice: Boolean(row.is_editors_choice),
    is_breaking: Boolean(row.is_breaking),
    category: cat ? hydrateBoolFields(cat, ['is_active', 'show_in_nav']) : null,
    subcategory: sub ? hydrateBoolFields(sub, ['is_active']) : null,
  };
}

function hydrateBoolFields<T extends Record<string, unknown>>(obj: T, keys: string[]): T {
  const copy = { ...obj } as Record<string, unknown>;
  for (const k of keys) {
    if (k in copy) copy[k] = Boolean(copy[k]);
  }
  return copy as T;
}

function safeJsonParse<T>(val: string | null | undefined, fallback: T): T {
  if (!val) return fallback;
  try {
    return JSON.parse(val) as T;
  } catch {
    return fallback;
  }
}

function escapeHtml(str: string): string {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ==============================================================================
// PUBLIC API ROUTES
// ==============================================================================
app.get('/api/health', (_req, res) => {
  const sUrl = (process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || '').trim();
  const sKey = (process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || '').trim();
  const supaReady = Boolean(sUrl && sKey && !sUrl.includes('YOUR_PROJECT_ID') && !sKey.includes('YOUR_SUPABASE_ANON_KEY'));
  res.json({
    ok: true,
    mode: supaReady ? 'supabase' : 'local_sqlite',
    supabaseConfigured: supaReady,
    env: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/public/bootstrap', (_req, res) => {
  promoteScheduledNews();
  const settings = db.prepare('SELECT * FROM website_settings WHERE id = 1').get() as Record<string, unknown>;
  const categories = (db.prepare('SELECT * FROM categories WHERE is_active = 1 ORDER BY display_order ASC').all() as Array<Record<string, unknown>>).map((c) =>
    hydrateBoolFields(c, ['is_active', 'show_in_nav'])
  );
  const subcategories = (db.prepare('SELECT * FROM subcategories WHERE is_active = 1 ORDER BY display_order ASC').all() as Array<Record<string, unknown>>).map((s) =>
    hydrateBoolFields(s, ['is_active'])
  );
  const sections = (db.prepare('SELECT * FROM homepage_sections WHERE is_visible = 1 ORDER BY display_order ASC').all() as Array<Record<string, unknown>>).map((s) =>
    hydrateBoolFields(s, ['is_visible', 'show_sidebar'])
  );
  const now = new Date().toISOString();
  const breakingNews = (
    db
      .prepare('SELECT * FROM breaking_news WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > ?) ORDER BY display_order ASC')
      .all(now) as Array<Record<string, unknown>>
  ).map((b) => hydrateBoolFields(b, ['is_active']));

  const ads = (db.prepare('SELECT * FROM advertisements WHERE is_active = 1').all() as Array<Record<string, unknown>>)
    .filter((a) => (!a.start_date || String(a.start_date) <= now) && (!a.end_date || String(a.end_date) >= now))
    .map((a) => hydrateBoolFields(a, ['is_active', 'show_desktop', 'show_mobile']));

  const news = (
    db.prepare("SELECT * FROM news WHERE status = 'published' ORDER BY is_pinned DESC, published_at DESC").all() as Array<Record<string, unknown>>
  ).map(hydrateNewsRow);

  const gallery = (db.prepare('SELECT * FROM gallery WHERE is_active = 1 ORDER BY display_order ASC, created_at DESC').all() as Array<Record<string, unknown>>).map(
    (g) => hydrateBoolFields(g, ['is_active'])
  );
  const videos = (db.prepare('SELECT * FROM video_news WHERE is_active = 1 ORDER BY published_at DESC').all() as Array<Record<string, unknown>>).map((v) =>
    hydrateBoolFields(v, ['is_featured', 'is_active'])
  );

  res.json({
    settings: settings ? hydrateBoolFields(settings, ['breaking_enabled']) : null,
    categories,
    subcategories,
    sections,
    breakingNews,
    ads,
    news,
    gallery,
    videos,
  });
});

app.get('/api/public/news/:slug', (req, res) => {
  promoteScheduledNews();
  const slug = decodeURIComponent(req.params.slug);
  const row = db.prepare("SELECT * FROM news WHERE slug = ? AND status = 'published'").get(slug) as Record<string, unknown> | undefined;
  if (!row) {
    return res.status(404).json({ error: 'সংবাদটি পাওয়া যায়নি।' });
  }
  const article = hydrateNewsRow(row);
  const related = (
    db
      .prepare("SELECT * FROM news WHERE status = 'published' AND category_id = ? AND id != ? ORDER BY published_at DESC LIMIT 4")
      .all(String(row.category_id), String(row.id)) as Array<Record<string, unknown>>
  ).map(hydrateNewsRow);
  return res.json({ article, related });
});

app.post('/api/public/views', rateLimit(60, 60_000), (req, res) => {
  const { newsId } = req.body || {};
  if (!newsId || typeof newsId !== 'string') {
    return res.status(400).json({ error: 'Invalid newsId' });
  }
  const existing = db.prepare("SELECT id FROM news WHERE id = ? AND status = 'published'").get(newsId);
  if (!existing) return res.status(404).json({ error: 'Not found' });

  const ip = req.ip || 'anon';
  const ua = req.headers['user-agent'] || '';
  const device = /mobile|android|iphone|ipad/i.test(ua) ? 'mobile' : 'desktop';
  const viewerHash = crypto.createHash('sha256').update(`${ip}:${ua.slice(0, 40)}`).digest('hex').slice(0, 16);

  db.prepare('UPDATE news SET views_count = views_count + 1 WHERE id = ?').run(newsId);
  db.prepare('INSERT INTO news_views (id, news_id, viewer_hash, referrer, user_agent_type, viewed_at) VALUES (?, ?, ?, ?, ?, ?)').run(
    crypto.randomUUID(),
    newsId,
    viewerHash,
    req.headers.referer || '',
    device,
    new Date().toISOString()
  );
  return res.json({ ok: true });
});

app.post('/api/public/newsletter', rateLimit(10, 60_000), (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'অনুগ্রহ করে সঠিক ইমেইল ঠিকানা লিখুন।' });
  }
  const existing = db.prepare('SELECT id FROM newsletter_subscribers WHERE email = ?').get(email);
  if (existing) {
    return res.json({ ok: true, message: 'আপনার ইমেইল ইতিমধ্যেই তালিকাভুক্ত রয়েছে।' });
  }
  db.prepare("INSERT INTO newsletter_subscribers (id, email, status, subscribed_at) VALUES (?, ?, 'active', ?)").run(
    crypto.randomUUID(),
    email,
    new Date().toISOString()
  );
  return res.json({ ok: true, message: 'নিউজলেটারে সাবস্ক্রিপশন সফল হয়েছে!' });
});

app.post('/api/public/ad-click', rateLimit(40, 60_000), (req, res) => {
  const { adId } = req.body || {};
  if (adId && typeof adId === 'string') {
    db.prepare('UPDATE advertisements SET clicks_count = clicks_count + 1 WHERE id = ?').run(adId);
  }
  res.json({ ok: true });
});

// ==============================================================================
// AUTH ROUTES (Username / Email + Password — Role-Based Access Control)
// ==============================================================================
function findAccountByIdentifier(identifier: string) {
  const clean = identifier.trim().toLowerCase();
  if (!clean) return undefined;
  return db
    .prepare(
      `SELECT * FROM admin_profiles
       WHERE LOWER(email) = ?
          OR LOWER(COALESCE(username, '')) = ?
          OR (INSTR(email, '@') > 1 AND LOWER(SUBSTR(email, 1, INSTR(email, '@') - 1)) = ?)
       LIMIT 1`
    )
    .get(clean, clean, clean) as
    | (Record<string, unknown> & {
        id: string;
        email: string;
        username?: string | null;
        password_hash: string;
        full_name: string;
        role: string;
        is_active: number;
      })
    | undefined;
}

app.post('/api/auth/login', rateLimit(15, 60_000), (req, res) => {
  const identifier = String(req.body?.identifier ?? req.body?.username ?? req.body?.email ?? '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const rememberMe = req.body?.rememberMe !== false;

  if (!identifier || !password) {
    return res.status(400).json({ error: 'ইমেইল/ইউজারনেম ও পাসওয়ার্ড আবশ্যক।' });
  }

  const account = findAccountByIdentifier(identifier);

  if (!account || !verifyPassword(password, account.password_hash)) {
    return res.status(401).json({ error: 'ভুল ইমেইল/ইউজারনেম অথবা পাসওয়ার্ড।' });
  }

  if (!account.is_active) {
    return res.status(403).json({ error: 'আপনার অ্যাকাউন্টটি নিষ্ক্রিয় করা হয়েছে। অনুগ্রহ করে সুপার অ্যাডমিনের সাথে যোগাযোগ করুন।' });
  }

  const hydrated = hydrateUserProfile(account);
  if (hydrated.role !== 'super_admin' && hydrated.permissions.length === 0) {
    return res.status(403).json({ error: 'এই অ্যাকাউন্টটির অ্যাডমিন প্যানেলে প্রবেশের অনুমতি নেই।' });
  }

  const now = new Date().toISOString();
  db.prepare('UPDATE admin_profiles SET last_login_at = ?, updated_at = ? WHERE id = ?').run(now, now, account.id);
  logActivity(account.email, 'ADMIN_LOGIN', 'admin_profiles', account.id, { method: 'password', rememberMe, role: account.role }, req.ip);

  const ttlMs = rememberMe ? 1000 * 60 * 60 * 24 * 30 : 1000 * 60 * 60 * 12;
  const token = createToken({ adminId: account.id, email: account.email, role: account.role }, ttlMs);
  return res.json({ token, profile: { ...hydrated, last_login_at: now } });
});

app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  const payload = token ? verifyToken(token) : null;
  if (payload?.email) {
    logActivity(String(payload.email), 'ADMIN_LOGOUT', 'admin_profiles', String(payload.adminId || ''), {}, req.ip);
  }
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAdmin, (req: AuthedRequest, res) => {
  const full = db
    .prepare(
      'SELECT id, user_id, username, full_name, email, role, custom_permissions, is_active, avatar_url, bio, phone, last_login_at, created_at, updated_at FROM admin_profiles WHERE id = ?'
    )
    .get(req.admin!.id) as Record<string, unknown> | undefined;
  if (!full) return res.status(404).json({ error: 'প্রোফাইল পাওয়া যায়নি।' });
  return res.json({ profile: hydrateUserProfile(full) });
});

app.post('/api/auth/forgot-password', rateLimit(5, 60_000), (req, res) => {
  const identifier = String(req.body?.identifier ?? req.body?.email ?? '').trim().toLowerCase();
  if (!identifier) {
    return res.status(400).json({ error: 'অনুগ্রহ করে আপনার ইমেইল অথবা ইউজারনেম লিখুন।' });
  }
  const admin = findAccountByIdentifier(identifier);
  if (admin) {
    logActivity(admin.email, 'PASSWORD_RESET_REQUESTED', 'admin_profiles', admin.id, {}, req.ip);
  }
  return res.json({
    ok: true,
    message: 'প্রোডাকশন Supabase মোডে আপনার সুপার অ্যাডমিন ইমেইলে রিসেট লিংক পাঠানো হবে। লোকাল প্রিভিউ মোডে .env এ SUPER_ADMIN_PASSWORD পরিবর্তন করতে পারেন অথবা প্রোফাইল থেকে পাসওয়ার্ড আপডেট করুন।',
  });
});

// ==============================================================================
// PROTECTED ADMIN DASHBOARD & RBAC API ROUTES
// ==============================================================================
function getAllSafeUsers(rolesMap = getRolesMap()) {
  const rows = db
    .prepare(
      'SELECT id, user_id, username, full_name, email, role, custom_permissions, is_active, avatar_url, bio, phone, last_login_at, created_at, updated_at FROM admin_profiles ORDER BY created_at DESC'
    )
    .all() as Array<Record<string, unknown>>;
  return rows.map((r) => hydrateUserProfile(r, rolesMap));
}

function getAllHydratedRoles() {
  const rows = db.prepare('SELECT * FROM roles ORDER BY is_system DESC, created_at ASC').all() as Array<Record<string, unknown>>;
  const counts = new Map<string, number>();
  const countRows = db.prepare('SELECT role, COUNT(*) as c FROM admin_profiles GROUP BY role').all() as Array<{ role: string; c: number }>;
  for (const row of countRows) counts.set(row.role, row.c);
  return rows.map((r) => ({
    ...r,
    permissions: safeJsonParse<string[]>(r.permissions as string, []),
    is_system: Boolean(r.is_system),
    user_count: counts.get(String(r.slug)) || 0,
  }));
}

app.get('/api/admin/bootstrap', requireAdmin, (req: AuthedRequest, res) => {
  promoteScheduledNews();
  const settings = db.prepare('SELECT * FROM website_settings WHERE id = 1').get() as Record<string, unknown>;
  const categories = (db.prepare('SELECT * FROM categories ORDER BY display_order ASC').all() as Array<Record<string, unknown>>).map((c) =>
    hydrateBoolFields(c, ['is_active', 'show_in_nav'])
  );
  const subcategories = (db.prepare('SELECT * FROM subcategories ORDER BY display_order ASC').all() as Array<Record<string, unknown>>).map((s) =>
    hydrateBoolFields(s, ['is_active'])
  );
  const sections = (db.prepare('SELECT * FROM homepage_sections ORDER BY display_order ASC').all() as Array<Record<string, unknown>>).map((s) =>
    hydrateBoolFields(s, ['is_visible', 'show_sidebar'])
  );
  const breakingNews = (db.prepare('SELECT * FROM breaking_news ORDER BY display_order ASC').all() as Array<Record<string, unknown>>).map((b) =>
    hydrateBoolFields(b, ['is_active'])
  );
  const ads = (db.prepare('SELECT * FROM advertisements ORDER BY created_at DESC').all() as Array<Record<string, unknown>>).map((a) =>
    hydrateBoolFields(a, ['is_active', 'show_desktop', 'show_mobile'])
  );
  const news = (db.prepare('SELECT * FROM news ORDER BY created_at DESC').all() as Array<Record<string, unknown>>).map(hydrateNewsRow);
  const gallery = (db.prepare('SELECT * FROM gallery ORDER BY display_order ASC, created_at DESC').all() as Array<Record<string, unknown>>).map((g) =>
    hydrateBoolFields(g, ['is_active'])
  );
  const videos = (db.prepare('SELECT * FROM video_news ORDER BY published_at DESC').all() as Array<Record<string, unknown>>).map((v) =>
    hydrateBoolFields(v, ['is_featured', 'is_active'])
  );
  const logs = (db.prepare('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 100').all() as Array<Record<string, unknown>>).map((l) => ({
    ...l,
    details: safeJsonParse(l.details as string, {}),
  }));
  const subscribers = db.prepare('SELECT * FROM newsletter_subscribers ORDER BY subscribed_at DESC').all();

  const canViewUsers = req.admin!.role === 'super_admin' || req.admin!.permissions.includes('manage_users');
  const canViewRoles = req.admin!.role === 'super_admin' || req.admin!.permissions.includes('manage_roles') || canViewUsers;
  const rolesMap = getRolesMap();
  const users = canViewUsers ? getAllSafeUsers(rolesMap) : [];
  const roles = canViewRoles ? getAllHydratedRoles() : [];

  const totalUsersCount = (db.prepare('SELECT COUNT(*) as c FROM admin_profiles').get() as { c: number }).c;
  const activeUsersCount = (db.prepare('SELECT COUNT(*) as c FROM admin_profiles WHERE is_active = 1').get() as { c: number }).c;
  const totalRolesCount = (db.prepare('SELECT COUNT(*) as c FROM roles').get() as { c: number }).c;

  const todayPrefix = new Date().toISOString().slice(0, 10);
  const todayViews = (db.prepare('SELECT COUNT(*) as c FROM news_views WHERE viewed_at LIKE ?').get(`${todayPrefix}%`) as { c: number }).c;
  const totalViews = (db.prepare('SELECT COALESCE(SUM(views_count), 0) as total FROM news').get() as { total: number }).total;

  res.json({
    settings: settings ? hydrateBoolFields(settings, ['breaking_enabled']) : null,
    categories,
    subcategories,
    sections,
    breakingNews,
    ads,
    news,
    gallery,
    videos,
    logs,
    subscribers,
    users,
    roles,
    stats: {
      totalNews: news.length,
      publishedNews: news.filter((n: Record<string, unknown>) => n.status === 'published').length,
      draftNews: news.filter((n: Record<string, unknown>) => n.status === 'draft').length,
      scheduledNews: news.filter((n: Record<string, unknown>) => n.status === 'scheduled').length,
      totalCategories: categories.length,
      totalViews,
      todayViews,
      totalAds: ads.length,
      totalSubscribers: subscribers.length,
      totalUsers: totalUsersCount,
      activeUsers: activeUsersCount,
      totalRoles: totalRolesCount,
    },
  });
});

// ==============================================================================
// USER MANAGEMENT & REGISTERED USERS ROUTES (RBAC: manage_users)
// ==============================================================================
app.get('/api/admin/users', requireAdmin, requirePermission('manage_users'), (_req, res) => {
  res.json({ users: getAllSafeUsers() });
});

app.post('/api/admin/users', requireAdmin, requirePermission('manage_users'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  const fullName = String(b.full_name || '').trim();
  const username = String(b.username || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '');
  const email = String(b.email || '').trim().toLowerCase();
  const password = String(b.password || '');
  const roleSlug = String(b.role || 'member').trim();
  const isActive = b.is_active !== false ? 1 : 0;
  const customPermissions = Array.isArray(b.custom_permissions)
    ? b.custom_permissions.filter((p: unknown) => typeof p === 'string' && (ALL_PERMISSION_KEYS as readonly string[]).includes(p))
    : [];

  if (!fullName || !username || !email) {
    return res.status(400).json({ error: 'পূর্ণ নাম, ইউজারনেম এবং ইমেইল ঠিকানা আবশ্যক।' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'অনুগ্রহ করে সঠিক ইমেইল ঠিকানা লিখুন।' });
  }
  if (username.length < 3) {
    return res.status(400).json({ error: 'ইউজারনেম কমপক্ষে ৩ অক্ষরের হতে হবে (ইংরেজি অক্ষর/সংখ্যা)।' });
  }
  const pwErr = validateStrongPassword(password);
  if (pwErr) {
    return res.status(400).json({ error: pwErr });
  }

  const roleExists = db.prepare('SELECT slug FROM roles WHERE slug = ?').get(roleSlug);
  if (!roleExists) {
    return res.status(400).json({ error: 'নির্বাচিত রোলটি সঠিক নয়।' });
  }

  const dup = db.prepare('SELECT id FROM admin_profiles WHERE LOWER(email) = ? OR LOWER(username) = ?').get(email, username);
  if (dup) {
    return res.status(409).json({ error: 'এই ইমেইল অথবা ইউজারনেম দিয়ে ইতিমধ্যেই একটি অ্যাকাউন্ট রয়েছে।' });
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO admin_profiles (
      id, user_id, username, full_name, email, password_hash, role, custom_permissions, is_active, avatar_url, bio, phone, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    crypto.randomUUID(),
    username,
    fullName,
    email,
    hashPassword(password),
    roleSlug,
    JSON.stringify(customPermissions),
    isActive,
    b.avatar_url || null,
    b.bio || null,
    b.phone || null,
    now,
    now
  );

  logActivity(req.admin!.email, 'CREATE_USER', 'admin_profiles', id, { username, email, role: roleSlug, isActive: Boolean(isActive) }, req.ip);
  const created = db
    .prepare(
      'SELECT id, user_id, username, full_name, email, role, custom_permissions, is_active, avatar_url, bio, phone, last_login_at, created_at, updated_at FROM admin_profiles WHERE id = ?'
    )
    .get(id) as Record<string, unknown>;
  return res.status(201).json({ user: hydrateUserProfile(created) });
});

app.put('/api/admin/users/:id', requireAdmin, requirePermission('manage_users'), (req: AuthedRequest, res) => {
  const { id } = req.params;
  const existing = db.prepare('SELECT * FROM admin_profiles WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  if (!existing) {
    return res.status(404).json({ error: 'ব্যবহারকারী পাওয়া যায়নি।' });
  }

  const b = req.body || {};
  const fullName = String(b.full_name ?? existing.full_name).trim();
  const username = String(b.username ?? existing.username ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '');
  const email = String(b.email ?? existing.email).trim().toLowerCase();
  const roleSlug = String(b.role ?? existing.role).trim();
  const isActive = b.is_active !== undefined ? (b.is_active ? 1 : 0) : Number(existing.is_active ?? 1);
  const customPermissions = Array.isArray(b.custom_permissions)
    ? b.custom_permissions.filter((p: unknown) => typeof p === 'string' && (ALL_PERMISSION_KEYS as readonly string[]).includes(p))
    : safeJsonParse<string[]>(existing.custom_permissions as string, []);

  if (!fullName || !username || !email) {
    return res.status(400).json({ error: 'পূর্ণ নাম, ইউজারনেম ও ইমেইল আবশ্যক।' });
  }

  const roleExists = db.prepare('SELECT slug FROM roles WHERE slug = ?').get(roleSlug);
  if (!roleExists) {
    return res.status(400).json({ error: 'নির্বাচিত রোলটি সঠিক নয়।' });
  }

  if (id === req.admin!.id && !isActive) {
    return res.status(400).json({ error: 'আপনি নিজের সক্রিয় অ্যাকাউন্ট নিষ্ক্রিয় করতে পারবেন না।' });
  }
  if (id === req.admin!.id && existing.role === 'super_admin' && roleSlug !== 'super_admin') {
    return res.status(400).json({ error: 'আপনি নিজের সুপার অ্যাডমিন রোল পরিবর্তন করতে পারবেন না।' });
  }
  if (existing.role === 'super_admin' && (roleSlug !== 'super_admin' || !isActive)) {
    const activeSupers = (db.prepare("SELECT COUNT(*) as c FROM admin_profiles WHERE role = 'super_admin' AND is_active = 1 AND id != ?").get(id) as { c: number }).c;
    if (activeSupers === 0) {
      return res.status(400).json({ error: 'সিস্টেমে অন্তত একজন সক্রিয় সুপার অ্যাডমিন থাকা আবশ্যক।' });
    }
  }

  const dup = db.prepare('SELECT id FROM admin_profiles WHERE (LOWER(email) = ? OR LOWER(username) = ?) AND id != ?').get(email, username, id);
  if (dup) {
    return res.status(409).json({ error: 'অন্য একটি অ্যাকাউন্টে এই ইমেইল বা ইউজারনেম ব্যবহৃত হচ্ছে।' });
  }

  const now = new Date().toISOString();
  db.prepare(`
    UPDATE admin_profiles SET
      username = ?, full_name = ?, email = ?, role = ?, custom_permissions = ?, is_active = ?,
      phone = ?, bio = ?, avatar_url = ?, updated_at = ?
    WHERE id = ?
  `).run(
    username,
    fullName,
    email,
    roleSlug,
    JSON.stringify(customPermissions),
    isActive,
    b.phone !== undefined ? b.phone || null : existing.phone,
    b.bio !== undefined ? b.bio || null : existing.bio,
    b.avatar_url !== undefined ? b.avatar_url || null : existing.avatar_url,
    now,
    id
  );

  if (b.new_password && String(b.new_password).trim().length > 0) {
    const newPass = String(b.new_password);
    const pwErr = validateStrongPassword(newPass);
    if (pwErr) {
      return res.status(400).json({ error: pwErr });
    }
    db.prepare('UPDATE admin_profiles SET password_hash = ? WHERE id = ?').run(hashPassword(newPass), id);
  }

  logActivity(req.admin!.email, 'UPDATE_USER', 'admin_profiles', id, { username, role: roleSlug, isActive: Boolean(isActive) }, req.ip);
  const updated = db
    .prepare(
      'SELECT id, user_id, username, full_name, email, role, custom_permissions, is_active, avatar_url, bio, phone, last_login_at, created_at, updated_at FROM admin_profiles WHERE id = ?'
    )
    .get(id) as Record<string, unknown>;
  return res.json({ user: hydrateUserProfile(updated) });
});

app.patch('/api/admin/users/:id/status', requireAdmin, requirePermission('manage_users'), (req: AuthedRequest, res) => {
  const { id } = req.params;
  const isActive = req.body?.is_active ? 1 : 0;
  const existing = db.prepare('SELECT id, role, email, username FROM admin_profiles WHERE id = ?').get(id) as
    | { id: string; role: string; email: string; username: string | null }
    | undefined;
  if (!existing) {
    return res.status(404).json({ error: 'ব্যবহারকারী পাওয়া যায়নি।' });
  }
  if (id === req.admin!.id && !isActive) {
    return res.status(400).json({ error: 'আপনি নিজের অ্যাকাউন্ট নিষ্ক্রিয় করতে পারবেন না।' });
  }
  if (existing.role === 'super_admin' && !isActive) {
    const activeSupers = (db.prepare("SELECT COUNT(*) as c FROM admin_profiles WHERE role = 'super_admin' AND is_active = 1 AND id != ?").get(id) as { c: number }).c;
    if (activeSupers === 0) {
      return res.status(400).json({ error: 'অন্তত একজন সক্রিয় সুপার অ্যাডমিন থাকা আবশ্যক।' });
    }
  }

  db.prepare('UPDATE admin_profiles SET is_active = ?, updated_at = ? WHERE id = ?').run(isActive, new Date().toISOString(), id);
  logActivity(req.admin!.email, isActive ? 'ACTIVATE_USER' : 'DEACTIVATE_USER', 'admin_profiles', id, { email: existing.email }, req.ip);
  const updated = db
    .prepare(
      'SELECT id, user_id, username, full_name, email, role, custom_permissions, is_active, avatar_url, bio, phone, last_login_at, created_at, updated_at FROM admin_profiles WHERE id = ?'
    )
    .get(id) as Record<string, unknown>;
  return res.json({ user: hydrateUserProfile(updated) });
});

app.delete('/api/admin/users/:id', requireAdmin, requirePermission('manage_users'), (req: AuthedRequest, res) => {
  const { id } = req.params;
  if (id === req.admin!.id) {
    return res.status(400).json({ error: 'আপনি নিজের সক্রিয় অ্যাকাউন্ট মুছে ফেলতে পারবেন না।' });
  }
  const existing = db.prepare('SELECT id, role, email FROM admin_profiles WHERE id = ?').get(id) as
    | { id: string; role: string; email: string }
    | undefined;
  if (!existing) {
    return res.status(404).json({ error: 'ব্যবহারকারী পাওয়া যায়নি।' });
  }
  if (existing.role === 'super_admin') {
    const otherSupers = (db.prepare("SELECT COUNT(*) as c FROM admin_profiles WHERE role = 'super_admin' AND id != ?").get(id) as { c: number }).c;
    if (otherSupers === 0) {
      return res.status(400).json({ error: 'সিস্টেমের সর্বশেষ সুপার অ্যাডমিন মুছে ফেলা যাবে না।' });
    }
  }
  db.prepare('DELETE FROM admin_profiles WHERE id = ?').run(id);
  logActivity(req.admin!.email, 'DELETE_USER', 'admin_profiles', id, { email: existing.email }, req.ip);
  return res.json({ ok: true });
});

// ==============================================================================
// ROLES & PERMISSIONS MANAGEMENT ROUTES (RBAC: manage_roles)
// ==============================================================================
app.get('/api/admin/roles', requireAdmin, (req: AuthedRequest, res) => {
  if (req.admin!.role !== 'super_admin' && !req.admin!.permissions.includes('manage_roles') && !req.admin!.permissions.includes('manage_users')) {
    return res.status(403).json({ error: 'রোল তালিকা দেখার অনুমতি নেই।' });
  }
  return res.json({ roles: getAllHydratedRoles() });
});

app.post('/api/admin/roles', requireAdmin, requirePermission('manage_roles'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim();
  const slug = String(b.slug || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '_');
  const description = b.description ? String(b.description).trim() : null;
  const permissions = Array.isArray(b.permissions)
    ? b.permissions.filter((p: unknown) => typeof p === 'string' && (ALL_PERMISSION_KEYS as readonly string[]).includes(p))
    : [];

  if (!name || !slug) {
    return res.status(400).json({ error: 'রোলের নাম এবং স্লাগ (ইংরেজি) আবশ্যক।' });
  }
  const dup = db.prepare('SELECT id FROM roles WHERE slug = ?').get(slug);
  if (dup) {
    return res.status(409).json({ error: 'এই স্লাগ দিয়ে ইতিমধ্যেই একটি রোল রয়েছে।' });
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare('INSERT INTO roles (id, name, slug, description, permissions, is_system, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)').run(
    id,
    name,
    slug,
    description,
    JSON.stringify(permissions),
    now,
    now
  );
  logActivity(req.admin!.email, 'CREATE_ROLE', 'roles', id, { name, slug, permissions }, req.ip);
  const created = db.prepare('SELECT * FROM roles WHERE id = ?').get(id) as Record<string, unknown>;
  return res.status(201).json({
    role: {
      ...created,
      permissions,
      is_system: false,
      user_count: 0,
    },
  });
});

app.put('/api/admin/roles/:id', requireAdmin, requirePermission('manage_roles'), (req: AuthedRequest, res) => {
  const { id } = req.params;
  const existing = db.prepare('SELECT * FROM roles WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  if (!existing) {
    return res.status(404).json({ error: 'রোল পাওয়া যায়নি।' });
  }
  const b = req.body || {};
  const name = String(b.name ?? existing.name).trim();
  const description = b.description !== undefined ? (b.description ? String(b.description).trim() : null) : (existing.description as string | null);
  let permissions = Array.isArray(b.permissions)
    ? b.permissions.filter((p: unknown) => typeof p === 'string' && (ALL_PERMISSION_KEYS as readonly string[]).includes(p))
    : safeJsonParse<string[]>(existing.permissions as string, []);

  if (existing.slug === 'super_admin') {
    permissions = [...ALL_PERMISSION_KEYS];
  }

  const now = new Date().toISOString();
  db.prepare('UPDATE roles SET name = ?, description = ?, permissions = ?, updated_at = ? WHERE id = ?').run(
    name,
    description,
    JSON.stringify(permissions),
    now,
    id
  );
  logActivity(req.admin!.email, 'UPDATE_ROLE', 'roles', id, { slug: existing.slug, permissions }, req.ip);
  const updated = db.prepare('SELECT * FROM roles WHERE id = ?').get(id) as Record<string, unknown>;
  const count = (db.prepare('SELECT COUNT(*) as c FROM admin_profiles WHERE role = ?').get(String(existing.slug)) as { c: number }).c;
  return res.json({
    role: {
      ...updated,
      permissions,
      is_system: Boolean(updated.is_system),
      user_count: count,
    },
  });
});

app.delete('/api/admin/roles/:id', requireAdmin, requirePermission('manage_roles'), (req: AuthedRequest, res) => {
  const { id } = req.params;
  const existing = db.prepare('SELECT * FROM roles WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  if (!existing) {
    return res.status(404).json({ error: 'রোল পাওয়া যায়নি।' });
  }
  if (existing.is_system) {
    return res.status(400).json({ error: 'ডিফল্ট সিস্টেম রোল মুছে ফেলা যাবে না।' });
  }
  const assigned = (db.prepare('SELECT COUNT(*) as c FROM admin_profiles WHERE role = ?').get(String(existing.slug)) as { c: number }).c;
  if (assigned > 0) {
    return res.status(400).json({ error: 'এই রোলটি বর্তমানে ব্যবহারকারীদের সাথে যুক্ত রয়েছে। আগে তাদের রোল পরিবর্তন করুন।' });
  }
  db.prepare('DELETE FROM roles WHERE id = ?').run(id);
  logActivity(req.admin!.email, 'DELETE_ROLE', 'roles', id, { slug: existing.slug }, req.ip);
  return res.json({ ok: true });
});

// News CRUD
app.post('/api/admin/news', requireAdmin, requirePermission('manage_news'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  if (!b.title || !b.summary || !b.content || !b.category_id) {
    return res.status(400).json({ error: 'শিরোনাম, সারসংক্ষেপ, মূল প্রতিবেদন ও ক্যাটাগরি আবশ্যক।' });
  }
  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  const slug = String(b.slug || `news-${Date.now().toString(36)}`).trim();
  const status = ['draft', 'published', 'scheduled', 'unpublished'].includes(b.status) ? b.status : 'draft';
  const publishedAt = status === 'published' ? b.published_at || now : null;

  try {
    db.prepare(`
      INSERT INTO news (
        id, title, subtitle, slug, summary, content, featured_image, image_caption, image_credit,
        gallery_images, video_url, category_id, subcategory_id, author_name, reporter_name, location,
        tags, status, is_featured, is_pinned, is_editors_choice, is_breaking,
        seo_title, seo_description, views_count, published_at, scheduled_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
    `).run(
      id,
      b.title,
      b.subtitle || null,
      slug,
      b.summary,
      b.content,
      b.featured_image || null,
      b.image_caption || null,
      b.image_credit || null,
      JSON.stringify(b.gallery_images || []),
      b.video_url || null,
      b.category_id,
      b.subcategory_id || null,
      b.author_name || 'নিজস্ব প্রতিবেদক',
      b.reporter_name || null,
      b.location || 'সিলেট',
      JSON.stringify(b.tags || []),
      status,
      b.is_featured ? 1 : 0,
      b.is_pinned ? 1 : 0,
      b.is_editors_choice ? 1 : 0,
      b.is_breaking ? 1 : 0,
      b.seo_title || b.title,
      b.seo_description || b.summary,
      publishedAt,
      b.scheduled_at || null,
      now,
      now
    );

    if (b.is_breaking && status === 'published') {
      db.prepare(`
        INSERT INTO breaking_news (id, headline, news_url, news_id, text_color, display_order, is_active, speed_seconds, display_duration_minutes, created_at, updated_at)
        VALUES (?, ?, ?, ?, '#FFFFFF', 0, 1, 32, 0, ?, ?)
      `).run(crypto.randomUUID(), b.title, `/news/${slug}`, id, now, now);
    }

    logActivity(req.admin!.email, 'CREATE_NEWS', 'news', id, { title: b.title, status }, req.ip);
    const created = db.prepare('SELECT * FROM news WHERE id = ?').get(id) as Record<string, unknown>;
    return res.json({ article: hydrateNewsRow(created) });
  } catch (err: unknown) {
    return res.status(400).json({ error: err instanceof Error ? err.message : 'সংবাদ সংরক্ষণে ত্রুটি হয়েছে।' });
  }
});

app.put('/api/admin/news/:id', requireAdmin, requirePermission('manage_news'), (req: AuthedRequest, res) => {
  const { id } = req.params;
  const b = req.body || {};
  const existing = db.prepare('SELECT * FROM news WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  if (!existing) return res.status(404).json({ error: 'সংবাদ পাওয়া যায়নি।' });

  const now = new Date().toISOString();
  const status = ['draft', 'published', 'scheduled', 'unpublished'].includes(b.status) ? b.status : String(existing.status);
  const publishedAt = status === 'published' ? existing.published_at || b.published_at || now : existing.published_at;

  try {
    db.prepare(`
      UPDATE news SET
        title = ?, subtitle = ?, slug = ?, summary = ?, content = ?,
        featured_image = ?, image_caption = ?, image_credit = ?, gallery_images = ?, video_url = ?,
        category_id = ?, subcategory_id = ?, author_name = ?, reporter_name = ?, location = ?,
        tags = ?, status = ?, is_featured = ?, is_pinned = ?, is_editors_choice = ?, is_breaking = ?,
        seo_title = ?, seo_description = ?, published_at = ?, scheduled_at = ?, updated_at = ?
      WHERE id = ?
    `).run(
      (b.title ?? existing.title) as string,
      (b.subtitle ?? existing.subtitle) as string | null,
      (b.slug ?? existing.slug) as string,
      (b.summary ?? existing.summary) as string,
      (b.content ?? existing.content) as string,
      (b.featured_image ?? existing.featured_image) as string | null,
      (b.image_caption ?? existing.image_caption) as string | null,
      (b.image_credit ?? existing.image_credit) as string | null,
      JSON.stringify(b.gallery_images ?? safeJsonParse(existing.gallery_images as string, [])),
      (b.video_url ?? existing.video_url) as string | null,
      (b.category_id ?? existing.category_id) as string,
      (b.subcategory_id ?? existing.subcategory_id) as string | null,
      (b.author_name ?? existing.author_name) as string,
      (b.reporter_name ?? existing.reporter_name) as string | null,
      (b.location ?? existing.location) as string | null,
      JSON.stringify(b.tags ?? safeJsonParse(existing.tags as string, [])),
      status,
      b.is_featured !== undefined ? (b.is_featured ? 1 : 0) : Number(existing.is_featured || 0),
      b.is_pinned !== undefined ? (b.is_pinned ? 1 : 0) : Number(existing.is_pinned || 0),
      b.is_editors_choice !== undefined ? (b.is_editors_choice ? 1 : 0) : Number(existing.is_editors_choice || 0),
      b.is_breaking !== undefined ? (b.is_breaking ? 1 : 0) : Number(existing.is_breaking || 0),
      (b.seo_title ?? existing.seo_title) as string | null,
      (b.seo_description ?? existing.seo_description) as string | null,
      publishedAt as string | null,
      (b.scheduled_at ?? existing.scheduled_at) as string | null,
      now,
      id
    );

    logActivity(req.admin!.email, 'UPDATE_NEWS', 'news', id, { title: b.title || existing.title, status }, req.ip);
    const updated = db.prepare('SELECT * FROM news WHERE id = ?').get(id) as Record<string, unknown>;
    return res.json({ article: hydrateNewsRow(updated) });
  } catch (err: unknown) {
    return res.status(400).json({ error: err instanceof Error ? err.message : 'আপডেটে ত্রুটি হয়েছে।' });
  }
});

app.delete('/api/admin/news/:id', requireAdmin, requirePermission('manage_news'), (req: AuthedRequest, res) => {
  const { id } = req.params;
  db.prepare('DELETE FROM news WHERE id = ?').run(id);
  logActivity(req.admin!.email, 'DELETE_NEWS', 'news', id, {}, req.ip);
  res.json({ ok: true });
});

// Categories & Subcategories CRUD
app.post('/api/admin/categories', requireAdmin, requirePermission('manage_taxonomy'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO categories (id, name, slug, description, image_url, seo_title, seo_description, display_order, is_active, show_in_nav, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    b.name,
    b.slug,
    b.description || null,
    b.image_url || null,
    b.seo_title || b.name,
    b.seo_description || b.description || null,
    Number(b.display_order || 0),
    b.is_active !== false ? 1 : 0,
    b.show_in_nav !== false ? 1 : 0,
    now,
    now
  );
  logActivity(req.admin!.email, 'CREATE_CATEGORY', 'categories', id, { name: b.name }, req.ip);
  res.json({ category: hydrateBoolFields(db.prepare('SELECT * FROM categories WHERE id = ?').get(id) as Record<string, unknown>, ['is_active', 'show_in_nav']) });
});

app.put('/api/admin/categories/:id', requireAdmin, requirePermission('manage_taxonomy'), (req: AuthedRequest, res) => {
  const { id } = req.params;
  const b = req.body || {};
  const now = new Date().toISOString();
  db.prepare(`
    UPDATE categories SET name = ?, slug = ?, description = ?, image_url = ?, seo_title = ?, seo_description = ?, display_order = ?, is_active = ?, show_in_nav = ?, updated_at = ?
    WHERE id = ?
  `).run(
    b.name,
    b.slug,
    b.description || null,
    b.image_url || null,
    b.seo_title || b.name,
    b.seo_description || null,
    Number(b.display_order || 0),
    b.is_active ? 1 : 0,
    b.show_in_nav ? 1 : 0,
    now,
    id
  );
  logActivity(req.admin!.email, 'UPDATE_CATEGORY', 'categories', id, { name: b.name }, req.ip);
  res.json({ category: hydrateBoolFields(db.prepare('SELECT * FROM categories WHERE id = ?').get(id) as Record<string, unknown>, ['is_active', 'show_in_nav']) });
});

app.delete('/api/admin/categories/:id', requireAdmin, requirePermission('manage_taxonomy'), (req: AuthedRequest, res) => {
  const used = db.prepare('SELECT COUNT(*) as c FROM news WHERE category_id = ?').get(req.params.id) as { c: number };
  if (used.c > 0) {
    return res.status(400).json({ error: 'এই ক্যাটাগরিতে প্রকাশিত বা খসড়া সংবাদ রয়েছে। আগে সংবাদগুলো অন্য ক্যাটাগরিতে সরিয়ে নিন।' });
  }
  db.prepare('DELETE FROM categories WHERE id = ?').run(req.params.id);
  logActivity(req.admin!.email, 'DELETE_CATEGORY', 'categories', req.params.id, {}, req.ip);
  return res.json({ ok: true });
});

app.post('/api/admin/subcategories', requireAdmin, requirePermission('manage_taxonomy'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO subcategories (id, category_id, name, slug, description, display_order, is_active, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, b.category_id, b.name, b.slug, b.description || null, Number(b.display_order || 0), b.is_active !== false ? 1 : 0, now, now);
  logActivity(req.admin!.email, 'CREATE_SUBCATEGORY', 'subcategories', id, { name: b.name }, req.ip);
  res.json({ subcategory: hydrateBoolFields(db.prepare('SELECT * FROM subcategories WHERE id = ?').get(id) as Record<string, unknown>, ['is_active']) });
});

app.put('/api/admin/subcategories/:id', requireAdmin, requirePermission('manage_taxonomy'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  db.prepare('UPDATE subcategories SET category_id = ?, name = ?, slug = ?, description = ?, display_order = ?, is_active = ?, updated_at = ? WHERE id = ?').run(
    b.category_id,
    b.name,
    b.slug,
    b.description || null,
    Number(b.display_order || 0),
    b.is_active ? 1 : 0,
    new Date().toISOString(),
    req.params.id
  );
  res.json({ subcategory: hydrateBoolFields(db.prepare('SELECT * FROM subcategories WHERE id = ?').get(req.params.id) as Record<string, unknown>, ['is_active']) });
});

app.delete('/api/admin/subcategories/:id', requireAdmin, requirePermission('manage_taxonomy'), (req: AuthedRequest, res) => {
  db.prepare('DELETE FROM subcategories WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Breaking News CRUD
app.post('/api/admin/breaking', requireAdmin, requirePermission('manage_breaking'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const durationMin = Number(b.display_duration_minutes || 0);
  const expiresAt = durationMin > 0 ? new Date(Date.now() + durationMin * 60_000).toISOString() : null;
  db.prepare(`
    INSERT INTO breaking_news (id, headline, news_url, news_id, text_color, display_order, is_active, speed_seconds, display_duration_minutes, expires_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    b.headline,
    b.news_url || null,
    b.news_id || null,
    b.text_color || '#FFFFFF',
    Number(b.display_order || 0),
    b.is_active !== false ? 1 : 0,
    Number(b.speed_seconds || 32),
    durationMin,
    expiresAt,
    now,
    now
  );
  logActivity(req.admin!.email, 'CREATE_BREAKING', 'breaking_news', id, { headline: b.headline }, req.ip);
  res.json({ item: hydrateBoolFields(db.prepare('SELECT * FROM breaking_news WHERE id = ?').get(id) as Record<string, unknown>, ['is_active']) });
});

app.put('/api/admin/breaking/:id', requireAdmin, requirePermission('manage_breaking'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  const now = new Date().toISOString();
  const durationMin = Number(b.display_duration_minutes || 0);
  const expiresAt = durationMin > 0 ? new Date(Date.now() + durationMin * 60_000).toISOString() : null;
  db.prepare(`
    UPDATE breaking_news SET headline = ?, news_url = ?, news_id = ?, text_color = ?, display_order = ?, is_active = ?, speed_seconds = ?, display_duration_minutes = ?, expires_at = ?, updated_at = ?
    WHERE id = ?
  `).run(
    b.headline,
    b.news_url || null,
    b.news_id || null,
    b.text_color || '#FFFFFF',
    Number(b.display_order || 0),
    b.is_active ? 1 : 0,
    Number(b.speed_seconds || 32),
    durationMin,
    expiresAt,
    now,
    req.params.id
  );
  res.json({ item: hydrateBoolFields(db.prepare('SELECT * FROM breaking_news WHERE id = ?').get(req.params.id) as Record<string, unknown>, ['is_active']) });
});

app.delete('/api/admin/breaking/:id', requireAdmin, requirePermission('manage_breaking'), (req: AuthedRequest, res) => {
  db.prepare('DELETE FROM breaking_news WHERE id = ?').run(req.params.id);
  logActivity(req.admin!.email, 'DELETE_BREAKING', 'breaking_news', req.params.id, {}, req.ip);
  res.json({ ok: true });
});

// Advertisements CRUD (Adsterra Popunder, Social Bar, Banners)
app.post('/api/admin/ads', requireAdmin, requirePermission('manage_ads'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO advertisements (id, title, format, placement, script_code, image_url, click_url, is_active, show_desktop, show_mobile, frequency_hours, start_date, end_date, impressions_count, clicks_count, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
  `).run(
    id,
    b.title,
    b.format,
    b.placement,
    b.script_code || null,
    b.image_url || null,
    b.click_url || null,
    b.is_active !== false ? 1 : 0,
    b.show_desktop !== false ? 1 : 0,
    b.show_mobile !== false ? 1 : 0,
    Number(b.frequency_hours ?? 6),
    b.start_date || null,
    b.end_date || null,
    now,
    now
  );
  logActivity(req.admin!.email, 'CREATE_AD', 'advertisements', id, { title: b.title, placement: b.placement }, req.ip);
  res.json({ ad: hydrateBoolFields(db.prepare('SELECT * FROM advertisements WHERE id = ?').get(id) as Record<string, unknown>, ['is_active', 'show_desktop', 'show_mobile']) });
});

app.put('/api/admin/ads/:id', requireAdmin, requirePermission('manage_ads'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  const now = new Date().toISOString();
  db.prepare(`
    UPDATE advertisements SET title = ?, format = ?, placement = ?, script_code = ?, image_url = ?, click_url = ?, is_active = ?, show_desktop = ?, show_mobile = ?, frequency_hours = ?, start_date = ?, end_date = ?, updated_at = ?
    WHERE id = ?
  `).run(
    b.title,
    b.format,
    b.placement,
    b.script_code || null,
    b.image_url || null,
    b.click_url || null,
    b.is_active ? 1 : 0,
    b.show_desktop ? 1 : 0,
    b.show_mobile ? 1 : 0,
    Number(b.frequency_hours ?? 6),
    b.start_date || null,
    b.end_date || null,
    now,
    req.params.id
  );
  logActivity(req.admin!.email, 'UPDATE_AD', 'advertisements', req.params.id, { title: b.title }, req.ip);
  res.json({ ad: hydrateBoolFields(db.prepare('SELECT * FROM advertisements WHERE id = ?').get(req.params.id) as Record<string, unknown>, ['is_active', 'show_desktop', 'show_mobile']) });
});

app.delete('/api/admin/ads/:id', requireAdmin, requirePermission('manage_ads'), (req: AuthedRequest, res) => {
  db.prepare('DELETE FROM advertisements WHERE id = ?').run(req.params.id);
  logActivity(req.admin!.email, 'DELETE_AD', 'advertisements', req.params.id, {}, req.ip);
  res.json({ ok: true });
});

// Homepage Sections Customization
app.put('/api/admin/homepage-sections', requireAdmin, requirePermission('manage_layout'), (req: AuthedRequest, res) => {
  const items = Array.isArray(req.body?.sections) ? req.body.sections : [];
  const now = new Date().toISOString();
  const stmt = db.prepare(`
    UPDATE homepage_sections
    SET title_bn = ?, category_slug = ?, layout_type = ?, item_count = ?, display_order = ?, is_visible = ?, show_sidebar = ?, updated_at = ?
    WHERE id = ?
  `);
  for (const s of items) {
    stmt.run(s.title_bn, s.category_slug || null, s.layout_type, Number(s.item_count || 4), Number(s.display_order || 0), s.is_visible ? 1 : 0, s.show_sidebar ? 1 : 0, now, s.id);
  }
  logActivity(req.admin!.email, 'UPDATE_HOMEPAGE_LAYOUT', 'homepage_sections', 'batch', { count: items.length }, req.ip);
  res.json({
    sections: (db.prepare('SELECT * FROM homepage_sections ORDER BY display_order ASC').all() as Array<Record<string, unknown>>).map((s) =>
      hydrateBoolFields(s, ['is_visible', 'show_sidebar'])
    ),
  });
});

// Website Settings Update
app.put('/api/admin/settings', requireAdmin, requirePermission('manage_settings'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  const now = new Date().toISOString();
  db.prepare(`
    UPDATE website_settings SET
      site_name_bn = ?, site_name_en = ?, tagline = ?, logo_url = ?, favicon_url = ?, default_og_image = ?,
      contact_email = ?, contact_phone = ?, office_address = ?, about_us = ?, privacy_policy = ?, terms_conditions = ?,
      facebook_url = ?, youtube_url = ?, twitter_url = ?, instagram_url = ?, whatsapp_number = ?, telegram_url = ?,
      footer_text = ?, copyright_text = ?, google_site_verification = ?, breaking_enabled = ?, breaking_speed = ?,
      theme_preset = ?, header_style = ?, primary_color = ?, accent_color = ?, updated_at = ?
    WHERE id = 1
  `).run(
    b.site_name_bn,
    b.site_name_en,
    b.tagline,
    b.logo_url || null,
    b.favicon_url || null,
    b.default_og_image || null,
    b.contact_email,
    b.contact_phone,
    b.office_address,
    b.about_us,
    b.privacy_policy,
    b.terms_conditions,
    b.facebook_url || null,
    b.youtube_url || null,
    b.twitter_url || null,
    b.instagram_url || null,
    b.whatsapp_number || null,
    b.telegram_url || null,
    b.footer_text,
    b.copyright_text,
    b.google_site_verification || '',
    b.breaking_enabled ? 1 : 0,
    Number(b.breaking_speed || 32),
    b.theme_preset || 'classic_navy',
    b.header_style || 'standard',
    b.primary_color || '#0B1F3A',
    b.accent_color || '#C81E1E',
    now
  );
  logActivity(req.admin!.email, 'UPDATE_SETTINGS', 'website_settings', '1', {}, req.ip);
  res.json({ settings: hydrateBoolFields(db.prepare('SELECT * FROM website_settings WHERE id = 1').get() as Record<string, unknown>, ['breaking_enabled']) });
});

// Gallery & Video CRUD
app.post('/api/admin/gallery', requireAdmin, requirePermission('manage_media'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare('INSERT INTO gallery (id, title, caption, image_url, photographer, category_name, display_order, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
    id,
    b.title,
    b.caption || null,
    b.image_url,
    b.photographer || 'ফটো ডেস্ক',
    b.category_name || 'সিলেট',
    Number(b.display_order || 0),
    b.is_active !== false ? 1 : 0,
    now
  );
  res.json({ item: hydrateBoolFields(db.prepare('SELECT * FROM gallery WHERE id = ?').get(id) as Record<string, unknown>, ['is_active']) });
});

app.delete('/api/admin/gallery/:id', requireAdmin, requirePermission('manage_media'), (req: AuthedRequest, res) => {
  db.prepare('DELETE FROM gallery WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/videos', requireAdmin, requirePermission('manage_media'), (req: AuthedRequest, res) => {
  const b = req.body || {};
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO video_news (id, title, description, video_url, thumbnail_url, duration, category_name, views_count, is_featured, is_active, published_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
  `).run(
    id,
    b.title,
    b.description || null,
    b.video_url,
    b.thumbnail_url || null,
    b.duration || '০৩:০০',
    b.category_name || 'জাতীয়',
    b.is_featured ? 1 : 0,
    b.is_active !== false ? 1 : 0,
    now,
    now
  );
  res.json({ video: hydrateBoolFields(db.prepare('SELECT * FROM video_news WHERE id = ?').get(id) as Record<string, unknown>, ['is_featured', 'is_active']) });
});

app.delete('/api/admin/videos/:id', requireAdmin, requirePermission('manage_media'), (req: AuthedRequest, res) => {
  db.prepare('DELETE FROM video_news WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Admin Profile & Password Update
app.put('/api/admin/profile', requireAdmin, (req: AuthedRequest, res) => {
  const b = req.body || {};
  const existing = db.prepare('SELECT * FROM admin_profiles WHERE id = ?').get(req.admin!.id) as Record<string, unknown> | undefined;
  if (!existing) {
    return res.status(404).json({ error: 'প্রোফাইল পাওয়া যায়নি।' });
  }

  const fullName = String(b.full_name ?? existing.full_name).trim();
  if (!fullName) {
    return res.status(400).json({ error: 'পূর্ণ নাম আবশ্যক।' });
  }

  let username = existing.username ? String(existing.username) : '';
  if (b.username !== undefined) {
    const cleanUsername = String(b.username)
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._-]/g, '');
    if (cleanUsername.length < 3) {
      return res.status(400).json({ error: 'ইউজারনেম কমপক্ষে ৩ অক্ষরের হতে হবে।' });
    }
    const dup = db.prepare('SELECT id FROM admin_profiles WHERE LOWER(username) = ? AND id != ?').get(cleanUsername, req.admin!.id);
    if (dup) {
      return res.status(409).json({ error: 'এই ইউজারনেম ইতিমধ্যেই ব্যবহৃত হচ্ছে।' });
    }
    username = cleanUsername;
  }

  if (b.new_password && String(b.new_password).trim().length > 0) {
    const newPassword = String(b.new_password);
    const pwErr = validateStrongPassword(newPassword);
    if (pwErr) {
      return res.status(400).json({ error: pwErr });
    }
    const currentPassword = String(b.current_password || '');
    if (!currentPassword || !verifyPassword(currentPassword, String(existing.password_hash))) {
      return res.status(400).json({ error: 'বর্তমান পাসওয়ার্ড সঠিক নয়।' });
    }
    db.prepare('UPDATE admin_profiles SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), req.admin!.id);
    logActivity(req.admin!.email, 'CHANGE_PASSWORD', 'admin_profiles', req.admin!.id, {}, req.ip);
  }

  const now = new Date().toISOString();
  db.prepare('UPDATE admin_profiles SET username = ?, full_name = ?, phone = ?, bio = ?, avatar_url = ?, updated_at = ? WHERE id = ?').run(
    username || null,
    fullName,
    b.phone !== undefined ? b.phone || null : existing.phone,
    b.bio !== undefined ? b.bio || null : existing.bio,
    b.avatar_url !== undefined ? b.avatar_url || null : existing.avatar_url,
    now,
    req.admin!.id
  );
  logActivity(req.admin!.email, 'UPDATE_PROFILE', 'admin_profiles', req.admin!.id, { full_name: fullName }, req.ip);

  const updated = db
    .prepare(
      'SELECT id, user_id, username, full_name, email, role, custom_permissions, is_active, avatar_url, bio, phone, last_login_at, created_at, updated_at FROM admin_profiles WHERE id = ?'
    )
    .get(req.admin!.id) as Record<string, unknown>;
  return res.json({ profile: hydrateUserProfile(updated) });
});

// Secure Base64 Image Upload Endpoint (Max 5MB, Strict MIME validation)
app.post('/api/admin/upload', requireAdmin, requirePermission('manage_media'), (req: AuthedRequest, res) => {
  const { filename, mimeType, base64Data } = req.body || {};
  const allowed: Record<string, string> = {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp',
    'image/gif': 'gif',
  };
  const ext = allowed[String(mimeType || '').toLowerCase()];
  if (!ext) {
    return res.status(400).json({ error: 'কেবলমাত্র JPG, PNG, WebP অথবা GIF ছবি আপলোড করা যাবে।' });
  }
  if (!base64Data || typeof base64Data !== 'string') {
    return res.status(400).json({ error: 'ছবির ডেটা পাওয়া যায়নি।' });
  }
  const cleanB64 = base64Data.replace(/^data:image\/\w+;base64,/, '');
  const buffer = Buffer.from(cleanB64, 'base64');
  if (buffer.length > 5 * 1024 * 1024) {
    return res.status(400).json({ error: 'ছবির আকার সর্বোচ্চ ৫ মেগাবাইটের মধ্যে হতে হবে।' });
  }
  const safeBase = String(filename || 'upload')
    .replace(/\.[^/.]+$/, '')
    .replace(/[^a-zA-Z0-9_-]/g, '')
    .slice(0, 32) || 'img';
  const finalName = `${safeBase}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}.${ext}`;
  fs.writeFileSync(path.join(UPLOADS_DIR, finalName), buffer);
  logActivity(req.admin!.email, 'UPLOAD_IMAGE', 'storage', finalName, { size: buffer.length }, req.ip);
  return res.json({ url: `/uploads/${finalName}` });
});

// Database Backup JSON Export
app.get('/api/admin/backup-json', requireAdmin, requirePermission('manage_backup'), (req: AuthedRequest, res) => {
  const payload = {
    exportedAt: new Date().toISOString(),
    version: '1.0.0',
    tables: {
      website_settings: db.prepare('SELECT * FROM website_settings').all(),
      categories: db.prepare('SELECT * FROM categories').all(),
      subcategories: db.prepare('SELECT * FROM subcategories').all(),
      homepage_sections: db.prepare('SELECT * FROM homepage_sections').all(),
      news: db.prepare('SELECT * FROM news').all(),
      breaking_news: db.prepare('SELECT * FROM breaking_news').all(),
      advertisements: db.prepare('SELECT * FROM advertisements').all(),
      gallery: db.prepare('SELECT * FROM gallery').all(),
      video_news: db.prepare('SELECT * FROM video_news').all(),
      newsletter_subscribers: db.prepare('SELECT * FROM newsletter_subscribers').all(),
    },
  };
  logActivity(req.admin!.email, 'EXPORT_DB_BACKUP', 'system', 'backup.json', {}, req.ip);
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="kushiara-express-backup-${new Date().toISOString().slice(0, 10)}.json"`);
  res.send(JSON.stringify(payload, null, 2));
});

// Complete Production Deployment Project ZIP Export (Never contains secrets or local sqlite db)
app.get('/api/admin/export-zip', requireAdmin, requirePermission('manage_backup'), async (req: AuthedRequest, res) => {
  try {
    const zip = new JSZip();
    const rootDir = process.cwd();
    const excludeDirs = new Set(['node_modules', 'dist', '.git', 'data', '.netlify']);
    const excludeFiles = new Set(['.env', '.DS_Store', 'server.js']);

    function addDirToZip(currentPath: string, relBase: string) {
      const entries = fs.readdirSync(currentPath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (excludeDirs.has(entry.name)) continue;
          addDirToZip(path.join(currentPath, entry.name), relBase ? `${relBase}/${entry.name}` : entry.name);
        } else {
          if (excludeFiles.has(entry.name)) continue;
          const filePath = path.join(currentPath, entry.name);
          const zipPath = relBase ? `${relBase}/${entry.name}` : entry.name;
          zip.file(zipPath, fs.readFileSync(filePath));
        }
      }
    }

    addDirToZip(rootDir, '');
    const buffer = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE', compressionOptions: { level: 6 } });
    logActivity(req.admin!.email, 'EXPORT_PROJECT_ZIP', 'system', 'kushiara-express-deploy.zip', { size: buffer.length }, req.ip);

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="kushiara-express-netlify-package.zip"');
    res.send(buffer);
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'প্রজেক্ট এক্সপোর্ট ব্যর্থ হয়েছে।' });
  }
});

function getPublicOrigin(req: Request): string {
  const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
  const host = forwardedHost || req.get('host') || `localhost:${PORT}`;
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const proto = forwardedProto || (host.includes('.run.app') ? 'https' : req.protocol || 'http');
  const reqOrigin = `${proto}://${host}`.replace(/\/$/, '');

  const configuredSiteUrl = (process.env.VITE_SITE_URL || '').trim().replace(/\/$/, '');
  if (
    configuredSiteUrl &&
    /^https?:\/\//i.test(configuredSiteUrl) &&
    !configuredSiteUrl.includes('kushiaraexpress.com') &&
    !host.includes('.run.app') &&
    !host.includes('localhost') &&
    !host.includes('127.0.0.1')
  ) {
    return configuredSiteUrl;
  }
  return reqOrigin;
}

function resolvePublicImageUrl(rawImg: string | null | undefined, siteUrl: string, fallback = '/og-cover.jpg'): string {
  const clean = String(rawImg || '').trim();
  const normalized =
    !clean || clean.includes('og_default_banner_1794719115320.jpg')
      ? fallback
      : clean;
  if (/^https?:\/\//i.test(normalized)) return normalized;
  return `${siteUrl}${normalized.startsWith('/') ? '' : '/'}${normalized}`;
}

function getRuntimePublicConfigScript(siteUrl: string): string {
  const supabaseUrl = (process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || '').trim();
  const supabaseAnonKey = (process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || '').trim();
  const payload = {
    VITE_SUPABASE_URL: supabaseUrl && !supabaseUrl.includes('YOUR_PROJECT_ID') ? supabaseUrl : '',
    VITE_SUPABASE_ANON_KEY: supabaseAnonKey && !supabaseAnonKey.includes('YOUR_SUPABASE_ANON_KEY') ? supabaseAnonKey : '',
    VITE_SITE_URL: siteUrl,
  };
  return `<script>window.__KUSHIARA_RUNTIME_CONFIG__=${JSON.stringify(payload).replace(/</g, '\\u003c')};</script>`;
}

async function fetchSupabaseArticleForOg(slug: string): Promise<Record<string, unknown> | null> {
  const supabaseUrl = (process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || '').trim().replace(/\/$/, '');
  const supabaseAnonKey = (process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY || '').trim();
  if (!supabaseUrl || !supabaseAnonKey || supabaseUrl.includes('YOUR_PROJECT_ID') || supabaseAnonKey.includes('YOUR_SUPABASE_ANON_KEY')) {
    return null;
  }
  try {
    const endpoint = `${supabaseUrl}/rest/v1/news?select=title,seo_title,summary,seo_description,featured_image,published_at,updated_at,author_name,slug&slug=eq.${encodeURIComponent(slug)}&status=eq.published&limit=1`;
    const res = await fetch(endpoint, {
      headers: {
        apikey: supabaseAnonKey,
        Authorization: `Bearer ${supabaseAnonKey}`,
      },
    });
    if (!res.ok) return null;
    const rows = (await res.json()) as Array<Record<string, unknown>>;
    return rows[0] || null;
  } catch {
    return null;
  }
}

// ==============================================================================
// DYNAMIC XML SITEMAP & ROBOTS.TXT
// ==============================================================================
app.get('/sitemap.xml', (req, res) => {
  const siteUrl = getPublicOrigin(req);
  const categories = db.prepare('SELECT slug FROM categories WHERE is_active = 1').all() as Array<{ slug: string }>;
  const articles = db.prepare("SELECT slug, updated_at, published_at FROM news WHERE status = 'published' ORDER BY published_at DESC LIMIT 500").all() as Array<{
    slug: string;
    updated_at: string;
    published_at: string;
  }>;

  const staticPaths = ['', '/latest', '/popular', '/gallery', '/videos', '/about', '/contact', '/privacy', '/terms'];
  const urls = [
    ...staticPaths.map((p) => `<url><loc>${escapeHtml(siteUrl + p)}</loc><changefreq>daily</changefreq><priority>${p === '' ? '1.0' : '0.7'}</priority></url>`),
    ...categories.map((c) => `<url><loc>${escapeHtml(`${siteUrl}/category/${c.slug}`)}</loc><changefreq>hourly</changefreq><priority>0.8</priority></url>`),
    ...articles.map(
      (a) =>
        `<url><loc>${escapeHtml(`${siteUrl}/news/${encodeURIComponent(a.slug)}`)}</loc><lastmod>${escapeHtml(new Date(a.updated_at || a.published_at).toISOString())}</lastmod><changefreq>daily</changefreq><priority>0.9</priority></url>`
    ),
  ];

  res.setHeader('Content-Type', 'application/xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>`);
});

// ==============================================================================
// SERVER-SIDE OPEN GRAPH (WHATSAPP / FACEBOOK / MESSENGER) + RUNTIME CONFIG
// ==============================================================================
async function injectPublicRuntimeAndOg(html: string, req: Request): Promise<string> {
  const siteUrl = getPublicOrigin(req);
  const runtimeScript = getRuntimePublicConfigScript(siteUrl);

  // Admin route: noindex + runtime config (protected by login gate + API JWT/Supabase auth)
  if (req.path.startsWith('/admin')) {
    return html
      .replace(/<title>.*?<\/title>/i, '<title>অ্যাডমিন প্যানেল | কুশিয়ারা এক্সপ্রেস</title>')
      .replace(/<meta\s+name="robots"[^>]*>/i, '<meta name="robots" content="noindex, nofollow" />')
      .replace('<!--RUNTIME_CONFIG-->', runtimeScript);
  }

  const settings = db.prepare('SELECT * FROM website_settings WHERE id = 1').get() as Record<string, unknown> | undefined;
  const siteNameBn = String(settings?.site_name_bn || 'কুশিয়ারা এক্সপ্রেস');
  const fullSiteTitle = `${siteNameBn} | Kushiara Express`;
  const tagline = String(settings?.tagline || 'সত্যের পথে, মানুষের সাথে।');
  const footerText = String(settings?.footer_text || 'সিলেট, গোলাপগঞ্জ ও বাংলাদেশের সত্যনিষ্ঠ ও স্বাধীন অনলাইন বাংলা সংবাদমাধ্যম।');
  const defaultDesc = `${fullSiteTitle} — ${tagline} ${footerText}`;
  const defaultCover = resolvePublicImageUrl(settings?.default_og_image as string | undefined, siteUrl, '/og-cover.jpg');
  const logoUrl = resolvePublicImageUrl(settings?.logo_url as string | undefined, siteUrl, '/brand-logo.jpg');
  const canonicalPath = req.path === '/' ? '' : req.path;
  let canonicalUrl = `${siteUrl}${canonicalPath}`;

  let pageTitle = fullSiteTitle;
  let pageDescription = defaultDesc;
  let ogType = 'website';
  let ogImage = defaultCover;
  let extraArticleTags = '';
  let schemaObj: Record<string, unknown> = {
    '@context': 'https://schema.org',
    '@type': 'NewsMediaOrganization',
    name: fullSiteTitle,
    alternateName: String(settings?.site_name_en || 'KUSHIARA EXPRESS'),
    description: defaultDesc,
    url: siteUrl,
    logo: {
      '@type': 'ImageObject',
      url: logoUrl,
    },
    image: defaultCover,
  };

  const newsMatch = req.path.match(/^\/news\/([^/]+)$/);
  const categoryMatch = req.path.match(/^\/category\/([^/]+)$/);

  if (newsMatch) {
    const slug = decodeURIComponent(newsMatch[1]);
    let row = db.prepare("SELECT * FROM news WHERE slug = ? AND status = 'published'").get(slug) as Record<string, unknown> | undefined;
    if (!row) {
      row = (await fetchSupabaseArticleForOg(slug)) || undefined;
    }
    if (row) {
      pageTitle = String(row.seo_title || `${row.title} | ${siteNameBn}`);
      pageDescription = String(row.seo_description || row.summary || defaultDesc);
      ogType = 'article';
      ogImage = resolvePublicImageUrl(row.featured_image as string | undefined, siteUrl, '/og-cover.jpg');
      canonicalUrl = `${siteUrl}/news/${encodeURIComponent(String(row.slug))}`;
      extraArticleTags = `
    <meta property="article:published_time" content="${escapeHtml(String(row.published_at || ''))}" />
    <meta property="article:modified_time" content="${escapeHtml(String(row.updated_at || ''))}" />`;
      schemaObj = {
        '@context': 'https://schema.org',
        '@type': 'NewsArticle',
        headline: row.title,
        description: row.summary || pageDescription,
        image: [ogImage],
        datePublished: row.published_at,
        dateModified: row.updated_at || row.published_at,
        author: [{ '@type': 'Person', name: row.author_name || 'নিজস্ব প্রতিবেদক' }],
        publisher: {
          '@type': 'NewsMediaOrganization',
          name: fullSiteTitle,
          url: siteUrl,
          logo: { '@type': 'ImageObject', url: logoUrl },
        },
        mainEntityOfPage: { '@type': 'WebPage', '@id': canonicalUrl },
      };
    }
  } else if (categoryMatch) {
    const catSlug = decodeURIComponent(categoryMatch[1]);
    const cat = db.prepare('SELECT * FROM categories WHERE slug = ? AND is_active = 1').get(catSlug) as Record<string, unknown> | undefined;
    if (cat) {
      pageTitle = String(cat.seo_title || `${cat.name} | ${fullSiteTitle}`);
      pageDescription = String(cat.seo_description || cat.description || defaultDesc);
      ogImage = resolvePublicImageUrl(cat.image_url as string | undefined, siteUrl, '/og-cover.jpg');
      canonicalUrl = `${siteUrl}/category/${encodeURIComponent(String(cat.slug))}`;
    }
  }

  const safeTitle = escapeHtml(pageTitle);
  const safeDesc = escapeHtml(pageDescription);
  const safeImg = escapeHtml(ogImage);
  const safeLogo = escapeHtml(logoUrl);
  const safeUrl = escapeHtml(canonicalUrl);
  const safeSiteName = escapeHtml(fullSiteTitle);

  const ogTags = `
    <meta property="og:type" content="${ogType}" />
    <meta property="og:locale" content="bn_BD" />
    <meta property="og:site_name" content="${safeSiteName}" />
    <meta property="og:title" content="${safeTitle}" />
    <meta property="og:description" content="${safeDesc}" />
    <meta property="og:url" content="${safeUrl}" />
    <meta property="og:image" content="${safeImg}" />
    <meta property="og:image:secure_url" content="${safeImg}" />
    <meta property="og:image:type" content="image/jpeg" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta property="og:image:alt" content="${safeTitle}" />
    <meta property="og:logo" content="${safeLogo}" />${extraArticleTags}
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${safeTitle}" />
    <meta name="twitter:description" content="${safeDesc}" />
    <meta name="twitter:image" content="${safeImg}" />
    <link rel="canonical" href="${safeUrl}" />`;

  return html
    .replace(/<title>.*?<\/title>/i, `<title>${safeTitle}</title>`)
    .replace(/<meta\s+name="description"[\s\S]*?\/>/i, `<meta name="description" content="${safeDesc}" />`)
    .replace(/<!--OG_META_TAGS-->[\s\S]*?<!--END_OG_META_TAGS-->/, ogTags)
    .replace('<!--JSON_LD_SCHEMA-->', `<script type="application/ld+json">${JSON.stringify(schemaObj).replace(/</g, '\\u003c')}</script>`)
    .replace('<!--RUNTIME_CONFIG-->', runtimeScript);
}

async function startServer() {
  const isProd = process.env.NODE_ENV === 'production' && fs.existsSync(path.resolve(process.cwd(), 'dist', 'index.html'));

  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'custom',
    });
    app.use(vite.middlewares);

    app.use(async (req, res, next) => {
      if (req.method !== 'GET' || req.originalUrl.startsWith('/api')) return next();
      try {
        let template = fs.readFileSync(path.resolve(process.cwd(), 'index.html'), 'utf-8');
        template = await vite.transformIndexHtml(req.originalUrl, template);
        template = await injectPublicRuntimeAndOg(template, req);
        res
          .status(200)
          .set({
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': req.path.startsWith('/admin') ? 'no-store' : 'public, max-age=60, s-maxage=300',
          })
          .end(template);
      } catch (err) {
        next(err);
      }
    });
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir, { index: false, maxAge: '1d' }));
    app.use(async (req, res) => {
      if (req.method !== 'GET' || req.originalUrl.startsWith('/api')) {
        return res.status(404).json({ error: 'Not found' });
      }
      let html = fs.readFileSync(path.join(distDir, 'index.html'), 'utf-8');
      html = await injectPublicRuntimeAndOg(html, req);
      return res
        .status(200)
        .set({
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': req.path.startsWith('/admin') ? 'no-store' : 'public, max-age=60, s-maxage=300',
        })
        .end(html);
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Kushiara Express server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
