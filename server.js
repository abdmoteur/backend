const express = require('express');
const admin = require('firebase-admin');
const cloudinary = require('cloudinary').v2; // reads CLOUDINARY_URL automatically
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');

admin.initializeApp({ credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)) });
const db = admin.firestore();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 6 * 1024 * 1024 },
  fileFilter: (_, f, cb) => cb(null, /^image\/(jpeg|png|webp|gif)$/.test(f.mimetype)) });
const SECRET = process.env.TOKEN_SECRET || 'change-me';
const fs = require('fs');
const clean = (v, n) => String(v || '').trim().slice(0, n);
const FEES = { home: 600, desk: 400 }; // delivery fees in DA (edit here and in index.html)

const hmac = p => crypto.createHmac('sha256', SECRET).update(p).digest('hex');
const sign = () => { const p = String(Date.now() + 7 * 864e5); return p + '.' + hmac(p); };
const auth = (req, res, next) => {
  const [p, h] = (req.headers.authorization || '').replace('Bearer ', '').split('.');
  if (p && h && +p > Date.now() && h === hmac(p)) return next();
  res.status(401).json({ error: 'unauthorized' });
};
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'server' }); });

const app = express();
app.use(express.json({ limit: '100kb' }));
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Strict-Transport-Security': 'max-age=15552000',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https://res.cloudinary.com; connect-src 'self'; frame-ancestors 'none'"
  });
  next();
});
// Only index.html is public. server.js and package.json are NOT exposed.
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Each product has its own shareable link: /p/<id>  (with preview for Facebook / WhatsApp)
const INDEX = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const attr = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
app.get('/p/:id', async (req, res) => {
  let html = INDEX;
  try {
    const d = await db.collection('products').doc(req.params.id).get();
    if (d.exists) {
      const p = d.data(), url = `${req.protocol}://${req.get('host')}/p/${d.id}`;
      const desc = p.description || `${p.price} DA - ABDmoteur`, og = (p.images && p.images[0]) || p.image;
      html = html.replace('<title>ABDmoteur</title>', `<title>${attr(p.name)} | ABDmoteur</title>`).replace('<!--OG-->',
        `<meta property="og:type" content="product"><meta property="og:site_name" content="ABDmoteur"><meta property="og:title" content="${attr(p.name)}"><meta property="og:description" content="${attr(desc)}"><meta property="og:url" content="${attr(url)}">` +
        (og ? `<meta property="og:image" content="${attr(og)}"><meta name="twitter:card" content="summary_large_image">` : ''));
    }
  } catch (e) { console.error(e); }
  res.send(html);
});

const fails = new Map(); // simple brute-force protection: 5 wrong tries = 15 min block
app.post('/api/login', (req, res) => {
  const f = fails.get(req.ip) || { n: 0, t: Date.now() };
  if (Date.now() - f.t > 15 * 60e3) { f.n = 0; f.t = Date.now(); }
  if (f.n >= 5) return res.status(429).json({ error: 'too many attempts' });
  const a = Buffer.from(String(req.body.password || '')), b = Buffer.from(process.env.ADMIN_PASSWORD || '');
  if (b.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b)) { fails.delete(req.ip); return res.json({ token: sign() }); }
  f.n++; fails.set(req.ip, f);
  res.status(401).json({ error: 'bad password' });
});

app.get('/api/products', wrap(async (_, res) => {
  const s = await db.collection('products').orderBy('createdAt', 'desc').get();
  res.json(s.docs.map(d => ({ id: d.id, ...d.data() })));
}));

const uploadImg = buf => new Promise((ok, no) =>
  cloudinary.uploader.upload_stream({ folder: 'abdmoteur/products', transformation: [{ width: 1600, height: 1600, crop: 'limit', quality: 80 }] }, (e, r) => (e ? no(e) : ok(r.secure_url))).end(buf));
const parseCompat = raw => {
  let c = []; try { c = JSON.parse(raw || '[]'); } catch {}
  return (Array.isArray(c) ? c : []).slice(0, 40)
    .map(x => ({ brand: clean(x && x.brand, 30), model: clean(x && x.model, 40) })).filter(x => x.brand);
};

app.post('/api/products', auth, upload.array('images', 6), wrap(async (req, res) => {
  const { name, price, category, description } = req.body;
  if (!clean(name, 100) || !(+price > 0)) return res.status(400).json({ error: 'invalid' });
  const compat = parseCompat(req.body.compat), universal = req.body.universal === '1';
  if (!universal && !compat.length) return res.status(400).json({ error: 'compat required' });
  const images = await Promise.all((req.files || []).slice(0, 6).map(f => uploadImg(f.buffer))), image = images[0] || '';
  const doc = { name: clean(name, 100), price: +price, category: clean(category, 40), description: clean(description, 600),
    compat, universal, available: req.body.available !== '0', image, images, createdAt: Date.now() };
  const ref = await db.collection('products').add(doc);
  res.json({ id: ref.id, ...doc });
}));

// Edit a product (full edit from the form, or just {available:true/false} from the quick toggle)
app.patch('/api/products/:id', auth, upload.array('images', 6), wrap(async (req, res) => {
  const b = req.body, upd = {};
  if (b.name !== undefined) { if (!clean(b.name, 100)) return res.status(400).json({ error: 'invalid' }); upd.name = clean(b.name, 100); }
  if (b.price !== undefined) { if (!(+b.price > 0)) return res.status(400).json({ error: 'invalid' }); upd.price = +b.price; }
  if (b.category !== undefined) upd.category = clean(b.category, 40);
  if (b.description !== undefined) upd.description = clean(b.description, 600);
  if (b.available !== undefined) upd.available = b.available === true || b.available === '1' || b.available === 'true';
  if (b.compat !== undefined) {
    const compat = parseCompat(b.compat), universal = b.universal === '1';
    if (!universal && !compat.length) return res.status(400).json({ error: 'compat required' });
    upd.compat = compat; upd.universal = universal;
  }
  const ref = db.collection('products').doc(req.params.id);
  // Photos: 'keep' = existing photo URLs to keep (in order), new files are appended. Max 6 in total.
  if (b.keep !== undefined || (req.files && req.files.length)) {
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'not found' });
    const o = snap.data(), oldImgs = o.images && o.images.length ? o.images : (o.image ? [o.image] : []);
    let keep = oldImgs;
    if (b.keep !== undefined) {
      let k = []; try { k = JSON.parse(b.keep); } catch {}
      keep = [...new Set(Array.isArray(k) ? k : [])].filter(u => oldImgs.includes(u));
    }
    const files = (req.files || []).slice(0, Math.max(0, 6 - keep.length));
    const added = await Promise.all(files.map(f => uploadImg(f.buffer)));
    upd.images = [...keep, ...added]; upd.image = upd.images[0] || '';
  }
  if (!Object.keys(upd).length) return res.status(400).json({ error: 'invalid' });
  await ref.update(upd);
  res.json({ ok: true });
}));

app.delete('/api/products/:id', auth, wrap(async (req, res) => {
  await db.collection('products').doc(req.params.id).delete();
  res.json({ ok: true });
}));

app.post('/api/orders', wrap(async (req, res) => {
  const { name, phone, wilaya, address, delivery, items } = req.body;
  if (!name || !/^[0-9+\s]{9,15}$/.test(phone || '') || !wilaya || !FEES[delivery] || !Array.isArray(items) || !items.length)
    return res.status(400).json({ error: 'invalid' });
  const lines = []; let subtotal = 0;
  for (const it of items.slice(0, 50)) {
    const d = await db.collection('products').doc(String(it.id)).get();
    const qty = Math.min(Math.max(parseInt(it.qty) || 0, 1), 99);
    if (!d.exists) continue;
    const p = d.data();
    if (p.available === false) return res.status(400).json({ error: 'unavailable', name: p.name });
    subtotal += p.price * qty;
    lines.push({ id: d.id, name: p.name, price: p.price, qty });
  }
  if (!lines.length) return res.status(400).json({ error: 'empty' });
  const clean = (v, n) => String(v || '').trim().slice(0, n);
  const order = { name: clean(name, 80), phone: clean(phone, 15), wilaya: clean(wilaya, 40), address: clean(address, 160), delivery,
    items: lines, subtotal, fee: FEES[delivery], total: subtotal + FEES[delivery], status: 'pending', reviewed: false, createdAt: Date.now() };
  const ref = await db.collection('orders').add(order);
  res.json({ id: ref.id });
}));

app.get('/api/orders', auth, wrap(async (_, res) => {
  const s = await db.collection('orders').orderBy('createdAt', 'desc').limit(500).get();
  res.json(s.docs.map(d => ({ id: d.id, ...d.data() })));
}));

app.patch('/api/orders/:id', auth, wrap(async (req, res) => {
  const upd = {};
  if (req.body.status !== undefined) {
    if (!['pending', 'shipped', 'delivered', 'cancelled'].includes(req.body.status)) return res.status(400).json({ error: 'invalid' });
    upd.status = req.body.status;
  }
  if (req.body.reviewed !== undefined) upd.reviewed = req.body.reviewed === true;
  if (!Object.keys(upd).length) return res.status(400).json({ error: 'invalid' });
  await db.collection('orders').doc(req.params.id).update(upd);
  res.json({ ok: true });
}));

app.post('/api/visit', wrap(async (_, res) => {
  const day = new Date().toISOString().slice(0, 10);
  await db.collection('visits').doc(day).set({ count: admin.firestore.FieldValue.increment(1) }, { merge: true });
  res.json({ ok: true });
}));

app.get('/api/stats', auth, wrap(async (_, res) => {
  const [os, vs, ps] = await Promise.all([db.collection('orders').get(), db.collection('visits').get(), db.collection('products').get()]);
  let outofstock = 0; ps.forEach(d => { if (d.data().available === false) outofstock++; });
  const st = { outofstock, orders: 0, revenue: 0, pending: 0, delivered: 0, cancelled: 0, shipped: 0, products: ps.size, visits: 0,
    byDay: {}, byWilaya: {}, top: {}, visitsByDay: {} };
  os.forEach(d => {
    const o = d.data(); st.orders++; st[o.status] = (st[o.status] || 0) + 1;
    if (!o.reviewed && o.status !== 'cancelled') st.unreviewed = (st.unreviewed || 0) + 1;
    if (o.status !== 'cancelled') {
      st.revenue += o.total;
      const day = new Date(o.createdAt).toISOString().slice(0, 10);
      st.byDay[day] = (st.byDay[day] || 0) + o.total;
      st.byWilaya[o.wilaya] = (st.byWilaya[o.wilaya] || 0) + 1;
      o.items.forEach(i => (st.top[i.name] = (st.top[i.name] || 0) + i.qty));
    }
  });
  vs.forEach(d => { st.visits += d.data().count; st.visitsByDay[d.id] = d.data().count; });
  const top = o => Object.fromEntries(Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 8));
  const last = o => Object.fromEntries(Object.entries(o).sort().slice(-14));
  res.json({ ...st, top: top(st.top), byWilaya: top(st.byWilaya), byDay: last(st.byDay), visitsByDay: last(st.visitsByDay) });
}));

// Upload errors (too many files, file too big...) -> clean JSON instead of a crash page
app.use((err, req, res, next) => { console.error(err.message); res.status(400).json({ error: 'upload' }); });

app.listen(process.env.PORT || 3000, () => console.log('ABDmoteur running'));
