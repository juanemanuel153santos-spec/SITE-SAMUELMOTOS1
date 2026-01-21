import express from 'express';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'samuelpanel';
const JWT_SECRET = process.env.JWT_SECRET || 'samueljwtsecret';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_HASH || bcrypt.hashSync('admin123', 10);
const DB_PATH = path.join(__dirname, 'data.db');

app.use(cors());
app.use(express.json());

let db;

async function initDb() {
  const exists = fs.existsSync(DB_PATH);
  db = await open({ filename: DB_PATH, driver: sqlite3.Database });
  await db.exec(`CREATE TABLE IF NOT EXISTS produtos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    categoria TEXT,
    preco REAL NOT NULL DEFAULT 0,
    estoque INTEGER NOT NULL DEFAULT 0,
    promo INTEGER NOT NULL DEFAULT 0,
    destaque INTEGER NOT NULL DEFAULT 0,
    imagem TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );`);

  await seedFromHtmlIfEmpty();
}

// Converte os cards estáticos de produtos do index.html para o banco SQLite (rodado apenas se estiver vazio)
async function seedFromHtmlIfEmpty() {
  const count = await db.get('SELECT COUNT(*) as c FROM produtos');
  if (count?.c > 1) return; // já populado

  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  const sectionRegex = /<section[^>]*id="([^"]+)"[^>]*>[\s\S]*?<h2[^>]*>([^<]+)<\/h2>[\s\S]*?<div class="produtos">([\s\S]*?)<\/div>\s*<\/section>/gi;
  const productRegex = /<div class="produto"[^>]*data-descricao="([^"]*)"[^>]*>[\s\S]*?<img[^>]*src="([^"]+)"[^>]*>[\s\S]*?<h3>([^<]+)<\/h3>[\s\S]*?<p[^>]*>([^<]+)<\/p>/gi;

  const items = [];

  let sectionMatch;
  while ((sectionMatch = sectionRegex.exec(html))) {
    const categoria = sectionMatch[2].trim();
    const produtosHtml = sectionMatch[3];

    let prodMatch;
    while ((prodMatch = productRegex.exec(produtosHtml))) {
      const descricao = prodMatch[1].trim();
      const imagem = prodMatch[2].trim();
      const nome = prodMatch[3].trim();
      const precoTexto = prodMatch[4].trim();
      const normalizado = precoTexto.replace(/[^0-9.,-]/g, '').replace(/\./g, '').replace(',', '.');
      const preco = parseFloat(normalizado) || 0;

      items.push({ nome, categoria, preco, estoque: 0, promo: 0, destaque: 0, imagem, descricao });
    }
  }

  if (!items.length) return;

  await db.run('DELETE FROM produtos');
  const stmt = await db.prepare('INSERT INTO produtos (nome, categoria, preco, estoque, promo, destaque, imagem) VALUES (?,?,?,?,?,?,?)');
  for (const p of items) {
    await stmt.run(p.nome, p.categoria, p.preco, p.estoque, p.promo, p.destaque, p.imagem);
  }
  await stmt.finalize();

  console.log(`Seeded ${items.length} produtos a partir do index.html`);
}

function requireToken(req, res, next) {
  const q = req.query.admin || req.headers['x-admin-token'];
  if (q === ADMIN_TOKEN || req.path.startsWith('/admin')) return next();
  return res.status(404).json({ error: 'Not found' });
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const [, token] = auth.split(' ');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/api/login', requireToken, (req, res) => {
  const { senha } = req.body || {};
  if (!senha) return res.status(400).json({ error: 'Senha obrigatória' });
  const ok = bcrypt.compareSync(senha, ADMIN_PASSWORD_HASH);
  if (!ok) return res.status(401).json({ error: 'Senha incorreta' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
  return res.json({ token });
});

app.get('/api/produtos', requireToken, requireAuth, async (req, res) => {
  const rows = await db.all('SELECT * FROM produtos ORDER BY id DESC');
  res.json(rows);
});

app.post('/api/produtos', requireToken, requireAuth, async (req, res) => {
  const { nome, categoria, preco, estoque = 0, promo = 0, destaque = 0, imagem = '' } = req.body || {};
  if (!nome || preco === undefined) return res.status(400).json({ error: 'Nome e preço são obrigatórios' });
  const result = await db.run(
    'INSERT INTO produtos (nome, categoria, preco, estoque, promo, destaque, imagem) VALUES (?,?,?,?,?,?,?)',
    nome, categoria || '', Number(preco) || 0, Number(estoque) || 0, Number(promo) || 0, destaque ? 1 : 0, imagem
  );
  const row = await db.get('SELECT * FROM produtos WHERE id = ?', result.lastID);
  res.status(201).json(row);
});

app.put('/api/produtos/:id', requireToken, requireAuth, async (req, res) => {
  const { id } = req.params;
  const existing = await db.get('SELECT * FROM produtos WHERE id = ?', id);
  if (!existing) return res.status(404).json({ error: 'Não encontrado' });
  const { nome, categoria, preco, estoque, promo, destaque, imagem } = req.body || {};
  await db.run(
    'UPDATE produtos SET nome=?, categoria=?, preco=?, estoque=?, promo=?, destaque=?, imagem=? WHERE id=?',
    nome ?? existing.nome,
    categoria ?? existing.categoria,
    preco !== undefined ? Number(preco) : existing.preco,
    estoque !== undefined ? Number(estoque) : existing.estoque,
    promo !== undefined ? Number(promo) : existing.promo,
    destaque !== undefined ? (destaque ? 1 : 0) : existing.destaque,
    imagem ?? existing.imagem,
    id
  );
  const updated = await db.get('SELECT * FROM produtos WHERE id = ?', id);
  res.json(updated);
});

app.delete('/api/produtos/:id', requireToken, requireAuth, async (req, res) => {
  const { id } = req.params;
  await db.run('DELETE FROM produtos WHERE id = ?', id);
  res.json({ ok: true });
});

app.get('/api/stats', requireToken, requireAuth, async (req, res) => {
  const total = await db.get('SELECT COUNT(*) as c FROM produtos');
  const valor = await db.get('SELECT SUM(preco * estoque) as v FROM produtos');
  const media = await db.get('SELECT AVG(preco) as m FROM produtos');
  const promos = await db.get('SELECT COUNT(*) as p FROM produtos WHERE promo > 0');
  res.json({
    total: total?.c || 0,
    valorEstoque: valor?.v || 0,
    precoMedio: media?.m || 0,
    promosAtivas: promos?.p || 0
  });
});

// Admin page
app.get('/admin', (req, res) => {
  return res.sendFile(path.join(__dirname, 'admin', 'admin.html'));
});

// Admin static assets (CSS, JS)
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// Public site
app.use(express.static(__dirname));

app.use((req, res) => res.status(404).send('Not found'));

initDb().then(() => {
  app.listen(PORT, () => console.log(`Servidor rodando em http://localhost:${PORT}`));
});
