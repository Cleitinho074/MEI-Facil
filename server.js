// ═══════════════════════════════════════════════════════════════
// MEI Fácil — Backend Completo (Pronto para Railway)
// ═══════════════════════════════════════════════════════════════

require('dotenv').config();
const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const { Pool }  = require('pg');
const path      = require('path');

const app = express();

// Configuração do banco de dados (A Railway injeta a DATABASE_URL automaticamente)
const db = new Pool({ 
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway') 
       ? false // Railway em rede interna geralmente não exige SSL estrito
       : (process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false) 
});

// ── Inicialização do Banco de Dados (Auto-Migration) ───────────
const initDB = async () => {
  if (!process.env.DATABASE_URL) {
    console.log("⚠️ DATABASE_URL não configurada. Pulei a criação das tabelas.");
    return;
  }
  const client = await db.connect();
  try {
    console.log("⏳ Verificando e criando tabelas no banco de dados...");
    await client.query(`
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        cpf_cnpj VARCHAR(50),
        razao_social VARCHAR(255),
        store_name VARCHAR(150),
        updated_at TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS clients (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(50),
        phone VARCHAR(50),
        email VARCHAR(255),
        city VARCHAR(255),
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS products (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(50) DEFAULT 'service',
        unit VARCHAR(20) DEFAULT 'un',
        cost DECIMAL(10,2) DEFAULT 0,
        margin_pct DECIMAL(10,2) DEFAULT 100,
        price DECIMAL(10,2) NOT NULL,
        stock INT,
        active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS sales (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        client_id UUID REFERENCES clients(id) ON DELETE SET NULL,
        client_name VARCHAR(255),
        total DECIMAL(10,2) DEFAULT 0,
        profit DECIMAL(10,2) DEFAULT 0,
        status VARCHAR(50) DEFAULT 'pending',
        pay_method VARCHAR(50) DEFAULT 'dinheiro',
        fee_pct DECIMAL(10,2) DEFAULT 0,
        fee_value DECIMAL(10,2) DEFAULT 0,
        net_total DECIMAL(10,2) DEFAULT 0,
        notes TEXT,
        sale_date DATE,
        sale_time VARCHAR(5),
        paid_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS sale_items (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        sale_id UUID REFERENCES sales(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        product_id UUID REFERENCES products(id) ON DELETE SET NULL,
        product_name VARCHAR(255),
        qty INT NOT NULL,
        unit_price DECIMAL(10,2) NOT NULL,
        cost DECIMAL(10,2) DEFAULT 0,
        subtotal DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS cashflow_entries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        sale_id UUID REFERENCES sales(id) ON DELETE CASCADE,
        description VARCHAR(255) NOT NULL,
        type VARCHAR(10) NOT NULL,
        value DECIMAL(10,2) NOT NULL,
        category VARCHAR(100),
        entry_date DATE,
        edit_history JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS revenue_audit (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        before_val DECIMAL(10,2),
        after_val DECIMAL(10,2) NOT NULL,
        reason TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    // Migrações seguras para bancos já existentes
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS store_name VARCHAR(150);`);
    await client.query(`ALTER TABLE sales ADD COLUMN IF NOT EXISTS sale_time VARCHAR(5);`);
    console.log("✅ Banco de dados inicializado e pronto para uso!");
  } catch (err) {
    console.error("❌ Erro ao criar as tabelas:", err);
  } finally {
    client.release();
  }
};
initDB();

// ── Middleware ─────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
    },
  },
}));
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json({ limit: '10kb' }));
app.use('/api/auth', rateLimit({ windowMs: 15*60*1000, max: 20, message: { error:'Muitas tentativas. Aguarde.' }}));
app.use('/api',      rateLimit({ windowMs: 15*60*1000, max: 300 }));
app.use(express.static(path.join(__dirname)));

// ── Auth Middleware ─────────────────────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  try {
    req.userId = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret-change-me').id;
    next();
  } catch { res.status(401).json({ error: 'Token inválido' }); }
};

const signToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET || 'dev-secret-change-me', { expiresIn: '7d' });

// ── Helper ──────────────────────────────────────────────────────
const Q = (text, params) => db.query(text, params);

// ══════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, cpf_cnpj } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Campos obrigatórios: name, email, password' });
    if (password.length < 8) return res.status(400).json({ error: 'Senha deve ter no mínimo 8 caracteres' });

    const exists = await Q('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (exists.rows.length) return res.status(409).json({ error: 'E-mail já cadastrado' });

    const hash = await bcrypt.hash(password, 12);
    const { rows } = await Q(
      `INSERT INTO users(name,email,password_hash,cpf_cnpj) VALUES($1,$2,$3,$4) RETURNING id,name,email,cpf_cnpj,razao_social`,
      [name, email.toLowerCase(), hash, cpf_cnpj]
    );
    res.status(201).json({ token: signToken(rows[0].id), user: rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao criar conta' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'E-mail e senha são obrigatórios' });
    const { rows } = await Q('SELECT * FROM users WHERE email=$1', [email?.toLowerCase()]);
    if (!rows.length || !await bcrypt.compare(password, rows[0].password_hash))
      return res.status(401).json({ error: 'E-mail ou senha incorretos' });
    const { password_hash, ...user } = rows[0];
    res.json({ token: signToken(user.id), user });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro no login' }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const { rows } = await Q('SELECT id, name, email, cpf_cnpj, razao_social, store_name FROM users WHERE id=$1', [req.userId]);
    if (!rows.length) return res.status(404).json({ error: 'Usuário não encontrado' });
    res.json({ user: rows[0] });
  } catch (e) { res.status(500).json({ error: 'Erro ao buscar usuário' }); }
});

app.patch('/api/auth/password', auth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) return res.status(400).json({ error: 'Informe a senha atual e a nova senha' });
    if (new_password.length < 8) return res.status(400).json({ error: 'A nova senha deve ter no mínimo 8 caracteres' });

    const { rows } = await Q('SELECT password_hash FROM users WHERE id=$1', [req.userId]);
    if (!rows.length) return res.status(404).json({ error: 'Usuário não encontrado' });

    const ok = await bcrypt.compare(current_password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Senha atual incorreta' });

    const newHash = await bcrypt.hash(new_password, 12);
    await Q('UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2', [newHash, req.userId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Erro ao alterar senha' }); }
});

app.put('/api/auth/profile', auth, async (req, res) => {
  try {
    const { name, cpf_cnpj, razao_social, store_name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Nome é obrigatório' });
    const { rows } = await Q(
      `UPDATE users SET name=$1, cpf_cnpj=$2, razao_social=$3, store_name=$4, updated_at=NOW() WHERE id=$5 RETURNING id, name, email, cpf_cnpj, razao_social, store_name`,
      [name.trim(), cpf_cnpj || null, razao_social || null, store_name || null, req.userId]
    );
    res.json({ user: rows[0] });
  } catch (e) { res.status(500).json({ error: 'Erro ao atualizar perfil' }); }
});

// ══════════════════════════════════════════════════════════════
// CLIENTS, PRODUCTS, SALES, CASHFLOW (Restante das Rotas Iguais)
// ══════════════════════════════════════════════════════════════
app.get('/api/clients', auth, async (req, res) => {
  const { rows } = await Q('SELECT * FROM clients WHERE user_id=$1 ORDER BY name', [req.userId]);
  res.json(rows);
});
app.post('/api/clients', auth, async (req, res) => {
  const { name, cpf, phone, email, city, notes } = req.body;
  const { rows } = await Q('INSERT INTO clients(user_id,name,cpf,phone,email,city,notes) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *', [req.userId, name, cpf, phone, email, city, notes]);
  res.status(201).json(rows[0]);
});
app.put('/api/clients/:id', auth, async (req, res) => {
  const { name, cpf, phone, email, city, notes } = req.body;
  const { rows } = await Q('UPDATE clients SET name=$1,cpf=$2,phone=$3,email=$4,city=$5,notes=$6 WHERE id=$7 AND user_id=$8 RETURNING *', [name, cpf, phone, email, city, notes, req.params.id, req.userId]);
  rows.length ? res.json(rows[0]) : res.status(404).json({ error: 'Não encontrado' });
});
app.delete('/api/clients/:id', auth, async (req, res) => {
  await Q('DELETE FROM clients WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
  res.status(204).end();
});

app.get('/api/products', auth, async (req, res) => {
  const { rows } = await Q('SELECT * FROM products WHERE user_id=$1 AND active=true ORDER BY name', [req.userId]);
  res.json(rows);
});
app.post('/api/products', auth, async (req, res) => {
  const { name, type='service', unit='un', cost=0, margin_pct=100, price, stock } = req.body;
  const stockVal = type === 'product' ? (stock ?? 0) : null;
  const { rows } = await Q('INSERT INTO products(user_id,name,type,unit,cost,margin_pct,price,stock) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *', [req.userId, name, type, unit, cost, margin_pct, price, stockVal]);
  res.status(201).json(rows[0]);
});
app.put('/api/products/:id', auth, async (req, res) => {
  const { name, type, unit, cost, margin_pct, price, stock } = req.body;
  const stockVal = type === 'product' ? (stock ?? 0) : null;
  const { rows } = await Q('UPDATE products SET name=$1,type=$2,unit=$3,cost=$4,margin_pct=$5,price=$6,stock=$7 WHERE id=$8 AND user_id=$9 RETURNING *', [name, type, unit, cost, margin_pct, price, stockVal, req.params.id, req.userId]);
  rows.length ? res.json(rows[0]) : res.status(404).json({ error: 'Não encontrado' });
});
app.delete('/api/products/:id', auth, async (req, res) => {
  await Q('UPDATE products SET active=false WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
  res.status(204).end();
});
app.patch('/api/products/:id/stock', auth, async (req, res) => {
  const { mode, value } = req.body;
  const num = parseInt(value);
  let sql = mode === 'set' ? 'UPDATE products SET stock=$1 WHERE id=$2 AND user_id=$3 RETURNING *' : mode === 'in' ? 'UPDATE products SET stock=COALESCE(stock,0)+$1 WHERE id=$2 AND user_id=$3 RETURNING *' : 'UPDATE products SET stock=GREATEST(0,COALESCE(stock,0)-$1) WHERE id=$2 AND user_id=$3 RETURNING *';
  const { rows } = await Q(sql, [num, req.params.id, req.userId]);
  rows.length ? res.json(rows[0]) : res.status(404).json({ error: 'Não encontrado' });
});

app.get('/api/sales', auth, async (req, res) => {
  const { rows: sales } = await Q('SELECT * FROM sales WHERE user_id=$1 ORDER BY sale_date DESC, created_at DESC', [req.userId]);
  if (!sales.length) return res.json([]);
  const ids = sales.map(s => s.id);
  const { rows: items } = await Q(`SELECT * FROM sale_items WHERE sale_id = ANY($1::uuid[]) ORDER BY id`, [ids]);
  const itemsBySale = {};
  items.forEach(i => { (itemsBySale[i.sale_id] ||= []).push(i); });
  res.json(sales.map(s => ({ ...s, items: itemsBySale[s.id] || [] })));
});
app.get('/api/sales/:id', auth, async (req, res) => {
  const { rows } = await Q('SELECT * FROM sales WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
  if (!rows.length) return res.status(404).json({ error: 'Venda não encontrada' });
  const { rows: items } = await Q('SELECT * FROM sale_items WHERE sale_id=$1 ORDER BY id', [req.params.id]);
  res.json({ ...rows[0], items });
});
app.post('/api/sales', auth, async (req, res) => {
  const { client_id, client_name, items, pay_method = 'dinheiro', fee_pct = 0, status = 'pending', notes, sale_date, sale_time } = req.body;
  const total = items.reduce((a, i) => a + i.qty * i.unit_price, 0);
  const profit = items.reduce((a, i) => a + (i.qty * i.unit_price - i.qty * (i.cost || 0)), 0);
  const feeValue = +(total * (fee_pct || 0) / 100).toFixed(2);
  const netTotal = +(total - feeValue).toFixed(2);
  const date = sale_date || new Date().toISOString().slice(0, 10);
  const time = (typeof sale_time === 'string' && /^\d{2}:\d{2}$/.test(sale_time)) ? sale_time : new Date().toTimeString().slice(0, 5);
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const { rows: saleRows } = await client.query(
      `INSERT INTO sales(user_id,client_id,client_name,total,profit,status,pay_method,fee_pct,fee_value,net_total,notes,sale_date,sale_time,paid_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [req.userId, client_id || null, client_name || null, total, profit, status, pay_method, fee_pct, feeValue, netTotal, notes || null, date, time, status === 'paid' ? new Date() : null]
    );
    const sale = saleRows[0];
    for (const it of items) {
      await client.query(
        `INSERT INTO sale_items(sale_id,user_id,product_id,product_name,qty,unit_price,cost,subtotal) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
        [sale.id, req.userId, it.product_id || null, it.product_name || null, it.qty, it.unit_price, it.cost || 0, +(it.qty * it.unit_price).toFixed(2)]
      );
      if (it.product_id) await client.query(`UPDATE products SET stock = GREATEST(0, COALESCE(stock,0) - $1) WHERE id=$2 AND user_id=$3 AND type='product' AND stock IS NOT NULL`, [it.qty, it.product_id, req.userId]);
    }
    if (status === 'paid') await client.query(`INSERT INTO cashflow_entries(user_id,description,type,value,entry_date,sale_id) VALUES($1,$2,'in',$3,$4,$5)`, [req.userId, `Venda — ${items.map(i => `${i.qty}x ${i.product_name}`).join(', ')}`, netTotal, date, sale.id]);
    await client.query('COMMIT');
    res.status(201).json(sale);
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Erro ao registrar venda' });
  } finally { client.release(); }
});
app.patch('/api/sales/:id/status', auth, async (req, res) => {
  const { status } = req.body;
  const { rows } = await Q(`UPDATE sales SET status=$1, paid_at=$2 WHERE id=$3 AND user_id=$4 RETURNING *`, [status, status === 'paid' ? new Date() : null, req.params.id, req.userId]);
  if (!rows.length) return res.status(404).json({ error: 'Venda não encontrada' });
  if (status === 'paid') {
    const { rows: items } = await Q('SELECT * FROM sale_items WHERE sale_id=$1', [rows[0].id]);
    await Q(`INSERT INTO cashflow_entries(user_id,description,type,value,entry_date,sale_id) VALUES($1,$2,'in',$3,CURRENT_DATE,$4)`, [req.userId, `Venda — ${items.map(i => `${i.qty}x ${i.product_name}`).join(', ')}`, rows[0].net_total, rows[0].id]);
  }
  res.json(rows[0]);
});
app.delete('/api/sales/:id', auth, async (req, res) => {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM cashflow_entries WHERE sale_id=$1 AND user_id=$2', [req.params.id, req.userId]);
    await client.query('DELETE FROM sale_items WHERE sale_id=$1 AND user_id=$2', [req.params.id, req.userId]);
    await client.query('DELETE FROM sales WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
    await client.query('COMMIT');
    res.status(204).end();
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Erro ao remover' });
  } finally { client.release(); }
});

app.get('/api/cashflow', auth, async (req, res) => {
  const { rows } = await Q('SELECT * FROM cashflow_entries WHERE user_id=$1 ORDER BY entry_date DESC, created_at DESC LIMIT 200', [req.userId]);
  res.json(rows);
});
app.post('/api/cashflow', auth, async (req, res) => {
  const { description, type, value, category, entry_date } = req.body;
  const { rows } = await Q('INSERT INTO cashflow_entries(user_id,description,type,value,category,entry_date) VALUES($1,$2,$3,$4,$5,$6) RETURNING *', [req.userId, description, type, value, category, entry_date||new Date()]);
  res.status(201).json(rows[0]);
});
app.delete('/api/cashflow/:id', auth, async (req, res) => {
  await Q('DELETE FROM cashflow_entries WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
  res.status(204).end();
});
app.patch('/api/cashflow/:id', auth, async (req, res) => {
  const { value, description, reason, user_name } = req.body;
  const { rows: existing } = await Q('SELECT * FROM cashflow_entries WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
  if (!existing.length) return res.status(404).json({ error: 'Não encontrado' });
  const entry = existing[0];
  const historyEntry = { ts: new Date().toISOString(), before: entry.value, after: value || entry.value, desc_before: entry.description, reason: reason.trim(), user: user_name || null };
  const { rows } = await Q('UPDATE cashflow_entries SET value=$1, description=$2, edit_history=$3 WHERE id=$4 AND user_id=$5 RETURNING *', [value || entry.value, description || entry.description, JSON.stringify([...(entry.edit_history || []), historyEntry]), req.params.id, req.userId]);
  res.json(rows[0]);
});

app.get('/api/revenue-audit', auth, async (req, res) => {
  const { rows } = await Q('SELECT * FROM revenue_audit WHERE user_id=$1 ORDER BY created_at ASC', [req.userId]);
  res.json(rows);
});
app.post('/api/revenue-audit', auth, async (req, res) => {
  const { before_val, after_val, reason } = req.body;
  const { rows } = await Q('INSERT INTO revenue_audit(user_id,before_val,after_val,reason) VALUES($1,$2,$3,$4) RETURNING *', [req.userId, before_val ?? null, after_val, reason.trim()]);
  res.status(201).json(rows[0]);
});

app.get('/api/reports/dashboard', auth, async (req, res) => {
  const [rev, exp, salesCount, yearRev, auditAdj] = await Promise.all([
    Q(`SELECT COALESCE(SUM(value),0) total FROM cashflow_entries WHERE user_id=$1 AND type='in' AND DATE_TRUNC('month',entry_date)=DATE_TRUNC('month',NOW())`, [req.userId]),
    Q(`SELECT COALESCE(SUM(value),0) total FROM cashflow_entries WHERE user_id=$1 AND type='out' AND DATE_TRUNC('month',entry_date)=DATE_TRUNC('month',NOW())`, [req.userId]),
    Q(`SELECT COUNT(*) count FROM sales WHERE user_id=$1 AND status='paid' AND DATE_TRUNC('month',sale_date)=DATE_TRUNC('month',NOW())`, [req.userId]),
    Q(`SELECT COALESCE(SUM(total),0) total FROM sales WHERE user_id=$1 AND status='paid' AND EXTRACT(YEAR FROM sale_date)=EXTRACT(YEAR FROM NOW())`, [req.userId]),
    Q(`SELECT COALESCE(SUM(after_val - COALESCE(before_val,0)),0) total FROM revenue_audit WHERE user_id=$1 AND EXTRACT(YEAR FROM created_at)=EXTRACT(YEAR FROM NOW())`, [req.userId]),
  ]);
  const MEI_LIMIT = 81000;
  const yr = +yearRev.rows[0].total + +auditAdj.rows[0].total;
  res.json({
    month_revenue: +rev.rows[0].total, month_expenses: +exp.rows[0].total, month_profit: +rev.rows[0].total - +exp.rows[0].total,
    sales_count: +salesCount.rows[0].count, year_revenue: yr, mei_limit: MEI_LIMIT,
    mei_pct: +(yr / MEI_LIMIT * 100).toFixed(2), mei_remaining: +(MEI_LIMIT - yr).toFixed(2)
  });
});

app.get('/api/reports/annual', auth, async (req, res) => {
  const year = req.query.year || new Date().getFullYear();
  const { rows } = await Q(`SELECT TO_CHAR(DATE_TRUNC('month',entry_date),'YYYY-MM') AS month, SUM(CASE WHEN type='in' THEN value ELSE 0 END) AS total_in, SUM(CASE WHEN type='out' THEN value ELSE 0 END) AS total_out FROM cashflow_entries WHERE user_id=$1 AND EXTRACT(YEAR FROM entry_date)=$2 GROUP BY 1 ORDER BY 1`, [req.userId, year]);
  res.json(rows);
});

// ── Health & Fallback ──────────────────────────────────────────
app.get('/api/health', (_, res) => res.json({ status:'ok', ts: new Date().toISOString() }));
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Erro interno no servidor' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`\n🏪 MEI Fácil rodando na porta ${PORT}\n`));
