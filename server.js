// ═══════════════════════════════════════════════════════════════
// MEI Fácil — Backend Completo (arquivo único para início rápido)
// Execute: node server.js
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
const db  = new Pool({ connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });

// ── Middleware ─────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));
app.options('*', cors()); // preflight
app.use(express.json({ limit: '10kb' }));
app.use('/api/auth', rateLimit({ windowMs: 15*60*1000, max: 20, message: { error:'Muitas tentativas. Aguarde.' }}));
app.use('/api',      rateLimit({ windowMs: 15*60*1000, max: 300 }));
app.use(express.static(path.join(__dirname, '.')));

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

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, cpf_cnpj } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Campos obrigatórios: name, email, password' });
    if (password.length < 8) return res.status(400).json({ error: 'Senha deve ter no mínimo 8 caracteres' });

    const exists = await Q('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (exists.rows.length) return res.status(409).json({ error: 'E-mail já cadastrado' });

    const hash = await bcrypt.hash(password, 12);
    const { rows } = await Q(
      `INSERT INTO users(name,email,password_hash,cpf_cnpj) VALUES($1,$2,$3,$4) RETURNING id,name,email`,
      [name, email.toLowerCase(), hash, cpf_cnpj]
    );
    res.status(201).json({ token: signToken(rows[0].id), user: rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao criar conta' }); }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'E-mail e senha são obrigatórios' });
    const { rows } = await Q('SELECT * FROM users WHERE email=$1', [email?.toLowerCase()]);
    if (!rows.length || !await bcrypt.compare(password, rows[0].password_hash))
      return res.status(401).json({ error: 'E-mail ou senha incorretos' });
    const { password_hash, ...user } = rows[0];
    res.json({ token: signToken(user.id), user });
  } catch (e) { res.status(500).json({ error: 'Erro no login' }); }
});

// GET /api/auth/me — valida token e retorna dados do usuário
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const { rows } = await Q(
      'SELECT id, name, email, cpf_cnpj, razao_social FROM users WHERE id=$1',
      [req.userId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Usuário não encontrado' });
    res.json({ user: rows[0] });
  } catch (e) { res.status(500).json({ error: 'Erro ao buscar usuário' }); }
});

// ══════════════════════════════════════════════════════════════
// CLIENTS
// ══════════════════════════════════════════════════════════════
app.get   ('/api/clients',     auth, async (req, res) => {
  const { rows } = await Q('SELECT * FROM clients WHERE user_id=$1 ORDER BY name', [req.userId]);
  res.json(rows);
});
app.post  ('/api/clients',     auth, async (req, res) => {
  const { name, cpf, phone, email, city, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'Nome é obrigatório' });
  const { rows } = await Q(
    'INSERT INTO clients(user_id,name,cpf,phone,email,city,notes) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [req.userId, name, cpf, phone, email, city, notes]
  );
  res.status(201).json(rows[0]);
});
app.put   ('/api/clients/:id', auth, async (req, res) => {
  const { name, cpf, phone, email, city, notes } = req.body;
  const { rows } = await Q(
    'UPDATE clients SET name=$1,cpf=$2,phone=$3,email=$4,city=$5,notes=$6 WHERE id=$7 AND user_id=$8 RETURNING *',
    [name, cpf, phone, email, city, notes, req.params.id, req.userId]
  );
  rows.length ? res.json(rows[0]) : res.status(404).json({ error: 'Não encontrado' });
});
app.delete('/api/clients/:id', auth, async (req, res) => {
  await Q('DELETE FROM clients WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
  res.status(204).end();
});

// ══════════════════════════════════════════════════════════════
// PRODUCTS
// ══════════════════════════════════════════════════════════════
app.get   ('/api/products',     auth, async (req, res) => {
  const { rows } = await Q('SELECT * FROM products WHERE user_id=$1 AND active=true ORDER BY name', [req.userId]);
  res.json(rows);
});
app.post  ('/api/products',     auth, async (req, res) => {
  const { name, type='service', unit='un', cost=0, margin_pct=100, price } = req.body;
  if (!name || !price) return res.status(400).json({ error: 'Nome e preço são obrigatórios' });
  const { rows } = await Q(
    'INSERT INTO products(user_id,name,type,unit,cost,margin_pct,price) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [req.userId, name, type, unit, cost, margin_pct, price]
  );
  res.status(201).json(rows[0]);
});
app.put   ('/api/products/:id', auth, async (req, res) => {
  const { name, type, unit, cost, margin_pct, price, stock } = req.body;
  const { rows } = await Q(
    'UPDATE products SET name=$1,type=$2,unit=$3,cost=$4,margin_pct=$5,price=$6,stock=$7 WHERE id=$8 AND user_id=$9 RETURNING *',
    [name, type, unit, cost, margin_pct, price, stock, req.params.id, req.userId]
  );
  rows.length ? res.json(rows[0]) : res.status(404).json({ error: 'Não encontrado' });
});
app.delete('/api/products/:id', auth, async (req, res) => {
  await Q('UPDATE products SET active=false WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
  res.status(204).end();
});

// ══════════════════════════════════════════════════════════════
// SALES
// ══════════════════════════════════════════════════════════════
app.get('/api/sales', auth, async (req, res) => {
  const { status, from, to, limit=100 } = req.query;
  let sql = 'SELECT * FROM sales WHERE user_id=$1';
  const params = [req.userId];
  if (status) { params.push(status); sql += ` AND status=$${params.length}`; }
  if (from)   { params.push(from);   sql += ` AND sale_date>=$${params.length}`; }
  if (to)     { params.push(to);     sql += ` AND sale_date<=$${params.length}`; }
  sql += ` ORDER BY sale_date DESC, created_at DESC LIMIT $${params.length+1}`;
  params.push(limit);
  const { rows } = await Q(sql, params);
  // Attach items to each sale
  for (const sale of rows) {
    const items = await Q('SELECT * FROM sale_items WHERE sale_id=$1', [sale.id]);
    sale.items = items.rows.map(i => ({
      productId: i.product_id, name: i.product_name,
      qty: i.qty, unitPrice: parseFloat(i.unit_price),
      cost: parseFloat(i.cost), subtotal: parseFloat(i.subtotal)
    }));
  }
  res.json(rows);
});

app.post('/api/sales', auth, async (req, res) => {
  const { client_id, client_name, items=[], total, profit=0, status='pending',
          pay_method='dinheiro', fee_pct=0, fee_value=0, net_total, sale_date, notes } = req.body;
  if (!items.length) return res.status(400).json({ error: 'Adicione pelo menos um item' });
  // Use sale_date as plain string (YYYY-MM-DD), fallback to today
  const saleDate = sale_date
    ? String(sale_date).substring(0, 10)
    : new Date().toISOString().substring(0, 10);
  try {
    const { rows } = await Q(
      `INSERT INTO sales(user_id,client_id,client_name,total,profit,status,pay_method,fee_pct,fee_value,net_total,sale_date,paid_at,notes)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [req.userId, client_id||null, client_name||'Cliente avulso', total, profit, status,
       pay_method, fee_pct, fee_value, net_total||total, saleDate,
       status==='paid'?new Date():null, notes]
    );
    const sale = rows[0];
    // Insert sale items
    for (const item of items) {
      await Q(
        `INSERT INTO sale_items(sale_id,user_id,product_id,product_name,qty,unit_price,cost,subtotal)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
        [sale.id, req.userId, item.product_id||null, item.product_name, item.qty, item.unit_price, item.cost||0, item.subtotal]
      );
      // Update stock
      if (item.product_id) {
        await Q("UPDATE products SET stock=GREATEST(0,COALESCE(stock,0)-$1) WHERE id=$2 AND user_id=$3 AND type='product'",
          [item.qty, item.product_id, req.userId]);
      }
    }
    // Auto cashflow if paid
    if (status === 'paid') {
      const desc = `Venda #${sale.id} — ${items.map(i=>`${i.qty}× ${i.product_name}`).join(', ')}`;
      await Q(`INSERT INTO cashflow_entries(user_id,description,type,value,entry_date,sale_id)
               VALUES($1,$2,'in',$3,$4,$5)`,
        [req.userId, desc, net_total||total, sale_date||new Date(), sale.id]);
    }
    sale.items = items;
    res.status(201).json(sale);
  } catch(e) { console.error(e); res.status(500).json({ error: 'Erro ao salvar venda' }); }
});

app.patch('/api/sales/:id/status', auth, async (req, res) => {
  const { status } = req.body;
  if (!['paid','pending','cancelled'].includes(status)) return res.status(400).json({ error: 'Status inválido' });
  const { rows } = await Q(
    `UPDATE sales SET status=$1, paid_at=$2 WHERE id=$3 AND user_id=$4 RETURNING *`,
    [status, status==='paid'?new Date():null, req.params.id, req.userId]
  );
  if (!rows.length) return res.status(404).json({ error: 'Venda não encontrada' });
  // Create cashflow on payment confirmation
  if (status === 'paid') {
    await Q(`INSERT INTO cashflow_entries(user_id,description,type,value,entry_date,sale_id)
             VALUES($1,$2,'in',$3,CURRENT_DATE,$4)`,
      [req.userId, `Venda: ${rows[0].product_name}`, rows[0].total, rows[0].id]);
  }
  res.json(rows[0]);
});

app.delete('/api/sales/:id', auth, async (req, res) => {
  await Q(`UPDATE sales SET status='cancelled' WHERE id=$1 AND user_id=$2`, [req.params.id, req.userId]);
  res.status(204).end();
});

// ══════════════════════════════════════════════════════════════
// CASHFLOW
// ══════════════════════════════════════════════════════════════
app.get('/api/cashflow', auth, async (req, res) => {
  const { from, to, type } = req.query;
  let sql = 'SELECT * FROM cashflow_entries WHERE user_id=$1';
  const params = [req.userId];
  if (type) { params.push(type); sql += ` AND type=$${params.length}`; }
  if (from) { params.push(from); sql += ` AND entry_date>=$${params.length}`; }
  if (to)   { params.push(to);   sql += ` AND entry_date<=$${params.length}`; }
  sql += ' ORDER BY entry_date DESC, created_at DESC LIMIT 200';
  const { rows } = await Q(sql, params);
  res.json(rows);
});

app.post('/api/cashflow', auth, async (req, res) => {
  const { description, type, value, category, entry_date } = req.body;
  if (!description || !type || !value) return res.status(400).json({ error: 'Campos obrigatórios: description, type, value' });
  if (!['in','out'].includes(type)) return res.status(400).json({ error: 'type deve ser "in" ou "out"' });
  const { rows } = await Q(
    'INSERT INTO cashflow_entries(user_id,description,type,value,category,entry_date) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',
    [req.userId, description, type, value, category, entry_date||new Date()]
  );
  res.status(201).json(rows[0]);
});

app.delete('/api/cashflow/:id', auth, async (req, res) => {
  await Q('DELETE FROM cashflow_entries WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
  res.status(204).end();
});

// ══════════════════════════════════════════════════════════════
// REPORTS
// ══════════════════════════════════════════════════════════════

// GET /api/reports/dashboard
app.get('/api/reports/dashboard', auth, async (req, res) => {
  const [rev, exp, salesCount, yearRev] = await Promise.all([
    Q(`SELECT COALESCE(SUM(value),0) total FROM cashflow_entries
       WHERE user_id=$1 AND type='in' AND DATE_TRUNC('month',entry_date)=DATE_TRUNC('month',NOW())`, [req.userId]),
    Q(`SELECT COALESCE(SUM(value),0) total FROM cashflow_entries
       WHERE user_id=$1 AND type='out' AND DATE_TRUNC('month',entry_date)=DATE_TRUNC('month',NOW())`, [req.userId]),
    Q(`SELECT COUNT(*) count FROM sales WHERE user_id=$1 AND status='paid'
       AND DATE_TRUNC('month',sale_date)=DATE_TRUNC('month',NOW())`, [req.userId]),
    Q(`SELECT COALESCE(SUM(total),0) total FROM sales
       WHERE user_id=$1 AND status='paid' AND EXTRACT(YEAR FROM sale_date)=EXTRACT(YEAR FROM NOW())`, [req.userId]),
  ]);
  const MEI_LIMIT = 81000;
  const yr = +yearRev.rows[0].total;
  res.json({
    month_revenue:  +rev.rows[0].total,
    month_expenses: +exp.rows[0].total,
    month_profit:   +rev.rows[0].total - +exp.rows[0].total,
    sales_count:    +salesCount.rows[0].count,
    year_revenue:   yr,
    mei_limit:      MEI_LIMIT,
    mei_pct:        +(yr / MEI_LIMIT * 100).toFixed(2),
    mei_remaining:  +(MEI_LIMIT - yr).toFixed(2),
  });
});

// GET /api/reports/annual — faturamento por mês no ano
app.get('/api/reports/annual', auth, async (req, res) => {
  const year = req.query.year || new Date().getFullYear();
  const { rows } = await Q(
    `SELECT TO_CHAR(DATE_TRUNC('month',entry_date),'YYYY-MM') AS month,
            SUM(CASE WHEN type='in'  THEN value ELSE 0 END) AS total_in,
            SUM(CASE WHEN type='out' THEN value ELSE 0 END) AS total_out
     FROM cashflow_entries
     WHERE user_id=$1 AND EXTRACT(YEAR FROM entry_date)=$2
     GROUP BY 1 ORDER BY 1`,
    [req.userId, year]
  );
  res.json(rows);
});

// PUT /api/cashflow/:id — edit with audit trail
app.put('/api/cashflow/:id', auth, async (req, res) => {
  const { value, description, reason } = req.body;
  if (!value || !reason) return res.status(400).json({ error: 'Valor e motivo são obrigatórios' });
  try {
    const existing = await Q('SELECT * FROM cashflow_entries WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
    if (!existing.rows.length) return res.status(404).json({ error: 'Não encontrado' });
    const old = existing.rows[0];
    const newHistory = [...(old.edit_history || []), {
      ts: new Date().toISOString(), before: old.value, after: value,
      reason, user_id: req.userId, desc_before: old.description
    }];
    const { rows } = await Q(
      `UPDATE cashflow_entries SET value=$1, description=$2, edit_history=$3 WHERE id=$4 AND user_id=$5 RETURNING *`,
      [value, description || old.description, JSON.stringify(newHistory), req.params.id, req.userId]
    );
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: 'Erro ao editar' }); }
});

// PATCH /api/products/:id/stock
app.patch('/api/products/:id/stock', auth, async (req, res) => {
  const { op, qty } = req.body;
  try {
    let sql;
    if (op === 'add') sql = 'UPDATE products SET stock=COALESCE(stock,0)+$1 WHERE id=$2 AND user_id=$3 RETURNING *';
    else if (op === 'sub') sql = 'UPDATE products SET stock=GREATEST(0,COALESCE(stock,0)-$1) WHERE id=$2 AND user_id=$3 RETURNING *';
    else sql = 'UPDATE products SET stock=$1 WHERE id=$2 AND user_id=$3 RETURNING *';
    const { rows } = await Q(sql, [qty, req.params.id, req.userId]);
    if (!rows.length) return res.status(404).json({ error: 'Produto não encontrado' });
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: 'Erro ao ajustar estoque' }); }
});

// GET /api/revenue-audit
app.get('/api/revenue-audit', auth, async (req, res) => {
  try {
    const { rows } = await Q(
      'SELECT * FROM revenue_audit WHERE user_id=$1 ORDER BY created_at DESC',
      [req.userId]
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: 'Erro' }); }
});

// POST /api/revenue-audit
app.post('/api/revenue-audit', auth, async (req, res) => {
  const { after_val, reason } = req.body;
  if (!after_val || !reason) return res.status(400).json({ error: 'Campos obrigatórios' });
  try {
    // Get current year revenue as before_val
    const rev = await Q(
      `SELECT COALESCE(SUM(total),0) total FROM sales WHERE user_id=$1 AND status='paid' AND EXTRACT(YEAR FROM sale_date)=EXTRACT(YEAR FROM NOW())`,
      [req.userId]
    );
    const before_val = parseFloat(rev.rows[0].total);
    const { rows } = await Q(
      'INSERT INTO revenue_audit(user_id,before_val,after_val,reason) VALUES($1,$2,$3,$4) RETURNING *',
      [req.userId, before_val, after_val, reason]
    );
    res.status(201).json(rows[0]);
  } catch(e) { res.status(500).json({ error: 'Erro ao salvar auditoria' }); }
});

// GET /api/sales/:id/items — get items for a sale
app.get('/api/sales/:id/items', auth, async (req, res) => {
  try {
    const { rows } = await Q(
      'SELECT * FROM sale_items WHERE sale_id=$1 AND user_id=$2',
      [req.params.id, req.userId]
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: 'Erro' }); }
});

// ── Health ──────────────────────────────────────────────────
app.get('/api/health', (_, res) => res.json({ status:'ok', ts: new Date().toISOString() }));

// ── Fallback SPA ────────────────────────────────────────────
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── Error handler ────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Erro interno no servidor' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`\n🏪 MEI Fácil rodando em http://localhost:${PORT}\n`));
