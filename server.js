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
      `INSERT INTO users(name,email,password_hash,cpf_cnpj) VALUES($1,$2,$3,$4) RETURNING id,name,email,cpf_cnpj,razao_social`,
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

// PATCH /api/auth/password — troca de senha (exige senha atual correta)
app.patch('/api/auth/password', auth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password)
      return res.status(400).json({ error: 'Informe a senha atual e a nova senha' });
    if (new_password.length < 8)
      return res.status(400).json({ error: 'A nova senha deve ter no mínimo 8 caracteres' });

    const { rows } = await Q('SELECT password_hash FROM users WHERE id=$1', [req.userId]);
    if (!rows.length) return res.status(404).json({ error: 'Usuário não encontrado' });

    const ok = await bcrypt.compare(current_password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Senha atual incorreta' });

    const newHash = await bcrypt.hash(new_password, 12);
    await Q('UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2', [newHash, req.userId]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao alterar senha' }); }
});

// PUT /api/auth/profile — atualiza nome, CNPJ e razão social
app.put('/api/auth/profile', auth, async (req, res) => {
  try {
    const { name, cpf_cnpj, razao_social } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Nome é obrigatório' });
    const { rows } = await Q(
      `UPDATE users SET name=$1, cpf_cnpj=$2, razao_social=$3, updated_at=NOW()
       WHERE id=$4 RETURNING id, name, email, cpf_cnpj, razao_social`,
      [name.trim(), cpf_cnpj || null, razao_social || null, req.userId]
    );
    res.json({ user: rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao atualizar perfil' }); }
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
  const { name, type='service', unit='un', cost=0, margin_pct=100, price, stock } = req.body;
  if (!name || !price) return res.status(400).json({ error: 'Nome e preço são obrigatórios' });
  const stockVal = type === 'product' ? (stock ?? 0) : null;
  const { rows } = await Q(
    'INSERT INTO products(user_id,name,type,unit,cost,margin_pct,price,stock) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
    [req.userId, name, type, unit, cost, margin_pct, price, stockVal]
  );
  res.status(201).json(rows[0]);
});
app.put   ('/api/products/:id', auth, async (req, res) => {
  const { name, type, unit, cost, margin_pct, price, stock } = req.body;
  const stockVal = type === 'product' ? (stock ?? 0) : null;
  const { rows } = await Q(
    'UPDATE products SET name=$1,type=$2,unit=$3,cost=$4,margin_pct=$5,price=$6,stock=$7 WHERE id=$8 AND user_id=$9 RETURNING *',
    [name, type, unit, cost, margin_pct, price, stockVal, req.params.id, req.userId]
  );
  rows.length ? res.json(rows[0]) : res.status(404).json({ error: 'Não encontrado' });
});
app.delete('/api/products/:id', auth, async (req, res) => {
  await Q('UPDATE products SET active=false WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
  res.status(204).end();
});

// PATCH /api/products/:id/stock — ajuste manual de estoque (entrada/saída/definir)
app.patch('/api/products/:id/stock', auth, async (req, res) => {
  const { mode, value } = req.body; // mode: 'in' | 'out' | 'set'
  if (!['in','out','set'].includes(mode)) return res.status(400).json({ error: 'mode inválido' });
  const num = parseInt(value);
  if (isNaN(num) || num < 0) return res.status(400).json({ error: 'Valor inválido' });
  let sql;
  if (mode === 'set') sql = 'UPDATE products SET stock=$1 WHERE id=$2 AND user_id=$3 RETURNING *';
  else if (mode === 'in') sql = 'UPDATE products SET stock=COALESCE(stock,0)+$1 WHERE id=$2 AND user_id=$3 RETURNING *';
  else sql = 'UPDATE products SET stock=GREATEST(0,COALESCE(stock,0)-$1) WHERE id=$2 AND user_id=$3 RETURNING *';
  const { rows } = await Q(sql, [num, req.params.id, req.userId]);
  rows.length ? res.json(rows[0]) : res.status(404).json({ error: 'Não encontrado' });
});

// ══════════════════════════════════════════════════════════════
// SALES (multi-item, com forma de pagamento, taxa e estoque)
// ══════════════════════════════════════════════════════════════

// GET /api/sales — lista vendas com os itens agregados
app.get('/api/sales', auth, async (req, res) => {
  const { status, from, to, limit=100 } = req.query;
  let sql = 'SELECT * FROM sales WHERE user_id=$1';
  const params = [req.userId];
  if (status) { params.push(status); sql += ` AND status=$${params.length}`; }
  if (from)   { params.push(from);   sql += ` AND sale_date>=$${params.length}`; }
  if (to)     { params.push(to);     sql += ` AND sale_date<=$${params.length}`; }
  sql += ` ORDER BY sale_date DESC, created_at DESC LIMIT $${params.length+1}`;
  params.push(limit);
  const { rows: sales } = await Q(sql, params);
  if (!sales.length) return res.json([]);

  const ids = sales.map(s => s.id);
  const { rows: items } = await Q(
    `SELECT * FROM sale_items WHERE sale_id = ANY($1::uuid[]) ORDER BY id`,
    [ids]
  );
  const itemsBySale = {};
  items.forEach(i => { (itemsBySale[i.sale_id] ||= []).push(i); });
  res.json(sales.map(s => ({ ...s, items: itemsBySale[s.id] || [] })));
});

// GET /api/sales/:id — detalhe de uma venda com itens
app.get('/api/sales/:id', auth, async (req, res) => {
  const { rows } = await Q('SELECT * FROM sales WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
  if (!rows.length) return res.status(404).json({ error: 'Venda não encontrada' });
  const { rows: items } = await Q('SELECT * FROM sale_items WHERE sale_id=$1 ORDER BY id', [req.params.id]);
  res.json({ ...rows[0], items });
});

// POST /api/sales — cria venda com múltiplos itens
app.post('/api/sales', auth, async (req, res) => {
  const {
    client_id, client_name, items, pay_method = 'dinheiro',
    fee_pct = 0, status = 'pending', notes, sale_date,
  } = req.body;

  if (!Array.isArray(items) || !items.length)
    return res.status(400).json({ error: 'Adicione ao menos um item à venda' });

  for (const it of items) {
    if (!it.qty || !it.unit_price)
      return res.status(400).json({ error: 'Cada item precisa de quantidade e preço unitário' });
  }

  const total = items.reduce((a, i) => a + i.qty * i.unit_price, 0);
  const profit = items.reduce((a, i) => a + (i.qty * i.unit_price - i.qty * (i.cost || 0)), 0);
  const feeValue = +(total * (fee_pct || 0) / 100).toFixed(2);
  const netTotal = +(total - feeValue).toFixed(2);
  const date = sale_date || new Date().toISOString().slice(0, 10);
  const client = await db.connect();
  try {
    await client.query('BEGIN');

    const { rows: saleRows } = await client.query(
      `INSERT INTO sales(user_id,client_id,client_name,total,profit,status,pay_method,fee_pct,fee_value,net_total,notes,sale_date,paid_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [req.userId, client_id || null, client_name || null, total, profit, status, pay_method,
       fee_pct, feeValue, netTotal, notes || null, date, status === 'paid' ? new Date() : null]
    );
    const sale = saleRows[0];

    for (const it of items) {
      const subtotal = +(it.qty * it.unit_price).toFixed(2);
      await client.query(
        `INSERT INTO sale_items(sale_id,user_id,product_id,product_name,qty,unit_price,cost,subtotal)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
        [sale.id, req.userId, it.product_id || null, it.product_name || null, it.qty, it.unit_price, it.cost || 0, subtotal]
      );
      // Baixa automática de estoque para produtos com controle de estoque
      if (it.product_id) {
        await client.query(
          `UPDATE products SET stock = GREATEST(0, COALESCE(stock,0) - $1)
           WHERE id=$2 AND user_id=$3 AND type='product' AND stock IS NOT NULL`,
          [it.qty, it.product_id, req.userId]
        );
      }
    }

    if (status === 'paid') {
      const desc = `Venda — ${items.map(i => `${i.qty}x ${i.product_name}`).join(', ')}`;
      await client.query(
        `INSERT INTO cashflow_entries(user_id,description,type,value,entry_date,sale_id)
         VALUES($1,$2,'in',$3,$4,$5)`,
        [req.userId, desc, netTotal, date, sale.id]
      );
    }

    await client.query('COMMIT');
    const { rows: savedItems } = await client.query('SELECT * FROM sale_items WHERE sale_id=$1', [sale.id]);
    res.status(201).json({ ...sale, items: savedItems });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Erro ao registrar venda' });
  } finally {
    client.release();
  }
});

// PATCH /api/sales/:id/status — confirma pagamento ou volta para pendente
app.patch('/api/sales/:id/status', auth, async (req, res) => {
  const { status } = req.body;
  if (!['paid', 'pending', 'cancelled'].includes(status))
    return res.status(400).json({ error: 'Status inválido' });

  const { rows } = await Q(
    `UPDATE sales SET status=$1, paid_at=$2 WHERE id=$3 AND user_id=$4 RETURNING *`,
    [status, status === 'paid' ? new Date() : null, req.params.id, req.userId]
  );
  if (!rows.length) return res.status(404).json({ error: 'Venda não encontrada' });
  const sale = rows[0];

  if (status === 'paid') {
    const { rows: items } = await Q('SELECT * FROM sale_items WHERE sale_id=$1', [sale.id]);
    const desc = `Venda — ${items.map(i => `${i.qty}x ${i.product_name}`).join(', ')}`;
    await Q(
      `INSERT INTO cashflow_entries(user_id,description,type,value,entry_date,sale_id)
       VALUES($1,$2,'in',$3,CURRENT_DATE,$4)`,
      [req.userId, desc, sale.net_total, sale.id]
    );
  }
  res.json(sale);
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

// PATCH /api/cashflow/:id — edita valor/descrição com histórico de auditoria
app.patch('/api/cashflow/:id', auth, async (req, res) => {
  const { value, description, reason, user_name } = req.body;
  if (!reason || !reason.trim()) return res.status(400).json({ error: 'Informe o motivo da correção' });

  const { rows: existing } = await Q('SELECT * FROM cashflow_entries WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
  if (!existing.length) return res.status(404).json({ error: 'Lançamento não encontrado' });
  const entry = existing[0];

  const newValue = value !== undefined && value !== null ? parseFloat(value) : entry.value;
  if (isNaN(newValue) || newValue <= 0) return res.status(400).json({ error: 'Valor inválido' });
  const newDesc = description && description.trim() ? description.trim() : entry.description;

  const historyEntry = {
    ts: new Date().toISOString(),
    before: entry.value,
    after: newValue,
    desc_before: entry.description,
    reason: reason.trim(),
    user: user_name || null,
  };
  const newHistory = [...(entry.edit_history || []), historyEntry];

  const { rows } = await Q(
    'UPDATE cashflow_entries SET value=$1, description=$2, edit_history=$3 WHERE id=$4 AND user_id=$5 RETURNING *',
    [newValue, newDesc, JSON.stringify(newHistory), req.params.id, req.userId]
  );
  res.json(rows[0]);
});

// ══════════════════════════════════════════════════════════════
// REVENUE AUDIT (correção manual do faturamento anual MEI)
// ══════════════════════════════════════════════════════════════
app.get('/api/revenue-audit', auth, async (req, res) => {
  const { rows } = await Q(
    'SELECT * FROM revenue_audit WHERE user_id=$1 ORDER BY created_at ASC',
    [req.userId]
  );
  res.json(rows);
});

app.post('/api/revenue-audit', auth, async (req, res) => {
  const { before_val, after_val, reason } = req.body;
  if (after_val === undefined || after_val === null || isNaN(parseFloat(after_val)))
    return res.status(400).json({ error: 'Informe um valor válido' });
  if (!reason || !reason.trim())
    return res.status(400).json({ error: 'Informe o motivo da correção' });

  const { rows } = await Q(
    'INSERT INTO revenue_audit(user_id,before_val,after_val,reason) VALUES($1,$2,$3,$4) RETURNING *',
    [req.userId, before_val ?? null, after_val, reason.trim()]
  );
  res.status(201).json(rows[0]);
});

// ══════════════════════════════════════════════════════════════
// REPORTS
// ══════════════════════════════════════════════════════════════

// GET /api/reports/dashboard
app.get('/api/reports/dashboard', auth, async (req, res) => {
  const [rev, exp, salesCount, yearRev, auditAdj] = await Promise.all([
    Q(`SELECT COALESCE(SUM(value),0) total FROM cashflow_entries
       WHERE user_id=$1 AND type='in' AND DATE_TRUNC('month',entry_date)=DATE_TRUNC('month',NOW())`, [req.userId]),
    Q(`SELECT COALESCE(SUM(value),0) total FROM cashflow_entries
       WHERE user_id=$1 AND type='out' AND DATE_TRUNC('month',entry_date)=DATE_TRUNC('month',NOW())`, [req.userId]),
    Q(`SELECT COUNT(*) count FROM sales WHERE user_id=$1 AND status='paid'
       AND DATE_TRUNC('month',sale_date)=DATE_TRUNC('month',NOW())`, [req.userId]),
    Q(`SELECT COALESCE(SUM(total),0) total FROM sales
       WHERE user_id=$1 AND status='paid' AND EXTRACT(YEAR FROM sale_date)=EXTRACT(YEAR FROM NOW())`, [req.userId]),
    // Soma dos ajustes manuais de auditoria (after_val - before_val) no ano atual
    Q(`SELECT COALESCE(SUM(after_val - COALESCE(before_val,0)),0) total FROM revenue_audit
       WHERE user_id=$1 AND EXTRACT(YEAR FROM created_at)=EXTRACT(YEAR FROM NOW())`, [req.userId]),
  ]);
  const MEI_LIMIT = 81000;
  const yr = +yearRev.rows[0].total + +auditAdj.rows[0].total;
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
