/**
 * Payroll Management System - REST API
 * Express.js backend connecting to MySQL database
 * 
 * Database tables: person, users, authentication, employee,
 *                  admin, attendance, workhours, payroll, payrolldetails
 */

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.use(express.json());

// ─── DB Connection Pool ───────────────────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASS     || '',
  database: process.env.DB_NAME     || 'payroll_db',
  waitForConnections: true,
  connectionLimit: 10,
});

// ─── JWT Middleware ───────────────────────────────────────────────────────────
const SECRET = process.env.JWT_SECRET || 'change_me_in_production';

function auth(requiredRole = null) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    try {
      const decoded = jwt.verify(token, SECRET);
      req.user = decoded;
      if (requiredRole && decoded.role !== requiredRole && decoded.role !== 'admin') {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }
      next();
    } catch {
      res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/auth/login
 * Body: { username, password }
 * Returns: { token, user }
 */
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  const [users] = await pool.query(
    `SELECT u.user_id, u.username, a.password_hash,
            CASE WHEN ad.admin_id IS NOT NULL THEN 'admin' ELSE 'employee' END AS role
     FROM users u
     JOIN authentication a ON a.user_id = u.user_id
     LEFT JOIN admin ad ON ad.user_id = u.user_id
     WHERE u.username = ?`,
    [username]
  );
  if (!users.length) return res.status(401).json({ error: 'Invalid credentials' });

  const user = users[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  await pool.query(
    'UPDATE authentication SET last_login = NOW() WHERE user_id = ?',
    [user.user_id]
  );

  const token = jwt.sign(
    { user_id: user.user_id, username: user.username, role: user.role },
    SECRET,
    { expiresIn: '8h' }
  );
  res.json({ token, user: { user_id: user.user_id, username: user.username, role: user.role } });
});

/**
 * POST /api/auth/register
 * Body: { first_name, last_name, email, phone, username, password, position, hire_date, hourly_rate }
 */
app.post('/api/auth/register', auth('admin'), async (req, res) => {
  const { first_name, last_name, email, phone, username, password, position, hire_date, hourly_rate } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1. person
    const [p] = await conn.query(
      'INSERT INTO person (first_name, last_name, phone, email) VALUES (?,?,?,?)',
      [first_name, last_name, phone, email]
    );
    const person_id = p.insertId;

    // 2. users
    const [u] = await conn.query(
      'INSERT INTO users (person_id, username) VALUES (?,?)',
      [person_id, username]
    );
    const user_id = u.insertId;

    // 3. authentication
    const hash = await bcrypt.hash(password, 10);
    await conn.query(
      'INSERT INTO authentication (user_id, password_hash) VALUES (?,?)',
      [user_id, hash]
    );

    // 4. employee
    await conn.query(
      'INSERT INTO employee (user_id, position, hire_date, hourly_rate) VALUES (?,?,?,?)',
      [user_id, position, hire_date, hourly_rate]
    );

    await conn.commit();
    res.status(201).json({ message: 'Employee registered', user_id, person_id });
  } catch (err) {
    await conn.rollback();
    if (err.code === 'ER_DUP_ENTRY')
      return res.status(409).json({ error: 'Username or email already exists' });
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// EMPLOYEE ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

/** GET /api/employees  — list all employees with personal info */
app.get('/api/employees', auth(), async (req, res) => {
  const [rows] = await pool.query(
    `SELECT e.employee_id, e.position, e.hire_date, e.hourly_rate,
            u.user_id, u.username,
            p.first_name, p.last_name, p.email, p.phone
     FROM employee e
     JOIN users u ON u.user_id = e.user_id
     JOIN person p ON p.person_id = u.person_id
     ORDER BY e.employee_id`
  );
  res.json(rows);
});

/** GET /api/employees/:id */
app.get('/api/employees/:id', auth(), async (req, res) => {
  const [rows] = await pool.query(
    `SELECT e.employee_id, e.position, e.hire_date, e.hourly_rate,
            u.user_id, u.username,
            p.first_name, p.last_name, p.email, p.phone
     FROM employee e
     JOIN users u ON u.user_id = e.user_id
     JOIN person p ON p.person_id = u.person_id
     WHERE e.employee_id = ?`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Employee not found' });
  res.json(rows[0]);
});

/** PUT /api/employees/:id  — update position / hourly_rate */
app.put('/api/employees/:id', auth('admin'), async (req, res) => {
  const { position, hourly_rate, first_name, last_name, email, phone } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query(
      'UPDATE employee SET position=?, hourly_rate=? WHERE employee_id=?',
      [position, hourly_rate, req.params.id]
    );
    await conn.query(
      `UPDATE person p
       JOIN users u ON u.person_id = p.person_id
       JOIN employee e ON e.user_id = u.user_id
       SET p.first_name=?, p.last_name=?, p.email=?, p.phone=?
       WHERE e.employee_id=?`,
      [first_name, last_name, email, phone, req.params.id]
    );
    await conn.commit();
    res.json({ message: 'Employee updated' });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

/** DELETE /api/employees/:id */
app.delete('/api/employees/:id', auth('admin'), async (req, res) => {
  await pool.query('DELETE FROM employee WHERE employee_id = ?', [req.params.id]);
  res.json({ message: 'Employee deleted' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ATTENDANCE ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

/** GET /api/attendance?employee_id=&from=&to= */
app.get('/api/attendance', auth(), async (req, res) => {
  const { employee_id, from, to } = req.query;
  let sql = `SELECT a.*, w.hours_worked,
                    p.first_name, p.last_name
             FROM attendance a
             LEFT JOIN workhours w ON w.attendance_id = a.attendance_id
             JOIN users u ON u.user_id = (
               SELECT user_id FROM employee WHERE employee_id = a.employee_id
             )
             JOIN person p ON p.person_id = u.person_id
             WHERE 1=1`;
  const params = [];
  if (employee_id) { sql += ' AND a.employee_id = ?'; params.push(employee_id); }
  if (from)        { sql += ' AND a.clock_in >= ?';   params.push(from); }
  if (to)          { sql += ' AND a.clock_in <= ?';   params.push(to); }
  sql += ' ORDER BY a.clock_in DESC';
  const [rows] = await pool.query(sql, params);
  res.json(rows);
});

/** POST /api/attendance/clock-in */
app.post('/api/attendance/clock-in', auth(), async (req, res) => {
  const { employee_id } = req.body;
  const [result] = await pool.query(
    'INSERT INTO attendance (employee_id, clock_in) VALUES (?, NOW())',
    [employee_id]
  );
  res.status(201).json({ attendance_id: result.insertId, message: 'Clocked in' });
});

/** PUT /api/attendance/:id/clock-out */
app.put('/api/attendance/:id/clock-out', auth(), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query(
      'UPDATE attendance SET clock_out = NOW() WHERE attendance_id = ?',
      [req.params.id]
    );
    const [rows] = await conn.query(
      `SELECT TIMESTAMPDIFF(SECOND, clock_in, clock_out)/3600 AS hours
       FROM attendance WHERE attendance_id = ?`,
      [req.params.id]
    );
    const hours = parseFloat(rows[0].hours).toFixed(2);
    await conn.query(
      'INSERT INTO workhours (attendance_id, hours_worked) VALUES (?,?)',
      [req.params.id, hours]
    );
    await conn.commit();
    res.json({ message: 'Clocked out', hours_worked: hours });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});


/** GET /api/attendance/late?from=&to=&work_start_hour=9
 *  Returns all clock-ins after work_start_hour (default 09:00)
 *  with minutes_late, employee name, trend data
 */
app.get('/api/attendance/late', auth('admin'), async (req, res) => {
  const { from, to, work_start_hour = 9 } = req.query;
  const startHour = parseInt(work_start_hour);

  let sql = `
    SELECT
      a.attendance_id,
      a.employee_id,
      a.clock_in,
      a.clock_out,
      w.hours_worked,
      p.first_name,
      p.last_name,
      e.position,
      TIME(a.clock_in) AS clock_in_time,
      HOUR(a.clock_in) * 60 + MINUTE(a.clock_in) AS clock_in_minutes,
      (HOUR(a.clock_in) * 60 + MINUTE(a.clock_in)) - (? * 60) AS minutes_late,
      DAYNAME(a.clock_in) AS day_name,
      DATE(a.clock_in) AS clock_in_date
    FROM attendance a
    LEFT JOIN workhours w ON w.attendance_id = a.attendance_id
    JOIN employee e ON e.employee_id = a.employee_id
    JOIN users u ON u.user_id = e.user_id
    JOIN person p ON p.person_id = u.person_id
    WHERE (HOUR(a.clock_in) * 60 + MINUTE(a.clock_in)) > (? * 60)
  `;
  const params = [startHour, startHour];

  if (from) { sql += ' AND DATE(a.clock_in) >= ?'; params.push(from); }
  if (to)   { sql += ' AND DATE(a.clock_in) <= ?'; params.push(to); }
  sql += ' ORDER BY a.clock_in DESC';

  const [rows] = await pool.query(sql, params);

  // Build per-employee late summary
  const summary = {};
  rows.forEach(r => {
    const key = r.employee_id;
    if (!summary[key]) {
      summary[key] = {
        employee_id: r.employee_id,
        name: r.first_name + ' ' + r.last_name,
        position: r.position,
        late_count: 0,
        total_minutes_late: 0,
        worst_minutes: 0,
      };
    }
    summary[key].late_count++;
    summary[key].total_minutes_late += r.minutes_late;
    if (r.minutes_late > summary[key].worst_minutes) summary[key].worst_minutes = r.minutes_late;
  });

  // Daily trend: count of late arrivals per date
  const trend = {};
  rows.forEach(r => {
    const d = r.clock_in_date instanceof Date
      ? r.clock_in_date.toISOString().split('T')[0]
      : String(r.clock_in_date).split('T')[0];
    trend[d] = (trend[d] || 0) + 1;
  });

  res.json({
    records: rows,
    summary: Object.values(summary).sort((a,b) => b.late_count - a.late_count),
    trend: Object.entries(trend).map(([date, count]) => ({ date, count })).sort((a,b) => a.date.localeCompare(b.date)),
    work_start_hour: startHour,
    total_late: rows.length
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// PAYROLL ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

/** GET /api/payroll?employee_id= */
app.get('/api/payroll', auth(), async (req, res) => {
  const { employee_id } = req.query;
  let sql = `SELECT py.*, p.first_name, p.last_name, e.position
             FROM payroll py
             JOIN employee e ON e.employee_id = py.employee_id
             JOIN users u ON u.user_id = e.user_id
             JOIN person p ON p.person_id = u.person_id
             WHERE 1=1`;
  const params = [];
  if (employee_id) { sql += ' AND py.employee_id = ?'; params.push(employee_id); }
  sql += ' ORDER BY py.period_start DESC';
  const [rows] = await pool.query(sql, params);
  res.json(rows);
});

/** POST /api/payroll/generate  — generate payroll for a period */
app.post('/api/payroll/generate', auth('admin'), async (req, res) => {
  const { employee_id, period_start, period_end } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Sum hours in range
    const [hours] = await conn.query(
      `SELECT COALESCE(SUM(w.hours_worked), 0) AS total_hours
       FROM attendance a
       JOIN workhours w ON w.attendance_id = a.attendance_id
       WHERE a.employee_id = ?
         AND a.clock_in BETWEEN ? AND ?`,
      [employee_id, period_start, period_end]
    );
    const total_hours = hours[0].total_hours;

    const [emp] = await conn.query(
      'SELECT hourly_rate FROM employee WHERE employee_id = ?',
      [employee_id]
    );
    const gross_pay = (total_hours * emp[0].hourly_rate).toFixed(2);

    const [py] = await conn.query(
      `INSERT INTO payroll (employee_id, period_start, period_end, total_hours, gross_pay)
       VALUES (?,?,?,?,?)`,
      [employee_id, period_start, period_end, total_hours, gross_pay]
    );

    // Add a payrolldetails summary line
    await conn.query(
      `INSERT INTO payrolldetails (payroll_id, description, amount)
       VALUES (?, 'Gross wages', ?)`,
      [py.insertId, gross_pay]
    );

    await conn.commit();
    res.status(201).json({ payroll_id: py.insertId, total_hours, gross_pay });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

/** GET /api/payroll/:id/details */
app.get('/api/payroll/:id/details', auth(), async (req, res) => {
  const [rows] = await pool.query(
    'SELECT * FROM payrolldetails WHERE payroll_id = ?',
    [req.params.id]
  );
  res.json(rows);
});

/** POST /api/payroll/:id/details  — add deduction / bonus line */
app.post('/api/payroll/:id/details', auth('admin'), async (req, res) => {
  const { description, amount } = req.body;
  const [r] = await pool.query(
    'INSERT INTO payrolldetails (payroll_id, description, amount) VALUES (?,?,?)',
    [req.params.id, description, amount]
  );
  res.status(201).json({ detail_id: r.insertId });
});

/** DELETE /api/payroll/:id */
app.delete('/api/payroll/:id', auth('admin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM payrolldetails WHERE payroll_id = ?', [req.params.id]);
    await pool.query('DELETE FROM payroll WHERE payroll_id = ?', [req.params.id]);
    res.json({ message: 'Payroll record deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD / STATS
// ═══════════════════════════════════════════════════════════════════════════════

/** GET /api/dashboard  — summary stats for admin */
app.get('/api/dashboard', auth('admin'), async (req, res) => {
  const [[{ total_employees }]]   = await pool.query('SELECT COUNT(*) AS total_employees FROM employee');
  const [[{ total_payroll }]]     = await pool.query('SELECT COALESCE(SUM(gross_pay),0) AS total_payroll FROM payroll');
  const [[{ present_today }]]     = await pool.query(
    "SELECT COUNT(*) AS present_today FROM attendance WHERE DATE(clock_in) = CURDATE()"
  );
  const [[{ pending_clockouts }]] = await pool.query(
    "SELECT COUNT(*) AS pending_clockouts FROM attendance WHERE clock_out IS NULL"
  );
  res.json({ total_employees, total_payroll, present_today, pending_clockouts });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
