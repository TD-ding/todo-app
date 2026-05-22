import os
import sqlite3
import time
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template_string, request, redirect, url_for,
    session, flash, jsonify, g
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')

DATABASE = os.path.join(os.path.dirname(__file__), 'todo.db')

VALID_PRIORITIES = {'low', 'medium', 'high'}

_login_attempts = {}



# ============================================================
#  Database
# ============================================================

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()


def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            priority TEXT NOT NULL DEFAULT 'medium',
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_todos_user_id ON todos(user_id);
    ''')
    admin_pw = os.environ.get('ADMIN_PASSWORD', 'admin123')
    cur = db.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    if not cur.fetchone():
        db.execute(
            'INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)',
            ('admin', generate_password_hash(admin_pw), 'admin', datetime.now().isoformat())
        )
    db.commit()


# ============================================================
#  Auth helpers
# ============================================================

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        db = get_db()
        user = db.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user or user['role'] != 'admin':
            flash('需要管理员权限', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper


# ============================================================
#  Rate limiter & error handler
# ============================================================

def _check_rate_limit(ip, max_attempts=5, window=60):
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < window]
    _login_attempts[ip] = attempts
    return len(attempts) < max_attempts


def _record_attempt(ip):
    _login_attempts.setdefault(ip, []).append(time.time())


@app.errorhandler(sqlite3.Error)
def handle_db_error(e):
    app.logger.exception("Database error")
    flash('操作失败，请稍后重试', 'danger')
    return redirect(request.referrer or url_for('index'))


# ============================================================
#  Shared CSS
# ============================================================

CSS = '''
<style>
  :root {
    --primary: #4f46e5;
    --primary-hover: #4338ca;
    --danger: #ef4444;
    --danger-hover: #dc2626;
    --success: #22c55e;
    --warning: #f59e0b;
    --bg: #f8fafc;
    --card: #ffffff;
    --border: #e2e8f0;
    --text: #1e293b;
    --muted: #64748b;
    --radius: 8px;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    min-height: 100vh;
  }
  .navbar {
    background: var(--card);
    border-bottom: 1px solid var(--border);
    padding: 0 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 56px;
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: 0 1px 3px rgba(0,0,0,.06);
  }
  .navbar .brand {
    font-size: 18px;
    font-weight: 700;
    color: var(--primary);
    text-decoration: none;
  }
  .navbar .nav-links { display: flex; align-items: center; gap: 16px; }
  .navbar .nav-links a, .navbar .nav-links span {
    font-size: 14px;
    color: var(--muted);
    text-decoration: none;
  }
  .navbar .nav-links a:hover { color: var(--primary); }
  .navbar .nav-links .btn-logout {
    background: none; border: 1px solid var(--border); border-radius: var(--radius);
    padding: 4px 12px; cursor: pointer; font-size: 13px; color: var(--muted);
  }
  .navbar .nav-links .btn-logout:hover { border-color: var(--danger); color: var(--danger); }
  .container { max-width: 860px; margin: 32px auto; padding: 0 20px; }
  .container-wide { max-width: 1100px; margin: 32px auto; padding: 0 20px; }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
    margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,.04);
  }
  .card h2 { font-size: 18px; margin-bottom: 16px; }
  .form-group { margin-bottom: 14px; }
  .form-group label {
    display: block;
    font-size: 13px;
    font-weight: 600;
    color: var(--muted);
    margin-bottom: 4px;
  }
  .form-group input, .form-group textarea, .form-group select {
    width: 100%;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    font-size: 14px;
    font-family: inherit;
    transition: border-color .15s;
  }
  .form-group input:focus, .form-group textarea:focus, .form-group select:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 3px rgba(79,70,229,.1);
  }
  .form-group textarea { resize: vertical; min-height: 60px; }
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 8px 16px;
    font-size: 14px;
    font-weight: 500;
    border: none;
    border-radius: var(--radius);
    cursor: pointer;
    transition: background .15s, transform .1s;
    text-decoration: none;
    gap: 6px;
  }
  .btn:active { transform: scale(.97); }
  .btn-primary { background: var(--primary); color: #fff; }
  .btn-primary:hover { background: var(--primary-hover); }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-danger:hover { background: var(--danger-hover); }
  .btn-sm { padding: 4px 10px; font-size: 12px; }
  .btn-outline {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--muted);
  }
  .btn-outline:hover { border-color: var(--primary); color: var(--primary); }
  .btn-success { background: var(--success); color: #fff; }
  .btn-warning { background: var(--warning); color: #fff; }
  .flash-container { list-style: none; margin-bottom: 16px; }
  .flash-container li {
    padding: 10px 16px;
    border-radius: var(--radius);
    font-size: 14px;
    margin-bottom: 8px;
  }
  .flash-success { background: #dcfce7; color: #166534; }
  .flash-danger  { background: #fee2e2; color: #991b1b; }
  .flash-warning { background: #fef3c7; color: #92400e; }
  .flash-info    { background: #dbeafe; color: #1e40af; }
  .todo-item {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 14px 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 10px;
    background: var(--card);
    transition: box-shadow .15s;
  }
  .todo-item:hover { box-shadow: 0 2px 8px rgba(0,0,0,.06); }
  .todo-item.done { opacity: .65; }
  .todo-item.done .todo-title { text-decoration: line-through; }
  .todo-check {
    width: 20px; height: 20px; flex-shrink: 0; margin-top: 2px;
    accent-color: var(--primary); cursor: pointer;
  }
  .todo-body { flex: 1; min-width: 0; }
  .todo-title { font-size: 15px; font-weight: 600; word-break: break-word; }
  .todo-desc { font-size: 13px; color: var(--muted); margin-top: 2px; }
  .todo-meta { display: flex; gap: 8px; align-items: center; margin-top: 6px; flex-wrap: wrap; }
  .todo-actions { display: flex; gap: 6px; flex-shrink: 0; align-items: center; }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge-high   { background: #fee2e2; color: #991b1b; }
  .badge-medium { background: #fef3c7; color: #92400e; }
  .badge-low    { background: #dcfce7; color: #166534; }
  .badge-done   { background: #dcfce7; color: #166534; }
  .badge-pending{ background: #fef3c7; color: #92400e; }
  .auth-wrapper {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: calc(100vh - 56px);
  }
  .auth-card { width: 100%; max-width: 400px; }
  .auth-card h1 { font-size: 22px; margin-bottom: 20px; text-align: center; }
  .auth-footer { text-align: center; margin-top: 12px; font-size: 13px; color: var(--muted); }
  .auth-footer a { color: var(--primary); text-decoration: none; }
  .filters { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
  .filters select {
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    font-size: 13px;
  }
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .stat-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px;
    text-align: center;
  }
  .stat-card .stat-value { font-size: 32px; font-weight: 700; color: var(--primary); }
  .stat-card .stat-label { font-size: 13px; color: var(--muted); margin-top: 4px; }
  .admin-table { width: 100%; border-collapse: collapse; font-size: 14px; }
  .admin-table th, .admin-table td {
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }
  .admin-table th {
    background: var(--bg);
    font-weight: 600;
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .5px;
  }
  .admin-table tr:hover td { background: var(--bg); }
  .role-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
  }
  .role-admin { background: #ede9fe; color: #6d28d9; }
  .role-user  { background: #e0f2fe; color: #0369a1; }
  .empty { text-align: center; padding: 40px 20px; color: var(--muted); }
  .empty p { font-size: 15px; margin-bottom: 12px; }
  .modal-overlay {
    position: fixed; inset: 0;
    background: rgba(0,0,0,.4);
    display: flex; align-items: center; justify-content: center;
    z-index: 200;
  }
  .modal-overlay.hidden { display: none; }
  .modal {
    background: var(--card);
    border-radius: var(--radius);
    padding: 24px;
    width: 100%;
    max-width: 480px;
    box-shadow: 0 20px 60px rgba(0,0,0,.15);
  }
  .modal h3 { margin-bottom: 16px; }
  .modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
</style>
'''

# ============================================================
#  Templates
# ============================================================

NAV_LOGGED_OUT = '''
<nav class="navbar">
  <a class="brand" href="{{ url_for('login') }}">TodoApp</a>
  <div class="nav-links">
    <a href="{{ url_for('login') }}">登录</a>
    <a href="{{ url_for('register') }}">注册</a>
  </div>
</nav>
'''

NAV_LOGGED_IN = '''
<nav class="navbar">
  <a class="brand" href="{{ url_for('index') }}">TodoApp</a>
  <div class="nav-links">
    <span>{{ session.username }}({{'管理员' if session.role == 'admin' else '用户'}})</span>
    {% if session.role == 'admin' %}
    <a href="{{ url_for('admin') }}">管理面板</a>
    {% endif %}
    <a href="{{ url_for('index') }}">我的任务</a>
    <form method="get" action="{{ url_for('logout') }}" style="display:inline">
      <button class="btn-logout" type="submit">退出</button>
    </form>
  </div>
</nav>
'''

FLASH_BLOCK = '''
{% with messages = get_flashed_messages(with_categories=true) %}
{% if messages %}
<ul class="flash-container">
  {% for cat, msg in messages %}
  <li class="flash-{{ cat }}">{{ msg }}</li>
  {% endfor %}
</ul>
{% endif %}
{% endwith %}
'''

LOGIN_TEMPLATE = CSS + NAV_LOGGED_OUT + FLASH_BLOCK + '''
<div class="auth-wrapper">
  <div class="card auth-card">
    <h1>登录</h1>
    <form method="post" action="{{ url_for('login') }}">
      <div class="form-group">
        <label>用户名</label>
        <input type="text" name="username" required autofocus>
      </div>
      <div class="form-group">
        <label>密码</label>
        <input type="password" name="password" required>
      </div>
      <button class="btn btn-primary" style="width:100%;margin-top:8px" type="submit">登录</button>
    </form>
    <div class="auth-footer">还没有账号？<a href="{{ url_for('register') }}">注册</a></div>
  </div>
</div>
'''

REGISTER_TEMPLATE = CSS + NAV_LOGGED_OUT + FLASH_BLOCK + '''
<div class="auth-wrapper">
  <div class="card auth-card">
    <h1>注册</h1>
    <form method="post" action="{{ url_for('register') }}">
      <div class="form-group">
        <label>用户名</label>
        <input type="text" name="username" required autofocus>
      </div>
      <div class="form-group">
        <label>密码</label>
        <input type="password" name="password" required>
      </div>
      <div class="form-group">
        <label>确认密码</label>
        <input type="password" name="password2" required>
      </div>
      <button class="btn btn-primary" style="width:100%;margin-top:8px" type="submit">注册</button>
    </form>
    <div class="auth-footer">已有账号？<a href="{{ url_for('login') }}">登录</a></div>
  </div>
</div>
'''

INDEX_TEMPLATE = CSS + NAV_LOGGED_IN + FLASH_BLOCK + '''
<div class="container">
  <div class="card">
    <h2>新建任务</h2>
    <form id="add-form" method="post" action="{{ url_for('add_todo') }}">
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <div class="form-group" style="flex:1;min-width:200px;margin-bottom:0">
          <input type="text" name="title" placeholder="任务标题..." required>
        </div>
        <div class="form-group" style="width:120px;margin-bottom:0">
          <select name="priority">
            <option value="low">低优先</option>
            <option value="medium" selected>中优先</option>
            <option value="high">高优先</option>
          </select>
        </div>
        <button class="btn btn-primary" type="submit">添加</button>
      </div>
      <div class="form-group" style="margin-top:10px">
        <textarea name="description" placeholder="描述（可选）" rows="2"></textarea>
      </div>
    </form>
  </div>

  <div class="filters">
    <span style="font-size:13px;color:var(--muted)">筛选：</span>
    <select id="filter-status" onchange="applyFilters()">
      <option value="all" {% if filter_status=='all' %}selected{% endif %}>全部状态</option>
      <option value="pending" {% if filter_status=='pending' %}selected{% endif %}>待完成</option>
      <option value="done" {% if filter_status=='done' %}selected{% endif %}>已完成</option>
    </select>
    <select id="filter-priority" onchange="applyFilters()">
      <option value="all" {% if filter_priority=='all' %}selected{% endif %}>全部优先级</option>
      <option value="high" {% if filter_priority=='high' %}selected{% endif %}>高</option>
      <option value="medium" {% if filter_priority=='medium' %}selected{% endif %}>中</option>
      <option value="low" {% if filter_priority=='low' %}selected{% endif %}>低</option>
    </select>
  </div>

  {% if todos %}
    {% for todo in todos %}
    <div class="todo-item {{ 'done' if todo.status == 'done' }}" id="todo-{{ todo.id }}">
      <input type="checkbox" class="todo-check"
             {{ 'checked' if todo.status == 'done' }}
             onchange="toggleTodo({{ todo.id }})">
      <div class="todo-body">
        <div class="todo-title" id="title-{{ todo.id }}">{{ todo.title }}</div>
        {% if todo.description %}
        <div class="todo-desc">{{ todo.description }}</div>
        {% endif %}
        <div class="todo-meta">
          <span class="badge badge-{{ todo.priority }}">{{ {'high':'高','medium':'中','low':'低'}[todo.priority] }}</span>
          <span class="badge badge-{{ todo.status }}">{{ {'pending':'待完成','done':'已完成'}[todo.status] }}</span>
          <span style="font-size:12px;color:var(--muted)">{{ todo.created_at[:16] }}</span>
        </div>
      </div>
      <div class="todo-actions">
        <button class="btn btn-outline btn-sm" onclick="openEdit({{ todo.id }}, '{{ todo.title | e }}', '{{ todo.description | e }}', '{{ todo.priority }}')">编辑</button>
        <form method="post" action="{{ url_for('delete_todo', todo_id=todo.id) }}" onsubmit="return confirm('确定删除？')">
          <button class="btn btn-danger btn-sm" type="submit">删除</button>
        </form>
      </div>
    </div>
    {% endfor %}
  {% else %}
    <div class="empty">
      <p>暂无任务，开始创建吧！</p>
    </div>
  {% endif %}
</div>

<div class="modal-overlay hidden" id="edit-modal">
  <div class="modal">
    <h3>编辑任务</h3>
    <input type="hidden" id="edit-id">
    <div class="form-group">
      <label>标题</label>
      <input type="text" id="edit-title">
    </div>
    <div class="form-group">
      <label>描述</label>
      <textarea id="edit-desc" rows="3"></textarea>
    </div>
    <div class="form-group">
      <label>优先级</label>
      <select id="edit-priority">
        <option value="low">低</option>
        <option value="medium">中</option>
        <option value="high">高</option>
      </select>
    </div>
    <div class="modal-actions">
      <button class="btn btn-outline" onclick="closeEdit()">取消</button>
      <button class="btn btn-primary" onclick="submitEdit()">保存</button>
    </div>
  </div>
</div>

<script>
function applyFilters() {
  const s = document.getElementById('filter-status').value;
  const p = document.getElementById('filter-priority').value;
  location.href = '{{ url_for("index") }}?status=' + s + '&priority=' + p;
}
function toggleTodo(id) {
  fetch('/todo/' + id + '/toggle', {method:'POST', headers:{'X-Requested-With':'fetch'}})
    .then(r => r.json())
    .then(data => { if (data.status) location.reload(); });
}
function openEdit(id, title, desc, priority) {
  document.getElementById('edit-id').value = id;
  document.getElementById('edit-title').value = title;
  document.getElementById('edit-desc').value = desc;
  document.getElementById('edit-priority').value = priority;
  document.getElementById('edit-modal').classList.remove('hidden');
}
function closeEdit() {
  document.getElementById('edit-modal').classList.add('hidden');
}
function submitEdit() {
  const id = document.getElementById('edit-id').value;
  const form = new FormData();
  form.append('title', document.getElementById('edit-title').value);
  form.append('description', document.getElementById('edit-desc').value);
  form.append('priority', document.getElementById('edit-priority').value);
  fetch('/todo/' + id + '/edit', {method:'POST', body: form})
    .then(() => location.reload());
}
</script>
'''

ADMIN_TEMPLATE = CSS + NAV_LOGGED_IN + FLASH_BLOCK + '''
<div class="container-wide">
  <h1 style="margin-bottom:24px">管理面板</h1>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-value">{{ stats.total_users }}</div>
      <div class="stat-label">注册用户</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ stats.total_todos }}</div>
      <div class="stat-label">任务总数</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ stats.pending_todos }}</div>
      <div class="stat-label">待完成</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ stats.done_todos }}</div>
      <div class="stat-label">已完成</div>
    </div>
  </div>

  <!-- User table -->
  <div class="card">
    <h2>用户管理</h2>
    <div style="overflow-x:auto">
      <table class="admin-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>用户名</th>
            <th>角色</th>
            <th>任务数</th>
            <th>注册时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {% for u in users %}
          <tr>
            <td>{{ u.id }}</td>
            <td>{{ u.username }}</td>
            <td>
              <span class="role-badge role-{{ u.role }}">{{ '管理员' if u.role == 'admin' else '用户' }}</span>
            </td>
            <td>{{ user_todo_counts.get(u.id, 0) }}</td>
            <td style="font-size:13px;color:var(--muted)">{{ u.created_at[:16] }}</td>
            <td>
              {% if u.id != session.user_id %}
              <form method="post" action="{{ url_for('toggle_role', user_id=u.id) }}" style="display:inline">
                <button class="btn btn-outline btn-sm" type="submit">
                  {{ '设为用户' if u.role == 'admin' else '设为管理员' }}
                </button>
              </form>
              <form method="post" action="{{ url_for('delete_user', user_id=u.id) }}" style="display:inline"
                    onsubmit="return confirm('确定删除用户 {{ u.username }} 及其所有任务？')">
                <button class="btn btn-danger btn-sm" type="submit">删除</button>
              </form>
              {% else %}
              <span style="font-size:12px;color:var(--muted)">（当前用户）</span>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>
'''

# ============================================================
#  Auth routes
# ============================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        password2 = request.form.get('password2', '')
        if not username or not password:
            flash('用户名和密码不能为空', 'danger')
            return redirect(url_for('register'))
        if len(username) > 32:
            flash('用户名不能超过32个字符', 'danger')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('密码至少需要6个字符', 'danger')
            return redirect(url_for('register'))
        if password != password2:
            flash('两次密码不一致', 'danger')
            return redirect(url_for('register'))
        db = get_db()
        if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            flash('用户名已存在', 'danger')
            return redirect(url_for('register'))
        db.execute(
            'INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)',
            (username, generate_password_hash(password), 'user', datetime.now().isoformat())
        )
        db.commit()
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    return render_template_string(REGISTER_TEMPLATE)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr
        if not _check_rate_limit(ip):
            flash('登录尝试过于频繁，请稍后再试', 'danger')
            return redirect(url_for('login'))
        username = request.form['username'].strip()
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('登录成功', 'success')
            return redirect(url_for('index'))
        flash('用户名或密码错误', 'danger')
        _record_attempt(ip)
        return redirect(url_for('login'))
    return render_template_string(LOGIN_TEMPLATE)


@app.route('/logout')
def logout():
    session.clear()
    flash('已退出登录', 'info')
    return redirect(url_for('login'))


# ============================================================
#  Todo routes
# ============================================================

@app.route('/')
@login_required
def index():
    db = get_db()
    filter_status = request.args.get('status', 'all')
    filter_priority = request.args.get('priority', 'all')

    query = 'SELECT * FROM todos WHERE user_id = ?'
    params = [session['user_id']]

    if filter_status != 'all':
        query += ' AND status = ?'
        params.append(filter_status)
    if filter_priority != 'all':
        query += ' AND priority = ?'
        params.append(filter_priority)

    query += ' ORDER BY created_at DESC'
    todos = db.execute(query, params).fetchall()
    return render_template_string(INDEX_TEMPLATE, todos=todos,
                                  filter_status=filter_status,
                                  filter_priority=filter_priority)


@app.route('/todo/add', methods=['POST'])
@login_required
def add_todo():
    title = request.form['title'].strip()
    description = request.form.get('description', '').strip()
    priority = request.form.get('priority', 'medium')
    if priority not in VALID_PRIORITIES:
        priority = 'medium'
    if not title:
        flash('任务标题不能为空', 'danger')
        return redirect(url_for('index'))
    if len(title) > 200:
        flash('任务标题不能超过200个字符', 'danger')
        return redirect(url_for('index'))
    if len(description) > 2000:
        flash('描述不能超过2000个字符', 'danger')
        return redirect(url_for('index'))
    now = datetime.now().isoformat()
    db = get_db()
    db.execute(
        'INSERT INTO todos (title, description, status, priority, user_id, created_at, updated_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        (title, description, 'pending', priority, session['user_id'], now, now)
    )
    db.commit()
    flash('任务已创建', 'success')
    return redirect(url_for('index'))


@app.route('/todo/<int:todo_id>/toggle', methods=['POST'])
@login_required
def toggle_todo(todo_id):
    db = get_db()
    todo = db.execute('SELECT * FROM todos WHERE id = ? AND user_id = ?',
                      (todo_id, session['user_id'])).fetchone()
    if not todo:
        return jsonify({'error': 'not found'}), 404
    new_status = 'done' if todo['status'] == 'pending' else 'pending'
    now = datetime.now().isoformat()
    db.execute('UPDATE todos SET status = ?, updated_at = ? WHERE id = ?',
               (new_status, now, todo_id))
    db.commit()
    return jsonify({'status': new_status})


@app.route('/todo/<int:todo_id>/delete', methods=['POST'])
@login_required
def delete_todo(todo_id):
    db = get_db()
    db.execute('DELETE FROM todos WHERE id = ? AND user_id = ?',
               (todo_id, session['user_id']))
    db.commit()
    flash('任务已删除', 'success')
    return redirect(url_for('index'))


@app.route('/todo/<int:todo_id>/edit', methods=['POST'])
@login_required
def edit_todo(todo_id):
    db = get_db()
    todo = db.execute('SELECT * FROM todos WHERE id = ? AND user_id = ?',
                      (todo_id, session['user_id'])).fetchone()
    if not todo:
        return jsonify({'error': 'not found'}), 404
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    priority = request.form.get('priority', 'medium')
    if priority not in VALID_PRIORITIES:
        priority = 'medium'
    if not title:
        return jsonify({'error': '标题不能为空'}), 400
    if len(title) > 200 or len(description) > 2000:
        return jsonify({'error': '输入过长'}), 400
    now = datetime.now().isoformat()
    db.execute('UPDATE todos SET title=?, description=?, priority=?, updated_at=? WHERE id=?',
               (title, description, priority, now, todo_id))
    db.commit()
    return jsonify({'ok': True})


# ============================================================
#  Admin routes
# ============================================================

@app.route('/admin')
@admin_required
def admin():
    db = get_db()
    users = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    row = db.execute(
        "SELECT COUNT(*) AS total,"
        " SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pending,"
        " SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) AS done"
        " FROM todos"
    ).fetchone()
    stats = {
        'total_users': len(users),
        'total_todos': row['total'] or 0,
        'pending_todos': row['pending'] or 0,
        'done_todos': row['done'] or 0,
    }
    user_todo_counts = {}
    for r in db.execute('SELECT user_id, COUNT(*) AS cnt FROM todos GROUP BY user_id'):
        user_todo_counts[r['user_id']] = r['cnt']
    return render_template_string(ADMIN_TEMPLATE, users=users, stats=stats,
                                  user_todo_counts=user_todo_counts)


@app.route('/admin/user/<int:user_id>/toggle-role', methods=['POST'])
@admin_required
def toggle_role(user_id):
    if user_id == session['user_id']:
        flash('不能修改自己的角色', 'danger')
        return redirect(url_for('admin'))
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('用户不存在', 'danger')
        return redirect(url_for('admin'))
    new_role = 'user' if user['role'] == 'admin' else 'admin'
    db.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    db.commit()
    flash(f'已将 {user["username"]} 的角色改为 {new_role}', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('不能删除自己', 'danger')
        return redirect(url_for('admin'))
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('用户不存在', 'danger')
        return redirect(url_for('admin'))
    db.execute('DELETE FROM todos WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash(f'已删除用户 {user["username"]}', 'success')
    return redirect(url_for('admin'))


# ============================================================
#  Init
# ============================================================

with app.app_context():
    init_db()

if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'
    app.run(host='0.0.0.0', port=5000, debug=debug)
