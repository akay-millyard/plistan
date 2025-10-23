# -*- coding: utf-8 -*-
import os, sqlite3, re, secrets, datetime, csv, random, string, base64
from types import SimpleNamespace
import io
from flask import Flask, g, render_template, request, redirect, url_for, jsonify, abort, flash, make_response, session
from werkzeug.security import generate_password_hash, check_password_hash
import jwt, qrcode
from functools import wraps

VERSION = "v3.2.0-2025-10-23"

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

DB_PATH = os.path.join(os.path.dirname(__file__), 'plistan.db')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, 'r', encoding='utf-8') as f:
        db = get_db()
        db.executescript(f.read())
        db.commit()

def migrate_db():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER,
      household_id INTEGER,
      email TEXT NOT NULL UNIQUE,
      pw_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('resident','admin','superadmin')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
      FOREIGN KEY (household_id) REFERENCES households(id) ON DELETE CASCADE
    )"""); db.commit()
    cols = {r['name'] for r in db.execute("PRAGMA table_info(tenants)").fetchall()}
    for col_sql, col in [
        ("ALTER TABLE tenants ADD COLUMN primary_color TEXT", "primary_color"),
        ("ALTER TABLE tenants ADD COLUMN fortnox_client_id TEXT", "fortnox_client_id"),
        ("ALTER TABLE tenants ADD COLUMN fortnox_client_secret TEXT", "fortnox_client_secret"),
        ("ALTER TABLE tenants ADD COLUMN fortnox_access_token TEXT", "fortnox_access_token"),
        ("ALTER TABLE tenants ADD COLUMN fortnox_refresh_token TEXT", "fortnox_refresh_token"),
        ("ALTER TABLE tenants ADD COLUMN fortnox_customer_number TEXT", "fortnox_customer_number"),
        ("ALTER TABLE tenants ADD COLUMN fortnox_unit_price REAL DEFAULT 0", "fortnox_unit_price"),
    ]:
        if col not in cols: db.execute(col_sql); db.commit()
    vcols = {r['name'] for r in db.execute("PRAGMA table_info(vehicles)").fetchall()}
    if 'ownership_type' not in vcols:
        db.execute("ALTER TABLE vehicles ADD COLUMN ownership_type TEXT"); db.commit()
    db.execute("""CREATE TABLE IF NOT EXISTS vehicle_changes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      household_id INTEGER NOT NULL,
      reg_old TEXT,
      reg_new TEXT,
      reason TEXT NOT NULL,
      changed_by TEXT NOT NULL,
      changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )"""); db.commit()

def get_current_user():
    uid = session.get('uid')
    if not uid: return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def get_current_tenant():
    return getattr(g, 'tenant', None)


def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrap(*a, **kw):
            u = get_current_user()
            if not u:
                flash('Logga in först.'); return redirect(url_for('login', next=request.full_path))
            if u['role'] not in roles: abort(403)
            return fn(*a, **kw)
        return wrap
    return deco

def ensure_superadmin_seed():
    email = os.environ.get('SUPERADMIN_EMAIL')
    pw = os.environ.get('SUPERADMIN_PASSWORD')
    if not email or not pw: return
    db = get_db()
    if not db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        pw_hash = generate_password_hash(pw)
        db.execute(
            "INSERT INTO users (email, pw_hash, role) VALUES (?, ?, 'superadmin')",
            (email, pw_hash),
        )
        db.commit()


PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


def hash_password(password):
    return generate_password_hash(password)


def verify_password(plain_password, stored_hash):
    if not stored_hash:
        return False
    return check_password_hash(stored_hash, plain_password)


def generate_password(length: int = 12) -> str:
    return ''.join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))

def normalize_reg(s):
    if not s: return ''
    return re.sub(r'[\s-]', '', s.strip().upper())

@app.before_request
def before_every_request():
    if not os.path.exists(DB_PATH): init_db()
    migrate_db()
    slug = request.args.get('t') or request.cookies.get('tenant_slug')
    g.tenant = get_db().execute("SELECT * FROM tenants WHERE slug = ?", (slug,)).fetchone() if slug else None
    ensure_superadmin_seed()
    g.user = get_current_user()
    g.version = VERSION

@app.context_processor
def inject_globals():
    tenant = getattr(g, 'tenant', None)
    tenant_slug = tenant['slug'] if tenant else None
    user = getattr(g, 'user', None)
    current_user = SimpleNamespace(**dict(user)) if user else None
    return dict(
        version=VERSION,
        tenant=tenant,
        tenant_slug=tenant_slug,
        current_user=current_user,
        login_page=False,
    )

def require_tenant_or_redirect():
    if not g.tenant:
        u = get_current_user()
        if u and u['role'] == 'superadmin': return redirect(url_for('root_dashboard'))
        return redirect(url_for('login'))
    return None

@app.get('/')
def home():
    u = get_current_user()
    if not u: return redirect(url_for('login'))
    if u['role'] == 'superadmin': return redirect(url_for('root_dashboard'))
    if u['role'] == 'admin':
        if g.tenant: return redirect(url_for('admin_dashboard', t=g.tenant['slug']))
        t = get_db().execute("SELECT slug FROM tenants WHERE id=?", (u['tenant_id'],)).fetchone()
        if t:
            resp = redirect(url_for('admin_dashboard', t=t['slug'])); resp.set_cookie('tenant_slug', t['slug']); return resp
        return "Ingen förening kopplad.", 404
    if u['role'] == 'resident':
        db = get_db()
        if not g.tenant:
            hh = db.execute("SELECT h.invite_code, t.slug FROM households h JOIN tenants t ON h.tenant_id=t.id WHERE h.id=?", (u['household_id'],)).fetchone()
            if hh:
                resp = redirect(url_for('resident_vehicles', household_code=hh['invite_code'], t=hh['slug'])); resp.set_cookie('tenant_slug', hh['slug']); return resp
            return "Hushåll saknas.", 404
        hh = db.execute("SELECT invite_code FROM households WHERE id=?", (u['household_id'],)).fetchone()
        if hh: return redirect(url_for('resident_vehicles', household_code=hh['invite_code'], t=g.tenant['slug']))
        return "Hushåll saknas.", 404

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        pw = request.form.get('password','')
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u and check_password_hash(u['pw_hash'], pw):
            session['uid'] = u['id']; flash('Inloggad.'); return redirect(url_for('home'))
        flash('Fel e-post eller lösenord.')
    return render_template("auth_login.html", login_page=True)

@app.post('/select-tenant')
def select_tenant():
    if not g.user:
        return redirect(url_for('login'))
    slug = request.form.get('slug')
    if not slug:
        abort(400)
    # (valfritt) verifiera att g.user har access till just denna tenant
    db = get_db()
    t = db.execute("SELECT id FROM tenants WHERE slug=?", (slug,)).fetchone()
    if not t:
        abort(404)
    return _redirect_to_role_start(g.user['role'], slug)

@app.route('/account/password', methods=['GET', 'POST'])
def account_password():
    if not g.user:
        return redirect(url_for('login'))
    if request.method == 'POST':
        cur = request.form.get('current') or ''
        new = request.form.get('new') or ''
        rep = request.form.get('repeat') or ''
        if not new or new != rep:
            return render_template('account_password.html', error='Lösenorden matchar inte.')
        if not verify_password(cur, g.user['pw_hash']):
            return render_template('account_password.html', error='Fel nuvarande lösenord.')
        db = get_db()
        db.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(new), g.user['id']))
        db.commit()
        flash('Lösenord uppdaterat.', 'success')
        return redirect(url_for('account_password'))
    return render_template('account_password.html')

@app.get('/logout')
def logout():
    session.clear(); flash('Utloggad.'); return redirect(url_for('login'))

# -------- Superadmin --------
@app.get('/root/dashboard')
@role_required('superadmin')
def root_dashboard():
    db = get_db()
    tenants = db.execute("SELECT * FROM tenants ORDER BY created_at DESC").fetchall()
    current_month = datetime.datetime.utcnow().strftime("%Y-%m")
    return render_template('root_dashboard.html', tenants=tenants, current_month=current_month)


@app.post('/root/admins/<int:user_id>/reset')
@role_required('superadmin')
def root_reset_admin(user_id):
    db = get_db()
    u = db.execute("SELECT id, role FROM users WHERE id=?", (user_id,)).fetchone()
    if not u or u['role'] != 'admin':
        abort(400)
    pw = generate_password()
    db.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(pw), user_id))
    db.commit()
    flash(f'Nytt admin-lösenord: {pw} (visa en gång).', 'success')
    return redirect(url_for('root_dashboard'))

@app.route('/tenants/new', methods=['GET','POST'])
@role_required('superadmin')
def new_tenant():
    db = get_db()
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        slug = request.form.get('slug','').strip()
        admin_email = request.form.get('admin_email','').strip().lower()
        if not (name and slug and admin_email):
            flash('Fyll i alla fält.'); return redirect(url_for('new_tenant'))
        if db.execute("SELECT 1 FROM tenants WHERE slug=?", (slug,)).fetchone():
            flash('Slug används redan.'); return redirect(url_for('new_tenant'))
        db.execute("INSERT INTO tenants (name, slug) VALUES (?, ?)", (name, slug)); db.commit()
        tenant = db.execute("SELECT * FROM tenants WHERE slug=?", (slug,)).fetchone()
        pwd = ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(12))
        try:
            db.execute("INSERT INTO users (tenant_id, email, pw_hash, role) VALUES (?, ?, ?, 'admin')",
                       (tenant['id'], admin_email, generate_password_hash(pwd))); db.commit()
        except sqlite3.IntegrityError:
            flash('Admin-e-post används redan, skapade föreningen ändå.'); pwd = '(oförändrat)'
        return render_template('tenant_new.html', created=True, tenant=tenant, admin_email=admin_email, admin_password=pwd)
    return render_template('tenant_new.html', created=False)

# -------- Admin --------
@app.get('/admin')
@role_required('admin','superadmin')
def admin_dashboard():
    r = require_tenant_or_redirect()
    if r: return r
    db = get_db(); tid = g.tenant['id']
    res = db.execute("SELECT COUNT(*) c FROM vehicles WHERE tenant_id=? AND type='resident'", (tid,)).fetchone()
    guest = db.execute("SELECT COUNT(*) c FROM vehicles WHERE tenant_id=? AND type='guest' AND (valid_to IS NULL OR valid_to > ?)", (tid, datetime.datetime.utcnow().isoformat())).fetchone()
    hh_count = db.execute("SELECT COUNT(*) c FROM households WHERE tenant_id=?", (tid,)).fetchone()
    households = []
    for h in db.execute("SELECT * FROM households WHERE tenant_id=? ORDER BY created_at DESC", (tid,)).fetchall():
        vs = db.execute("SELECT reg, type, valid_to, ownership_type FROM vehicles WHERE tenant_id=? AND household_id=? ORDER BY created_at DESC", (tid, h['id'])).fetchall()
        households.append(dict(id=h['id'], name=h['name'], invite_code=h['invite_code'], vehicles=[dict(x) for x in vs]))
    class S: pass
    stats = S(); stats.resident = res['c']; stats.guest = guest['c']; stats.households = hh_count['c']
    return render_template('admin_dashboard.html', tenant=g.tenant, households=households, stats=stats)


@app.route('/admin/household/<int:hid>', methods=['GET','POST'])
@role_required('admin','superadmin')
def admin_manage_household(hid):
    r = require_tenant_or_redirect()
    if r:
        return r
    tenant = get_current_tenant()
    if not tenant:
        return redirect(url_for('admin_dashboard'))
    db = get_db()
    household = db.execute(
        "SELECT * FROM households WHERE id=? AND tenant_id=?",
        (hid, tenant['id']),
    ).fetchone()
    if not household:
        abort(404)

    if request.method == 'POST':
        if 'delete_vehicle' in request.form:
            vid = request.form.get('delete_vehicle')
            try:
                vid_int = int(vid)
            except (TypeError, ValueError):
                flash('Ogiltigt fordon.', 'warning')
            else:
                db.execute(
                    "DELETE FROM vehicles WHERE id=? AND household_id=? AND tenant_id=?",
                    (vid_int, hid, tenant['id']),
                )
                db.commit()
                flash('Fordon borttaget.', 'success')
        elif 'reg' in request.form:
            reg = normalize_reg(request.form.get('reg'))
            ownership_type = request.form.get('ownership_type', 'egen')
            if ownership_type not in {'egen', 'företag', 'lånad', 'hyrbil'}:
                ownership_type = 'egen'
            if not reg:
                flash('Ange registreringsnummer.', 'warning')
            else:
                try:
                    db.execute(
                        "INSERT INTO vehicles (tenant_id, household_id, reg, type, ownership_type) VALUES (?, ?, ?, 'resident', ?)",
                        (tenant['id'], hid, reg, ownership_type),
                    )
                    db.commit()
                    flash('Fordon tillagt.', 'success')
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash('Det registreringsnumret finns redan.', 'warning')
        return redirect(url_for('admin_manage_household', hid=hid, t=tenant['slug']))

    vehicles = db.execute(
        "SELECT * FROM vehicles WHERE household_id=? AND tenant_id=?",
        (hid, tenant['id']),
    ).fetchall()
    residents = db.execute(
        "SELECT * FROM users WHERE household_id=? AND (tenant_id=? OR tenant_id IS NULL)",
        (hid, tenant['id']),
    ).fetchall()

    return render_template(
        'admin_manage_household.html',
        tenant=tenant,
        household=household,
        vehicles=vehicles,
        residents=residents,
    )


@app.route("/admin/household/<int:hid>/add_resident", methods=["POST"])
@role_required('admin','superadmin')
def admin_add_resident(hid):
    r = require_tenant_or_redirect()
    if r:
        return r
    tenant = get_current_tenant()
    if not tenant:
        return redirect(url_for('admin_dashboard'))
    db = get_db()
    household = db.execute(
        "SELECT id FROM households WHERE id=? AND tenant_id=?",
        (hid, tenant['id']),
    ).fetchone()
    if not household:
        abort(404)

    email = (request.form.get('new_email') or '').strip().lower()
    if not email:
        flash('Ange e-postadress.', 'warning')
        return redirect(url_for('admin_manage_household', hid=hid, t=tenant['slug']))

    password = generate_password()
    try:
        db.execute(
            "INSERT INTO users (tenant_id, household_id, email, pw_hash, role) VALUES (?,?,?,?,?)",
            (tenant['id'], hid, email, hash_password(password), 'resident'),
        )
        db.commit()
        flash(f"Boende {email} skapad (lösenord: {password})", 'success')
    except sqlite3.IntegrityError:
        db.rollback()
        flash('E-postadressen används redan.', 'warning')

    return redirect(url_for('admin_manage_household', hid=hid, t=tenant['slug']))



@app.route("/admin/household/<int:hid>/remove_resident/<int:uid>", methods=["POST"])
@role_required('admin','superadmin')
def admin_remove_resident(hid, uid):
    r = require_tenant_or_redirect()
    if r:
        return r
    tenant = get_current_tenant()
    if not tenant:
        return redirect(url_for('admin_dashboard'))
    db = get_db()
    cursor = db.execute(
        "DELETE FROM users WHERE id=? AND household_id=? AND tenant_id=?",
        (uid, hid, tenant['id']),
    )
    db.commit()
    if cursor.rowcount:
        flash('Användare borttagen från hushållet', 'info')
    else:
        flash('Användaren hittades inte.', 'warning')
    return redirect(url_for('admin_manage_household', hid=hid, t=tenant['slug']))


@app.route("/admin/household/<int:hid>/delete", methods=["POST"])
@role_required('admin','superadmin')
def admin_delete_household(hid):
    r = require_tenant_or_redirect()
    if r:
        return r
    tenant = get_current_tenant()
    if not tenant:
        return redirect(url_for('admin_dashboard'))
    db = get_db()
    db.execute(
        "DELETE FROM vehicles WHERE household_id=? AND tenant_id=?",
        (hid, tenant['id']),
    )
    db.execute(
        "DELETE FROM users WHERE household_id=? AND tenant_id=?",
        (hid, tenant['id']),
    )
    household_cur = db.execute(
        "DELETE FROM households WHERE id=? AND tenant_id=?",
        (hid, tenant['id']),
    )
    db.commit()
    if household_cur.rowcount:
        flash('Hushållet har raderats', 'success')
    else:
        flash('Hushållet kunde inte hittas.', 'warning')
    return redirect(url_for('admin_dashboard', t=tenant['slug']))

@app.route('/admin/create-household', methods=['GET','POST'])
@role_required('admin','superadmin')
def admin_create_household():
    r = require_tenant_or_redirect()
    if r: return r
    db = get_db()
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        resident_email = request.form.get('resident_email','').strip().lower()
        if not name:
            flash('Ange namn.'); return redirect(url_for('admin_create_household', t=g.tenant['slug']))
        code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(8))
        db.execute("INSERT INTO households (tenant_id, name, invite_code) VALUES (?, ?, ?)", (g.tenant['id'], name, code)); db.commit()
        # defaults
        if not db.execute("SELECT 1 FROM settings WHERE tenant_id=? AND key='max_guest_hours'", (g.tenant['id'],)).fetchone():
            db.execute("INSERT INTO settings (tenant_id, key, value) VALUES (?, 'max_guest_hours', '24')", (g.tenant['id'],)); db.commit()
        if not db.execute("SELECT 1 FROM settings WHERE tenant_id=? AND key='max_resident_vehicles'", (g.tenant['id'],)).fetchone():
            db.execute("INSERT INTO settings (tenant_id, key, value) VALUES (?, 'max_resident_vehicles', '1')", (g.tenant['id'],)); db.commit()
        hid = db.execute("SELECT id FROM households WHERE tenant_id=? AND invite_code=?", (g.tenant['id'], code)).fetchone()['id']
        guest_link = url_for('guest_register', _external=True) + f"?t={g.tenant['slug']}"
        qr_svg = ""
        resident_password = None
        if resident_email:
            resident_password = ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(12))
            try:
                db.execute("INSERT INTO users (tenant_id, household_id, email, pw_hash, role) VALUES (?, ?, ?, ?, 'resident')",
                           (g.tenant['id'], hid, resident_email, generate_password_hash(resident_password))); db.commit()
            except sqlite3.IntegrityError:
                resident_password = "(oförändrat)"; flash('Boende-e-post används redan – skapade hushållet ändå.')
        return render_template('admin_create_household.html', created=True, tenant=g.tenant,
                               household=dict(name=name, invite_code=code),
                               resident_link=url_for('resident_vehicles', household_code=code, _external=True) + f"?t={g.tenant['slug']}",
                               guest_link=guest_link, qr_svg=qr_svg,
                               resident_email=(resident_email if resident_email else None),
                               resident_password=resident_password)
    return render_template('admin_create_household.html', created=False, tenant=g.tenant)

@app.route('/admin/settings', methods=['GET','POST'])
@role_required('admin','superadmin')
def admin_settings():
    r = require_tenant_or_redirect()
    if r: return r
    db = get_db(); tid = g.tenant['id']
    if request.method == 'POST':
        hours = request.form.get('max_guest_hours', type=int)
        max_resident = request.form.get('max_resident_vehicles', type=int)
        if not hours or hours < 1 or hours > 72: flash('Välj gästtimmar 1–72.')
        else: db.execute("INSERT INTO settings (tenant_id,key,value) VALUES (?, 'max_guest_hours', ?) ON CONFLICT(tenant_id,key) DO UPDATE SET value=excluded.value", (tid, str(hours))); db.commit()
        if not max_resident or max_resident < 1 or max_resident > 5: flash('Välj boendefordon 1–5.')
        else: db.execute("INSERT INTO settings (tenant_id,key,value) VALUES (?, 'max_resident_vehicles', ?) ON CONFLICT(tenant_id,key) DO UPDATE SET value=excluded.value", (tid, str(max_resident))); db.commit(); flash('Inställningar sparade.')
        return redirect(url_for('admin_settings', t=g.tenant['slug']))
    def getset(k, d):
        r = db.execute("SELECT value FROM settings WHERE tenant_id=? AND key=?", (tid, k)).fetchone()
        return int(r['value']) if r else d
    return render_template('admin_settings.html', tenant=g.tenant,
                           max_guest_hours=getset('max_guest_hours', 24),
                           max_resident_vehicles=getset('max_resident_vehicles', 1))


@app.get('/admin/users')
@role_required('admin')
def admin_users():
    r = require_tenant_or_redirect()
    if r: return r
    db = get_db()
    users = db.execute(
        """
        SELECT DISTINCT u.id, u.email
        FROM users u
        JOIN user_tenants ut ON ut.user_id=u.id
        WHERE ut.tenant_id=? AND ut.role='resident'
        ORDER BY u.email
        """,
        (g.tenant['id'],),
    ).fetchall()
    return render_template('admin_users.html', users=users, tenant=g.tenant)


@app.post('/admin/users/<int:user_id>/reset')
@role_required('admin')
def admin_reset_user(user_id):
    r = require_tenant_or_redirect()
    if r: return r
    db = get_db()
    own = db.execute(
        """
        SELECT 1 FROM user_tenants
        WHERE user_id=? AND tenant_id=? AND role='resident'
        """,
        (user_id, g.tenant['id']),
    ).fetchone()
    if not own:
        abort(403)
    pw = generate_password()
    db.execute(
        "UPDATE users SET pw_hash=? WHERE id=?",
        (hash_password(pw), user_id),
    )
    db.commit()
    flash(f'Nytt lösenord: {pw} (visa en gång).', 'success')
    return redirect(url_for('admin_users') + f'?t={g.tenant["slug"]}')


@app.get('/admin/export/vehicles.csv')
@role_required('admin','superadmin')
def export_vehicles_csv():
    r = require_tenant_or_redirect()
    if r: return r
    db = get_db()
    rows = db.execute("""
      SELECT v.reg, v.type, v.ownership_type, v.valid_to, h.name as household
      FROM vehicles v JOIN households h ON v.household_id = h.id
      WHERE v.tenant_id=?
      ORDER BY v.type DESC, v.created_at DESC
    """, (g.tenant['id'],)).fetchall()
    si = io.StringIO(); w = csv.writer(si)
    w.writerow(['reg','type','ownership_type','valid_to','household'])
    for rr in rows: w.writerow([rr['reg'], rr['type'], rr['ownership_type'] or '', rr['valid_to'] or '', rr['household']])
    out = make_response(si.getvalue()); out.headers['Content-Type']='text/csv'
    out.headers['Content-Disposition']=f'attachment; filename="vehicles_{g.tenant["slug"]}.csv"'; return out

# -------- Resident --------
@app.get('/resident/<household_code>')
@role_required('resident','admin','superadmin')
def resident_vehicles(household_code):
    r = require_tenant_or_redirect()
    if r: return r
    db = get_db(); hh = db.execute("SELECT * FROM households WHERE tenant_id=? AND invite_code=?", (g.tenant['id'], household_code)).fetchone()
    if not hh: return ("Hushåll hittades inte", 404)
    u = get_current_user()
    if u['role']=='resident' and u['household_id'] != hh['id']: abort(403)
    vs = db.execute("SELECT id, reg, type, ownership_type FROM vehicles WHERE tenant_id=? AND household_id=? ORDER BY type DESC, created_at DESC", (g.tenant['id'], hh['id'])).fetchall()
    def getset(k, d):
        r = db.execute("SELECT value FROM settings WHERE tenant_id=? AND key=?", (g.tenant['id'], k)).fetchone()
        return int(r['value']) if r else d
    return render_template('resident_vehicles.html', household=hh, vehicles=[dict(x) for x in vs],
                           max_hours=getset('max_guest_hours', 24), max_resident=getset('max_resident_vehicles', 1),
                           tenant_slug=g.tenant['slug'])

@app.post('/resident/add')
@role_required('resident','admin','superadmin')
def resident_add_vehicle():
    r = require_tenant_or_redirect()
    if r: return r
    db = get_db(); u = get_current_user()
    hid = request.args.get('hid', type=int)
    if u['role']=='resident' and u['household_id'] != hid: abort(403)
    reg = normalize_reg(request.form.get('reg','')); ownership_type = request.form.get('ownership_type','egen')
    if not re.match(r'^[A-ZÅÄÖ]{3}(?:\d{3}|\d{2}[A-ZÅÄÖ])$', reg):
        flash('Ogiltigt registreringsnummer.'); return redirect(request.referrer or url_for('home'))
    rset = db.execute("SELECT value FROM settings WHERE tenant_id=? AND key='max_resident_vehicles'", (g.tenant['id'],)).fetchone()
    max_resident = int(rset['value']) if rset else 1
    c = db.execute("SELECT COUNT(*) c FROM vehicles WHERE tenant_id=? AND household_id=? AND type='resident'", (g.tenant['id'], hid)).fetchone()['c']
    if c >= max_resident:
        flash(f'Du har redan max {max_resident} registrerade fordon.'); return redirect(request.referrer or url_for('home'))
    try:
        db.execute("INSERT INTO vehicles (tenant_id, household_id, reg, type, ownership_type, added_by) VALUES (?, ?, ?, 'resident', ?, 'resident')", (g.tenant['id'], hid, reg, ownership_type)); db.commit(); flash('Fordon tillagt.')
    except sqlite3.IntegrityError:
        flash('Det registreringsnumret finns redan.')
    return redirect(request.referrer or url_for('home'))

@app.post('/resident/delete/<int:vehicle_id>')
@role_required('resident','admin','superadmin')
def resident_delete_vehicle(vehicle_id):
    r = require_tenant_or_redirect()
    if r: return r
    db = get_db(); u = get_current_user(); hid = request.args.get('hid', type=int)
    if u['role']=='resident' and u['household_id'] != hid: abort(403)
    reason = request.form.get('reason','Annat')
    row = db.execute("SELECT reg FROM vehicles WHERE id=? AND tenant_id=? AND household_id=? AND type='resident'", (vehicle_id, g.tenant['id'], hid)).fetchone()
    if row:
        reg_old = row['reg']
        db.execute("DELETE FROM vehicles WHERE id=? AND tenant_id=? AND household_id=? AND type='resident'", (vehicle_id, g.tenant['id'], hid))
        db.execute("INSERT INTO vehicle_changes (tenant_id, household_id, reg_old, reg_new, reason, changed_by) VALUES (?, ?, ?, NULL, ?, 'resident')", (g.tenant['id'], hid, reg_old, reason)); db.commit()
        flash('Fordon borttaget.')
    return redirect(request.referrer or url_for('home'))

@app.post('/resident/guest-link')
@role_required('resident','admin','superadmin')
def resident_new_guest_link():
    r = require_tenant_or_redirect()
    if r: return r
    db = get_db(); u = get_current_user(); hid = request.args.get('hid', type=int)
    if u['role']=='resident' and u['household_id'] != hid: abort(403)
    hh = db.execute("SELECT * FROM households WHERE id=? AND tenant_id=?", (hid, g.tenant['id'])).fetchone()
    if not hh: return ("Hushåll hittades inte", 404)
    rset = db.execute("SELECT value FROM settings WHERE tenant_id=? AND key='max_guest_hours'", (g.tenant['id'],)).fetchone()
    max_hours = int(rset['value']) if rset else 24
    hours = request.form.get('hours', type=int) or max_hours
    if hours < 1 or hours > max_hours: hours = max_hours
    now = datetime.datetime.utcnow(); exp = now + datetime.timedelta(hours=72)
    payload = dict(tid=g.tenant['id'], hid=hid, iat=int(now.timestamp()), exp=int(exp.timestamp()))
    token = jwt.encode(payload, os.environ.get('JWT_SECRET', 'dev-jwt-secret'), algorithm='HS256')
    db.execute("INSERT INTO guest_tokens (tenant_id, household_id, token, expires_at) VALUES (?, ?, ?, ?)", (g.tenant['id'], hid, token, exp.isoformat())); db.commit()
    guest_link = url_for('guest_register', _external=True) + f"?t={g.tenant['slug']}&token={token}"
    qr = qrcode.make(guest_link)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    qr_svg = f"<img src='data:image/png;base64,{qr_b64}' alt='QR code' style='width:160px'>"
    vs = db.execute("SELECT id, reg, type, ownership_type FROM vehicles WHERE tenant_id=? AND household_id=? ORDER BY type DESC, created_at DESC", (g.tenant['id'], hid)).fetchall()
    rset2 = db.execute("SELECT value FROM settings WHERE tenant_id=? AND key='max_resident_vehicles'", (g.tenant['id'],)).fetchone()
    max_res = int(rset2['value']) if rset2 else 1
    return render_template('resident_vehicles.html', household=hh, vehicles=[dict(x) for x in vs],
                           guest_link=guest_link, qr_svg=qr_svg, max_hours=max_hours, max_resident=max_res, tenant_slug=g.tenant['slug'])

@app.get('/admin/billing.csv')
@role_required('superadmin')
def admin_billing_csv():
    # Kräver att en tenant är vald via ?t=slug (precis som admin-sidorna)
    r = require_tenant_or_redirect()
    if r: 
        return r

    db = get_db()
    month = request.args.get('month') or datetime.datetime.utcnow().strftime("%Y-%m")
    try:
        unit_price = float(request.args.get('unit_price') or 0)
    except ValueError:
        unit_price = 0.0

    # Enkelt underlag: antal hushåll * enhetspris
    hh_count = db.execute("SELECT COUNT(*) AS c FROM households WHERE tenant_id=?", (g.tenant['id'],)).fetchone()['c']
    amount = unit_price * hh_count

    si = io.StringIO()
    w = csv.writer(si)
    w.writerow(['tenant', 'month', 'households', 'unit_price', 'amount'])
    w.writerow([g.tenant['slug'], month, hh_count, f"{unit_price:.2f}", f"{amount:.2f}"])

    resp = make_response(si.getvalue())
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = f'attachment; filename="billing_{g.tenant["slug"]}_{month}.csv"'
    return resp

# -------- Kontroll --------
@app.route('/guest', methods=['GET','POST'])
def guest_register():
    r = require_tenant_or_redirect()
    if r: return r
    db = get_db()
    token = request.values.get('token','')
    try:
        payload = jwt.decode(token, os.environ.get('JWT_SECRET', 'dev-jwt-secret'), algorithms=['HS256'])
        tid, hid = payload.get('tid'), payload.get('hid')
        ok = db.execute("SELECT 1 FROM guest_tokens WHERE token=? AND expires_at > ? AND tenant_id=? AND household_id=?", (token, datetime.datetime.utcnow().isoformat(), tid, hid)).fetchone()
        if not ok: return render_template('guest_register.html', error="Ogiltig eller utgången QR-länk.", household={'name':'(okänd)'}, token=token, max_hours=24)
    except Exception:
        return render_template('guest_register.html', error="Ogiltig eller utgången QR-länk.", household={'name':'(okänd)'}, token=token, max_hours=24)
    hh = db.execute("SELECT * FROM households WHERE id=? AND tenant_id=?", (hid, tid)).fetchone()
    if not g.tenant or g.tenant['id'] != tid: g.tenant = db.execute("SELECT * FROM tenants WHERE id=?", (tid,)).fetchone()
    rset = db.execute("SELECT value FROM settings WHERE tenant_id=? AND key='max_guest_hours'", (tid,)).fetchone()
    max_hours = int(rset['value']) if rset else 24
    if request.method == 'POST':
        reg = normalize_reg(request.form.get('reg','')); hours = request.form.get('hours', type=int)
        if not re.match(r'^[A-ZÅÄÖ]{3}(?:\d{3}|\d{2}[A-ZÅÄÖ])$', reg):
            return render_template('guest_register.html', error="Ogiltigt registreringsnummer.", household=hh, token=token, max_hours=max_hours)
        if hours is None or hours < 1 or hours > max_hours:
            return render_template('guest_register.html', error=f"Välj timmar 1–{max_hours}.", household=hh, token=token, max_hours=max_hours)
        valid_to = (datetime.datetime.utcnow() + datetime.timedelta(hours=hours)).isoformat()
        existing = db.execute("SELECT id, type FROM vehicles WHERE tenant_id=? AND household_id=? AND reg = ?", (tid, hid, reg)).fetchone()
        if existing and existing['type'] == 'resident':
            return render_template('guest_register.html', household=hh, token=token, max_hours=max_hours, valid_to=valid_to)
        if existing and existing['type'] == 'guest':
            db.execute("UPDATE vehicles SET valid_to=?, added_by='guest' WHERE id=?", (valid_to, existing['id']))
        else:
            db.execute("INSERT INTO vehicles (tenant_id, household_id, reg, type, valid_to, added_by) VALUES (?, ?, ?, 'guest', ?, 'guest')", (tid, hid, reg, valid_to))
        db.commit()
        return render_template('guest_register.html', household=hh, token=token, max_hours=max_hours, valid_to=valid_to)
    return render_template('guest_register.html', household=hh, token=token, max_hours=max_hours)

@app.get('/status')
@role_required('admin','superadmin')
def status_page():
    r = require_tenant_or_redirect()
    if r: return r
    reg = request.args.get('reg','')
    if not reg: return render_template('status.html', result=None, reg='')
    nreg = normalize_reg(reg); db = get_db(); now_iso = datetime.datetime.utcnow().isoformat()
    row = db.execute("""
        SELECT v.type, v.valid_to, h.name as household
        FROM vehicles v JOIN households h ON v.household_id = h.id
        WHERE v.tenant_id=? AND v.reg = ?
    """, (g.tenant['id'], nreg)).fetchone()
    result = dict(status='unknown', type=None, household=None, valid_to=None)
    if row:
        if row['type']=='resident': result.update(status='allowed', type='resident', household=row['household'], valid_to=None)
        elif row['type']=='guest':
            if row['valid_to'] and row['valid_to'] > now_iso: result.update(status='allowed', type='guest', household=row['household'], valid_to=row['valid_to'])
            else: result.update(status='expired', type='guest', household=row['household'], valid_to=row['valid_to'])
    db.execute("INSERT INTO scans (tenant_id, reg, result, household_id) VALUES (?, ?, ?, NULL)", (g.tenant['id'], nreg, result['status'])); db.commit()
    if request.args.get('format') == 'json' or request.headers.get('Accept') == 'application/json': return jsonify(result)
    return render_template('status.html', result=result, reg=nreg)

@app.get('/healthz')
def healthz():
    return {'ok': True, 'version': VERSION}

if __name__ == '__main__':
    app.run(debug=True)
