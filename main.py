import math
import os
import secrets
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__,
            template_folder=os.path.join(basedir, 'templates'),
            static_folder=os.path.join(basedir, 'static'))

app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL')
    or 'sqlite:///' + os.path.join(basedir, 'database.db')
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)


# --- MODELOS ---

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # hash
    rol = db.Column(db.String(20), nullable=False, default='user')  # 'admin' o 'user'


class Donacion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    monto = db.Column(db.Float, nullable=False)
    beneficiario = db.Column(db.String(150), nullable=False)


beneficiarios_db = [
    "Fundación de Apoyo Infantil",
    "Asilo de Ancianos San José",
    "Comedor Comunitario Esperanza",
    "Rescate Animal Patitas"
]


# --- UTILIDADES ---

def password_es_hash(valor):
    return valor.startswith(("scrypt:", "pbkdf2:"))


def verificar_password(usuario, password):
    """Verifica la contraseña. Si hay una en texto plano (versión anterior),
    la acepta una vez y la convierte a hash."""
    if password_es_hash(usuario.password):
        return check_password_hash(usuario.password, password)
    if secrets.compare_digest(usuario.password, password):
        usuario.password = generate_password_hash(password)
        db.session.commit()
        return True
    return False


def parsear_monto(valor):
    try:
        monto = float(valor)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(monto) or monto <= 0:
        return None
    return round(monto, 2)


def es_peticion_fetch():
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        if session.get('rol') != 'admin':
            return "Acceso denegado. Se requiere cuenta de Administrador.", 403
        return f(*args, **kwargs)
    return wrapper


# --- DATOS INICIALES ---

with app.app_context():
    db.create_all()
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@donaciones.com")
    admin_pass = os.environ.get("ADMIN_PASSWORD", "123")

    if not Usuario.query.filter_by(email=admin_email).first():
        db.session.add(Usuario(nombre="Administrador General", email=admin_email,
                                password=generate_password_hash(admin_pass), rol="admin"))
    if not Usuario.query.filter_by(email="user@donaciones.com").first():
        db.session.add(Usuario(nombre="Juan Pérez", email="user@donaciones.com",
                                password=generate_password_hash("123"), rol="user"))
    db.session.commit()


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'"
    )
    return response


# --- RUTAS ---

@app.route('/')
@login_required
def index():
    ultimas_donaciones = Donacion.query.order_by(Donacion.id.desc()).limit(3).all()
    return render_template('index.html', donaciones=ultimas_donaciones,
                            rol=session.get('rol'))


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = (request.form.get('nombre') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''

        if not nombre or not email or len(password) < 6:
            return render_template(
                'registro.html',
                error="Completa todos los campos (contraseña de al menos 6 caracteres)."
            ), 400

        if Usuario.query.filter_by(email=email).first():
            return render_template('registro.html',
                                    error="El correo ya está registrado."), 400

        db.session.add(Usuario(nombre=nombre, email=email,
                                password=generate_password_hash(password),
                                rol='user'))
        db.session.commit()
        return redirect(url_for('login_page'))

    return render_template('registro.html')


@app.route('/login', methods=['GET'])
def login_page():
    if 'user' in session:
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''

    usuario = Usuario.query.filter_by(email=email).first()

    if usuario and verificar_password(usuario, password):
        session.clear()  # evita fijación de sesión
        session['user'] = usuario.email
        session['nombre'] = usuario.nombre
        session['rol'] = usuario.rol

        destino = (url_for('admin_dashboard_web') if usuario.rol == 'admin'
                    else url_for('index'))

        if es_peticion_fetch():
            return jsonify({"ok": True, "redirect": destino})
        return redirect(destino)

    if es_peticion_fetch():
        return jsonify({"error": "Correo o contraseña incorrectos."}), 401
    return render_template('login.html', error="Credenciales inválidas"), 401


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))


@app.route('/donar', methods=['GET', 'POST'])
@login_required
def donar():
    if request.method == 'POST':
        nombre = (request.form.get('nombre') or '').strip()
        monto = parsear_monto(request.form.get('monto'))
        beneficiario = request.form.get('beneficiario')

        if not nombre or monto is None or beneficiario not in beneficiarios_db:
            return render_template('donar.html', beneficiarios=beneficiarios_db,
                                    rol=session.get('rol'),
                                    error="Datos de donación inválidos."), 400

        db.session.add(Donacion(nombre=nombre, monto=monto, beneficiario=beneficiario))
        db.session.commit()
        return redirect(url_for('historial'))

    return render_template('donar.html', beneficiarios=beneficiarios_db,
                            rol=session.get('rol'))


@app.route('/historial')
@login_required
def historial():
    todas_donaciones = Donacion.query.order_by(Donacion.id.desc()).all()
    return render_template('historial.html', donaciones=todas_donaciones,
                            rol=session.get('rol'))


@app.route('/editar/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_donacion(id):
    donacion = db.get_or_404(Donacion, id)

    if request.method == 'POST':
        nombre = (request.form.get('nombre') or '').strip()
        monto = parsear_monto(request.form.get('monto'))
        beneficiario = request.form.get('beneficiario')

        if not nombre or monto is None or beneficiario not in beneficiarios_db:
            return render_template('editar.html', donacion=donacion,
                                    beneficiarios=beneficiarios_db,
                                    rol=session.get('rol'),
                                    error="Datos de donación inválidos."), 400

        donacion.nombre = nombre
        donacion.monto = monto
        donacion.beneficiario = beneficiario
        db.session.commit()
        return redirect(url_for('historial'))

    return render_template('editar.html', donacion=donacion,
                            beneficiarios=beneficiarios_db, rol=session.get('rol'))


@app.route('/eliminar/<int:id>', methods=['POST'])
@admin_required
def eliminar_donacion(id):
    donacion = db.get_or_404(Donacion, id)
    db.session.delete(donacion)
    db.session.commit()
    return redirect(url_for('historial'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard_web():
    total_usuarios = Usuario.query.count()
    total_donaciones = Donacion.query.count()
    todas_donaciones = Donacion.query.order_by(Donacion.id.desc()).all()
    return render_template('admin_dashboard.html',
                            total_usuarios=total_usuarios,
                            total_donaciones=total_donaciones,
                            donaciones=todas_donaciones)


if __name__ == '__main__':
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000, debug=debug)