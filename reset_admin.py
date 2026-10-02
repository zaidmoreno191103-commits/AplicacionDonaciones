from main import app, db, Usuario
from werkzeug.security import generate_password_hash
    
NUEVA_PASSWORD = 'Admin12345'

with app.app_context():
    print("BD en uso:", app.config['SQLALCHEMY_DATABASE_URI'])
    u = Usuario.query.filter_by(email='admin@donaciones.com').first()
    if u is None:
        u = Usuario(nombre='Administrador General', email='admin@donaciones.com',
                    rol='admin', password='')
        db.session.add(u)
    u.rol = 'admin'
    u.password = generate_password_hash(NUEVA_PASSWORD)
    db.session.commit()
    print([(x.email, x.rol) for x in Usuario.query.all()])