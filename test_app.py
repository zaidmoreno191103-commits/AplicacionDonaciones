import os
import sys
import pytest

# Python debe buscar los archivos en la misma carpeta
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from main import app, donaciones_registradas

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_pagina_principal(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b"Plataforma de Donaciones" in response.data  # O el texto que tengas en tu h1/navbar

def test_registrar_donacion(client):
    response = client.post('/donar', data={
        "nombre": "Test Local",
        "monto": "500"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Test Local" in response.data

def test_login_exitoso(client):
    """Verifica que un usuario válido pueda iniciar sesión y recibir un token JWT."""
    response = client.post('/login', data={
        'email': 'admin@donaciones.com',
        'password': '123'
    })
    assert response.status_code == 200
    json_data = response.get_json()
    assert 'access_token' in json_data

def test_admin_dashboard_con_permisos(client):
    """Verifica que un administrador pueda acceder al dashboard protegido."""
    # Primero obtenemos el token de admin
    res_login = client.post('/login', data={
        'email': 'admin@donaciones.com',
        'password': '123'
    })
    token = res_login.get_json()['access_token']

    # Consultamos la ruta protegida enviando el token en los headers
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get('/admin/dashboard', headers=headers)
    assert response.status_code == 200
    assert b"Bienvenido al panel de administracion" in response.data or response.get_json().get("mensaje") is not None