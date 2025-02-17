import pytest
from app import app
import jwt
import time

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_jwks_endpoint(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    assert "keys" in response.json

def test_auth_endpoint(client):
    response = client.post('/auth')
    assert response.status_code == 200
    assert "token" in response.json

def test_auth_endpoint_expired(client):
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    assert "token" in response.json
