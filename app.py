from uuid import uuid4
from datetime import datetime, timedelta
import json

from flask import Flask, jsonify, request
import jwt
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask_basicauth import BasicAuth

from scope import Scope


app = Flask(__name__)
app.debug = True

basic_auth = BasicAuth(app)

TOKEN_VALID_FOR_SECONDS = 3600

app.config['SERVICE'] = 'kdreyer-registry'  # eg. "registry.ceph.com"
app.config['ISSUER'] = 'kdreyer-registry'  # eg. "registry-auth.ceph.com"
app.config['BASIC_AUTH_USERNAME'] = 'admin'
app.config['BASIC_AUTH_PASSWORD'] = 'pass'
app.config['BASIC_AUTH_REALM'] = app.config['ISSUER']


# To generate a cert and key:
# openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=kdreyer-registry'


def get_certificate():
    """Return a cryptography.x509.Certificate object"""
    with open('cert.pem', 'rb') as cert_file:
        return load_pem_x509_certificate(cert_file.read(),
                                         default_backend())

def get_private_key():
    with open('key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        return private_key


def get_token_payload(service, issuer, scopes):
    now = datetime.utcnow()
    token_payload = {
                     'iss' : issuer,
                     'sub' : 'test',  # XXX?
                     'aud' : service,
                     'exp' : now + timedelta(seconds=TOKEN_VALID_FOR_SECONDS),
                     'nbf' : now,
                     'iat' : now,
                     'jti' : uuid4().get_hex(),
                     'access' : [
                                {
                                 'type' : scope.type,
                                 'name' : scope.name,
                                 'actions' : scope.actions
                                 }
                                for scope in scopes
                                 ]
                     }
    # app.logger.debug(('token', token_payload))
    return token_payload


def construct_token_response(service, issuer, scopes):
    token_payload = get_token_payload(service, issuer, scopes)
    cert = get_certificate()
    x5c = cert.public_bytes(serialization.Encoding.PEM)
    x5c = x5c.replace('\n', '')
    x5c = x5c.replace('-----BEGIN CERTIFICATE-----', '')
    x5c = x5c.replace('-----END CERTIFICATE-----', '')
    response_payload = {
        'token' : jwt.encode(token_payload,
                             get_private_key(),
                             headers = {
                                 'x5c':[x5c]
                             },
                             algorithm='RS256'),
        'expires_in' : 3600,
        'issued_at' : datetime.utcnow().isoformat() + 'Z'
    }
    #app.logger.debug(('response', json.dumps(response_payload)))

    decoded = jwt.decode(response_payload['token'],
                        get_private_key(),
                        verify=False)
    # app.logger.debug(('decoded', json.dumps(decoded)))
    return response_payload


def get_scopes():
    scopes = set()
    for s in request.args.getlist('scope'):
        scopes.add(Scope.parse(s))
    return scopes


def requires_auth(scopes):
    """ Determine if this HTTP request requires authentication """
    # Any action other than pulling requires authentication.
    for scope in scopes:
        if scope.actions != ['pull']:
            app.logger.debug('scope %s requires auth' % scope.name)
            return True
    # A "docker login" command request an offline token, and we should check
    # the auth attempt.
    if request.args.get('offline_token', '') == 'true':
        return True
    return False


@app.route('/token')
def token():
    """
    See https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md#requesting-a-token
    """
    try:
        service = request.args['service']
    except KeyError:
        response = jsonify({'error': 'service parameter required'})
        response.status_code = 400
        return response
    if service != app.config['SERVICE']:
        response = jsonify({'error': 'service parameter incorrect'})
        response.status_code = 400
        return response

    scopes = get_scopes()

    if requires_auth(scopes) and not basic_auth.authenticate():
        return basic_auth.challenge()

    payload = construct_token_response(service, app.config['ISSUER'], scopes)
    return jsonify(**payload)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
