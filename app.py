#!/usr/bin/env python
# encoding: utf-8

import jwt
import logging
from jwt.exceptions import ExpiredSignatureError, DecodeError
from flask import Flask, request, make_response, g, jsonify
from datetime import datetime, timedelta

app = Flask(__name__)

@app.before_request
def process_token():
    token = request.cookies.get('jwt',
            request.headers.get('Authorization', 'a.b.c'))
    try:
        if request.path == "/api/auth":
            return None
        user_info = jwt.decode(token, 'secret')
        g.user_info = user_info
    except ExpiredSignatureError as e:
        logging.warning(e)
        response = make_response('You JWT has expired')
        response.status_code = 401
        return response
    except DecodeError as e:
        logging.warning(e)
        response = make_response('You JWT is invalid')
        response.status_code = 401
        return response

@app.route('/api/jwt', methods=['GET'])
def get_jwt():
    return jsonify(**g.user_info)

@app.route('/api/auth', methods=['GET'])
def login():
    token = jwt.encode({'username':"lijing",
        'role':'super_admin',
        'exp':datetime.utcnow()+timedelta(minutes=app.config.get('HAPYAK_JWT_LIFETIME', 60)),
        'iat':datetime.utcnow()},
        app.config.get('JWT_KEY', 'secret'))
    response = make_response(token)
    response.set_cookie('jwt',token)
    return response

app.run(debug=True)

