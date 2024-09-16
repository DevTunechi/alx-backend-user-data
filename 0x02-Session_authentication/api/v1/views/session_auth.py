#!/usr/bin/env python3
""" Session Authentication views """
from flask import abort, jsonify, request
from os import getenv
import os
from typing import Tuple
from models.user import User
from api.v1.views import app_views
from api.v1.app import auth


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> Tuple[str, int]:
    """
        Session Auth login handler
        Returns:
            Json representation of a User obj
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if not email or len(email.strip()) == 0:
        return jsonify({"error": "email missing"}), 400

    if not password or len(password.strip()) == 0:
        return jsonify({"error": "password missing"}), 400

    try:
        users = User.search({'email': email})
    except Exception as e:
        return jsonify({"error": "no user found for this email"}), 404

    if not users:
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    sess_id = auth.create_session(user.id)
    res = jsonify(user.to_json())
    res.set_cookie(getenv("SESSION_NAME"), sess_id)
    return res


@app_views.route('/auth_session/logout',
                 methods=['DELETE'], strict_slashes=False)
def signout() -> Tuple[str, int]:
    """
        Deletes/Destroys user session
        Return empty JSON obj
    """
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({})
