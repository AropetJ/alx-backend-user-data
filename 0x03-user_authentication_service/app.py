#!/usr/bin/env python3

from flask import Flask, jsonify, redirect, request

from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def index() -> str:
    """GET /
    Return: {"message": "Bienvenue"}"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """POST /users
    JSON body:
      - email: string -> user email
      - password: string -> user password
    Return: {"email": "<user email>", "message": "user created"}
    """
    email, password = request.form.get('email'), request.form.get('password')
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError as err:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """POST /sessions
    JSON body:
      - email: string -> user email
      - password: string -> user password
    Return: {"email": "<user email>", "message": "logged in"}
    """
    email, password = request.form.get('email'), request.form.get('password')
    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        response.set_cookie('session_id', session_id)
        return response
    else:
        return jsonify({"message": "wrong password"}), 401


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> str:
    """DELETE /sessions
    JSON body:
      - session_id: string -> session ID
    Return: {"message": "Bienvenue"}
    """
    session_id = request.cookies.get('session_id')
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            AUTH.destroy_session(user)
    return redirect('/')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5003")
