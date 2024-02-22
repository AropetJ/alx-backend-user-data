#!/usr/bin/env python3

from flask import Flask, abort, jsonify, redirect, request

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


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout() -> str:
    """DELETE /sessions
    Return: redirect to /
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect("/")


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """GET /profile
    Return: {"email": "<user email>"}
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    return jsonify({"email": user.email})


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """POST /reset_password
    JSON body:
      - email: string -> user email
    Return: {"email": "<user email>", "reset_token": "<reset" token>"}
    """
    email = request.form.get('email')
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token})
    except ValueError:
        reset_token = None
    if reset_token is None:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
