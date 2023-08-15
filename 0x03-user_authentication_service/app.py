#!/usr/bin/env python3
"""App
"""
from auth import Auth
from flask import Flask, jsonify, request, abort, make_response, redirect


app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """Routes"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users() -> str:
    """Registers user"""
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": f"{user.email}",
                       "message": "user created"}), 200
    except Exception as e:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> str:
    """Login through sessions"""
    email = request.form.get("email")
    password = request.form.get("password")

    result = AUTH.valid_login(email, password)
    if not result:
        abort(401)
    session = AUTH.create_session(email)
    response = make_response(jsonify({"email": f"{email}",
                                     "message": "logged in"}))
    response.set_cookie("session_id", session)
    return response


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout():
    """Destroy sessions"""
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if session_id is None or user is None:
        abort(403)
    print(session_id)
    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile():
    """Get profile"""
    session_id = request.cookies.get("session_id")
    if session_id is None:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    return jsonify({"user": user.email}), 200


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def reset_password():
    """reset password"""
    email = request.form.get("email")
    validate = AUTH.create_session(email)
    if not validate:
        abort(403)
    reset_token = AUTH.get_reset_password_token(email)
    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route("/reset_password", methods=["PUT"], strict_slashes=False)
def update_password():
    """updates password"""
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    password = request.form.get("new_password")
    try:
        AUTH.update_password(reset_token, password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except Exception as error:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000", debug=True)
