import requests
import os

from flask import Flask, render_template, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from okta_login.helpers import is_access_token_valid, is_id_token_valid
from okta_login.user import User
import random
import string
from dotenv import load_dotenv

app = Flask(__name__)
app.config.update({"SECRET_KEY": "".join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=32))})

login_manager = LoginManager()
login_manager.init_app(app)


APP_STATE = "State"
NONCE = "Nonce"
OKTA_INSTANCE_URL = ""
CLIENT_ID = ""
CLIENT_SECRET = ""
REDIRECT_URL = ""


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login")
def login():
    query_params = {"client_id": CLIENT_ID,
                    "redirect_uri": f"{REDIRECT_URL}/authorization-code/callback",
                    "scope": "openid email profile",
                    "state": APP_STATE,
                    "nonce": NONCE,
                    "response_type": "code",
                    "response_mode": "query"}

    request_url = f"{OKTA_INSTANCE_URL}/oauth2/default/v1/authorize?{requests.compat.urlencode(query_params)}"
    return redirect(request_url)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)


@app.route("/authorization-code/callback")
def callback():
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    code = request.args.get("code")
    if not code:
        return "The code not reutrned", 403
    query_params = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": request.base_url
    }
    query_params = requests.compat.urlencode(query_params)
    exchange = requests.post(
        f"{OKTA_INSTANCE_URL}/oauth2/default/v1/token",
        headers=headers,
        data=query_params,
        auth=(CLIENT_ID, CLIENT_SECRET),
    ).json()

    if not exchange.get("token_type"):
        return "Token should be 'Bearer'.", 403
    access_token = exchange["access_token"]
    id_token = exchange["id_token"]

    if not is_access_token_valid(access_token, f"{OKTA_INSTANCE_URL}/oauth2/default"):
        return "Access token is invalid", 403

    if not is_id_token_valid(id_token, f"{OKTA_INSTANCE_URL}/oauth2/default", CLIENT_ID, NONCE):
        return "ID token is invalid", 403

    userinfo_response = requests.get(f"{OKTA_INSTANCE_URL}/oauth2/default/v1/userinfo", headers={"Authorization": f"Bearer {access_token}"}).json()

    unique_id = userinfo_response["sub"]
    user_email = userinfo_response["email"]
    user_name = userinfo_response["name"]

    user = User(
        id=unique_id, name=user_name, email=user_email
    )

    if not User.get(unique_id):
        User.create(unique_id, user_name, user_email)

    login_user(user)

    return redirect(url_for("profile"))


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


if __name__ == "__main__":
    load_dotenv()
    OKTA_INSTANCE_URL = os.environ.get("OKTA_INSTANCE_URL")
    CLIENT_ID = os.environ.get("CLIENT_ID")
    CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
    REDIRECT_URL = os.environ.get("REDIRECT_URL")
    app.run(host="localhost", port=8080, debug=False)
