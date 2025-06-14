import os

from time import time
from datetime import datetime
from hashlib import sha256

import requests
from requests.auth import HTTPBasicAuth

from sanic import Sanic
from sanic.response import text, redirect
from sanic.request import Request

from sanic_ext import render

import jwt

app = Sanic("SL_Auth")

app.config.SECRET = os.getenv("SECRET")
app.config.JWT = os.getenv("JWT_NAME")
app.config.NEXTCLOUD_URL = os.getenv("NEXTCLOUD_URL")
app.config.TOKEN_DURATION_SEC = int(os.getenv("TOKEN_DURATION_SEC"))
app.config.DOMAIN = os.getenv("DOMAIN")


@app.middleware("response")
async def prevent_xss(request, response):
    origin = request.headers.get("origin") or "*"

    r_method = request.method
    if r_method == "OPTIONS":
        headers = {
            "Access-Control-Allow-Methods": "OPTIONS,GET,POST",
            "Access-Control-Allow-Origin": origin,
        }
        response.headers.extend(headers)
    else:
        headers = {
            "Access-Control-Allow-Methods": "OPTIONS,GET,POST",
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": (
                "origin, content-type, accept, "
                "authorization, x-xsrf-token, x-request-id"
            ),
        }
        response.headers.extend(headers)


def check_token(request):
    sl_jwt = request.token or request.cookies.get(app.config.JWT)

    if not sl_jwt:
        return None

    try:
        token_body = jwt.decode(
            sl_jwt, request.app.config.SECRET, algorithms=["HS256"]
        )
    except jwt.exceptions.InvalidTokenError as _err:
        print("Invalid Token: {}".format(sl_jwt))
        print(_err)
        return None
    else:
        expired = token_body.get("exp")
        if expired and expired > int(time()):
            return token_body
        else:
            print("..Expired")
            return None


def _do_login(username, password):
    nextcloud_url = app.config.NEXTCLOUD_URL
    headers = {
        "OCS-APIRequest": "true",
        "Accept": "application/json"
    }

    response = requests.get(
        nextcloud_url,
        auth=HTTPBasicAuth(username, password),
        headers=headers,
    )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if response.status_code != 200:
        print(f"{now} {username} auth failed.")
        return None
    else:
        print(f"{now} {username} auth ok.")
        token = response.json()
        return str(token)


def _get_token_dict(login: str) -> dict:
    """
    Generate dict for token.
    :param login: str. username
    :return: dict.
    """
    _st = time()

    jti = sha256(str(_st).encode("utf-8")).hexdigest()

    data = {
        "username": login,
        "exp": int(_st) + app.config.TOKEN_DURATION_SEC,
        "jti": jti,
        "token_type": "access"
    }

    return data


def get_jwt(login, request):
    data = _get_token_dict(login)
    token = jwt.encode(data, request.app.config.SECRET, algorithm="HS256")

    return token


def _return_if_auth(request: Request):
    """
    Check if we have redirect path and return corresponding response type.
    :param request:
    :return:
    """
    redirect_url = request.args.get("redirect")

    if redirect_url:
        return redirect(redirect_url)
    else:
        return text("Authorized")


@app.route("/", name="login", methods=["GET", "POST"])
@app.ext.template("index.html")
async def handler(request: Request):
    if check_token(request):
        return _return_if_auth(request)

    if request.method == "POST":
        username = request.form.get("username") or ""
        password = request.form.get("password") or ""

        username = username.lower()  # Fix Case.
        username = username.replace("!", "")  # Admin Active Directory.

        print(f"Try login {username}")
        success = _do_login(username, password)
        if success:
            print("..Success")
            token = get_jwt(username, request)

            res = _return_if_auth(request)
            res.add_cookie(
                app.config.JWT,
                token,
                domain=app.config.DOMAIN,
                httponly=True,
                max_age=app.config.TOKEN_DURATION_SEC,
                samesite="Strict"
            )

            return res
        else:
            print("..Failed")
            return await render(context={}, status=401)
    elif request.method == "GET":
        return await render(context={}, status=401)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=12000)
