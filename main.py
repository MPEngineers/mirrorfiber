#!/usr/bin/env python

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, FileResponse, HTMLResponse
import os
from dotenv import load_dotenv
import jwt
from urllib.parse import parse_qs
from datetime import datetime
import logging

load_dotenv()

ALGORITHM = "HS256"
JALFRY_JWT_KEY = os.getenv("JALFRY_JWT_KEY")

log = logging.getLogger()
app = FastAPI()

def verify_token(encoded_jwt):
    try:
        if encoded_jwt == None:
            return {
                "status": False
            }
        payload = jwt.decode(encoded_jwt, JALFRY_JWT_KEY, algorithms=[ALGORITHM])
        expiration_datetime = datetime.fromisoformat(payload["expiration"].rstrip("Z")).date()
        today_date = datetime.now().date()
        if payload and expiration_datetime == today_date:
            return {
                "status": True,
                "payload": payload
            }
        return {
            "status": False
        }
    except Exception as e:
        print("Error in decode_token: ", e)
        return {
            "status": False
        }

@app.get("/")
def root(request: Request):
    return FileResponse("static/index.html")

@app.get("/login")
def redirect_to_jalfry(request: Request):
    jalfry_url = "https://jalfry.com/login"
    app_domain = request.url.hostname
    return RedirectResponse(url=f"{jalfry_url}/{app_domain}")

@app.get("/dashboard")
def dashboard(request: Request):
    token = request.cookies.get("auth_token")
    status = verify_token(token)
    if not status["status"]:
        return RedirectResponse(url="/login")
    # return FileResponse("static/dashboard.html")
    log.debug(f"{token=}")
    token = jwt.decode(token, JALFRY_JWT_KEY, algorithms=[ALGORITHM])
    content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <style>
        body {{
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            flex-direction: column;
            background-color: #f4f4f4;
            font-family: Arial, sans-serif;
            margin: 0;
        }}
        h1 {{
            font-size: 3rem;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <h1>Welcome, {token["email"]}</h1>
</body>
</html>
"""
    return HTMLResponse(content=content, status_code=200)

@app.get("/sso/{token}")
def handle_jalfry_callback(token: str):
    try:
        decoded_token = jwt.decode(token, JALFRY_JWT_KEY, algorithms=[ALGORITHM])
        log.debug(f"{decoded_token=}")
        email = decoded_token['email']

        # Dhaval: Here is probably where we would redirect to pyvix to check for authorization level before finally redirecting to /dashboard

        response = RedirectResponse(url="/dashboard", status_code=302)
        response.set_cookie(
            key="auth_token",
            value=token,
            max_age=60*60*24,
            httponly=True,
            secure=False,
            samesite="Lax",
        )
        return response
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Unauthorized: Expired sso token")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid sso token")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3002)
