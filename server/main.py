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
from db_connection.connection import get_db
from utilities.auth import verify_token
from routers import sso
from middleware import role_based_auth
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

log = logging.getLogger()
app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(sso.router)

@app.get("/")
def root(request: Request):
    return FileResponse("static/index.html")

@app.get("/login")
def redirect_to_jalfry(request: Request):
    jalfry_url = "https://jalfry.com/login"
    app_domain = request.url.hostname
    
    # Complete the redirection
    redirect_url = f"{jalfry_url}/{app_domain}"
    return RedirectResponse(url=redirect_url)

@app.get("/dashboard")
async def dashboard(request: Request):
    token = request.cookies.get("jwt_token")
    status = verify_token(token)
    if not status["status"]:
        return RedirectResponse(url="/login")
    #TODO: Remove this in production
    # role = "admin"

    # Redirect based on role
    role = status["payload"]["role"]
    if role == "sales":
        return RedirectResponse(url="/sales-dashboard")
    elif role == "technician":
        return RedirectResponse(url="/technician-dashboard")
    elif role == "customer":
        return RedirectResponse(url="/customer-dashboard")
    elif role in ["director", "admin"]:
        return RedirectResponse(url="/admin-dashboard")
    else:
        return RedirectResponse(url="/login")

@app.get("/sales-dashboard")
async def sales_dashboard(request: Request):
    user = await role_based_auth(request, ["sales", "director", "admin"])
    return FileResponse("static/sales-dashboard.html")

@app.get("/technician-dashboard")
async def technician_dashboard(request: Request):
    user = await role_based_auth(request, ["technician", "director", "admin"])
    return FileResponse("static/technician-dashboard.html")

@app.get("/customer-dashboard")
async def customer_dashboard(request: Request):
    user = await role_based_auth(request, ["customer"])
    return FileResponse("static/customer-dashboard.html")

@app.get("/admin-dashboard")
async def admin_dashboard(request: Request):
    user = await role_based_auth(request, ["director", "admin"])
    return FileResponse("static/admin-dashboard.html")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3002)
