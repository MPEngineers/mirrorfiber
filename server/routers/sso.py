from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from utilities.auth import  SECRET_KEY, ALGORITHM, generate_token, verify_token
from datetime import datetime
import jwt
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from fastapi import Depends
from db_connection.connection import get_db
import os
from dotenv import load_dotenv
import logging

router = APIRouter()

load_dotenv()

JALFRY_JWT_KEY = os.getenv("JALFRY_JWT_KEY")
ALGORITHM = os.getenv("ALGORITHM")
log = logging.getLogger()


def db_user_data_from_email(email: str, db: Session):
    try:
        # Query user and also check that they have active access to the application
        print("email: ", email)
        
        # Raw SQL query to check email and get role for mirriorfiber app
        query = """
        SELECT 
            u.id, u.phone, u.name, u.username, r.name as role_name
        FROM 
            users u
        JOIN 
            user_access ua ON u.id = ua.user_id
        JOIN 
            roles r ON ua.role_id = r.id
        JOIN 
            applications a ON ua.application_id = a.id
        WHERE 
            u.email = :email
            AND a.name = 'mirrorfiber'
            AND ua.is_active = TRUE
        """
        
        # Create a SQLAlchemy text object with parameters bound directly
        stmt = text(query).bindparams(email=email)
        result = db.execute(stmt).first()
        
        print("query result: ", result)
        if result:
            # User exists and has access to the application
            return {
                "status": True,
                "data": {
                    "phone": result.phone,
                    "id": result.id,
                    "name": result.name,
                    "username": result.username,
                    "role": result.role_name  # Use the actual role from database
                }
            }
        # No user found or user doesn't have active access
        return {
            "status": False,
            "description": "User doesn't exist or doesn't have permission to access this application"
        }
    except Exception as e:
        print(f"Error in db_user_data_from_email: {e}")
        import traceback
        traceback.print_exc()
        return {
            "status": False,
            "description": "Error checking user permissions"
        }

@router.get("/sso/{token}")
def handle_jalfry_callback(token: str):
    data = verify_token(token)

    if data["status"] == False: 
        return RedirectResponse(url='https://jalfry.com/login/mirrorfiber.com')
    db = next(get_db())
    user_data = db_user_data_from_email(data["payload"]["email"], db)
    if user_data["status"]==False:
        return RedirectResponse(url='https://jalfry.com/login/mirrorfiber.com')
    user_data = user_data["data"]

    token = generate_token(user_data["phone"], user_data["name"], user_data["username"], user_data["role"], user_data["id"])
    if token["status"]==False:
        return {"status": False, "description": "Could not generate token: STA291"}
    token = token["token"]
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="jwt_token", value=token, httponly=True, secure=True, samesite="none")
    return response