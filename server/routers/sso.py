from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from utilities.auth import SECRET_KEY, ALGORITHM, generate_token, verify_token
from datetime import datetime
import jwt
import requests
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
PYVIX_URL = os.getenv("PYVIX_URL", "https://pyvix.com/api/verify_access")
APP_NAME = os.getenv("APP_NAME", "mirrorfiber")
log = logging.getLogger()

def create_verification_token(email):
    """Create a signed token for verification with Pyvix"""
    expiration = datetime.now() + datetime.timedelta(seconds=10)
    payload = {
        "email": email,
        "app_name": APP_NAME,
        "timestamp": datetime.now().isoformat(),
        "exp": int(expiration.timestamp())  # Standard JWT expiration claim
    }
    token = jwt.encode(payload, JALFRY_JWT_KEY, algorithm=ALGORITHM)
    return token

def verify_user_with_pyvix(email):
    """Verify user access with Pyvix API"""
    try:
        # Create a signed token
        token = create_verification_token(email)
        
        # Send request to Pyvix
        response = requests.post(
            PYVIX_URL,
            json={"token": token},
            headers={"Content-Type": "application/json"}
        )
        
        # Check if the request was successful
        if response.status_code != 200:
            log.error(f"Pyvix API returned status code {response.status_code}: {response.text}")
            return {
                "status": False,
                "description": f"Failed to verify access: HTTP {response.status_code}"
            }
        
        # Parse the response
        result = response.json()
        
        # Decode the returned token
        if "token" not in result:
            log.error("No token in Pyvix response")
            return {
                "status": False,
                "description": "Invalid response from verification service"
            }
        
        user_token = result["token"]
        try:
            user_data = jwt.decode(user_token, JALFRY_JWT_KEY, algorithms=[ALGORITHM])
            
            # Check if the token contains the required fields
            required_fields = ["id", "phone", "name", "username", "role"]
            if not all(field in user_data for field in required_fields):
                missing = [field for field in required_fields if field not in user_data]
                log.error(f"Missing fields in user data: {missing}")
                return {
                    "status": False,
                    "description": "Incomplete user data received"
                }
            
            return {
                "status": True,
                "data": {
                    "id": user_data["id"],
                    "phone": user_data["phone"],
                    "name": user_data["name"],
                    "username": user_data["username"],
                    "role": user_data["role"]
                }
            }
        except Exception as e:
            log.error(f"Error decoding user token: {e}")
            return {
                "status": False,
                "description": "Error processing user data"
            }
            
    except Exception as e:
        log.error(f"Error in verify_user_with_pyvix: {e}")
        import traceback
        traceback.print_exc()
        return {
            "status": False,
            "description": "Error verifying user access"
        }

@router.get("/sso/{token}")
def handle_jalfry_callback(token: str):
    data = verify_token(token)
    
    if data["status"] == False:
        return RedirectResponse(url='https://jalfry.com/login/mirrorfiber.com')
    
    # Extract email from the token
    email = data["payload"]["email"]
    
    # Verify user with Pyvix instead of querying the database
    user_data = verify_user_with_pyvix(email)
    
    if user_data["status"] == False:
        return RedirectResponse(url='https://jalfry.com/login/mirrorfiber.com')
    
    user_data = user_data["data"]
    
    # Generate a token for the application
    token = generate_token(user_data["phone"], user_data["name"], user_data["username"], user_data["role"], user_data["id"])
    
    if token["status"] == False:
        return {"status": False, "description": "Could not generate token: STA291"}
    
    token = token["token"]
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="jwt_token", value=token, httponly=True, secure=True, samesite="none")
    return response