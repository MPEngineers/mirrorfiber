from datetime import datetime
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("JALFRY_JWT_KEY")
ALGORITHM = os.getenv("ALGORITHM")

# Debugging: Remove before deployment
# print(f"SECRET_KEY: {SECRET_KEY}")
# print(f"ALGORITHM: {ALGORITHM}")

def generate_token(phone, name, username, role, id):
    expiration = datetime.now()

    try:
        payload = {
            "phone": phone,
            "name": name,
            "username": username,
            "role": role,
            "id": id,
            "expiration": expiration.isoformat(),
        }
        encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        print("Updated Token Generated!")
        return {
            "status": True,
            "token": encoded_jwt
        }
    except Exception as e:
        print("Error in generate_token: ", e)
        return {
            "status": False
        }

def verify_token(encoded_jwt):
    print("encoded_jwt: ", encoded_jwt)
    print("type of encoded_jwt: ", type(encoded_jwt))
    
    try:
        # Handle None case
        if encoded_jwt is None:
            print("Token is None")
            return {"status": False}
        
        # Handle non-string case by converting to string if possible
        if not isinstance(encoded_jwt, str):
            try:
                print(f"Converting non-string token to string: {encoded_jwt}")
                encoded_jwt = str(encoded_jwt)
            except Exception as e:
                print(f"Failed to convert token to string: {e}")
                return {"status": False}
        
        # Handle byte string representation
        if encoded_jwt.startswith("b'") and encoded_jwt.endswith("'"):
            print("Removing byte string markers")
            encoded_jwt = encoded_jwt[2:-1]
        
        # Decode the token
        payload = jwt.decode(encoded_jwt, SECRET_KEY, algorithms=[ALGORITHM])

        # Validate expiration
        expiration_datetime = datetime.fromisoformat(payload["expiration"].rstrip("Z")).date()
        today_date = datetime.now().date()
        if payload and expiration_datetime >= today_date:
            return {
                "status": True,
                "payload": payload
            }
        return {
            "status": False
        }

    except Exception as e:
        print("Error in verify_token: ", e)
        print("Token value: ", repr(encoded_jwt))
        return {
            "status": False
        }
