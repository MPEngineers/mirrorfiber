from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse
from utilities.auth import verify_token

async def role_based_auth(request: Request, allowed_roles: list):
    token = request.cookies.get("jwt_token")
    if not token:
        return RedirectResponse(url="/login")
    
    status = verify_token(token)
    if not status["status"]:
        return RedirectResponse(url="/login")
    
    #TODO: Remove this in production
    # user_role = "admin"
    user_role = status["payload"]["role"]
    
    if user_role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Unauthorized access")
    
    return status["payload"]