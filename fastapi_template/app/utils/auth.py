import jwt
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security import HTTPBearer
from starlette.requests import Request

from ..configs.settings import JWTSettings


def decode_jwt(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, JWTSettings.secret_key, algorithms=[JWTSettings.algo])
        print(decoded_token)
        return decoded_token
    except:
        {}


def verify_jwt(token: str) -> bool:
    is_token_valid: bool = False

    try:
        print(token)
        payload = decode_jwt(token)
        print(decode_jwt(token))
    except:
        payload = None
    if payload:
        is_token_valid = True
    return is_token_valid


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")
