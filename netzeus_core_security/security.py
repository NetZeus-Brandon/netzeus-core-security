import jwt
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from passlib.context import CryptContext

from netzeus_core_config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=settings.API_AUTH_URL, auto_error=False)


def get_pwd_context(
    schemes: list = ["bcrypt"], deprecated: str = "auto"
) -> CryptContext:
    "Returns password context"
    return CryptContext(schemes=schemes, deprecated=deprecated)


def get_password_hash(
    password: str, pwd_context: CryptContext = get_pwd_context()
) -> str:
    """Returns password hash"""
    return pwd_context.hash(password)


def verify_password(
    password: str, hashed_password: str, pwd_context: CryptContext
) -> bool:
    """Verifies a password against the hashed password"""
    return pwd_context.verify(password, hashed_password)


def create_access_token(
    payload: dict,
    expires_delta: timedelta = None,
    algorithm: str = settings.ACCESS_TOKEN_ALGORITHM,
    secret: str = settings.SECRET_KEY,
) -> bytes:
    """Creates a JWT token that expires based on app settings

    Args:
        payload:        Data to encode in access token
        expires_delta:  Token access Expiration in seconds
        algorithm:      Algorithm to use for encryption
        secret:         Secret key to encode the JWT data
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + settings.ACCESS_TOKEN_EXPIRES_IN

    payload.update({"exp": expire})
    encoded_jwt = jwt.encode(payload, secret, algorithm=algorithm)
    return encoded_jwt
