from src.config.env_reader import settings
import httpx
import httpx
import asyncio

import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import binascii


def get_auth_info(email: str):
    url = "https://gateway.filen-2.net/v3/auth/info"
    data = {"email": email}

    try:
        response = httpx.post(url, json=data)
        response.raise_for_status()

        if not response.json().get("status"):
            raise ValueError(response.json().get("message"))

        return {
            "authVersion": response.json()["data"]["authVersion"],
            "salt": response.json()["data"]["salt"]
        }
    except httpx.RequestError as e:
        raise SystemError(f"Request error: {e}")
    except httpx.HTTPStatusError as e:
        raise ValueError(f"HTTP error: {e.response.status_code}")


def calculate_filen_password(raw_password, salt=None):
    """
    Derives Filen master key and login hash from user's password, and optionally a salt.
    :param raw_password: User's plaintext password
    :param salt: Optional salt from Filen API
    :return: Tuple containing master key and hashed password
    """
    if salt:
        # PBKDF2 key derivation with salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt.encode(),
            iterations=200000,
            backend=default_backend()
        )
        derived_key = kdf.derive(raw_password.encode())
    else:
        # Simple SHA-512 hashing if no salt is provided
        derived_key = hashlib.sha512(raw_password.encode()).digest()

    # Split the derived key into two parts
    m_key, password_part = derived_key[:32], derived_key[32:]

    # Convert to hexadecimal strings
    m_key_hex = binascii.hexlify(m_key).decode()
    password_hex = binascii.hexlify(password_part).decode()

    # SHA-512 hash of the hexadecimal string of password part
    sent_password_hex = hashlib.sha512(password_hex.encode()).hexdigest()

    return m_key_hex, sent_password_hex  # Use None if salt is not available


async def filen_login(email, sent_password, two_factor_code, auth_version):
    url = 'https://gateway.filen-2.net/v3/login'
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "filen-mobile"
    }
    data = {
        "email": email,
        "password": sent_password,
        "twoFactorCode": two_factor_code,
        "authVersion": auth_version
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, json=data)
        return response.json()


email = settings.email
raw_password = settings.password.get_secret_value()
two_factor_code = settings.two_factor_code


async def get_logged_in():
    try:
        auth_info = get_auth_info(email)

        salt = auth_info["salt"]
        auth_version = auth_info["authVersion"]

        m_key, sent_password = calculate_filen_password(raw_password, salt)

        response = await filen_login(email, sent_password, two_factor_code, auth_version)
        print(response)
        return response
    except Exception as e:
        print(f"Error: {e}")
