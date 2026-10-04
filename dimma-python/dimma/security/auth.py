"""Hashing seguro de senha usando bcrypt (custo 12)."""
import secrets
import bcrypt

SALT_ROUNDS = 12
BCRYPT_MAX_PASSWORD_BYTES = 72


def _validate_bcrypt_password(password: str) -> bytes:
    if not isinstance(password, str):
        raise TypeError("Senha deve ser uma string.")
    encoded = password.encode("utf-8")
    if len(encoded) > BCRYPT_MAX_PASSWORD_BYTES:
        raise ValueError(
            f"Senha excede o limite seguro do bcrypt de {BCRYPT_MAX_PASSWORD_BYTES} bytes."
        )
    return encoded


def hash_password(plain_password: str) -> str:
    if not isinstance(plain_password, str) or len(plain_password) < 8:
        raise ValueError("Senha deve ter no minimo 8 caracteres.")
    encoded = _validate_bcrypt_password(plain_password)
    salt = bcrypt.gensalt(rounds=SALT_ROUNDS)
    return bcrypt.hashpw(encoded, salt).decode("utf-8")


def verify_password(plain_password: str, hashed: str) -> bool:
    try:
        encoded = _validate_bcrypt_password(plain_password)
        return bcrypt.checkpw(encoded, hashed.encode("utf-8"))
    except (ValueError, TypeError, AttributeError):
        return False


def generate_secure_token(n_bytes: int = 32) -> str:
    return secrets.token_hex(n_bytes)
