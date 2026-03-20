"""
src/auth/service.py Servico de autenticacao
"""
import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional


@dataclass
class User:
    id: int
    username: str
    password_hash: str
    is_active: bool = True


class AuthError(Exception):
    pass


class AuthService:
    """Servico de autenticacacao de usuarios."""

    def __init__(self, secret_key: str):
        if not secret_key or len(secret_key) < 16:
            raise ValueError("secret_key deve ter pelo menos 16 caracteres")
        self._secret = secret_key
        self._users: dict[str, User] = {}

    def hash_password(self, password: str) -> str:
        """Gera o hash seguro de uma senha."""
        if not password:
            raise ValueError("Senha nao pode ser vazia")
        if len(password) < 8:
            raise ValueError("Senha deve ter pelo menos 8 caracteres")
        return hmac.new(
            self._secret.encode(),
            password.encode(),
            hashlib.sha256,
        ).hexdigest()

    def register(self, username: str, password: str) -> User:
        """Registra um novo usu�rio."""
        if not username or not username.strip():
            raise ValueError("Username n�o pode ser vazio")
        if username in self._users:
            raise AuthError(f"Username '{username}' j� est� em uso")
        user = User(
            id            = len(self._users) + 1,
            username      = username.strip(),
            password_hash = self.hash_password(password),
        )
        self._users[username] = user
        return user

    def login(self, username: str, password: str) -> Optional[User]:
        """
        Autentica um usu�rio.
        Retorna o User se as credenciais forem v�lidas, None caso contr�rio.
        """
        user = self._users.get(username)
        if user is None:
            return None
        if not user.is_active:
            raise AuthError("Conta desativada")
        expected = self.hash_password(password)
        if not hmac.compare_digest(expected, user.password_hash):
            return None
        return user

    def deactivate(self, username: str) -> bool:
        """Desativa uma conta de usu�rio. Retorna True se encontrou o usu�rio."""
        user = self._users.get(username)
        if user is None:
            return False
        user.is_active = False
        return True
