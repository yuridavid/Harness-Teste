"""
main.py — Ponto de entrada e código de exemplo para o agente testar

Execute com:
    export ANTHROPIC_API_KEY="sua-chave"
    python main.py
"""

from dotenv import load_dotenv
load_dotenv()

import os
from pathlib import Path
from agent import TestGeneratorAgent


# ──────────────────────────────────────────────
# Código de exemplo: módulo de autenticação
# O agente vai ler esse arquivo e gerar os testes
# ──────────────────────────────────────────────

SAMPLE_CODE = '''"""
src/auth/service.py — Serviço de autenticação
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
    """Serviço de autenticação de usuários."""

    def __init__(self, secret_key: str):
        if not secret_key or len(secret_key) < 16:
            raise ValueError("secret_key deve ter pelo menos 16 caracteres")
        self._secret = secret_key
        self._users: dict[str, User] = {}

    def hash_password(self, password: str) -> str:
        """Gera o hash seguro de uma senha."""
        if not password:
            raise ValueError("Senha não pode ser vazia")
        if len(password) < 8:
            raise ValueError("Senha deve ter pelo menos 8 caracteres")
        return hmac.new(
            self._secret.encode(),
            password.encode(),
            hashlib.sha256,
        ).hexdigest()

    def register(self, username: str, password: str) -> User:
        """Registra um novo usuário."""
        if not username or not username.strip():
            raise ValueError("Username não pode ser vazio")
        if username in self._users:
            raise AuthError(f"Username '{username}' já está em uso")
        user = User(
            id            = len(self._users) + 1,
            username      = username.strip(),
            password_hash = self.hash_password(password),
        )
        self._users[username] = user
        return user

    def login(self, username: str, password: str) -> Optional[User]:
        """
        Autentica um usuário.
        Retorna o User se as credenciais forem válidas, None caso contrário.
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
        """Desativa uma conta de usuário. Retorna True se encontrou o usuário."""
        user = self._users.get(username)
        if user is None:
            return False
        user.is_active = False
        return True
'''


def setup_workspace(workspace: Path) -> None:
    """Cria a estrutura de workspace com o código de exemplo."""
    src_dir = workspace / "src" / "auth"
    src_dir.mkdir(parents=True, exist_ok=True)

    (src_dir / "__init__.py").write_text("")
    (workspace / "src" / "__init__.py").write_text("")
    (src_dir / "service.py").write_text(SAMPLE_CODE)

    tests_dir = workspace / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    (tests_dir / "__init__.py").write_text("")

    print(f"  Workspace criado em: {workspace}")
    print(f"  Arquivo alvo: src/auth/service.py")


def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print("[AVISO] ANTHROPIC_API_KEY não definida.")
        print("         Execute: export ANTHROPIC_API_KEY='sua-chave'")
        print("         O agente vai simular sem fazer chamadas reais.\n")

    # Cria workspace de exemplo
    workspace = Path("/tmp/test_agent_workspace")
    setup_workspace(workspace)

    # Instancia o agente com o harness configurado
    agent = TestGeneratorAgent(
        workspace_root   = str(workspace),
        auto_approve_low = True,   # baixo risco: auto-aprova
        max_steps        = 30,
        max_cost_usd     = 0.50,
    )

    # Executa a tarefa
    result = agent.run(
        "Gere testes unitários completos para o módulo src/auth/service.py. "
        "Cubra: hash_password, register, login e deactivate. "
        "Inclua happy path, casos de erro e edge cases."
    )

    print("\n=== Resultado final ===")
    print(f"Status      : {result['status']}")
    print(f"Arquivos    : {result.get('files_written', [])}")
    print(f"Audit log   : {result.get('audit_log', 'N/A')}")

    if result.get("final_message"):
        print(f"\nSumário do agente:\n{result['final_message'][:500]}")


if __name__ == "__main__":
    main()
