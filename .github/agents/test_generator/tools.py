"""
tools.py — As 4 ferramentas do agente gerador de testes.

Princípio do menor privilégio: o agente recebe apenas o que
precisa para ler código e escrever arquivos de teste.

  1. read_file       — lê um arquivo do workspace
  2. list_dir        — lista arquivos de um diretório
  3. write_test_file — escreve um arquivo de teste (restrito a tests/)
  4. run_tests       — executa pytest em modo sandbox
"""

import subprocess
from pathlib import Path


class WorkspaceTools:
    """
    Ferramentas com escopo limitado ao workspace do agente.
    Todos os caminhos são forçados a ficarem dentro do WORKSPACE_ROOT.
    """

    # Extensões de arquivo que o agente pode ler
    READABLE_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".rb", ".md", ".txt"}

    # Prefixos de caminho proibidos para leitura (segurança)
    FORBIDDEN_PATHS = ["/etc", "/root", "/proc", "/sys", "~", "../"]

    def __init__(self, workspace_root: str):
        self.root = Path(workspace_root).resolve()
        # Garante que o diretório de testes existe
        (self.root / "tests").mkdir(parents=True, exist_ok=True)

    def _safe_path(self, relative_path: str) -> Path:
        """
        Resolve o caminho e garante que está dentro do workspace.
        Previne path traversal (../../etc/passwd etc).
        """
        for forbidden in self.FORBIDDEN_PATHS:
            if forbidden in relative_path:
                raise PermissionError(
                    f"Caminho proibido: '{relative_path}' contém '{forbidden}'"
                )
        resolved = (self.root / relative_path).resolve()
        if not str(resolved).startswith(str(self.root)):
            raise PermissionError(
                f"Path traversal detectado: '{relative_path}' sai do workspace"
            )
        return resolved

    # ── Ferramenta 1 ──────────────────────────────────────────────

    def read_file(self, path: str) -> str:
        """
        Lê o conteúdo de um arquivo do workspace.
        Retorna o texto como string. Máximo 10.000 caracteres.
        """
        safe = self._safe_path(path)

        if not safe.exists():
            return f"[ERRO] Arquivo não encontrado: {path}"

        if safe.suffix not in self.READABLE_EXTENSIONS:
            return f"[ERRO] Extensão '{safe.suffix}' não permitida para leitura"

        if safe.stat().st_size > 500_000:  # 500 KB limit
            return f"[ERRO] Arquivo muito grande ({safe.stat().st_size} bytes). Limite: 500KB"

        content = safe.read_text(encoding="utf-8", errors="replace")
        # Trunca para evitar context window explosion
        if len(content) > 10_000:
            content = content[:10_000] + "\n\n[... truncado — arquivo tem mais conteúdo]"

        return content

    # ── Ferramenta 2 ──────────────────────────────────────────────

    def list_dir(self, path: str = ".", max_files: int = 50) -> str:
        """
        Lista arquivos de um diretório do workspace.
        Retorna uma string com os paths relativos, um por linha.
        """
        safe = self._safe_path(path)

        if not safe.is_dir():
            return f"[ERRO] '{path}' não é um diretório"

        files = []
        for p in sorted(safe.rglob("*")):
            if p.is_file() and p.suffix in self.READABLE_EXTENSIONS:
                files.append(str(p.relative_to(self.root)))
            if len(files) >= max_files:
                files.append(f"... ({max_files} arquivos listados, pode haver mais)")
                break

        if not files:
            return f"[VAZIO] Nenhum arquivo encontrado em '{path}'"

        return "\n".join(files)

    # ── Ferramenta 3 ──────────────────────────────────────────────

    def write_test_file(self, filename: str, content: str) -> str:
        """
        Escreve um arquivo de teste no diretório tests/.
        RESTRITO: o agente só pode escrever dentro de tests/.
        O conteúdo é validado para garantir que é código Python de teste.
        """
        # Força o arquivo a ficar dentro de tests/
        if not filename.startswith("tests/"):
            filename = f"tests/{filename}"

        # Garante que tem prefixo test_
        basename = Path(filename).name
        if not basename.startswith("test_"):
            filename = str(Path(filename).parent / f"test_{basename}")

        # Garante extensão .py
        if not filename.endswith(".py"):
            filename += ".py"

        safe = self._safe_path(filename)

        # Validação básica: deve conter pelo menos uma função de teste
        if "def test_" not in content:
            return (
                "[ERRO] O arquivo de teste não contém nenhuma função 'def test_...'."
                " Gere testes válidos antes de escrever."
            )

        # Verifica que não há imports suspeitos
        forbidden_imports = ["os.system", "subprocess", "shutil.rmtree", "__import__"]
        for fi in forbidden_imports:
            if fi in content:
                return f"[ERRO] Import/chamada proibida detectada: '{fi}'"

        safe.parent.mkdir(parents=True, exist_ok=True)
        safe.write_text(content, encoding="utf-8")

        return f"[OK] Arquivo escrito: {filename} ({len(content)} caracteres)"

    # ── Ferramenta 4 ──────────────────────────────────────────────

    def run_tests(self, test_path: str = "tests/", timeout: int = 60) -> str:
        """
        Executa pytest no diretório de testes do workspace.
        Sempre em sandbox — nunca acessa recursos externos.
        Timeout máximo: 60 segundos.
        """
        safe = self._safe_path(test_path)

        if not safe.exists():
            return f"[ERRO] Caminho de testes não existe: {test_path}"

        try:
            result = subprocess.run(
                [
                    "python", "-m", "pytest",
                    str(safe),
                    "--tb=short",        # traceback curto
                    "--no-header",
                    "-q",                # output compacto
                    "--timeout=30",      # timeout por teste
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.root),
                # Sem acesso à rede: o pytest roda isolado
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "PYTHONPATH": str(self.root),
                    "HOME": "/tmp",
                },
            )
            output = result.stdout + result.stderr
            # Trunca output muito longo
            if len(output) > 3000:
                output = output[:3000] + "\n[... output truncado]"
            return output or "[OK] Sem output do pytest"
        except subprocess.TimeoutExpired:
            return f"[ERRO] Timeout de {timeout}s excedido ao rodar testes"
        except FileNotFoundError:
            return "[ERRO] pytest não encontrado. Instale com: pip install pytest"

    def as_tool_dict(self) -> dict:
        """Retorna o dicionário de ferramentas para o ToolRouter."""
        return {
            "read_file":       self.read_file,
            "list_dir":        self.list_dir,
            "write_test_file": self.write_test_file,
            "run_tests":       self.run_tests,
        }
