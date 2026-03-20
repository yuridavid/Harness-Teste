"""
agent.py — Agente gerador de testes

Loop ReAct integrado ao harness completo:
  CircuitBreaker + ToolRouter + AuditLog + HITLGate

Fluxo:
  1. Recebe o diff de um PR (ou path de um módulo)
  2. Lê os arquivos relevantes via ToolRouter
  3. Analisa o código e gera casos de teste
  4. Escreve os testes via write_test_file (gate HITL)
  5. Roda os testes para confirmar que passam
  6. Retorna sumário para abertura do PR
"""

import json
import os
import uuid
from typing import Optional
import anthropic

from harness import (
    CircuitBreaker,
    RiskClassifier,
    HITLGate,
    ToolRouter,
    AuditLog,
    AgentHalted,
    AgentAborted,
)
from tools import WorkspaceTools


# ──────────────────────────────────────────────
# Tool definitions para a API do Claude
# ──────────────────────────────────────────────

TOOL_DEFINITIONS = [
    {
        "name": "read_file",
        "description": (
            "Lê o conteúdo de um arquivo do workspace. "
            "Use para entender o código que precisa de testes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Caminho relativo ao workspace, ex: src/auth/login.py",
                }
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_dir",
        "description": (
            "Lista arquivos de um diretório do workspace. "
            "Use para descobrir quais arquivos existem antes de ler."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Caminho relativo do diretório, ex: src/ ou tests/",
                    "default": ".",
                },
                "max_files": {
                    "type": "integer",
                    "description": "Máximo de arquivos a listar",
                    "default": 50,
                },
            },
        },
    },
    {
        "name": "write_test_file",
        "description": (
            "Escreve um arquivo de testes Python no diretório tests/. "
            "Só use após ter lido o código-fonte e planejado os casos de teste. "
            "O arquivo DEVE conter funções def test_*."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Nome do arquivo, ex: test_auth_login.py",
                },
                "content": {
                    "type": "string",
                    "description": "Conteúdo completo do arquivo de testes Python",
                },
            },
            "required": ["filename", "content"],
        },
    },
    {
        "name": "run_tests",
        "description": (
            "Executa os testes com pytest. "
            "Use após escrever os testes para confirmar que passam. "
            "Se falharem, leia o erro e corrija o arquivo de testes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "test_path": {
                    "type": "string",
                    "description": "Caminho do arquivo ou diretório de testes",
                    "default": "tests/",
                }
            },
        },
    },
]

# ──────────────────────────────────────────────
# System prompt do agente
# ──────────────────────────────────────────────

SYSTEM_PROMPT = """Você é um agente especializado em geração de testes unitários de alta qualidade.

Seu fluxo de trabalho é:
1. Use list_dir para entender a estrutura do repositório
2. Use read_file para ler os arquivos relevantes (código-fonte, testes existentes)
3. Analise o código e identifique:
   - Casos felizes (happy path)
   - Casos de erro e exceções
   - Edge cases (valores nulos, vazios, extremos)
   - Comportamentos de segurança relevantes
4. Use write_test_file para escrever os testes
5. Use run_tests para confirmar que os testes passam
6. Se os testes falharem, corrija e rode novamente
7. Quando estiver satisfeito, finalize com um sumário do que foi gerado

Padrões obrigatórios:
- Use pytest (não unittest)
- Cada função de teste testa exatamente uma coisa (princípio single assertion)
- Nomes descritivos: test_login_retorna_erro_quando_senha_incorreta
- Use fixtures para setup/teardown
- Docstring em cada test explicando o que está testando
- Mock de dependências externas (banco de dados, APIs, etc.)
- Cobertura mínima: happy path + 2 casos de erro por função pública

NÃO acesse arquivos fora do workspace.
NÃO instale pacotes.
NÃO faça chamadas de rede.
NÃO modifique arquivos fora de tests/.
"""


# ──────────────────────────────────────────────
# Agente principal
# ──────────────────────────────────────────────

class TestGeneratorAgent:
    AGENT_ID = "test-generator-v1"

    def __init__(
        self,
        workspace_root: str,
        auto_approve_low: bool = True,
        max_steps: int = 30,
        max_cost_usd: float = 0.50,
    ):
        self.run_id    = f"tga-{uuid.uuid4().hex[:8]}"
        self.workspace = workspace_root

        # Instancia as camadas do harness
        self.breaker    = CircuitBreaker(max_steps=max_steps, max_cost_usd=max_cost_usd)
        self.audit      = AuditLog(run_id=self.run_id)
        self.hitl       = HITLGate(auto_approve_low=auto_approve_low)
        self.classifier = RiskClassifier()
        self.ws_tools   = WorkspaceTools(workspace_root)

        self.router = ToolRouter(
            tools      = self.ws_tools.as_tool_dict(),
            classifier = self.classifier,
            hitl       = self.hitl,
            audit      = self.audit,
            breaker    = self.breaker,
            agent_id   = self.AGENT_ID,
        )

        self.client = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY", "")
        )

    def run(self, task: str) -> dict:
        """
        Ponto de entrada principal.
        `task` pode ser:
          - "Gere testes para src/auth/login.py"
          - "Cubra os módulos alterados neste PR: src/payment/, src/cart/"
        """
        print(f"\n{'═'*60}")
        print(f"  Agente: {self.AGENT_ID}")
        print(f"  Run ID: {self.run_id}")
        print(f"  Tarefa: {task}")
        print(f"{'═'*60}\n")

        self.audit.log_event(self.AGENT_ID, "agent_start", task)

        messages = [{"role": "user", "content": task}]
        total_tokens = 0
        files_written = []

        try:
            # ── Loop ReAct ─────────────────────────────────────────
            while True:
                self.breaker.tick()

                response = self.client.messages.create(
                    model      = "claude-sonnet-4-20250514",
                    max_tokens = 4096,
                    system     = SYSTEM_PROMPT,
                    tools      = TOOL_DEFINITIONS,
                    messages   = messages,
                )

                total_tokens += response.usage.input_tokens + response.usage.output_tokens

                # Adiciona a resposta do assistente ao histórico
                messages.append({"role": "assistant", "content": response.content})

                # ── Fim do loop: sem mais tool calls ──────────────
                if response.stop_reason == "end_turn":
                    # Extrai o texto final do agente
                    final_text = ""
                    for block in response.content:
                        if hasattr(block, "text"):
                            final_text = block.text
                            break

                    self.audit.log_event(
                        self.AGENT_ID,
                        "agent_end",
                        f"tokens: {total_tokens} | arquivos: {files_written}",
                    )

                    summary = {
                        "run_id":        self.run_id,
                        "status":        "success",
                        "files_written": files_written,
                        "final_message": final_text,
                        "harness":       self.breaker.summary,
                        "audit_log":     str(self.audit.path),
                    }
                    self._print_summary(summary)
                    return summary

                # ── Processa tool calls ────────────────────────────
                tool_results = []

                for block in response.content:
                    if block.type != "tool_use":
                        continue

                    tool_name = block.name
                    params    = block.input or {}

                    print(f"  → [{tool_name}] {json.dumps(params, ensure_ascii=False)[:80]}")

                    try:
                        result = self.router.call(
                            tool_name = tool_name,
                            params    = params,
                            tokens    = response.usage.output_tokens,
                        )
                        result_str = str(result) if result is not None else ""

                        # Rastreia arquivos escritos
                        if tool_name == "write_test_file" and result_str.startswith("[OK]"):
                            fname = params.get("filename", "")
                            if fname and fname not in files_written:
                                files_written.append(fname)

                    except AgentAborted as e:
                        result_str = f"[ABORTADO] {e}"
                    except PermissionError as e:
                        result_str = f"[PERMISSÃO NEGADA] {e}"
                    except Exception as e:
                        result_str = f"[ERRO] {type(e).__name__}: {e}"

                    tool_results.append({
                        "type":        "tool_result",
                        "tool_use_id": block.id,
                        "content":     result_str,
                    })

                # Devolve resultados ao agente
                messages.append({"role": "user", "content": tool_results})

        except AgentHalted as e:
            self.audit.log_event(self.AGENT_ID, "circuit_breaker", str(e))
            return {
                "run_id":  self.run_id,
                "status":  "halted",
                "reason":  str(e),
                "harness": self.breaker.summary,
                "audit_log": str(self.audit.path),
            }

        except Exception as e:
            self.audit.log_event(self.AGENT_ID, "error", str(e))
            raise

    def _print_summary(self, summary: dict) -> None:
        print(f"\n{'═'*60}")
        print(f"  Agente finalizado com sucesso")
        print(f"  Arquivos gerados : {summary['files_written']}")
        h = summary['harness']
        print(f"  Passos usados    : {h['steps']}")
        print(f"  Custo estimado   : ${h['cost_usd']:.4f}")
        print(f"  Tempo total      : {h['elapsed_s']}s")
        print(f"  Audit log        : {summary['audit_log']}")
        print(f"{'═'*60}\n")
