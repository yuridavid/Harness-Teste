"""
harness.py — Camadas de controle do ACI
  · CircuitBreaker  : limites automáticos de execução
  · AuditLog        : registro imutável de todas as ações
  · RiskClassifier  : classifica risco de cada ação
  · ToolRouter      : intercepta e valida chamadas de ferramentas
"""

import time
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Any


# ──────────────────────────────────────────────
# Exceptions
# ──────────────────────────────────────────────

class AgentHalted(Exception):
    """Lançada pelo CircuitBreaker quando um limite é atingido."""

class PermissionDenied(Exception):
    """Lançada pelo ToolRouter quando a ferramenta ou parâmetro não é permitido."""

class AgentAborted(Exception):
    """Lançada quando o humano rejeita uma ação no gate HITL."""


# ──────────────────────────────────────────────
# Audit Log
# ──────────────────────────────────────────────

@dataclass
class AuditEntry:
    run_id:     str
    agent_id:   str
    timestamp:  str
    event:      str          # "tool_call" | "hitl_decision" | "agent_start" | "agent_end" | "error"
    tool:       str  = ""
    params:     dict = field(default_factory=dict)
    result:     str  = ""
    tokens:     int  = 0
    cost_usd:   float = 0.0
    risk_level: str  = ""
    approved_by: str = ""    # "auto" | "human:<user>" | ""
    data_class: str  = "INTERNO"  # da AI Policy


class AuditLog:
    """
    Grava cada evento do agente em JSON Lines — uma entrada por linha.
    O arquivo é append-only: nunca sobrescrito, apenas crescido.
    """
    def __init__(self, run_id: str, log_dir: str = "logs"):
        self.run_id  = run_id
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path    = self.log_dir / f"{run_id}.jsonl"

    def write(self, entry: AuditEntry) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")

    def log_tool_call(self, agent_id, tool, params, result, tokens, risk, approved_by="auto"):
        entry = AuditEntry(
            run_id     = self.run_id,
            agent_id   = agent_id,
            timestamp  = datetime.now(timezone.utc).isoformat(),
            event      = "tool_call",
            tool       = tool,
            params     = params,
            result     = result[:200],   # trunca resultado longo
            tokens     = tokens,
            cost_usd   = round(tokens * 0.000003, 6),
            risk_level = risk,
            approved_by= approved_by,
        )
        self.write(entry)

    def log_event(self, agent_id, event, detail=""):
        entry = AuditEntry(
            run_id    = self.run_id,
            agent_id  = agent_id,
            timestamp = datetime.now(timezone.utc).isoformat(),
            event     = event,
            result    = detail[:300],
        )
        self.write(entry)


# ──────────────────────────────────────────────
# Circuit Breaker
# ──────────────────────────────────────────────

class CircuitBreaker:
    """
    Para a execução do agente automaticamente se qualquer limite
    for atingido. Todos os limites são configuráveis por tarefa.
    """
    def __init__(
        self,
        max_steps:   int   = 30,
        max_cost_usd: float = 0.50,
        timeout_s:   int   = 180,
    ):
        self.max_steps    = max_steps
        self.max_cost     = max_cost_usd
        self.timeout_s    = timeout_s
        self.steps        = 0
        self.total_cost   = 0.0
        self.started_at   = time.time()

    def tick(self, tokens_used: int = 0) -> None:
        self.steps      += 1
        self.total_cost += tokens_used * 0.000003
        elapsed          = time.time() - self.started_at

        if self.steps > self.max_steps:
            raise AgentHalted(
                f"Circuit breaker: max_steps ({self.max_steps}) excedido"
            )
        if self.total_cost > self.max_cost:
            raise AgentHalted(
                f"Circuit breaker: custo ${self.total_cost:.4f} excede limite ${self.max_cost}"
            )
        if elapsed > self.timeout_s:
            raise AgentHalted(
                f"Circuit breaker: timeout de {self.timeout_s}s atingido"
            )

    @property
    def summary(self) -> dict:
        return {
            "steps":      self.steps,
            "cost_usd":   round(self.total_cost, 6),
            "elapsed_s":  round(time.time() - self.started_at, 1),
        }


# ──────────────────────────────────────────────
# Risk Classifier
# ──────────────────────────────────────────────

class RiskClassifier:
    """
    Classifica o risco de cada chamada de ferramenta.
    Regras explícitas — sem heurísticas — para garantir
    rastreabilidade em auditoria de compliance.
    """

    # Ferramentas que nunca precisam de aprovação humana
    AUTO_APPROVE_TOOLS = frozenset({
        "read_file",
        "list_dir",
        "run_tests",
    })

    # Ferramentas que sempre exigem revisão humana (criam PR)
    MEDIUM_RISK_TOOLS = frozenset({
        "write_test_file",
        "create_pr",
    })

    # Padrões nos parâmetros que elevam qualquer ação para ALTO
    HIGH_RISK_PATTERNS = [
        "production", "prod-db", "prod_db",
        "DROP ", "TRUNCATE ", "DELETE FROM",
        "master", "main",            # branches protegidas
        "/etc/", "/root/",           # paths de sistema
        "SECRET", "PASSWORD", "TOKEN",
    ]

    def classify(self, tool: str, params: dict) -> str:
        params_str = str(params)

        # Padrões críticos nos parâmetros → sempre ALTO
        for pattern in self.HIGH_RISK_PATTERNS:
            if pattern.lower() in params_str.lower():
                return "alto"

        if tool in self.AUTO_APPROVE_TOOLS:
            return "baixo"

        if tool in self.MEDIUM_RISK_TOOLS:
            return "medio"

        # Qualquer ferramenta desconhecida → ALTO por padrão
        return "alto"


# ──────────────────────────────────────────────
# HITL Gate (síncrono / CLI para fase 1)
# ──────────────────────────────────────────────

class HITLGate:
    """
    Gate de aprovação humana. Nesta versão (fase 1) funciona via
    CLI interativo. Em fases futuras substitua por webhook Slack/GitHub.

    Política:
      baixo  → auto-aprovado (loga como "auto")
      medio  → exibe resumo e aguarda input
      alto   → bloqueia completamente, exibe aviso
    """

    def __init__(self, auto_approve_low: bool = True):
        self.auto_approve_low = auto_approve_low

    def request(self, tool: str, params: dict, risk: str) -> tuple[bool, str]:
        """
        Retorna (approved: bool, reason: str).
        """
        if risk == "baixo" and self.auto_approve_low:
            return True, "auto"

        print("\n" + "═" * 60)
        print(f"  [HITL] Aprovação necessária — risco: {risk.upper()}")
        print(f"  Ferramenta : {tool}")
        print(f"  Parâmetros : {json.dumps(params, indent=4, ensure_ascii=False)}")
        print("═" * 60)

        while True:
            choice = input("  Aprovar? [s/n]: ").strip().lower()
            if choice in ("s", "sim", "y", "yes"):
                return True, "human:cli"
            if choice in ("n", "nao", "não", "no"):
                reason = input("  Motivo da rejeição (opcional): ").strip()
                return False, reason or "rejeitado pelo operador"


# ──────────────────────────────────────────────
# Tool Router
# ──────────────────────────────────────────────

class ToolRouter:
    """
    Intercepta TODA chamada de ferramenta do agente.
    Valida permissões → classifica risco → solicita aprovação → executa → loga.

    O agente nunca chama o ambiente diretamente.
    """

    def __init__(
        self,
        tools: dict,             # {"tool_name": callable}
        classifier: RiskClassifier,
        hitl: HITLGate,
        audit: AuditLog,
        breaker: CircuitBreaker,
        agent_id: str,
    ):
        self.tools      = tools
        self.classifier = classifier
        self.hitl       = hitl
        self.audit      = audit
        self.breaker    = breaker
        self.agent_id   = agent_id
        self.allowed    = frozenset(tools.keys())

    def call(self, tool_name: str, params: dict, tokens: int = 0) -> Any:
        # 1. Verifica se a ferramenta existe na allow-list
        if tool_name not in self.allowed:
            self.audit.log_event(
                self.agent_id,
                "permission_denied",
                f"tool_not_in_allowlist: {tool_name}",
            )
            raise PermissionDenied(
                f"'{tool_name}' não está na allow-list do harness. "
                f"Ferramentas disponíveis: {sorted(self.allowed)}"
            )

        # 2. Classifica o risco
        risk = self.classifier.classify(tool_name, params)

        # 3. Gate HITL
        approved, approver = self.hitl.request(tool_name, params, risk)

        if not approved:
            self.audit.log_tool_call(
                self.agent_id, tool_name, params,
                "REJECTED", tokens, risk, approved_by=approver,
            )
            raise AgentAborted(f"Ação rejeitada pelo operador: {approver}")

        # 4. Executa a ferramenta real
        try:
            result = self.tools[tool_name](**params)
        except Exception as exc:
            self.audit.log_tool_call(
                self.agent_id, tool_name, params,
                f"ERROR: {exc}", tokens, risk, approved_by=approver,
            )
            raise

        # 5. Loga a execução bem-sucedida
        result_str = str(result) if result is not None else ""
        self.audit.log_tool_call(
            self.agent_id, tool_name, params,
            result_str, tokens, risk, approved_by=approver,
        )

        # 6. Tick no circuit breaker
        self.breaker.tick(tokens)

        return result
