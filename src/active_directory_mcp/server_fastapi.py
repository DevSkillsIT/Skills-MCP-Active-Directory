"""
FastAPI-based MCP server for Active Directory with Streamable HTTP support.

This module provides full HTTP transport with:
- Streamable HTTP Transport (GET/POST/DELETE) for Gemini CLI compatibility
- Bearer Token authentication for security
- Multi-tenant support
- Session management for long-running connections
"""

import os
import sys
import json
import logging
import asyncio
import copy
import threading
import unicodedata
import uuid
import signal
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager, contextmanager

from fastapi import FastAPI, HTTPException, Request, Header, Depends
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
import uvicorn
from ldap3.utils.conv import escape_filter_chars

from .config.loader import load_config, validate_config
from .config.models import LoggingConfig
from .config.multi_loader import load_multi_config, MultiConfigError
from .core.ad_pool import ADServerPool
from .core.logging import setup_logging
from .core.redaction import redact, register_secret
from .core.ldap_manager import LDAPManager
from .core.client_security import init_security_manager
from .core.resolver import nome_novo_de, resolver_argumentos
from .tools.definitions import (
    DESCRICOES_TOOLS, INSTRUCOES_DO_SERVIDOR, aplicar_descricoes,
)
from .tools.user import UserTools
from .tools.group import GroupTools
from .tools.computer import ComputerTools
from .tools.organizational_unit import OrganizationalUnitTools
from .tools.security import SecurityTools
from .tools.prompts import PROMPTS_CATALOG, handle_get_prompt


# ============= MODELS =============

class MCPRequest(BaseModel):
    """MCP JSON-RPC request model."""
    jsonrpc: str = "2.0"
    method: str
    params: Optional[Dict[str, Any]] = None
    id: Optional[Any] = None


class MCPResponse(BaseModel):
    """MCP JSON-RPC response model."""
    jsonrpc: str = "2.0"
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[Any] = None


# ============= SESSION MANAGEMENT =============

mcp_sessions: Dict[str, Dict] = {}


def cleanup_expired_sessions():
    """Remove sessions older than 15 minutes."""
    now = datetime.now(timezone.utc)
    expired = [
        sid for sid, data in mcp_sessions.items()
        if (now - data.get("created_at", now)).total_seconds() > 900
    ]
    for sid in expired:
        del mcp_sessions[sid]


# ============= AUTHENTICATION =============

async def verify_bearer_token(authorization: str = Header(None)) -> str:
    """
    Verify Bearer token from Authorization header.
    Token is configured via AD_MCP_API_TOKEN environment variable.
    """
    expected_token = os.getenv("AD_MCP_API_TOKEN")

    if not expected_token:
        # Se nao houver token configurado, permitir acesso (desenvolvimento)
        return "no_auth_configured"

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization format. Use: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = authorization.replace("Bearer ", "")

    if token != expected_token:
        raise HTTPException(
            status_code=403,
            detail="Invalid or expired token"
        )

    return token


# ============= SERVER CLASS =============

class _PorAD:
    """A tenant attribute resolved per THREAD, not per process.

    @MX:ANCHOR Every tool handler reads its directory through these
    attributes (self.user_tools, self.ldap_manager, self.config...).
    @MX:REASON Calls now run concurrently in worker threads. The previous design
    swapped the attributes on the shared server object under one global lock,
    which made the whole process serve one call at a time: a directory whose
    VPN was down froze every other call, ad_list_ad_servers included. Bound per
    thread, two calls to two customers cannot see each other's directory.
    """

    def __set_name__(self, owner, name):
        self.nome = name
        self.base = "_base_" + name

    def __get__(self, obj, owner=None) -> Any:
        if obj is None:
            return self
        local = obj.__dict__.get("_tenant_local")
        bundle = getattr(local, "bundle", None) if local is not None else None
        if bundle is not None:
            return bundle.key if self.nome == "_bound_server" else getattr(bundle, self.nome)
        return obj.__dict__.get(self.base)

    def __set__(self, obj, valor: Any) -> None:
        obj.__dict__[self.base] = valor


_VERDADEIROS = {"true", "sim", "s", "yes", "y", "1", "on", "verdadeiro", "v"}
_FALSOS = {"false", "nao", "n", "no", "0", "off", "falso", "f"}


class ActiveDirectoryMCPFastAPI:
    """
    FastAPI-based MCP server for Active Directory.

    Supports:
    - Streamable HTTP Transport (Claude + Gemini)
    - Bearer Token authentication
    - Multi-tenant client identification
    - Full AD management operations
    """

    # Tools that do not target one directory and therefore take no ad_server.
    _GLOBAL_TOOLS = ("ad_search_directory_servers",)

    # Attributes bound per call (per thread) in multi-AD mode.
    _TENANT_ATTRS = (
        "config", "ldap_manager", "user_tools", "group_tools",
        "computer_tools", "ou_tools", "security_tools", "security_manager",
    )
    config = _PorAD()
    ldap_manager = _PorAD()
    user_tools = _PorAD()
    group_tools = _PorAD()
    computer_tools = _PorAD()
    ou_tools = _PorAD()
    security_tools = _PorAD()
    security_manager = _PorAD()
    _bound_server = _PorAD()

    # Deadlines, all below the 30 s the Skyller client gives an MCP call: an
    # answer that explains what is slow beats the client's empty timeout error.
    _PRAZO_CHAMADA = float(os.getenv("AD_MCP_CALL_DEADLINE", "22"))
    _PRAZO_TODOS = float(os.getenv("AD_MCP_FANOUT_DEADLINE", "18"))
    # 3 s was not enough for the fuzzy path (it reads the whole index) over a
    # slow link: measured 2026-09-21, one customer AD was cut every time while
    # the rest answered. The fan-out ceiling is _PRAZO_TODOS, still far from
    # the client's 30 s.
    _GRACA_APOS_ACHADO = float(os.getenv("AD_MCP_FANOUT_GRACE", "6"))
    # Grace given instead when a directory is still opening its connection:
    # the connection budget plus a margin, so a cold but healthy AD answers.
    _PRAZO_CONEXAO_FRIA = float(os.getenv("AD_MCP_FANOUT_GRACE_COLD", "12"))
    _TRABALHADORES = int(os.getenv("AD_MCP_WORKERS", "16"))

    def __init__(
        self,
        config_path: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 8820,
        servers_path: Optional[str] = None,
        mode: Optional[str] = None,
    ):
        self.config_path = config_path
        self.host = host
        self.port = port
        # The bearer token never appears in a log line or an error.
        register_secret(os.getenv("AD_MCP_API_TOKEN"))

        # Mode gate. 'single' keeps the original one-AD-per-process path.
        self.mode = (mode or os.getenv("AD_MCP_MODE") or "single").strip().lower()
        if self.mode not in ("single", "multi"):
            raise ValueError(
                f"AD_MCP_MODE invalido: {self.mode!r}. Use 'single' ou 'multi'."
            )
        self.multi = self.mode == "multi"
        self.pool = None
        self.servers_path = None
        self._bound_server = None
        self.__dict__.setdefault("_tenant_local", threading.local())

        if self.multi:
            self._init_multi(servers_path)
        else:
            self._init_single()

        # Build tool registry
        self._build_tool_registry()

        # Create FastAPI app
        self.app = self._create_app()

    def _init_single(self):
        """Single-AD mode: one directory per process (unchanged behaviour)."""
        # Load configuration
        self.config = load_config(self.config_path)
        validate_config(self.config)

        # Setup logging
        self.logger = setup_logging(self.config.logging)

        # Initialize security manager
        self._init_client_security()

        # Initialize LDAP manager
        self.ldap_manager = LDAPManager(
            self.config.active_directory,
            self.config.security,
            self.config.performance,
            ou_config=self.config.organizational_units,
        )

        # Test connection
        self._test_connection()

        # Initialize tools
        self.user_tools = UserTools(self.ldap_manager)
        self.group_tools = GroupTools(self.ldap_manager)
        self.computer_tools = ComputerTools(self.ldap_manager)
        self.ou_tools = OrganizationalUnitTools(self.ldap_manager)
        self.security_tools = SecurityTools(self.ldap_manager)

    def _init_multi(self, servers_path: Optional[str] = None):
        """Multi-AD mode: N directories served by one process.

        No LDAP connection is opened here. A directory is only contacted when a
        tool actually targets it, so a misconfigured or unreachable server
        cannot stop the process from starting.
        """
        self.servers_path = servers_path or os.getenv("AD_MCP_SERVERS")
        entries = load_multi_config(self.servers_path)

        logging_config = LoggingConfig(
            level=os.getenv("AD_MCP_LOG_LEVEL", "INFO"),
            file=os.getenv("AD_MCP_LOG_FILE") or None,
        )
        self.logger = setup_logging(logging_config)

        self.pool = ADServerPool(entries)

        # @MX:ANCHOR Unbound tenant state is None on purpose: any handler that
        # runs outside _bound() must crash loudly instead of silently reusing
        # whichever directory happened to be bound last.
        for name in self._TENANT_ATTRS:
            setattr(self, name, None)

        invalid = {k: e.error for k, e in entries.items() if not e.valid}
        self.logger.info(
            "Modo multi-AD: %d servidores configurados (%d validos) a partir de %s",
            len(entries), len(entries) - len(invalid), self.servers_path,
        )
        for key, error in invalid.items():
            self.logger.error("Servidor '%s' NAO utilizavel: %s", key, error)



    @contextmanager
    def _bound(self, bundle):
        """Bind one directory to the CURRENT THREAD for the duration of a call."""
        local = self.__dict__.setdefault("_tenant_local", threading.local())
        anterior = getattr(local, "bundle", None)
        local.bundle = bundle
        try:
            yield bundle
        finally:
            local.bundle = anterior

    def _trava_de_escrita(self, chave: str) -> threading.Lock:
        """One write at a time per directory; reads are not affected."""
        guarda = self.__dict__.setdefault("_guarda_das_travas", threading.Lock())
        with guarda:
            return self.__dict__.setdefault("_travas_de_escrita", {}).setdefault(
                chave, threading.Lock())

    def _executor(self) -> ThreadPoolExecutor:
        executor = self.__dict__.get("_pool_de_threads")
        if executor is None:
            executor = self.__dict__.setdefault("_pool_de_threads", ThreadPoolExecutor(
                max_workers=self._TRABALHADORES, thread_name_prefix="ad-mcp"))
        return executor

    async def _em_thread(self, funcao, prazo, tool_name, escrita=False, ad_server=None):
        """Run blocking LDAP work off the event loop, answering within a deadline.

        The work keeps running after the deadline (a thread cannot be killed);
        the caller gets an explanation instead of the client's silent timeout.
        """
        loop = asyncio.get_running_loop()
        futuro = loop.run_in_executor(self._executor(), funcao)
        try:
            return await asyncio.wait_for(asyncio.shield(futuro), timeout=prazo)
        except asyncio.TimeoutError:
            self.logger.error("tools/call %s excedeu %.0fs (ad_server=%s)", tool_name, prazo,
                              ad_server)
            return self._tempo_esgotado(tool_name, prazo, escrita, ad_server)

    @staticmethod
    def _tempo_esgotado(tool_name, prazo, escrita, ad_server=None) -> dict:
        resposta = {
            "sucesso": False,
            "erro": "TEMPO_ESGOTADO",
            "tool": tool_name,
            "mensagem": (
                f"O Active Directory nao respondeu em {prazo:.0f}s. "
                + ("A alteracao PODE ter sido aplicada: confira o objeto com uma consulta "
                   "antes de repetir." if escrita else
                   "Nada foi confirmado. Use ad_test_ldap_connection_status para ver se o AD "
                   "esta acessivel.")),
        }
        if ad_server:
            resposta["ad_server"] = ad_server
        return resposta

    def _init_client_security(self):
        """Initialize client security manager."""
        try:
            if self.config_path and os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config_dict = json.load(f)
            else:
                config_dict = {}

            self.security_manager = init_security_manager(config_dict, self.config_path)
            self.logger.info(f"Client: {self.security_manager.client_name}")
        except Exception as e:
            self.logger.warning(f"Security manager init failed: {e}")
            self.security_manager = None

    def _test_connection(self):
        """Test LDAP connection on startup."""
        try:
            info = self.ldap_manager.test_connection()
            if info.get('connected'):
                self.logger.info(f"LDAP connected: {info.get('server')}")
            else:
                self.logger.error(f"LDAP failed: {info.get('error')}")
        except Exception as e:
            self.logger.error(f"LDAP test error: {e}")

    def _check_write_permission(self, operation: str, target: str,
                                 automation_token: Optional[str] = None,
                                 client_confirmation: Optional[str] = None) -> dict:
        """Check if write operation is permitted."""
        if not self.security_manager:
            return {"permitted": True, "mode": "no_security"}
        resultado = self.security_manager.check_write_permission(
            operation, target, automation_token, client_confirmation
        )
        if not resultado.get("permitted"):
            # A refusal that carries neither success nor erro is ambiguous to
            # every consumer: it is what made _atualizar_e_mover treat it as a
            # success and move the object anyway (audit 2026-09-21).
            resultado = {"success": False, "sucesso": False,
                         "erro": "CONFIRMACAO_NECESSARIA", **resultado}
        return resultado

    # ------------------------------------------------------------ catalogue
    # 2026-09-19: 38 tools became 10 -- one read-only search_* and one
    # manage_* (with an ``action``) per kind of object, the house pattern
    # (MELHORES-PRATICAS 4.1 and 5.6). A lookup of ONE object lives in
    # search_*, not in manage_*: the Skyller approval classifier scores a
    # whole tool, so a get inside manage_* would put an approval card on
    # every read.
    ACOES = {
        "ad_manage_directory_users": ["create", "update", "move", "enable", "disable",
                                      "reset_password", "delete"],
        "ad_manage_directory_groups": ["create", "update", "move", "add_members",
                                       "remove_members", "delete"],
        "ad_manage_directory_computers": ["create", "update", "move", "enable", "disable",
                                          "reset_trust", "delete"],
        "ad_manage_organizational_units": ["create", "update", "move", "delete"],
    }
    RELATORIOS = ["domain_policy", "privileged_groups", "admin_accounts",
                  "password_violations", "user_permissions"]

    # What each action needs and reads. A parameter that the chosen action
    # does not read is reported back as ignored instead of vanishing.
    REQUISITOS_POR_ACAO = {
        ("ad_manage_directory_users", "create"): (
            ["password", "first_name", "last_name"],
            ["email", "ou", "copy_from_user", "must_change_password", "attributes"]),
        ("ad_manage_directory_users", "update"): ([], ["attributes", "move_to_ou"]),
        ("ad_manage_directory_users", "move"): (["move_to_ou"], []),
        ("ad_manage_directory_users", "enable"): ([], ["move_to_ou"]),
        ("ad_manage_directory_users", "disable"): ([], ["move_to_ou", "remove_from_groups"]),
        ("ad_manage_directory_users", "reset_password"): (
            [], ["password", "must_change_password", "password_never_expires"]),
        ("ad_manage_directory_users", "delete"): ([], []),
        ("ad_manage_directory_groups", "create"): (
            [], ["display_name", "description", "ou", "group_scope", "group_type", "attributes"]),
        ("ad_manage_directory_groups", "update"): ([], ["attributes", "description",
                                                        "move_to_ou"]),
        ("ad_manage_directory_groups", "move"): (["move_to_ou"], []),
        ("ad_manage_directory_groups", "add_members"): (["members"], []),
        ("ad_manage_directory_groups", "remove_members"): (["members"], []),
        ("ad_manage_directory_groups", "delete"): ([], []),
        ("ad_manage_directory_computers", "create"): (
            [], ["description", "ou", "dns_hostname", "attributes"]),
        ("ad_manage_directory_computers", "update"): ([], ["attributes", "description",
                                                           "move_to_ou"]),
        ("ad_manage_directory_computers", "move"): (["move_to_ou"], []),
        ("ad_manage_directory_computers", "enable"): ([], []),
        ("ad_manage_directory_computers", "disable"): ([], []),
        ("ad_manage_directory_computers", "reset_trust"): ([], []),
        ("ad_manage_directory_computers", "delete"): ([], []),
        ("ad_manage_organizational_units", "create"): (
            ["name"], ["parent_ou", "description", "managed_by", "attributes"]),
        ("ad_manage_organizational_units", "update"): (
            ["ou_dn"], ["attributes", "description", "managed_by", "move_to_ou"]),
        ("ad_manage_organizational_units", "move"): (["ou_dn", "move_to_ou"], []),
        ("ad_manage_organizational_units", "delete"): (["ou_dn"], ["force"]),
    }

    def _build_tool_registry(self):
        """Build the catalogue: ten tools, the same in single and multi mode."""
        texto = {"anyOf": [{"type": "string"}, {"type": "null"}]}
        inteiro = {"anyOf": [{"type": "integer"}, {"type": "null"}]}
        lista = {"anyOf": [{"type": "array", "items": {}}, {"type": "null"}]}
        objeto = {"anyOf": [{"type": "object"}, {"type": "null"}]}
        um_ou_varios = {"anyOf": [{"type": "string"},
                                  {"type": "array", "items": {"type": "string"}}]}
        confirmacao = {"automation_token": dict(texto), "client_confirmation": dict(texto)}
        leitura = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True,
                   "openWorldHint": True}
        escrita = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False,
                   "openWorldHint": True}

        def ferramenta(nome, titulo, propriedades, obrigatorios, handler, anotacoes, **extra):
            self.tools[nome] = {
                "description": DESCRICOES_TOOLS[nome],
                # deepcopy: these spec dicts are shared between tools, and
                # aplicar_descricoes mutates them -- object_types' enum leaked
                # into every `attributes` (audit 2026-09-21).
                # one deepcopy per property: copying the dict as a whole keeps
                # two keys that referenced the same spec object aliased, and
                # aplicar_descricoes then mutates both at once.
                "inputSchema": {"type": "object",
                                "properties": {k: copy.deepcopy(v)
                                               for k, v in propriedades.items()},
                                "required": list(obrigatorios)},
                "handler": handler,
                "annotations": {"title": titulo, **anotacoes},
                **extra,
            }

        def acao(nome_tool):
            return {"type": "string", "enum": list(self.ACOES[nome_tool])}

        self.tools = {}

        ferramenta("ad_search_directory_servers", "Servidores de AD configurados", {
            "server_name": texto,
            "test_connection": {"type": "boolean", "default": False},
        }, [], self._handle_search_servers, leitura, **{"global": True})

        ferramenta("ad_search_directory_users", "Buscar usuários no AD", {
            "username": texto, "filter_criteria": texto, "ou": texto,
            "inactive_days": inteiro,
            "include_disabled": {"type": "boolean", "default": False},
            "attributes": lista,
        }, [], self._handle_search_users, leitura)

        ferramenta("ad_manage_directory_users", "Gerenciar usuários do AD", {
            "action": acao("ad_manage_directory_users"),
            "username": {"type": "string"},
            "password": texto, "first_name": texto, "last_name": texto, "email": texto,
            "ou": texto, "copy_from_user": texto,
            "must_change_password": {"type": "boolean", "default": True},
            "password_never_expires": {"type": "boolean", "default": False},
            "attributes": objeto, "move_to_ou": texto,
            "remove_from_groups": {"type": "boolean", "default": False},
            **confirmacao,
        }, ["action", "username"], self._handle_manage_users, escrita)

        ferramenta("ad_search_directory_groups", "Buscar grupos no AD", {
            "group_name": texto,
            "recursive": {"type": "boolean", "default": False},
            "filter_criteria": texto, "ou": texto, "attributes": lista,
        }, [], self._handle_search_groups, leitura)

        ferramenta("ad_manage_directory_groups", "Gerenciar grupos do AD", {
            "action": acao("ad_manage_directory_groups"),
            "group_name": um_ou_varios,
            "members": {"anyOf": [{"type": "string"},
                                  {"type": "array", "items": {"type": "string"}},
                                  {"type": "null"}]},
            "display_name": texto, "description": texto, "ou": texto,
            "group_scope": {"type": "string", "default": "Global"},
            "group_type": {"type": "string", "default": "Security"},
            "attributes": objeto, "move_to_ou": texto,
            **confirmacao,
        }, ["action", "group_name"], self._handle_manage_groups, escrita)

        ferramenta("ad_search_directory_computers", "Buscar computadores no AD", {
            "computer_name": texto, "filter_criteria": texto, "ou": texto,
            "inactive_days": inteiro, "attributes": lista,
        }, [], self._handle_search_computers, leitura)

        ferramenta("ad_manage_directory_computers", "Gerenciar computadores do AD", {
            "action": acao("ad_manage_directory_computers"),
            "computer_name": {"type": "string"},
            "description": texto, "ou": texto, "dns_hostname": texto,
            "attributes": objeto, "move_to_ou": texto,
            **confirmacao,
        }, ["action", "computer_name"], self._handle_manage_computers, escrita)

        ferramenta("ad_search_organizational_units", "Buscar OUs no AD", {
            "ou_dn": texto, "object_types": lista,
            "parent_ou": texto, "filter_criteria": texto,
            "recursive": {"type": "boolean", "default": True},
            "attributes": lista,
        }, [], self._handle_search_ous, leitura)

        ferramenta("ad_manage_organizational_units", "Gerenciar OUs do AD", {
            "action": acao("ad_manage_organizational_units"),
            "ou_dn": texto, "name": texto, "parent_ou": texto,
            "description": texto, "managed_by": texto, "attributes": objeto,
            "move_to_ou": texto,
            "force": {"type": "boolean", "default": False},
            **confirmacao,
        }, ["action"], self._handle_manage_ous, escrita)

        ferramenta("ad_search_security_reports", "Relatórios de segurança do AD", {
            "report": {"type": "string", "enum": list(self.RELATORIOS)},
            "username": texto,
        }, ["report"], self._handle_security_reports, leitura)

        # Not listed: reached only through ALIASES_DE_TOOLS (old names) and
        # internally (test_connection). They keep their own code paths.
        ferramenta("ad_test_ldap_connection_status", "Teste de conexão LDAP", {},
                   [], self._handle_test_connection, leitura, oculta=True)
        ferramenta("ad_move_organizational_unit_parent", "Mover objeto de OU", {
            "object_name": {"type": "string"},
            "object_type": {"type": "string",
                            "enum": ["user", "computer", "group", "organizational_unit"]},
            "ou_dn": {"type": "string"}, "new_parent_dn": {"type": "string"},
            **confirmacao,
        }, ["new_parent_dn"], self._handle_move_organizational_unit, escrita, oculta=True)

        # ---------------------------------------------------------------
        # Multi-AD layer (no-op in single mode)
        # ---------------------------------------------------------------
        if self.multi:
            self._inject_ad_server_parameter()

        # Parameter texts and enums come from tools/definitions.py.
        for name, tool in self.tools.items():
            aplicar_descricoes(name, tool["inputSchema"])

    # ============= MULTI-AD LAYER =============

    _AD_SERVER_PARAM = {
        "type": "string",
        "description": (
            "Servidor de Active Directory alvo. OBRIGATORIO nesta tool de escrita: "
            "uma alteracao precisa nomear um unico diretorio, e 'todos' nao e aceito. "
            "Aceita o nome do cliente como o usuario falou (ex.: Empresa Alfa), apelido, "
            "dominio ou slug; nao precisa consultar ad_search_directory_servers antes."
        ),
    }

    _AD_SERVER_PARAM_LEITURA = {
        "type": "string",
        "description": (
            "Servidor de Active Directory a consultar. Opcional: se omitido, ou com "
            "'todos'/'all', a busca roda em TODOS os ADs configurados e a resposta diz "
            "em qual cada resultado foi encontrado. Use isso quando nao souber onde a "
            "pessoa ou o objeto esta. Aceita o nome do cliente (ex.: Empresa Alfa), "
            "apelido, dominio ou slug."
        ),
    }

    # Values that mean "every configured directory".
    _TODOS = {"all", "todos", "todas", "*", "any", "qualquer", "geral", "tudo"}

    def _is_write_tool(self, tool: dict) -> bool:
        """A tool is a write when its own schema asks for a confirmation.

        @MX:ANCHOR Derived from the schema, never from a hand-kept list: a new
        write tool is covered the moment it declares client_confirmation.
        """
        props = (tool.get("inputSchema") or {}).get("properties") or {}
        return "client_confirmation" in props or "automation_token" in props

    def _inject_ad_server_parameter(self) -> None:
        """Add the required ad_server parameter to every directory-bound tool.

        @MX:ANCHOR The schema is the only place the requirement is declared;
        handle_tools_call is the only place it is enforced. Both must agree on
        the same set (everything not marked "global").
        """
        for name, tool in self.tools.items():
            if tool.get("global"):
                continue
            escrita = self._is_write_tool(tool)
            tool["write"] = escrita

            schema = dict(tool.get("inputSchema") or {"type": "object"})
            properties = dict(schema.get("properties") or {})
            param = dict(self._AD_SERVER_PARAM if escrita else self._AD_SERVER_PARAM_LEITURA)
            # ad_server first: the model reads the routing key before the payload.
            merged = {"ad_server": param}
            merged.update(properties)
            schema["properties"] = merged

            required = list(schema.get("required") or [])
            if escrita:
                # A write must name exactly one directory. There is no "all".
                if "ad_server" not in required:
                    required.insert(0, "ad_server")
            else:
                # Reads may omit it: absent means every configured directory.
                required = [r for r in required if r != "ad_server"]
            schema["required"] = required
            tool["inputSchema"] = schema

    def _handle_list_ad_servers(self, params: dict) -> dict:
        procurado = str(params.get("server_name") or "").strip()
        if procurado:
            return self._handle_check_client_exists({"server_name": procurado})
        if not self.multi or self.pool is None:
            return {
                "modo": "single",
                "total": 1,
                "mensagem": (
                    "Esta instancia atende um unico Active Directory, entao nao existe "
                    "parametro ad_server. Nao informe ad_server nas demais tools."
                ),
                "servidor": {
                    "dominio": self.config.active_directory.domain,
                    "servidor_ldap": self.config.active_directory.server,
                    "base_dn": self.config.active_directory.base_dn,
                },
            }
        return self.pool.list_servers()

    # ============= TOOL HANDLERS =============

    def _format_result(self, result) -> dict:
        """Format tool result for MCP response."""
        if isinstance(result, list) and len(result) > 0:
            # Handle MCP TextContent format
            if hasattr(result[0], 'text'):
                try:
                    return json.loads(result[0].text)
                except:
                    return {"text": result[0].text}
        if isinstance(result, dict):
            return result
        return {"result": str(result)}

    # ============= search_* / manage_* DISPATCH =============
    # Each action reuses the per-operation handler below it, which already
    # checks write permission and was covered by the write audit. The
    # dispatcher only validates what the action needs and says what it ignored.

    _PARAMETROS_DE_BASE = {"action", "ad_server", "automation_token", "client_confirmation",
                           "username", "group_name", "computer_name"}

    # Where each manage_* tool carries the name of the object it acts on, for
    # the audit log and the confirmation gate.
    _ALVO_DA_TOOL = {
        "ad_manage_directory_users": "username",
        "ad_manage_directory_groups": "group_name",
        "ad_manage_directory_computers": "computer_name",
        "ad_manage_organizational_units": "ou_dn",
    }

    @staticmethod
    def _recusado(payload) -> bool:
        """Whether a step refused. A permission refusal carries 'permitted',
        not 'success': looking only at 'success' counted it as a success and
        let the next step run (audit 2026-09-21)."""
        if not isinstance(payload, dict):
            return False
        return (payload.get("success") is False or payload.get("sucesso") is False
                or payload.get("permitted") is False)

    def _checar_acao(self, tool_name: str, params: dict):
        """Return (action, refusal, ignored) for a manage_* call.

        @MX:ANCHOR Every action of every manage_* tool passes here, so this is
        where the write gate is applied -- once.
        @MX:REASON The dispatch introduced a second way in: action="move" went
        straight to the move helper and skipped the confirmation that every
        other write asks for (audit 2026-09-21).
        """
        acao = params.get("action")
        obrigatorios, opcionais = self.REQUISITOS_POR_ACAO[(tool_name, acao)]
        faltando = [c for c in obrigatorios if params.get(c) in (None, "", [], {})]
        if not faltando:
            alvo = params.get(self._ALVO_DA_TOOL.get(tool_name, "")) or params.get("name") or ""
            permissao = self._check_write_permission(
                f"{tool_name}:{acao}", str(alvo),
                params.get("automation_token"), params.get("client_confirmation"))
            if not permissao.get("permitted"):
                return acao, permissao, []
        if faltando:
            return acao, {
                "sucesso": False, "erro": "PARAMETRO_OBRIGATORIO_AUSENTE", "tool": tool_name,
                "mensagem": (f"action='{acao}' exige {', '.join(faltando)}. Nada foi executado."),
                "parametros_faltando": faltando,
            }, []
        props = self.tools[tool_name]["inputSchema"].get("properties") or {}
        usados = set(obrigatorios) | set(opcionais) | self._PARAMETROS_DE_BASE
        if tool_name == "ad_manage_organizational_units":
            usados |= {"ou_dn"}
        ignorados = []
        for chave, valor in params.items():
            if chave.startswith("_") or chave in usados or chave not in props:
                continue
            padrao = (props.get(chave) or {}).get("default")
            if valor not in (None, "", [], {}) and valor != padrao:
                ignorados.append(chave)
        return acao, None, ignorados

    @staticmethod
    def _com_ignorados(resultado, ignorados):
        if ignorados and isinstance(resultado, dict):
            resultado = dict(resultado)
            resultado["parametros_ignorados"] = {
                "nomes": ignorados,
                "motivo": "a action escolhida nao usa estes parametros; nada foi feito com eles",
            }
        return resultado

    def _dn_por_login(self, filtro_classe: str, login: str) -> Optional[str]:
        achado = self.ldap_manager.search(
            search_base=self.config.active_directory.base_dn,
            search_filter=f"(&{filtro_classe}(sAMAccountName={escape_filter_chars(login)}))",
            attributes=["sAMAccountName"])
        return achado[0]["dn"] if achado else None

    def _mover(self, filtro_classe: str, login: str, destino: str, rotulo: str) -> dict:
        dn = self._dn_por_login(filtro_classe, login)
        if dn is None:
            return {"success": False, "error": f"{rotulo} '{login}' not found"}
        return self._format_result(self.ou_tools.move_object(dn, destino))

    def _atualizar_e_mover(self, atualizar, mover, params: dict, tool_name: str) -> dict:
        """update = change attributes and/or move, in that order, both reported."""
        if not params.get("attributes") and not params.get("description") \
                and not params.get("managed_by") and not params.get("move_to_ou"):
            return {
                "sucesso": False, "erro": "PARAMETRO_OBRIGATORIO_AUSENTE", "tool": tool_name,
                "mensagem": ("action='update' precisa de algo a alterar: attributes (campos) "
                             "e/ou move_to_ou (nova OU). Nada foi executado."),
            }
        partes = {}
        if params.get("attributes") or params.get("description") or params.get("managed_by"):
            partes["atualizacao"] = atualizar()
            if self._recusado(partes["atualizacao"]):
                # Do not move an object whose update was refused: the call
                # would end up half applied and reported as a success.
                return partes["atualizacao"]
        if params.get("move_to_ou"):
            partes["movimento"] = mover()
        if len(partes) == 1:
            return next(iter(partes.values()))
        ok = not any(self._recusado(v) for v in partes.values())
        return {"success": ok, **partes}

    # -------------------------------------------------------------- servers
    def _handle_search_servers(self, params: dict) -> dict:
        return self._handle_list_ad_servers(params)

    # ---------------------------------------------------------------- users
    _FILTRO_PESSOA = "(objectCategory=person)(objectClass=user)"

    def _handle_search_users(self, params: dict) -> dict:
        if params.get("username"):
            return self._handle_get_user(params)
        if params.get("inactive_days") is not None:
            return self._handle_get_inactive_users({
                "days": params["inactive_days"],
                "include_disabled": params.get("include_disabled", False) is True})
        return self._handle_list_users(params)

    def _handle_manage_users(self, params: dict) -> dict:
        tool = "ad_manage_directory_users"
        acao, recusa, ignorados = self._checar_acao(tool, params)
        if recusa:
            return recusa
        p = dict(params)
        if acao == "create":
            p["additional_attributes"] = p.pop("attributes", None)
            r = self._handle_create_user(p)
        elif acao == "update":
            r = self._atualizar_e_mover(
                lambda: self._handle_modify_user(p),
                lambda: self._mover(self._FILTRO_PESSOA, p["username"], p["move_to_ou"],
                                    "User"), p, tool)
        elif acao == "move":
            r = self._mover(self._FILTRO_PESSOA, p["username"], p["move_to_ou"], "User")
        elif acao == "enable":
            r = self._handle_enable_user(p)
        elif acao == "disable":
            r = self._handle_disable_user(p)
        elif acao == "reset_password":
            r = self._handle_reset_user_password({
                **p, "new_password": p.get("password"),
                "force_change": p.get("must_change_password", True) is not False})
        else:
            r = self._handle_delete_user(p)
        return self._com_ignorados(r, ignorados)

    # --------------------------------------------------------------- groups
    def _handle_search_groups(self, params: dict) -> dict:
        if params.get("group_name"):
            return self._handle_get_group(params)
        return self._handle_list_groups(params)

    def _handle_manage_groups(self, params: dict) -> dict:
        tool = "ad_manage_directory_groups"
        acao, recusa, ignorados = self._checar_acao(tool, params)
        if recusa:
            return recusa
        p = dict(params)
        grupos = p.get("group_name")
        if acao not in ("add_members", "remove_members") and isinstance(grupos, list):
            if len(grupos) != 1:
                return {"sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool,
                        "mensagem": (f"action='{acao}' age sobre UM grupo; lista de grupos so "
                                     "vale para add_members/remove_members. Nada foi executado.")}
            p["group_name"] = grupos[0]
        if acao == "create":
            p["additional_attributes"] = p.pop("attributes", None)
            r = self._handle_create_group(p)
        elif acao == "update":
            atributos = dict(p.get("attributes") or {})
            if p.get("description"):
                atributos.setdefault("description", p["description"])
            r = self._atualizar_e_mover(
                lambda: self._handle_modify_group({**p, "attributes": atributos}),
                lambda: self._mover("(objectClass=group)", p["group_name"], p["move_to_ou"],
                                    "Group"), p, tool)
        elif acao == "move":
            r = self._mover("(objectClass=group)", p["group_name"], p["move_to_ou"], "Group")
        elif acao in ("add_members", "remove_members"):
            p["member_dn"] = p.get("members")
            r = self._handle_add_group_member(p) if acao == "add_members" \
                else self._handle_remove_group_member(p)
        else:
            r = self._handle_delete_group(p)
        return self._com_ignorados(r, ignorados)

    # ------------------------------------------------------------ computers
    def _handle_search_computers(self, params: dict) -> dict:
        if params.get("computer_name"):
            return self._handle_get_computer(params)
        if params.get("inactive_days") is not None:
            return self._handle_get_stale_computers({"days": params["inactive_days"]})
        return self._handle_list_computers(params)

    def _handle_manage_computers(self, params: dict) -> dict:
        tool = "ad_manage_directory_computers"
        acao, recusa, ignorados = self._checar_acao(tool, params)
        if recusa:
            return recusa
        p = dict(params)
        login = str(p["computer_name"])
        login = login if login.endswith("$") else login + "$"
        if acao == "create":
            p["additional_attributes"] = p.pop("attributes", None)
            r = self._handle_create_computer(p)
        elif acao == "update":
            atributos = dict(p.get("attributes") or {})
            if p.get("description"):
                atributos.setdefault("description", p["description"])
            r = self._atualizar_e_mover(
                lambda: self._handle_modify_computer({**p, "attributes": atributos}),
                lambda: self._mover("(objectClass=computer)", login, p["move_to_ou"],
                                    "Computer"), p, tool)
        elif acao == "move":
            r = self._mover("(objectClass=computer)", login, p["move_to_ou"], "Computer")
        elif acao == "enable":
            r = self._handle_enable_computer(p)
        elif acao == "disable":
            r = self._handle_disable_computer(p)
        elif acao == "reset_trust":
            r = self._handle_reset_computer_password(p)
        else:
            r = self._handle_delete_computer(p)
        return self._com_ignorados(r, ignorados)

    # ------------------------------------------------------------------ OUs
    def _handle_search_ous(self, params: dict) -> dict:
        if params.get("ou_dn"):
            return self._handle_get_organizational_unit(params)
        return self._handle_list_organizational_units(params)

    def _handle_manage_ous(self, params: dict) -> dict:
        tool = "ad_manage_organizational_units"
        acao, recusa, ignorados = self._checar_acao(tool, params)
        if recusa:
            return recusa
        p = dict(params)
        if acao == "create":
            p["additional_attributes"] = p.pop("attributes", None)
            r = self._handle_create_organizational_unit(p)
        elif acao == "update":
            atributos = dict(p.get("attributes") or {})
            for campo, ldap in (("description", "description"), ("managed_by", "managedBy")):
                if p.get(campo):
                    atributos.setdefault(ldap, p[campo])
            r = self._atualizar_e_mover(
                lambda: self._handle_modify_organizational_unit({**p, "attributes": atributos}),
                lambda: self._handle_move_organizational_unit(
                    {**p, "new_parent_dn": p["move_to_ou"]}), p, tool)
        elif acao == "move":
            r = self._handle_move_organizational_unit({**p, "new_parent_dn": p["move_to_ou"]})
        else:
            r = self._handle_delete_organizational_unit(p)
        return self._com_ignorados(r, ignorados)

    # ------------------------------------------------------------- security
    def _handle_security_reports(self, params: dict) -> dict:
        relatorio = params.get("report")
        if relatorio == "user_permissions":
            if not params.get("username"):
                return {"sucesso": False, "erro": "PARAMETRO_OBRIGATORIO_AUSENTE",
                        "tool": "ad_search_security_reports",
                        "mensagem": "report='user_permissions' exige username. Nada foi executado.",
                        "parametros_faltando": ["username"]}
            return self._handle_get_user_permissions(params)
        return {
            "domain_policy": self._handle_get_domain_info,
            "privileged_groups": self._handle_get_privileged_groups,
            "admin_accounts": self._handle_audit_admin_accounts,
            "password_violations": self._handle_get_password_policy_violations,
        }[relatorio](params)

    def _handle_get_client_info(self, params: dict) -> dict:
        if self.security_manager:
            info = self.security_manager.get_client_info()
            if self.multi and self._bound_server:
                info["ad_server"] = self._bound_server
            return info
        return {
            "client": {"name": "Unknown", "slug": "unknown"},
            "domain": {"name": self.config.active_directory.domain},
            "warning": "Security manager not initialized"
        }

    def _handle_list_ad_clients(self, params: dict) -> dict:
        if self.multi and self.pool is not None:
            listing = self.pool.list_servers()
            return {
                "total": listing["total"],
                "clients": [
                    {
                        "slug": s["ad_server"],
                        "name": s["nome"],
                        "domain": s["dominio"],
                        "type": s.get("tipo", "cliente"),
                        "status": s["status"],
                    }
                    for s in listing["servidores"]
                ],
                "message": (
                    "Clientes com AD configurado nesta instancia multi-AD. Use o campo "
                    "'slug' no parametro ad_server das demais tools."
                ),
                "detalhes": "Chame ad_search_directory_servers para dominio, host, base DN e OUs.",
            }

        # Single-AD mode: this process serves exactly one client, and saying
        # so is the whole truth available here. (There used to be a central
        # registry file; it pointed at a path that never existed and listed
        # ports that were never used, so it always answered "no clients".)
        if not self.security_manager:
            return {
                "total": 0,
                "clients": [],
                "message": "Identificacao de cliente indisponivel nesta instancia.",
            }
        return {
            "total": 1,
            "clients": [{
                "slug": self.security_manager.client_slug,
                "name": self.security_manager.client_name,
                "domain": self.security_manager.domain,
                "type": self.security_manager.client_type,
            }],
            "current_instance": {
                "name": self.security_manager.client_name,
                "slug": self.security_manager.client_slug,
                "domain": self.security_manager.domain,
            },
            "message": (
                f"Esta instancia atende um unico cliente: "
                f"{self.security_manager.client_name} ({self.security_manager.domain}). "
                "Outros clientes podem existir em outras instancias e nao aparecem aqui."
            ),
        }

    def _handle_check_client_exists(self, params: dict) -> dict:
        # server_name is the multi-AD name; client_name is the single-AD legacy one.
        client_name = params.get("server_name") or params.get("client_name") or ""

        if self.multi and self.pool is not None:
            bundle, error = self.pool.resolve_or_error(client_name)
            if error is not None:
                return {"exists": False, "searched_for": client_name, **error}
            detalhes = next((s for s in self.pool.list_servers()["servidores"]
                             if s.get("ad_server") == bundle.key), {})
            return {
                "exists": True,
                "ad_server": bundle.key,
                "client": {
                    "slug": bundle.key,
                    "name": bundle.entry.label,
                    "domain": bundle.entry.domain,
                },
                "servidor": detalhes,
                "message": (
                    f"Cliente '{bundle.entry.label}' tem AD configurado. Use "
                    f"ad_server='{bundle.key}' -- ou o proprio nome do cliente, que as "
                    "demais tools tambem aceitam."
                ),
            }

        if not self.security_manager:
            return {"exists": False, "searched_for": client_name,
                    "message": "Identificacao de cliente indisponivel nesta instancia."}

        normalized = str(client_name).lower().strip().replace(" ", "-")
        known = {
            self.security_manager.client_slug,
            self.security_manager.client_name.lower().replace(" ", "-"),
            self.security_manager.domain.split(".")[0].lower(),
        }
        if normalized in known:
            return {
                "exists": True,
                "client": {
                    "slug": self.security_manager.client_slug,
                    "name": self.security_manager.client_name,
                    "domain": self.security_manager.domain,
                },
            }
        return {
            "exists": False,
            "searched_for": client_name,
            "available": [f"{self.security_manager.client_name} "
                          f"({self.security_manager.client_slug})"],
            "message": (
                f"Esta instancia atende apenas {self.security_manager.client_name}. "
                f"Nao e possivel afirmar, daqui, se '{client_name}' tem AD em outra "
                "instancia."
            ),
        }

    def _handle_list_users(self, params: dict) -> dict:
        result = self.user_tools.list_users(
            params.get("ou"), params.get("filter_criteria"), params.get("attributes")
        )
        return self._format_result(result)

    def _handle_get_user(self, params: dict) -> dict:
        result = self.user_tools.get_user(params["username"], params.get("attributes"))
        return self._format_result(result)

    def _handle_create_user(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_create_user_account", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        # Top-level attributes were folded into additional_attributes by the
        # sanitizer, before name resolution (see _dobrar_atributos_de_topo).
        movidos = params.get("_lidos_como_atributos") or []
        result = self._format_result(self.user_tools.create_user(
            params["username"], params["password"], params["first_name"], params["last_name"],
            params.get("email"), params.get("ou"), params.get("additional_attributes"),
            must_change_password=params.get("must_change_password"),
            copy_from_user=params.get("copy_from_user"),
        ))
        if movidos and isinstance(result, dict):
            result["parametros_lidos_como_atributos"] = movidos
        return result

    def _handle_modify_user(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_modify_user_attributes", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.user_tools.modify_user(params["username"], params["attributes"])
        return self._format_result(result)

    def _handle_delete_user(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_delete_user_account_permanently", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.user_tools.delete_user(params["username"])
        return self._format_result(result)

    def _handle_enable_user(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_enable_user_account_access", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.user_tools.enable_user(params["username"],
                                             move_to_ou=params.get("move_to_ou"))
        return self._format_result(result)

    def _handle_disable_user(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_disable_user_account_access", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.user_tools.disable_user(
            params["username"], move_to_ou=params.get("move_to_ou"),
            remove_from_groups=params.get("remove_from_groups", False) is True)
        return self._format_result(result)

    def _handle_reset_user_password(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_reset_user_password_forced", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.user_tools.reset_password(
            params["username"], params.get("new_password"),
            params.get("force_change", True), params.get("password_never_expires", False)
        )
        return self._format_result(result)

    def _handle_list_groups(self, params: dict) -> dict:
        result = self.group_tools.list_groups(
            params.get("ou"), params.get("filter_criteria"), params.get("attributes")
        )
        return self._format_result(result)

    def _handle_get_group(self, params: dict) -> dict:
        result = self.group_tools.get_group(params["group_name"], params.get("attributes"),
                                            recursive=params.get("recursive", False) is True)
        return self._format_result(result)

    def _handle_create_group(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_create_group_security_or_distribution", params["group_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.group_tools.create_group(
            params["group_name"], params.get("display_name"), params.get("description"),
            params.get("ou"), params.get("group_scope", "Global"),
            params.get("group_type", "Security"), params.get("additional_attributes")
        )
        return self._format_result(result)

    def _handle_modify_group(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_modify_group_attributes", params["group_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.group_tools.modify_group(params["group_name"], params["attributes"])
        return self._format_result(result)

    def _handle_delete_group(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_delete_group_permanently", params["group_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.group_tools.delete_group(params["group_name"])
        return self._format_result(result)

    def _handle_add_group_member(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_add_member_to_group", str(params["group_name"]),
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.group_tools.add_member(params["group_name"], params["member_dn"])
        return self._format_result(result)

    def _handle_remove_group_member(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_remove_member_from_group", str(params["group_name"]),
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.group_tools.remove_member(params["group_name"], params["member_dn"])
        return self._format_result(result)

    def _handle_list_computers(self, params: dict) -> dict:
        result = self.computer_tools.list_computers(
            params.get("ou"), params.get("filter_criteria"), params.get("attributes")
        )
        return self._format_result(result)

    def _handle_get_computer(self, params: dict) -> dict:
        result = self.computer_tools.get_computer(params["computer_name"], params.get("attributes"))
        return self._format_result(result)

    def _handle_create_computer(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_create_computer_account", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.create_computer(
            params["computer_name"], params.get("description"), params.get("ou"),
            params.get("dns_hostname"), params.get("additional_attributes")
        )
        return self._format_result(result)

    def _handle_modify_computer(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_modify_computer_attributes", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.modify_computer(params["computer_name"], params["attributes"])
        return self._format_result(result)

    def _handle_delete_computer(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_delete_computer_account_permanently", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.delete_computer(params["computer_name"])
        return self._format_result(result)

    def _handle_enable_computer(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_enable_computer_account_trust", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.enable_computer(params["computer_name"])
        return self._format_result(result)

    def _handle_disable_computer(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_disable_computer_account_trust", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.disable_computer(params["computer_name"])
        return self._format_result(result)

    def _handle_reset_computer_password(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_reset_computer_password_trust", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.reset_computer_password(params["computer_name"])
        return self._format_result(result)

    def _handle_get_stale_computers(self, params: dict) -> dict:
        result = self.computer_tools.get_stale_computers(params.get("days", 90))
        return self._format_result(result)

    def _handle_list_organizational_units(self, params: dict) -> dict:
        result = self.ou_tools.list_ous(
            params.get("parent_ou"), params.get("filter_criteria"),
            params.get("attributes"), params.get("recursive", True)
        )
        return self._format_result(result)

    def _handle_get_organizational_unit(self, params: dict) -> dict:
        result = self.ou_tools.get_ou(params["ou_dn"], params.get("attributes"),
                                      object_types=params.get("object_types"))
        return self._format_result(result)

    def _handle_create_organizational_unit(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_create_organizational_unit", params["name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.ou_tools.create_ou(
            params["name"], params.get("parent_ou"), params.get("description"),
            params.get("managed_by"), params.get("additional_attributes")
        )
        return self._format_result(result)

    def _handle_modify_organizational_unit(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_modify_organizational_unit_attributes", params["ou_dn"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.ou_tools.modify_ou(params["ou_dn"], params["attributes"])
        return self._format_result(result)

    def _handle_delete_organizational_unit(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_delete_organizational_unit_forced", params["ou_dn"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.ou_tools.delete_ou(params["ou_dn"], params.get("force", False) is True)
        return self._format_result(result)

    def _handle_move_organizational_unit(self, params: dict) -> dict:
        # object_name and ou_dn arrive here already resolved to DNs.
        alvo = params.get("object_name") or params.get("ou_dn")
        if not alvo:
            return {
                "sucesso": False,
                "erro": "PARAMETRO_OBRIGATORIO_AUSENTE",
                "mensagem": (
                    "Informe o que mover: 'object_name' para um usuario, computador, grupo "
                    "ou OU (por nome, login ou DN), ou 'ou_dn' para uma OU. O destino vai "
                    "em 'new_parent_dn'."),
                "parametros_faltando": ["object_name"],
            }
        perm = self._check_write_permission("ad_move_organizational_unit_parent", alvo,
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        # The legacy ou_dn path moves OUs only, as it always did; anything else
        # goes through object_name, which says what it is moving.
        result = self.ou_tools.move_object(alvo, params["new_parent_dn"],
                                           only_ou=not params.get("object_name"))
        return self._format_result(result)

    def _handle_get_domain_info(self, params: dict) -> dict:
        result = self.security_tools.get_domain_info()
        return self._format_result(result)

    def _handle_get_privileged_groups(self, params: dict) -> dict:
        result = self.security_tools.get_privileged_groups()
        return self._format_result(result)

    def _handle_get_user_permissions(self, params: dict) -> dict:
        result = self.security_tools.get_user_permissions(params["username"])
        return self._format_result(result)

    def _handle_get_inactive_users(self, params: dict) -> dict:
        result = self.security_tools.get_inactive_users(
            params.get("days", 90), params.get("include_disabled", False)
        )
        return self._format_result(result)

    def _handle_get_password_policy_violations(self, params: dict) -> dict:
        result = self.security_tools.get_password_policy_violations()
        return self._format_result(result)

    def _handle_audit_admin_accounts(self, params: dict) -> dict:
        result = self.security_tools.audit_admin_accounts()
        return self._format_result(result)

    def _handle_test_connection(self, params: dict) -> dict:
        """Live test of one directory -- also the health answer (tools merged).

        A directory that does not answer comes back as FALHA_AO_CONSULTAR_O_AD
        so a 'todos' run lists it under servidores_com_falha instead of
        counting a {"connected": false} payload as a finding.
        """
        try:
            info = dict(self.ldap_manager.test_connection())
        except Exception as e:
            info = {"connected": False, "error": str(e), "error_type": type(e).__name__}
        cliente = None
        if self.security_manager:
            try:
                cliente = self.security_manager.get_client_info()
            except Exception:  # noqa: BLE001 - the connection answer stands alone
                cliente = None
        if not info.get("connected"):
            falha = {
                "sucesso": False,
                "erro": "FALHA_AO_CONSULTAR_O_AD",
                "mensagem": info.get("error") or "sem conexao com o controlador de dominio",
                "detalhe": info,
            }
            if cliente:
                falha["cliente"] = cliente
            return falha
        info["status"] = "ok" if info.get("search_test", True) else "degradado"
        if cliente:
            info["cliente"] = cliente
        return info

    def _handle_health(self, params: dict) -> dict:
        if self.multi and self.pool is not None:
            listing = self.pool.list_servers()
            servers = listing["servidores"]
            broken = [s["ad_server"] for s in servers
                      if s["status"] in ("configuracao_invalida", "erro")]
            health_info = {
                "status": "degraded" if broken else "ok",
                "server": "ActiveDirectoryMCP-FastAPI",
                "version": "1.1.0",
                "mode": "multi",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "transport": "streamable-http",
                "total_servidores": listing["total"],
                "total_habilitados": listing["total_habilitados"],
                "servidores": [
                    {"ad_server": s["ad_server"], "dominio": s["dominio"],
                     "status": s["status"]}
                    for s in servers
                ],
                "nota": (
                    "Servidores com status 'nao_conectado' ainda nao foram usados nesta "
                    "execucao. A conexao LDAP so e aberta na primeira operacao, portanto "
                    "este health check nao afirma nada sobre a saude deles."
                ),
            }
            if broken:
                health_info["servidores_com_problema"] = broken
            return health_info

        health_info = {
            "status": "ok",
            "server": "ActiveDirectoryMCP-FastAPI",
            "version": "1.1.0",
            "mode": "single",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "transport": "streamable-http",
            "ldap_connection": "unknown"
        }

        if self.security_manager:
            health_info["client"] = {
                "name": self.security_manager.client_name,
                "slug": self.security_manager.client_slug,
                "domain": self.security_manager.domain
            }

        try:
            conn_info = self.ldap_manager.test_connection()
            health_info["ldap_connection"] = "connected" if conn_info.get("connected") else "error"
            health_info["ldap_server"] = conn_info.get("server", "unknown")
        except Exception as e:
            health_info["ldap_connection"] = "error"
            health_info["ldap_error"] = str(e)
            health_info["status"] = "degraded"

        return health_info

    # ============= MCP PROTOCOL HANDLERS =============

    async def handle_initialize(self, params: dict) -> dict:
        """Handle MCP initialize method."""
        return {
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "mcp-active-directory",
                "version": "1.0.0"
            },
            "capabilities": {
                "tools": {},
                "prompts": {}
            },
            "instructions": INSTRUCOES_DO_SERVIDOR,
        }

    async def handle_tools_list(self, params: dict) -> dict:
        """Handle tools/list method."""
        tools_list = []
        for name, tool in self.tools.items():
            if tool.get("oculta"):
                continue
            entrada = {
                "name": name,
                "description": tool["description"],
                "inputSchema": tool["inputSchema"],
            }
            if tool.get("annotations"):
                entrada["annotations"] = dict(tool["annotations"])
            tools_list.append(entrada)
        return {"tools": tools_list}

    def _as_content(self, payload) -> dict:
        """Wrap a payload in the MCP content envelope.

        A failure payload is redacted as a whole: error text is assembled from
        exceptions in many places, and none of them may carry a secret. A
        successful one is not -- a reset must still hand the operator the
        password it set.
        """
        texto = json.dumps(payload, indent=2, ensure_ascii=False)
        if isinstance(payload, dict) and (
                payload.get("success") is False or payload.get("sucesso") is False
                or payload.get("erro") or payload.get("error")):
            texto = redact(texto)
        return {"content": [{"type": "text", "text": texto}]}

    # ============= ENTRADA DE MODELO FRACO =============
    # The server owns its schema, so it can absorb the shapes a model actually
    # sends instead of answering with a Python exception the model cannot act on.

    _CAMPOS_DE_LOGIN = ("username", "computer_name", "group_name")
    _LIMITE_DIAS = 36500  # a hundred years; beyond this datetime itself overflows

    @staticmethod
    def _extrair_login(valor: str) -> str:
        """Reduce a DN, a UPN or DOMAIN\\user to the bare account name."""
        texto = str(valor).strip().strip('"').strip("'")
        if not texto:
            return texto
        if "=" in texto and "," in texto:          # CN=Joao Silva,CN=Users,DC=...
            primeiro = texto.split(",")[0]
            if "=" in primeiro:
                return primeiro.split("=", 1)[1].strip()
        if "\\" in texto:                          # DOMINIO\usuario
            return texto.rsplit("\\", 1)[1].strip()
        if "@" in texto:                            # usuario@dominio
            return texto.split("@", 1)[0].strip()
        return texto

    @staticmethod
    def _coagir(valor, tipos):
        """Best-effort conversion of a value to one of the schema's types."""
        if "array" in tipos and not isinstance(valor, list):
            if isinstance(valor, str) and "string" in tipos \
                    and not valor.strip().startswith("["):
                return valor    # one name where one-or-many is accepted
            if isinstance(valor, str):
                texto = valor.strip()
                if texto.startswith("["):
                    try:
                        carregado = json.loads(texto)
                        if isinstance(carregado, list):
                            return [v for v in carregado if v is not None]
                    except (ValueError, TypeError):
                        pass
                return [texto] if texto else []
            if valor is not None:
                return [valor]
        if "array" in tipos and isinstance(valor, list):
            return [v for v in valor if v is not None]
        if "object" in tipos and isinstance(valor, str):
            try:
                carregado = json.loads(valor)
                if isinstance(carregado, dict):
                    return carregado
            except (ValueError, TypeError):
                pass
        if "integer" in tipos and isinstance(valor, str):
            try:
                return int(valor.strip())
            except ValueError:
                pass
        if "boolean" in tipos and isinstance(valor, str):
            texto = unicodedata.normalize("NFKD", valor.strip().lower().lstrip("$"))
            texto = "".join(c for c in texto if not unicodedata.combining(c))
            if texto in _VERDADEIROS:
                return True
            if texto in _FALSOS:
                return False
        if "boolean" in tipos and isinstance(valor, int) and not isinstance(valor, bool) \
                and valor in (0, 1):
            return bool(valor)
        if "string" in tipos and isinstance(valor, list) and len(valor) == 1:
            return str(valor[0])
        if "string" in tipos and isinstance(valor, (int, float)) and "integer" not in tipos:
            return str(valor)
        return valor

    @staticmethod
    def _tipos_do_schema(spec: dict) -> set:
        tipos = set()
        if isinstance(spec.get("type"), str):
            tipos.add(spec["type"])
        for alternativa in spec.get("anyOf") or []:
            if isinstance(alternativa, dict) and isinstance(alternativa.get("type"), str):
                tipos.add(alternativa["type"])
        return tipos

    def _sanear_argumentos(self, tool_name, tool, args):
        """Coerce arguments to the tool's own schema.

        @MX:ANCHOR Everything here is driven by inputSchema, so a tool added
        later is covered without touching this function. Returns
        (argumentos, recusa) -- recusa is a ready payload when the call cannot
        proceed, and it always says what to send instead.
        """
        schema = tool.get("inputSchema") or {}
        propriedades = schema.get("properties") or {}
        saneados = {}

        bruto_ad_server = args.get("ad_server")
        if bruto_ad_server is not None and not isinstance(bruto_ad_server, (str, list)):
            return None, {
                "sucesso": False,
                "erro": "AD_SERVER_INVALIDO",
                "mensagem": (
                    f"'ad_server' precisa ser um texto com o nome do servidor; veio "
                    f"{type(bruto_ad_server).__name__} ({bruto_ad_server!r}). "
                    "Use ad_search_directory_servers para ver os nomes."
                ),
                "tool": tool_name,
            }

        args = dict(args)
        if "action" in args and isinstance(args["action"], str):
            args["action"] = self._normalizar_acao(args["action"])
        if tool_name == "ad_manage_directory_users" and args.get("action") == "create":
            args = self._dobrar_atributos_de_topo(args, propriedades)

        for chave, valor in args.items():
            spec = propriedades.get(chave)
            if spec is None:
                # Unknown key: keep it, the handler reads by name and ignores it.
                saneados[chave] = valor
                continue
            tipos = self._tipos_do_schema(spec)
            valor = self._coagir(valor, tipos)
            recusa = self._tipo_recusado(tool_name, chave, valor, tipos)
            if recusa is not None:
                return None, recusa
            if spec.get("enum") and valor is not None:
                valor, recusa = self._valor_do_enum(tool_name, chave, valor, spec["enum"])
                if recusa is not None:
                    return None, recusa
            if "boolean" in tipos and (valor is None or (
                    isinstance(valor, str) and valor.strip().lower() in ("", "null", "none"))):
                continue        # "null" for a flag means "use the default"
            # Only the NEW object's name is reduced to a login here. Everything
            # that names an existing object goes to the resolver untouched: a DN
            # or an e-mail identifies the object better than the login cut out
            # of it, and cutting "CN=Full Name,..." yields a CN, not a login.
            # A NEW user's login is never cut: "user@other-domain" or a DN from
            # another tenant used to become an account here (audit 2026-09-19);
            # UserTools.create_user refuses those shapes with an explanation.
            if (chave in self._CAMPOS_DE_LOGIN and isinstance(valor, str)
                    and nome_novo_de(tool_name, args) == chave and chave != "username"):
                valor = self._extrair_login(valor)
            if isinstance(valor, str) and chave != "filter_criteria":
                valor = valor.strip()
            saneados[chave] = valor

        faltando = [c for c in (schema.get("required") or [])
                    if c not in saneados or saneados[c] in (None, "", [])]

        if "ad_server" in faltando and tool.get("write"):
            # The specific message says WHY, which the generic one cannot.
            return None, {
                "sucesso": False,
                "erro": "AD_SERVER_OBRIGATORIO_PARA_ESCRITA",
                "mensagem": (
                    f"A tool {tool_name} altera o Active Directory, entao exige um unico "
                    "servidor em 'ad_server'. 'todos' nao e aceito para escrita, e nao "
                    "existe servidor padrao."
                ),
                "servidores_disponiveis": self.pool._short_catalog() if self.pool else [],
                "tool": tool_name,
            }

        if faltando:
            return None, {
                "sucesso": False,
                "erro": "PARAMETRO_OBRIGATORIO_AUSENTE",
                "mensagem": (
                    f"A tool {tool_name} exige {', '.join(faltando)}, que nao veio na "
                    "chamada. Repita informando esse(s) parametro(s)."
                ),
                "parametros_faltando": faltando,
                "parametros_aceitos": sorted(propriedades),
                "tool": tool_name,
            }

        dias = saneados.get("days", saneados.get("inactive_days"))
        if dias is not None:
            if not isinstance(dias, int):
                return None, {
                    "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
                    "mensagem": f"o numero de dias precisa ser inteiro; veio {dias!r}.",
                }
            if dias <= 0 or dias > self._LIMITE_DIAS:
                return None, {
                    "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
                    "mensagem": (
                        f"o numero de dias precisa estar entre 1 e {self._LIMITE_DIAS}; veio {dias}. "
                        "Um valor negativo ou fora dessa faixa nao descreve um periodo."
                    ),
                }
        return saneados, None

    def _tipo_recusado(self, tool_name, chave, valor, tipos):
        """Refuse a value the schema cannot mean, BEFORE anything is written.

        @MX:WARN Any non-empty string is truthy in Python: "não", "off" or
        "null" in remove_from_groups stripped every group, and force="não"
        deleted an OU with everything inside (audit 2026-09-19). A flag is a
        recognised boolean or it is refused; a single-value parameter never
        takes a list, whose items would be resolved and then passed on raw.
        @MX:REASON Guessing is only safe in the direction that changes nothing,
        and that direction differs per flag, so the server does not guess.
        """
        if "boolean" in tipos and not isinstance(valor, bool) and valor is not None:
            if isinstance(valor, str) and valor.strip().lower() in ("", "null", "none"):
                return None
            return {
                "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
                "mensagem": (
                    f"'{chave}' e sim/nao; veio {valor!r}. Use true ou false (aceitos tambem: "
                    "sim, nao, on, off, 1, 0). Nada foi executado."),
            }
        if isinstance(valor, list) and "array" not in tipos:
            return {
                "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
                "mensagem": (
                    f"'{chave}' recebe um unico valor; veio uma lista com {len(valor)} itens "
                    f"({valor!r}). Nada foi executado."),
            }
        if isinstance(valor, dict) and "object" not in tipos:
            return {
                "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
                "mensagem": f"'{chave}' recebe texto; veio um objeto ({valor!r}). Nada foi executado.",
            }
        return None

    # Words a model uses for an action; compared without case or accents.
    _SINONIMOS_DE_ACAO = {
        "criar": "create", "cadastrar": "create", "novo": "create",
        "atualizar": "update", "alterar": "update", "editar": "update", "modificar": "update",
        "modify": "update", "set": "update",
        "mover": "move", "transferir": "move",
        "ativar": "enable", "habilitar": "enable", "reativar": "enable", "desbloquear": "enable",
        "desativar": "disable", "desabilitar": "disable", "bloquear": "disable",
        "resetar_senha": "reset_password", "redefinir_senha": "reset_password",
        "trocar_senha": "reset_password",
        "reset_password_forced": "reset_password", "reset_computer_password": "reset_trust",
        # "remover"/"remove"/"add"/"reset" are deliberately absent: on a group
        # "remover" may mean the group or its members -- guessing could delete
        # the group. An unknown word is refused with the accepted list.
        "excluir": "delete", "apagar": "delete", "deletar": "delete",
        "adicionar_membros": "add_members", "incluir_membros": "add_members",
        "add_member": "add_members", "remover_membros": "remove_members",
        "remove_member": "remove_members",
    }

    def _normalizar_acao(self, valor: str) -> str:
        texto = unicodedata.normalize("NFKD", valor.strip().lower())
        texto = "".join(c for c in texto if not unicodedata.combining(c))
        texto = texto.replace("-", "_").replace(" ", "_")
        return self._SINONIMOS_DE_ACAO.get(texto, texto)

    @staticmethod
    def _valor_do_enum(tool_name, chave, valor, opcoes):
        """Canonical enum value (case-insensitive) or a refusal listing them all."""
        if isinstance(valor, str):
            for opcao in opcoes:
                if opcao.lower() == valor.strip().lower():
                    return opcao, None
        return None, {
            "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
            "mensagem": (f"'{chave}' nao aceita {valor!r}. Valores aceitos: "
                         f"{', '.join(opcoes)}. Nada foi executado."),
            "valores_aceitos": list(opcoes),
        }

    def _dobrar_atributos_de_topo(self, args, propriedades):
        """Attributes sent beside the schema (department=..., Office=...) join
        additional_attributes BEFORE name resolution, so a top-level manager
        goes through the resolver like any other. They used to be dropped in
        silence, and then (first fix) folded in after resolution, raw."""
        conhecidos = UserTools._ALIASES_DE_ATRIBUTO.keys() | UserTools._OPCOES_DE_CRIACAO.keys() \
            | {"country", "pais", "c", "co", "otherattributes"}
        extras = args.get("attributes")
        extras = dict(extras) if isinstance(extras, dict) else {}
        movidos = []
        for chave, valor in args.items():
            if chave in propriedades:
                continue
            if UserTools._chave_simples(chave) in conhecidos:
                extras.setdefault(chave, valor)
                movidos.append(chave)
        if not movidos:
            return args
        novos = {k: v for k, v in args.items() if k not in movidos}
        novos["attributes"] = extras
        novos["_lidos_como_atributos"] = movidos
        return novos

    _CAMPOS_DN = ("ou", "parent_ou", "target_parent_dn", "source_dn", "ou_dn", "target_dn",
                  "move_to_ou", "new_parent_dn")

    def _validar_dn_no_dominio(self, tool_name, args, bundle):
        """A DN from another domain is a wrong-tenant call, not a search miss.

        Without this the LDAP layer answered "invalid server address", which
        says nothing about the actual mistake.
        """
        base = bundle.config.active_directory.base_dn.lower().replace(" ", "")
        for chave in self._CAMPOS_DN:
            valor = args.get(chave)
            if not isinstance(valor, str) or not valor.strip():
                continue
            alvo = valor.lower().replace(" ", "")
            if "dc=" in alvo and not alvo.endswith(base):
                return {
                    "sucesso": False,
                    "erro": "OU_FORA_DO_DOMINIO",
                    "mensagem": (
                        f"O DN informado em '{chave}' ({valor}) nao pertence ao servidor "
                        f"'{bundle.key}', cujo dominio e {bundle.config.active_directory.base_dn}. "
                        "Ou o ad_server esta errado, ou o DN e de outro cliente."
                    ),
                    "ad_server": bundle.key,
                    "base_dn_do_servidor": bundle.config.active_directory.base_dn,
                    "tool": tool_name,
                }
        return None

    def _resolver_nome_de_tool(self, tool_name):
        """Accept the hub-prefixed name and suggest neighbours for a typo."""
        if tool_name in self.tools:
            return tool_name, None
        nome = str(tool_name or "")
        for prefixo in ("ad-multi-", "ad_multi_", "mcp__ad-multi__", "ad-multi."):
            if nome.startswith(prefixo) and nome[len(prefixo):] in self.tools:
                return nome[len(prefixo):], None
        pedaco = nome.lower().replace("-", "_")
        parecidas = [t for t in self.tools
                     if pedaco in t or any(p in t for p in pedaco.split("_") if len(p) > 4)]
        return None, {
            "sucesso": False,
            "erro": "TOOL_DESCONHECIDA",
            "mensagem": (
                f"Nao existe uma tool chamada '{tool_name}' neste servidor. "
                "Use um dos nomes exatos listados."
            ),
            "tools_parecidas": sorted(parecidas)[:8] or sorted(self.tools)[:8],
        }

    # Above this many characters the aggregated answer is replaced by a
    # per-server summary instead of being silently cut.
    _LIMITE_RESPOSTA = 120_000

    def _executar(self, tool_name, tool, handler, args, propagar_falha=False) -> dict:
        """Resolve the call's identifiers against the bound directory, then run it.

        @MX:ANCHOR The only way a handler runs: single mode, one server and
        every-server calls all come through here.
        @MX:REASON A handler reached any other way would receive what the model
        typed ("Full Name", "Filial/Financeiro") where it expects a login or a
        DN, which is the defect this resolver exists to remove.
        """
        base_dn = self.config.active_directory.base_dn
        try:
            args, recusa, identificacoes = resolver_argumentos(
                tool_name, args, self.ldap_manager, base_dn,
                escrita=self._is_write_tool(tool))
        except Exception as exc:
            if propagar_falha:
                raise
            self.logger.error("Resolucao falhou em %s: %s", tool_name, exc)
            return {
                "sucesso": False, "erro": "FALHA_AO_CONSULTAR_O_AD", "tool": tool_name,
                "mensagem": (
                    "Nao foi possivel consultar o Active Directory para localizar o objeto "
                    f"informado ({type(exc).__name__}: {redact(str(exc))[:200]}). Nada foi "
                    "executado. "
                    "Use ad_test_ldap_connection_status para verificar a conexao."),
            }
        if recusa is not None:
            return recusa
        resultado = handler(args)
        if identificacoes and isinstance(resultado, dict):
            resultado = dict(resultado)
            resultado["identificacao"] = identificacoes
        return resultado

    def _classificar(self, chave, resultado, achados, vazios, falhas, parecidos, recusas):
        """Sort one directory's answer into found / empty / failed."""
        if self._eh_falha(resultado):
            falhas.append({
                "ad_server": chave,
                "erro": resultado.get("erro") or resultado.get("type") or "FALHA",
                "mensagem": (resultado.get("mensagem") or resultado.get("error")
                             or "falha sem detalhe")[:400],
            })
        elif self._tem_resultado(resultado):
            achados[chave] = resultado
        else:
            vazios.append(chave)
            if isinstance(resultado, dict) and resultado.get("parecidos"):
                parecidos[chave] = resultado["parecidos"]
            if isinstance(resultado, dict) and resultado.get("erro") in self._RECUSAS_DE_ENTRADA:
                recusas[chave] = resultado

    @staticmethod
    def _eh_falha(payload) -> bool:
        """A directory that could not be asked is a failure, not an empty answer.

        Tools report exceptions as {"success": false, "error": ..., "type": <class>};
        counting that as "sem resultado" told the model a directory that was
        unreachable simply did not have the person.
        """
        if not isinstance(payload, dict):
            return False
        if payload.get("erro") in ("FALHA_AO_CONSULTAR_O_AD", "TEMPO_ESGOTADO"):
            return True
        return payload.get("success") is False and bool(payload.get("type"))

    # A connectivity test is about every directory, not about finding one
    # object: cutting the slow ones after the first answer hid the real error
    # (VPN down, DC off) behind a generic TEMPO_ESGOTADO.
    _SEM_GRACA = {"ad_test_ldap_connection_status"}

    # Refusals that depend on the input, not on the directory's content.
    _RECUSAS_DE_ENTRADA = {"FILTRO_LDAP_INVALIDO", "PARAMETRO_INVALIDO", "OBJETO_FORA_DO_DOMINIO",
                           "FILTRO_LDAP_PROIBIDO", "ATRIBUTO_SENSIVEL"}

    @staticmethod
    def _tem_resultado(payload) -> bool:
        """Whether a per-server payload actually found something."""
        if not isinstance(payload, dict):
            return bool(payload)
        if payload.get("erro") == "IDENTIFICACAO_AMBIGUA":
            # Candidates ARE a finding: dropping them would report "nothing
            # here" for a directory that holds several matching objects.
            return True
        if payload.get("success") is False or "error" in payload or "erro" in payload:
            return False
        for chave, valor in payload.items():
            if isinstance(valor, list):
                return len(valor) > 0
            if chave.startswith(("total", "count")) and isinstance(valor, int):
                return valor > 0
        return True

    async def _executar_em_todos(self, tool_name, handler, tool_args, pedido) -> dict:
        """Run a read tool against every enabled directory, in parallel, and merge.

        @MX:ANCHOR A server that fails is listed, never dropped: an omitted
        directory reads as "nothing there", which is a different -- and false --
        statement from "could not look".
        @MX:REASON Measured 2026-09-19: sequential, one directory with its VPN
        down cost 32 s each and pushed every "todos" call past the client's 30 s.
        All directories now run at once; once one of them finds the object the
        others get _GRACA_APOS_ACHADO more seconds, because the same name in a
        second customer's AD must still be reported -- stopping at the first hit
        would let a write land on the wrong customer.
        """
        achados, vazios, falhas, parecidos, recusas = {}, [], [], {}, {}
        tool = self.tools[tool_name]
        loop = asyncio.get_running_loop()
        inicio = loop.time()

        por_futuro = {}
        for chave in self.pool.available_names():
            bundle, error = self.pool.resolve_or_error(chave)
            if error is not None:
                falhas.append({"ad_server": chave, "erro": error.get("erro"),
                               "mensagem": error.get("mensagem")})
                continue

            def trabalho(b=bundle):
                with self._bound(b):
                    return self._executar(tool_name, tool, handler, dict(tool_args),
                                          propagar_falha=True)

            por_futuro[loop.run_in_executor(self._executor(), trabalho)] = chave

        limite = inicio + self._PRAZO_TODOS
        pendentes = set(por_futuro)
        while pendentes:
            espera = limite - loop.time()
            if espera <= 0:
                break
            prontos, pendentes = await asyncio.wait(
                pendentes, timeout=espera, return_when=asyncio.FIRST_COMPLETED)
            for futuro in prontos:
                chave = por_futuro[futuro]
                try:
                    resultado = futuro.result()
                except Exception as exc:
                    falhas.append({"ad_server": chave, "erro": type(exc).__name__,
                                   "mensagem": (str(exc) or type(exc).__name__)[:400]})
                    continue
                self._classificar(chave, resultado, achados, vazios, falhas, parecidos,
                                  recusas)
            if achados and tool_name not in self._SEM_GRACA:
                # A directory still opening its first connection has not had a
                # chance to answer yet: cutting it after the grace reported
                # "tempo esgotado" for healthy customers (measured 2026-09-21).
                frios = [c for f, c in por_futuro.items()
                         if f in pendentes and not self.pool.esta_conectado(c)]
                prazo = self._PRAZO_CONEXAO_FRIA if frios else self._GRACA_APOS_ACHADO
                limite = min(limite, loop.time() + prazo)

        for futuro in pendentes:
            chave = por_futuro[futuro]
            frio = not self.pool.esta_conectado(chave)
            prazo = self._PRAZO_TODOS if (not achados or tool_name in self._SEM_GRACA) \
                else (self._PRAZO_CONEXAO_FRIA if frio else self._GRACA_APOS_ACHADO)
            falhas.append({
                "ad_server": chave, "erro": "TEMPO_ESGOTADO",
                "mensagem": (
                    f"Nao respondeu a tempo ({prazo:.0f}s"
                    + (" apos o primeiro resultado" if achados else "")
                    + (", e a conexao com ele ainda estava sendo aberta" if frio else "")
                    + "). O que este AD contem NAO foi verificado; consulte-o sozinho "
                      "informando ad_server se precisar."),
            })
        falhas.sort(key=lambda f: f["ad_server"])

        # An input refusal is not "nothing here": when every directory refused
        # the same input (an invalid filter is invalid everywhere), the refusal
        # IS the answer. Reporting "found in 0 of 8" hid it from the model.
        if not achados and vazios and len(recusas) == len(vazios) \
                and len({r["erro"] for r in recusas.values()}) == 1:
            recusa = dict(next(iter(recusas.values())))
            recusa["servidores_consultados"] = len(vazios) + len(falhas)
            if falhas:
                recusa["servidores_com_falha"] = falhas
            return recusa

        consultados = len(achados) + len(vazios) + len(falhas)
        resposta = {
            "modo_de_busca": "TODOS OS SERVIDORES",
            "tool": tool_name,
            "servidores_consultados": consultados,
            "encontrado_em": sorted(achados),
            "sem_resultado_em": sorted(vazios),
            "resultados_por_servidor": achados,
        }
        if not achados and parecidos:
            resposta["parecidos_por_servidor"] = parecidos
            resposta["nota_parecidos"] = (
                "Nada corresponde ao nome informado, mas estes objetos tem nome proximo. "
                "Se um deles for o pretendido, repita a chamada com o login dele e o "
                "ad_server onde foi encontrado.")
        if falhas:
            resposta["servidores_com_falha"] = falhas
            resposta["aviso"] = (
                f"{len(falhas)} de {consultados} servidores nao responderam. O que eles "
                "tem NAO foi verificado: 'sem resultado' vale apenas para "
                f"{len(vazios) + len(achados)} servidores."
            )
        if not pedido:
            resposta["nota"] = (
                "'ad_server' nao foi informado, entao a busca rodou em todos os ADs. "
                "Para consultar um so, informe o nome do servidor."
            )
        resposta["tempo_s"] = round(loop.time() - inicio, 1)
        resposta["resumo"] = (
            f"Encontrado em {len(achados)} de {consultados} servidores"
            + (f": {', '.join(sorted(achados))}." if achados else ".")
        )

        tamanho = len(json.dumps(resposta, ensure_ascii=False, default=str))
        if tamanho > self._LIMITE_RESPOSTA:
            resumo_por_servidor = {}
            for chave, payload in achados.items():
                if isinstance(payload, dict):
                    resumo_por_servidor[chave] = {
                        k: (v if k == "identificacao" else len(v) if isinstance(v, list) else v)
                        for k, v in payload.items()
                        if isinstance(v, (int, str, bool)) or isinstance(v, list)
                    }
                else:
                    resumo_por_servidor[chave] = "resultado nao estruturado"
            resposta["resultados_por_servidor"] = resumo_por_servidor
            resposta["RESPOSTA_CONDENSADA"] = (
                f"A resposta completa teria {tamanho} caracteres, acima do limite. "
                "Cada servidor aparece apenas com suas contagens. Para ver os registros, "
                "repita a chamada informando um 'ad_server' especifico, ou restrinja a "
                "busca com filtros."
            )
        return resposta

    # Tools merged into others on 2026-09-19. The old names keep answering --
    # a client or saved prompt that still calls them gets the new tool's
    # answer plus a note -- but they are no longer listed: seven near-twins in
    # the catalogue were seven chances for the hub's search to pick a partial
    # tool. old -> (new, {old argument: new argument}).
    # Every name this server ever listed, mapped onto the 10-tool catalogue of
    # 2026-09-19: old -> (new tool, {old arg: new arg}, {fixed arg: value}).
    # A client connected directly (or a saved prompt) keeps working and gets a
    # 'tool_unificada' note; a gateway that only routes listed tools (mcphub)
    # answers "tool not available" and the model searches again.
    _U, _G, _C, _O = ("ad_manage_directory_users", "ad_manage_directory_groups",
                      "ad_manage_directory_computers", "ad_manage_organizational_units")
    ALIASES_DE_TOOLS = {
        # catalogue and diagnostics
        "ad_list_ad_servers": ("ad_search_directory_servers", {}, {}),
        "ad_check_ad_server_configured": ("ad_search_directory_servers",
                                          {"client_name": "server_name"}, {}),
        "ad_check_client_configuration": ("ad_search_directory_servers",
                                          {"client_name": "server_name"}, {}),
        "ad_list_configured_clients": ("ad_search_directory_servers", {}, {}),
        "ad_get_client_tenant_info": ("ad_search_directory_servers",
                                      {"ad_server": "server_name"}, {}),
        "ad_health_check_mcp_server": ("ad_search_directory_servers", {},
                                       {"test_connection": True}),
        "ad_get_mcp_schema_tools_info": ("ad_search_directory_servers", {}, {}),
        # users
        "ad_list_users_with_filters": ("ad_search_directory_users", {}, {}),
        "ad_get_user_details_by_username": ("ad_search_directory_users", {}, {}),
        "ad_get_user_group_memberships": ("ad_search_directory_users", {}, {}),
        # the old tools defaulted to 90 days; without it the call would
        # silently become "list everyone" (audit 2026-09-21)
        "ad_get_inactive_users_by_days": ("ad_search_directory_users",
                                          {"days": "inactive_days"}, {}, {"inactive_days": 90}),
        "ad_create_user_account": (_U, {"additional_attributes": "attributes"},
                                   {"action": "create"}),
        "ad_modify_user_attributes": (_U, {}, {"action": "update"}),
        "ad_delete_user_account_permanently": (_U, {}, {"action": "delete"}),
        "ad_enable_user_account_access": (_U, {}, {"action": "enable"}),
        "ad_disable_user_account_access": (_U, {}, {"action": "disable"}),
        "ad_reset_user_password_forced": (_U, {"new_password": "password",
                                               "force_change": "must_change_password"},
                                          {"action": "reset_password"}),
        # groups
        "ad_list_groups_with_filters": ("ad_search_directory_groups", {}, {}),
        "ad_get_group_details_by_name": ("ad_search_directory_groups", {}, {}),
        "ad_get_group_members_recursive": ("ad_search_directory_groups", {}, {}),
        "ad_create_group_security_or_distribution": (
            _G, {"additional_attributes": "attributes"}, {"action": "create"}),
        "ad_modify_group_attributes": (_G, {}, {"action": "update"}),
        "ad_delete_group_permanently": (_G, {}, {"action": "delete"}),
        "ad_add_member_to_group": (_G, {"member_dn": "members"}, {"action": "add_members"}),
        "ad_remove_member_from_group": (_G, {"member_dn": "members"},
                                        {"action": "remove_members"}),
        # computers
        "ad_list_computers_with_filters": ("ad_search_directory_computers", {}, {}),
        "ad_get_computer_details_by_name": ("ad_search_directory_computers", {}, {}),
        "ad_get_inactive_computers_by_days": ("ad_search_directory_computers",
                                              {"days": "inactive_days"}, {},
                                              {"inactive_days": 90}),
        "ad_create_computer_account": (_C, {"additional_attributes": "attributes"},
                                       {"action": "create"}),
        "ad_modify_computer_attributes": (_C, {}, {"action": "update"}),
        "ad_delete_computer_account_permanently": (_C, {}, {"action": "delete"}),
        "ad_enable_computer_account_trust": (_C, {}, {"action": "enable"}),
        "ad_disable_computer_account_trust": (_C, {}, {"action": "disable"}),
        "ad_reset_computer_password_trust": (_C, {}, {"action": "reset_trust"}),
        # organizational units
        "ad_list_organizational_units_hierarchy": ("ad_search_organizational_units", {}, {}),
        "ad_get_organizational_unit_details": ("ad_search_organizational_units", {}, {}),
        "ad_get_organizational_unit_objects": ("ad_search_organizational_units", {}, {}),
        "ad_create_organizational_unit": (_O, {"additional_attributes": "attributes"},
                                          {"action": "create"}),
        "ad_modify_organizational_unit_attributes": (_O, {}, {"action": "update"}),
        "ad_delete_organizational_unit_forced": (_O, {}, {"action": "delete"}),
        # security
        "ad_get_domain_security_policy_info": ("ad_search_security_reports", {},
                                               {"report": "domain_policy"}),
        "ad_get_privileged_security_groups": ("ad_search_security_reports", {},
                                              {"report": "privileged_groups"}),
        "ad_get_user_effective_permissions": ("ad_search_security_reports", {},
                                              {"report": "user_permissions"}),
        "ad_get_password_policy_violations": ("ad_search_security_reports", {},
                                              {"report": "password_violations"}),
        "ad_audit_administrative_accounts": ("ad_search_security_reports", {},
                                             {"report": "admin_accounts"}),
    }

    @classmethod
    def _alias(cls, nome):
        """(new tool, renames, fixed args, defaults) -- defaults only apply
        when the caller left the value out."""
        entrada = cls.ALIASES_DE_TOOLS[nome]
        return entrada if len(entrada) == 4 else (*entrada, {})

    def _aplicar_alias(self, tool_name, tool_args):
        """Map a merged tool's name (hub prefix allowed) to its replacement."""
        nome = str(tool_name or "")
        for prefixo in ("ad-multi-", "ad_multi_", "mcp__ad-multi__", "ad-multi."):
            if nome.startswith(prefixo):
                nome = nome[len(prefixo):]
        if nome in self.tools or nome not in self.ALIASES_DE_TOOLS:
            return tool_name, tool_args, None
        nova, renomes, fixos, padroes = self._alias(nome)
        if nova not in self.tools:
            return tool_name, tool_args, None
        novos = {}
        for chave, valor in tool_args.items():
            novos[renomes.get(chave, chave)] = valor
        novos.update(fixos)
        for chave, valor in padroes.items():
            novos.setdefault(chave, valor)
        # Unknown keys are kept on purpose: create folds the attributes a model
        # sends at the top level (department=..., Office=...) into attributes,
        # and filtering here dropped them before that could happen.
        self.logger.info("tools/call %s -> alias de %s", nome, nova)
        return nova, novos, (
            f"A tool '{nome}' foi unificada em '{nova}', que respondeu esta chamada. "
            f"Use '{nova}' diretamente.")

    async def handle_tools_call(self, params: dict) -> dict:
        """Route a call, translating the names of merged tools first."""
        bruto = params.get("arguments")
        if isinstance(bruto, str):
            try:
                bruto = json.loads(bruto)
            except (ValueError, TypeError):
                bruto = {}
        nome, args, nota = self._aplicar_alias(params.get("name"), dict(bruto or {}))
        resposta = await self._tools_call(dict(params, name=nome, arguments=args))
        if nota:
            try:
                payload = json.loads(resposta["content"][0]["text"])
                if isinstance(payload, dict):
                    payload = {"tool_unificada": nota, **payload}
                    resposta = self._as_content(payload)
            except (KeyError, IndexError, ValueError, TypeError):
                pass
        return resposta

    async def _tools_call(self, params: dict) -> dict:
        """Handle tools/call method.

        In multi-AD mode this is the single place where a call is routed to a
        directory. Routing lives here and nowhere else, so a tool cannot reach
        an LDAP connection without having named its server first.
        """
        tool_name = params.get("name")
        bruto = params.get("arguments")
        if isinstance(bruto, str):
            # Some clients send the arguments object as a JSON string.
            try:
                bruto = json.loads(bruto)
            except (ValueError, TypeError):
                bruto = {}
        tool_args = dict(bruto or {})

        resolvido, recusa = self._resolver_nome_de_tool(tool_name)
        if recusa is not None:
            self.logger.warning("tools/call com nome desconhecido: %r", tool_name)
            return self._as_content(recusa)
        tool_name = resolvido

        tool = self.tools[tool_name]
        handler = tool["handler"]

        if tool_name == "ad_search_directory_servers" and \
                str(tool_args.get("test_connection")).strip().lower() in _VERDADEIROS:
            # The live connection test runs per directory, like any read:
            # server_name (or none = every directory) becomes the routing key.
            alvo = tool_args.get("server_name")
            tool_name, tool = "ad_test_ldap_connection_status", \
                self.tools["ad_test_ldap_connection_status"]
            handler = tool["handler"]
            tool_args = {"ad_server": alvo} if (self.multi and alvo) else {}

        tool_args, recusa = self._sanear_argumentos(tool_name, tool, tool_args)
        if recusa is not None:
            self.logger.warning("tools/call recusada em %s: %s", tool_name, recusa["erro"])
            return self._as_content(recusa)

        if self.multi and not tool.get("global"):
            requested = tool_args.pop("ad_server", None)
            pedido = str(requested).strip().lower() if requested is not None else ""

            if pedido in self._TODOS or pedido == "":
                if tool.get("write"):
                    # Never fan a write out, and never guess which directory it
                    # meant: both would edit the wrong customer's AD.
                    return self._as_content({
                        "sucesso": False,
                        "erro": "AD_SERVER_OBRIGATORIO_PARA_ESCRITA",
                        "mensagem": (
                            f"A tool {tool_name} altera o Active Directory, entao exige um "
                            "unico servidor em 'ad_server'. 'todos' nao e aceito para "
                            "escrita, e nao existe servidor padrao."
                        ),
                        "servidores_disponiveis": self.pool._short_catalog(),
                        "tool": tool_name,
                    })
                self.logger.info("tools/call %s -> ad_server=TODOS", tool_name)
                return self._as_content(
                    await self._executar_em_todos(tool_name, handler, tool_args, pedido))

            bundle, error = self.pool.resolve_or_error(requested)
            if error is not None:
                error["tool"] = tool_name
                self.logger.warning(
                    "Chamada recusada em %s: %s (ad_server=%r)",
                    tool_name, error["erro"], requested,
                )
                return self._as_content(error)

            recusa = self._validar_dn_no_dominio(tool_name, tool_args, bundle)
            if recusa is not None:
                return self._as_content(recusa)

            # The directory is bound to the worker thread that runs the call, so
            # concurrent calls to different customers never share state. Reads on
            # one directory run in parallel; writes on one directory run one at a
            # time, as they did when the whole server was serial.
            escrita = self._is_write_tool(tool)

            def trabalho():
                trava = self._trava_de_escrita(bundle.key) if escrita else None
                espera = max(0.1, self._PRAZO_CHAMADA * 0.8)
                if trava is not None and not trava.acquire(timeout=espera):
                    return {
                        "sucesso": False, "erro": "AD_OCUPADO", "tool": tool_name,
                        "mensagem": (
                            "Outra alteracao neste AD ainda esta em andamento. Nada foi "
                            "executado; repita em instantes."),
                    }
                try:
                    with self._bound(bundle):
                        self.logger.info("tools/call %s -> ad_server=%s", tool_name,
                                         bundle.key)
                        return self._executar(tool_name, tool, handler, tool_args)
                finally:
                    if trava is not None:
                        trava.release()

            result = await self._em_thread(trabalho, self._PRAZO_CHAMADA, tool_name,
                                           escrita=escrita, ad_server=bundle.key)
            if isinstance(result, dict) and result.get("sucesso") is False:
                result.setdefault("ad_server", bundle.key)
        elif tool.get("global"):
            result = await self._em_thread(lambda: handler(tool_args), self._PRAZO_CHAMADA,
                                           tool_name)
        else:
            result = await self._em_thread(
                lambda: self._executar(tool_name, tool, handler, tool_args),
                self._PRAZO_CHAMADA, tool_name, escrita=self._is_write_tool(tool))

        return self._as_content(result)

    async def handle_prompts_list(self, params: dict) -> dict:
        """Handle prompts/list method."""
        return {"prompts": PROMPTS_CATALOG}

    async def handle_prompts_get(self, params: dict) -> dict:
        """Handle prompts/get method."""
        prompt_name = params.get("name")
        prompt_args = params.get("arguments", {})

        if not prompt_name:
            raise ValueError("Prompt name is required")

        # Verificar se prompt existe
        prompt = next((p for p in PROMPTS_CATALOG if p["name"] == prompt_name), None)
        if not prompt:
            raise ValueError(f"Prompt não encontrado: {prompt_name}")

        # Chamar handler de prompts com o ldap_manager
        ldap_manager = self.ldap_manager
        if self.multi and self.pool is not None:
            bundle, error = self.pool.resolve_or_error(prompt_args.get("ad_server"))
            if error is not None:
                raise ValueError(error["mensagem"])
            ldap_manager = bundle.ldap_manager
            prompt_args = {k: v for k, v in prompt_args.items() if k != "ad_server"}

        # Prompt builders query LDAP synchronously; off the event loop, with the
        # same deadline as a tool call.
        loop = asyncio.get_running_loop()
        futuro = loop.run_in_executor(
            self._executor(),
            lambda: asyncio.run(handle_get_prompt(prompt_name, prompt_args, ldap_manager)))
        try:
            return await asyncio.wait_for(asyncio.shield(futuro), timeout=self._PRAZO_CHAMADA)
        except asyncio.TimeoutError as exc:
            raise ValueError(
                f"O Active Directory nao respondeu em {self._PRAZO_CHAMADA:.0f}s ao montar o "
                f"prompt {prompt_name}.") from exc

    async def handle_request(self, request_data: dict) -> dict:
        """Handle MCP JSON-RPC request."""
        method = request_data.get("method", "")
        params = request_data.get("params", {})
        request_id = request_data.get("id")

        try:
            if method == "initialize":
                result = await self.handle_initialize(params)
            elif method == "tools/list":
                result = await self.handle_tools_list(params)
            elif method == "tools/call":
                result = await self.handle_tools_call(params)
            elif method == "prompts/list":
                result = await self.handle_prompts_list(params)
            elif method == "prompts/get":
                result = await self.handle_prompts_get(params)
            elif method == "notifications/initialized":
                return {"jsonrpc": "2.0", "result": {}, "id": request_id}
            else:
                raise ValueError(f"Unknown method: {method}")

            return {"jsonrpc": "2.0", "result": result, "id": request_id}

        except Exception as e:
            self.logger.error(f"Error handling {method}: {e}")
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": redact(str(e))},
                "id": request_id
            }

    # ============= FASTAPI APP CREATION =============

    def _create_app(self) -> FastAPI:
        """Create FastAPI application with Streamable HTTP endpoints."""

        server = self

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            server.logger.info(f"Starting AD MCP on port {server.port}")
            yield
            server.logger.info("Shutting down AD MCP")
            server._shutdown_connections()

        app = FastAPI(
            title="MCP Active Directory Server",
            description="MCP server for Active Directory with Streamable HTTP support",
            version="1.0.0",
            lifespan=lifespan
        )

        # Health check (no auth required)
        @app.get("/health")
        async def health_check():
            return server._handle_health({})

        # ============= STREAMABLE HTTP ENDPOINTS =============

        # GET /mcp - SSE endpoint for Gemini
        @app.get("/mcp")
        async def mcp_sse_endpoint(
            request: Request,
            token: str = Depends(verify_bearer_token)
        ):
            session_id = request.headers.get("mcp-session-id") or str(uuid.uuid4())
            server.logger.info(f"SSE connection opened: {session_id}")

            mcp_sessions[session_id] = {"created_at": datetime.now(timezone.utc), "active": True}

            async def event_generator():
                try:
                    yield f"event: endpoint\ndata: /mcp\n\n"
                    while True:
                        if await request.is_disconnected():
                            break
                        if session_id not in mcp_sessions:
                            break
                        yield ":keepalive\n\n"
                        await asyncio.sleep(30)
                except asyncio.CancelledError:
                    pass
                finally:
                    if session_id in mcp_sessions:
                        del mcp_sessions[session_id]
                    server.logger.info(f"SSE connection closed: {session_id}")

            return StreamingResponse(
                event_generator(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "Mcp-Session-Id": session_id
                }
            )

        # DELETE /mcp - Session termination
        @app.delete("/mcp")
        async def mcp_session_terminate(
            request: Request,
            token: str = Depends(verify_bearer_token)
        ):
            session_id = request.headers.get("mcp-session-id")
            if session_id and session_id in mcp_sessions:
                del mcp_sessions[session_id]
                server.logger.info(f"Session terminated: {session_id}")
            return {"status": "session_terminated", "session_id": session_id}

        # POST /mcp - JSON-RPC handler
        @app.post("/mcp")
        async def mcp_handler_http(
            request: Request,
            mcp_request: MCPRequest,
            token: str = Depends(verify_bearer_token)
        ):
            session_id = request.headers.get("mcp-session-id") or str(uuid.uuid4())

            server.logger.info(f"MCP request: method={mcp_request.method}")

            response = await server.handle_request(mcp_request.model_dump())

            return JSONResponse(
                content=response,
                headers={"Mcp-Session-Id": session_id}
            )

        return app

    def _shutdown_connections(self) -> None:
        """Close every LDAP connection this process opened."""
        if self.multi and self.pool is not None:
            self.pool.disconnect_all()
        elif self.ldap_manager is not None:
            self.ldap_manager.disconnect()

    def _aquecer_conexoes(self) -> None:
        """Open every connection in the background (see ADServerPool.aquecer).

        Called when the process starts serving, never on construction: a test
        that only builds the server must not dial eight directories.
        """
        if not self.multi or self.pool is None:
            return
        if os.getenv("AD_MCP_AQUECER", "1").strip().lower() in ("0", "false", "nao", "no"):
            return
        self.pool.aquecer()

    def run(self):
        """Start the server."""
        self._aquecer_conexoes()
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Active Directory MCP FastAPI Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8820, help='Port (default: 8820)')
    parser.add_argument('--config', help='Config file path (single-AD mode)')
    parser.add_argument('--servers', help='Multi-AD servers file (multi-AD mode)')
    parser.add_argument('--mode', choices=['single', 'multi'],
                        help='single (default) or multi. Overrides AD_MCP_MODE.')

    args = parser.parse_args()

    mode = (args.mode or os.getenv("AD_MCP_MODE") or "single").strip().lower()
    config_path = args.config or os.getenv("AD_MCP_CONFIG")
    servers_path = args.servers or os.getenv("AD_MCP_SERVERS")

    if mode == "multi":
        if not servers_path:
            print("Error: modo multi exige AD_MCP_SERVERS (ou --servers)")
            sys.exit(1)
    elif not config_path:
        print("Error: AD_MCP_CONFIG not set")
        sys.exit(1)

    try:
        server = ActiveDirectoryMCPFastAPI(
            config_path=config_path,
            host=args.host,
            port=args.port,
            servers_path=servers_path,
            mode=mode,
        )
    except MultiConfigError as exc:
        print(f"Error: configuracao multi-AD invalida: {exc}")
        sys.exit(1)

    server.run()


if __name__ == "__main__":
    main()
