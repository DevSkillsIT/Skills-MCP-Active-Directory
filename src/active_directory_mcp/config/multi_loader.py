"""Multi-server configuration loader for Active Directory MCP.

Loads a single JSON file describing N Active Directory servers and validates
each block with the very same ``Config`` model used by the single-AD mode.

File format::

    {
      "version": 1,
      "servers": {
        "cliente-exemplo": {
          "label": "Cliente Exemplo",
          "aliases": ["exemplo"],
          "enabled": true,
          "dc_hostname": "DCEXEMPLO01.exemplo.local",
          "netbios_domain": "EXEMPLO.LOCAL",
          "site": "Default-First-Site-Name",
          "active_directory": { ... },      # identical to ad-config.json
          "organizational_units": { ... },
          "security": { ... },
          "performance": { ... },
          "logging": { ... },
          "client": { ... }
        }
      }
    }

Each server block is byte-compatible with the existing per-client
``ad-config.json``, so migrating an instance is a copy, not a rewrite.
"""

import json
import logging
import os
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..core.redaction import redact, register_secret
from .models import Config

logger = logging.getLogger("active-directory-mcp.multi-config")

# Metadata keys that live alongside the Config blocks and are NOT part of Config.
_META_KEYS = {"label", "aliases", "enabled", "notes",
              "dc_hostname", "netbios_domain", "site"}


def normalize_name(value: str) -> str:
    """Normalize a server name for matching: casefold, strip accents and spaces.

    @MX:ANCHOR Every lookup key in the pool passes through this function.
    Accent handling decides how many candidates a name matches, so resolution
    and registration MUST use the same normalization.
    """
    if not value:
        return ""
    text = unicodedata.normalize("NFKD", str(value).strip())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.casefold()
    for ch in (" ", "_", "."):
        text = text.replace(ch, "-")
    while "--" in text:
        text = text.replace("--", "-")
    return text.strip("-")


@dataclass
class ADServerEntry:
    """One configured Active Directory server."""

    key: str
    label: str
    aliases: List[str] = field(default_factory=list)
    enabled: bool = True
    notes: Optional[str] = None
    dc_hostname: Optional[str] = None
    netbios_domain: Optional[str] = None
    site: Optional[str] = None
    config: Optional[Config] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def valid(self) -> bool:
        return self.config is not None and self.error is None

    @property
    def domain(self) -> str:
        if self.config:
            return self.config.active_directory.domain
        return str(self.raw.get("active_directory", {}).get("domain", "")) or "desconhecido"

    @property
    def base_dn(self) -> str:
        if self.config:
            return self.config.active_directory.base_dn
        return str(self.raw.get("active_directory", {}).get("base_dn", ""))

    @property
    def ldap_url(self) -> str:
        if self.config:
            return self.config.active_directory.server
        return str(self.raw.get("active_directory", {}).get("server", ""))

    @property
    def host(self) -> str:
        """Host or IP taken from the LDAP URL (never invented)."""
        url = self.ldap_url
        if not url:
            return ""
        try:
            parsed = urlparse(url)
            return parsed.hostname or ""
        except Exception:
            return ""

    @property
    def port(self) -> Optional[int]:
        url = self.ldap_url
        if not url:
            return None
        try:
            parsed = urlparse(url)
            if parsed.port:
                return parsed.port
            return 636 if parsed.scheme == "ldaps" else 389
        except Exception:
            return None

    def match_keys(self) -> List[str]:
        """All normalized names that unambiguously identify this server."""
        keys = [self.key, self.label] + list(self.aliases)
        domain = self.domain
        if domain and domain != "desconhecido":
            keys.append(domain)
            keys.append(domain.split(".")[0])
        client = self.raw.get("client", {})
        if isinstance(client, dict):
            for candidate in (client.get("slug"), client.get("name")):
                if candidate:
                    keys.append(str(candidate))
        # The DC hostname identifies this server too: a model that saw it in a
        # ticket should be able to route with it.
        if self.dc_hostname:
            keys.append(self.dc_hostname)
            keys.append(self.dc_hostname.split(".")[0])
        if self.netbios_domain:
            keys.append(self.netbios_domain)
        seen, result = set(), []
        for k in keys:
            nk = normalize_name(k)
            if nk and nk not in seen:
                seen.add(nk)
                result.append(nk)
        return result

    def public_info(self, status: str = "nao_conectado",
                    status_detail: Optional[str] = None) -> Dict[str, Any]:
        """Describe the server WITHOUT credentials.

        @MX:WARN bind_dn and password are deliberately absent. This payload is
        handed to the model; a service-account DN is not needed to operate.
        """
        info: Dict[str, Any] = {
            "ad_server": self.key,
            "nome": self.label,
            "apelidos": self.aliases,
            "dominio": self.domain,
            "controlador_de_dominio": self.dc_hostname or "nao informado",
            "dominio_netbios": self.netbios_domain or "nao informado",
            "servidor_ldap": self.ldap_url,
            "host": self.host,
            "porta": self.port,
            "base_dn": self.base_dn,
            "habilitado": self.enabled,
            "status": status,
        }
        if self.config:
            info["ssl"] = self.config.active_directory.use_ssl
            ous = self.config.organizational_units
            info["unidades_organizacionais"] = {
                "usuarios": ous.users_ou,
                "grupos": ous.groups_ou,
                "computadores": ous.computers_ou,
                "contas_de_servico": ous.service_accounts_ou,
            }
        client = self.raw.get("client", {})
        if isinstance(client, dict) and client.get("type"):
            info["tipo"] = client.get("type")
        if self.site:
            info["site_ad"] = self.site
        if self.notes:
            info["observacoes"] = self.notes
        if status_detail:
            info["status_detalhe"] = status_detail
        if self.error:
            info["erro_de_configuracao"] = self.error
        return info


class MultiConfigError(Exception):
    """Raised when the multi-server file cannot be used at all."""


def load_multi_config(servers_path: Optional[str] = None) -> Dict[str, ADServerEntry]:
    """Load and validate the multi-server configuration file.

    A server block that fails validation is KEPT in the registry carrying its
    error, instead of being dropped. A dropped server would look like "not
    configured" to the model, which is a different -- and false -- statement.

    Raises:
        MultiConfigError: file missing, unreadable, empty or with ambiguous names.
    """
    if servers_path is None:
        servers_path = os.getenv("AD_MCP_SERVERS")
    if not servers_path:
        raise MultiConfigError(
            "Modo multi-AD ativo, mas nenhum arquivo de servidores foi informado. "
            "Defina AD_MCP_SERVERS ou passe --servers."
        )

    path = Path(servers_path)
    if not path.exists():
        raise MultiConfigError(f"Arquivo de servidores nao encontrado: {servers_path}")

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise MultiConfigError(f"JSON invalido em {servers_path}: {exc}") from exc

    servers = data.get("servers")
    if not isinstance(servers, dict) or not servers:
        raise MultiConfigError(
            f"Arquivo {servers_path} nao possui a chave 'servers' com ao menos um servidor."
        )

    entries: Dict[str, ADServerEntry] = {}
    for raw_key, block in servers.items():
        key = normalize_name(raw_key)
        if not key:
            raise MultiConfigError(f"Nome de servidor invalido: {raw_key!r}")
        if key in entries:
            raise MultiConfigError(
                f"Nome de servidor duplicado apos normalizacao: {raw_key!r} colide com {key!r}"
            )
        if not isinstance(block, dict):
            raise MultiConfigError(f"Bloco do servidor {raw_key!r} nao e um objeto JSON")

        entry = ADServerEntry(
            key=key,
            label=str(block.get("label") or raw_key),
            aliases=[str(a) for a in (block.get("aliases") or [])],
            enabled=bool(block.get("enabled", True)),
            notes=block.get("notes"),
            dc_hostname=block.get("dc_hostname"),
            netbios_domain=block.get("netbios_domain"),
            site=block.get("site"),
            raw=block,
        )

        config_payload = {k: v for k, v in block.items() if k not in _META_KEYS}
        _registrar_segredos_do_bloco(config_payload)
        try:
            entry.config = Config(**config_payload)
        except Exception as exc:
            # pydantic prints input_value (the whole section, password included)
            # and this text is logged and shown in the catalogue.
            entry.error = redact(f"{type(exc).__name__}: {exc}")
            logger.error("Servidor '%s' com configuracao invalida: %s", key, entry.error)

        entries[key] = entry

    _assert_unambiguous(entries)
    logger.info(
        "Multi-config carregada de %s: %d servidores (%d validos)",
        servers_path, len(entries), sum(1 for e in entries.values() if e.valid),
    )
    return entries


def _registrar_segredos_do_bloco(bloco: Dict[str, Any]) -> None:
    """Register a block's secrets BEFORE validation, which may echo them."""
    if not isinstance(bloco, dict):
        return
    for secao, chave in (("active_directory", "password"), ("client", "automation_token")):
        valor = (bloco.get(secao) or {}).get(chave) if isinstance(bloco.get(secao), dict) \
            else None
        register_secret(valor)


def _assert_unambiguous(entries: Dict[str, ADServerEntry]) -> None:
    """Fail loudly when two servers answer to the same name.

    @MX:WARN An ambiguous alias in multi-AD mode means a write can land on the
    wrong customer's directory. This must never be resolved by "first match".
    """
    owners: Dict[str, str] = {}
    for key, entry in entries.items():
        for name in entry.match_keys():
            previous = owners.get(name)
            if previous and previous != key:
                raise MultiConfigError(
                    f"Nome ambiguo '{name}': pertence a '{previous}' e a '{key}'. "
                    "Ajuste os campos 'aliases'/'label' para que cada nome aponte "
                    "para um unico servidor."
                )
            owners[name] = key
