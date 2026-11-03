"""Base class for Active Directory tools."""

import json
import re
import unicodedata
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone

from mcp.types import TextContent as Content
from ldap3.core.exceptions import LDAPException

import ldap3

from ..core.ldap_manager import LDAPManager
from ..core.resolver import caminho_legivel, dividir_dn, normalizar_dn
from ..core.logging import get_logger, log_ldap_operation
from ..core.ldap_policy import ocultar_sensiveis, recusa_de_consulta
from ..core.redaction import redact


# Privileged targets (upstream 48a965d). Identity comes from the directory
# first: a well-known RID or BUILTIN SID does not depend on the DC's language,
# while names do ("Domain Admins" is "Admins. do domínio" on a pt-BR DC).
_RIDS_PRIVILEGIADOS = {
    500: "Administrator", 502: "krbtgt", 512: "Domain Admins", 516: "Domain Controllers",
    518: "Schema Admins", 519: "Enterprise Admins", 520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers", 526: "Key Admins", 527: "Enterprise Key Admins",
}
_SIDS_BUILTIN_PRIVILEGIADOS = {
    "S-1-5-32-544": "Administrators", "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators", "S-1-5-32-552": "Replicator",
}
# Fallback when the SID is not readable, compared with case, accents and
# punctuation removed. English and pt-BR built-in names.
_NOMES_PRIVILEGIADOS = {
    "domainadmins", "enterpriseadmins", "schemaadmins", "administrators",
    "administradores", "adminsdodominio", "administradoresdaempresa",
    "administradoresdeesquema", "accountoperators", "operadoresdeconta",
    "backupoperators", "operadoresdebackup", "serveroperators", "operadoresdeservidor",
    "printoperators", "operadoresdeimpressao", "grouppolicycreatorowners",
    "proprietarioscriadoresdepoliticadegrupo", "dnsadmins", "keyadmins",
    "enterprisekeyadmins", "domaincontrollers", "controladoresdedominio",
    "administrator", "administrador", "krbtgt",
}


def _nome_simples(valor: Any) -> str:
    texto = unicodedata.normalize("NFKD", str(valor or "")).casefold()
    return "".join(c for c in texto if c.isalnum() and not unicodedata.combining(c))


class BaseTool(ABC):
    """Base class for all Active Directory tools."""
    
    def __init__(self, ldap_manager: LDAPManager):
        """
        Initialize base tool.
        
        Args:
            ldap_manager: LDAP manager instance
        """
        self.ldap = ldap_manager
        self.logger = get_logger(self.__class__.__name__)
    
    def _serialize_datetime(self, obj):
        """Helper function to serialize datetime objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {key: self._serialize_datetime(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_datetime(item) for item in obj]
        else:
            return obj
    
    def _format_response(self, data: Any, operation: str = "operation") -> List[Content]:
        """
        Format response data for MCP.
        
        Args:
            data: Data to format
            operation: Operation name for logging
            
        Returns:
            List of MCP content objects
        """
        try:
            # Serialize datetime objects before JSON conversion. Secret
            # attributes are masked here, the one exit every tool shares, so
            # attributes=["*"] cannot carry a LAPS or gMSA password out.
            serialized_data = ocultar_sensiveis(self._serialize_datetime(data))
            
            if isinstance(serialized_data, dict):
                formatted_data = json.dumps(serialized_data, indent=2, ensure_ascii=False)
            elif isinstance(serialized_data, list):
                formatted_data = json.dumps(serialized_data, indent=2, ensure_ascii=False)
            else:
                formatted_data = str(serialized_data)
            
            return [Content(type="text", text=formatted_data)]
            
        except Exception as e:
            self.logger.error(f"Error formatting response for {operation}: {e}")
            error_response = {
                "error": f"Failed to format response: {str(e)}",
                "operation": operation
            }
            return [Content(type="text", text=json.dumps(error_response, indent=2))]
    
    def _recusa_de_consulta(self, operation: str, filter_criteria: Any = None,
                            attributes: Any = None) -> Optional[List[Content]]:
        """Refuse a caller-supplied filter or attribute list that reaches a secret.

        The resolver already refuses these before routing; this is the same
        predicate at the tool layer, for callers that do not go through it.
        """
        recusa = recusa_de_consulta(filter_criteria, attributes)
        if recusa is None:
            return None
        self.logger.warning("%s: consulta recusada (%s)", operation, recusa["erro"])
        return self._format_response(recusa, operation)

    # ------------------------------------------------------ privileged targets

    def _protecao_de_privilegiados_ativa(self) -> bool:
        """security.protect_privileged_targets; absent (fakes, old configs) = on."""
        config = getattr(self.ldap, "security_config", None)
        return getattr(config, "protect_privileged_targets", True) is not False

    def _motivo_privilegiado(self, attrs: Dict[str, Any], *nomes: Any) -> Optional[str]:
        """Why an object is a privileged target, or None.

        @MX:ANCHOR One predicate for every path that changes privileged
        membership or a privileged password (members, copy_from_user,
        offboarding, reset, update with password).
        @MX:REASON The fork had the same check in four places and three of them
        only warned; one function cannot disagree with itself.
        """
        sid = self._get_attr(attrs, 'objectSid', None)
        if isinstance(sid, (bytes, bytearray)):
            try:
                from ldap3.protocol.formatters.formatters import format_sid
                sid = format_sid(bytes(sid))
            except Exception:  # noqa: BLE001 - fall back to adminCount and name
                sid = None
        if isinstance(sid, str) and sid.startswith("S-"):
            sid = sid.strip().upper()
            if sid in _SIDS_BUILTIN_PRIVILEGIADOS:
                return f"grupo interno privilegiado ({_SIDS_BUILTIN_PRIVILEGIADOS[sid]}, {sid})"
            if sid.startswith("S-1-5-21-"):
                try:
                    rid = int(sid.rsplit("-", 1)[1])
                except ValueError:
                    rid = None
                if rid in _RIDS_PRIVILEGIADOS:
                    return f"objeto interno privilegiado ({_RIDS_PRIVILEGIADOS[rid]}, RID {rid})"
        try:
            admin_count = int(str(self._get_attr(attrs, 'adminCount', 0) or 0))
        except ValueError:
            admin_count = 0
        if admin_count == 1:
            return "adminCount=1 (objeto protegido pelo AdminSDHolder)"
        candidatos = list(nomes) + [self._get_attr(attrs, 'sAMAccountName', None),
                                    self._get_attr(attrs, 'cn', None)]
        for nome in candidatos:
            simples = _nome_simples(nome)
            if simples in _NOMES_PRIVILEGIADOS or simples.startswith("krbtgt"):
                return f"nome de objeto interno privilegiado ({nome})"
        return None

    _ATRIBUTOS_DE_PRIVILEGIO = ['sAMAccountName', 'cn', 'objectSid', 'adminCount']

    def _privilegios_por_dn(self, dns: List[str]) -> Dict[str, Dict[str, Any]]:
        """{normalized DN: {nome, dn, motivo}} for every PRIVILEGED DN in the list.

        Batched like _descrever_grupos. A DN whose details cannot be read is
        reported as privileged: refusing to touch an unknown group is the
        fail-closed side (it stays where it was, and the answer says so).
        """
        dns = [str(d) for d in dns if d]
        lidos: Dict[str, Dict[str, Any]] = {}
        for inicio in range(0, len(dns), self._LOTE_DE_DNS):
            lote = dns[inicio:inicio + self._LOTE_DE_DNS]
            filtro = "(|" + "".join(
                f"(distinguishedName={self._escape_ldap_filter(d)})" for d in lote) + ")"
            try:
                for entrada in self.ldap.search(search_base=self.ldap.ad_config.base_dn,
                                                search_filter=filtro,
                                                attributes=self._ATRIBUTOS_DE_PRIVILEGIO):
                    lidos[normalizar_dn(entrada['dn'])] = entrada['attributes']
            except Exception as exc:  # noqa: BLE001 - unread = treated as privileged
                self.logger.warning("Nao foi possivel ler privilegios de grupos: %s", exc)
        privilegiados: Dict[str, Dict[str, Any]] = {}
        for dn in dns:
            attrs = lidos.get(normalizar_dn(dn))
            motivo = ("detalhes nao lidos (permissao, grupo de outro dominio ou removido); "
                      "nao alterado por seguranca") if attrs is None \
                else self._motivo_privilegiado(attrs, self._nome_do_dn(dn))
            if motivo:
                privilegiados[normalizar_dn(dn)] = {"nome": self._nome_do_dn(dn), "dn": dn,
                                                    "motivo": motivo}
        return privilegiados

    def _recusa_alvo_privilegiado(self, operation: str,
                                  alvos: List[Dict[str, Any]]) -> List[Content]:
        """The refusal payload: nothing was written, and who can change that."""
        nomes = ", ".join(f"{a['nome']} ({a['motivo']})" for a in alvos)
        self.logger.warning("%s: recusado alvo privilegiado: %s", operation,
                            ", ".join(a["nome"] for a in alvos))
        return self._format_response({
            "success": False, "sucesso": False, "erro": "ALVO_PRIVILEGIADO",
            "mensagem": (
                f"Recusado: {nomes} e alvo privilegiado. Este servidor nao altera membros de "
                "grupos privilegiados nem senhas de contas privilegiadas, mesmo com "
                "confirmacao. Nada foi alterado. Faca a mudanca pelo console do AD, ou um "
                "administrador desliga a protecao deste AD em security."
                "protect_privileged_targets=false (decisao humana, fora do alcance da IA)."),
            "operation": operation,
            "alvos_privilegiados": alvos,
            "setting": "security.protect_privileged_targets",
        }, operation)

    # -------------------------------------------------------- password channel

    def _canal_de_senha_seguro(self, operation: str) -> bool:
        """Whether a password may leave the process now. Fails closed."""
        try:
            return self.ldap.is_secure_channel() is True
        except Exception as exc:  # noqa: BLE001 - unknown channel = insecure
            self.logger.warning("%s: nao foi possivel verificar o canal (%s)",
                                operation, type(exc).__name__)
            return False

    def _recusa_canal_de_senha(self, operation: str) -> Optional[List[Content]]:
        """Pre-flight for every password write; call it BEFORE any mutation.

        @MX:ANCHOR Asked by create, reset, update-with-password and the
        computer trust reset, before anything is written.
        @MX:REASON Checking after the add left a half-made account to roll back;
        checking at the write alone sends nothing but decides too late.
        """
        if self._canal_de_senha_seguro(operation):
            return None
        self.logger.warning("%s: senha recusada, canal sem protecao", operation)
        return self._format_response({
            "success": False, "sucesso": False, "erro": "CANAL_INSEGURO_PARA_SENHA",
            "mensagem": (
                "Senha NAO enviada: a conexao com este AD nao usa TLS com certificado "
                "validado, entao a senha atravessaria a rede em texto claro ou para um "
                "servidor nao autenticado. Nada foi alterado. No bloco deste AD em "
                "ad-servers.json: servidor com ldaps://, security.validate_certificate=true "
                "e security.ca_cert_file com a CA raiz do dominio (o nome no certificado "
                "precisa bater com o endereco do servidor)."),
            "operation": operation,
        }, operation)

    # Generic updates that would reach the gated effects without the gate.
    _ATRIBUTOS_DE_SENHA = {"unicodepwd", "userpassword"}
    _ATRIBUTOS_DE_MEMBRO = {"member", "memberof"}

    def _recusa_atributo_reservado(self, operation: str,
                                   attributes: Any) -> Optional[List[Content]]:
        """Refuse password or membership attributes in a generic create/update."""
        if not isinstance(attributes, dict):
            return None
        chaves = {str(k).split(";", 1)[0].strip().lower(): str(k) for k in attributes}
        senha = [chaves[k] for k in chaves if k in self._ATRIBUTOS_DE_SENHA]
        membro = [chaves[k] for k in chaves if k in self._ATRIBUTOS_DE_MEMBRO]
        if not senha and not membro:
            return None
        partes = []
        if senha:
            partes.append(f"{', '.join(senha)}: senha so pela action reset_password (ou o "
                          "parametro password na criacao), que checa canal seguro e alvo "
                          "privilegiado")
        if membro:
            partes.append(f"{', '.join(membro)}: membros so pelas actions add_members / "
                          "remove_members, que checam grupo privilegiado e nao substituem a "
                          "lista inteira")
        return self._format_response({
            "success": False, "sucesso": False, "erro": "ATRIBUTO_RESERVADO",
            "mensagem": "Recusado, nada foi alterado. " + "; ".join(partes) + ".",
            "operation": operation, "atributos_recusados": senha + membro,
        }, operation)

    def _handle_ldap_error(self, e: Exception, operation: str, dn: str = "") -> List[Content]:
        """
        Handle LDAP errors and format error response.
        
        Args:
            e: Exception that occurred
            operation: Operation that failed
            dn: Distinguished name (if applicable)
            
        Returns:
            List of MCP content objects with error information
        """
        # An exception with an empty str() used to reach the client as an empty
        # error; the class name at least says what kind of failure it was.
        error_msg = redact(str(e)) or type(e).__name__
        
        if isinstance(e, LDAPException):
            self.logger.error(f"LDAP error during {operation}: {error_msg}")
        else:
            self.logger.error(f"Unexpected error during {operation}: {error_msg}")
        
        # Log for audit
        if dn:
            log_ldap_operation(operation, dn, False, error_msg)
        
        error_response = {
            "success": False,
            "error": error_msg,
            "operation": operation,
            "type": type(e).__name__
        }
        
        if dn:
            error_response["dn"] = dn
        
        return [Content(type="text", text=json.dumps(error_response, indent=2))]
    
    def _validate_dn(self, dn: str) -> bool:
        """
        Validate Distinguished Name format.
        
        Args:
            dn: Distinguished name to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not dn or not isinstance(dn, str):
            return False
        
        # Basic DN validation - should contain at least one component. Split on
        # UNESCAPED commas only: "CN=Silva\, Joao,OU=x" is one RDN plus one,
        # and a plain split rejected every "Surname, Name" account as malformed.
        dn_parts = re.split(r'(?<!\\),', dn)
        for part in dn_parts:
            part = part.strip()
            if '=' not in part:
                return False
            
            key, value = part.split('=', 1)
            if not key.strip() or not value.strip():
                return False
        
        return True
    
    def _build_dn(self, name: str, ou: str) -> str:
        """
        Build Distinguished Name from name and organizational unit.
        
        Args:
            name: Object name (CN)
            ou: Organizational unit DN
            
        Returns:
            Complete DN
        """
        return f"CN={name},{ou}"
    
    def _success_response(self, message: str, data: Optional[Dict[str, Any]] = None) -> List[Content]:
        """
        Create success response.
        
        Args:
            message: Success message
            data: Optional additional data
            
        Returns:
            List of MCP content objects
        """
        response = {
            "success": True,
            "message": message
        }
        
        if data:
            response.update(data)
        
        return [Content(type="text", text=json.dumps(response, indent=2, ensure_ascii=False))]
    
    def _escape_ldap_filter(self, value: str) -> str:
        """
        Escape special characters in LDAP filter values.
        
        Args:
            value: Value to escape
            
        Returns:
            Escaped value
        """
        # Escape special LDAP filter characters.
        # The backslash MUST be escaped first, otherwise the backslashes we
        # introduce for the other replacements (\2a, \28, ...) would be
        # re-escaped, corrupting the filter.
        escape_chars = {
            '\\': r'\5c',
            '*': r'\2a',
            '(': r'\28',
            ')': r'\29',
            '\x00': r'\00'
        }

        for char, escaped in escape_chars.items():
            value = value.replace(char, escaped)
        
        return value
    
    @abstractmethod
    def get_schema_info(self) -> Dict[str, Any]:
        """
        Get schema information for this tool's operations.
        
        Returns:
            Dictionary with schema information
        """
        pass

    # Windows FILETIME epoch and the "never expires" sentinel.
    _FILETIME_EPOCH = datetime(1601, 1, 1)
    _NEVER_EXPIRES = 9223372036854775807

    # AD default containers, present in every domain.
    _CONTAINER_PADRAO = {"users": "CN=Users", "groups": "CN=Users",
                         "computers": "CN=Computers", "service_accounts": "CN=Users"}

    def _default_ou(self, kind: str) -> str:
        """Where to create an object when the caller did not say.

        @MX:ANCHOR group.py and computer.py used to read
        ad_config.organizational_units, a field ActiveDirectoryConfig never had:
        creating without an explicit OU raised AttributeError, and the
        configured OUs were dead letters. The unit tests missed it because they
        mocked ad_config with a bare Mock, which answers any attribute.
        """
        ou_config = getattr(self.ldap, "ou_config", None)
        if ou_config is not None:
            valor = getattr(ou_config, f"{kind}_ou", None)
            if valor:
                return valor
        return f"{self._CONTAINER_PADRAO.get(kind, 'CN=Users')},{self.ldap.ad_config.base_dn}"

    def _as_filetime(self, value) -> int:
        """Normalize an AD time attribute to FILETIME ticks (100ns).

        @MX:ANCHOR ldap3 decodes AD time attributes inconsistently: an int for
        raw values, a datetime for Generalized-Time (pwdLastSet, accountExpires,
        lastLogon) and a timedelta for the Interval syntax (maxPwdAge). Code that
        compares the raw value against an int is right for one form and silently
        wrong for the others. Every arithmetic use must pass through here.
        """
        if value is None or isinstance(value, bool):
            return 0
        if isinstance(value, datetime):
            dt = value
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return int((dt - self._FILETIME_EPOCH).total_seconds() * 10000000)
        if isinstance(value, timedelta):
            return int(value.total_seconds() * 10000000)
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _now_filetime(self) -> int:
        """Current time as FILETIME ticks. AD stores these in UTC."""
        return self._as_filetime(datetime.now(timezone.utc))

    def _never_expires_floor(self) -> int:
        """Any accountExpires at or above this means "never".

        Covers both forms: the int sentinel and the year-9999 datetime ldap3
        produces from it.
        """
        return self._as_filetime(datetime(9999, 1, 1))

    def _get_attr(self, attributes: Dict, key: str, default=None):
        """
        Safely get attribute value from LDAP response.
        Handles both list and single value returns from ldap3.
        
        Args:
            attributes: Dict of attributes from LDAP response
            key: Attribute name
            default: Default value if not found
            
        Returns:
            Attribute value (first item if list, otherwise direct value)
        """
        value = attributes.get(key, default)
        if value is None:
            return default
        if isinstance(value, list):
            return value[0] if value else default
        return value

    def _get_attr_list(self, attributes: Dict, key: str) -> List[Any]:
        """
        Safely get a multivalued attribute as a list from an LDAP response.

        ldap3 returns a multivalued attribute as a scalar (str) when it holds
        exactly one value, as a list when it holds two or more, and may return
        None when the attribute is present but empty. This normalizes all three
        cases to a list so callers can safely iterate or call len().

        Args:
            attributes: Dict of attributes from LDAP response
            key: Attribute name

        Returns:
            List of attribute values (empty list if missing/None)
        """
        value = attributes.get(key)
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    # ------------------------------------------------ shared building blocks
    # Several tools answer with the same pieces (the groups of an account, the
    # OU it lives in, a move read back from the directory). They are built
    # here once so the answers cannot drift apart between tools.

    _LOTE_DE_DNS = 40

    @staticmethod
    def _nome_do_dn(dn: str) -> str:
        """'CN=Financeiro - Leitura,OU=...' -> 'Financeiro - Leitura'."""
        partes = dividir_dn(str(dn))
        if not partes or "=" not in partes[0]:
            return str(dn)
        return partes[0].split("=", 1)[1].replace("\\,", ",").strip()

    @staticmethod
    def _pai_do_dn(dn: str) -> str:
        return ",".join(dividir_dn(str(dn))[1:])

    @staticmethod
    def _caminho_da_ou(dn: str) -> str:
        """Readable path of the OU that holds an object: 'Filial/Financeiro'."""
        return caminho_legivel(dn)

    def _descrever_grupos(self, dns: List[str]) -> List[Dict[str, Any]]:
        """Name, login, type and scope of each group DN, in batched searches.

        One OR search per batch instead of one BASE search per group: an
        account in 30 groups used to cost 30 round trips. A DN the directory
        does not return (deleted meanwhile, other domain) is still listed, by
        the name read from the DN itself, and flagged -- dropping it would
        understate the account's access.
        """
        dns = [str(d) for d in dns if d]
        achados: Dict[str, Dict[str, Any]] = {}
        for inicio in range(0, len(dns), self._LOTE_DE_DNS):
            lote = dns[inicio:inicio + self._LOTE_DE_DNS]
            filtro = "(|" + "".join(
                f"(distinguishedName={self._escape_ldap_filter(d)})" for d in lote) + ")"
            try:
                resultados = self.ldap.search(
                    search_base=self.ldap.ad_config.base_dn,
                    search_filter=f"(&(objectClass=group){filtro})",
                    attributes=['cn', 'sAMAccountName', 'groupType', 'description'])
            except Exception as exc:  # noqa: BLE001 - the names still come from the DNs
                self.logger.warning("Nao foi possivel detalhar grupos: %s", exc)
                resultados = []
            for entrada in resultados:
                achados[normalizar_dn(entrada['dn'])] = entrada
        grupos = []
        for dn in dns:
            entrada = achados.get(normalizar_dn(dn))
            item: Dict[str, Any] = {"nome": self._nome_do_dn(dn)}
            if entrada is None:
                item["dn"] = dn
                item["aviso"] = "detalhes nao lidos (grupo fora do dominio ou removido)"
            else:
                attrs = entrada['attributes']
                login = self._get_attr(attrs, 'sAMAccountName', '')
                if login and login != item["nome"]:
                    item["login"] = login
                tipo = self._get_attr(attrs, 'groupType', None)
                if tipo is not None:
                    tipo = int(tipo)
                    item["tipo"] = "Security" if tipo & 0x80000000 else "Distribution"
                    item["escopo"] = ("Global" if tipo & 0x2 else "DomainLocal" if tipo & 0x4
                                      else "Universal" if tipo & 0x8 else "Desconhecido")
                item["dn"] = entrada['dn']
            grupos.append(item)
        grupos.sort(key=lambda g: g["nome"].lower())
        return grupos

    # Built-in primary groups, used when the SID lookup is not possible.
    _GRUPOS_PRIMARIOS = {512: "Domain Admins", 513: "Domain Users", 514: "Domain Guests",
                         515: "Domain Computers", 516: "Domain Controllers"}

    def _grupo_primario(self, attrs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """The group an account belongs to through primaryGroupID.

        memberOf never lists it, so an account whose only group is Domain
        Users showed "0 groups" -- and a model asked to copy those groups
        went looking for them in six more tools.
        """
        rid = self._get_attr(attrs, 'primaryGroupID', None)
        if rid is None:
            return None
        rid = int(rid)
        nome, dn = self._GRUPOS_PRIMARIOS.get(rid, f"RID {rid}"), None
        sid = self._get_attr(attrs, 'objectSid', None)
        if isinstance(sid, str) and sid.startswith("S-") and "-" in sid:
            sid_do_grupo = sid.rsplit("-", 1)[0] + f"-{rid}"
            try:
                achado = self.ldap.search(
                    search_base=self.ldap.ad_config.base_dn,
                    search_filter=f"(&(objectClass=group)(objectSid={sid_do_grupo}))",
                    attributes=['cn'])
                if achado:
                    nome, dn = self._get_attr(achado[0]['attributes'], 'cn', nome), achado[0]['dn']
            except Exception as exc:  # noqa: BLE001 - the well-known name is enough
                self.logger.debug("Grupo primario por SID indisponivel: %s", exc)
        resposta = {"nome": nome, "rid": rid,
                    "nota": "grupo primario: vem de primaryGroupID, nao de memberOf; toda "
                            "conta nova ja nasce em Domain Users, nao precisa copiar"}
        if dn:
            resposta["dn"] = dn
        return resposta

    def _mover_e_reler(self, dn: str, novo_pai: str) -> Dict[str, Any]:
        """Move one object and read its new DN back from the directory.

        Returns old_dn/new_dn/changed/verified. Moving into the OU the object
        is already in is not an error: nothing is written and changed=False.
        """
        if normalizar_dn(self._pai_do_dn(dn)) == normalizar_dn(novo_pai):
            return {"old_dn": dn, "new_dn": dn, "changed": False, "verified": True}
        self.ldap.move(dn, novo_pai)
        novo_dn = f"{dividir_dn(dn)[0]},{novo_pai}"
        relido = self.ldap.search(search_base=novo_dn, search_filter="(objectClass=*)",
                                  attributes=['name'], search_scope=ldap3.BASE)
        return {"old_dn": dn, "new_dn": relido[0]['dn'] if relido else novo_dn,
                "changed": True, "verified": bool(relido)}

