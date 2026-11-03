"""What a caller may ask the directory for: secrets are never readable nor guessable.

Ported by hand from upstream alpadalar/ActiveDirectoryMCP f5fef26 (WR-02) and
extended to the read side, which upstream left open in this fork.

A filter is a blind oracle: ``(ms-Mcs-AdmPwd=a*)`` matching one computer and
``(ms-Mcs-AdmPwd=b*)`` matching none reveals a LAPS password one character at a
time through result counts, even if the attribute itself is never returned. So
caller-supplied filters must not *name* a secret attribute, must not name any
attribute by OID (which would bypass the name list), and must not use
extensible-match terms (``attr:rule:=``), the syntax of chained-membership and
bitwise probes.

The same names are refused in an explicit ``attributes`` request, and
:func:`ocultar_sensiveis` scrubs them from any payload as a backstop for
``attributes=["*"]``, which AD answers with every attribute the service account
can read -- confidential ones included when it is a Domain Admin.

Only caller input goes through here. Internal reads that must touch a protected
attribute (the DACL in ``LDAPManager.get_security_descriptor``) use the
connection directly and are not affected.

Only attribute NAMES are ever reported back, never the values of a filter.
"""

from typing import Any, Iterable, List, Optional

from ldap3.operation.search import MATCH_EXTENSIBLE, parse_filter

# Lower-cased. Passwords and their history, LAPS (legacy and Windows LAPS,
# DSRM included), gMSA, key credentials (shadow credentials), BitLocker
# recovery, trust secrets, credential roaming, security descriptors and the
# delegation attribute that grants impersonation.
SENSITIVE_ATTRIBUTES = frozenset(nome.lower() for nome in (
    "userPassword", "unicodePwd", "dBCSPwd", "lmPwdHistory", "ntPwdHistory",
    "pwdHistory", "supplementalCredentials", "unixUserPassword",
    "ntSecurityDescriptor",
    "msDS-KeyCredentialLink",
    "msDS-ManagedPassword", "msDS-ManagedPasswordId", "msDS-ManagedPasswordPreviousId",
    "ms-Mcs-AdmPwd",
    "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory",
    "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory",
    "msFVE-RecoveryPassword", "msFVE-KeyPackage", "msFVE-RecoveryGuid", "msFVE-VolumeGuid",
    "priorValue", "currentValue",
    "initialAuthIncoming", "initialAuthOutgoing", "trustAuthIncoming", "trustAuthOutgoing",
    "msPKI-CredentialRoamingTokens", "msPKI-DPAPIMasterKeys", "msPKIAccountCredentials",
    "securityIdentifier", "sIDHistory",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
))

MARCA_OCULTO = "<oculto: atributo sensivel, nunca devolvido por este servidor>"

ERRO_FILTRO = "FILTRO_LDAP_PROIBIDO"
ERRO_ATRIBUTO = "ATRIBUTO_SENSIVEL"


def _nome_base(atributo: str) -> str:
    """'MS-MCS-ADMPWD;binary ' -> 'ms-mcs-admpwd' (options and case dropped)."""
    return str(atributo).split(";", 1)[0].strip().lower()


def eh_sensivel(atributo: Any) -> bool:
    return isinstance(atributo, str) and _nome_base(atributo) in SENSITIVE_ATTRIBUTES


def _motivo_no_no(no: Any) -> Optional[str]:
    if no.tag == MATCH_EXTENSIBLE:
        return ("usa correspondencia extensivel (':regra:=' ou ':dn:='), como "
                "memberOf:1.2.840.113556.1.4.1941:= ou o E bit a bit em userAccountControl")
    assercao = no.assertion if isinstance(no.assertion, dict) else {}
    atributo = assercao.get("attr")
    if isinstance(atributo, str):
        base = _nome_base(atributo)
        if base[:1].isdigit():
            return f"nomeia um atributo por OID ('{atributo.strip()}'); use o nome do atributo"
        if base in SENSITIVE_ATTRIBUTES:
            return (f"consulta o atributo sensivel '{atributo.split(';', 1)[0].strip()}' "
                    "(senha, LAPS, gMSA, BitLocker ou equivalente)")
    for filho in no.elements or []:
        motivo = _motivo_no_no(filho)
        if motivo:
            return motivo
    return None


def motivo_filtro_proibido(filtro: Any) -> Optional[str]:
    """Why a caller-supplied LDAP filter must not run; None when it may.

    Text that does not parse is not judged here (the resolver turns free text
    into a word search and reports malformed filters itself); the bare
    ``attr=value`` form is wrapped in parentheses first, as the resolver does.
    """
    if not isinstance(filtro, str):
        return None
    texto = filtro.strip()
    if not texto:
        return None
    if not texto.startswith("("):
        texto = f"({texto})"
    try:
        arvore = parse_filter(texto, None, auto_escape=True, auto_encode=True,
                              validator=None, check_names=False)
    except Exception:  # noqa: BLE001 - not an LDAP filter: free text, judged elsewhere
        return None
    return _motivo_no_no(arvore)


def atributos_sensiveis_pedidos(atributos: Any) -> List[str]:
    """The secret attribute names inside an ``attributes`` request."""
    if isinstance(atributos, str):
        atributos = [atributos]
    if not isinstance(atributos, (list, tuple, set)):
        return []
    return [str(a).split(";", 1)[0].strip() for a in atributos if eh_sensivel(a)]


def recusa_de_consulta(filtro: Any = None, atributos: Optional[Iterable[Any]] = None,
                       tool: Optional[str] = None) -> Optional[dict]:
    """A ready refusal payload for a forbidden filter or attribute request.

    @MX:ANCHOR The one predicate for caller-supplied reads: the resolver (both
    transports) and the tool layer (direct callers) both ask here.
    @MX:REASON Two copies of a deny-list drift; one function cannot disagree
    with itself.
    """
    motivo = motivo_filtro_proibido(filtro)
    if motivo:
        recusa = {
            "success": False, "sucesso": False, "erro": ERRO_FILTRO,
            "mensagem": (
                f"filter_criteria recusado: o filtro {motivo}. Filtros assim permitem "
                "adivinhar segredos pela contagem de resultados, entao este servidor nao os "
                "executa. Nada foi consultado. Use texto livre (nome, login, e-mail) ou um "
                "filtro sobre atributos comuns, ex.: (department=Financeiro)."),
        }
        if tool:
            recusa["tool"] = tool
        return recusa
    pedidos = atributos_sensiveis_pedidos(atributos)
    if pedidos:
        recusa = {
            "success": False, "sucesso": False, "erro": ERRO_ATRIBUTO,
            "mensagem": (
                f"attributes recusado: {', '.join(pedidos)} guarda segredo (senha, LAPS, "
                "gMSA, BitLocker ou equivalente) e nunca e devolvido por este servidor. "
                "Nada foi consultado. Retire esses nomes do pedido."),
            "atributos_recusados": pedidos,
        }
        if tool:
            recusa["tool"] = tool
        return recusa
    return None


def ocultar_sensiveis(dados: Any) -> Any:
    """Replace the value of every secret attribute, at any depth (backstop)."""
    if isinstance(dados, dict):
        return {chave: (MARCA_OCULTO if eh_sensivel(chave) else ocultar_sensiveis(valor))
                for chave, valor in dados.items()}
    if isinstance(dados, list):
        return [ocultar_sensiveis(item) for item in dados]
    return dados
