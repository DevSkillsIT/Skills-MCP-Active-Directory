"""Server-side resolution of what the operator typed into one Active Directory object.

Why this exists: every tool used to look objects up by sAMAccountName and
nothing else. Asked to offboard an employee by full name, a model got "found
in 0 of 8 servers" for an account that existed -- its CN was the full name,
its displayName something else, its login a third thing. The model cannot be
trusted to guess which field holds what, so the server resolves the name.

Resolution runs in layers and stops at the first that answers:

1. exact identifier: login, UPN, e-mail, DN, CN, displayName (or OU name);
2. every word: each typed word appears in some name field, in any order;
3. approximate: a typo-tolerant comparison against the directory's index,
   only when the first two found nothing.

Measured on the eight production directories: substring and equality matches
already ignore case AND accents ((cn=*joao*) == (cn=*joão*) == (cn=*JOÃO*)), so
layers 1 and 2 run as LDAP filters on the server. The largest directory holds
about 400 users, so layer 3 can afford to read the whole index.

Write policy (decided by the operator, 2026-09-18): a write runs when exactly
one object matches at layer 1 or 2 -- every typed word present. A match that
exists only as a fragment of a word, or only as a typo, is shown as a
candidate and never executed. Ambiguity never executes, read or write.
"""

import difflib
import re
import threading
import time
import unicodedata
import weakref
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import ldap3
from ldap3.core.exceptions import LDAPInvalidFilterError
from ldap3.operation.search import parse_filter
from ldap3.utils.conv import escape_filter_chars

from .ldap_policy import recusa_de_consulta

# ----------------------------------------------------------------- object kinds

_PESSOA = "(&(objectCategory=person)(objectClass=user))"
_GRUPO = "(objectClass=group)"
_COMPUTADOR = "(objectClass=computer)"
_OU = "(objectClass=organizationalUnit)"
# A destination may also be a plain container (CN=Users) or the domain root.
_CONTEINER = "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domain))"


@dataclass(frozen=True)
class Tipo:
    chave: str
    rotulo: str
    plural: str
    filtro: str
    exatos: Tuple[str, ...]
    palavras: Tuple[str, ...]
    devolve: str                  # "login" (sAMAccountName) or "dn"
    procurado_em: str


_USUARIO_EXATOS = ("sAMAccountName", "userPrincipalName", "mail", "cn", "displayName", "name")
_USUARIO_PALAVRAS = ("cn", "displayName", "givenName", "sn", "sAMAccountName",
                     "userPrincipalName", "mail")
_GRUPO_EXATOS = ("sAMAccountName", "cn", "name", "displayName", "mail")
_GRUPO_PALAVRAS = ("cn", "displayName", "sAMAccountName", "mail")
_COMPUTADOR_EXATOS = ("sAMAccountName", "cn", "name", "dNSHostName")
_COMPUTADOR_PALAVRAS = ("cn", "dNSHostName", "sAMAccountName")
_OU_EXATOS = ("ou", "name", "cn")
_OU_PALAVRAS = ("ou", "name")


def _uniao(*listas):
    vistos, saida = set(), []
    for lista in listas:
        for item in lista:
            if item.lower() not in vistos:
                vistos.add(item.lower())
                saida.append(item)
    return tuple(saida)


TIPOS: Dict[str, Tipo] = {
    "usuario": Tipo(
        "usuario", "usuário", "usuários", _PESSOA, _USUARIO_EXATOS, _USUARIO_PALAVRAS,
        "login",
        "login (sAMAccountName), e-mail, UPN, nome completo (CN), nome de exibição, "
        "nome e sobrenome"),
    "grupo": Tipo(
        "grupo", "grupo", "grupos", _GRUPO, _GRUPO_EXATOS, _GRUPO_PALAVRAS, "login",
        "nome do grupo (CN), login do grupo (sAMAccountName), nome de exibição, e-mail"),
    "computador": Tipo(
        "computador", "computador", "computadores", _COMPUTADOR, _COMPUTADOR_EXATOS,
        _COMPUTADOR_PALAVRAS, "login",
        "nome do computador, nome DNS (FQDN), login da máquina (sAMAccountName)"),
    "ou": Tipo(
        "ou", "unidade organizacional (OU)", "unidades organizacionais", _OU,
        _OU_EXATOS, _OU_PALAVRAS, "dn",
        "nome da OU, caminho (ex.: Filial/Financeiro) ou DN"),
    "membro": Tipo(
        "membro", "usuário, grupo ou computador", "objetos",
        f"(|{_PESSOA}{_GRUPO}{_COMPUTADOR})",
        _uniao(_USUARIO_EXATOS, _GRUPO_EXATOS, _COMPUTADOR_EXATOS),
        _uniao(_USUARIO_PALAVRAS, _GRUPO_PALAVRAS, _COMPUTADOR_PALAVRAS), "dn",
        "login, e-mail, nome completo, nome de exibição, nome de grupo ou de computador"),
    "responsavel": Tipo(
        "responsavel", "usuário ou grupo", "objetos", f"(|{_PESSOA}{_GRUPO})",
        _uniao(_USUARIO_EXATOS, _GRUPO_EXATOS), _uniao(_USUARIO_PALAVRAS, _GRUPO_PALAVRAS),
        "dn", "login, e-mail, nome completo, nome de exibição ou nome do grupo"),
    "objeto": Tipo(
        "objeto", "usuário, computador, grupo ou OU", "objetos",
        f"(|{_PESSOA}{_GRUPO}{_COMPUTADOR}{_OU})",
        _uniao(_USUARIO_EXATOS, _GRUPO_EXATOS, _COMPUTADOR_EXATOS, _OU_EXATOS),
        _uniao(_USUARIO_PALAVRAS, _GRUPO_PALAVRAS, _COMPUTADOR_PALAVRAS, _OU_PALAVRAS),
        "dn", "login, e-mail, nome completo, nome de exibição, nome de grupo, de "
              "computador ou de OU"),
}

# Values of object_type that narrow an object_name lookup.
TIPO_POR_OBJECT_TYPE = {
    "user": "usuario", "usuario": "usuario", "computer": "computador",
    "computador": "computador", "group": "grupo", "grupo": "grupo",
    "organizational_unit": "ou", "organizationalunit": "ou", "ou": "ou",
    "unidade_organizacional": "ou",
}

# --------------------------------------------------------- which params resolve

# @MX:ANCHOR Parameter name -> object kind. A tool added later that names an
# existing object with one of these parameters is resolved without touching
# this module. A parameter that names a NEW object must be listed in
# NOMES_NOVOS, or the server would look for an object that does not exist yet.
PARAMETROS_RESOLVIDOS = {
    "username": "usuario",
    "group_name": "grupo",
    "computer_name": "computador",
    "member_dn": "membro",
    "managed_by": "responsavel",
    "object_name": "objeto",
    "ou": "ou",
    "parent_ou": "ou",
    "ou_dn": "ou",
    "new_parent_dn": "ou",
    "copy_from_user": "usuario",
    "move_to_ou": "ou",
    "members": "membro",
}

# tool -> (parameter, actions in which it names an object that does not exist
# yet). With manage_* tools the same `username` is new on create and existing
# on every other action, so the action decides.
NOMES_NOVOS = {
    "ad_manage_directory_users": ("username", {"create"}),
    "ad_manage_directory_groups": ("group_name", {"create"}),
    "ad_manage_directory_computers": ("computer_name", {"create"}),
}


def nome_novo_de(tool_name: str, args: Dict[str, Any]) -> Optional[str]:
    """The parameter that names a NEW object in this call, if any."""
    regra = NOMES_NOVOS.get(tool_name)
    if not regra:
        return None
    parametro, acoes = regra
    return parametro if str(args.get("action") or "") in acoes else None

# LDAP attributes whose value is a DN, inside attributes/additional_attributes.
# Keys compare without case or punctuation, and the operator names that
# UserTools maps onto the same attribute are here too: "gestor" used to reach
# the directory raw, skipping the other-domain and ambiguity refusals.
ATRIBUTOS_DN = {"manager": "usuario", "gestor": "usuario",
                "managedby": "responsavel", "responsavel": "responsavel"}
# A nested dict (PowerShell's -OtherAttributes) is scanned as well.
_ATRIBUTOS_ANINHADOS = {"otherattributes"}


def _chave_de_atributo(chave: Any) -> str:
    return re.sub(r"[^0-9a-z]", "", normalizar(chave))
PARAMETROS_DE_ATRIBUTOS = ("attributes", "additional_attributes")

# Listing tools whose filter_criteria also accepts plain text.
LISTAGENS = {
    "ad_search_directory_users": "usuario",
    "ad_search_directory_groups": "grupo",
    "ad_search_directory_computers": "computador",
    "ad_search_organizational_units": "ou",
}

_ATRIBUTOS_LIDOS = [
    "sAMAccountName", "userPrincipalName", "mail", "cn", "displayName", "name",
    "givenName", "sn", "dNSHostName", "ou", "objectClass", "userAccountControl",
]

_ROTULO_DO_ATRIBUTO = {
    "samaccountname": "login (sAMAccountName)", "userprincipalname": "UPN",
    "mail": "e-mail", "cn": "nome completo (CN)", "displayname": "nome de exibição",
    "name": "nome", "dnshostname": "nome DNS", "ou": "nome da OU",
}

_PARTICULAS = {"de", "da", "do", "das", "dos", "e"}
_LIMITE_CANDIDATOS = 10
_LIMITE_PARECIDOS = 5
_NOTA_RESOLVE = 0.84          # approximate match strong enough to name one object
_FOLGA_RESOLVE = 0.08         # ...and clearly ahead of the runner-up
_NOTA_PARECIDO = 0.6          # worth suggesting
_TTL_INDICE = 120.0

# --------------------------------------------------------------- normalization


def normalizar(texto: Any) -> str:
    """Casefold, strip accents and collapse spaces -- how AD itself compares."""
    bruto = unicodedata.normalize("NFKD", str(texto or "").casefold())
    sem_acento = "".join(c for c in bruto if not unicodedata.combining(c))
    return " ".join(sem_acento.split())


def palavras_de(texto: Any) -> List[str]:
    return [p for p in re.split(r"[^0-9a-z]+", normalizar(texto)) if p]


def termos_de_busca(texto: str) -> List[str]:
    """Words worth searching for: particles like 'de'/'da' match everything."""
    palavras = palavras_de(texto)
    uteis = [p for p in palavras if len(p) >= 2 and p not in _PARTICULAS]
    return uteis or [p for p in palavras if len(p) >= 2] or palavras


def dividir_dn(dn: str) -> List[str]:
    """Split a DN on unescaped commas (CN=Silva\\, Joao stays one RDN)."""
    partes, atual, escapado = [], [], False
    for c in str(dn):
        if escapado:
            atual.append(c)
            escapado = False
        elif c == "\\":
            atual.append(c)
            escapado = True
        elif c == ",":
            partes.append("".join(atual).strip())
            atual = []
        else:
            atual.append(c)
    partes.append("".join(atual).strip())
    return [p for p in partes if p]


def _valor_do_rdn(rdn: str) -> str:
    return rdn.split("=", 1)[1].strip() if "=" in rdn else rdn.strip()


def _chave_de_nome(texto: str) -> str:
    return re.sub(r"[^0-9a-z]", "", normalizar(texto))


def normalizar_dn(dn: str) -> str:
    """Compare DNs by component: spaces INSIDE a value are significant."""
    partes = []
    for rdn in dividir_dn(dn):
        chave, _, valor = rdn.partition("=")
        partes.append(f"{chave.strip().lower()}={normalizar(valor)}")
    return ",".join(partes)


def caminho_legivel(dn: str) -> str:
    """'CN=x,OU=Financeiro,OU=Filial,DC=a' -> 'Filial/Financeiro'."""
    pais = [_valor_do_rdn(p) for p in dividir_dn(dn)[1:] if not p.lower().startswith("dc=")]
    return "/".join(reversed(pais)) or "(raiz do domínio)"


def _um(atributos: Optional[Dict[str, Any]], nome: str):
    for chave, valor in (atributos or {}).items():
        if chave.lower() == nome.lower():
            if isinstance(valor, (list, tuple)):
                return valor[0] if valor else None
            return valor
    return None


def _todos(atributos: Optional[Dict[str, Any]], nome: str) -> List[Any]:
    for chave, valor in (atributos or {}).items():
        if chave.lower() == nome.lower():
            if valor is None:
                return []
            return list(valor) if isinstance(valor, (list, tuple)) else [valor]
    return []


def _classe_de(entrada: Dict[str, Any]) -> str:
    classes = {str(c).lower() for c in _todos(entrada.get("attributes"), "objectClass")}
    if "computer" in classes:
        return "computador"
    if "group" in classes:
        return "grupo"
    if "organizationalunit" in classes:
        return "ou"
    if "user" in classes:
        return "usuario"
    if "domain" in classes or "domaindns" in classes:
        return "dominio"
    return "conteiner"


def _palavras_do_objeto(entrada: Dict[str, Any]) -> set:
    a = entrada.get("attributes") or {}
    palavras = set()
    for nome in ("cn", "displayName", "givenName", "sn", "name", "ou", "sAMAccountName"):
        for valor in _todos(a, nome):
            palavras.update(palavras_de(valor))
    for nome in ("mail", "userPrincipalName"):
        for valor in _todos(a, nome):
            palavras.update(palavras_de(str(valor).split("@", 1)[0]))
    for valor in _todos(a, "dNSHostName"):
        palavras.update(palavras_de(str(valor).split(".", 1)[0]))
    if not palavras:
        palavras.update(palavras_de(_valor_do_rdn(dividir_dn(entrada.get("dn", ""))[0])))
    return palavras


def filtro_de_palavras(chave_tipo: str, texto: str) -> str:
    """Every word must appear somewhere in the kind's name fields."""
    tipo = TIPOS[chave_tipo]
    blocos = []
    for termo in termos_de_busca(texto):
        valor = escape_filter_chars(termo)
        blocos.append("(|" + "".join(f"({a}=*{valor}*)" for a in tipo.palavras) + ")")
    return "(&" + "".join(blocos) + ")" if len(blocos) > 1 else (blocos[0] if blocos else "")


def validar_filtro_ldap(filtro: str) -> Optional[str]:
    """None when the filter parses; otherwise the parser's complaint."""
    try:
        parse_filter(filtro, None, auto_escape=True, auto_encode=True,
                     validator=None, check_names=False)
    except LDAPInvalidFilterError as exc:
        return str(exc) or "filtro invalido"
    except Exception as exc:  # the parser raises plain errors on some shapes
        return str(exc) or type(exc).__name__
    return None


# ------------------------------------------------------------------- the index

# Tool calls now run in worker threads; these caches are shared across them.
_TRAVA_DOS_CACHES = threading.Lock()
_INDICES: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()
_NETBIOS: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()
_DOMINIOS_DE_EMAIL: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _indice(ldap, base_dn: str, tipo: Tipo) -> List[Dict[str, Any]]:
    """Every object of a kind, name fields only -- for the typo-tolerant layer."""
    chave = (base_dn.lower(), tipo.filtro)
    with _TRAVA_DOS_CACHES:
        guardado = _INDICES.setdefault(ldap, {}).get(chave)
    if guardado and time.monotonic() - guardado[0] < _TTL_INDICE:
        return guardado[1]
    entradas = ldap.search(search_base=base_dn, search_filter=tipo.filtro,
                           attributes=_ATRIBUTOS_LIDOS)
    with _TRAVA_DOS_CACHES:
        _INDICES.setdefault(ldap, {})[chave] = (time.monotonic(), entradas)
    return entradas


# ------------------------------------------------------------------ the result

@dataclass
class Resolucao:
    situacao: str                 # resolvido | ambiguo | nao_encontrado |
                                  # parcial_em_escrita | fora_do_dominio
    tipo: Tipo
    informado: str
    valor: Optional[str] = None
    dn: Optional[str] = None
    nome: Optional[str] = None
    nivel: Optional[str] = None   # exato | palavras | prefixo | trecho |
                                  # caminho_parcial | aproximado
    criterio: Optional[str] = None
    aviso: Optional[str] = None
    candidatos: List[Dict[str, Any]] = field(default_factory=list)
    total_candidatos: int = 0
    parecidos: List[Dict[str, Any]] = field(default_factory=list)
    entrada: Optional[Dict[str, Any]] = field(default=None, repr=False)
    outros: List[Dict[str, Any]] = field(default_factory=list)
    homonimos: bool = False


class ResolvedorAD:
    """Resolves one typed identifier against one bound directory."""

    # Only these levels may run a write (owner's policy, 2026-09-18).
    NIVEIS_DE_ESCRITA = ("exato", "palavras")
    _ORDEM = {"exato": 0, "palavras": 1, "prefixo": 2, "trecho": 3,
              "caminho_parcial": 4, "aproximado": 5}
    _AVISOS = {
        "prefixo": "por abreviacao ou inicial",
        "trecho": "por trecho de nome",
        "caminho_parcial": "por caminho de OU incompleto (ha OUs no meio do caminho)",
        "aproximado": "aproximada (possivel erro de digitacao)",
    }

    def __init__(self, ldap, base_dn: str):
        self.ldap = ldap
        self.base_dn = base_dn
        self.dominio = ".".join(_valor_do_rdn(p) for p in dividir_dn(base_dn)
                                if p.lower().startswith("dc="))

    # ------------------------------------------------------------ public entry

    def resolver(self, chave_tipo: str, informado: Any, escrita: bool,
                 devolver: Optional[str] = None) -> Resolucao:
        tipo = TIPOS[chave_tipo]
        texto = " ".join(str(informado).strip().strip('"').strip("'").split())
        res = self._resolver(tipo, texto, escrita)
        res.tipo = tipo
        res.informado = str(informado)
        if res.situacao != "resolvido":
            return res
        entrada = res.entrada
        res.dn = entrada["dn"]
        res.nome = self._nome(entrada)
        forma = devolver or tipo.devolve
        if forma == "login" and _classe_de(entrada) in ("usuario", "grupo", "computador"):
            res.valor = _um(entrada.get("attributes"), "sAMAccountName") or res.dn
        else:
            res.valor = res.dn
        if escrita and res.homonimos:
            # "Exactly one object contains every typed word" is the write rule;
            # an exact name with whole-word twins does not meet it.
            res.situacao = "ambiguo"
            res.candidatos = [self._descrever(entrada, tipo)] + res.outros
            res.total_candidatos = len(res.candidatos)
            return res
        if res.nivel not in self.NIVEIS_DE_ESCRITA:
            if escrita:
                res.candidatos = [self._descrever(entrada, tipo)]
                res.total_candidatos = 1
                res.situacao = "parcial_em_escrita"
            else:
                res.aviso = (f"Correspondencia {self._AVISOS.get(res.nivel, res.nivel)}: "
                             f"confira se '{res.nome}' e o objeto pretendido."
                             + (f" {res.aviso}" if res.aviso else ""))
        return res

    # --------------------------------------------------------------- layers

    def _resolver(self, tipo: Tipo, texto: str, escrita: bool) -> Resolucao:
        if not texto:
            return Resolucao("nao_encontrado", tipo, texto)
        baixo = texto.lower()

        if "dc=" in baixo and "=" in texto:
            return self._por_dn(tipo, texto)
        if re.match(r"^(cn|ou)=[^,]+(,|$)", baixo):
            return self._por_dn(tipo, f"{texto},{self.base_dn}")
        if tipo.chave == "ou" and normalizar(texto) in (normalizar(self.dominio),
                                                         normalizar(self.base_dn)):
            return self._por_dn(tipo, self.base_dn)

        separadores = r"[/>\\]" if tipo.chave == "ou" else r"[/>]"
        if tipo.chave in ("ou", "objeto") and re.search(separadores, texto):
            return self._por_caminho(TIPOS["ou"], texto)

        if tipo.chave != "ou" and "\\" in texto:
            dominio, login = (p.strip() for p in texto.rsplit("\\", 1))
            if normalizar(dominio) not in self._nomes_do_dominio():
                return Resolucao("fora_do_dominio", tipo, texto)
            achados = self._exato(tipo, login, atributos=("sAMAccountName",))
            if achados:
                return self._decidir_exato(tipo, login, achados)
            return self._sem_identificador(tipo, texto, login, escrita)

        if tipo.chave != "ou" and "@" in texto:
            achados = self._exato(tipo, texto, atributos=("mail", "userPrincipalName"))
            if achados:
                return self._decidir_exato(tipo, texto, achados)
            local, dominio = texto.rsplit("@", 1)
            if not self._dominio_de_email_conhecido(dominio):
                return Resolucao("fora_do_dominio", tipo, texto)
            return self._sem_identificador(tipo, texto, local, escrita)

        if tipo.chave == "computador" and texto.count(".") >= 2:
            sufixo = texto.split(".", 1)[1]
            if normalizar(sufixo) != normalizar(self.dominio):
                return Resolucao("fora_do_dominio", tipo, texto)

        achados = self._exato(tipo, texto)
        if achados:
            return self._decidir_exato(tipo, texto, achados)
        return self._por_palavras(tipo, texto)

    def _sem_identificador(self, tipo, texto, restante, escrita) -> Resolucao:
        """A login or address from THIS domain that does not exist.

        A write never falls back to a name search here: measured, 200 of 200
        addresses that did not exist resolved to someone by their local part.
        A read may, flagged as a fragment.
        """
        if escrita:
            return self._nao_encontrado(tipo, texto, self._notas(tipo, restante))
        res = self._por_palavras(tipo, restante)
        if res.situacao == "resolvido" and self._ORDEM[res.nivel] < self._ORDEM["trecho"]:
            res.nivel = "trecho"
            res.aviso = f"'{texto}' nao existe neste AD; o objeto foi achado pelo nome."
        return res

    def _exato(self, tipo: Tipo, texto: str, atributos: Optional[Tuple[str, ...]] = None):
        atributos = atributos or tipo.exatos
        itens = "".join(f"({a}={escape_filter_chars(texto)})" for a in atributos)
        classe = f"(|{_OU}(objectClass=container))" if tipo.chave == "ou" else tipo.filtro
        filtro = f"(&{classe}(|{itens}))"
        extras = []
        if tipo.chave in ("computador", "membro", "objeto"):
            # Computer-only variants, never tried against users/groups/OUs:
            # "PC01" -> sAMAccountName "PC01$", and a host name taken from an
            # FQDN only when the FQDN is in THIS domain. Splitting any dotted
            # text used to turn "TI.Suporte" into the OU "TI" and a typo'd
            # dotted login into whatever account its first part named.
            if not texto.endswith("$"):
                extras.append(f"(sAMAccountName={escape_filter_chars(texto + '$')})")
            if "." in texto:
                host, sufixo = texto.split(".", 1)
                if normalizar(sufixo) == normalizar(self.dominio):
                    extras.append(f"(cn={escape_filter_chars(host)})")
                    extras.append(f"(sAMAccountName={escape_filter_chars(host + '$')})")
        if extras:
            filtro = f"(|{filtro}(&{_COMPUTADOR}(|{''.join(extras)})))"
        return self.ldap.search(search_base=self.base_dn, search_filter=filtro,
                                attributes=_ATRIBUTOS_LIDOS)

    def _decidir_exato(self, tipo, texto, achados) -> Resolucao:
        if len({_classe_de(e) for e in achados}) > 1:
            # A group and an OU both named "Domain Controllers" (all 8 ADs):
            # which one was meant is not ours to guess.
            return self._ambiguo(tipo, texto, achados)
        preteridos, desempate = [], None
        if len(achados) > 1:
            # Unique keys first; mail is not unique (8 of 120 sampled accounts
            # shared it), sAMAccountName and userPrincipalName are.
            for chave in ("sAMAccountName", "userPrincipalName", "mail"):
                primarios = [e for e in achados if self._casa_atributo(e, texto, chave)]
                if len(primarios) == 1:
                    preteridos = [e for e in achados if e is not primarios[0]]
                    achados, desempate = primarios, chave
                    break
        if len(achados) != 1:
            return self._ambiguo(tipo, texto, achados)
        casado = self._atributo_casado(achados[0], texto)
        res = Resolucao("resolvido", tipo, texto, nivel="exato",
                        criterio="identificador exato: " + _ROTULO_DO_ATRIBUTO.get(
                            casado.lower(), casado))
        res.entrada = achados[0]
        if preteridos:
            # An address that is one account's UPN and another's mail (a shared
            # mailbox, measured in one directory) is a read answer, not a write
            # authorisation: the owner decided writes treat it as ambiguous. A
            # login (sAMAccountName) still decides.
            res.homonimos = desempate in ("userPrincipalName", "mail")
            res.outros = [self._descrever(e, tipo) for e in preteridos[:5]]
            res.aviso = (
                f"O valor informado tambem aparece em {len(preteridos)} outra(s) conta(s) "
                "(ex.: e-mail compartilhado). Foi usada a conta cujo login ou UPN e exatamente "
                "esse valor; veja 'outros_com_as_mesmas_palavras'.")
        elif casado.lower() in ("cn", "displayname", "name", "ou"):
            self._marcar_homonimos(res, tipo, texto)
        return res

    def _marcar_homonimos(self, res: Resolucao, tipo: Tipo, texto: str) -> None:
        """Other objects of the kind holding every typed word as whole words."""
        digitadas = self._palavras_digitadas(texto)
        termos = [p for p in digitadas if len(p) >= 2]
        if not termos:
            return
        outros = [e for e in self.ldap.search(
            search_base=self.base_dn,
            search_filter=f"(&{tipo.filtro}{filtro_de_palavras(tipo.chave, texto)})",
            attributes=_ATRIBUTOS_LIDOS)
            if e["dn"].lower() != res.entrada["dn"].lower()
            and self._qualidade(e, digitadas) == "palavra"]
        if outros:
            res.homonimos = True
            res.outros = [self._descrever(e, tipo) for e in self._ordenar(outros, texto)[:5]]
            res.aviso = (
                f"Resolvido pelo nome exato, mas {len(outros)} outro(s) {tipo.plural} tambem "
                "contem essas palavras (veja 'outros_com_as_mesmas_palavras'). Confira se e o "
                "objeto pretendido.")

    def _por_palavras(self, tipo: Tipo, texto: str) -> Resolucao:
        digitadas = self._palavras_digitadas(texto)
        if not [p for p in digitadas if len(p) >= 2]:
            return self._nao_encontrado(tipo, texto)
        achados = self.ldap.search(
            search_base=self.base_dn,
            search_filter=f"(&{tipo.filtro}{filtro_de_palavras(tipo.chave, texto)})",
            attributes=_ATRIBUTOS_LIDOS)
        classificados = [(self._qualidade(e, digitadas), e) for e in achados]
        return self._escolher(tipo, texto, [(q, e) for q, e in classificados if q])

    def _escolher(self, tipo, texto, classificados) -> Resolucao:
        """Best level wins; one object at that level resolves, more is ambiguous."""
        if not classificados:
            return self._aproximado(tipo, texto)
        nivel_de = {"palavra": "palavras"}
        por_nivel: Dict[str, list] = {}
        for qualidade, entrada in classificados:
            por_nivel.setdefault(nivel_de.get(qualidade, qualidade), []).append(entrada)
        niveis = sorted(por_nivel, key=lambda n: self._ORDEM[n])
        melhor = por_nivel[niveis[0]]
        if len(melhor) == 1:
            criterios = {
                "exato": "identificador exato",
                "palavras": "todas as palavras informadas aparecem no nome",
                "prefixo": "palavras abreviadas ou iniciais",
                "trecho": "as palavras aparecem apenas como trecho do nome",
                "caminho_parcial": "caminho de OUs incompleto",
            }
            res = Resolucao("resolvido", tipo, texto, nivel=niveis[0],
                            criterio=criterios.get(niveis[0], niveis[0]))
            res.entrada = melhor[0]
            return res
        ordenados = melhor + [e for n in niveis[1:] for e in por_nivel[n]]
        return self._ambiguo(tipo, texto, ordenados, total=len(classificados))

    def _aproximado(self, tipo: Tipo, texto: str) -> Resolucao:
        notas = self._notas(tipo, texto)
        if notas:
            melhor_nota, melhor = notas[0]
            segunda = notas[1][0] if len(notas) > 1 else 0.0
            if melhor_nota >= _NOTA_RESOLVE and melhor_nota - segunda >= _FOLGA_RESOLVE:
                res = Resolucao("resolvido", tipo, texto, nivel="aproximado",
                                criterio="nome parecido com o informado (possivel erro de "
                                         "digitacao)")
                res.entrada = melhor
                return res
        return self._nao_encontrado(tipo, texto, notas)

    def _por_dn(self, tipo: Tipo, dn: str) -> Resolucao:
        dn = ",".join(dividir_dn(dn))
        base = normalizar_dn(self.base_dn)
        alvo = normalizar_dn(dn)
        if alvo != base and not alvo.endswith("," + base):
            return Resolucao("fora_do_dominio", tipo, dn)
        filtro = _CONTEINER if tipo.chave == "ou" else tipo.filtro
        achados = self.ldap.search(search_base=dn, search_filter=filtro,
                                   attributes=_ATRIBUTOS_LIDOS, search_scope=ldap3.BASE)
        if achados:
            res = Resolucao("resolvido", tipo, dn, nivel="exato", criterio="DN")
            res.entrada = achados[0]
            return res
        nome = _valor_do_rdn(dividir_dn(dn)[0])
        return self._nao_encontrado(tipo, dn, self._notas(tipo, nome))

    def _por_caminho(self, tipo: Tipo, texto: str) -> Resolucao:
        partes = [p.strip() for p in re.split(r"\s*[/>\\]\s*", texto) if p.strip()]
        if len(partes) == 1:
            return self._resolver(tipo, partes[0], escrita=True)
        ultimo = partes[-1]
        acima = [_chave_de_nome(p) for p in reversed(partes[:-1])]   # nearest first

        exatos = self._exato(tipo, ultimo)
        if exatos:
            candidatos = [("exato", e) for e in exatos]
        else:
            digitadas = self._palavras_digitadas(ultimo)
            achados = self.ldap.search(
                search_base=self.base_dn,
                search_filter=f"(&{tipo.filtro}{filtro_de_palavras(tipo.chave, ultimo)})",
                attributes=_ATRIBUTOS_LIDOS) if [p for p in digitadas if len(p) >= 2] else []
            candidatos = [(q, e) for e in achados
                          for q in [self._qualidade(e, digitadas)] if q]

        classificados = []
        for qualidade, entrada in candidatos:
            ancestrais = [_chave_de_nome(_valor_do_rdn(p))
                          for p in dividir_dn(entrada["dn"])[1:]]
            if ancestrais[:len(acima)] == acima:
                classificados.append((qualidade, entrada))
            elif self._subsequencia(acima, ancestrais):
                classificados.append(("caminho_parcial", entrada))
        if not classificados:
            return self._nao_encontrado(tipo, texto, [(0.7, e) for _, e in candidatos])
        res = self._escolher(tipo, texto, classificados)
        if res.situacao == "resolvido" and res.nivel == "exato":
            res.criterio = "caminho de OUs"
        return res

    @staticmethod
    def _subsequencia(procurados, ancestrais) -> bool:
        pos = 0
        for exigido in procurados:
            while pos < len(ancestrais) and ancestrais[pos] != exigido:
                pos += 1
            if pos == len(ancestrais):
                return False
            pos += 1
        return True

    # -------------------------------------------------------------- scoring

    @staticmethod
    def _palavras_digitadas(texto: str) -> List[str]:
        """Every typed word except particles -- single letters and digits count."""
        palavras = palavras_de(texto)
        uteis = [p for p in palavras if p not in _PARTICULAS]
        return uteis or palavras

    @staticmethod
    def _qualidade(entrada, digitadas) -> Optional[str]:
        """How every typed word is present in the object's name; None if one is not.

        Measured before: words shorter than two characters were dropped, so
        "Joao Silva 2" wrote on joao.silva and "LOJA-PC-3" on LOJA-PC-1.
        """
        palavras = _palavras_do_objeto(entrada)
        pior = "palavra"
        ordem = {"palavra": 0, "prefixo": 1, "trecho": 2}
        for termo in digitadas:
            if termo in palavras:
                nivel = "palavra"
            elif termo.isdigit():
                return None                   # a number matches only itself
            elif (len(termo) == 1 or len(termo) >= 3) and any(
                    p.startswith(termo) for p in palavras):
                nivel = "prefixo"             # initial or abbreviation
            elif len(termo) >= 2 and any(termo in p for p in palavras):
                nivel = "trecho"
            else:
                return None
            if ordem[nivel] > ordem[pior]:
                pior = nivel
        return pior

    def _notas(self, tipo: Tipo, texto: str):
        termos = termos_de_busca(texto)
        if not termos:
            return []
        alvo = normalizar(texto)
        notas = []
        for entrada in _indice(self.ldap, self.base_dn, tipo):
            palavras = _palavras_do_objeto(entrada)
            if not palavras:
                continue
            por_termo = [max(difflib.SequenceMatcher(None, t, p).ratio() for p in palavras)
                         for t in termos]
            nota = sum(por_termo) / len(por_termo)
            a = entrada.get("attributes") or {}
            for nome in ("cn", "displayName"):
                valor = _um(a, nome)
                if valor:
                    nota = max(nota, difflib.SequenceMatcher(None, alvo, normalizar(valor)).ratio())
            notas.append((nota, entrada))
        notas.sort(key=lambda par: -par[0])
        return notas

    # ------------------------------------------------------ domain identity

    def _nomes_do_dominio(self) -> set:
        """Names that designate THIS domain before a backslash."""
        nomes = {normalizar(self.dominio), normalizar(self.dominio.split(".")[0])}
        with _TRAVA_DOS_CACHES:
            guardado = _NETBIOS.get(self.ldap)
        if guardado is None:
            guardado = ""
            try:
                achados = self.ldap.search(
                    search_base=f"CN=Partitions,CN=Configuration,{self.base_dn}",
                    search_filter=f"(&(objectClass=crossRef)(nCName="
                                  f"{escape_filter_chars(self.base_dn)}))",
                    attributes=["nETBIOSName"], size_limit=1)
                if achados:
                    guardado = str(_um(achados[0].get("attributes"), "nETBIOSName") or "")
            except Exception:  # the NetBIOS name only widens what is accepted
                guardado = ""
            with _TRAVA_DOS_CACHES:
                _NETBIOS[self.ldap] = guardado
        if guardado:
            nomes.add(normalizar(guardado))
        return nomes

    def _dominio_de_email_conhecido(self, dominio: str) -> bool:
        """Whether any object here carries an address in that domain."""
        alvo = normalizar(dominio)
        if not alvo:
            return False
        if alvo == normalizar(self.dominio):
            return True
        with _TRAVA_DOS_CACHES:
            guardado = _DOMINIOS_DE_EMAIL.setdefault(self.ldap, {}).get(alvo)
        if guardado and time.monotonic() - guardado[0] < _TTL_INDICE:
            return guardado[1]
        valor = escape_filter_chars(dominio.strip())
        conhecido = bool(self.ldap.search(
            search_base=self.base_dn,
            search_filter=f"(|(mail=*@{valor})(userPrincipalName=*@{valor}))",
            attributes=["mail"], size_limit=1))
        with _TRAVA_DOS_CACHES:
            _DOMINIOS_DE_EMAIL.setdefault(self.ldap, {})[alvo] = (time.monotonic(), conhecido)
        return conhecido

    # ------------------------------------------------------------ outcomes

    def _ambiguo(self, tipo, texto, achados, total=None) -> Resolucao:
        res = Resolucao("ambiguo", tipo, texto)
        res.total_candidatos = total or len(achados)
        res.candidatos = [self._descrever(e, tipo)
                          for e in self._ordenar(achados, texto)[:_LIMITE_CANDIDATOS]]
        return res

    @staticmethod
    def _ordenar(entradas, texto):
        """Closest first: typed first word opens the name, last word closes it.

        Measured on a 404-user directory: "First Last" matched dozens of
        accounts and, in LDAP order, the intended one fell outside the ten
        candidates shown.
        """
        termos = termos_de_busca(texto)
        alvo = normalizar(texto)

        def chave(entrada):
            a = entrada.get("attributes") or {}
            nome = normalizar(_um(a, "cn") or _um(a, "displayName") or _um(a, "name") or "")
            palavras = palavras_de(nome)
            abre = bool(termos and palavras and palavras[0] == termos[0])
            fecha = bool(termos and palavras and palavras[-1] == termos[-1])
            return (-(abre + fecha), -difflib.SequenceMatcher(None, alvo, nome).ratio(), nome)

        return sorted(entradas, key=chave)

    def _nao_encontrado(self, tipo, texto, notas=None) -> Resolucao:
        if notas is None:
            notas = self._notas(tipo, texto)
        res = Resolucao("nao_encontrado", tipo, texto)
        res.parecidos = [self._descrever(e, tipo) for nota, e in notas
                         if nota >= _NOTA_PARECIDO][:_LIMITE_PARECIDOS]
        return res

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _nome(entrada) -> str:
        a = entrada.get("attributes") or {}
        return str(_um(a, "cn") or _um(a, "ou") or _um(a, "name")
                   or _valor_do_rdn(dividir_dn(entrada["dn"])[0]))

    def _descrever(self, entrada, tipo: Tipo) -> Dict[str, Any]:
        a = entrada.get("attributes") or {}
        classe = _classe_de(entrada)
        item: Dict[str, Any] = {}
        if tipo.chave in ("membro", "responsavel", "objeto"):
            item["tipo"] = classe
        if classe in ("usuario", "grupo", "computador"):
            item["login"] = _um(a, "sAMAccountName")
        item["nome"] = self._nome(entrada)
        exibicao = _um(a, "displayName")
        if exibicao and normalizar(exibicao) != normalizar(item["nome"]):
            item["exibicao"] = exibicao
        email = _um(a, "mail")
        if email:
            item["email"] = email
        if classe in ("usuario", "computador"):
            uac = _um(a, "userAccountControl")
            try:
                item["ativo"] = not (int(uac) & 2) if uac is not None else None
            except (TypeError, ValueError):
                item["ativo"] = None
        item["ou"] = caminho_legivel(entrada["dn"])
        if classe not in ("usuario", "grupo", "computador") or tipo.devolve == "dn":
            item["dn"] = entrada["dn"]
        return item

    @staticmethod
    def _casa_atributo(entrada, texto, nome) -> bool:
        alvo = normalizar(texto)
        return any(normalizar(v) in (alvo, alvo + "$")
                   for v in _todos(entrada.get("attributes"), nome))

    def _atributo_casado(self, entrada, texto) -> str:
        a = entrada.get("attributes") or {}
        alvo = normalizar(texto)
        host = alvo.split(".", 1)[0] if alvo.endswith("." + normalizar(self.dominio)) else None
        for nome in ("sAMAccountName", "userPrincipalName", "mail", "cn", "displayName",
                     "dNSHostName", "ou", "name"):
            for valor in _todos(a, nome):
                v = normalizar(valor)
                if v in (alvo, alvo + "$") or (host and v.rstrip("$") == host):
                    return nome
        return "identificador"



# --------------------------------------------------------- call-level resolution

def _recusa(res: Resolucao, parametro: str, tool_name: str) -> Dict[str, Any]:
    tipo = res.tipo
    chave = "login" if tipo.devolve == "login" else "DN"
    if res.situacao == "ambiguo":
        mostrando = ""
        if res.total_candidatos > len(res.candidatos):
            mostrando = f" Mostrando {len(res.candidatos)} de {res.total_candidatos}."
        return {
            "sucesso": False, "erro": "IDENTIFICACAO_AMBIGUA", "tool": tool_name,
            "mensagem": (
                f"'{res.informado}' corresponde a {res.total_candidatos} {tipo.plural} "
                f"neste AD. Nada foi executado. Repita a chamada informando em "
                f"'{parametro}' o {chave} de um dos candidatos, ou mais palavras do nome "
                f"(ex.: um sobrenome do meio). Se o contexto nao deixar claro qual e, "
                f"confirme com o usuario.{mostrando}"),
            "parametro": parametro, "informado": res.informado,
            "candidatos": res.candidatos,
        }
    if res.situacao == "parcial_em_escrita":
        motivo = {
            "prefixo": "o nome foi informado abreviado ou por inicial",
            "trecho": "o nome aparece apenas como trecho de outra palavra",
            "caminho_parcial": "o caminho informado pula OUs intermediarias",
            "aproximado": "o nome so e parecido (possivel erro de digitacao)",
        }.get(res.nivel, "a correspondencia nao e exata")
        return {
            "sucesso": False, "erro": "CORRESPONDENCIA_PARCIAL_EM_ESCRITA", "tool": tool_name,
            "mensagem": (
                f"'{res.informado}' nao identifica um {tipo.rotulo} com seguranca: {motivo}. "
                "Como esta tool altera o Active Directory, o servidor so executa com "
                "identificador exato ou com todas as palavras inteiras do nome. Nada foi "
                "executado. Confirme com o usuario se e o candidato abaixo; se for, repita "
                f"com {parametro}='{res.valor}'."),
            "parametro": parametro, "informado": res.informado,
            "candidatos": res.candidatos,
        }
    if res.situacao == "fora_do_dominio":
        return {
            "sucesso": False, "erro": "OBJETO_FORA_DO_DOMINIO", "tool": tool_name,
            "mensagem": (
                f"O valor informado em '{parametro}' ({res.informado}) aponta para outro "
                "dominio (DN, e-mail, DOMINIO\\login ou nome DNS que nao sao deste AD). Nada "
                "foi executado. Ou o ad_server esta errado, ou o objeto e de outro cliente."),
            "parametro": parametro, "informado": res.informado,
        }
    resposta = {
        "sucesso": False, "erro": "OBJETO_NAO_ENCONTRADO", "tool": tool_name,
        "mensagem": (
            f"Nenhum {tipo.rotulo} neste AD corresponde a '{res.informado}'. Procurado por: "
            f"{tipo.procurado_em}, inclusive por partes do nome e sem diferenciar acento. "
            "Nada foi executado."
            + (" Veja em 'parecidos' os nomes mais proximos." if res.parecidos else "")),
        "parametro": parametro, "informado": res.informado,
    }
    if res.parecidos:
        resposta["parecidos"] = res.parecidos
    return resposta


def _registro(parametro: str, res: Resolucao) -> Dict[str, Any]:
    registro = {
        "parametro": parametro, "informado": res.informado,
        "resolvido_para": res.valor, "dn": res.dn, "nome": res.nome,
        "nivel": res.nivel, "criterio": res.criterio,
    }
    if res.aviso:
        registro["aviso"] = res.aviso
    if res.outros:
        registro["outros_com_as_mesmas_palavras"] = res.outros
    return registro


def resolver_argumentos(tool_name: str, args: Dict[str, Any], ldap, base_dn: str,
                        escrita: bool):
    """Resolve every identifier in one call.

    @MX:ANCHOR Single decision point for both transports (server_fastapi and
    the stdio server.py). Returns (arguments, refusal, identifications): the
    refusal is a ready payload and means the tool must NOT run.
    """
    # Secrets first, before any lookup: a probe must not reach the directory,
    # not even to resolve a name (upstream f5fef26, extended to attributes).
    recusa_de_segredo = recusa_de_consulta(args.get("filter_criteria"),
                                           args.get("attributes"), tool=tool_name)
    if recusa_de_segredo is not None:
        return None, recusa_de_segredo, []

    resolvedor = ResolvedorAD(ldap, base_dn)
    novos = dict(args)
    identificacoes: List[Dict[str, Any]] = []
    nome_novo = nome_novo_de(tool_name, args)

    tipo_de_listagem = LISTAGENS.get(tool_name)
    filtro = novos.get("filter_criteria")
    if tipo_de_listagem and isinstance(filtro, str) and filtro.strip():
        texto = filtro.strip()
        if re.match(r"^[A-Za-z][\w-]*[~<>]?=", texto):
            texto = f"({texto})"
        if texto.startswith("("):
            problema = validar_filtro_ldap(texto)
            if problema:
                return None, {
                    "sucesso": False, "erro": "FILTRO_LDAP_INVALIDO", "tool": tool_name,
                    "mensagem": (
                        f"filter_criteria nao e um filtro LDAP valido ({problema}): {filtro}. "
                        "Use um filtro entre parenteses, por exemplo (department=Financeiro) "
                        "ou (&(department=TI)(title=*Analista*)), ou escreva apenas texto "
                        "livre (parte do nome, login ou e-mail) que o servidor monta a busca."),
                }, []
            novos["filter_criteria"] = texto
        elif not termos_de_busca(texto):
            return None, {
                "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
                "mensagem": (
                    f"filter_criteria ('{filtro}') nao tem nenhuma palavra para buscar. Informe "
                    "parte do nome, login ou e-mail, ou um filtro LDAP entre parenteses. Para "
                    "listar tudo, omita filter_criteria."),
            }, []
        else:
            novos["filter_criteria"] = filtro_de_palavras(tipo_de_listagem, texto)
            # The generated LDAP filter already comes back in the tool's own
            # answer; repeating it here doubled the payload for nothing.
            identificacoes.append({
                "parametro": "filter_criteria", "informado": filtro,
                "palavras_buscadas": termos_de_busca(texto),
                "criterio": "texto livre: cada palavra em login, nome, nome de exibicao, "
                            "e-mail ou UPN, em qualquer ordem",
            })

    object_type = normalizar(novos.get("object_type") or "").replace(" ", "_")
    if object_type and object_type not in TIPO_POR_OBJECT_TYPE:
        return None, {
            "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
            "mensagem": (
                f"object_type '{novos.get('object_type')}' nao e um tipo conhecido. Valores "
                "aceitos: user, computer, group, organizational_unit (ou usuario, computador, "
                "grupo, ou). Omita para procurar em todos os tipos."),
        }, []
    for parametro, chave_tipo_base in PARAMETROS_RESOLVIDOS.items():
        valor = novos.get(parametro)
        if parametro == nome_novo:
            continue
        # A list (several groups in one membership call) resolves item by
        # item, and ONE unresolved item refuses the whole call: nothing runs
        # until every name points at exactly one object.
        em_lista = isinstance(valor, list)
        if em_lista:
            estranhos = [v for v in valor if not isinstance(v, str) or not v.strip()]
            if estranhos:
                # Dropping them silently let an other-tenant DN hidden in a
                # nested list vanish while the rest of the call succeeded.
                return None, {
                    "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
                    "mensagem": (
                        f"'{parametro}' e uma lista de nomes, mas tem itens que nao sao texto "
                        f"ou estao vazios: {estranhos!r}. Nada foi executado."),
                }, identificacoes
            if not valor:
                return None, {
                    "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
                    "mensagem": f"'{parametro}' veio como lista vazia. Nada foi executado.",
                }, identificacoes
        itens = list(valor) if em_lista else \
            ([valor] if isinstance(valor, str) and valor.strip() else [])
        if not itens:
            continue
        resolvidos = []
        for posicao, item in enumerate(itens):
            chave_tipo, devolver = chave_tipo_base, None
            if parametro == "object_name" and object_type in TIPO_POR_OBJECT_TYPE:
                chave_tipo, devolver = TIPO_POR_OBJECT_TYPE[object_type], "dn"
            rotulo = f"{parametro}[{posicao}]" if em_lista else parametro
            res = resolvedor.resolver(chave_tipo, item, escrita, devolver=devolver)
            if res.situacao != "resolvido":
                return None, _recusa(res, rotulo, tool_name), identificacoes
            resolvidos.append(res.valor)
            if escrita or normalizar(res.valor) != normalizar(item):
                identificacoes.append(_registro(rotulo, res))
        novos[parametro] = resolvidos if em_lista else resolvidos[0]

    def _resolver_atributos(atributos: Dict[str, Any], rotulo: str):
        copia = dict(atributos)
        for chave, valor in atributos.items():
            chave_n = _chave_de_atributo(chave)
            if chave_n in _ATRIBUTOS_ANINHADOS and isinstance(valor, dict):
                aninhado, recusa = _resolver_atributos(valor, f"{rotulo}.{chave}")
                if recusa is not None:
                    return None, recusa
                copia[chave] = aninhado
                continue
            chave_tipo = ATRIBUTOS_DN.get(chave_n)
            if not chave_tipo or not isinstance(valor, str) or not valor.strip():
                continue
            res = resolvedor.resolver(chave_tipo, valor, escrita, devolver="dn")
            if res.situacao != "resolvido":
                return None, _recusa(res, f"{rotulo}.{chave}", tool_name)
            copia[chave] = res.valor
            if normalizar(res.valor) != normalizar(valor):
                identificacoes.append(_registro(f"{rotulo}.{chave}", res))
        return copia, None

    for parametro in PARAMETROS_DE_ATRIBUTOS:
        atributos = novos.get(parametro)
        if not isinstance(atributos, dict):
            continue
        resolvidos, recusa = _resolver_atributos(atributos, parametro)
        if recusa is not None:
            return None, recusa, identificacoes
        novos[parametro] = resolvidos

    return novos, None, identificacoes
