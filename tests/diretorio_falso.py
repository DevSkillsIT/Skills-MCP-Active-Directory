"""In-memory directory that evaluates LDAP filters the way Active Directory does.

Measured on the eight production directories before this module existed:
substring and equality matches ignore both case and accents -- (cn=*joao*),
(cn=*joão*) and (cn=*JOÃO*) return the same count in every domain. A fake that
compared bytes would pass tests that fail in production, or the reverse.

Only the filter grammar the server generates is supported (&, |, !, equality,
presence, substring). Anything else raises, so a test can never pass because
the fake silently ignored part of a filter.
"""

import unicodedata
from types import SimpleNamespace


def _normalizar(valor) -> str:
    texto = unicodedata.normalize("NFKD", str(valor).casefold())
    return "".join(c for c in texto if not unicodedata.combining(c))


def _decodificar(valor: str) -> str:
    """Undo RFC 4515 escapes (\\2a, \\28, \\29, \\5c, \\00)."""
    saida, i = [], 0
    while i < len(valor):
        if valor[i] == "\\" and i + 2 < len(valor) + 1:
            saida.append(chr(int(valor[i + 1:i + 3], 16)))
            i += 3
        else:
            saida.append(valor[i])
            i += 1
    return "".join(saida)


def _dividir_dn(dn: str):
    """Split a DN on unescaped commas."""
    partes, atual, escapado = [], [], False
    for c in dn:
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
    return partes


class _Filtro:
    def __init__(self, texto: str):
        self.texto = texto
        self.no, fim = self._no(0)
        if fim != len(texto):
            raise ValueError(f"filtro com sobra apos a posicao {fim}: {texto!r}")

    def _no(self, i):
        if self.texto[i] != "(":
            raise ValueError(f"esperado '(' na posicao {i}: {self.texto!r}")
        i += 1
        op = self.texto[i]
        if op in "&|":
            filhos, i = [], i + 1
            while self.texto[i] == "(":
                filho, i = self._no(i)
                filhos.append(filho)
            if self.texto[i] != ")":
                raise ValueError(f"esperado ')' na posicao {i}: {self.texto!r}")
            return (op, filhos), i + 1
        if op == "!":
            filho, i = self._no(i + 1)
            if self.texto[i] != ")":
                raise ValueError(f"esperado ')' na posicao {i}: {self.texto!r}")
            return ("!", [filho]), i + 1
        fim = self.texto.index(")", i)
        item = self.texto[i:fim]
        if "=" not in item or any(s in item for s in (">=", "<=", "~=", ":=")):
            raise ValueError(f"item de filtro nao suportado pelo diretorio falso: {item!r}")
        atributo, valor = item.split("=", 1)
        return ("item", atributo.strip(), valor), fim + 1

    def casa(self, entrada) -> bool:
        return self._casa(self.no, entrada)

    def _casa(self, no, entrada) -> bool:
        tipo = no[0]
        if tipo == "&":
            return all(self._casa(f, entrada) for f in no[1])
        if tipo == "|":
            return any(self._casa(f, entrada) for f in no[1])
        if tipo == "!":
            return not self._casa(no[1][0], entrada)
        _, atributo, bruto = no
        valores = entrada.valores(atributo)
        if bruto == "*":
            return bool(valores)
        if "*" in bruto:
            pedacos = [_normalizar(_decodificar(p)) for p in bruto.split("*")]
            return any(self._casa_trecho(pedacos, _normalizar(v)) for v in valores)
        alvo = _normalizar(_decodificar(bruto))
        return any(_normalizar(v) == alvo for v in valores)

    @staticmethod
    def _casa_trecho(pedacos, valor) -> bool:
        inicio, *meio, fim = pedacos
        if not valor.startswith(inicio):
            return False
        pos = len(inicio)
        for p in meio:
            achado = valor.find(p, pos)
            if achado < 0:
                return False
            pos = achado + len(p)
        return valor.endswith(fim) and len(valor) - len(fim) >= pos


class _Entrada:
    def __init__(self, dn, atributos):
        self.dn = dn
        self.atributos = dict(atributos)

    def valores(self, atributo):
        if atributo.lower() == "distinguishedname":
            return [self.dn]
        for chave, valor in self.atributos.items():
            if chave.lower() == atributo.lower():
                if valor is None:
                    return []
                return list(valor) if isinstance(valor, (list, tuple)) else [valor]
        return []


class DiretorioFalso:
    """Stands in for LDAPManager: search, move and the ad_config it exposes."""

    def __init__(self, base_dn: str, entradas):
        self.ad_config = SimpleNamespace(base_dn=base_dn, domain=".".join(
            p.split("=", 1)[1] for p in _dividir_dn(base_dn)))
        self.entradas = [_Entrada(dn, attrs) for dn, attrs in entradas]
        self.buscas = []
        self.movimentos = []
        self.escritas = []

    def _no_escopo(self, dn, base, escopo) -> bool:
        dn_n, base_n = _normalizar(dn), _normalizar(base)
        escopo = str(escopo).upper()
        if escopo == "BASE":
            return dn_n == base_n
        if escopo in ("LEVEL", "ONELEVEL", "ONE"):
            return ",".join(_dividir_dn(dn_n)[1:]) == base_n
        return dn_n == base_n or dn_n.endswith("," + base_n)

    def search(self, search_base, search_filter, attributes=None,
               search_scope="SUBTREE", size_limit=0):
        self.buscas.append(search_filter)
        filtro = _Filtro(search_filter)
        resultado = []
        for entrada in self.entradas:
            if not self._no_escopo(entrada.dn, search_base, search_scope):
                continue
            if not filtro.casa(entrada):
                continue
            if attributes in (None, "*") or attributes == ["*"]:
                attrs = dict(entrada.atributos)
            else:
                pedidos = {a.lower() for a in attributes}
                attrs = {k: v for k, v in entrada.atributos.items() if k.lower() in pedidos}
                if "distinguishedname" in pedidos:
                    attrs["distinguishedName"] = entrada.dn
            resultado.append({"dn": entrada.dn, "attributes": attrs})
            if size_limit and len(resultado) >= size_limit:
                break
        return resultado

    # Write operations: recorded, applied just enough for read-back checks.
    def add(self, dn, attributes):
        # AD refuses a zero-length value with invalidAttributeSyntax (00000057);
        # the whole add fails and nothing is created.
        for nome, valor in (attributes or {}).items():
            if valor in ("", []) or (isinstance(valor, list) and "" in valor):
                raise Exception(
                    "LDAPInvalidAttributeSyntaxResult - 21 - invalidAttributeSyntax - "
                    f"00000057: Error in attribute conversion operation ({nome})")
        if self._entrada(dn) is not None:
            raise Exception(f"LDAPEntryAlreadyExistsResult - 68 - entryAlreadyExists: {dn}")
        self.entradas.append(_Entrada(dn, attributes or {}))
        self.escritas.append(("add", dn))
        return True

    def _entrada(self, dn):
        alvo = _normalizar(dn)
        for entrada in self.entradas:
            if _normalizar(entrada.dn) == alvo:
                return entrada
        return None

    def modify(self, dn, changes):
        """Apply the change so a test can read the EFFECT back, not the request.

        group.member and user.memberOf are kept in step the way AD keeps its
        back-link: a test that only checked what was sent passed while nothing
        was written (see feedback: teste afirma o envio, nao o efeito).
        """
        self.escritas.append(("modify", dn))
        entrada = self._entrada(dn)
        if entrada is None:
            raise Exception(f"noSuchObject: {dn}")
        for atributo, operacoes in changes.items():
            for operacao, valores in operacoes:
                valores = list(valores or [])
                chave = next((k for k in entrada.atributos if k.lower() == atributo.lower()),
                             atributo)
                atuais = entrada.valores(atributo)
                if str(operacao).upper().endswith("REPLACE"):
                    novos = valores
                elif str(operacao).upper().endswith("ADD"):
                    novos = atuais + [v for v in valores if v not in atuais]
                elif str(operacao).upper().endswith("DELETE"):
                    tirar = {_normalizar(v) for v in valores}
                    novos = [v for v in atuais if _normalizar(v) not in tirar] if valores else []
                else:
                    raise ValueError(f"operacao desconhecida: {operacao}")
                if not novos:
                    entrada.atributos.pop(chave, None)
                else:
                    entrada.atributos[chave] = novos[0] if len(novos) == 1 and \
                        not isinstance(entrada.atributos.get(chave), list) and \
                        atributo.lower() != "member" else novos
                if atributo.lower() == "member":
                    self._sincronizar_member_of(dn, atuais, novos)
                if atributo.lower() == "unicodepwd":
                    # AD stamps pwdLastSet when a password is set; without
                    # this every new account would read as "must change".
                    entrada.atributos["pwdLastSet"] = 134000000000000000
        return True

    def _sincronizar_member_of(self, grupo_dn, antes, depois):
        antes_n = {_normalizar(v) for v in antes}
        depois_n = {_normalizar(v) for v in depois}
        for membro in self.entradas:
            m = _normalizar(membro.dn)
            if m in antes_n and m not in depois_n:
                restantes = [g for g in membro.valores("memberOf")
                             if _normalizar(g) != _normalizar(grupo_dn)]
                if restantes:
                    membro.atributos["memberOf"] = restantes
                else:
                    membro.atributos.pop("memberOf", None)
            elif m in depois_n and m not in antes_n:
                membro.atributos["memberOf"] = membro.valores("memberOf") + [grupo_dn]

    def incluir_membro(self, grupo_dn, membro_dn):
        """Fixture helper: membership as AD stores it (member + memberOf)."""
        grupo, membro = self._entrada(grupo_dn), self._entrada(membro_dn)
        assert grupo is not None and membro is not None, (grupo_dn, membro_dn)
        grupo.atributos["member"] = grupo.valores("member") + [membro_dn]
        membro.atributos["memberOf"] = membro.valores("memberOf") + [grupo_dn]

    def delete(self, dn):
        self.entradas = [e for e in self.entradas if _normalizar(e.dn) != _normalizar(dn)]
        self.escritas.append(("delete", dn))
        return True

    def get_connection_stats(self):
        return {"connected": True}

    def estado_de_disponibilidade(self):
        return {"indisponivel": False}

    def is_secure_channel(self):
        """The fake stands for an LDAPS connection with a validated certificate.
        Tests about the channel replace this method; without it, the
        fail-closed pre-flight would (rightly) refuse every password write."""
        return True

    def test_connection(self):
        return {"connected": True, "server": "falso", "search_test": True}

    def move(self, dn, new_parent):
        rdn = _dividir_dn(dn)[0]
        novo = f"{rdn},{new_parent}"
        antigo_n = _normalizar(dn)
        for entrada in self.entradas:
            atual_n = _normalizar(entrada.dn)
            if atual_n == antigo_n:
                entrada.dn = novo
            elif atual_n.endswith("," + antigo_n):
                entrada.dn = entrada.dn[: len(entrada.dn) - len(dn)] + novo
        # AD keeps DN-valued links (member, memberOf, manager) pointing at the
        # moved object; without this a remove-after-move matched nothing here
        # while it works against a real directory.
        for entrada in self.entradas:
            for chave, valor in list(entrada.atributos.items()):
                if chave.lower() not in ("member", "memberof", "manager", "managedby"):
                    continue
                valores = valor if isinstance(valor, list) else [valor]
                trocados = [novo if _normalizar(v) == antigo_n else v for v in valores]
                entrada.atributos[chave] = trocados if isinstance(valor, list) else trocados[0]
        self.movimentos.append((dn, new_parent))
        return True


BASE = "DC=alfa,DC=local"


def usuario(cn, login, ou, exibicao=None, nome=None, sobrenome=None, ativo=True):
    dn = f"CN={cn},{ou}"
    return dn, {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "objectCategory": "person",
        "cn": cn, "name": cn,
        "displayName": exibicao or cn,
        "givenName": nome or cn.split()[0],
        "sn": sobrenome or cn.split()[-1],
        "sAMAccountName": login,
        "userPrincipalName": f"{login}@alfa.com",
        "mail": f"{login}@alfa.com",
        "userAccountControl": 512 if ativo else 514,
    }


def grupo(cn, login, ou, exibicao=None):
    return f"CN={cn},{ou}", {
        "objectClass": ["top", "group"], "objectCategory": "group",
        "cn": cn, "name": cn, "sAMAccountName": login,
        "displayName": exibicao or cn,
    }


def computador(nome, ou):
    return f"CN={nome},{ou}", {
        "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
        "objectCategory": "computer",
        "cn": nome, "name": nome, "sAMAccountName": f"{nome}$",
        "dNSHostName": f"{nome.lower()}.alfa.local",
        "userAccountControl": 4096,
    }


def unidade(nome, pai):
    return f"OU={nome},{pai}", {
        "objectClass": ["top", "organizationalUnit"], "objectCategory": "organizationalUnit",
        "ou": nome, "name": nome,
    }


RAIZ = f"OU=_Alfa,{BASE}"
FILIAL = f"OU=Filial,{RAIZ}"
FIN_FILIAL = f"OU=Financeiro,{FILIAL}"
MATRIZ = f"OU=Matriz,{RAIZ}"
FIN_MATRIZ = f"OU=Financeiro,{MATRIZ}"
TI = f"OU=TI,{FILIAL}"
DESATIVADOS = f"OU=_DESATIVADOS,{BASE}"


def diretorio_padrao() -> DiretorioFalso:
    """A small domain that reproduces every shape the resolver has to handle.

    The first account mirrors the production case that started this work: the
    full name the operator typed is the CN, while displayName says something
    else entirely. Only a search across several fields finds it.
    """
    return DiretorioFalso(BASE, [
        (BASE, {"objectClass": ["top", "domain", "domainDNS"], "name": "alfa"}),
        (f"CN=Users,{BASE}", {"objectClass": ["top", "container"], "cn": "Users", "name": "Users"}),
        unidade("_Alfa", BASE), unidade("Filial", RAIZ), unidade("Financeiro", FILIAL),
        unidade("Matriz", RAIZ), unidade("Financeiro", MATRIZ), unidade("TI", FILIAL),
        unidade("_DESATIVADOS", BASE),
        usuario("Sabrina De Moura Lopes Rocha", "sabrina.rocha", FIN_FILIAL,
                 exibicao="Sabrina Rocha - Administrativo Financeiro",
                 nome="Sabrina", sobrenome="Rocha"),
        usuario("João da Silva", "joao.silva", TI, nome="João", sobrenome="Silva"),
        usuario("João Pereira", "joao.pereira", FIN_MATRIZ, nome="João", sobrenome="Pereira"),
        usuario("Mariana Souza", "mariana.souza", FIN_MATRIZ),
        usuario("Ana Clara Mendes", "ana.mendes", TI, nome="Ana Clara", sobrenome="Mendes"),
        usuario("Conceição Alves", "conceicao.alves", FIN_FILIAL,
                 nome="Conceição", sobrenome="Alves", ativo=False),
        grupo("Financeiro - Filial", "fin-filial", FILIAL),
        grupo("Financeiro - Matriz", "fin-matriz", MATRIZ),
        grupo("TI Suporte", "ti-suporte", TI),
        computador("FIN-PC01", FIN_FILIAL),
        computador("FIN-PC02", FIN_FILIAL),
    ])
