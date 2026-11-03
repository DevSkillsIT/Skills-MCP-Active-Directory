"""Secrets must not be readable or guessable through the search tools.

Ported by hand from upstream alpadalar/ActiveDirectoryMCP f5fef26 (WR-02).
A filter is a blind oracle: ``(ms-Mcs-AdmPwd=a*)`` returning one computer and
``(ms-Mcs-AdmPwd=b*)`` returning none reveals the LAPS password one character at
a time, through result counts alone, even when the attribute itself is never
returned. Extensible-match terms (``attr:rule:=``) are refused as well: they
are how chained-membership and bitwise probes are written.

Measured before the fix (2026-11-02): every filter below reached the directory,
and ``attributes=["ms-Mcs-AdmPwd"]`` (or ``["*"]``) returned the secret itself.
"""

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

from active_directory_mcp.core.ldap_manager import LDAPManager
from active_directory_mcp.tools.user import UserTools

from .diretorio_falso import BASE, FIN_FILIAL, computador
from .test_fluxos_de_uma_chamada import chamar

SEGREDO_LAPS = "Laps#Segredo-9f3"

FILTROS_SENSIVEIS = [
    "(ms-Mcs-AdmPwd=a*)",
    "(ms-Mcs-AdmPwd=*)",
    "ms-Mcs-AdmPwd=L*",                      # bare form, the resolver wraps it
    "(MS-MCS-ADMPWD;binary=*)",              # case and attribute options
    "(msLAPS-Password=*)",
    "(msLAPS-EncryptedPassword=*)",
    "(msDS-ManagedPassword=*)",
    "(unicodePwd=*)",
    "(userPassword=a*)",
    "(msFVE-RecoveryPassword=1*)",
    "(&(cn=*)(|(objectClass=user)(!(msLAPS-Password>=m))))",   # nested
]

FILTROS_EXTENSIVEIS = [
    "(userAccountControl:1.2.840.113556.1.4.803:=2)",
    "(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=alfa,DC=local)",
    "(:dn:2.4.6.8.10:=Dino)",
]

FILTROS_POR_OID = ["(1.2.840.113556.1.4.221=*)"]

TOOLS_COM_FILTRO = ["ad_search_directory_users", "ad_search_directory_groups",
                    "ad_search_directory_computers", "ad_search_organizational_units"]


def _consultas_com(falso, trecho):
    return [b for b in falso.buscas if trecho.lower() in b.lower()]


@pytest.mark.parametrize("tool", TOOLS_COM_FILTRO)
@pytest.mark.parametrize("filtro", FILTROS_SENSIVEIS + FILTROS_EXTENSIVEIS + FILTROS_POR_OID)
def test_filtro_proibido_e_recusado_antes_de_consultar(srv, tool, filtro):
    antes = len(srv.falso.buscas)
    r = chamar(srv, tool, filter_criteria=filtro)
    assert r.get("erro") == "FILTRO_LDAP_PROIBIDO", r
    assert "Nada foi consultado" in r["mensagem"]
    # Not one query left the process carrying the probe.
    assert srv.falso.buscas[antes:] == []


def test_recusa_nomeia_o_atributo_sem_ecoar_valor(srv):
    r = chamar(srv, "ad_search_directory_computers",
               filter_criteria="(ms-Mcs-AdmPwd=Abc123*)")
    assert "ms-Mcs-AdmPwd" in r["mensagem"]
    assert "Abc123" not in r["mensagem"]


@pytest.mark.parametrize("filtro", ["(department=Financeiro)", "(cn=*Sabrina*)",
                                    "(&(objectClass=user)(sAMAccountName=sabrina.rocha))",
                                    "Sabrina Rocha"])
def test_filtros_comuns_continuam_funcionando(srv, filtro):
    r = chamar(srv, "ad_search_directory_users", filter_criteria=filtro)
    assert r.get("erro") is None, r


def _computador_com_laps(srv):
    dn, attrs = computador("FIN-PC09", FIN_FILIAL)
    attrs["ms-Mcs-AdmPwd"] = SEGREDO_LAPS
    attrs["msLAPS-Password"] = '{"p": "' + SEGREDO_LAPS + '"}'
    srv.falso.entradas.append(type(srv.falso.entradas[0])(dn, attrs))
    return dn


@pytest.mark.parametrize("pedido", [["ms-Mcs-AdmPwd"], ["cn", "msLAPS-Password"],
                                    ["UNICODEPWD"], ["msDS-ManagedPassword;binary"]])
def test_pedir_atributo_sensivel_e_recusado(srv, pedido):
    _computador_com_laps(srv)
    antes = len(srv.falso.buscas)
    r = chamar(srv, "ad_search_directory_computers", computer_name="FIN-PC09",
               attributes=pedido)
    assert r.get("erro") == "ATRIBUTO_SENSIVEL", r
    assert SEGREDO_LAPS not in str(r)
    assert srv.falso.buscas[antes:] == []


def test_todos_os_atributos_nao_devolvem_segredo(srv):
    """attributes=["*"] is legitimate, but the secret must not ride along."""
    _computador_com_laps(srv)
    r = chamar(srv, "ad_search_directory_computers", computer_name="FIN-PC09",
               attributes=["*"])
    assert r.get("erro") is None, r
    assert SEGREDO_LAPS not in str(r)
    assert "FIN-PC09" in str(r)


# ------------------------------------------------------------- the sink itself

@pytest.fixture
def ldap_mock_sync():
    """ldap3's own MOCK_SYNC: real filter parsing and schema, no network."""
    servidor = Server("falso", get_info=OFFLINE_AD_2012_R2)
    conexao = Connection(servidor, user=f"CN=svc,{BASE}", password="x",
                         client_strategy=MOCK_SYNC, raise_exceptions=True)
    conexao.strategy.add_entry(f"CN=svc,{BASE}", {"userPassword": "x",
                                                   "objectClass": ["top", "person"]})
    conexao.bind()
    gerente = LDAPManager.__new__(LDAPManager)
    import threading
    gerente._lock = threading.Lock()
    gerente._op_lock = threading.RLock()
    gerente._connection = conexao
    gerente._last_successful_operation = 0
    gerente._ensure_connection = lambda: conexao
    from types import SimpleNamespace
    gerente.ad_config = SimpleNamespace(base_dn=BASE)
    gerente.performance_config = SimpleNamespace(page_size=500, max_retries=1,
                                                 retry_delay=0)
    gerente._connection_errors = 0
    gerente._max_connection_errors = 5
    consultas = []
    original = conexao.search

    def contar(*a, **k):
        consultas.append(k.get("search_filter") or (a[1] if len(a) > 1 else None))
        return original(*a, **k)
    conexao.search = contar
    return gerente, consultas


def test_list_users_direto_tambem_recusa(ldap_mock_sync):
    """The tool layer refuses on its own: a caller that skips the server
    (stdio adapter, a script, a future transport) gets the same answer."""
    gerente, consultas = ldap_mock_sync
    import json
    resposta = UserTools(gerente).list_users(filter_criteria="(userPassword=x*)")
    payload = json.loads(resposta[0].text)
    assert payload.get("erro") == "FILTRO_LDAP_PROIBIDO", payload
    assert consultas == []


def test_list_users_direto_aceita_filtro_comum(ldap_mock_sync):
    gerente, consultas = ldap_mock_sync
    import json
    payload = json.loads(UserTools(gerente).list_users(
        filter_criteria="(department=TI)")[0].text)
    assert payload.get("erro") is None, payload
    assert len(consultas) == 1
