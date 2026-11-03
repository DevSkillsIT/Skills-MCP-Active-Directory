"""Reproductions of the defects behind a failed offboarding + onboarding run.

Measured on production (2026-09-19, one customer directory): an operator asked
a model to disable an employee, move the account to _DESATIVADOS, copy her
groups and OU to a new hire and create that new hire. The model needed 39
calls and still left the job half done:

* the move failed twice with ``Connection.modify_dn() missing 1 required
  positional argument: 'relative_dn'`` -- LDAPManager.move had never passed
  the RDN to ldap3, so no user, group or computer move had ever worked;
* the first create failed with invalidAttributeSyntax because an empty
  ``mobile`` value went straight into the LDAP add;
* "change password at next logon" was impossible to request, so the new
  account kept the temporary password forever.

Every test here failed before the fix. The move is checked against ldap3's
own MOCK_SYNC strategy, which enforces the real call signature: the Mock()
used by the older tests accepted the broken call and passed.
"""

import json

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

from active_directory_mcp.core.ldap_manager import LDAPManager
from active_directory_mcp.tools.organizational_unit import OrganizationalUnitTools
from active_directory_mcp.tools.user import UserTools

from .diretorio_falso import BASE, DESATIVADOS, FIN_FILIAL, diretorio_padrao


def _payload(resultado):
    if isinstance(resultado, list):
        return json.loads(resultado[0].text)
    return resultado


# ------------------------------------------------------------------ move

@pytest.fixture
def ldap_mock():
    servidor = Server("falso", get_info=OFFLINE_AD_2012_R2)
    conexao = Connection(servidor, user=f"CN=svc,{BASE}", password="x",
                         client_strategy=MOCK_SYNC, raise_exceptions=True)
    conexao.strategy.add_entry(f"CN=svc,{BASE}", {"userPassword": "x",
                                                   "objectClass": ["top", "person"]})
    for dn, ou in ((FIN_FILIAL, "Financeiro"), (DESATIVADOS, "_DESATIVADOS")):
        conexao.strategy.add_entry(dn, {"objectClass": ["top", "organizationalUnit"],
                                        "ou": ou})
    dn = f"CN=Sabrina De Moura Lopes Rocha,{FIN_FILIAL}"
    conexao.strategy.add_entry(dn, {"objectClass": ["top", "person", "user"],
                                    "cn": "Sabrina De Moura Lopes Rocha",
                                    "sAMAccountName": "sabrina.rocha"})
    conexao.bind()

    gerente = LDAPManager.__new__(LDAPManager)
    import threading
    gerente._lock = threading.Lock()
    gerente._op_lock = threading.RLock()
    gerente._connection = conexao
    gerente._last_successful_operation = 0
    gerente._ensure_connection = lambda: conexao
    return gerente, conexao, dn


def test_mover_usuario_chega_ao_ldap3_com_o_rdn(ldap_mock):
    gerente, conexao, dn = ldap_mock
    assert gerente.move(dn, DESATIVADOS) is True
    conexao.search(BASE, "(sAMAccountName=sabrina.rocha)", attributes=["cn"])
    assert [e.entry_dn for e in conexao.entries] == [
        f"CN=Sabrina De Moura Lopes Rocha,{DESATIVADOS}"]


def test_mover_preserva_virgula_escapada_no_rdn(ldap_mock):
    gerente, conexao, _ = ldap_mock
    dn = f"CN=Rocha\\, Sabrina,{FIN_FILIAL}"
    conexao.strategy.add_entry(dn, {"objectClass": ["top", "person", "user"],
                                    "cn": "Rocha, Sabrina", "sAMAccountName": "s.rocha"})
    gerente.move(dn, DESATIVADOS)
    conexao.search(BASE, "(sAMAccountName=s.rocha)", attributes=["cn"])
    assert [e.entry_dn for e in conexao.entries] == [f"CN=Rocha\\, Sabrina,{DESATIVADOS}"]


# ------------------------------------------------------ enable / disable

def _com_uac(falso, login, uac):
    for entrada in falso.entradas:
        if entrada.atributos.get("sAMAccountName") == login:
            entrada.atributos["userAccountControl"] = uac
            return entrada
    raise AssertionError(login)


def test_desativar_so_liga_o_bit_de_desativada():
    """Disable used to REPLACE userAccountControl with 514, erasing every other
    flag -- a 'password never expires' service account lost it for good."""
    falso = diretorio_padrao()
    entrada = _com_uac(falso, "joao.silva", 0x200 | 0x10000)
    _payload(UserTools(falso).disable_user("joao.silva"))
    assert entrada.atributos["userAccountControl"] == 0x200 | 0x10000 | 0x2


def test_ativar_so_desliga_o_bit_de_desativada():
    falso = diretorio_padrao()
    entrada = _com_uac(falso, "joao.silva", 0x200 | 0x10000 | 0x2)
    _payload(UserTools(falso).enable_user("joao.silva"))
    assert entrada.atributos["userAccountControl"] == 0x200 | 0x10000


# ---------------------------------------------------------- listing users

def test_listar_usuarios_nao_traz_contas_de_computador():
    """In AD every computer is also objectClass=user."""
    falso = diretorio_padrao()
    dados = _payload(UserTools(falso).list_users())
    logins = {u["sAMAccountName"] for u in dados["users"]}
    assert "sabrina.rocha" in logins
    assert not any(login.endswith("$") for login in logins), logins


# ------------------------------------------------------------- OU gPLink

def test_detalhes_da_ou_le_o_gplink_inteiro():
    """gPLink is single-valued: ldap3 gives a str, and [0] was its first char."""
    falso = diretorio_padrao()
    guid = "31B2F340-016D-11D2-945F-00C04FB984F9"
    for entrada in falso.entradas:
        if entrada.dn == FIN_FILIAL:
            entrada.atributos["gPLink"] = (
                f"[LDAP://cn={{{guid}}},cn=policies,cn=system,{BASE};0]")
    dados = _payload(OrganizationalUnitTools(falso).get_ou(FIN_FILIAL))
    gpos = dados["computed"]["linked_gpos"]
    assert len(gpos) == 1 and guid.lower() in json.dumps(gpos).lower()


# ------------------------------------------------------------ create user

def test_criar_usuario_ignora_campo_vazio_em_vez_de_quebrar():
    falso = diretorio_padrao()
    dados = _payload(UserTools(falso).create_user(
        "marta.souto", "Mudar@12345", "Marta", "Lima Souto", ou=FIN_FILIAL,
        additional_attributes={"mobile": "", "title": "Assistente Financeiro"}))
    assert dados.get("success") is not False, dados
    criada = falso._entrada(f"CN=Marta Lima Souto,{FIN_FILIAL}")
    assert criada is not None
    assert "mobile" not in {k.lower() for k in criada.atributos}
    assert criada.atributos["title"] == "Assistente Financeiro"


def test_criar_usuario_obriga_troca_de_senha_no_proximo_logon():
    falso = diretorio_padrao()
    _payload(UserTools(falso).create_user(
        "marta.souto", "Mudar@12345", "Marta", "Lima Souto", ou=FIN_FILIAL,
        must_change_password=True))
    criada = falso._entrada(f"CN=Marta Lima Souto,{FIN_FILIAL}")
    assert criada.atributos.get("pwdLastSet") in (0, "0")


# ------------------------------------------- searches that asked for a 'dn' attribute
#
# Measured 2026-09-19 against a real directory: ad_delete_group_permanently
# answered "invalid attribute type dn". Six tools located their object with
# attributes=['dn']; with the server schema loaded ldap3 refuses that name
# before sending anything, so modify/delete group, modify/delete/enable/
# disable computer and the computer trust reset had never worked. The OU
# child counters swallowed the same error and always answered 0.

from types import SimpleNamespace

from active_directory_mcp.tools.computer import ComputerTools
from active_directory_mcp.tools.group import GroupTools

PC_DN = f"CN=FIN-PC01,{FIN_FILIAL}"
GRUPO_DN = f"CN=Financeiro - Filial,{FIN_FILIAL}"


@pytest.fixture
def ad_com_schema(ldap_mock):
    gerente, conexao, _ = ldap_mock
    gerente.ad_config = SimpleNamespace(base_dn=BASE, domain="alfa.local")
    gerente.performance_config = SimpleNamespace(page_size=500)
    gerente.ou_config = None
    # Stands for ldaps:// as in production; the password pre-flight reads it.
    conexao.server.ssl = True
    conexao.strategy.add_entry(BASE, {"objectClass": ["top", "domain"], "dc": "alfa"})
    conexao.strategy.add_entry(GRUPO_DN, {"objectClass": ["top", "group"],
                                          "cn": "Financeiro - Filial",
                                          "sAMAccountName": "fin-filial",
                                          "groupType": -2147483646})
    conexao.strategy.add_entry(PC_DN, {"objectClass": ["top", "person", "user", "computer"],
                                       "cn": "FIN-PC01", "sAMAccountName": "FIN-PC01$",
                                       # workstation + trusted for delegation
                                       "userAccountControl": 0x1000 | 0x80000})
    return gerente, conexao


def _existe(conexao, dn):
    conexao.search(BASE, "(objectClass=*)", attributes=["cn"])
    return any(e.entry_dn.lower() == dn.lower() for e in conexao.entries)


def _uac(conexao, dn):
    conexao.search(dn, "(objectClass=*)", search_scope="BASE",
                   attributes=["userAccountControl"])
    return int(conexao.entries[0].userAccountControl.value)


def test_apagar_grupo_funciona(ad_com_schema):
    gerente, conexao = ad_com_schema
    dados = _payload(GroupTools(gerente).delete_group("fin-filial"))
    assert dados["success"] is True, dados
    assert not _existe(conexao, GRUPO_DN)


def test_alterar_grupo_funciona(ad_com_schema):
    gerente, conexao = ad_com_schema
    dados = _payload(GroupTools(gerente).modify_group("fin-filial", {"description": "novo"}))
    assert dados["success"] is True, dados


def test_apagar_computador_funciona(ad_com_schema):
    gerente, conexao = ad_com_schema
    dados = _payload(ComputerTools(gerente).delete_computer("FIN-PC01"))
    assert dados["success"] is True, dados
    assert not _existe(conexao, PC_DN)


def test_alterar_computador_funciona(ad_com_schema):
    gerente, _ = ad_com_schema
    dados = _payload(ComputerTools(gerente).modify_computer("FIN-PC01", {"location": "Sala 2"}))
    assert dados["success"] is True, dados


def test_desativar_computador_so_liga_o_bit_e_preserva_delegacao(ad_com_schema):
    gerente, conexao = ad_com_schema
    dados = _payload(ComputerTools(gerente).disable_computer("FIN-PC01"))
    assert dados["success"] is True, dados
    assert _uac(conexao, PC_DN) == 0x1000 | 0x80000 | 0x2
    _payload(ComputerTools(gerente).enable_computer("FIN-PC01"))
    assert _uac(conexao, PC_DN) == 0x1000 | 0x80000


def test_reset_de_confianca_grava_uma_senha_e_nao_inventa_outra(ad_com_schema):
    """The old reset only zeroed pwdLastSet and answered with a password that
    was never written anywhere. Now a random password is written (not ADUC's
    guessable default) and none is returned."""
    gerente, conexao = ad_com_schema
    dados = _payload(ComputerTools(gerente).reset_computer_password("FIN-PC01"))
    assert dados["success"] is True, dados
    assert "new_password" not in dados
    conexao.search(PC_DN, "(objectClass=*)", search_scope="BASE", attributes=["unicodePwd"])
    gravada = conexao.entries[0].unicodePwd.value
    assert gravada and gravada != '"fin-pc01"'.encode("utf-16-le")


def test_contagem_de_filhos_da_ou_nao_e_sempre_zero(ad_com_schema):
    gerente, _ = ad_com_schema
    # ldap3's MOCK_SYNC also returns the base entry on a LEVEL search (a real
    # DC does not), so the floor is what matters: before the fix it was 0.
    assert OrganizationalUnitTools(gerente)._count_child_objects(FIN_FILIAL) >= 3
