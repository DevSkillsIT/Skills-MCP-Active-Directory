"""A password only leaves the process over a protected channel.

Ported by hand from upstream alpadalar/ActiveDirectoryMCP (the
``unicodePwd_requires_tls`` pre-flight and 96f0f2a). Before the fix
(2026-11-02) no path checked the channel: over ``ldap://`` without StartTLS the
password travelled in clear and only then did AD refuse it (5003,
unwillingToPerform) -- after the secret had already crossed the network.

The check runs BEFORE any write: create_user must not leave an account behind,
reset must not touch flags, and an exception while checking counts as insecure
(fail closed).
"""

import threading
from types import SimpleNamespace

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

from active_directory_mcp.core.ldap_manager import LDAPManager

from .diretorio_falso import BASE, TI
from .test_fluxos_de_uma_chamada import _entrada, chamar

SENHA = "Canal@Seguro-2026"
JOAO = f"CN=João da Silva,{TI}"


# ------------------------------------------------------- LDAPManager decides

def _gerente(url: str, tls_iniciado: bool = False, valida: bool = True) -> LDAPManager:
    conexao = Connection(Server(url, get_info=OFFLINE_AD_2012_R2), user=f"CN=svc,{BASE}",
                         password="x", client_strategy=MOCK_SYNC)
    conexao.tls_started = tls_iniciado
    gerente = LDAPManager.__new__(LDAPManager)
    gerente._lock = threading.Lock()
    gerente._op_lock = threading.RLock()
    gerente._connection = conexao
    gerente._ensure_connection = lambda: conexao
    gerente.security_config = SimpleNamespace(validate_certificate=valida)
    return gerente


def test_ldap_sem_tls_nao_e_canal_de_senha():
    assert _gerente("ldap://dc.alfa.local").is_secure_channel() is False


def test_ldaps_e_canal_de_senha():
    assert _gerente("ldaps://dc.alfa.local").is_secure_channel() is True


def test_starttls_concluido_e_canal_de_senha():
    assert _gerente("ldap://dc.alfa.local", tls_iniciado=True).is_secure_channel() is True


# ------------------------------------------------- every password write asks

@pytest.fixture
def inseguro(srv):
    srv.falso.is_secure_channel = lambda: False
    return srv


def _sem_senha_gravada(srv, dn):
    entrada = _entrada(srv, dn)
    return entrada is None or "pwdLastSet" not in entrada.atributos


def test_reset_recusado_sem_canal_seguro(inseguro):
    antes = list(inseguro.falso.escritas)
    r = chamar(inseguro, "ad_manage_directory_users", action="reset_password",
               username="joao.silva", password=SENHA)
    assert r.get("erro") == "CANAL_INSEGURO_PARA_SENHA", r
    assert inseguro.falso.escritas == antes
    assert SENHA not in str(r)


def test_criacao_recusada_antes_de_criar_a_conta(inseguro):
    r = chamar(inseguro, "ad_manage_directory_users", action="create", username="canal.x",
               password=SENHA, first_name="Canal", last_name="X", ou="TI")
    assert r.get("erro") == "CANAL_INSEGURO_PARA_SENHA", r
    assert _entrada(inseguro, f"CN=Canal X,{TI}") is None
    assert not any(e[0] == "add" for e in inseguro.falso.escritas)


def test_update_com_senha_recusado(inseguro):
    antes = list(inseguro.falso.escritas)
    r = chamar(inseguro, "ad_manage_directory_users", action="update", username="joao.silva",
               attributes={"password": SENHA, "description": "x"})
    assert r.get("erro") == "CANAL_INSEGURO_PARA_SENHA", r
    assert inseguro.falso.escritas == antes


def test_reset_de_confianca_de_computador_recusado(inseguro):
    antes = list(inseguro.falso.escritas)
    r = chamar(inseguro, "ad_manage_directory_computers", action="reset_trust",
               computer_name="FIN-PC01")
    assert r.get("erro") == "CANAL_INSEGURO_PARA_SENHA", r
    assert inseguro.falso.escritas == antes


def test_falha_ao_verificar_o_canal_conta_como_inseguro(srv):
    def quebrado():
        raise RuntimeError("socket fechado")
    srv.falso.is_secure_channel = quebrado
    r = chamar(srv, "ad_manage_directory_users", action="reset_password",
               username="joao.silva", password=SENHA)
    assert r.get("erro") == "CANAL_INSEGURO_PARA_SENHA", r


def test_update_sem_senha_nao_depende_do_canal(inseguro):
    """Only a password needs the protected channel; a description does not."""
    r = chamar(inseguro, "ad_manage_directory_users", action="update", username="joao.silva",
               attributes={"description": "Analista"})
    assert r.get("success") is True, r


def test_canal_seguro_continua_gravando(srv):
    r = chamar(srv, "ad_manage_directory_users", action="reset_password",
               username="joao.silva", password=SENHA)
    assert r.get("success") is True, r


# ------------------------------- certificate validation (upstream 96f0f2a)

def test_ldaps_sem_validar_certificado_nao_e_canal_de_senha():
    """TLS whose peer is not authenticated protects nothing against whoever
    sits in the middle: the password must not travel over it."""
    assert _gerente("ldaps://dc.alfa.local", valida=False).is_secure_channel() is False


def test_starttls_sem_validar_certificado_nao_e_canal_de_senha():
    assert _gerente("ldap://dc.alfa.local", tls_iniciado=True,
                    valida=False).is_secure_channel() is False


def test_config_sem_campo_de_validacao_conta_como_nao_validado():
    gerente = _gerente("ldaps://dc.alfa.local")
    gerente.security_config = SimpleNamespace()
    assert gerente.is_secure_channel() is False


def test_recusa_explica_como_validar_o_certificado(inseguro):
    r = chamar(inseguro, "ad_manage_directory_users", action="reset_password",
               username="joao.silva", password=SENHA)
    assert "validate_certificate" in r["mensagem"] and "ca_cert_file" in r["mensagem"]
