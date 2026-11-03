"""Secrets never reach a log line or an error message.

Ported by hand from upstream alpadalar/ActiveDirectoryMCP 4fa2bef and b99cd1b.
Reproduced before the fix (2026-11-02), on this fork's own paths:

* a server block that fails validation (a missing base_dn is enough) stored
  ``str(ValidationError)`` -- which pydantic v2 writes with
  ``input_value={... 'password': '<bind password>' ...}`` -- and that text was
  logged AND returned to clients as ``erro_de_configuracao`` in the catalogue;
* a password write whose error text echoes the value went back verbatim in
  the tool's error and in the log.

Upstream's design is kept: registered secrets (and their URL, base64, JSON,
repr and unicodePwd wire encodings) are replaced at LogRecord creation, for
every logger -- ldap3, uvicorn and the root logger included.
"""

import json
import logging

import pytest

try:
    from active_directory_mcp.core import redaction
except ImportError:  # red phase: the module did not exist yet
    redaction = None
from active_directory_mcp.server_fastapi import ActiveDirectoryMCPFastAPI

from .diretorio_falso import BASE
from .test_fluxos_de_uma_chamada import chamar

SENHA_BIND = "Bind#Segredo-77!"
SENHA_NOVA = "Nova@Senha-Redacao9"


@pytest.fixture(autouse=True)
def _limpo():
    if redaction is not None:
        redaction.clear_secrets()
    yield
    if redaction is not None:
        redaction.clear_secrets()


def _texto_dos_logs(caplog) -> str:
    return "\n".join(r.getMessage() + (r.exc_text or "") for r in caplog.records)


def _config_com_bloco_invalido(tmp_path, bloco_ad) -> str:
    valido = {
        "active_directory": {"server": "ldaps://10.0.0.1:636", "domain": "alfa.local",
                             "base_dn": BASE, "bind_dn": f"CN=svc,{BASE}",
                             "password": "outra-senha-valida", "timeout": 5},
        "organizational_units": {"users_ou": BASE, "groups_ou": BASE,
                                 "computers_ou": BASE, "service_accounts_ou": BASE},
    }
    invalido = {"active_directory": bloco_ad,
                "organizational_units": valido["organizational_units"]}
    caminho = tmp_path / "s.json"
    caminho.write_text(json.dumps({"version": 1, "servers": {"alfa": valido,
                                                              "beta": invalido}}))
    return str(caminho)


# pydantic v2 prints input_value truncated to its head and tail, so whether the
# password shows depends on where it sits. Both shapes below happen for real: a
# directory being added with only the essentials (password typed last, base_dn
# forgotten), and an all-digit password typed without quotes (a type error
# prints the whole value).
BLOCOS_INVALIDOS = {
    "bloco_curto_sem_base_dn": {"server": "ldaps://10.0.0.2:636", "domain": "beta.local",
                                "bind_dn": "CN=svc,DC=beta,DC=local", "password": SENHA_BIND},
    "senha_numerica_sem_aspas": {"server": "ldaps://10.0.0.2:636", "domain": "beta.local",
                                 "base_dn": "DC=beta,DC=local",
                                 "bind_dn": "CN=svc,DC=beta,DC=local",
                                 "password": 98127734651, "timeout": 5},
}


@pytest.mark.parametrize("caso", sorted(BLOCOS_INVALIDOS))
def test_bloco_invalido_nao_vaza_senha_de_bind(tmp_path, caplog, caso):
    caplog.set_level(logging.DEBUG)
    bloco = BLOCOS_INVALIDOS[caso]
    segredo = str(bloco["password"])
    srv = ActiveDirectoryMCPFastAPI(port=0, mode="multi",
                                    servers_path=_config_com_bloco_invalido(tmp_path, bloco))
    r = chamar(srv, "ad_search_directory_servers", ad_server=None)
    texto = json.dumps(r, ensure_ascii=False)
    # The invalid block is still reported as invalid -- only the secret goes.
    assert "beta" in texto and "erro_de_configuracao" in texto
    assert segredo not in texto
    assert segredo not in _texto_dos_logs(caplog)


@pytest.mark.parametrize("logger_name", ["ldap3", "uvicorn.error", "", "qualquer.coisa",
                                         "active-directory-mcp.UserTools"])
def test_segredo_registrado_some_de_qualquer_logger(caplog, logger_name):
    caplog.set_level(logging.DEBUG)
    redaction.register_secret(SENHA_BIND)
    logging.getLogger(logger_name).warning("bind falhou com %s", SENHA_BIND)
    assert SENHA_BIND not in _texto_dos_logs(caplog)
    assert redaction.REDACTED in _texto_dos_logs(caplog)


@pytest.mark.parametrize("forma", [
    lambda s: json.dumps({"password": s}),
    lambda s: repr({"password": s}),
    lambda s: __import__("base64").b64encode(s.encode()).decode(),
    lambda s: __import__("base64").b64encode(f'"{s}"'.encode("utf-16-le")).decode(),
    lambda s: __import__("urllib.parse").parse.quote(s, safe=""),
])
def test_formas_codificadas_tambem_somem(caplog, forma):
    caplog.set_level(logging.DEBUG)
    redaction.register_secret(SENHA_BIND)
    vazado = forma(SENHA_BIND)
    logging.getLogger("x").error("payload=%s", vazado)
    assert vazado not in _texto_dos_logs(caplog)


def test_excecao_com_traceback_tambem_e_limpa(caplog):
    caplog.set_level(logging.DEBUG)
    redaction.register_secret(SENHA_BIND)
    try:
        raise RuntimeError(f"bind recusado para senha {SENHA_BIND}")
    except RuntimeError:
        logging.getLogger("y").exception("falhou")
    assert SENHA_BIND not in _texto_dos_logs(caplog)


def test_senha_curta_demais_nao_e_registrada():
    """Replacing 'x' everywhere would destroy every log line; real AD
    passwords are never this short (default policy: 7)."""
    redaction.register_secret("x")
    assert redaction.redact("texto com x") == "texto com x"


def test_erro_de_gravacao_de_senha_nao_ecoa_a_senha(srv, caplog):
    caplog.set_level(logging.DEBUG)
    falso = srv.falso
    original = falso.modify

    def modify_que_ecoa(dn, changes):
        if any(k.lower() == "unicodepwd" for k in changes):
            valor = changes[next(k for k in changes if k.lower() == "unicodepwd")][0][1][0]
            raise Exception(f"constraintViolation 0000052D: valor rejeitado {valor!r} "
                            f"(texto: {SENHA_NOVA})")
        return original(dn, changes)
    falso.modify = modify_que_ecoa
    r = chamar(srv, "ad_manage_directory_users", action="reset_password",
               username="joao.silva", password=SENHA_NOVA)
    assert r.get("success") is False, r
    texto = json.dumps(r, ensure_ascii=False)
    assert SENHA_NOVA not in texto
    assert "constraintViolation" in texto      # the useful part survives
    assert SENHA_NOVA not in _texto_dos_logs(caplog)


def test_criacao_com_falha_na_senha_nao_ecoa_a_senha(srv, caplog):
    caplog.set_level(logging.DEBUG)
    falso = srv.falso
    original = falso.modify

    def modify_que_ecoa(dn, changes):
        if any(k.lower() == "unicodepwd" for k in changes):
            raise Exception(f"unwillingToPerform: senha {SENHA_NOVA} fora da politica")
        return original(dn, changes)
    falso.modify = modify_que_ecoa
    r = chamar(srv, "ad_manage_directory_users", action="create", username="red.x",
               password=SENHA_NOVA, first_name="Red", last_name="X", ou="TI")
    assert r.get("success") is False, r
    assert SENHA_NOVA not in json.dumps(r, ensure_ascii=False)
    assert SENHA_NOVA not in _texto_dos_logs(caplog)


def test_reset_bem_sucedido_ainda_entrega_a_senha_ao_operador(srv):
    """Redaction is for logs and errors: the operator still gets the password
    they set or that was generated for them."""
    r = chamar(srv, "ad_manage_directory_users", action="reset_password",
               username="joao.silva", password=SENHA_NOVA)
    assert r.get("success") is True, r
    assert r["new_password"] == SENHA_NOVA
